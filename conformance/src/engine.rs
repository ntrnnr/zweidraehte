//! Conformance test execution engine.
//!
//! Everything needed to *run* a [`TestSuite`] against a DUT child
//! process: time scaling, the per-step dispatch table, and the
//! suite/case/step loop with its result tally.
//!
//! Kept separate from any particular set of tests so that both the
//! hand-written suites (`bin/runner.rs`) and suites lowered from an
//! EITT XML template (`bin/eitt.rs`, see [`crate::eitt`]) execute
//! through exactly the same machinery — a divergence there would make
//! the two runners incomparable, which is the whole point of having
//! both.

use std::collections::BTreeMap;

// Timing is runtime-agnostic: `std::time` for the clock, async-io's
// timer (the same reactor that drives the DUT socket) for sleeping.
// See `harness::lifecycle` on why the parent side avoids embassy.
use async_io::Timer;
use std::time::{Duration, Instant};

use crate::harness::protocol::RunnerMessage;
use crate::harness::{ChildLifecycle, DutMode};
use crate::logger;
use crate::tests::security::context::SecurityTestContext;
use crate::tests::security::crypto;
use crate::*;

// ============================================================================
// TP1 ↔ internal format helpers (unchanged from the old runner)
// ============================================================================

fn tp1_to_internal(tp1: &[u8]) -> Vec<u8> {
    use zweidraehte_proto::encoding::tp1;
    let mut buf = tp1.to_vec();
    buf = tp1::tp1_to_knx_message_no_checksum(buf);
    buf
}

fn internal_to_tp1(internal: &[u8]) -> Vec<u8> {
    use zweidraehte_proto::encoding::tp1;
    let mut buf = internal.to_vec();
    buf = tp1::knx_to_tp1_message_no_checksum(buf);
    buf
}

fn tp1_shrink_per_byte<T: Copy>(per_byte: &[T], tp1_data: &[u8]) -> Vec<T> {
    if tp1_data.is_empty() {
        return per_byte.to_vec();
    }
    if (tp1_data[0] & 0x80) == 0 && per_byte.len() > 1 {
        let mut result: Vec<T> = Vec::with_capacity(per_byte.len() - 1);
        result.push(per_byte[0]);
        result.extend_from_slice(&per_byte[2..]);
        let internal_len = tp1_data.len() - 1;
        result.truncate(internal_len);
        result
    } else {
        per_byte.to_vec()
    }
}

// ============================================================================
// Time scaling — unified single rule (Phase 6 polish pending)
// ============================================================================
//
// The `--realtime` flag disables scaling (divisor = 1). Otherwise we
// divide every millisecond value by the divisor (default 50) with a
// floor of `IPC_FLOOR_MS`. The floor exists because even an empty
// IPC round-trip (socket write → embassy wake → socket read) takes a
// few ms in practice.
//
// The DUT inherits `KNX_TIME_DIVISOR` via environment and scales its
// own TL timers by the same factor when the `conformance` feature is
// enabled, so protocol-level timing stays coherent.

pub const DEFAULT_TIME_DIVISOR: u64 = 50;

/// Floor for `Expect` / `ExpectNone` / `ExpectSecure` timeouts.
///
/// Even with zero protocol delay, the embassy executor needs a few
/// ticks and the IPC socket needs to round-trip the frame.
const EXPECT_FLOOR_MS: u64 = 15;

/// Floor for `Inject` / `InjectSecure` inter-step delays.
///
/// Tests use `delay_before_ms` to let the DUT finish a prior
/// action before the next inject lands. If this floor is set
/// high enough to noticeably delay injects, the DUT's internal
/// TL ACK timer (60 ms in fast mode) fires between injects and
/// the DUT retransmits earlier responses — which then appear as
/// unsolicited frames polluting subsequent expects. Keep this
/// very low so baseline-speed timing is preserved.
const DELAY_FLOOR_MS: u64 = 2;

/// Floor for lifecycle-terminating commands (`PowerCycle`,
/// `MasterReset`). These need time for the DUT to flush state
/// to SHM + write `Exiting` + shutdown the socket — noticeably
/// more than a plain step round-trip.
const LIFECYCLE_FLOOR_MS: u64 = 80;

fn scale_with_floor(ms: u32, divisor: u64, floor: u64) -> u64 {
    if divisor <= 1 {
        return ms as u64;
    }
    (ms as u64 / divisor).max(floor)
}

/// Scale an `Expect`-family timeout.
fn scale_ms(ms: u32, divisor: u64) -> u64 {
    scale_with_floor(ms, divisor, EXPECT_FLOOR_MS)
}

/// Scale a short inter-step delay. Uses the low
/// [`DELAY_FLOOR_MS`] so scaling matches baseline timing — too
/// much delay provokes DUT TL retransmissions that pollute the
/// unsolicited-frame buffer.
fn scale_delay_ms(ms: u32, divisor: u64) -> u64 {
    scale_with_floor(ms, divisor, DELAY_FLOOR_MS)
}

/// Scale a lifecycle-terminating timeout.
fn scale_lifecycle_ms(ms: u32, divisor: u64) -> u64 {
    scale_with_floor(ms, divisor, LIFECYCLE_FLOOR_MS)
}

// ============================================================================
// Step result & context
// ============================================================================

/// Shared outcome type so every per-variant handler has the same
/// return shape. `false` is a test failure; `true` passes.
type StepOk = bool;

/// Per-step runtime context threaded into every `step_*` function.
///
/// Collapsing `sec_ctx` + `variables` + `time_divisor` into one struct
/// keeps new pieces of shared runtime state a single-line edit rather
/// than a 20-signature refactor. Secure steps panic if `sec` is `None`
/// — that invariant is enforced by test authorship, not by type.
pub struct StepContext<'a> {
    /// Security state (keys, sequence numbers). `Some` for secure
    /// suites, `None` for plain.
    pub sec: Option<&'a mut SecurityTestContext>,
    /// Named telegram variables (`#EDI`, `#BDUT_ADDR`, group
    /// addresses) used by `InjectTemplate` / `ExpectTemplate` /
    /// secure templates.
    pub vars: &'a BTreeMap<String, TestVariable>,
    /// Time-scaling divisor passed through to `scale_ms` etc.
    /// Normally 50 (fast mode) or 1 (`--realtime`).
    pub divisor: u64,
}

impl<'a> StepContext<'a> {
    pub fn new(
        sec: Option<&'a mut SecurityTestContext>,
        vars: &'a BTreeMap<String, TestVariable>,
        divisor: u64,
    ) -> Self {
        Self { sec, vars, divisor }
    }

    /// Borrow the security context mutably without consuming the
    /// wrapper. Secure steps that used to take
    /// `Option<&mut SecurityTestContext>` take `&mut StepContext` now
    /// and call this helper.
    #[inline]
    pub fn sec_mut(&mut self) -> Option<&mut SecurityTestContext> {
        self.sec.as_deref_mut()
    }
}

// ============================================================================
// Step dispatch
// ============================================================================

/// Execute one resolved `TestStep`. Dispatches to a per-variant
/// handler. Splitting the 700-line match into named functions makes
/// each variant independently readable and grep-able.
async fn execute_step(
    harness: &mut ChildLifecycle,
    step: &TestStep,
    index: usize,
    ctx: &mut StepContext<'_>,
) -> StepOk {
    match step {
        TestStep::Comment(text) => step_comment(index, text),
        TestStep::Inject { telegram, delay_before_ms } => {
            step_inject(harness, index, &telegram.data, *delay_before_ms, ctx.divisor).await
        }
        TestStep::Expect { matcher, timeout_ms } => {
            step_expect(harness, index, matcher, *timeout_ms, ctx.divisor).await
        }
        TestStep::ExpectBlock { matchers, timeout_ms } => {
            step_expect_block(harness, index, matchers, *timeout_ms, ctx).await
        }
        TestStep::ExpectNone { timeout_ms } => step_expect_none(harness, index, *timeout_ms, ctx.divisor).await,
        TestStep::Wait { duration_ms } => step_wait(index, *duration_ms, ctx.divisor).await,
        TestStep::WallClockWait { duration_ms } => step_wall_clock_wait(index, *duration_ms).await,
        TestStep::Custom => step_custom(index),
        TestStep::SetProgrammingMode(enabled) => step_set_programming_mode(harness, index, *enabled).await,
        TestStep::TriggerRead { asap } => step_trigger_read(harness, index, *asap).await,
        TestStep::TriggerWrite { asap } => step_trigger_write(harness, index, *asap).await,
        TestStep::TriggerSync { peer_ia, tool_access, is_broadcast } => {
            step_trigger_sync(harness, index, *peer_ia, *tool_access, *is_broadcast).await
        }
        TestStep::Drain { settle_ms } => step_drain(harness, index, *settle_ms, ctx.divisor).await,
        TestStep::WaitForRestart { timeout_ms } => step_wait_for_restart(harness, index, *timeout_ms).await,
        TestStep::PowerCycle { timeout_ms } => step_power_cycle(harness, index, *timeout_ms, ctx.divisor).await,
        TestStep::MasterReset { erase_code, timeout_ms } => {
            step_master_reset(harness, index, *erase_code, *timeout_ms, ctx.divisor).await
        }
        TestStep::FullReset { timeout_ms } => {
            let divisor = ctx.divisor;
            step_full_reset(harness, ctx.sec_mut(), index, *timeout_ms, divisor).await
        }
        TestStep::InjectSyncRes { params, delay_before_ms } => {
            step_inject_sync_res(harness, index, params, *delay_before_ms, ctx).await
        }
        TestStep::ResetSecuritySequences => match ctx.sec_mut() {
            Some(sec) => {
                sec.reset_peer_state();
                println!("  [{index}] 🔒 security sequence numbers reset (runner side only)");
                true
            }
            None => {
                println!("  [{index}] ❌ security sequence reset outside a secure suite");
                false
            }
        },
        TestStep::SetSecuritySequence { counter, value } => match ctx.sec_mut() {
            Some(sec) => {
                sec.set_sequence(*counter, *value);
                println!("  [{index}] 🔒 {counter:?} sequence number set to {value}");
                true
            }
            None => {
                println!("  [{index}] ❌ security sequence set outside a secure suite");
                false
            }
        },
        TestStep::InjectTemplate { .. } | TestStep::ExpectTemplate { .. } | TestStep::ExpectBlockTemplate { .. } => {
            println!("  [{}] ❌ Unresolved template", index);
            false
        }
        TestStep::InjectSecure { template, sec_params, delay_before_ms } => {
            step_inject_secure(harness, index, template, sec_params, *delay_before_ms, ctx).await
        }
        TestStep::ExpectSecure { template, sec_params, timeout_ms } => {
            step_expect_secure(harness, index, template, sec_params, *timeout_ms, ctx).await
        }
        TestStep::InjectSecureInvalid { template, sec_params, invalid, delay_before_ms } => {
            step_inject_secure_invalid(harness, index, template, sec_params, invalid, *delay_before_ms, ctx).await
        }
        TestStep::InjectSyncReq { sync_params, delay_before_ms } => {
            step_inject_sync_req(harness, index, sync_params, *delay_before_ms, ctx).await
        }
        TestStep::InjectSyncReqInvalid { sync_params, invalid, delay_before_ms } => {
            step_inject_sync_req_invalid(harness, index, sync_params, invalid, *delay_before_ms, ctx).await
        }
        TestStep::ExpectSyncRes { sync_expect, timeout_ms } => {
            step_expect_sync_res(harness, index, sync_expect, *timeout_ms, ctx).await
        }
        TestStep::ExpectSyncReqThenRespond { params, timeout_ms } => {
            step_expect_sync_req_then_respond(harness, index, params, *timeout_ms, ctx).await
        }
    }
}

// ============================================================================
// Simple steps
// ============================================================================

fn step_comment(index: usize, text: &str) -> StepOk {
    println!("  [{}] 💬 {}", index, text);
    true
}

fn step_custom(index: usize) -> StepOk {
    println!("  [{}] 🔧 Custom step", index);
    true
}

async fn step_wait(index: usize, duration_ms: u32, time_divisor: u64) -> StepOk {
    let effective_ms = scale_ms(duration_ms, time_divisor);
    println!("  [{}] ⏳ Wait {}ms", index, effective_ms);
    Timer::after(Duration::from_millis(effective_ms)).await;
    true
}

async fn step_wall_clock_wait(index: usize, duration_ms: u32) -> StepOk {
    println!("  [{}] ⏳ WallClockWait {}ms", index, duration_ms);
    Timer::after(Duration::from_millis(duration_ms as u64)).await;
    true
}

/// `WaitForRestart` respawns the DUT with post-respawn ROI frames
/// *preserved* in the unsolicited buffer. Use it after an
/// `A_Restart` inject when the test wants to observe the ROI scan
/// (e.g. test 1.4.1.6).
///
/// Without this step, the default path in
/// [`ChildLifecycle::step`] auto-respawns on the next inject and
/// discards ROI — which is what most tests want, since ROI frames
/// would otherwise poison unrelated expects.
async fn step_wait_for_restart(harness: &mut ChildLifecycle, index: usize, _timeout_ms: u32) -> StepOk {
    println!("  [{}] 🔄 WaitForRestart (respawn, preserving ROI)", index);
    match harness.auto_respawn_if_dead(true).await {
        Ok(()) => true,
        Err(e) => {
            println!("        ❌ Failed: {}", e);
            false
        }
    }
}

async fn step_drain(harness: &mut ChildLifecycle, index: usize, settle_ms: u32, time_divisor: u64) -> StepOk {
    let effective_ms = scale_ms(settle_ms, time_divisor);
    println!("  [{}] 🧹 Drain (settle {}ms)", index, effective_ms);
    if effective_ms > 0 {
        Timer::after(Duration::from_millis(effective_ms)).await;
    }
    // Give any in-flight UnsolicitedFrames a chance to land, then
    // discard everything buffered.
    let _ = harness.next_frame(Duration::from_millis(1)).await;
    harness.discard_unsolicited();
    true
}

// ============================================================================
// Inject / expect
// ============================================================================

async fn step_inject(
    harness: &mut ChildLifecycle,
    index: usize,
    data: &[u8],
    delay_before_ms: u32,
    time_divisor: u64,
) -> StepOk {
    println!("  [{}] ⬇️  Inject: {:02X?}", index, data);
    if delay_before_ms > 0 {
        let delay = scale_delay_ms(delay_before_ms, time_divisor);
        println!("        (delay: {}ms)", delay);
        Timer::after(Duration::from_millis(delay)).await;
    }
    let data = data.to_vec();
    match harness.step(|seq| RunnerMessage::Inject { seq, data: data.clone() }).await {
        Ok(n) => {
            if n > 0 {
                log::debug!("Inject produced {} outbox frame(s)", n);
            }
            true
        }
        Err(e) => {
            println!("        ❌ Inject failed: {}", e);
            false
        }
    }
}

async fn step_expect(
    harness: &mut ChildLifecycle,
    index: usize,
    matcher: &TelegramMatcher,
    timeout_ms: u32,
    time_divisor: u64,
) -> StepOk {
    let ms = if timeout_ms == 0 { scale_ms(1000, time_divisor) } else { scale_ms(timeout_ms, time_divisor) };
    println!("  [{}] ⬆️  Expect: {:02X?} ({}ms)", index, matcher.expected, ms);
    match harness.next_frame(Duration::from_millis(ms)).await {
        Ok(Some(tagged)) => {
            let data = &tagged.message.data;
            if matcher.matches(data) {
                println!("        ✅ Matched: {:02X?}", data.as_slice());
                true
            } else {
                println!("        ❌ Mismatch!");
                println!("           Expected: {:02X?}", matcher.expected);
                println!("           Got:      {:02X?}  (source: {})", data.as_slice(), tagged.source.label());
                false
            }
        }
        Ok(None) => {
            println!("        ⏰ Timeout: No message received within {}ms", ms);
            false
        }
        Err(e) => {
            println!("        ⚠️  Socket error: {}", e);
            false
        }
    }
}

/// Match a block of telegrams in any order within a single window.
///
/// Mirrors EITT's "block of OUT telegrams" semantics (see
/// EITT manual §11.2.3.6) for spec tests where the order of two or
/// more outbound telegrams is not constrained — today only the
/// GO-diagnostics tests 6.2.7 / 6.2.11 / 6.2.15.
///
/// Algorithm: read frames sequentially up to `timeout_ms`. For each
/// frame, try every still-unmatched block element; secure elements
/// attempt to decrypt with their `sec_params` first, plain elements
/// match raw bytes. The first matching element claims the frame.
/// A frame that matches no remaining element fails the step. Success
/// when every element is matched.
async fn step_expect_block(
    harness: &mut ChildLifecycle,
    index: usize,
    matchers: &[BlockExpect],
    timeout_ms: u32,
    ctx: &mut StepContext<'_>,
) -> StepOk {
    let time_divisor = ctx.divisor;
    let ms = if timeout_ms == 0 { scale_ms(1000, time_divisor) } else { scale_ms(timeout_ms, time_divisor) };
    println!("  [{}] ⬆️⬆️  ExpectBlock ({} elements, total window {}ms)", index, matchers.len(), ms);

    let needs_secure = matchers.iter().any(|m| matches!(m, BlockExpect::Secure { .. }));
    if needs_secure && ctx.sec_mut().is_none() {
        println!("        ❌ ExpectBlock with Secure element used without SecurityTestContext");
        return false;
    }

    let mut claimed = vec![false; matchers.len()];
    let deadline = Instant::now() + Duration::from_millis(ms);

    'frames: while claimed.iter().any(|c| !c) {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        let tagged = match harness.next_frame(remaining).await {
            Ok(Some(t)) => t,
            Ok(None) => break,
            Err(e) => {
                println!("        ⚠️  Socket error: {}", e);
                return false;
            }
        };

        let raw = tagged.message.data.as_slice().to_vec();
        let internal = tp1_to_internal(&raw);

        // Try secure elements first — only they have a chance to
        // unwrap a wrapped frame; plain elements would never match
        // a secure-on-the-wire payload.
        for (i, expect) in matchers.iter().enumerate() {
            if claimed[i] {
                continue;
            }
            if let BlockExpect::Secure { matcher, sec_params } = expect {
                let Some(sec) = ctx.sec_mut() else { continue };
                if let Some(plaintext_apdu) = crypto::unwrap_secure(&internal, sec_params, sec) {
                    let mut plain_internal = internal[..6].to_vec();
                    plain_internal.extend_from_slice(&plaintext_apdu);
                    let expected_internal = tp1_to_internal(&matcher.expected);
                    let masks_internal = tp1_shrink_per_byte(&matcher.masks, &matcher.expected);
                    let wildcards_internal = tp1_shrink_per_byte(&matcher.wildcards, &matcher.expected);
                    let internal_matcher = TelegramMatcher {
                        expected: expected_internal,
                        masks: masks_internal,
                        wildcards: wildcards_internal,
                    };
                    if internal_matcher.matches(&plain_internal) {
                        println!("        ✅ Secure element {} matched (key={})", i, sec_params.key_name);
                        claimed[i] = true;
                        continue 'frames;
                    }
                }
            }
        }

        // Plain elements match the raw on-wire bytes.
        for (i, expect) in matchers.iter().enumerate() {
            if claimed[i] {
                continue;
            }
            if let BlockExpect::Plain { matcher } = expect {
                if matcher.matches(&raw) {
                    println!("        ✅ Plain element {} matched: {:02X?}", i, raw);
                    claimed[i] = true;
                    continue 'frames;
                }
            }
        }

        println!("        ❌ Frame matched no remaining block element (source: {})", tagged.source.label());
        println!("           Got: {:02X?}", raw);
        for (i, expect) in matchers.iter().enumerate() {
            if claimed[i] {
                continue;
            }
            match expect {
                BlockExpect::Plain { matcher } => {
                    println!("           Pending plain[{}]: {:02X?}", i, matcher.expected);
                }
                BlockExpect::Secure { matcher, sec_params } => {
                    println!(
                        "           Pending secure[{}] (key={}): {:02X?}",
                        i, sec_params.key_name, matcher.expected
                    );
                }
            }
        }
        return false;
    }

    if claimed.iter().all(|c| *c) {
        true
    } else {
        println!("        ⏰ Timeout: block window expired with unmatched elements");
        for (i, expect) in matchers.iter().enumerate() {
            if !claimed[i] {
                match expect {
                    BlockExpect::Plain { matcher } => {
                        println!("           Missing plain[{}]: {:02X?}", i, matcher.expected);
                    }
                    BlockExpect::Secure { matcher, sec_params } => {
                        println!(
                            "           Missing secure[{}] (key={}): {:02X?}",
                            i, sec_params.key_name, matcher.expected
                        );
                    }
                }
            }
        }
        false
    }
}

async fn step_expect_none(harness: &mut ChildLifecycle, index: usize, timeout_ms: u32, time_divisor: u64) -> StepOk {
    let ms = scale_ms(timeout_ms, time_divisor);
    println!("  [{}] 🚫 ExpectNone (timeout {}ms)", index, ms);
    match harness.next_frame(Duration::from_millis(ms)).await {
        Ok(Some(tagged)) => {
            println!("        ❌ Unexpected message received!");
            println!("           Got: {:02X?}  (source: {})", tagged.message.data.as_slice(), tagged.source.label());
            false
        }
        Ok(None) => {
            println!("        ✅ No message received (as expected)");
            true
        }
        Err(e) => {
            // A socket-level disconnect during ExpectNone is treated
            // as a pass — the DUT clearly didn't send us anything.
            println!("        ✅ No message (socket: {})", e);
            true
        }
    }
}

// ============================================================================
// Triggers
// ============================================================================

async fn step_set_programming_mode(harness: &mut ChildLifecycle, index: usize, enabled: bool) -> StepOk {
    println!("  [{}] 🔧 SetProgrammingMode({})", index, enabled);
    match harness.step(|seq| RunnerMessage::SetProgrammingMode { seq, enabled }).await {
        Ok(_) => true,
        Err(e) => {
            println!("        ❌ Failed: {}", e);
            false
        }
    }
}

async fn step_trigger_read(harness: &mut ChildLifecycle, index: usize, asap: u16) -> StepOk {
    println!("  [{}] 📤 TriggerRead(ASAP {})", index, asap);
    match harness.step(|seq| RunnerMessage::TriggerRead { seq, asap }).await {
        Ok(_) => true,
        Err(e) => {
            println!("        ❌ Failed: {}", e);
            false
        }
    }
}

async fn step_trigger_write(harness: &mut ChildLifecycle, index: usize, asap: u16) -> StepOk {
    println!("  [{}] 📤 TriggerWrite(ASAP {})", index, asap);
    match harness.step(|seq| RunnerMessage::TriggerWrite { seq, asap }).await {
        Ok(_) => true,
        Err(e) => {
            println!("        ❌ Failed: {}", e);
            false
        }
    }
}

async fn step_trigger_sync(
    harness: &mut ChildLifecycle,
    index: usize,
    peer_ia: u16,
    tool_access: bool,
    is_broadcast: bool,
) -> StepOk {
    println!("  [{}] TriggerSync(peer={:#06X}, tool={}, broadcast={})", index, peer_ia, tool_access, is_broadcast);
    match harness.step(|seq| RunnerMessage::TriggerSync { seq, peer_ia, tool_access, is_broadcast }).await {
        Ok(_) => true,
        Err(e) => {
            println!("        Failed: {}", e);
            false
        }
    }
}

// ============================================================================
// Lifecycle commands
// ============================================================================

async fn step_power_cycle(harness: &mut ChildLifecycle, index: usize, timeout_ms: u32, time_divisor: u64) -> StepOk {
    let ms = scale_lifecycle_ms(timeout_ms, time_divisor);
    println!("  [{}] 🔌 PowerCycle (timeout {}ms)", index, ms);
    match harness.step_exiting(RunnerMessage::PowerCycle, Duration::from_millis(ms)).await {
        Ok(_) => {
            println!("        ✅ DUT power-cycled");
            true
        }
        Err(e) => {
            println!("        ❌ Failed: {}", e);
            false
        }
    }
}

async fn step_master_reset(
    harness: &mut ChildLifecycle,
    index: usize,
    erase_code: u8,
    timeout_ms: u32,
    time_divisor: u64,
) -> StepOk {
    let ms = scale_lifecycle_ms(timeout_ms, time_divisor);
    println!("  [{}] ♻️  MasterReset(erase=0x{:02x}, timeout {}ms)", index, erase_code, ms);
    match harness.step_exiting(RunnerMessage::MasterReset { erase_code }, Duration::from_millis(ms)).await {
        Ok(_) => {
            println!("        ✅ DUT reset");
            true
        }
        Err(e) => {
            println!("        ❌ Failed: {}", e);
            false
        }
    }
}

async fn step_full_reset(
    harness: &mut ChildLifecycle,
    sec_ctx: Option<&mut SecurityTestContext>,
    index: usize,
    _timeout_ms: u32,
    _time_divisor: u64,
) -> StepOk {
    println!("  [{}] 🏭 FullReset (wipe SHM + respawn)", index);
    if let Err(e) = harness.full_reset().await {
        println!("        ❌ Failed to full-reset DUT: {}", e);
        return false;
    }
    // Any persisted sec_ctx is stale because the DUT is factory-fresh.
    if let Some(ctx) = sec_ctx {
        ctx.reset_peer_state();
    }
    println!("        ✅ DUT fully reset to defaults");
    true
}

// ============================================================================
// Secure steps
// ============================================================================

async fn step_inject_secure(
    harness: &mut ChildLifecycle,
    index: usize,
    template: &str,
    sec_params: &SecureParams,
    delay_before_ms: u32,
    ctx: &mut StepContext<'_>,
) -> StepOk {
    let time_divisor = ctx.divisor;
    let variables = ctx.vars;
    let Some(sec) = ctx.sec_mut() else {
        println!("  [{}] ❌ InjectSecure used without SecurityTestContext", index);
        return false;
    };
    let plaintext = match Telegram::parse(template, variables) {
        Ok(t) => t,
        Err(e) => {
            println!("  [{}] ❌ Template error: {}", index, e);
            return false;
        }
    };
    let internal = tp1_to_internal(&plaintext.data);
    let secure_internal = crypto::wrap_secure(&internal, sec_params, sec);
    let secure_tp1 = internal_to_tp1(&secure_internal);
    println!(
        "  [{}] 🔒⬇️  InjectSecure ({:?}, key={}): {} bytes",
        index,
        sec_params.sec_type,
        sec_params.key_name,
        secure_tp1.len()
    );
    if delay_before_ms > 0 {
        Timer::after(Duration::from_millis(scale_delay_ms(delay_before_ms, time_divisor))).await;
    }
    match harness.step(|seq| RunnerMessage::Inject { seq, data: secure_tp1.clone() }).await {
        Ok(_) => true,
        Err(e) => {
            println!("        ❌ Inject failed: {}", e);
            false
        }
    }
}

async fn step_expect_secure(
    harness: &mut ChildLifecycle,
    index: usize,
    template: &str,
    sec_params: &SecureParams,
    timeout_ms: u32,
    ctx: &mut StepContext<'_>,
) -> StepOk {
    let time_divisor = ctx.divisor;
    let variables = ctx.vars;
    let Some(sec) = ctx.sec_mut() else {
        println!("  [{}] ❌ ExpectSecure used without SecurityTestContext", index);
        return false;
    };
    let ms = if timeout_ms == 0 { scale_ms(1000, time_divisor) } else { scale_ms(timeout_ms, time_divisor) };
    println!(
        "  [{}] 🔒⬆️  ExpectSecure ({:?}, key={}, timeout={}ms)",
        index, sec_params.sec_type, sec_params.key_name, ms
    );

    // Skip stray plain control frames (most often a `T_Disconnect`
    // emitted when the DUT's TL connection-idle timer fires after the
    // last legitimate response) until we either consume the genuine
    // secure response or exhaust the budget. The deadline spans the
    // whole loop, so a flood of plain frames cannot extend the
    // effective timeout — same shape as `step_expect_block` above.
    let deadline = Instant::now() + Duration::from_millis(ms);
    loop {
        let now = Instant::now();
        if now >= deadline {
            println!("        ❌ Timeout (no secure response)");
            return false;
        }
        let remaining = deadline - now;
        let tagged = match harness.next_frame(remaining).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                println!("        ❌ Timeout (no secure response)");
                return false;
            }
            Err(e) => {
                println!("        ❌ Socket error: {}", e);
                return false;
            }
        };

        let internal = tp1_to_internal(&tagged.message.data);
        let Some(plaintext_apdu) = crypto::unwrap_secure(&internal, sec_params, sec) else {
            log::debug!(
                "step_expect_secure: skipping non-Secure frame from {}: {:02X?}",
                tagged.source.label(),
                tagged.message.data
            );
            continue;
        };

        let mut plain_internal = internal[..6].to_vec();
        plain_internal.extend_from_slice(&plaintext_apdu);
        let matcher = match TelegramMatcher::parse(template, variables) {
            Ok(m) => m,
            Err(e) => {
                println!("        ❌ Template error: {}", e);
                return false;
            }
        };
        let expected_internal = tp1_to_internal(&matcher.expected);
        let masks_internal = tp1_shrink_per_byte(&matcher.masks, &matcher.expected);
        let wildcards_internal = tp1_shrink_per_byte(&matcher.wildcards, &matcher.expected);
        let internal_matcher =
            TelegramMatcher { expected: expected_internal, masks: masks_internal, wildcards: wildcards_internal };
        return if internal_matcher.matches(&plain_internal) {
            println!("        ✅ Secure response matches");
            true
        } else {
            println!("        ❌ Plaintext mismatch (source: {}):", tagged.source.label());
            println!("           {}", internal_matcher.diff(&plain_internal));
            false
        };
    }
}

async fn step_inject_secure_invalid(
    harness: &mut ChildLifecycle,
    index: usize,
    template: &str,
    sec_params: &SecureParams,
    invalid: &InvalidSecurityParam,
    delay_before_ms: u32,
    ctx: &mut StepContext<'_>,
) -> StepOk {
    let time_divisor = ctx.divisor;
    let variables = ctx.vars;
    let Some(sec) = ctx.sec_mut() else {
        println!("  [{}] ❌ InjectSecureInvalid used without SecurityTestContext", index);
        return false;
    };
    let plaintext = match Telegram::parse(template, variables) {
        Ok(t) => t,
        Err(e) => {
            println!("  [{}] ❌ Template error: {}", index, e);
            return false;
        }
    };
    let internal = tp1_to_internal(&plaintext.data);
    let secure_internal = crypto::wrap_secure_invalid(&internal, sec_params, sec, invalid);
    let secure_tp1 = internal_to_tp1(&secure_internal);
    println!("  [{}] 🔒💥⬇️  InjectSecureInvalid ({:?}): {} bytes", index, invalid, secure_tp1.len());
    if delay_before_ms > 0 {
        Timer::after(Duration::from_millis(scale_delay_ms(delay_before_ms, time_divisor))).await;
    }
    match harness.step(|seq| RunnerMessage::Inject { seq, data: secure_tp1.clone() }).await {
        Ok(_) => true,
        Err(e) => {
            println!("        ❌ Inject failed: {}", e);
            false
        }
    }
}

// ============================================================================
// Sync (S-A_Sync_Req / _Res)
// ============================================================================

async fn step_inject_sync_req(
    harness: &mut ChildLifecycle,
    index: usize,
    sync_params: &SyncReqParams,
    delay_before_ms: u32,
    ctx: &mut StepContext<'_>,
) -> StepOk {
    let time_divisor = ctx.divisor;
    let variables = ctx.vars;
    let Some(sec) = ctx.sec_mut() else {
        println!("  [{}] ❌ InjectSyncReq requires security context", index);
        return false;
    };
    let key = sec.key(&sync_params.key_name);
    // Resolved here rather than at lowering time: a named counter means
    // whatever it holds now, and a request sent after a reset has to say
    // so. Peeking, not consuming — the request advertises the next
    // number, it does not spend one.
    let seq_local = sec.peek_sequence(&sync_params.seq_local);
    let seq_nr_local = crate::tests::security::context::seq_to_bytes(seq_local);

    let src_bytes = Telegram::parse(&format!("00 00 {} 00 00 00 00", sync_params.src_template), variables)
        .map(|t| u16::from_be_bytes([t.data[2], t.data[3]]))
        .unwrap_or(0);
    let dst_bytes = Telegram::parse(&format!("00 00 00 00 {} 00 00", sync_params.dst_template), variables)
        .map(|t| u16::from_be_bytes([t.data[4], t.data[5]]))
        .unwrap_or(0);

    let scf = zweidraehte_proto::crypto::scf::SecurityControlField {
        service: zweidraehte_proto::crypto::scf::SecureServiceType::SyncRequest,
        system_broadcast: sync_params.system_broadcast,
        confidentiality: true,
        tool_access: sync_params.tool_access,
    };
    let scf_byte = scf.encode();

    let frame = crypto::wrap_sync_req(
        sync_params.ctrl_byte,
        src_bytes,
        dst_bytes,
        sync_params.npdu_byte,
        sync_params.tpci_high,
        &key,
        scf_byte,
        &seq_nr_local,
        &sync_params.serial_number,
        &sync_params.challenge,
    );

    let tp1 = internal_to_tp1(&frame);
    println!("  [{}] 🔄⬇️  InjectSyncReq: {} bytes, seqLocal={}", index, tp1.len(), seq_local);
    if delay_before_ms > 0 {
        Timer::after(Duration::from_millis(scale_delay_ms(delay_before_ms, time_divisor))).await;
    }
    match harness.step(|seq| RunnerMessage::Inject { seq, data: tp1.clone() }).await {
        Ok(_) => true,
        Err(e) => {
            println!("        ❌ Inject failed: {}", e);
            false
        }
    }
}

async fn step_inject_sync_req_invalid(
    harness: &mut ChildLifecycle,
    index: usize,
    sync_params: &SyncReqParams,
    invalid: &InvalidSecurityParam,
    delay_before_ms: u32,
    ctx: &mut StepContext<'_>,
) -> StepOk {
    let time_divisor = ctx.divisor;
    let variables = ctx.vars;
    let Some(sec) = ctx.sec_mut() else {
        println!("  [{}] ❌ InjectSyncReqInvalid requires security context", index);
        return false;
    };
    let key = sec.key(&sync_params.key_name);
    // Resolved here rather than at lowering time: a named counter means
    // whatever it holds now, and a request sent after a reset has to say
    // so. Peeking, not consuming — the request advertises the next
    // number, it does not spend one.
    let seq_local = sec.peek_sequence(&sync_params.seq_local);
    let seq_nr_local = crate::tests::security::context::seq_to_bytes(seq_local);

    let src_bytes = Telegram::parse(&format!("00 00 {} 00 00 00 00", sync_params.src_template), variables)
        .map(|t| u16::from_be_bytes([t.data[2], t.data[3]]))
        .unwrap_or(0);
    let dst_bytes = Telegram::parse(&format!("00 00 00 00 {} 00 00", sync_params.dst_template), variables)
        .map(|t| u16::from_be_bytes([t.data[4], t.data[5]]))
        .unwrap_or(0);

    let scf = zweidraehte_proto::crypto::scf::SecurityControlField {
        service: zweidraehte_proto::crypto::scf::SecureServiceType::SyncRequest,
        system_broadcast: sync_params.system_broadcast,
        confidentiality: true,
        tool_access: sync_params.tool_access,
    };
    let scf_byte = scf.encode();

    let frame = crypto::wrap_sync_req_invalid(
        sync_params.ctrl_byte,
        src_bytes,
        dst_bytes,
        sync_params.npdu_byte,
        sync_params.tpci_high,
        &key,
        scf_byte,
        &seq_nr_local,
        &sync_params.serial_number,
        &sync_params.challenge,
        invalid,
    );

    let tp1 = internal_to_tp1(&frame);
    println!("  [{}] 🔄💥⬇️  InjectSyncReqInvalid ({:?}): {} bytes", index, invalid, tp1.len());
    if delay_before_ms > 0 {
        Timer::after(Duration::from_millis(scale_delay_ms(delay_before_ms, time_divisor))).await;
    }
    match harness.step(|seq| RunnerMessage::Inject { seq, data: tp1.clone() }).await {
        Ok(_) => true,
        Err(e) => {
            println!("        ❌ Inject failed: {}", e);
            false
        }
    }
}

async fn step_expect_sync_res(
    harness: &mut ChildLifecycle,
    index: usize,
    sync_expect: &SyncResExpect,
    timeout_ms: u32,
    ctx: &mut StepContext<'_>,
) -> StepOk {
    let time_divisor = ctx.divisor;
    let Some(sec) = ctx.sec_mut() else {
        println!("  [{}] ❌ ExpectSyncRes requires security context", index);
        return false;
    };
    let ms = scale_ms(timeout_ms, time_divisor);
    println!("  [{}] 🔄⬆️  ExpectSyncRes (timeout={}ms)", index, ms);

    let tagged = match harness.next_frame(Duration::from_millis(ms)).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            println!("        ❌ Timeout waiting for sync response");
            return false;
        }
        Err(e) => {
            println!("        ❌ Socket error: {}", e);
            return false;
        }
    };

    let internal = tp1_to_internal(&tagged.message.data);
    let key = sec.key(&sync_expect.key_name);
    match crypto::unwrap_sync_res(&internal, &key, &sync_expect.challenge) {
        Some(decoded) => {
            let seq_remote = crate::tests::security::context::seq_from_bytes(&decoded.seq_nr_remote);
            let seq_local = crate::tests::security::context::seq_from_bytes(&decoded.seq_nr_local);
            println!("        SeqNr_remote={}, SeqNr_local={}", seq_remote, seq_local);

            let mut ok = true;
            if let Some(expected) = sync_expect.expected_seq_remote {
                if seq_remote != expected {
                    println!("        ❌ SeqNr_remote: expected {}, got {}", expected, seq_remote);
                    ok = false;
                }
            }
            if let Some(expected) = sync_expect.expected_seq_local {
                if seq_local != expected {
                    println!("        ❌ SeqNr_local: expected {}, got {}", expected, seq_local);
                    ok = false;
                }
            }

            sec.update_table_seq(seq_remote);
            if sync_expect.tool_access && seq_local > sec.tool_seq_nr {
                sec.tool_seq_nr = seq_local;
            }
            if ok {
                println!("        ✅ Sync response matches");
            }
            ok
        }
        None => {
            println!("        ❌ Sync response decryption/verification failed");
            false
        }
    }
}

/// Inject an S-A_Sync_Res that answers nothing.
///
/// `crypto::wrap_sync_res` builds a response around the request it
/// answers, so an unsolicited one needs a stand-in: the fields it reads
/// are the SCF, the challenge, and the address the request came from.
/// All three are in the step's own parameters, because when there is no
/// request the template has to say what the response claims to answer.
async fn step_inject_sync_res(
    harness: &mut ChildLifecycle,
    index: usize,
    params: &crate::SyncResInject,
    delay_before_ms: u32,
    ctx: &mut StepContext<'_>,
) -> StepOk {
    let time_divisor = ctx.divisor;
    let variables = ctx.vars;
    let Some(sec) = ctx.sec_mut() else {
        println!("  [{index}] InjectSyncRes requires security context");
        return false;
    };
    if delay_before_ms > 0 {
        Timer::after(Duration::from_millis(scale_ms(delay_before_ms, time_divisor) as u64)).await;
    }

    let addr = |tmpl: &str| -> u16 {
        Telegram::parse(&format!("00 00 {tmpl} 00 00 00 00"), variables)
            .map(|t| u16::from_be_bytes([t.data[2], t.data[3]]))
            .unwrap_or(0)
    };
    let us = addr(&params.src_template);
    let device = addr(&params.dst_template);

    let scf = zweidraehte_proto::crypto::scf::SecurityControlField {
        service: zweidraehte_proto::crypto::scf::SecureServiceType::SyncRequest,
        system_broadcast: params.system_broadcast,
        confidentiality: true,
        tool_access: params.tool_access,
    };
    // `wrap_sync_res` reads `src` as "who asked", and answers back to
    // it, so the stand-in request is the device asking us.
    let stand_in = crypto::SyncReqDecrypted {
        challenge: params.challenge,
        seq_nr_local: crate::tests::security::context::seq_to_bytes(params.seq_nr_local),
        scf_byte: scf.encode(),
        src: device,
        dst: us,
        addr_type: params.npdu_byte,
        tpci_apci: u16::from_be_bytes([params.tpci_high | 0x03, 0xF1]),
        serial_number: [0u8; 6],
    };

    let key = sec.key(&params.key_name);
    let frame = crypto::wrap_sync_res(
        &stand_in,
        &key,
        &crate::tests::security::context::seq_to_bytes(params.seq_nr_remote),
        &crate::tests::security::context::seq_to_bytes(params.seq_nr_local),
        us,
        Some(params.system_broadcast),
    );

    let tp1 = internal_to_tp1(&frame);
    println!(
        "  [{index}] 🔒⬇️  InjectSyncRes (unsolicited, key={}): {} bytes, seqRemote={}, seqLocal={}",
        params.key_name,
        tp1.len(),
        params.seq_nr_remote,
        params.seq_nr_local
    );
    harness.step(|seq| RunnerMessage::Inject { seq, data: tp1.clone() }).await.is_ok()
}

async fn step_expect_sync_req_then_respond(
    harness: &mut ChildLifecycle,
    index: usize,
    params: &SyncResponseParams,
    timeout_ms: u32,
    ctx: &mut StepContext<'_>,
) -> StepOk {
    let time_divisor = ctx.divisor;
    let variables = ctx.vars;
    let Some(sec) = ctx.sec_mut() else {
        println!("  [{}] ExpectSyncReqThenRespond requires security context", index);
        return false;
    };
    let ms = scale_ms(timeout_ms, time_divisor);
    println!("  [{}] ExpectSyncReqThenRespond (timeout={}ms)", index, ms);

    let tagged = match harness.next_frame(Duration::from_millis(ms)).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            println!("        Timeout waiting for DUT sync request");
            return false;
        }
        Err(e) => {
            println!("        Socket error: {}", e);
            return false;
        }
    };

    let internal = tp1_to_internal(&tagged.message.data);
    let key = sec.key(&params.key_name);
    let Some(decoded_req) = crypto::unwrap_sync_req(&internal, &key) else {
        println!("        Failed to decrypt DUT sync request (source: {})", tagged.source.label());
        return false;
    };
    let seq_local_val = crate::tests::security::context::seq_from_bytes(&decoded_req.seq_nr_local);
    println!("        DUT SyncReq: SeqNr_local={}, challenge={:02x?}", seq_local_val, decoded_req.challenge);

    let seq_nr_remote = crate::tests::security::context::seq_to_bytes(params.seq_nr_remote);
    let seq_nr_local = crate::tests::security::context::seq_to_bytes(params.seq_nr_local);
    let response_src = Telegram::parse(&format!("00 00 {} 00 00 00 00", params.src_template), variables)
        .map(|t| u16::from_be_bytes([t.data[2], t.data[3]]))
        .unwrap_or(0);

    let response = crypto::wrap_sync_res(
        &decoded_req,
        &key,
        &seq_nr_remote,
        &seq_nr_local,
        response_src,
        Some(params.system_broadcast),
    );

    let tp1 = internal_to_tp1(&response);
    println!(
        "        Injecting SyncRes: {} bytes, seqRemote={}, seqLocal={}",
        tp1.len(),
        params.seq_nr_remote,
        params.seq_nr_local
    );
    match harness.step(|seq| RunnerMessage::Inject { seq, data: tp1.clone() }).await {
        Ok(_) => true,
        Err(e) => {
            println!("        Inject SyncRes failed: {}", e);
            false
        }
    }
}

// ============================================================================
// Suite execution
// ============================================================================

/// Knobs the caller supplies once per run.
pub struct EngineOptions {
    /// Time-scaling divisor. 1 is realtime; the default fast mode is
    /// [`DEFAULT_TIME_DIVISOR`].
    pub divisor: u64,
    /// Which DUT binary to drive.
    pub dut_mode: DutMode,
    /// Case-name filters. If any filter matches a case name in the
    /// supplied suites, only matching cases run; otherwise the filters
    /// are treated as having selected whole suites already and every
    /// case runs.
    pub case_filters: Vec<String>,
}

/// What a run produced. Callers add their own out-of-band results (the
/// socket-level IP Secure suite, for instance) before printing.
#[derive(Debug, Default, Clone, Copy)]
pub struct Summary {
    pub suites: usize,
    pub tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub steps: usize,
}

/// Case-insensitive substring match, the filter rule both binaries use.
pub fn matches_filter(name: &str, filter: &str) -> bool {
    name.to_lowercase().contains(&filter.to_lowercase())
}

/// Run every suite against a freshly spawned DUT child and report the
/// tally.
///
/// Spawns the child, waits for `Ready` + `RoiComplete`, then walks
/// suite preparation → cases → suite teardown. Startup read-on-init
/// frames are dropped: tests that care about ROI trigger it explicitly
/// with `A_Restart` and observe the post-restart scan.
pub async fn run_suites(suites: &[TestSuite], opts: &EngineOptions) -> Summary {
    let time_divisor = opts.divisor;
    let filters = &opts.case_filters;
    let has_test_case_filter =
        filters.iter().any(|f| suites.iter().any(|s| s.cases.iter().any(|c| matches_filter(&c.name, f))));

    let mut harness = ChildLifecycle::new(opts.dut_mode).expect("create child lifecycle");
    println!("DUT mode: {}", match opts.dut_mode {
        DutMode::SystemBSecure => "System B secure (conformance-dut-systemb-secure)",
        DutMode::SystemB => "System B (conformance-dut-systemb)",
        DutMode::System7 => "System 7 (conformance-dut-system7)",
        DutMode::System7Secure => "System 7 secure (conformance-dut-system7-secure)",
    });

    harness.spawn_and_wait_roi().await.expect("spawn DUT child");
    harness.discard_unsolicited();

    let mut summary = Summary { suites: suites.len(), ..Default::default() };
    let mut persistent_sec_ctx: Option<SecurityTestContext> = None;

    // Cross-suite plain→secure reset hook: the first secure suite needs
    // a DUT whose sequence-number state has not been touched by the
    // plain suites that ran before it.
    let mut prev_was_secure = false;

    for suite in suites {
        if suite.use_secure_dut && !prev_was_secure && opts.dut_mode == DutMode::SystemBSecure {
            println!("🔁 Resetting DUT before first secure suite (clean seqnr + volatile state)");
            harness.kill().await;
            harness.reset_shared_memory().expect("reset shared memory before secure suite");
            harness.spawn_and_wait_roi().await.expect("respawn DUT child");
            harness.discard_unsolicited();
            persistent_sec_ctx = None;
        }
        prev_was_secure = suite.use_secure_dut;

        println!("====================================================================");
        println!("Suite: {}", suite.name);
        println!("--------------------------------------------------------------------");
        println!("Variables:");
        for (name, var) in &suite.variables {
            println!("  #{}: {:02X?}", name, var.as_bytes());
        }
        println!();

        let mut sec_ctx = if suite.use_secure_dut {
            let mut ctx =
                persistent_sec_ctx.take().unwrap_or_else(crate::tests::security::variables::create_security_context);
            ctx.table_seq_nr = 1;
            Some(ctx)
        } else {
            None
        };

        if !suite.preparation.is_empty() {
            println!("Preparation:");
            println!("--------------------------------------------------------------------");
            // Drop any unsolicited frames left over from the previous
            // suite — most often post-restart ROI from the last test.
            harness.discard_unsolicited();
            let mut prep_passed = true;
            for (i, step) in suite.preparation.iter().enumerate() {
                let resolved_step = match step.resolve(&suite.variables) {
                    Ok(s) => s,
                    Err(e) => {
                        println!("  [{}] ❌ Template error: {}", i, e);
                        prep_passed = false;
                        continue;
                    }
                };
                if !execute_step(
                    &mut harness,
                    &resolved_step,
                    i,
                    &mut StepContext::new(sec_ctx.as_mut(), &suite.variables, time_divisor),
                )
                .await
                {
                    prep_passed = false;
                }
                summary.steps += 1;
            }

            if prep_passed {
                println!("✅ Preparation completed successfully\n");
            } else {
                println!("❌ Preparation failed - skipping suite tests\n");
                continue;
            }
        }

        for test in &suite.cases {
            if has_test_case_filter && !filters.iter().any(|f| matches_filter(&test.name, f)) {
                continue;
            }
            summary.tests += 1;

            // Between tests, discard leftover outbox frames so one
            // test's stray response can't match the next test's
            // Expect. The 30 ms window first gives in-flight
            // asynchronous frames (timer-driven retransmits,
            // post-restart ROI bleeding past RoiComplete) a chance to
            // land so they get dropped too.
            let _ = harness.next_frame(Duration::from_millis(30)).await;
            harness.discard_unsolicited();

            logger::start_test(&test.name);
            println!("Test: {}", test.name);
            println!("----------------------------------------------------------------------");
            let mut test_passed = true;

            if !test.preparation.is_empty() {
                println!("  --- Preparation ---------------------------------------------------");
                for (i, step) in test.preparation.iter().enumerate() {
                    let resolved_step = match step.resolve(&suite.variables) {
                        Ok(s) => s,
                        Err(e) => {
                            println!("  [P{}] ❌ Template error: {}", i, e);
                            test_passed = false;
                            continue;
                        }
                    };
                    if !execute_step(
                        &mut harness,
                        &resolved_step,
                        i,
                        &mut StepContext::new(sec_ctx.as_mut(), &suite.variables, time_divisor),
                    )
                    .await
                    {
                        test_passed = false;
                    }
                }
                summary.steps += test.preparation.len();
                println!("  --- Steps ---------------------------------------------------------");
            }

            for (i, step) in test.steps.iter().enumerate() {
                let resolved_step = match step.resolve(&suite.variables) {
                    Ok(s) => s,
                    Err(e) => {
                        println!("  [{}] ❌ Template error: {}", i, e);
                        test_passed = false;
                        continue;
                    }
                };
                if !execute_step(
                    &mut harness,
                    &resolved_step,
                    i,
                    &mut StepContext::new(sec_ctx.as_mut(), &suite.variables, time_divisor),
                )
                .await
                {
                    test_passed = false;
                }
            }
            summary.steps += test.steps.len();

            if !test.teardown.is_empty() {
                println!("  --- Teardown ------------------------------------------------------");
                for (i, step) in test.teardown.iter().enumerate() {
                    let resolved_step = match step.resolve(&suite.variables) {
                        Ok(s) => s,
                        Err(e) => {
                            println!("  [T{}] ⚠️  Template error: {}", i, e);
                            continue;
                        }
                    };
                    execute_step(
                        &mut harness,
                        &resolved_step,
                        i,
                        &mut StepContext::new(sec_ctx.as_mut(), &suite.variables, time_divisor),
                    )
                    .await;
                }
                summary.steps += test.teardown.len();
            }

            let logs = logger::end_test();
            println!("----------------------------------------------------------------------");
            if test_passed {
                println!("  ✅ PASSED");
                logger::print_log_summary(&logs, "  ");
                summary.passed += 1;
            } else {
                println!("  ❌ FAILED");
                logger::print_log_summary(&logs, "  ");
                if !logs.is_empty() {
                    println!("  --- Stack Trace ---------------------------------------------------");
                    logger::print_logs(&logs, "    ");
                }
                summary.failed += 1;
            }
            println!();
        }

        if !suite.teardown.is_empty() {
            println!("Teardown:");
            println!("--------------------------------------------------------------------");
            for (i, step) in suite.teardown.iter().enumerate() {
                let resolved_step = match step.resolve(&suite.variables) {
                    Ok(s) => s,
                    Err(e) => {
                        println!("  [{}] ❌ Template error: {}", i, e);
                        continue;
                    }
                };
                execute_step(
                    &mut harness,
                    &resolved_step,
                    i,
                    &mut StepContext::new(sec_ctx.as_mut(), &suite.variables, time_divisor),
                )
                .await;
                summary.steps += 1;
            }
            println!("✅ Teardown completed\n");
        }

        if sec_ctx.is_some() {
            persistent_sec_ctx = sec_ctx;
        }

        // End-of-suite: drop leftover outbox frames (typically
        // post-A_Restart ROI from the last test) so the next suite's
        // preparation expects can't match the wrong frame.
        harness.discard_unsolicited();
    }

    summary
}
