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
use std::process::ExitCode;

// Timing is runtime-agnostic: `std::time` for the clock, async-io's
// timer (the same reactor that drives the DUT socket) for sleeping.
// See `harness::lifecycle` on why the parent side avoids embassy.
use async_io::Timer;
use std::time::{Duration, Instant};
use zweidraehte_proto::crypto::scf::{SecureServiceType, SecurityControlField};

use crate::harness::{ChildLifecycle, DutMode};
use crate::ipc::protocol::RunnerMessage;
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
        TestStep::VerifyUnsolicitedSyncRes { params, timeout_ms } => {
            step_verify_unsolicited_sync_res(harness, index, params, *timeout_ms, ctx).await
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
            step_inject_sync_req(harness, index, sync_params, None, *delay_before_ms, ctx).await
        }
        TestStep::InjectSyncReqInvalid { sync_params, invalid, delay_before_ms } => {
            step_inject_sync_req(harness, index, sync_params, Some(invalid), *delay_before_ms, ctx).await
        }
        TestStep::ExpectSyncRes { sync_expect, timeout_ms } => {
            receive_sync_res(harness, index, sync_expect, *timeout_ms, ctx).await.is_some()
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

            let BlockExpect::Plain { matcher } = expect else {
                continue;
            };

            if matcher.matches(&raw) {
                println!("        ✅ Plain element {} matched: {:02X?}", i, raw);
                claimed[i] = true;
                continue 'frames;
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

fn sync_address(template: &str, variables: &BTreeMap<String, TestVariable>) -> Result<u16, String> {
    // Telegram::parse accepts matcher wildcards by substituting zero. An
    // address used to construct or validate a sync must name an exact peer.
    if template.contains('?') {
        return Err(format!("sync address {template:?} must not contain wildcards"));
    }
    let telegram =
        Telegram::parse(template, variables).map_err(|error| format!("sync address {template:?}: {error}"))?;
    let [high, low] = telegram.data.as_slice() else {
        return Err(format!("sync address {template:?} must resolve to two octets"));
    };
    Ok(u16::from_be_bytes([*high, *low]))
}

async fn step_inject_sync_req(
    harness: &mut ChildLifecycle,
    index: usize,
    sync_params: &SyncReqParams,
    invalid: Option<&InvalidSecurityParam>,
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

    let addresses = sync_address(&sync_params.src_template, variables)
        .and_then(|src| sync_address(&sync_params.dst_template, variables).map(|dst| (src, dst)));
    let (src, dst) = match addresses {
        Ok(addresses) => addresses,
        Err(error) => {
            println!("  [{index}] ❌ Invalid sync request address: {error}");
            return false;
        }
    };

    let scf = SecurityControlField {
        service: SecureServiceType::SyncRequest,
        system_broadcast: sync_params.system_broadcast,
        confidentiality: true,
        tool_access: sync_params.tool_access,
    };
    let scf_byte = scf.encode();

    // A deliberate security-field corruption does not excuse an unresolved
    // peer: both variants share address validation and sequence handling.
    let frame = match invalid {
        Some(invalid) => crypto::wrap_sync_req_invalid(
            sync_params.ctrl_byte,
            src,
            dst,
            sync_params.npdu_byte,
            sync_params.tpci_high,
            &key,
            scf_byte,
            &seq_nr_local,
            &sync_params.serial_number,
            &sync_params.challenge,
            invalid,
        ),
        None => crypto::wrap_sync_req(
            sync_params.ctrl_byte,
            src,
            dst,
            sync_params.npdu_byte,
            sync_params.tpci_high,
            &key,
            scf_byte,
            &seq_nr_local,
            &sync_params.serial_number,
            &sync_params.challenge,
        ),
    };

    let tp1 = internal_to_tp1(&frame);
    println!("  [{index}] 🔄⬇️  InjectSyncReq: {} bytes, seqLocal={seq_local}, corruption={invalid:?}", tp1.len());
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyncCounters {
    sending: u64,
    peer_next: u64,
}

async fn receive_sync_res(
    harness: &mut ChildLifecycle,
    index: usize,
    sync_expect: &SyncResExpect,
    timeout_ms: u32,
    ctx: &mut StepContext<'_>,
) -> Option<SyncCounters> {
    let time_divisor = ctx.divisor;
    let variables = ctx.vars;
    let Some(sec) = ctx.sec_mut() else {
        println!("  [{}] ❌ ExpectSyncRes requires security context", index);
        return None;
    };
    let ms = scale_ms(timeout_ms, time_divisor);
    println!("  [{}] 🔄⬆️  ExpectSyncRes (timeout={}ms)", index, ms);

    let tagged = match harness.next_frame(Duration::from_millis(ms)).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            println!("        ❌ Timeout waiting for sync response");
            return None;
        }
        Err(e) => {
            println!("        ❌ Socket error: {}", e);
            return None;
        }
    };

    let internal = tp1_to_internal(&tagged.message.data);
    let key = sec.key(&sync_expect.key_name);
    match crypto::unwrap_sync_res(&internal, &key, &sync_expect.challenge) {
        Some(decoded) => {
            let expected_scf = SecurityControlField {
                service: SecureServiceType::SyncResponse,
                system_broadcast: sync_expect.system_broadcast,
                confidentiality: true,
                tool_access: sync_expect.tool_access,
            };
            let expected_src = sync_address(&sync_expect.expected_src_template, variables);
            let actual_src = u16::from_be_bytes([internal[1], internal[2]]);
            if decoded.scf_byte != expected_scf.encode() || expected_src != Ok(actual_src) {
                println!(
                    "        ❌ Sync response: expected source {:?}, SCF {:02X}; got {:04X}, SCF {:02X}",
                    sync_expect.expected_src_template,
                    expected_scf.encode(),
                    actual_src,
                    decoded.scf_byte
                );
                return None;
            }
            let seq_remote = crate::tests::security::context::seq_from_bytes(&decoded.seq_nr_remote);
            let seq_local = crate::tests::security::context::seq_from_bytes(&decoded.seq_nr_local);
            println!("        SeqNr_remote={}, SeqNr_local={}", seq_remote, seq_local);

            let mut ok = true;
            let remote_mismatch = sync_expect.expected_seq_remote.filter(|expected| seq_remote != *expected);

            if let Some(expected) = remote_mismatch {
                println!("        ❌ SeqNr_remote: expected {}, got {}", expected, seq_remote);
                ok = false;
            }

            let local_mismatch = sync_expect.expected_seq_local.filter(|expected| seq_local != *expected);

            if let Some(expected) = local_mismatch {
                println!("        ❌ SeqNr_local: expected {}, got {}", expected, seq_local);
                ok = false;
            }

            sec.update_table_seq(seq_remote);
            if sync_expect.tool_access && seq_local > sec.tool_seq_nr {
                sec.tool_seq_nr = seq_local;
            }
            if ok {
                println!("        ✅ Sync response matches");
            }
            ok.then_some(SyncCounters { sending: seq_remote, peer_next: seq_local })
        }
        None => {
            println!("        ❌ Sync response decryption/verification failed");
            None
        }
    }
}

/// Read counters without consuming a secure data sequence or raising the
/// peer's replay floor. A successful probe also proves this peer/key is usable.
async fn probe_sync_counters(
    harness: &mut ChildLifecycle,
    index: usize,
    peer: &str,
    expected: &SyncResExpect,
    timeout_ms: u32,
    ctx: &mut StepContext<'_>,
) -> Option<SyncCounters> {
    for address in [peer, &expected.expected_src_template] {
        if let Err(error) = sync_address(address, ctx.vars) {
            println!("        ❌ Invalid sync probe address: {error}");
            return None;
        }
    }
    // Clear the DUT's sync-request rate limit before each observation.
    Timer::after(Duration::from_millis(scale_ms(1500, ctx.divisor))).await;
    let probe = SyncReqParams {
        key_name: expected.key_name.clone(),
        tool_access: expected.tool_access,
        system_broadcast: false,
        src_template: peer.into(),
        dst_template: expected.expected_src_template.clone(),
        npdu_byte: 0x60,
        ctrl_byte: 0x3C,
        seq_local: SeqSource::Fixed(0),
        serial_number: [0; 6],
        challenge: expected.challenge,
        tpci_high: 0,
    };
    if !step_inject_sync_req(harness, index, &probe, None, 0, ctx).await {
        return None;
    }
    receive_sync_res(harness, index, expected, timeout_ms, ctx).await
}

async fn step_verify_unsolicited_sync_res(
    harness: &mut ChildLifecycle,
    index: usize,
    params: &SyncResInject,
    timeout_ms: u32,
    ctx: &mut StepContext<'_>,
) -> StepOk {
    if params.system_broadcast || params.npdu_byte & 0x80 != 0 || params.tpci_high & 0xFC != 0 {
        println!("        ❌ Unsolicited sync verification requires a unicast, connectionless response");
        return false;
    }
    let mut expected = SyncResExpect {
        key_name: params.key_name.clone(),
        tool_access: params.tool_access,
        system_broadcast: false,
        expected_seq_remote: None,
        expected_seq_local: None,
        challenge: params.challenge,
        expected_src_template: params.dst_template.clone(),
    };
    let Some(before) = probe_sync_counters(harness, index, &params.src_template, &expected, timeout_ms, ctx).await
    else {
        return false;
    };

    // Both values must advance state if accepted. Fixed XML examples can be
    // below the live counters and turn a rejection test into a false positive.
    let mut response = params.clone();
    let Some(sending) = SyncResponseLocalSequence::RequestOffset(1).resolve(before.sending) else {
        println!("        ❌ Cannot advance the DUT sending counter beyond 48 bits");
        return false;
    };
    let Some(peer_next) = SyncResponseLocalSequence::RequestOffset(1).resolve(before.peer_next) else {
        println!("        ❌ Cannot advance the peer counter beyond 48 bits");
        return false;
    };
    response.seq_nr_local = sending;
    response.seq_nr_remote = peer_next;
    if !step_inject_sync_res(harness, index, &response, 0, ctx).await {
        return false;
    }

    expected.expected_seq_remote = Some(before.sending);
    expected.expected_seq_local = Some(before.peer_next);
    // Distinguish the second observation from a replay of the first response.
    expected.challenge[5] ^= 1;
    probe_sync_counters(harness, index, &params.src_template, &expected, timeout_ms, ctx).await.is_some()
}

/// Inject an S-A_Sync_Res that answers nothing.
async fn step_inject_sync_res(
    harness: &mut ChildLifecycle,
    index: usize,
    params: &SyncResInject,
    delay_before_ms: u32,
    ctx: &mut StepContext<'_>,
) -> StepOk {
    let time_divisor = ctx.divisor;
    let variables = ctx.vars;
    let Some(sec) = ctx.sec_mut() else {
        println!("  [{index}] InjectSyncRes requires security context");
        return false;
    };
    let addresses = sync_address(&params.src_template, variables)
        .and_then(|src| sync_address(&params.dst_template, variables).map(|dst| (src, dst)));
    let (src, dst) = match addresses {
        Ok(addresses) => addresses,
        Err(error) => {
            println!("  [{index}] ❌ Invalid sync response address: {error}");
            return false;
        }
    };

    let scf = SecurityControlField {
        service: SecureServiceType::SyncResponse,
        system_broadcast: params.system_broadcast,
        confidentiality: true,
        tool_access: params.tool_access,
    };
    let key = sec.key(&params.key_name);
    let frame = crypto::wrap_sync_res(
        params.ctrl_byte,
        src,
        dst,
        params.npdu_byte,
        params.tpci_high,
        &key,
        scf.encode(),
        &crate::tests::security::context::seq_to_bytes(params.seq_nr_remote),
        &crate::tests::security::context::seq_to_bytes(params.seq_nr_local),
        &params.challenge,
    );

    let tp1 = internal_to_tp1(&frame);
    println!(
        "  [{index}] 🔒⬇️  InjectSyncRes (unsolicited, key={}): {} bytes, seqRemote={}, seqLocal={}",
        params.key_name,
        tp1.len(),
        params.seq_nr_remote,
        params.seq_nr_local
    );
    if delay_before_ms > 0 {
        Timer::after(Duration::from_millis(scale_ms(delay_before_ms, time_divisor))).await;
    }
    harness.step(|seq| RunnerMessage::Inject { seq, data: tp1.clone() }).await.is_ok()
}

/// Inspect the encoded header and MAC independently of DUT acceptance: a
/// filtered or otherwise rejected response must still preserve its input fields.
fn build_paired_sync_response(
    params: &SyncResponseParams,
    request: &crypto::SyncReqDecrypted,
    key: &[u8; 16],
    seq_nr_remote: &[u8; 6],
    seq_nr_local: &[u8; 6],
    variables: &BTreeMap<String, TestVariable>,
) -> Result<Vec<u8>, String> {
    let source = sync_address(&params.src_template, variables)?;
    // EITT owns the response header: a deliberately wrong destination or TPCI
    // must reach the wire unchanged, with a valid MAC for those exact fields.
    // Handwritten helpers may still ask for the usual connectionless reply.
    let (ctrl, npdu, tpci, destination) = if let Some(frame) = &params.response_frame {
        (frame.ctrl_byte, frame.npdu_byte, frame.tpci_high, sync_address(&frame.dst_template, variables)?)
    } else if params.system_broadcast {
        (0xBC, 0xE0, 0, 0)
    } else {
        (0xB0, 0x60, 0, request.src)
    };
    Ok(crypto::wrap_sync_res(
        ctrl,
        source,
        destination,
        npdu,
        tpci,
        key,
        SecurityControlField {
            service: SecureServiceType::SyncResponse,
            system_broadcast: params.system_broadcast,
            confidentiality: true,
            tool_access: params.tool_access,
        }
        .encode(),
        seq_nr_remote,
        seq_nr_local,
        &request.challenge,
    ))
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
    let request_key = sec.key(&params.request_key_name);
    let Some(decoded_req) = crypto::unwrap_sync_req(&internal, &request_key) else {
        println!("        Failed to decrypt DUT sync request (source: {})", tagged.source.label());
        return false;
    };
    let Ok(request_scf) = SecurityControlField::parse(decoded_req.scf_byte) else {
        println!("        Invalid SCF in DUT sync request");
        return false;
    };
    if request_scf.service != SecureServiceType::SyncRequest
        || !request_scf.confidentiality
        || request_scf.tool_access != params.request_tool_access
    {
        println!("        Unexpected SCF in DUT sync request: {:02X}", decoded_req.scf_byte);
        return false;
    }
    if let Some(expected) = &params.request_frame {
        let (src, dst) =
            match (sync_address(&expected.src_template, variables), sync_address(&expected.dst_template, variables)) {
                (Ok(src), Ok(dst)) => (src.to_be_bytes(), dst.to_be_bytes()),
                addresses => {
                    println!("        Invalid sync request addresses: {addresses:?}");
                    return false;
                }
            };

        // Compare the header with the ordinary telegram matcher, including its
        // repeat-bit rule. Only a standard frame's length nibble disappears in
        // internal format. Challenge and counters remain live protocol values.
        let npdu = if expected.ctrl_byte & 0x80 != 0 { expected.npdu_byte & 0xF0 } else { expected.npdu_byte };
        let matcher = TelegramMatcher::exact(&[
            expected.ctrl_byte,
            src[0],
            src[1],
            dst[0],
            dst[1],
            npdu,
            (expected.tpci_high & 0xFC) | 3,
            0xF1,
        ]);
        if !matcher.matches(&internal[..8]) || request_scf.system_broadcast != expected.system_broadcast {
            println!("        DUT sync request header/SBC does not match {expected:?}");
            println!("{}", matcher.diff(&internal[..8]));
            return false;
        }
    }
    let seq_local_val = crate::tests::security::context::seq_from_bytes(&decoded_req.seq_nr_local);
    println!("        DUT SyncReq: SeqNr_local={}, challenge={:02x?}", seq_local_val, decoded_req.challenge);

    let Some(response_seq_local) = params.seq_nr_local.resolve(seq_local_val) else {
        println!("        Sync response local sequence is outside the 48-bit range");
        return false;
    };
    if params.seq_nr_remote >= (1 << 48) {
        println!("        Sync response remote sequence is outside the 48-bit range");
        return false;
    }
    let expected_sending = match params.verify {
        Some(check) => match check.sending.resolve(seq_local_val) {
            Some(value) if check.peer_next < (1 << 48) => Some(value),
            _ => {
                println!("        Sync response verification counter is outside the 48-bit range");
                return false;
            }
        },
        None => None,
    };
    let seq_nr_remote = crate::tests::security::context::seq_to_bytes(params.seq_nr_remote);
    let seq_nr_local = crate::tests::security::context::seq_to_bytes(response_seq_local);
    let response = match build_paired_sync_response(
        params,
        &decoded_req,
        &sec.key(&params.key_name),
        &seq_nr_remote,
        &seq_nr_local,
        variables,
    ) {
        Ok(frame) => frame,
        Err(error) => {
            println!("        Invalid sync response: {error}");
            return false;
        }
    };

    let tp1 = internal_to_tp1(&response);
    println!(
        "        Injecting SyncRes: {} bytes, seqRemote={}, seqLocal={}",
        tp1.len(),
        params.seq_nr_remote,
        response_seq_local
    );
    if let Err(error) = harness.step(|seq| RunnerMessage::Inject { seq, data: tp1.clone() }).await {
        println!("        Inject SyncRes failed: {error}");
        return false;
    }

    let Some(check) = params.verify else { return true };
    let device = format!("{:02X} {:02X}", decoded_req.src >> 8, decoded_req.src & 0xff);
    let expected = SyncResExpect {
        key_name: params.request_key_name.clone(),
        tool_access: params.request_tool_access,
        system_broadcast: false,
        expected_seq_remote: expected_sending,
        expected_seq_local: Some(check.peer_next),
        challenge: decoded_req.challenge,
        expected_src_template: device,
    };
    println!("        Verify DUT sending={expected_sending:?}, peer next={}", check.peer_next);
    probe_sync_counters(harness, index, &params.src_template, &expected, timeout_ms, ctx).await.is_some()
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
    /// Name filters, resolved by [`select_suites`]: a filter
    /// matching a suite's name runs that suite in full, a filter
    /// matching case names runs those cases in the suite they live in.
    /// Empty runs everything. Sequential runs also include preceding cases.
    pub case_filters: Vec<String>,
    /// Whether a case needs the successful execution of every preceding case.
    pub case_order: CaseOrder,
}

/// How filtering and failures affect later cases in one engine run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CaseOrder {
    /// Cases can be selected independently; a failure does not block later cases.
    #[default]
    Independent,
    /// Replay the prefix through the last match. A case, suite preparation or teardown
    /// failure blocks the remainder because its required state is unknown.
    Sequential,
}

/// What a run produced. Callers add their own out-of-band results (the
/// socket-level IP Secure suite, for instance) before printing.
#[derive(Debug, Default, Clone, Copy)]
pub struct Summary {
    pub suites: usize,
    /// Selected cases, including those blocked by setup or an earlier failure.
    pub tests: usize,
    pub passed: usize,
    /// Executed cases that failed, including case-level preparation and teardown.
    pub failed: usize,
    /// Selected cases blocked by suite preparation or an earlier sequential failure.
    pub blocked: usize,
    /// Suites with at least one failed preparation step, even if no cases exist.
    pub preparation_failed: usize,
    /// Suites with at least one failed teardown step, even if no cases exist.
    pub teardown_failed: usize,
    pub steps: usize,
}

impl Summary {
    /// A suite setup or teardown failure fails the run even without cases.
    pub fn exit_code(&self) -> ExitCode {
        if self.failed > 0 || self.preparation_failed > 0 || self.teardown_failed > 0 {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    }

    /// Report the same coverage and failure categories in both step runners.
    pub fn print(&self) {
        println!("====================================================================");
        println!("SUMMARY");
        println!("====================================================================");
        println!("  Test Suites:  {}", self.suites);
        println!("  Total Tests:  {}", self.tests);
        println!("  Executed:     {}", self.passed + self.failed);
        println!("  Passed:       {} ✅", self.passed);
        println!("  Failed:       {} ❌", self.failed);
        println!("  Blocked:      {}", self.blocked);
        println!("  Prep Failed:  {} suite(s)", self.preparation_failed);
        println!("  Cleanup Failed: {} suite(s)", self.teardown_failed);
        println!("  Total Steps:  {}", self.steps);
        println!("====================================================================");
    }
}

/// Case-insensitive substring match, the filter rule both binaries use.
pub fn matches_filter(name: &str, filter: &str) -> bool {
    name.to_lowercase().contains(&filter.to_lowercase())
}

/// What a filter set selects out of one suite.
///
/// The decision is deliberately made *per suite*. A filter that happens
/// to match a case name in some other suite must not narrow a suite
/// that was selected by its own name: filters are plain substrings, so
/// `"4.3 Property"` matches the case `3.8.14.3 PropertyValueRead` as
/// readily as the suite it was aimed at. Deciding this globally — one
/// "somebody matched a case somewhere" flag gating every suite's cases
/// — is how a run used to print a healthy suite list, execute zero
/// cases and report zero failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiteSelection {
    /// Nothing in this suite matched; it is not part of the run.
    None,
    /// The suite runs in full: its name matched, there are no filters,
    /// or a later sequential case needs it as a prerequisite.
    AllCases,
    /// Specific indices into [`TestSuite::cases`], including any sequential
    /// prerequisites. Never empty.
    Cases(Vec<usize>),
}

/// Resolve a filter set against one suite.
///
/// A suite-name match wins outright: asking for a suite asks for all of
/// it, so case hits inside that same suite add nothing.
pub fn select_suite(suite: &TestSuite, filters: &[String]) -> SuiteSelection {
    if filters.is_empty() || filters.iter().any(|f| matches_filter(&suite.name, f)) {
        return SuiteSelection::AllCases;
    }

    let cases: Vec<usize> = suite
        .cases
        .iter()
        .enumerate()
        .filter(|(_, c)| filters.iter().any(|f| matches_filter(&c.name, f)))
        .map(|(i, _)| i)
        .collect();

    if cases.is_empty() { SuiteSelection::None } else { SuiteSelection::Cases(cases) }
}

/// Resolve the complete run, including the prefix required by sequential cases.
/// The returned entries correspond one-to-one with `suites`, so listing and
/// execution can share exactly the same selection without losing dependencies.
pub fn select_suites(suites: &[TestSuite], filters: &[String], order: CaseOrder) -> Vec<SuiteSelection> {
    let mut selected: Vec<_> = suites.iter().map(|suite| select_suite(suite, filters)).collect();
    if order == CaseOrder::Sequential
        && let Some(last) = selected.iter().rposition(|s| *s != SuiteSelection::None)
    {
        selected[..last].fill(SuiteSelection::AllCases);
        if let SuiteSelection::Cases(cases) = &mut selected[last] {
            let end = *cases.last().expect("a case selection is nonempty");
            *cases = (0..=end).collect();
        }
    }
    selected
}

impl SuiteSelection {
    /// How many cases this selection runs out of `suite`.
    pub fn case_count(&self, suite: &TestSuite) -> usize {
        match self {
            SuiteSelection::None => 0,
            SuiteSelection::AllCases => suite.cases.len(),
            SuiteSelection::Cases(idx) => idx.len(),
        }
    }

    /// One line describing what will run, for the pre-run report both
    /// binaries print when filters are in play.
    pub fn describe(&self, suite: &TestSuite) -> String {
        match self {
            SuiteSelection::None => "no case(s) matched".to_string(),
            SuiteSelection::AllCases => format!("all {} case(s)", suite.cases.len()),
            SuiteSelection::Cases(idx) => format!("{} of {} case(s) matched", idx.len(), suite.cases.len()),
        }
    }

    /// Whether the case at `index` in the suite runs. Used by the
    /// engine to drive the case loop and by `--list` to show the same
    /// set the run would execute.
    pub fn selects(&self, index: usize) -> bool {
        match self {
            SuiteSelection::None => false,
            SuiteSelection::AllCases => true,
            SuiteSelection::Cases(idx) => idx.contains(&index),
        }
    }
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

    let mut harness = ChildLifecycle::new(opts.dut_mode).expect("create child lifecycle");
    println!("DUT mode: {}", match opts.dut_mode {
        DutMode::Bcu1 => "BCU1 (conformance-dut-bcu1)",
        DutMode::SystemBSecure => "System B secure (conformance-dut-systemb-secure)",
        DutMode::SystemB => "System B (conformance-dut-systemb)",
        DutMode::System7 => "System 7 (conformance-dut-system7)",
        DutMode::System7Secure => "System 7 secure (conformance-dut-system7-secure)",
        DutMode::Bcu2 => "BCU2 (conformance-dut-bcu2)",
        DutMode::Bcu2Secure => "secure BCU2 (conformance-dut-bcu2-secure)",
        DutMode::Bcu2SecureBase => "secure BCU2 base profile (conformance-dut-bcu2-secure-base)",
        DutMode::MicroSystem7 => "micro System 7 (conformance-dut-micro-system7)",
        DutMode::MicroSystem7Secure => "secure micro System 7 (conformance-dut-micro-system7-secure)",
    });

    harness.spawn_and_wait_roi().await.expect("spawn DUT child");
    harness.discard_unsolicited();

    // `suites` is counted as the loop goes rather than up front: a
    // suite the filters select nothing out of contributes no tests, so
    // counting it would overstate what the run covered.
    let mut summary = Summary::default();
    let mut persistent_sec_ctx: Option<SecurityTestContext> = None;

    // Cross-suite plain→secure reset hook: the first secure suite needs
    // a DUT whose sequence-number state has not been touched by the
    // plain suites that ran before it.
    let mut prev_was_secure = false;

    for (suite, selection) in suites.iter().zip(select_suites(suites, filters, opts.case_order)) {
        if selection == SuiteSelection::None {
            continue;
        }
        summary.suites += 1;
        let selected_cases = selection.case_count(suite);
        summary.tests += selected_cases;

        if opts.case_order == CaseOrder::Sequential && summary.exit_code() == ExitCode::FAILURE {
            summary.blocked += selected_cases;
            println!("❌ Suite {}: blocking {selected_cases} case(s) after an earlier failure", suite.name);
            continue;
        }

        if suite.requires_security_context && !prev_was_secure && opts.dut_mode == DutMode::SystemBSecure {
            println!("🔁 Resetting DUT before first secure suite (clean seqnr + volatile state)");
            harness.kill().await;
            harness.reset_shared_memory();
            harness.spawn_and_wait_roi().await.expect("respawn DUT child");
            harness.discard_unsolicited();
            persistent_sec_ctx = None;
        }
        prev_was_secure = suite.requires_security_context;

        println!("====================================================================");
        println!("Suite: {}", suite.name);
        println!("--------------------------------------------------------------------");
        println!("Variables:");
        for (name, var) in &suite.variables {
            println!("  #{}: {:02X?}", name, var.as_bytes());
        }
        println!();

        let mut sec_ctx = if suite.requires_security_context {
            let mut ctx =
                persistent_sec_ctx.take().unwrap_or_else(crate::tests::security::variables::create_security_context);
            ctx.table_seq_nr = 1;
            Some(ctx)
        } else {
            None
        };

        let mut prep_passed = true;
        if !suite.preparation.is_empty() {
            println!("Preparation:");
            println!("--------------------------------------------------------------------");
            // Drop any unsolicited frames left over from the previous
            // suite — most often post-restart ROI from the last test.
            harness.discard_unsolicited();
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
                summary.preparation_failed += 1;
                summary.blocked += selected_cases;
                println!("❌ Preparation failed - blocking {selected_cases} selected case(s)\n");
            }
        }

        // Failed setup may already have changed keys, addresses or tables.
        // Skip its cases but still run teardown and retain the security context
        // so cleanup can authenticate and later suites see consistent state.
        for (case_index, test) in suite.cases.iter().enumerate() {
            if !prep_passed || !selection.selects(case_index) {
                continue;
            }
            if opts.case_order == CaseOrder::Sequential && summary.failed > 0 {
                summary.blocked += 1;
                println!("❌ Blocked {}: an earlier case failed", test.name);
                continue;
            }

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
                // Keep attempting cleanup after an error, but never report a
                // case as passing when its promised restoration failed.
                for (i, step) in test.teardown.iter().enumerate() {
                    let resolved_step = match step.resolve(&suite.variables) {
                        Ok(s) => s,
                        Err(e) => {
                            println!("  [T{}] ❌ Template error: {}", i, e);
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
            let mut teardown_passed = true;
            for (i, step) in suite.teardown.iter().enumerate() {
                let resolved_step = match step.resolve(&suite.variables) {
                    Ok(s) => s,
                    Err(e) => {
                        println!("  [{}] ❌ Template error: {}", i, e);
                        teardown_passed = false;
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
                    teardown_passed = false;
                }
            }
            summary.steps += suite.teardown.len();
            if teardown_passed {
                println!("✅ Teardown completed\n");
            } else {
                summary.teardown_failed += 1;
                println!("❌ Suite teardown failed\n");
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential_selection_keeps_the_prefix_through_the_last_match() {
        let suites = [
            TestSuite::new("Setup", BTreeMap::new()).with_cases(vec![TestCase::new("load")]),
            TestSuite::new("Sync", BTreeMap::new()).with_cases(vec![
                TestCase::new("provision peer"),
                TestCase::new("target"),
                TestCase::new("later"),
            ]),
            TestSuite::new("Unrelated", BTreeMap::new()).with_cases(vec![TestCase::new("last")]),
        ];
        assert_eq!(select_suites(&suites, &filters(&["target"]), CaseOrder::Independent), vec![
            SuiteSelection::None,
            SuiteSelection::Cases(vec![1]),
            SuiteSelection::None,
        ]);
        assert_eq!(select_suites(&suites, &filters(&["target"]), CaseOrder::Sequential), vec![
            SuiteSelection::AllCases,
            SuiteSelection::Cases(vec![0, 1]),
            SuiteSelection::None,
        ]);
        assert_eq!(
            select_suites(&suites, &filters(&["target", "load"]), CaseOrder::Sequential),
            select_suites(&suites, &filters(&["target"]), CaseOrder::Sequential)
        );
        assert_eq!(select_suites(&suites, &filters(&["Sync"]), CaseOrder::Sequential), vec![
            SuiteSelection::AllCases,
            SuiteSelection::AllCases,
            SuiteSelection::None,
        ]);
        assert_eq!(select_suites(&suites, &filters(&["typo"]), CaseOrder::Sequential), vec![SuiteSelection::None; 3]);
        assert_eq!(select_suites(&suites, &[], CaseOrder::Sequential), vec![SuiteSelection::AllCases; 3]);
    }

    #[test]
    fn sync_addresses_require_exactly_two_resolved_octets() {
        let vars = BTreeMap::from([("DEVICE".into(), TestVariable::Bytes(vec![0x12, 0x34]))]);
        assert_eq!(sync_address("#DEVICE", &vars), Ok(0x1234));
        assert_eq!(sync_address("00 00", &vars), Ok(0));
        for invalid in ["#MISSING", "12", "12 34 56", "?? ??"] {
            assert!(sync_address(invalid, &vars).is_err(), "{invalid}");
        }
    }

    #[test]
    fn paired_sync_uses_the_declared_header_even_when_it_disagrees_with_the_request() {
        let key = [0x42; 16];
        let remote = [0, 0, 0, 0, 0, 23];
        let local = [0, 0, 0, 0, 0, 47];
        let request = crypto::SyncReqDecrypted {
            challenge: [1, 2, 3, 4, 5, 6],
            seq_nr_local: local,
            scf_byte: 0x12,
            src: 0x1234,
            dst: 0x5678,
            addr_type: 0,
            tpci_apci: 0x03F1,
            serial_number: [0; 6],
        };
        let variables = BTreeMap::from([("OTHER_DEVICE".into(), TestVariable::Bytes(vec![0x9A, 0xBC]))]);
        for system_broadcast in [false, true] {
            for (destination, npdu) in [("9A BC", 0xA0), ("#OTHER_DEVICE", 0x20)] {
                let mut params = SyncResponseParams {
                    request_key_name: "P2PK1".into(),
                    request_tool_access: false,
                    request_frame: None,
                    key_name: "P2PK1".into(),
                    tool_access: false,
                    seq_nr_remote: 23,
                    seq_nr_local: SyncResponseLocalSequence::Fixed(47),
                    system_broadcast,
                    src_template: "56 78".into(),
                    response_frame: Some(SyncResponseFrame {
                        dst_template: destination.into(),
                        ctrl_byte: 0x34,
                        npdu_byte: npdu,
                        tpci_high: 0x58,
                    }),
                    verify: None,
                };

                let frame = build_paired_sync_response(&params, &request, &key, &remote, &local, &variables)
                    .expect("resolved response");
                let wire = internal_to_tp1(&frame);
                // Destination differs from the requesting DUT; AT and TPCI
                // are independent of SBC. None may be silently corrected.
                assert_eq!(&wire[..9], &[0x34, npdu, 0x56, 0x78, 0x9A, 0xBC, 24, 0x5B, 0xF1]);
                assert_eq!(wire[9], if system_broadcast { 0x1B } else { 0x13 });
                let frame = tp1_to_internal(&wire);
                let decoded = crypto::unwrap_sync_res(&frame, &key, &request.challenge)
                    .expect("MAC authenticates the declared header");
                assert_eq!(decoded.seq_nr_remote, remote);
                assert_eq!(decoded.seq_nr_local, local);

                // Default replies also need EFF=0; a standard-frame length
                // nibble here would become a reserved extended frame format.
                params.response_frame = None;
                let default = build_paired_sync_response(&params, &request, &key, &remote, &local, &variables)
                    .expect("default response");
                assert_eq!(internal_to_tp1(&default)[1], if system_broadcast { 0xE0 } else { 0x60 });
            }
        }
    }

    fn suite(name: &'static str, cases: &[&'static str]) -> TestSuite {
        TestSuite::new(name, BTreeMap::new()).with_cases(cases.iter().map(|c| TestCase::new(*c)).collect())
    }

    fn filters(fs: &[&str]) -> Vec<String> {
        fs.iter().map(|f| f.to_string()).collect()
    }

    #[test]
    fn no_filters_runs_everything() {
        let s = suite("3.8.4.3 PropertyValue", &["a", "b"]);
        assert_eq!(select_suite(&s, &[]), SuiteSelection::AllCases);
    }

    #[test]
    fn suite_name_match_runs_the_whole_suite() {
        let s = suite("3.8.4.3 PropertyValue", &["3.8.4.3.1 read", "3.8.4.3.2 write"]);
        assert_eq!(select_suite(&s, &filters(&["3.8.4.3"])), SuiteSelection::AllCases);
    }

    /// The regression this selection exists for: a filter aimed at one
    /// suite's *name* also matches a case name in a different suite.
    /// The global "somebody matched a case" flag this replaced turned
    /// case filtering on everywhere, so the named suite ran none of its
    /// cases and the run reported zero failures.
    #[test]
    fn a_case_hit_elsewhere_does_not_narrow_a_named_suite() {
        let named = suite("3.8.4.3 PropertyValue", &["3.8.4.3.1 read", "3.8.4.3.2 write"]);
        let other = suite("3.8.14 Sync", &["3.8.14.3 PropertyValueRead/write"]);
        let f = filters(&["4.3 Property"]);

        assert_eq!(select_suite(&named, &f), SuiteSelection::AllCases);
        assert_eq!(select_suite(&other, &f), SuiteSelection::Cases(vec![0]));
    }

    #[test]
    fn case_only_match_selects_those_cases() {
        let s = suite("3.8.9 Restart", &["3.8.9.1 basic", "3.8.9.2 master", "3.8.9.3 basic again"]);
        assert_eq!(select_suite(&s, &filters(&["basic"])), SuiteSelection::Cases(vec![0, 2]));
    }

    #[test]
    fn no_match_excludes_the_suite() {
        let s = suite("3.8.9 Restart", &["3.8.9.1 basic"]);
        assert_eq!(select_suite(&s, &filters(&["nonexistent"])), SuiteSelection::None);
    }

    #[test]
    fn matching_is_case_insensitive_on_both_levels() {
        let s = suite("3.8.9 Restart", &["3.8.9.1 Basic"]);
        assert_eq!(select_suite(&s, &filters(&["restart"])), SuiteSelection::AllCases);
        assert_eq!(select_suite(&s, &filters(&["bASIc"])), SuiteSelection::Cases(vec![0]));
    }

    #[test]
    fn several_filters_union_within_a_suite() {
        let s = suite("3.8.9 Restart", &["one", "two", "three"]);
        assert_eq!(select_suite(&s, &filters(&["one", "three"])), SuiteSelection::Cases(vec![0, 2]));
    }

    #[test]
    fn describe_reports_the_selected_share() {
        let s = suite("3.8.9 Restart", &["one", "two", "three"]);
        assert_eq!(select_suite(&s, &[]).describe(&s), "all 3 case(s)");
        assert_eq!(select_suite(&s, &filters(&["one"])).describe(&s), "1 of 3 case(s) matched");
    }
}
