//! KNX Conformance Test Runner.
//!
//! Drives `conformance-dut` / `conformance-dut-secure` child processes
//! over the new postcard IPC protocol (see
//! [`zweidraehte_conformance::harness::protocol`]). Every inject/
//! trigger/programming-mode step is synchronous:
//! [`ChildLifecycle::step`](zweidraehte_conformance::harness::ChildLifecycle::step)
//! sends the command and waits for `StepComplete` before returning.
//! Outbox frames land in a per-lifecycle buffer that `Expect*` steps
//! consume via `pop_unsolicited` / `next_frame`.
//!
//! Usage:
//!   cargo run --bin conformance-runner [--realtime] [--non-secure] [filter...]
//!
//! Arguments:
//!   --realtime    Use spec-compliant timeouts (for real hardware testing).
//!                 Without this flag, timeouts are divided by 50 for fast
//!                 IPC-connected testing.
//!   --non-secure  Run against the plain (`conformance-dut`) DUT and SKIP
//!                 any suite that requires the secure stack
//!                 (`TestSuite::use_secure_dut == true`).
//!   filter        Optional filters (case-insensitive substring match)
//!
//! Environment:
//!   RUST_LOG    Set log level (error, warn, info, debug, trace)
//!   LIVE_LOGS   If set, print logs in real-time instead of buffering
//!   KNX_TIME_DIVISOR  Exported from `--realtime` for the DUT child
//!                     so its TL timers scale identically.

use std::collections::BTreeMap;
use std::env;

use embassy_time::{Duration, Timer};
use log::LevelFilter;

use zweidraehte_conformance::harness::protocol::RunnerMessage;
use zweidraehte_conformance::harness::{ChildLifecycle, DutMode};
use zweidraehte_conformance::logger;
use zweidraehte_conformance::tests::security::context::SecurityTestContext;
use zweidraehte_conformance::tests::security::crypto;
use zweidraehte_conformance::*;

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

const DEFAULT_TIME_DIVISOR: u64 = 50;

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
        TestStep::ExpectNone { timeout_ms } => step_expect_none(harness, index, *timeout_ms, ctx.divisor).await,
        TestStep::Wait { duration_ms } => step_wait(index, *duration_ms, ctx.divisor).await,
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
        TestStep::InjectTemplate { .. } | TestStep::ExpectTemplate { .. } => {
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

    let tagged = match harness.next_frame(Duration::from_millis(ms)).await {
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
    match crypto::unwrap_secure(&internal, sec_params, sec) {
        Some(plaintext_apdu) => {
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
            if internal_matcher.matches(&plain_internal) {
                println!("        ✅ Secure response matches");
                true
            } else {
                println!("        ❌ Plaintext mismatch (source: {}):", tagged.source.label());
                println!("           {}", internal_matcher.diff(&plain_internal));
                false
            }
        }
        None => {
            println!("        ❌ Decryption/verification failed (source: {})", tagged.source.label());
            println!("           Raw: {:02X?}", tagged.message.data);
            false
        }
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
    let seq_nr_local = zweidraehte_conformance::tests::security::context::seq_to_bytes(sync_params.seq_nr_local);

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
    println!("  [{}] 🔄⬇️  InjectSyncReq: {} bytes, seqLocal={}", index, tp1.len(), sync_params.seq_nr_local);
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
    let seq_nr_local = zweidraehte_conformance::tests::security::context::seq_to_bytes(sync_params.seq_nr_local);

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
            let seq_remote = zweidraehte_conformance::tests::security::context::seq_from_bytes(&decoded.seq_nr_remote);
            let seq_local = zweidraehte_conformance::tests::security::context::seq_from_bytes(&decoded.seq_nr_local);
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
    let seq_local_val = zweidraehte_conformance::tests::security::context::seq_from_bytes(&decoded_req.seq_nr_local);
    println!("        DUT SyncReq: SeqNr_local={}, challenge={:02x?}", seq_local_val, decoded_req.challenge);

    let seq_nr_remote = zweidraehte_conformance::tests::security::context::seq_to_bytes(params.seq_nr_remote);
    let seq_nr_local = zweidraehte_conformance::tests::security::context::seq_to_bytes(params.seq_nr_local);
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
// Entry Point
// ============================================================================

#[embassy_executor::main]
async fn main(_spawner: embassy_executor::Spawner) {
    // Argument parsing — same surface as before: flags + filters.
    let args: Vec<String> = env::args().collect();
    let realtime = args.iter().any(|a| a == "--realtime");
    let non_secure = args.iter().any(|a| a == "--non-secure");
    let time_divisor: u64 = if realtime { 1 } else { DEFAULT_TIME_DIVISOR };
    let dut_mode = if non_secure { DutMode::Plain } else { DutMode::Secure };

    // Export the divisor so the DUT child scales its TL timers to match.
    // SAFETY: single-threaded before any child is spawned.
    unsafe { env::set_var("KNX_TIME_DIVISOR", time_divisor.to_string()) };

    let filters: Vec<&str> =
        args.iter().skip(1).filter(|s| *s != "--realtime" && *s != "--non-secure").map(|s| s.as_str()).collect();

    let log_level = match env::var("RUST_LOG").ok().as_deref() {
        Some("error") => LevelFilter::Error,
        Some("warn") => LevelFilter::Warn,
        Some("info") => LevelFilter::Info,
        Some("debug") => LevelFilter::Debug,
        Some("trace") => LevelFilter::Trace,
        _ => LevelFilter::Debug,
    };
    let live_logs = env::var("LIVE_LOGS").is_ok();
    logger::init(log_level, live_logs);

    println!("╔═════════════════════════════════════════════════════════════╗");
    println!("║                 KNX Conformance Test Runner                 ║");
    println!("╚═════════════════════════════════════════════════════════════╝\n");
    if time_divisor > 1 {
        println!("Time scale: {}x fast mode (use --realtime for spec timeouts)", time_divisor);
    } else {
        println!("Time scale: realtime (spec-compliant timeouts)");
    }
    println!("Log level: {:?}, Live logs: {}\n", log_level, live_logs);

    // Collect all test suites (unchanged from the old runner).
    let all_suites = vec![
        zweidraehte_conformance::tests::network_layer::create_network_layer_suite(),
        zweidraehte_conformance::tests::transport_layer_general::create_transport_layer_suite(),
        zweidraehte_conformance::tests::transport_layer_timing::create_transport_layer_timing_suite(),
        zweidraehte_conformance::tests::transport_layer_state_machine::create_transport_layer_state_machine_suite(),
        zweidraehte_conformance::tests::group_objects::create_group_objects_uint1_suite(),
        zweidraehte_conformance::tests::management::create_individual_address_read_suite(),
        zweidraehte_conformance::tests::management::create_individual_address_write_suite(),
        zweidraehte_conformance::tests::management::create_device_descriptor_type0_suite(),
        zweidraehte_conformance::tests::management::create_device_descriptor_type2_suite(),
        zweidraehte_conformance::tests::management::create_device_descriptor_illegal_types_suite(),
        zweidraehte_conformance::tests::management::create_memory_read_suite(),
        zweidraehte_conformance::tests::management::create_memory_write_suite(),
        zweidraehte_conformance::tests::management::create_adc_read_suite(),
        zweidraehte_conformance::tests::management::create_memorybit_write_suite(),
        zweidraehte_conformance::tests::management::create_memorybit_write_verify_suite(),
        zweidraehte_conformance::tests::management::create_authorization_suite(),
        zweidraehte_conformance::tests::management::create_key_write_suite(),
        zweidraehte_conformance::tests::management::create_restart_suite(),
        zweidraehte_conformance::tests::management::create_individual_address_serial_number_write_suite(),
        zweidraehte_conformance::tests::management::create_individual_address_serial_number_read_suite(),
        zweidraehte_conformance::tests::management::create_system_network_parameter_read_suite(),
        zweidraehte_conformance::tests::management::create_illegal_apci_suite(),
        zweidraehte_conformance::tests::management::create_user_memory_read_suite(),
        zweidraehte_conformance::tests::management::create_user_memory_write_suite(),
        zweidraehte_conformance::tests::management::create_user_memory_write_verify_suite(),
        zweidraehte_conformance::tests::management::create_user_manufacturer_info_read_suite(),
        zweidraehte_conformance::tests::load_state_machines::create_preparation_suite(),
        zweidraehte_conformance::tests::load_state_machines::create_unloaded_state_suite(),
        zweidraehte_conformance::tests::load_state_machines::create_loaded_state_suite(),
        zweidraehte_conformance::tests::load_state_machines::create_loading_state_suite(),
        zweidraehte_conformance::tests::load_state_machines::create_error_state_suite(),
        zweidraehte_conformance::tests::load_state_machines::create_no_access_rights_suite(),
        zweidraehte_conformance::tests::run_state_machines::create_preparation_suite(),
        zweidraehte_conformance::tests::run_state_machines::create_halted_state_suite(),
        zweidraehte_conformance::tests::security::section_3_1::create_section_3_1_suite(),
        zweidraehte_conformance::tests::security::section_3_3::create_section_3_3_suite(),
        zweidraehte_conformance::tests::security::section_3_4::create_section_3_4_suite(),
        zweidraehte_conformance::tests::security::section_3_5::create_section_3_5_suite(),
        zweidraehte_conformance::tests::security::section_3_6::create_section_3_6_suite(),
        zweidraehte_conformance::tests::security::section_3_7::create_section_3_7_suite(),
        zweidraehte_conformance::tests::security::section_3_9::create_section_3_9_suite(),
        zweidraehte_conformance::tests::security::section_4_1::create_section_4_1_suite(),
        zweidraehte_conformance::tests::security::section_4_2::create_section_4_2_suite(),
        zweidraehte_conformance::tests::security::section_4_3::create_section_4_3_suite(),
        zweidraehte_conformance::tests::security::section_4_4::create_section_4_4_suite(),
        zweidraehte_conformance::tests::security::section_4_5::create_section_4_5_suite(),
        zweidraehte_conformance::tests::security::section_3_8_1::create_section_3_8_1_suite(),
        zweidraehte_conformance::tests::security::section_3_8_2::create_section_3_8_2_suite(),
        zweidraehte_conformance::tests::security::section_3_8_3::create_section_3_8_3_suite(),
        zweidraehte_conformance::tests::security::section_3_8_4::create_section_3_8_4_suite(),
        zweidraehte_conformance::tests::security::section_3_8_5::create_section_3_8_5_suite(),
        zweidraehte_conformance::tests::security::section_3_8_6::create_section_3_8_6_suite(),
        zweidraehte_conformance::tests::security::section_3_8_7::create_section_3_8_7_suite(),
        zweidraehte_conformance::tests::security::section_3_8_8::create_section_3_8_8_suite(),
        zweidraehte_conformance::tests::security::section_3_8_9::create_section_3_8_9_suite(),
        zweidraehte_conformance::tests::security::section_3_8_10::create_section_3_8_10_suite(),
        zweidraehte_conformance::tests::security::section_3_8_11::create_section_3_8_11_suite(),
        zweidraehte_conformance::tests::security::section_3_8_12::create_section_3_8_12_suite(),
        zweidraehte_conformance::tests::security::section_3_8_13::create_section_3_8_13_suite(),
        zweidraehte_conformance::tests::security::section_3_8_14::create_section_3_8_14_suite(),
        zweidraehte_conformance::tests::security::section_3_8_15::create_section_3_8_15_suite(),
        zweidraehte_conformance::tests::security::section_3_8_16::create_section_3_8_16_suite(),
        zweidraehte_conformance::tests::security::section_3_8_17::create_section_3_8_17_suite(),
        zweidraehte_conformance::tests::security::section_3_8_18::create_section_3_8_18_suite(),
        zweidraehte_conformance::tests::security::section_4_6_4_7::create_section_4_6_4_7_suite(),
        zweidraehte_conformance::tests::security::section_5::create_section_5_suite(),
        zweidraehte_conformance::tests::security::section_6::create_section_6_suite(),
        zweidraehte_conformance::tests::security::section_6::create_section_6_2_suite(),
        zweidraehte_conformance::tests::security::section_3_2::create_section_3_2_suite(),
    ];

    let matches_filter = |name: &str, filter: &str| -> bool { name.to_lowercase().contains(&filter.to_lowercase()) };
    let has_test_case_filter =
        filters.iter().any(|f| all_suites.iter().any(|s| s.cases.iter().any(|c| matches_filter(c.name, f))));

    let mut suites: Vec<_> = if filters.is_empty() {
        all_suites
    } else {
        all_suites
            .into_iter()
            .filter(|s| {
                let suite_matches = filters.iter().any(|f| matches_filter(s.name, f));
                let case_matches = s.cases.iter().any(|c| filters.iter().any(|f| matches_filter(c.name, f)));
                suite_matches || case_matches
            })
            .collect()
    };

    if dut_mode == DutMode::Plain {
        let before = suites.len();
        suites.retain(|s| !s.use_secure_dut);
        let skipped = before - suites.len();
        if skipped > 0 {
            println!("⚠️  Skipped {} secure-only suite(s) because --non-secure is active", skipped);
        }
    }

    if suites.is_empty() {
        println!("No suites or tests matched filters: {:?}", filters);
        std::process::exit(1);
    }

    if !filters.is_empty() {
        if has_test_case_filter {
            println!("Running tests matching: {:?}\n", filters);
        } else {
            println!("Running {} suite(s) matching: {:?}\n", suites.len(), filters);
        }
    }

    // Create the lifecycle (SHM + per-mode child management).
    let mut harness = ChildLifecycle::new(dut_mode).expect("create child lifecycle");
    println!("DUT mode: {}", match dut_mode {
        DutMode::Secure => "secure (conformance-dut-secure)",
        DutMode::Plain => "plain (conformance-dut)",
    });

    // Spawn + wait for Ready + RoiComplete. The new protocol's
    // `RoiComplete` replaces the old timed-drain loop — no more
    // guessing how long ROI takes.
    harness.spawn_and_wait_roi().await.expect("spawn DUT child");
    // Startup ROI frames are an implementation detail — tests that
    // care about ROI trigger it explicitly via A_Restart and
    // observe the post-restart scan (see 1.4.1.6). For every other
    // test the initial scan is noise; drop the buffered frames so
    // they can't poison the first suite's expects.
    harness.discard_unsolicited();

    let mut passed = 0;
    let mut failed = 0;
    let mut total_steps = 0;
    let mut total_tests = 0;

    let mut persistent_sec_ctx: Option<SecurityTestContext> = None;

    // Cross-suite plain→secure reset hook — same as before. Problem
    // 9 (SHM seqnr leak) remains solvable by this + `FullReset`;
    // eliminating the implicit hook entirely is a Phase-6 task.
    let mut prev_was_secure = false;

    for suite in &suites {
        if suite.use_secure_dut && !prev_was_secure && dut_mode == DutMode::Secure {
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
            let mut ctx = persistent_sec_ctx
                .take()
                .unwrap_or_else(|| zweidraehte_conformance::tests::security::variables::create_security_context());
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
                total_steps += 1;
            }

            if prep_passed {
                println!("✅ Preparation completed successfully\n");
            } else {
                println!("❌ Preparation failed - skipping suite tests\n");
                continue;
            }
        }

        for test in &suite.cases {
            if has_test_case_filter && !filters.iter().any(|f| matches_filter(test.name, f)) {
                continue;
            }
            total_tests += 1;

            // Between tests, discard any leftover outbox frames so
            // one test's stray response can't match the next test's
            // Expect. The new protocol makes this cheap — no timed
            // drain loop needed.
            //
            // Also: give any in-flight asynchronous frames (timer-
            // driven retransmits, post-restart ROI bleeding past
            // RoiComplete) a chance to land, then drain them. 30 ms
            // is comfortable in fast mode without inflating test
            // wall-clock.
            let _ = harness.next_frame(Duration::from_millis(30)).await;
            harness.discard_unsolicited();

            logger::start_test(test.name);
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
                total_steps += test.preparation.len();
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
            total_steps += test.steps.len();

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
                total_steps += test.teardown.len();
            }

            let logs = logger::end_test();
            println!("----------------------------------------------------------------------");
            if test_passed {
                println!("  ✅ PASSED");
                logger::print_log_summary(&logs, "  ");
                passed += 1;
            } else {
                println!("  ❌ FAILED");
                logger::print_log_summary(&logs, "  ");
                if !logs.is_empty() {
                    println!("  --- Stack Trace ---------------------------------------------------");
                    logger::print_logs(&logs, "    ");
                }
                failed += 1;
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
                total_steps += 1;
            }
            println!("✅ Teardown completed\n");
        }

        if sec_ctx.is_some() {
            persistent_sec_ctx = sec_ctx;
        }

        // End-of-suite: drop any leftover outbox frames (typically
        // post-A_Restart ROI from the last test). The next suite's
        // preparation-step expects would otherwise match the wrong
        // frame.
        harness.discard_unsolicited();
    }

    println!("====================================================================");
    println!("SUMMARY");
    println!("====================================================================");
    println!("  Test Suites:  {}", suites.len());
    println!("  Total Tests:  {}", total_tests);
    println!("  Passed:       {} ✅", passed);
    println!("  Failed:       {} ❌", failed);
    println!("  Total Steps:  {}", total_steps);
    println!("====================================================================");
    if failed > 0 {
        std::process::exit(1);
    }
    std::process::exit(0);
}
