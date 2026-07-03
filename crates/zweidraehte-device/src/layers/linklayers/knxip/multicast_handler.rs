//! Secure routing — multicast timer sync state machine (03/08/09
//! §2.2.2.3.2) and backbone-key SECURE_WRAPPER handling.
//!
//! KNXnet/IP multicast cannot use per-sender sequence numbers, so
//! replay protection rides on a free-running 48-bit millisecond timer
//! (`mc_timer`) synchronized across the multicast group (§2.2.2.2).
//! Every multicast SECURE_WRAPPER and TIMER_NOTIFY carries the sender's
//! current timer value; receivers only adopt *greater* values (forward
//! sync) and discard frames older than `latencyTolerance`.
//!
//! Event/action labels in comments refer to the transition table in
//! §2.2.2.3.2.7 (E01–E11) and the action list in §2.2.2.3.2.6 (A0–A9).
//! The TIMER_NOTIFY events E01–E04 and the SECURE_WRAPPER events
//! E05–E08 classify the received timer value identically; they differ
//! in their actions (only TIMER_NOTIFY reception changes time-keeper
//! status — §2.2.2.3.2.7 NOTE 2 — and only wrappers carry data).
//!
//! Only compiled with the `ip-secure` cargo feature; reached through
//! the [`WithIpSecure`](super::secure::WithIpSecure) hooks.

use embassy_time::Duration;

use zweidraehte_proto::crypto::ip_secure_ccm::{self, IpSecureNonce};
use zweidraehte_proto::messages::knxip::{SecureWrapper, TimerNotify, TimerNotifyBuilder};
use zweidraehte_proto::util::packets::{ParseBuffer, SerializablePacket, SerializeBuffer};

use super::secure::{
    McTimerParams, McTimerSyncState, MulticastTimerState, SECURE_WRAPPER_OVERHEAD, SecureEnv, TimerNotifyFrame,
};

/// §2.2.4.2: maximum persistence interval `D`, measured in mc_timer
/// milliseconds. A device may only emit timer values in
/// `watermark .. watermark + D`; beyond that it must persist first.
/// Deliberately *not* scaled by `KNX_TIME_DIVISOR` — it bounds flash
/// wear, not protocol timing.
const PERSIST_INTERVAL_MS: u64 = 3_600_000;

/// Classification of a received timer value against the local
/// mc_timer (§2.2.2.3.2.5, Figure 10). Maps onto E01–E04 for
/// TIMER_NOTIFY and E05–E08 for SECURE_WRAPPER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerClass {
    /// `received > mc_timer` (E01/E05)
    Newer,
    /// within `syncLatencyTolerance` behind (E02/E06)
    Fresh,
    /// behind `syncLatencyTolerance` but within `latencyTolerance` (E03/E07)
    Outdated,
    /// behind `latencyTolerance` — replay (E04/E08)
    Replay,
}

/// Classify in signed arithmetic: early after a timer reset the
/// thresholds `mc_timer - tolerance` go negative, and saturating
/// unsigned math would misclassify fresh frames as replays.
fn classify(received: u64, current: u64, params: &McTimerParams) -> TimerClass {
    let received = received as i64;
    let current = current as i64;
    if received > current {
        TimerClass::Newer
    } else if received > current - params.sync_latency_tolerance_ms as i64 {
        TimerClass::Fresh
    } else if received > current - params.latency_tolerance_ms as i64 {
        TimerClass::Outdated
    } else {
        TimerClass::Replay
    }
}

/// 48-bit big-endian sequence information as a counter value.
fn seq_to_u64(seq_info: &[u8; 6]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes[2..8].copy_from_slice(seq_info);
    u64::from_be_bytes(bytes)
}

/// Uniform random integer in `min..=max` from the stack's RNG.
fn rand_range(env: &SecureEnv<'_>, min: u64, max: u64) -> u64 {
    if max <= min {
        return min;
    }
    let mut bytes = [0u8; 8];
    (env.rng_fill)(&mut bytes);
    min + u64::from_le_bytes(bytes) % (max - min + 1)
}

/// The secure-routing parameter set, available iff the device carries
/// IP Secure storage.
fn params(env: &SecureEnv<'_>) -> Option<McTimerParams> {
    env.config.map(McTimerParams::from_view)
}

/// Backbone key, `None` while unprovisioned (all-zero, §2.3.1.2).
fn backbone_key(env: &SecureEnv<'_>) -> Option<[u8; 16]> {
    let key = env.config?.backbone_key();
    (key != [0u8; 16]).then_some(key)
}

// ============================================================================
// §2.2.4.2 persistence watermark
// ============================================================================

/// Record that the mc_timer crossed the persistence window, so the
/// timer cannot run backwards across a power loss.
///
/// Updates the persisted-value mirror eagerly and flags
/// `timer.persist_pending`; the runtime's `drain_mc_persist` writes the
/// flagged value straight to the mc_timer store (via
/// [`IpSecureFeature::mc_take_persist_value`](super::secure::IpSecureFeature::mc_take_persist_value)):
///
/// - **Send path** (`wrap_multicast_outgoing`, `mc_tick`): the runtime
///   drains the flag *before* the produced frame leaves the device —
///   the 03/08/09 §2.2.4.2 ordering guarantee.
/// - **Receive path** (adopting a peer's newer value): drained at the
///   top of the next runtime loop iteration. The spec's "store
///   immediately" thus becomes "within one scheduler wake (and before
///   any outgoing frame)" — losing power inside that window leaves the
///   old, lower watermark behind, which is safe for outgoing replay
///   protection (nothing beyond it was ever sent) and re-converges on
///   the incoming side from the group's other members.
///
/// The watermark advances at most once per `PERSIST_INTERVAL_MS` of
/// mc_timer time on the send path; the receive path can be forced more
/// often by peers jumping the timer forward (wear-DoS consideration —
/// rate-limiting is the storage backend's call).
fn note_watermark(timer: &mut MulticastTimerState, env: &SecureEnv<'_>, value: u64) {
    if value > timer.persisted_watermark + PERSIST_INTERVAL_MS {
        if let Some(config) = env.config {
            config.set_persisted_mc_timer(value);
            timer.persist_pending = true;
        }
        timer.persisted_watermark = value;
    }
}

// ============================================================================
// Scheduling (actions A3 / A4) and time-keeper status (A8 / A9)
// ============================================================================

/// A3: reschedule the notify timer with the periodic window of the
/// current time-keeper status.
fn schedule_periodic(timer: &mut MulticastTimerState, params: &McTimerParams, env: &SecureEnv<'_>) {
    let (min, max) = if timer.is_time_keeper {
        (params.min_delay_periodic_keeper, params.max_delay_periodic_keeper)
    } else {
        (params.min_delay_periodic_follower, params.max_delay_periodic_follower)
    };
    timer.notify_deadline = Some(env.now + Duration::from_millis(rand_range(env, min, max)));
}

/// A4 (second half): schedule the update notify answering an outdated
/// frame. The serial/tag memorization happens at the call sites.
fn schedule_update(timer: &mut MulticastTimerState, params: &McTimerParams, env: &SecureEnv<'_>) {
    let (min, max) = if timer.is_time_keeper {
        (params.min_delay_update_keeper, params.max_delay_update_keeper)
    } else {
        (params.min_delay_update_follower, params.max_delay_update_follower)
    };
    timer.notify_deadline = Some(env.now + Duration::from_millis(rand_range(env, min, max)));
}

/// §2.2.2.3.2.8: the authenticity acquisition window starts with the
/// *first* TIMER_NOTIFY or SECURE_WRAPPER sent or received after the
/// sync (re)started.
fn arm_authenticity_window(timer: &mut MulticastTimerState, params: &McTimerParams, env: &SecureEnv<'_>) {
    if !timer.mc_timer_authentic && timer.authentic_deadline.is_none() {
        timer.authentic_deadline = Some(env.now + Duration::from_millis(params.authenticity_window_ms()));
    }
}

// ============================================================================
// Lifecycle: start / stop / E11
// ============================================================================

/// (Re)start the timer synchronization per §2.2.2.3.2.8.
///
/// The first start after process boot is the power-up case with the
/// random initial-notify delay that staggers notifies after a
/// site-wide power cycle; restarts triggered by configuration changes
/// schedule the notify immediately (also 03/02/06 §4.3.5.3.5.2 NOTE 3).
pub(super) fn start_sync(timer: &mut MulticastTimerState, env: &SecureEnv<'_>) {
    let power_up = !timer.ever_started;
    timer.ever_started = true;
    let Some(params) = params(env) else {
        return;
    };
    let Some(config) = env.config else {
        return;
    };

    // mc_timer = persisted watermark + worst-case interval offset
    // (§2.2.4.2); 0 only when never persisted with the current key.
    // A restart while the timer is already running keeps the (possibly
    // network-synced, thus greater) running value — the timer never
    // decreases (§2.2.2.2.2).
    let watermark = config.persisted_mc_timer();
    let from_storage = if watermark > 0 { watermark + PERSIST_INTERVAL_MS } else { 0 };
    if timer.started {
        timer.adopt_at_least(from_storage, env.now);
    } else {
        timer.base = from_storage;
        timer.epoch = env.now;
    }
    timer.persisted_watermark = timer.persisted_watermark.max(watermark);

    timer.started = true;
    timer.sync_state = McTimerSyncState::SchedPeriodic;
    timer.is_time_keeper = false;
    timer.mc_timer_authentic = false;
    timer.authentic_deadline = None;
    timer.last_received_timer = 0;

    // "Send or schedule a TIMER_NOTIFY. Remember the used tag." — the
    // tag is fixed now so a faster-than-us echo still matches.
    (env.rng_fill)(&mut timer.own_notify_tag);

    let delay = if power_up { rand_range(env, 0, params.max_delay_initial_notify) } else { 0 };
    timer.notify_deadline = Some(env.now + Duration::from_millis(delay));
    debug!("Secure routing timer sync started (initial notify in {} ms)", delay);
}

/// Stop the synchronization — §2.2.1.4.5: with Routing set to
/// non-secure, no TimerNotify frames may be sent or received.
pub(super) fn stop_sync(timer: &mut MulticastTimerState) {
    timer.started = false;
    timer.notify_deadline = None;
    timer.authentic_deadline = None;
    debug!("Secure routing timer sync stopped");
}

/// E11 (backbone key rewritten with a different value): the mc_timer
/// implicitly resets to 0 (§2.2.2.2.2), the persisted watermark of the
/// old key is invalidated, and the synchronization restarts (A7).
pub(super) fn on_backbone_key_changed(timer: &mut MulticastTimerState, env: &SecureEnv<'_>) {
    if let Some(config) = env.config {
        // Unlike the watermark advance in `ensure_persisted`, the reset
        // to 0 is not gated on the storage round-trip: losing it leaves
        // the *old* (higher) watermark behind, which errs in the safe
        // never-decrease direction, and the PID 91 write that raised
        // this event already marked the device state dirty.
        config.set_persisted_mc_timer(0);
    }
    timer.base = 0;
    timer.epoch = env.now;
    timer.persisted_watermark = 0;
    if timer.started {
        start_sync(timer, env);
    }
}

// ============================================================================
// TIMER_NOTIFY reception (events E01–E04)
// ============================================================================

pub(super) fn handle_timer_notify(timer: &mut MulticastTimerState, frame: &[u8], env: &SecureEnv<'_>) {
    if !timer.started {
        return;
    }
    let (Some(params), Some(key)) = (params(env), backbone_key(env)) else {
        return;
    };

    let mut buf = frame;
    let Ok(notify) = buf.parse::<TimerNotify>() else {
        debug!("Malformed TIMER_NOTIFY discarded");
        return;
    };
    if ip_secure_ccm::verify_timer_notify_mac(
        &key,
        &notify.timer_value,
        &notify.serial_number,
        &notify.message_tag,
        &notify.mac,
    )
    .is_err()
    {
        debug!("TIMER_NOTIFY failed authentication, discarded");
        return;
    }

    let received = seq_to_u64(&notify.timer_value);
    arm_authenticity_window(timer, &params, env);
    timer.last_received_timer = received;

    // §2.2.2.3.2.8: a TIMER_NOTIFY repeating our own serial number and
    // remembered tag is another group member echoing an authentic
    // timer value — acquisition completes early.
    if !timer.mc_timer_authentic
        && notify.serial_number == env.serial_number
        && notify.message_tag == timer.own_notify_tag
    {
        timer.adopt_at_least(received, env.now);
        note_watermark(timer, env, timer.current(env.now));
        timer.mc_timer_authentic = true;
        timer.authentic_deadline = None;
        debug!("mc_timer authentic (own TIMER_NOTIFY echoed)");
    }

    match classify(received, timer.current(env.now), &params) {
        // E01: A1 + A9 + A3, both states end in SCHED_PERIODIC.
        TimerClass::Newer => {
            let current = timer.adopt_at_least(received, env.now);
            note_watermark(timer, env, current);
            timer.is_time_keeper = false;
            timer.sync_state = McTimerSyncState::SchedPeriodic;
            schedule_periodic(timer, &params, env);
        }
        // E02: A9 + A3, both states end in SCHED_PERIODIC.
        TimerClass::Fresh => {
            timer.is_time_keeper = false;
            timer.sync_state = McTimerSyncState::SchedPeriodic;
            schedule_periodic(timer, &params, env);
        }
        // E03: A0.
        TimerClass::Outdated => {}
        // E04: A4 from SCHED_PERIODIC, A0 from SCHED_UPDATE (an update
        // notify answering the outdated sender is already scheduled).
        TimerClass::Replay => {
            if timer.sync_state == McTimerSyncState::SchedPeriodic {
                timer.remembered_serial = notify.serial_number;
                timer.remembered_tag = notify.message_tag;
                timer.sync_state = McTimerSyncState::SchedUpdate;
                schedule_update(timer, &params, env);
            }
        }
    }
}

// ============================================================================
// Multicast SECURE_WRAPPER reception (events E05–E08)
// ============================================================================

/// Authenticate and decrypt a multicast SECURE_WRAPPER, run the timer
/// sync events, and return the inner frame length in `scratch` when
/// the payload may be passed to upper layers.
pub(super) fn handle_multicast_wrapper(
    timer: &mut MulticastTimerState,
    frame: &[u8],
    env: &SecureEnv<'_>,
    scratch: &mut [u8],
) -> Option<usize> {
    if !timer.started {
        debug!("Multicast SECURE_WRAPPER discarded: timer sync not active");
        return None;
    }
    let (Some(params), Some(key)) = (params(env), backbone_key(env)) else {
        return None;
    };

    let mut buf = frame;
    let Ok(wrapper) = buf.parse::<SecureWrapper>() else {
        debug!("Malformed multicast SECURE_WRAPPER discarded");
        return None;
    };
    // §2.2.1.4.5: multicast communication uses session identifier 0000h.
    if wrapper.session_id != 0 {
        debug!("Multicast SECURE_WRAPPER with session id {} discarded", wrapper.session_id);
        return None;
    }

    let ciphertext = &buf[..wrapper.payload_len];
    let received_mac: [u8; 16] = buf[wrapper.payload_len..wrapper.payload_len + 16].try_into().ok()?;

    if scratch.len() < wrapper.payload_len {
        warn!("Multicast SECURE_WRAPPER payload exceeds scratch buffer, discarded");
        return None;
    }
    let inner = &mut scratch[..wrapper.payload_len];
    inner.copy_from_slice(ciphertext);

    // §2.2.1.3.3 "Sequence Information (Multicast)": even outdated
    // timer values feed the sync state machine, so the MAC must verify
    // *before* the timer comparison.
    let assoc = SecureWrapper::associated_data(0, wrapper.payload_len);
    let nonce = IpSecureNonce {
        seq_info: wrapper.seq_info,
        serial_number: wrapper.serial_number,
        message_tag: wrapper.message_tag,
    };
    if ip_secure_ccm::unwrap_secure(&key, &nonce, &assoc, inner, &received_mac).is_err() {
        debug!("Multicast SECURE_WRAPPER failed authentication, discarded");
        return None;
    }

    let received = seq_to_u64(&wrapper.seq_info);
    arm_authenticity_window(timer, &params, env);
    timer.last_received_timer = received;

    let accepted = match classify(received, timer.current(env.now), &params) {
        // E05: A1 + A2 (+ A3 in SCHED_PERIODIC). NOTE 2: receiving a
        // newer wrapper does not change time-keeper status.
        TimerClass::Newer => {
            let current = timer.adopt_at_least(received, env.now);
            // §2.2.4.2: a received value beyond the persistence window
            // must be persisted immediately.
            note_watermark(timer, env, current);
            if timer.sync_state == McTimerSyncState::SchedPeriodic {
                schedule_periodic(timer, &params, env);
            }
            true
        }
        // E06: A2 (+ A3 in SCHED_PERIODIC).
        TimerClass::Fresh => {
            if timer.sync_state == McTimerSyncState::SchedPeriodic {
                schedule_periodic(timer, &params, env);
            }
            true
        }
        // E07: A2 only — accepted, but does not feed the schedule.
        TimerClass::Outdated => true,
        // E08: A4 from SCHED_PERIODIC, A0 from SCHED_UPDATE; discard.
        TimerClass::Replay => {
            if timer.sync_state == McTimerSyncState::SchedPeriodic {
                timer.remembered_serial = wrapper.serial_number;
                timer.remembered_tag = wrapper.message_tag;
                timer.sync_state = McTimerSyncState::SchedUpdate;
                schedule_update(timer, &params, env);
            }
            debug!("Multicast SECURE_WRAPPER replay (timer {} too old) discarded", received);
            false
        }
    };

    // §2.2.2.3.2.8: until the mc_timer is authentic, decrypted payloads
    // must not reach upper layers (the timer state machine above still
    // ran — that is how the authentic time is acquired).
    if accepted && !timer.mc_timer_authentic {
        debug!("Multicast SECURE_WRAPPER payload withheld: mc_timer not yet authentic");
        return None;
    }

    accepted.then_some(wrapper.payload_len)
}

// ============================================================================
// Outgoing wrap (event E09)
// ============================================================================

/// Wrap an outgoing plain routing frame in a multicast SECURE_WRAPPER
/// (session id 0000h, backbone key, mc_timer as sequence information).
pub(super) fn wrap_multicast_outgoing(
    timer: &mut MulticastTimerState,
    plain: &[u8],
    env: &SecureEnv<'_>,
    out: &mut [u8],
) -> Option<usize> {
    if !timer.started {
        return None;
    }
    let (Some(params), Some(key)) = (params(env), backbone_key(env)) else {
        return None;
    };
    // §2.2.2.3.2.8 strict gate: no SECURE_WRAPPER may be sent before
    // the mc_timer is authentic. TODO: the spec alternatively allows
    // sending early when the application is robust against the
    // resulting replay window — expose that as an opt-in if a device
    // ever needs sub-17 s data readiness after boot.
    if !timer.mc_timer_authentic {
        debug!("Outgoing routing frame dropped: mc_timer not yet authentic");
        return None;
    }

    let total = plain.len() + SECURE_WRAPPER_OVERHEAD;
    if out.len() < total {
        error!("Multicast SECURE_WRAPPER output buffer too small ({} < {})", out.len(), total);
        return None;
    }

    // §2.2.4.2: persist before emitting a timer value beyond the
    // persistence window.
    let value = timer.current(env.now);
    note_watermark(timer, env, value);

    let seq_info = timer.seq_info(env.now);
    // The message tag differentiates two frames sent by the same device
    // in the same millisecond (§2.2.1.3.2) — random per frame.
    let mut message_tag = [0u8; 2];
    (env.rng_fill)(&mut message_tag);

    // Encrypt the payload in place inside `out`, then frame it — same
    // layout as the unicast wrap in `session_handler::wrap_outgoing`.
    let payload_range = 22..22 + plain.len();
    out[payload_range.clone()].copy_from_slice(plain);
    let assoc = SecureWrapper::associated_data(0, plain.len());
    let nonce = IpSecureNonce { seq_info, serial_number: env.serial_number, message_tag };
    let mac = ip_secure_ccm::wrap_secure(&key, &nonce, &assoc, &mut out[payload_range.clone()]);

    out[0..8].copy_from_slice(&assoc);
    out[8..14].copy_from_slice(&seq_info);
    out[14..20].copy_from_slice(&env.serial_number);
    out[20..22].copy_from_slice(&message_tag);
    out[payload_range.end..total].copy_from_slice(&mac);

    // E09: A3 in SCHED_PERIODIC, A0 in SCHED_UPDATE (a pending update
    // notify deliberately survives our own send — §2.2.2.3.2.7 NOTE 3).
    if timer.sync_state == McTimerSyncState::SchedPeriodic {
        schedule_periodic(timer, &params, env);
    }

    Some(total)
}

// ============================================================================
// Deadline tick (event E10 + authenticity window expiry)
// ============================================================================

/// Drive the two wall-clock deadlines. Returns a TIMER_NOTIFY frame to
/// send on the routing multicast endpoint when E10 fired.
pub(super) fn mc_tick(timer: &mut MulticastTimerState, env: &SecureEnv<'_>) -> Option<TimerNotifyFrame> {
    if !timer.started {
        return None;
    }
    let (Some(params), Some(key)) = (params(env), backbone_key(env)) else {
        return None;
    };

    // Authenticity window expired: adopt the most recent received timer
    // value (never decreasing) and open the data path (§2.2.2.3.2.8).
    if timer.authentic_deadline.is_some_and(|deadline| deadline <= env.now) {
        let current = timer.adopt_at_least(timer.last_received_timer, env.now);
        note_watermark(timer, env, current);
        timer.mc_timer_authentic = true;
        timer.authentic_deadline = None;
        debug!("mc_timer authentic (acquisition window elapsed)");
    }

    // E10: the notify timer expired.
    if timer.notify_deadline.is_some_and(|deadline| deadline <= env.now) {
        timer.notify_deadline = None;

        let value = timer.current(env.now);
        note_watermark(timer, env, value);
        let timer_value = timer.seq_info(env.now);

        // SCHED_PERIODIC → A5: own serial, fresh random tag (remembered
        // for the §2.2.2.3.2.8 echo check). SCHED_UPDATE → A6: repeat
        // the outdated sender's serial and tag remembered by A4.
        let (serial, tag) = match timer.sync_state {
            McTimerSyncState::SchedPeriodic => {
                (env.rng_fill)(&mut timer.own_notify_tag);
                (env.serial_number, timer.own_notify_tag)
            }
            McTimerSyncState::SchedUpdate => (timer.remembered_serial, timer.remembered_tag),
        };

        // Both rows: + A8 (become time keeper) + A3, ending in
        // SCHED_PERIODIC.
        timer.is_time_keeper = true;
        timer.sync_state = McTimerSyncState::SchedPeriodic;
        schedule_periodic(timer, &params, env);

        let mac = ip_secure_ccm::timer_notify_mac(&key, &timer_value, &serial, &tag);
        let builder = TimerNotifyBuilder { timer_value, serial_number: serial, message_tag: tag, mac };
        let mut frame = TimerNotifyFrame::new();
        frame.resize(builder.bytes_len(), 0).expect("TIMER_NOTIFY is exactly TIMER_NOTIFY_LEN bytes");
        let mut buf = frame.as_mut_slice();
        SerializeBuffer::serialize(&mut buf, &builder);

        // Sending a TIMER_NOTIFY also opens the authenticity window —
        // it is the "first frame sent" of §2.2.2.3.2.8.
        arm_authenticity_window(timer, &params, env);

        return Some(frame);
    }

    None
}

// ============================================================================
// Unit tests — state machine transitions against hand-built frames
// ============================================================================

#[cfg(test)]
mod tests {
    extern crate std;

    use core::cell::Cell;

    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use embassy_sync::channel::Channel;
    use embassy_time::Instant;

    use crate::ip::{IpSecureStateView, IpSecureSyncEvent};
    use zweidraehte_proto::messages::knxip::substructs::ServiceFamily;

    use super::*;

    /// Appendix A backbone key `00 01 … 0f`.
    const KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const OWN_SERIAL: [u8; 6] = [0x00, 0xfa, 0x12, 0x34, 0x56, 0x78];
    const PEER_SERIAL: [u8; 6] = [0x00, 0xfb, 0x00, 0x00, 0x00, 0x01];

    struct MockView {
        backbone_key: [u8; 16],
        persisted: Cell<u64>,
        channel: Channel<NoopRawMutex, IpSecureSyncEvent, 2>,
    }

    impl MockView {
        fn new() -> Self {
            Self { backbone_key: KEY, persisted: Cell::new(0), channel: Channel::new() }
        }
    }

    impl IpSecureStateView for MockView {
        fn backbone_key(&self) -> [u8; 16] {
            self.backbone_key
        }
        fn device_authentication_code(&self) -> [u8; 16] {
            [0; 16]
        }
        fn password_hash(&self, _user_id: u8) -> Option<[u8; 16]> {
            None
        }
        fn secured_service_family(&self, _family: ServiceFamily) -> u8 {
            1
        }
        fn multicast_latency_tolerance_ms(&self) -> u16 {
            2000
        }
        fn sync_latency_fraction(&self) -> u8 {
            0x1A // ≈ 10.2 % → syncLatencyTolerance = 203 ms
        }
        fn tunnelling_user_allowed(&self, _user_id: u8, _tunnelling_slot: u8) -> bool {
            false
        }
        fn persisted_mc_timer(&self) -> u64 {
            self.persisted.get()
        }
        fn set_persisted_mc_timer(&self, value: u64) {
            self.persisted.set(value);
        }
        fn mc_sync_event_channel(&self) -> &Channel<NoopRawMutex, IpSecureSyncEvent, 2> {
            &self.channel
        }
    }

    fn fixed_rng(buf: &mut [u8]) {
        buf.fill(0x42);
    }

    fn env_at<'a>(view: &'a MockView, ms: u64) -> SecureEnv<'a> {
        SecureEnv { config: Some(view), serial_number: OWN_SERIAL, rng_fill: fixed_rng, now: Instant::from_millis(ms) }
    }

    fn started_timer(view: &MockView) -> MulticastTimerState {
        let mut timer = MulticastTimerState::default();
        start_sync(&mut timer, &env_at(view, 0));
        timer
    }

    /// Skip the §2.2.2.3.2.8 acquisition so data flows in tests that
    /// exercise the steady state.
    fn make_authentic(timer: &mut MulticastTimerState) {
        timer.mc_timer_authentic = true;
        timer.authentic_deadline = None;
    }

    fn build_notify(timer_value: u64, serial: [u8; 6], tag: [u8; 2]) -> std::vec::Vec<u8> {
        let bytes = timer_value.to_be_bytes();
        let value = [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]];
        let mac = ip_secure_ccm::timer_notify_mac(&KEY, &value, &serial, &tag);
        let builder = TimerNotifyBuilder { timer_value: value, serial_number: serial, message_tag: tag, mac };
        let mut out = std::vec![0u8; builder.bytes_len()];
        let mut buf = out.as_mut_slice();
        SerializeBuffer::serialize(&mut buf, &builder);
        out
    }

    fn build_wrapper(timer_value: u64, serial: [u8; 6], plain: &[u8]) -> std::vec::Vec<u8> {
        let bytes = timer_value.to_be_bytes();
        let seq_info = [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]];
        let message_tag = [0xaf, 0xfe];
        let mut payload = std::vec::Vec::from(plain);
        let assoc = SecureWrapper::associated_data(0, plain.len());
        let nonce = IpSecureNonce { seq_info, serial_number: serial, message_tag };
        let mac = ip_secure_ccm::wrap_secure(&KEY, &nonce, &assoc, &mut payload);

        let mut out = std::vec::Vec::new();
        out.extend_from_slice(&assoc);
        out.extend_from_slice(&seq_info);
        out.extend_from_slice(&serial);
        out.extend_from_slice(&message_tag);
        out.extend_from_slice(&payload);
        out.extend_from_slice(&mac);
        out
    }

    /// A minimal plain inner frame (KNXnet/IP header only, service type
    /// irrelevant for the wrapper layer).
    const INNER: [u8; 6] = [0x06, 0x10, 0x05, 0x30, 0x00, 0x06];

    #[test]
    fn wrapper_roundtrip_through_wrap_and_handle() {
        let view = MockView::new();
        let mut sender = started_timer(&view);
        make_authentic(&mut sender);
        let mut receiver = started_timer(&view);
        make_authentic(&mut receiver);

        let env = env_at(&view, 5_000);
        let mut wire = [0u8; 64];
        let len = wrap_multicast_outgoing(&mut sender, &INNER, &env, &mut wire).expect("wrap succeeds");
        assert_eq!(len, INNER.len() + SECURE_WRAPPER_OVERHEAD);

        let mut scratch = [0u8; 64];
        let inner_len = handle_multicast_wrapper(&mut receiver, &wire[..len], &env, &mut scratch)
            .expect("authentic fresh wrapper accepted");
        assert_eq!(&scratch[..inner_len], &INNER);
    }

    #[test]
    fn replayed_wrapper_discarded_and_schedules_update_notify() {
        let view = MockView::new();
        let mut timer = started_timer(&view);
        make_authentic(&mut timer);
        // Local mc_timer at 10 s; a frame stamped 1 s is 9 s old —
        // far beyond the 2 s latencyTolerance, so E08 (replay).
        let env = env_at(&view, 10_000);
        let frame = build_wrapper(1_000, PEER_SERIAL, &INNER);
        let mut scratch = [0u8; 64];

        assert!(handle_multicast_wrapper(&mut timer, &frame, &env, &mut scratch).is_none());
        assert_eq!(timer.sync_state, McTimerSyncState::SchedUpdate);
        assert_eq!(timer.remembered_serial, PEER_SERIAL);
        // A4 scheduled the update notify; firing it must echo the
        // outdated sender's serial + tag (A6).
        let deadline = timer.notify_deadline.expect("update notify scheduled");
        let env_late = env_at(&view, deadline.as_millis());
        let notify = mc_tick(&mut timer, &env_late).expect("E10 emits TIMER_NOTIFY");
        let mut buf = &notify[..];
        let parsed = buf.parse::<TimerNotify>().expect("valid TIMER_NOTIFY");
        assert_eq!(parsed.serial_number, PEER_SERIAL);
        assert_eq!(parsed.message_tag, [0xaf, 0xfe]);
        // A8: answering an update made us time keeper, back in PERIODIC.
        assert!(timer.is_time_keeper);
        assert_eq!(timer.sync_state, McTimerSyncState::SchedPeriodic);
    }

    #[test]
    fn newer_timer_notify_adopts_value_and_demotes_keeper() {
        let view = MockView::new();
        let mut timer = started_timer(&view);
        make_authentic(&mut timer);
        timer.is_time_keeper = true;

        let env = env_at(&view, 1_000);
        let frame = build_notify(50_000, PEER_SERIAL, [0x12, 0x34]);
        handle_timer_notify(&mut timer, &frame, &env);

        // E01: A1 adopted the greater value, A9 demoted us.
        assert_eq!(timer.current(env.now), 50_000);
        assert!(!timer.is_time_keeper);
        // §2.2.4.2: the adopted value left the persistence window of
        // watermark 0 … 0 + D? 50_000 < 3_600_000 — within, no persist.
        assert_eq!(view.persisted.get(), 0);
    }

    #[test]
    fn mc_timer_never_decreases() {
        let view = MockView::new();
        let mut timer = started_timer(&view);
        make_authentic(&mut timer);
        let env = env_at(&view, 1_000);
        timer.adopt_at_least(80_000, env.now);

        // An older (but within tolerance of 80 000) TIMER_NOTIFY must
        // not pull the timer back.
        let frame = build_notify(79_900, PEER_SERIAL, [0x12, 0x34]);
        handle_timer_notify(&mut timer, &frame, &env);
        assert_eq!(timer.current(env.now), 80_000);
    }

    #[test]
    fn data_withheld_until_authentic_then_window_expiry_opens_path() {
        let view = MockView::new();
        let mut timer = started_timer(&view);
        assert!(!timer.mc_timer_authentic);

        // A fresh wrapper arrives during acquisition: state machine
        // runs (timer adopted) but the payload is withheld.
        let env = env_at(&view, 100);
        let frame = build_wrapper(7_000, PEER_SERIAL, &INNER);
        let mut scratch = [0u8; 64];
        assert!(handle_multicast_wrapper(&mut timer, &frame, &env, &mut scratch).is_none());
        assert_eq!(timer.current(env.now), 7_000);
        let deadline = timer.authentic_deadline.expect("window armed by first received frame");

        // Window elapses: acquisition completes with the most recent
        // received value; subsequent wrappers pass through.
        let env_late = env_at(&view, deadline.as_millis());
        assert!(mc_tick(&mut timer, &env_late).is_none() || timer.mc_timer_authentic);
        assert!(timer.mc_timer_authentic);

        let env_after = env_at(&view, deadline.as_millis() + 10);
        let fresh = build_wrapper(timer.current(env_after.now), PEER_SERIAL, &INNER);
        assert!(handle_multicast_wrapper(&mut timer, &fresh, &env_after, &mut scratch).is_some());
    }

    #[test]
    fn own_notify_echo_completes_acquisition_early() {
        let view = MockView::new();
        let mut timer = started_timer(&view);

        // Fire the initial notify (E10) — remembers own_notify_tag.
        let deadline = timer.notify_deadline.expect("initial notify scheduled");
        let env = env_at(&view, deadline.as_millis());
        let notify = mc_tick(&mut timer, &env).expect("initial TIMER_NOTIFY");
        let mut buf = &notify[..];
        let own_tag = buf.parse::<TimerNotify>().expect("valid frame").message_tag;
        assert!(!timer.mc_timer_authentic);

        // A peer echoes our serial + tag with its (greater) timer.
        let env2 = env_at(&view, deadline.as_millis() + 50);
        let echo = build_notify(90_000, OWN_SERIAL, own_tag);
        handle_timer_notify(&mut timer, &echo, &env2);
        assert!(timer.mc_timer_authentic);
        assert_eq!(timer.current(env2.now), 90_000);
    }

    #[test]
    fn wrapper_with_nonzero_session_id_discarded() {
        let view = MockView::new();
        let mut timer = started_timer(&view);
        make_authentic(&mut timer);

        let env = env_at(&view, 1_000);
        let mut frame = build_wrapper(1_000, PEER_SERIAL, &INNER);
        // Corrupt the session id (bytes 6..8 of the wrapper) — §2.2.1.4.5
        // requires 0000h on multicast. The MAC would fail anyway (the
        // session id is associated data), but the id check must reject
        // it first.
        frame[7] = 0x01;
        let mut scratch = [0u8; 64];
        assert!(handle_multicast_wrapper(&mut timer, &frame, &env, &mut scratch).is_none());
    }

    #[test]
    fn periodic_notify_after_idle_window() {
        let view = MockView::new();
        let mut timer = started_timer(&view);
        make_authentic(&mut timer);

        // Receive one fresh frame to (re)arm the periodic schedule.
        let env = env_at(&view, 1_000);
        let frame = build_notify(1_000, PEER_SERIAL, [0x12, 0x34]);
        handle_timer_notify(&mut timer, &frame, &env);
        let deadline = timer.notify_deadline.expect("periodic notify scheduled");

        // Nothing received until the deadline — E10 sends our own value
        // (A5) and promotes us to time keeper (A8).
        let env_late = env_at(&view, deadline.as_millis());
        let notify = mc_tick(&mut timer, &env_late).expect("periodic TIMER_NOTIFY");
        let mut buf = &notify[..];
        let parsed = buf.parse::<TimerNotify>().expect("valid frame");
        assert_eq!(parsed.serial_number, OWN_SERIAL);
        assert!(timer.is_time_keeper);
    }

    #[test]
    fn backbone_key_change_resets_timer_and_watermark() {
        let view = MockView::new();
        view.persisted.set(10_000_000);
        let mut timer = MulticastTimerState::default();
        start_sync(&mut timer, &env_at(&view, 0));
        // Power-up restored watermark + interval.
        assert_eq!(timer.current(Instant::from_millis(0)), 10_000_000 + PERSIST_INTERVAL_MS);

        let env = env_at(&view, 1_000);
        on_backbone_key_changed(&mut timer, &env);
        assert_eq!(timer.current(env.now), 0);
        assert_eq!(view.persisted.get(), 0);
        assert!(timer.started, "sync restarts after key change");
        assert!(!timer.mc_timer_authentic);
        // §2.2.2.3.2.8 / 03/02/06 NOTE 3: no random power-up delay on a
        // config-triggered restart.
        assert_eq!(timer.notify_deadline, Some(env.now));
    }

    #[test]
    fn sends_gated_while_not_authentic() {
        let view = MockView::new();
        let mut timer = started_timer(&view);
        let env = env_at(&view, 1_000);
        let mut out = [0u8; 64];
        assert!(wrap_multicast_outgoing(&mut timer, &INNER, &env, &mut out).is_none());
    }

    #[test]
    fn persistence_watermark_advances_before_send() {
        let view = MockView::new();
        let mut timer = started_timer(&view);
        make_authentic(&mut timer);

        // Jump the mc_timer beyond watermark + D via a received notify.
        let env = env_at(&view, 1_000);
        let frame = build_notify(PERSIST_INTERVAL_MS + 500_000, PEER_SERIAL, [0x12, 0x34]);
        handle_timer_notify(&mut timer, &frame, &env);
        assert_eq!(view.persisted.get(), PERSIST_INTERVAL_MS + 500_000, "received value beyond window persists");

        let mut out = [0u8; 64];
        let env2 = env_at(&view, 2_000);
        wrap_multicast_outgoing(&mut timer, &INNER, &env2, &mut out).expect("wrap succeeds");
        // Still inside the new window — no further persist.
        assert_eq!(view.persisted.get(), PERSIST_INTERVAL_MS + 500_000);
    }

    /// 03/08/09 §2.2.4.2: a watermark advance updates the persisted
    /// mirror eagerly and flags the pending durable save for the
    /// runtime's drain (`mc_take_persist_value` → gated round-trip);
    /// values inside the window do neither. The blocks-until-reply
    /// property of the drain is `ActorRequest` semantics, covered by
    /// the persist-channel test in `crate::persist`.
    #[test]
    fn note_watermark_flags_pending_persist() {
        let view = MockView::new();
        let mut timer = started_timer(&view);
        make_authentic(&mut timer);

        // Within the window: no persist activity.
        let env = env_at(&view, 1_000);
        note_watermark(&mut timer, &env, 50_000);
        assert!(!timer.persist_pending);
        assert_eq!(view.persisted.get(), 0);

        // Beyond watermark + D: mirror updated, pending flagged.
        const JUMPED: u64 = PERSIST_INTERVAL_MS + 500_000;
        note_watermark(&mut timer, &env, JUMPED);
        assert!(timer.persist_pending);
        assert_eq!(view.persisted.get(), JUMPED);
        assert_eq!(timer.persisted_watermark, JUMPED);

        // The receive path reaches it through the handlers too.
        timer.persist_pending = false;
        let frame = build_notify(JUMPED + PERSIST_INTERVAL_MS + 1, PEER_SERIAL, [0x12, 0x34]);
        handle_timer_notify(&mut timer, &frame, &env);
        assert!(timer.persist_pending, "adopted received value beyond the window flags the persist");
    }
}
