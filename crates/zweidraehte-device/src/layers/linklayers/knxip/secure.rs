//! KNX IP Secure unicast sessions (03/08/09 §2.2.3).
//!
//! Compile-time feature slot plus the per-session state vocabulary. The
//! actual handshake / wrapper state machine lives in
//! [`super::session_handler`] and is only compiled with the `ip-secure`
//! cargo feature — without it, [`WithIpSecure`] does not exist and a
//! secure device definition fails to compile instead of silently
//! dropping secure traffic.
//!
//! Per-device secrets (PIDs 91–97) belong to the IP extension's
//! persistent config and reach this layer through
//! [`IpSecureConfigContext`](super::context::IpSecureConfigContext);
//! per-session scratch is link-layer state and lives here. Sessions are
//! TCP-only per §2.2.3.3, so the pool is sized by `MAX_TCP_STREAMS`
//! with a 1:1 session-per-stream affinity (closing the TCP connection
//! implicitly closes the session opened on it, §2.4.2).

use embassy_time::{Duration, Instant};
use heapless::Vec;

// ============================================================================
// Timeouts (§2.2.3.5.2.1.1)
// ============================================================================

/// Wall-clock time compression for conformance runs: 1 outside the
/// `conformance` feature, otherwise the `KNX_TIME_DIVISOR` environment
/// variable (matching the Transport Layer's fast-mode scaling so
/// logical ordering survives compressed test runs).
#[cfg_attr(not(feature = "ip-secure"), allow(dead_code))]
pub(super) fn time_divisor() -> u64 {
    #[cfg(feature = "conformance")]
    {
        extern crate std;
        std::env::var("KNX_TIME_DIVISOR").ok().and_then(|s| s.parse().ok()).filter(|&d| d > 0).unwrap_or(1)
    }
    #[cfg(not(feature = "conformance"))]
    1
}

/// `timeoutAuthentication` (10 s) and `timeoutSession` (60 s), scaled
/// by [`time_divisor`].
#[cfg_attr(not(feature = "ip-secure"), allow(dead_code))] // only the WithIpSecure path consumes these
pub(super) fn session_timeouts() -> (Duration, Duration) {
    const TIMEOUT_AUTHENTICATION_MS: u64 = 10_000;
    const TIMEOUT_SESSION_MS: u64 = 60_000;

    let divisor = time_divisor();
    (Duration::from_millis(TIMEOUT_AUTHENTICATION_MS / divisor), Duration::from_millis(TIMEOUT_SESSION_MS / divisor))
}

// ============================================================================
// Dispatch-path vocabulary
// ============================================================================

/// Upper bound for a handler-built response frame: the largest is the
/// plain SESSION_RESPONSE (56 bytes); wrapped SESSION_STATUS is 46.
pub(super) const SECURE_RESPONSE_MAX: usize = 64;

/// Response frames produced by the secure frame handler, to be sent
/// back on the originating TCP stream in order.
pub(super) type SecureResponses = Vec<Vec<u8, SECURE_RESPONSE_MAX>, 2>;

/// Read-only environment for the secure frame handler.
#[cfg_attr(not(feature = "ip-secure"), allow(dead_code))]
pub(super) struct SecureEnv<'a> {
    /// Persisted secrets (PIDs 91–97); `None` when the device state
    /// carries no IP Secure storage — all secure traffic is dropped.
    pub config: Option<&'a dyn crate::ip::IpSecureStateView>,
    /// Device KNX serial number (sender identity in outgoing wrappers).
    pub serial_number: [u8; 6],
    /// Cryptographically secure random fill, from
    /// [`StackDefinition::Rng`](crate::definition::StackDefinition::Rng).
    pub rng_fill: fn(&mut [u8]),
    pub now: Instant,
}

/// What the dispatch path should do after the handler ran.
#[cfg_attr(not(feature = "ip-secure"), allow(dead_code))]
pub(super) enum SecureFrameOutcome {
    /// Frame fully consumed (handshake step, status, drop). Any
    /// responses were pushed to the [`SecureResponses`] out-param. When
    /// the step deallocated a session, its ID is reported so the
    /// caller can tear down the KNX/IP connections bound to it.
    Handled { closed_session: Option<u16> },
    /// A SECURE_WRAPPER was authenticated and decrypted: `scratch[..len]`
    /// holds the plaintext inner KNXnet/IP frame, to be re-dispatched
    /// with the session identity attached.
    Inner { len: usize, session_id: u16, user_id: u8 },
}

/// Sessions expired by the periodic tick: the wrapped STATUS_TIMEOUT
/// frame to send, the TCP stream to send it on, and the session ID so
/// the caller can close the contained KNX/IP connections (§2.2.3.5.2.4
/// action A5).
#[cfg_attr(not(feature = "ip-secure"), allow(dead_code))]
pub(super) struct ExpiredSession {
    pub tcp_idx: usize,
    pub session_id: u16,
    pub status_frame: Vec<u8, SECURE_RESPONSE_MAX>,
}

// ============================================================================
// Session pool
// ============================================================================

/// Fixed pool of session slots plus the server-assigned ID counter.
///
/// Zero-sized when IP Secure is disabled (`SessionSlot = ()`).
#[cfg_attr(not(feature = "ip-secure"), allow(dead_code))]
pub struct SessionPool<S, const N: usize> {
    pub(super) slots: [S; N],
    /// Next candidate session identifier. IDs are non-zero (`0000h` is
    /// reserved for multicast) and skip values still in use.
    pub(super) next_session_id: u16,
}

impl<S: Default, const N: usize> SessionPool<S, N> {
    pub fn new() -> Self {
        Self { slots: core::array::from_fn(|_| S::default()), next_session_id: 1 }
    }
}

impl<S: Default, const N: usize> Default for SessionPool<S, N> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// IpSecureFeature: type-state slot
// ============================================================================

/// Compile-time feature slot for KNX IP Secure.
///
/// The disabled variant ([`NoIpSecure`]) zeroes out `MAX_SESSIONS`,
/// uses `()` as the session slot type, and folds every dispatch hook
/// to a no-op that LLVM eliminates. The enabled variant
/// (`WithIpSecure<N>`, `ip-secure` feature only) carves out `N` real
/// [`IpSecureSessionSlot`]s and routes the hooks to
/// [`super::session_handler`].
#[allow(private_interfaces)] // dispatch hooks take crate-internal types, same as TunnelingFeature
pub trait IpSecureFeature: 'static {
    /// Whether IP Secure is enabled in this build.
    const ENABLED: bool;

    /// Maximum concurrent IP Secure sessions. Bounded by TCP stream
    /// count because secure sessions are TCP-only (§2.2.3.3).
    const MAX_SESSIONS: usize;

    /// Per-session storage. Zero-sized when disabled.
    type SessionSlot: Default + 'static;

    /// Multicast timer + sync state machine storage for secure routing
    /// (§2.2.2). `()` when disabled, [`MulticastTimerState`] otherwise.
    type McTimerState: Default + 'static;

    /// Handle a top-level frame in the secure service-type range
    /// (`0950h..=0955h`). `tcp_idx` is `None` for UDP arrivals (secure
    /// unicast frames over UDP are discarded per §2.2.3.3). Decrypted
    /// inner frames are written to `scratch`.
    fn handle_secure_frame<const N: usize>(
        _pool: &mut SessionPool<Self::SessionSlot, N>,
        _frame: &[u8],
        _tcp_idx: Option<usize>,
        _env: &SecureEnv<'_>,
        _scratch: &mut [u8],
        _responses: &mut SecureResponses,
    ) -> SecureFrameOutcome {
        SecureFrameOutcome::Handled { closed_session: None }
    }

    /// Wrap an outgoing plaintext KNXnet/IP frame for the authenticated
    /// session bound to `tcp_idx`, writing the SECURE_WRAPPER into
    /// `out`. Returns the wrapper length, or `None` when no
    /// authenticated session owns that stream (send plain).
    fn wrap_outgoing<const N: usize>(
        _pool: &mut SessionPool<Self::SessionSlot, N>,
        _tcp_idx: usize,
        _plain: &[u8],
        _serial_number: &[u8; 6],
        _out: &mut [u8],
    ) -> Option<usize> {
        None
    }

    /// The authenticated session bound to `tcp_idx`, as
    /// `(session_id, user_id)`.
    fn session_for_tcp<const N: usize>(
        _pool: &SessionPool<Self::SessionSlot, N>,
        _tcp_idx: usize,
    ) -> Option<(u16, u8)> {
        None
    }

    /// Expire sessions whose timer ran out (event E06 → action A5).
    fn tick<const N: usize>(
        _pool: &mut SessionPool<Self::SessionSlot, N>,
        _now: Instant,
        _serial_number: &[u8; 6],
    ) -> Vec<ExpiredSession, 8> {
        Vec::new()
    }

    /// Earliest session deadline, for the runtime's select timer.
    fn next_deadline<const N: usize>(_pool: &SessionPool<Self::SessionSlot, N>) -> Option<Instant> {
        None
    }

    /// Tear down all sessions opened on a closing TCP stream (§2.4.2).
    /// Returns the closed session IDs so contained connections can be
    /// dropped.
    fn on_tcp_closed<const N: usize>(_pool: &mut SessionPool<Self::SessionSlot, N>, _tcp_idx: usize) -> Vec<u16, 8> {
        Vec::new()
    }

    // ---- Secure routing (multicast, §2.2.2) ----

    /// Handle a multicast SECURE_WRAPPER (session id `0000h`, backbone
    /// key) received on the routing endpoint. Runs the timer sync
    /// events E05–E08. Returns the decrypted inner frame length in
    /// `scratch` when the frame is authentic, fresh, and the mc_timer
    /// authenticity acquisition completed — `None` discards.
    fn handle_multicast_wrapper(
        _timer: &mut Self::McTimerState,
        _frame: &[u8],
        _env: &SecureEnv<'_>,
        _scratch: &mut [u8],
    ) -> Option<usize> {
        None
    }

    /// Handle a TIMER_NOTIFY received on the routing endpoint (timer
    /// sync events E01–E04).
    fn handle_timer_notify(_timer: &mut Self::McTimerState, _frame: &[u8], _env: &SecureEnv<'_>) {}

    /// Wrap an outgoing plain routing frame in a multicast
    /// SECURE_WRAPPER (backbone key, mc_timer as sequence information;
    /// timer sync event E09). Returns the wrapper length in `out`, or
    /// `None` when wrapping is impossible (no key, buffer too small,
    /// mc_timer not yet authentic).
    fn wrap_multicast_outgoing(
        _timer: &mut Self::McTimerState,
        _plain: &[u8],
        _env: &SecureEnv<'_>,
        _out: &mut [u8],
    ) -> Option<usize> {
        None
    }

    /// Drive the timer sync deadlines: event E10 (notify timer expiry,
    /// returns the TIMER_NOTIFY frame to send on the routing multicast
    /// endpoint) and the §2.2.2.3.2.8 authenticity-window expiry.
    fn mc_tick(_timer: &mut Self::McTimerState, _env: &SecureEnv<'_>) -> Option<TimerNotifyFrame> {
        None
    }

    /// Earliest timer-sync deadline, for the runtime's select timer.
    fn mc_next_deadline(_timer: &Self::McTimerState) -> Option<Instant> {
        None
    }

    /// Whether timer synchronization is currently running.
    fn mc_sync_started(_timer: &Self::McTimerState) -> bool {
        false
    }

    /// Start (or restart, action A7) the timer synchronization per
    /// §2.2.2.3.2.8. The first start after boot uses the random
    /// power-up initial-notify delay; restarts schedule immediately.
    fn mc_start_sync(_timer: &mut Self::McTimerState, _env: &SecureEnv<'_>) {}

    /// Stop the timer synchronization (§2.2.1.4.5: with Routing set to
    /// non-secure, no TimerNotify frames may be sent or received).
    fn mc_stop_sync(_timer: &mut Self::McTimerState) {}

    /// Event E11: the backbone key was rewritten with a different
    /// value — the mc_timer implicitly resets to 0 (§2.2.2.2.2) and
    /// the synchronization restarts (action A7).
    fn mc_on_backbone_key_changed(_timer: &mut Self::McTimerState, _env: &SecureEnv<'_>) {}
}

/// IP Secure disabled — no per-session storage, all hooks no-ops.
pub struct NoIpSecure;

#[allow(private_interfaces)]
impl IpSecureFeature for NoIpSecure {
    const ENABLED: bool = false;
    const MAX_SESSIONS: usize = 0;
    type SessionSlot = ();
    type McTimerState = ();
}

/// IP Secure enabled with `N` concurrent session slots.
///
/// `N` should equal `MAX_TCP_STREAMS` in the
/// [`KnxNetIpDefinition`](super::KnxNetIpDefinition) — secure sessions
/// have a 1:1 affinity with TCP streams (§2.2.3.3, §2.4.2: closing the
/// TCP connection implicitly closes all sessions opened on it).
#[cfg(feature = "ip-secure")]
pub struct WithIpSecure<const N: usize>;

#[cfg(feature = "ip-secure")]
#[allow(private_interfaces)]
impl<const N: usize> IpSecureFeature for WithIpSecure<N> {
    const ENABLED: bool = true;
    const MAX_SESSIONS: usize = N;
    type SessionSlot = IpSecureSessionSlot;
    type McTimerState = MulticastTimerState;

    fn handle_secure_frame<const NP: usize>(
        pool: &mut SessionPool<Self::SessionSlot, NP>,
        frame: &[u8],
        tcp_idx: Option<usize>,
        env: &SecureEnv<'_>,
        scratch: &mut [u8],
        responses: &mut SecureResponses,
    ) -> SecureFrameOutcome {
        super::session_handler::handle_secure_frame(pool, frame, tcp_idx, env, scratch, responses)
    }

    fn wrap_outgoing<const NP: usize>(
        pool: &mut SessionPool<Self::SessionSlot, NP>,
        tcp_idx: usize,
        plain: &[u8],
        serial_number: &[u8; 6],
        out: &mut [u8],
    ) -> Option<usize> {
        super::session_handler::wrap_outgoing(pool, tcp_idx, plain, serial_number, out)
    }

    fn session_for_tcp<const NP: usize>(
        pool: &SessionPool<Self::SessionSlot, NP>,
        tcp_idx: usize,
    ) -> Option<(u16, u8)> {
        super::session_handler::session_for_tcp(pool, tcp_idx)
    }

    fn tick<const NP: usize>(
        pool: &mut SessionPool<Self::SessionSlot, NP>,
        now: Instant,
        serial_number: &[u8; 6],
    ) -> Vec<ExpiredSession, 8> {
        super::session_handler::tick(pool, now, serial_number)
    }

    fn next_deadline<const NP: usize>(pool: &SessionPool<Self::SessionSlot, NP>) -> Option<Instant> {
        pool.slots
            .iter()
            .filter(|s| s.session_state != SecureSessionState::Idle)
            .filter_map(|s| s.session_timer_deadline)
            .min()
    }

    fn on_tcp_closed<const NP: usize>(pool: &mut SessionPool<Self::SessionSlot, NP>, tcp_idx: usize) -> Vec<u16, 8> {
        super::session_handler::on_tcp_closed(pool, tcp_idx)
    }

    fn handle_multicast_wrapper(
        timer: &mut Self::McTimerState,
        frame: &[u8],
        env: &SecureEnv<'_>,
        scratch: &mut [u8],
    ) -> Option<usize> {
        super::multicast_handler::handle_multicast_wrapper(timer, frame, env, scratch)
    }

    fn handle_timer_notify(timer: &mut Self::McTimerState, frame: &[u8], env: &SecureEnv<'_>) {
        super::multicast_handler::handle_timer_notify(timer, frame, env)
    }

    fn wrap_multicast_outgoing(
        timer: &mut Self::McTimerState,
        plain: &[u8],
        env: &SecureEnv<'_>,
        out: &mut [u8],
    ) -> Option<usize> {
        super::multicast_handler::wrap_multicast_outgoing(timer, plain, env, out)
    }

    fn mc_tick(timer: &mut Self::McTimerState, env: &SecureEnv<'_>) -> Option<TimerNotifyFrame> {
        super::multicast_handler::mc_tick(timer, env)
    }

    fn mc_next_deadline(timer: &Self::McTimerState) -> Option<Instant> {
        timer.next_deadline()
    }

    fn mc_sync_started(timer: &Self::McTimerState) -> bool {
        timer.started
    }

    fn mc_start_sync(timer: &mut Self::McTimerState, env: &SecureEnv<'_>) {
        super::multicast_handler::start_sync(timer, env)
    }

    fn mc_stop_sync(timer: &mut Self::McTimerState) {
        super::multicast_handler::stop_sync(timer)
    }

    fn mc_on_backbone_key_changed(timer: &mut Self::McTimerState, env: &SecureEnv<'_>) {
        super::multicast_handler::on_backbone_key_changed(timer, env)
    }
}

// ============================================================================
// IpSecureSessionSlot: per-session runtime state
// ============================================================================

/// Per-session runtime state for one secure unicast session (§2.2.3.5).
///
/// Sessions are allocated when a SESSION_REQUEST arrives over a TCP
/// control endpoint, parameterised with a fresh Curve25519 ECDH
/// keypair, and torn down on SESSION_STATUS `STATUS_CLOSE`, timeout,
/// authentication failure, or TCP disconnect.
#[derive(Default)]
pub struct IpSecureSessionSlot {
    /// Session identifier (assigned by server in SESSION_RESPONSE,
    /// non-zero for unicast; `0000h` reserved for multicast). 0 means
    /// "slot free" by convention here.
    pub session_id: u16,

    /// AES-128 key derived from the ECDH shared secret:
    /// `SHA256(Curve25519(myPrivateKey, peerPublicKey))[0..16]`
    /// (§2.2.3.1.2).
    pub session_key: [u8; 16],

    /// 48-bit monotonically increasing send counter. Starts at 0 each
    /// session; incremented after every SECURE_WRAPPER sent
    /// (§2.2.3.3).
    pub send_seq: u64,

    /// Next acceptable 48-bit receive counter. The first wrapper of a
    /// session carries 0; frames with a sequence below this value are
    /// replays and discarded (§2.2.3.3).
    pub recv_next_seq: u64,

    /// Session lifecycle state per the §2.2.3.5.2 state machine.
    pub session_state: SecureSessionState,

    /// Deadline for the current `session_timer`. `timeoutAuthentication`
    /// (10 s) while `Unauthenticated`, `timeoutSession` (60 s) while
    /// `Authenticated` (§2.2.3.5.2.1).
    pub session_timer_deadline: Option<Instant>,

    /// User ID that authenticated this session. `1` is the management
    /// user (full access); `2..=127` are device-specific roles
    /// (gated by `PID_TUNNELLING_USERS`). `None` while unauthenticated.
    pub authenticated_user_id: Option<u8>,

    /// Index of the TCP stream this session was opened on. Used for
    /// O(N) cleanup when the TCP connection closes (§2.4.2).
    pub tcp_stream_index: u8,

    /// ECDH ephemeral handshake state. Only valid during the
    /// SESSION_REQUEST → SESSION_RESPONSE → SESSION_AUTHENTICATE
    /// handshake; zeroed once `session_state` leaves `Unauthenticated`.
    pub ecdh_ephemeral: EcdhState,
}

impl IpSecureSessionSlot {
    /// Reserve the next send sequence number (post-increment).
    pub fn next_send_seq(&mut self) -> u64 {
        let seq = self.send_seq;
        self.send_seq += 1;
        seq
    }

    /// Validate and advance the receive counter. Returns `false` for
    /// replayed (already-seen) sequence numbers.
    pub fn accept_recv_seq(&mut self, seq: u64) -> bool {
        if seq >= self.recv_next_seq {
            self.recv_next_seq = seq + 1;
            true
        } else {
            false
        }
    }

    /// Free the slot, zeroising all key material.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Lifecycle state per §2.2.3.5.2.2.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureSessionState {
    /// Slot is free.
    #[default]
    Idle,
    /// SESSION_REQUEST received, SESSION_RESPONSE sent, awaiting
    /// SESSION_AUTHENTICATE within `timeoutAuthentication` (10 s).
    Unauthenticated,
    /// SESSION_AUTHENTICATE validated. Session may carry wrapped
    /// service requests until `timeoutSession` (60 s) or
    /// SESSION_STATUS `STATUS_CLOSE`.
    Authenticated,
}

/// ECDH ephemeral handshake state.
///
/// The public values X and Y are kept until authentication completes
/// because the SESSION_AUTHENTICATE MAC covers `XOR(X, Y)`
/// (§2.2.3.8.4); everything is zeroed once the session leaves
/// `Unauthenticated`.
#[derive(Default)]
pub struct EcdhState {
    /// Client public value X from the SESSION_REQUEST.
    pub client_public_key: [u8; 32],
    /// Our ephemeral public value Y sent in the SESSION_RESPONSE.
    pub server_public_key: [u8; 32],
}

// ============================================================================
// Service type identifiers (§2.6.1)
// ============================================================================

/// Service type identifiers for the KNX IP Secure family (`09xxh`),
/// as raw constants for range checks in the dispatch path. Typed
/// variants exist on `KNXnetIPServiceType`.
pub mod secure_service_types {
    pub const SECURE_WRAPPER: u16 = 0x0950;
    pub const SESSION_REQUEST: u16 = 0x0951;
    pub const SESSION_RESPONSE: u16 = 0x0952;
    pub const SESSION_AUTHENTICATE: u16 = 0x0953;
    pub const SESSION_STATUS: u16 = 0x0954;
    pub const TIMER_NOTIFY: u16 = 0x0955;

    /// Whether a raw service type belongs to the secure family.
    pub const fn is_secure(service_type: u16) -> bool {
        service_type >= SECURE_WRAPPER && service_type <= TIMER_NOTIFY
    }
}

/// Reserved User IDs (§2.2.3.8.2).
pub mod user_id {
    /// Management-level user — implicit access to all tunnelling
    /// addresses, never appears in `PID_TUNNELLING_USERS`.
    pub const MANAGEMENT: u8 = 0x01;
    /// Lowest valid user-level User ID.
    pub const USER_MIN: u8 = 0x02;
    /// Highest valid user-level User ID. Beyond this is reserved.
    pub const USER_MAX: u8 = 0x7F;
}

// ============================================================================
// Frame-size constants
// ============================================================================

/// Bytes added by SECURE_WRAPPER on top of the encapsulated KNXnet/IP
/// frame: 6 B Secure Header + 16 B Security Information + 16 B MAC
/// (§2.2.1.3.3).
///
/// Driver for the `TCP_SCRATCH_BUF_SIZE` bump on builds that enable
/// IP Secure (512 → 560 covers the worst case).
pub const SECURE_WRAPPER_OVERHEAD: usize = 6 + 16 + 16; // = 38

/// Minimum total frame size for SECURE_WRAPPER: 38 B overhead + 6 B
/// inner KNXnet/IP header = 44 B (§2.2.1.3.3). Frames smaller than
/// this must be discarded.
pub const SECURE_WRAPPER_MIN_LEN: usize = 44;

/// Fixed wire size of TIMER_NOTIFY: 6 B header + 14 B Security
/// Information + 16 B MAC = 36 B (§2.2.2.4.4).
pub const TIMER_NOTIFY_LEN: usize = 36;

/// A TIMER_NOTIFY frame built by the timer sync state machine, ready
/// to send on the routing multicast endpoint.
#[cfg_attr(not(feature = "ip-secure"), allow(dead_code))]
pub(super) type TimerNotifyFrame = Vec<u8, TIMER_NOTIFY_LEN>;

// ============================================================================
// Multicast timer sync (§2.2.2) — parameters and state
// ============================================================================

/// State of the timer sync state machine (§2.2.2.3.2.4).
#[cfg(feature = "ip-secure")]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum McTimerSyncState {
    /// A periodic TIMER_NOTIFY is scheduled (delay between
    /// `minDelayPeriodicNotify` and `maxDelayPeriodicNotify`).
    #[default]
    SchedPeriodic,
    /// An update TIMER_NOTIFY answering an outdated frame is scheduled
    /// (delay between `minDelayUpdateNotify` and `maxDelayUpdateNotify`).
    SchedUpdate,
}

/// Timer sync parameters per §2.2.2.3.2.2, derived from PID 95
/// (`latencyTolerance`) and PID 96 (`syncLatencyFraction`).
///
/// The tolerances classify *received timer values* and therefore live
/// in unscaled mc_timer milliseconds (the mc_timer always ticks
/// real-time, §2.2.2.2.2). The notify delays are *wall-clock waits* and
/// are compressed by [`time_divisor`] in conformance runs.
#[cfg(feature = "ip-secure")]
pub(super) struct McTimerParams {
    /// Frames older than this against the local mc_timer are replays
    /// and discarded (events E04/E08).
    pub latency_tolerance_ms: u64,
    /// Common-case latency; frames older than this (but within
    /// `latency_tolerance_ms`) are outdated-but-acceptable (E03/E07).
    pub sync_latency_tolerance_ms: u64,
    /// Power-up initial notify window: random(0, this) (§2.2.2.3.1.1 a).
    pub max_delay_initial_notify: u64,
    /// Periodic notify window, picked by time-keeper status (A8/A9).
    pub min_delay_periodic_keeper: u64,
    pub max_delay_periodic_keeper: u64,
    pub min_delay_periodic_follower: u64,
    pub max_delay_periodic_follower: u64,
    /// Update notify window, picked by time-keeper status (A8/A9).
    pub min_delay_update_keeper: u64,
    pub max_delay_update_keeper: u64,
    pub min_delay_update_follower: u64,
    pub max_delay_update_follower: u64,
}

#[cfg(feature = "ip-secure")]
impl McTimerParams {
    /// Build the parameter set from the persisted PIDs.
    pub fn from_view(view: &dyn crate::ip::IpSecureStateView) -> Self {
        let latency_tolerance = view.multicast_latency_tolerance_ms() as u64;
        // PID 96 is PDT_SCALING: 0..=255 maps linearly onto 0..=100 %.
        let sync_tolerance = latency_tolerance * view.sync_latency_fraction() as u64 / 255;

        let divisor = time_divisor();
        let scale = |ms: u64| ms / divisor;

        // Fixed bases and derived windows from the §2.2.2.3.2.2 tables.
        let min_periodic_keeper = 10_000u64;
        let max_periodic_keeper = min_periodic_keeper + 3 * sync_tolerance;
        let min_periodic_follower = max_periodic_keeper + sync_tolerance;
        let max_periodic_follower = min_periodic_follower + 10 * sync_tolerance;
        let min_update_keeper = 100u64;
        let max_update_keeper = min_update_keeper + sync_tolerance;
        let min_update_follower = max_update_keeper + sync_tolerance;
        let max_update_follower = min_update_follower + 10 * sync_tolerance;

        Self {
            latency_tolerance_ms: latency_tolerance,
            sync_latency_tolerance_ms: sync_tolerance,
            max_delay_initial_notify: scale(10_000),
            min_delay_periodic_keeper: scale(min_periodic_keeper),
            max_delay_periodic_keeper: scale(max_periodic_keeper),
            min_delay_periodic_follower: scale(min_periodic_follower),
            max_delay_periodic_follower: scale(max_periodic_follower),
            min_delay_update_keeper: scale(min_update_keeper),
            max_delay_update_keeper: scale(max_update_keeper),
            min_delay_update_follower: scale(min_update_follower),
            max_delay_update_follower: scale(max_update_follower),
        }
    }

    /// Wall-clock window of the mc_timer authenticity acquisition
    /// (§2.2.2.3.2.8): `maxDelayTimeFollowerUpdateNotify +
    /// 2 × latencyTolerance` after the first sent or received frame.
    pub fn authenticity_window_ms(&self) -> u64 {
        self.max_delay_update_follower + scaled(2 * self.latency_tolerance_ms)
    }
}

/// Scale a wall-clock duration by [`time_divisor`]. Free function so
/// param-derived values (already scaled) and raw tolerances (not
/// scaled, because they double as mc_timer-value thresholds) can be
/// combined explicitly.
#[cfg(feature = "ip-secure")]
fn scaled(ms: u64) -> u64 {
    ms / time_divisor()
}

/// Runtime state of the multicast timer and its sync state machine
/// (§2.2.2.3.2.3). Lives on the KNX/IP runtime next to [`SessionPool`]
/// — secure routing works with zero unicast sessions.
///
/// The mc_timer itself is an anchor pair: `base` milliseconds at
/// `epoch`, so the current value is `base + (now - epoch)` without a
/// dedicated hardware timer. The anchor only ever moves forward
/// (§2.2.2.2.2: the timer shall not be decreased in any case).
#[cfg(feature = "ip-secure")]
pub struct MulticastTimerState {
    /// Whether timer synchronization is active (§2.2.2.3.2.8: only
    /// while a multicast service family requires security).
    pub(super) started: bool,
    /// Whether the sync ever ran since process start. The first start
    /// is the §2.2.2.3.2.8 power-up case (random initial-notify delay
    /// against notify floods after a site-wide power cycle); later
    /// restarts schedule the notify immediately.
    pub(super) ever_started: bool,
    /// mc_timer milliseconds at `epoch`.
    pub(super) base: u64,
    /// Anchor instant for `base`.
    pub(super) epoch: Instant,
    pub(super) sync_state: McTimerSyncState,
    /// A8/A9: selects the keeper or follower delay windows.
    pub(super) is_time_keeper: bool,
    /// `notify_timer` (§2.2.2.3.2.3) as an absolute deadline; firing
    /// is event E10.
    pub(super) notify_deadline: Option<Instant>,
    /// Serial number and tag of the last outdated frame (action A4),
    /// echoed back in the update notify (action A6).
    pub(super) remembered_serial: [u8; 6],
    pub(super) remembered_tag: [u8; 2],
    /// §2.2.2.3.2.8: until true, decrypted multicast wrapper payloads
    /// are *not* passed to upper layers (the state machine still runs
    /// so the timer can be acquired).
    pub(super) mc_timer_authentic: bool,
    /// Deadline of the authenticity acquisition window; armed by the
    /// first sent or received TIMER_NOTIFY / multicast wrapper.
    pub(super) authentic_deadline: Option<Instant>,
    /// Tag of our last self-originated TIMER_NOTIFY (action A5);
    /// a received TIMER_NOTIFY repeating our serial + this tag proves
    /// another group member echoed an authentic timer value.
    pub(super) own_notify_tag: [u8; 2],
    /// Timer value of the most recently received valid frame, adopted
    /// as the initial mc_timer when the authenticity window expires.
    pub(super) last_received_timer: u64,
    /// §2.2.4.2 persistence watermark mirror: sending or adopting a
    /// timer value beyond this requires persisting first.
    pub(super) persisted_watermark: u64,
}

#[cfg(feature = "ip-secure")]
impl Default for MulticastTimerState {
    fn default() -> Self {
        Self {
            started: false,
            ever_started: false,
            base: 0,
            epoch: Instant::from_ticks(0),
            sync_state: McTimerSyncState::SchedPeriodic,
            is_time_keeper: false,
            notify_deadline: None,
            remembered_serial: [0; 6],
            remembered_tag: [0; 2],
            mc_timer_authentic: false,
            authentic_deadline: None,
            own_notify_tag: [0; 2],
            last_received_timer: 0,
            persisted_watermark: 0,
        }
    }
}

#[cfg(feature = "ip-secure")]
impl MulticastTimerState {
    /// Current mc_timer value in milliseconds.
    pub fn current(&self, now: Instant) -> u64 {
        self.base + now.saturating_duration_since(self.epoch).as_millis()
    }

    /// Adopt a received timer value (action A1) — but never decrease
    /// (§2.2.2.2.2). Returns the resulting current value.
    pub(super) fn adopt_at_least(&mut self, value: u64, now: Instant) -> u64 {
        if value > self.current(now) {
            self.base = value;
            self.epoch = now;
        }
        self.current(now)
    }

    /// Current mc_timer as 48-bit big-endian sequence information.
    pub(super) fn seq_info(&self, now: Instant) -> [u8; 6] {
        let bytes = self.current(now).to_be_bytes();
        [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
    }

    /// Earliest pending deadline (notify timer or authenticity window).
    pub fn next_deadline(&self) -> Option<Instant> {
        if !self.started {
            return None;
        }
        [self.notify_deadline, self.authentic_deadline].into_iter().flatten().min()
    }
}
