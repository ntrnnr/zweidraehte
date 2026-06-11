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

/// `timeoutAuthentication` (10 s) and `timeoutSession` (60 s).
///
/// With the `conformance` feature, both are scaled down by the
/// `KNX_TIME_DIVISOR` environment variable, matching the Transport
/// Layer's fast-mode scaling so logical ordering survives compressed
/// test runs.
#[cfg_attr(not(feature = "ip-secure"), allow(dead_code))] // only the WithIpSecure path consumes these
pub(super) fn session_timeouts() -> (Duration, Duration) {
    const TIMEOUT_AUTHENTICATION_MS: u64 = 10_000;
    const TIMEOUT_SESSION_MS: u64 = 60_000;

    #[cfg(feature = "conformance")]
    {
        extern crate std;
        let divisor: u64 =
            std::env::var("KNX_TIME_DIVISOR").ok().and_then(|s| s.parse().ok()).filter(|&d| d > 0).unwrap_or(1);
        (
            Duration::from_millis(TIMEOUT_AUTHENTICATION_MS / divisor),
            Duration::from_millis(TIMEOUT_SESSION_MS / divisor),
        )
    }
    #[cfg(not(feature = "conformance"))]
    (Duration::from_millis(TIMEOUT_AUTHENTICATION_MS), Duration::from_millis(TIMEOUT_SESSION_MS))
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
}

/// IP Secure disabled — no per-session storage, all hooks no-ops.
pub struct NoIpSecure;

#[allow(private_interfaces)]
impl IpSecureFeature for NoIpSecure {
    const ENABLED: bool = false;
    const MAX_SESSIONS: usize = 0;
    type SessionSlot = ();
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
