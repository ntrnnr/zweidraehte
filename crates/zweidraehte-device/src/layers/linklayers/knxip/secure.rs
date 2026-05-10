//! KNX IP Secure: feature trait + skeleton types.
//!
//! This module provides only the *shape* needed for IP Secure (Vol 3
//! Part 8 §9, document `03_08_09 KNX IP Secure v01.01.02 AS.pdf`). No
//! crypto code lives here yet. The goal is that other parts of the
//! link-layer refactor can already mention `D::Features::IpSecure`,
//! `IpSecureSessionSlot`, and the per-session pool sizing without
//! breaking when the crypto eventually lands.
//!
//! ## What goes here vs the device extension
//!
//! Persistent IP-Secure secrets (PIDs 91–97 of the KNXnet/IP Parameter
//! Object: `backbone_key`, `device_authentication_code`,
//! `password_hashes`, `secured_service_families`,
//! `multicast_latency_tolerance`, `sync_latency_fraction`,
//! `tunnelling_users`) are **device state**, not link-layer state —
//! they belong on the IP extension's persistent config blob in
//! `bcus/system_b/extensions/ip/storage.rs`. The link layer reaches
//! them through the [`HasIpSecureConfig`](super::context::HasIpSecureConfig) /
//! [`HasMcTimer`](super::context::HasMcTimer) context traits. The
//! per-session pool, on the other hand, is link-layer scratch (one
//! slot per concurrent secure unicast session) and lives in
//! [`KnxNetIpResources`](super::KnxNetIpResources).
//!
//! ## Sizing
//!
//! IP Secure unicast sessions must use TCP per §2.2.3.3 — they cannot
//! run over UDP because the replay-attack defence relies on TCP
//! reliability. This means `MAX_SECURE_SESSIONS` is naturally bounded
//! by `MAX_TCP_STREAMS`; the `KnxNetIpDefinition` trait defaults the
//! two to the same value.

#![allow(dead_code)] // skeleton — used once IP Secure crypto lands

use core::marker::PhantomData;

use embassy_time::Instant;

// ============================================================================
// IpSecureFeature: type-state slot
// ============================================================================

/// Compile-time feature slot for KNX IP Secure.
///
/// The disabled variant ([`NoIpSecure`]) zeroes out `MAX_SESSIONS` and
/// uses `()` as the session slot type, so the secure-session array in
/// [`KnxNetIpResources`](super::KnxNetIpResources) compiles down to
/// nothing. The enabled variant ([`WithIpSecure<N>`]) carves out `N`
/// real [`IpSecureSessionSlot`]s.
///
/// Once IP Secure ships, the link-layer dispatch path for the secure
/// service-type range `0950h..=09FFh` (SECURE_WRAPPER, SESSION_REQUEST,
/// SESSION_RESPONSE, SESSION_AUTHENTICATE, SESSION_STATUS, TIMER_NOTIFY)
/// will gain handler methods on this trait, mirroring the
/// `RoutingFeature` / `TunnelingFeature` pattern.
pub trait IpSecureFeature: 'static {
    /// Whether IP Secure is enabled in this build.
    const ENABLED: bool;

    /// Maximum concurrent IP Secure sessions. Bounded by TCP stream
    /// count because secure sessions are TCP-only (§2.2.3.3).
    const MAX_SESSIONS: usize;

    /// Per-session storage. Zero-sized when disabled.
    type SessionSlot: Default + 'static;
}

/// IP Secure disabled — no per-session storage.
pub struct NoIpSecure;

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
pub struct WithIpSecure<const N: usize>;

impl<const N: usize> IpSecureFeature for WithIpSecure<N> {
    const ENABLED: bool = true;
    const MAX_SESSIONS: usize = N;
    type SessionSlot = IpSecureSessionSlot;
}

// ============================================================================
// IpSecureSessionSlot: per-session runtime state
// ============================================================================

/// Per-session runtime state for one secure unicast session (§2.2.3.5).
///
/// Sessions are allocated when a [`SESSION_REQUEST`](secure_service_types::SESSION_REQUEST)
/// arrives over a TCP control endpoint, parameterised with a fresh
/// Curve25519 ECDH keypair, and torn down on
/// [`SESSION_STATUS`](secure_service_types::SESSION_STATUS) `STATUS_CLOSE`,
/// timeout, or TCP disconnect.
///
/// All fields are stubs — the crypto layer fills them in. Sized
/// purposely so the storage cost in [`KnxNetIpResources`] is
/// predictable when sizing a build.
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

    /// Last accepted 48-bit receive counter. Frames with seq ≤ this
    /// are discarded (§2.2.3.3).
    pub recv_seq: u64,

    /// Session lifecycle state per the §2.2.3.5.2 state machine.
    pub session_state: SecureSessionState,

    /// Deadline for the current `session_timer`. 10 s while in
    /// `Unauthenticated` (§2.2.3.5.2.1 timeoutAuthentication), 60 s
    /// while in `Authenticated` (timeoutSession).
    pub session_timer_deadline: Option<Instant>,

    /// User ID that authenticated this session. `1` is the management
    /// user (full access); `2..=127` are device-specific roles
    /// (gated by `PID_TUNNELLING_USERS`). `None` while unauthenticated.
    pub authenticated_user_id: Option<u8>,

    /// Index of the TCP stream this session was opened on. Used for
    /// O(N) cleanup when the TCP connection closes (§2.4.2).
    pub tcp_stream_index: u8,

    /// ECDH ephemeral keypair state. Only valid during the
    /// SESSION_REQUEST → SESSION_RESPONSE → SESSION_AUTHENTICATE
    /// handshake; zeroed once `session_state` reaches `Authenticated`.
    pub ecdh_ephemeral: EcdhState,
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
/// Real implementation will hold the 32-byte private value and the
/// peer's 32-byte public value during the handshake window. Stub for
/// now; `_phantom` keeps the struct shape stable.
#[derive(Default)]
pub struct EcdhState {
    _phantom: PhantomData<[u8; 64]>,
}

// ============================================================================
// Service type identifiers (§2.6.1)
// ============================================================================

/// Service type identifiers for the KNX IP Secure family (`09xxh`).
///
/// Spelled out as constants here — the proto-level `KNXnetIPServiceType`
/// enum will gain matching variants when the dispatch path is wired up.
pub mod secure_service_types {
    pub const SECURE_WRAPPER: u16 = 0x0950;
    pub const SESSION_REQUEST: u16 = 0x0951;
    pub const SESSION_RESPONSE: u16 = 0x0952;
    pub const SESSION_AUTHENTICATE: u16 = 0x0953;
    pub const SESSION_STATUS: u16 = 0x0954;
    pub const TIMER_NOTIFY: u16 = 0x0955;
}

/// SESSION_STATUS status codes (§2.2.3.9).
pub mod session_status {
    pub const AUTHENTICATION_SUCCESS: u8 = 0x00;
    pub const AUTHENTICATION_FAILED: u8 = 0x01;
    pub const UNAUTHENTICATED: u8 = 0x02;
    pub const TIMEOUT: u8 = 0x03;
    pub const KEEPALIVE: u8 = 0x04;
    pub const CLOSE: u8 = 0x05;
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
