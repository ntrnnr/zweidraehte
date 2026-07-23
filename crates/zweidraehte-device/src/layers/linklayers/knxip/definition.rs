//! Compile-time bill-of-materials for the KNX/IP link layer.
//!
//! Mirrors [`StackDefinition`](crate::definition::StackDefinition) at the
//! link-layer level: a single `Copy + 'static` ZST trait that pins the
//! transport, the feature set, and every numeric sizing knob the link
//! layer needs. The downstream user implements it once per binary and
//! every const-generic sizing follows from that single impl.
//!
//! ## Why a separate trait, not just associated types on `StackDefinition`
//!
//! [`StackDefinition`](crate::definition::StackDefinition) is medium-
//! agnostic. A TP1-only device or a USB interface device must not be
//! forced to spell out IP-specific sizing knobs. The IP-specific
//! definition lives in this trait and only matters once `StackDefinition::LLB`
//! is `KnxNetIpBuilder<D>`.
//!
//! ## Sizing defaults — single source of truth
//!
//! Almost every numeric is defaulted off the tunneling capacity (which
//! the user already had to spell out via the chosen `Features` alias),
//! so the typical impl looks like:
//!
//! ```ignore
//! impl KnxNetIpDefinition for MyIpInterface {
//!     type Transport = EmbassyIpTransportTcp<2, 4>;
//!     type Features  = KnxIpInterfaceTcp<4>;
//!     // MAX_TCP_STREAMS, MAX_TCP_CHANNELS, MAX_SECURE_SESSIONS
//!     // all default to 4 (TUNNEL_CAPACITY); MAX_UDP_SOCKETS to 2.
//! }
//! ```
//!
//! Override a const only when the default is wrong for your build —
//! e.g. when accepting more TCP clients than you have tunnel slots, or
//! when an exotic port layout demands a deeper UDP socket pool.

use zweidraehte_platform::IpTransport;

use super::features::{FeatureSet, TcpFeature};
use super::secure::IpSecureFeature;

/// Compile-time configuration for the KNX/IP link layer.
///
/// Implemented as a `Copy + 'static` ZST per the
/// [`StackDefinition`](crate::definition::StackDefinition) pattern —
/// the trait is never instantiated, only used as a type-level handle.
pub trait KnxNetIpDefinition: Copy + 'static {
    /// Platform IP transport (e.g. `EmbassyIpTransport`,
    /// `EmbassyIpTransportTcp`, `LinuxIpTransport`).
    type Transport: IpTransport;

    /// Compile-time feature set: routing / remote-config / tunneling /
    /// TCP / IP-Secure. Pick one of the aliases in
    /// [`super::features`] or roll your own
    /// [`Features<...>`](super::features::Features).
    type Features: FeatureSet;

    /// Random source for IP Secure ephemeral session keys.
    ///
    /// Defaults to [`NoRng`](crate::rng::NoRng), which panics if ever
    /// invoked — IP Secure builds must set a real
    /// [`Rng`](crate::rng::Rng) here (typically the same type as
    /// `StackDefinition::Rng`). Non-secure builds never call it.
    type Rng: crate::rng::Rng = crate::rng::NoRng;

    // ------------------------------------------------------------------
    // Derived sizing constants
    // ------------------------------------------------------------------

    /// Maximum concurrent tunneling slots.
    ///
    /// Mirrored from `<Self::Features::Tunneling as TunnelingFeature>::CAPACITY`
    /// for ergonomic access — write `D::TUNNEL_CAPACITY` instead of
    /// the long projection.
    const TUNNEL_CAPACITY: usize =
        <<Self::Features as FeatureSet>::Tunneling as super::features::TunnelingFeature>::CAPACITY;

    /// Maximum concurrent TCP connections accepted by the listener.
    ///
    /// Default when TCP is enabled: [`TUNNEL_CAPACITY`](Self::TUNNEL_CAPACITY),
    /// but never below `1` — 03/08/02 Core §6.5 requires a TCP-capable
    /// server to "support at least one single TCP connection at a time".
    /// A tunnelling device already has `TUNNEL_CAPACITY ≥ 1` (worst case
    /// every tunnel over its own TCP connection); a routing device has
    /// `TUNNEL_CAPACITY = 0` and would otherwise advertise TCP yet accept
    /// nothing, so it gets the one mandated slot for the Device Management
    /// connection ETS opens over TCP. When TCP is disabled the count is
    /// `0`, collapsing the `TcpManager` storage to zero bytes. Override
    /// when you accept more management/discovery TCP clients than you have
    /// tunnel slots.
    const MAX_TCP_STREAMS: usize = if <<Self::Features as FeatureSet>::Tcp as TcpFeature>::ENABLED {
        if Self::TUNNEL_CAPACITY > 0 { Self::TUNNEL_CAPACITY } else { 1 }
    } else {
        0
    };

    /// Maximum KNX/IP channel IDs tracked per TCP stream.
    ///
    /// Default when TCP is enabled: [`TUNNEL_CAPACITY`](Self::TUNNEL_CAPACITY),
    /// but never below `1` — a single TCP connection carries at least the
    /// one plain KNXnet/IP (Device Management) channel it multiplexes
    /// (03/08/02 Core §6.5). A routing device with no tunnels still needs
    /// that one channel slot, so a `0` here would silently drop the
    /// management channel from the stream's tracking. `0` when TCP is
    /// disabled. Override (downward) to save per-stream RAM if your
    /// deployment caps multiplexing per client.
    const MAX_TCP_CHANNELS: usize = if <<Self::Features as FeatureSet>::Tcp as TcpFeature>::ENABLED {
        if Self::TUNNEL_CAPACITY > 0 { Self::TUNNEL_CAPACITY } else { 1 }
    } else {
        0
    };

    /// Maximum concurrent KNX/IP connections managed by the connection
    /// manager (Device Management + tunneling slots combined).
    ///
    /// Default: `TUNNEL_CAPACITY + 1` — one slot for the Device
    /// Management connection ETS uses for programming, plus one slot
    /// per tunneling client. A UDP-only routing device with no
    /// tunneling (e.g. `KnxIpDeviceUdp`) still needs the `+ 1` so ETS
    /// can open a management connection to upload the device's
    /// configuration; without it every `CONNECT_REQUEST` would get
    /// `E_NO_MORE_CONNECTIONS`.
    ///
    /// This is independent of [`MAX_TCP_CHANNELS`](Self::MAX_TCP_CHANNELS):
    /// `MAX_TCP_CHANNELS` is the per-TCP-stream channel multiplexing
    /// bound (relevant only when a single TCP client opens multiple
    /// inner KNX/IP channels); `MAX_CONNECTIONS` is the link-layer-wide
    /// connection lifecycle slot count.
    const MAX_CONNECTIONS: usize = Self::TUNNEL_CAPACITY + 1;

    /// Deduped UDP socket pool size.
    ///
    /// The builder collects every UDP endpoint each enabled feature
    /// needs (discovery on KNX_PORT × {multicast, any}, routing
    /// multicast, remote-config multicast …) and collapses them by
    /// port. Default `2` covers a typical configuration: one socket on
    /// the System Setup multicast / KNX port for discovery + routing
    /// joined as a multicast group; one wildcard socket on KNX_PORT
    /// for unicast control. Override only when you mix in non-standard
    /// ports.
    const MAX_UDP_SOCKETS: usize = 2;

    /// Per-TCP-connection read/frame scratch buffer size in bytes.
    ///
    /// Default `512` fits the largest plain KNX/IP frame on TCP. IP-Secure
    /// builds need `512 + `[`SECURE_WRAPPER_OVERHEAD`](super::secure::SECURE_WRAPPER_OVERHEAD)
    /// (= 560) so a SECURE_WRAPPER around a 512-byte inner frame still fits.
    const TCP_SCRATCH_BUF_SIZE: usize = 512;

    /// Maximum concurrent IP Secure sessions.
    ///
    /// Default: [`MAX_TCP_STREAMS`](Self::MAX_TCP_STREAMS) — secure
    /// sessions are TCP-only per spec §2.2.3.3, so each session pins a
    /// TCP stream. Effective storage is zero when
    /// `Features::IpSecure = NoIpSecure` because the slot type is `()`.
    const MAX_SECURE_SESSIONS: usize = Self::MAX_TCP_STREAMS;

    // ------------------------------------------------------------------
    // Derived helpers
    // ------------------------------------------------------------------

    /// Total embassy-net socket count for this definition.
    ///
    /// The embassy-net stack needs one socket per UDP socket plus one
    /// per concurrent TCP connection plus one for DHCP. Use as
    /// `NetStackResources::<{ MyDef::EMBASSY_NET_SOCKETS }>::new()`.
    const EMBASSY_NET_SOCKETS: usize = 1 + Self::MAX_UDP_SOCKETS + Self::MAX_TCP_STREAMS;

    /// Convenience marker: does the chosen feature set imply IP Secure
    /// support? Used by downstream sanity-checks that want to refuse
    /// running secure traffic on a non-secure build.
    const IP_SECURE_ENABLED: bool = <<Self::Features as FeatureSet>::IpSecure as IpSecureFeature>::ENABLED;
}
