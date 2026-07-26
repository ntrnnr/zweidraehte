//! Runtime selection of the local interface a KNX/IP device binds to.
//!
//! A KNX/IP device has to commit to exactly one interface: its IPv4 address
//! pins outgoing multicast (`IP_MULTICAST_IF`), selects the group membership
//! (`IP_ADD_MEMBERSHIP`), and is advertised as the control endpoint HPAI in
//! search/description responses. Hard-coding that interface makes a binary
//! non-portable across hosts, so this module resolves it at startup instead —
//! from an explicit request when the operator has one, otherwise by asking the
//! host what it has.
//!
//! Everything here is plain POSIX (`getifaddrs` plus one throwaway UDP socket)
//! and works the same on Linux and macOS. Only the *flags* interpretation is
//! host policy; there is deliberately no Linux-only routing code.

use core::fmt;
use core::net::{Ipv4Addr, SocketAddrV4};

use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;

// ============================================================================
// Interface enumeration
// ============================================================================

/// A local interface that carries an IPv4 address.
///
/// Only the flags that matter for the selection policy are kept; everything
/// else `getifaddrs` reports is irrelevant to a KNX/IP device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterface {
    /// Kernel interface name, e.g. `eth0` or `en0`.
    pub name: String,
    /// The interface's IPv4 address (the first one, if it has several).
    pub address: Ipv4Addr,
    /// Administratively up *and* carrying a link (`IFF_UP | IFF_RUNNING`).
    pub up: bool,
    /// Supports multicast (`IFF_MULTICAST`) — mandatory for KNX/IP routing.
    pub multicast: bool,
    /// Loopback interface (`IFF_LOOPBACK`).
    pub loopback: bool,
    /// Point-to-point link (`IFF_POINTOPOINT`) — VPN/tunnel interfaces.
    pub point_to_point: bool,
}

impl NetworkInterface {
    /// Whether this interface may be picked *without* an explicit request.
    ///
    /// The filter is deliberately strict, because everything it lets through
    /// competes for the automatic choice: a KNX/IP device needs a live,
    /// multicast-capable, non-loopback link. Point-to-point interfaces (VPN
    /// tunnels, `utun*` on macOS) are excluded because they have no L2
    /// broadcast domain to carry a KNX installation, even when they claim
    /// `IFF_MULTICAST`. An explicit request bypasses this filter entirely —
    /// the operator knows their setup better than we do.
    pub fn is_auto_candidate(&self) -> bool {
        self.disqualification().is_none()
    }

    /// Why this interface is not an automatic candidate, if it is not.
    ///
    /// Split out from [`is_auto_candidate`](Self::is_auto_candidate) so that
    /// overriding the filter can say *what* was overridden — "loopback" and
    /// "no carrier" call for very different second thoughts.
    fn disqualification(&self) -> Option<&'static str> {
        if self.loopback {
            Some("loopback interface")
        } else if self.point_to_point {
            Some("point-to-point link")
        } else if !self.up {
            Some("down or without carrier")
        } else if !self.multicast {
            Some("no multicast support")
        } else if self.address.is_unspecified() {
            Some("no address")
        } else {
            None
        }
    }

    /// Whether the address is IPv4 link-local (169.254.0.0/16, "AutoIP").
    ///
    /// A legitimate KNX/IP address, but usually a sign of a link with no DHCP
    /// server, so these sort last in listings.
    fn is_link_local(&self) -> bool {
        self.address.is_link_local()
    }
}

impl fmt::Display for NetworkInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.address)
    }
}

/// Every local interface that has an IPv4 address.
///
/// Interfaces without one are omitted — an interface a KNX/IP device cannot
/// bind to is not interesting to a caller. Use [`InterfaceSelector`] rather
/// than filtering this list by hand.
pub fn ipv4_interfaces() -> nix::Result<Vec<NetworkInterface>> {
    enumerate().map(|(interfaces, _)| interfaces)
}

/// Enumerate interfaces, returning the IPv4-capable ones plus the names of
/// *all* interfaces the kernel reported.
///
/// The second list exists purely for error messages: it is what lets us tell
/// "no such interface" apart from "that interface exists but has no IPv4
/// address yet" — two problems with very different fixes.
fn enumerate() -> nix::Result<(Vec<NetworkInterface>, Vec<String>)> {
    let mut interfaces = Vec::new();
    let mut names: Vec<String> = Vec::new();

    for ifaddr in getifaddrs()? {
        if !names.iter().any(|seen| seen == &ifaddr.interface_name) {
            names.push(ifaddr.interface_name.clone());
        }

        // getifaddrs reports one entry per (interface, address family), so an
        // interface shows up several times; we want the AF_INET rows only.
        let Some(address) = ifaddr.address.as_ref().and_then(|a| a.as_sockaddr_in()).map(|a| a.ip()) else {
            continue;
        };

        // Keep the first IPv4 address of an interface with several: the
        // primary address is the one the kernel puts first, and a KNX/IP
        // device can only advertise one HPAI anyway.
        if interfaces.iter().any(|i: &NetworkInterface| i.name == ifaddr.interface_name) {
            continue;
        }

        let flags = ifaddr.flags;
        interfaces.push(NetworkInterface {
            name: ifaddr.interface_name,
            address,
            // IFF_UP alone only means "configured"; IFF_RUNNING is the one
            // that reflects an actual carrier, so an unplugged NIC does not
            // become a candidate.
            up: flags.contains(InterfaceFlags::IFF_UP) && flags.contains(InterfaceFlags::IFF_RUNNING),
            multicast: flags.contains(InterfaceFlags::IFF_MULTICAST),
            loopback: flags.contains(InterfaceFlags::IFF_LOOPBACK),
            point_to_point: flags.contains(InterfaceFlags::IFF_POINTOPOINT),
        });
    }

    // Deterministic order, so "the candidates" listed in an error message and
    // the tie-break behaviour do not depend on kernel enumeration order.
    // Link-local addresses sort last: they are valid but usually a fallback.
    interfaces.sort_by(|a, b| a.is_link_local().cmp(&b.is_link_local()).then_with(|| a.name.cmp(&b.name)));

    Ok((interfaces, names))
}

// ============================================================================
// Routing-table probe
// ============================================================================

/// The local address the kernel would use to reach `destination`.
///
/// `connect()` on a UDP socket performs a full routing-table lookup and binds
/// the socket to the source address the kernel picked — **without sending a
/// single packet**. That makes it the portable way to ask "which interface
/// serves this destination" on Linux and macOS alike, with no netlink dump,
/// no `route(4)` sysctl and no `/proc/net/route` parsing.
///
/// Caveat, and the reason callers must announce the result loudly: for a
/// multicast destination this usually resolves to the *primary* interface.
/// Linux normally has no `224.0.0.0/4` route and falls back to the default
/// route; macOS' `224.0.0/4` entry points at the primary interface. That is
/// the right answer on a host whose KNX network is also its default route
/// (and a good way to ignore `docker0`/`vmnet*`/`bridge100` clutter), and the
/// wrong one on a host whose KNX network is an isolated bridge — there the
/// interface has to be named explicitly.
///
/// Returns `None` when the destination is unroutable (no default route,
/// `ENETUNREACH`) or the kernel reports an unspecified source address.
pub fn route_source_address(destination: SocketAddrV4) -> Option<Ipv4Addr> {
    use std::net::{SocketAddr, UdpSocket};

    let probe = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    probe.connect(SocketAddr::V4(destination)).ok()?;
    match probe.local_addr().ok()? {
        SocketAddr::V4(local) if !local.ip().is_unspecified() => Some(*local.ip()),
        _ => None,
    }
}

// ============================================================================
// Selection
// ============================================================================

/// Why [`InterfaceSelector::select`] settled on a given interface.
///
/// Callers are expected to report this on startup: the automatic choices are
/// heuristics, and a KNX/IP device bound to the wrong interface fails in a way
/// that looks like "ETS does not find the device" rather than like an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionReason {
    /// The caller named this interface explicitly.
    Requested,
    /// It was the only interface qualifying for automatic selection.
    OnlyCandidate,
    /// Several interfaces qualified; the kernel's route to `destination`
    /// broke the tie. See [`route_source_address`] for what that implies.
    KernelRoute { destination: Ipv4Addr, candidates: usize },
}

impl fmt::Display for SelectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested => write!(f, "explicitly requested"),
            Self::OnlyCandidate => write!(f, "the only interface that qualifies"),
            Self::KernelRoute { destination, candidates } => {
                write!(f, "picked out of {candidates} candidates by the kernel's route to {destination}")
            }
        }
    }
}

/// Why no interface could be selected.
///
/// The `Display` impl states the problem and lists what was available; adding
/// a host-specific hint on how to name an interface (a CLI flag, an
/// environment variable) is the caller's job — this crate does not know the
/// application's conventions.
#[derive(Debug)]
pub enum SelectInterfaceError {
    /// `getifaddrs` failed outright.
    Enumeration(nix::Error),
    /// The requested name/address matches no interface at all.
    NotFound { requested: String, available: Vec<NetworkInterface> },
    /// The requested interface exists but has no IPv4 address (yet).
    NoIpv4 { requested: String },
    /// No interface qualifies for automatic selection.
    NoCandidates { available: Vec<NetworkInterface> },
    /// Several interfaces qualify and the routing probe did not resolve the
    /// tie — the operator has to name one.
    Ambiguous { candidates: Vec<NetworkInterface> },
}

impl fmt::Display for SelectInterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enumeration(e) => write!(f, "could not enumerate network interfaces: {e}"),
            Self::NotFound { requested, available } => {
                write!(f, "no interface matches {requested:?}")?;
                write_list(f, "interfaces with an IPv4 address", available)
            }
            Self::NoIpv4 { requested } => {
                write!(f, "interface {requested:?} exists but has no IPv4 address")
            }
            Self::NoCandidates { available } => {
                write!(f, "no interface is usable for KNX/IP (needs a live, multicast-capable, non-loopback link)")?;
                write_list(f, "interfaces with an IPv4 address", available)
            }
            Self::Ambiguous { candidates } => {
                write!(f, "several interfaces could carry KNX/IP and the host's routing table did not resolve which")?;
                write_list(f, "candidates", candidates)
            }
        }
    }
}

impl core::error::Error for SelectInterfaceError {}

/// Append `label: ` and one indented line per interface, or nothing when the
/// list is empty (a "candidates: (none)" line helps nobody).
fn write_list(f: &mut fmt::Formatter<'_>, label: &str, interfaces: &[NetworkInterface]) -> fmt::Result {
    if interfaces.is_empty() {
        return Ok(());
    }
    write!(f, "\n{label}:")?;
    for interface in interfaces {
        write!(f, "\n  {interface}")?;
    }
    Ok(())
}

/// Resolves which interface a KNX/IP device should bind to.
///
/// ```no_run
/// use core::net::{Ipv4Addr, SocketAddrV4};
/// use zweidraehte_platform::InterfaceSelector;
///
/// let requested = std::env::var("KNX_INTERFACE").ok();
/// let (interface, reason) = InterfaceSelector::new()
///     .requested(requested.as_deref())
///     .route_probe(SocketAddrV4::new(Ipv4Addr::new(224, 0, 23, 12), 3671))
///     .select()?;
/// println!("KNX/IP interface: {interface} — {reason}");
/// # Ok::<(), zweidraehte_platform::SelectInterfaceError>(())
/// ```
#[derive(Debug, Default, Clone)]
pub struct InterfaceSelector<'a> {
    requested: Option<&'a str>,
    route_probe: Option<SocketAddrV4>,
}

impl<'a> InterfaceSelector<'a> {
    /// A selector that picks automatically and never probes the routing table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Name the interface explicitly, as an interface name (`"eth0"`) or an
    /// IPv4 literal (`"192.168.1.42"`).
    ///
    /// Takes `Option` so callers can pass a missing flag/environment variable
    /// straight through. An explicit request wins over everything else and
    /// bypasses the [candidate filter](NetworkInterface::is_auto_candidate) —
    /// selecting an interface that looks unusable only warns.
    pub fn requested(mut self, requested: Option<&'a str>) -> Self {
        self.requested = requested;
        self
    }

    /// Break a tie between several candidates by asking the kernel which
    /// interface serves `destination` (the KNX routing multicast group).
    ///
    /// Without this, several candidates are always an error.
    pub fn route_probe(mut self, destination: SocketAddrV4) -> Self {
        self.route_probe = Some(destination);
        self
    }

    /// Resolve the interface, or explain why it could not be resolved.
    pub fn select(&self) -> Result<(NetworkInterface, SelectionReason), SelectInterfaceError> {
        let (interfaces, names) = enumerate().map_err(SelectInterfaceError::Enumeration)?;
        choose(&interfaces, &names, self.requested, self.route_probe, route_source_address)
    }
}

/// The selection policy, free of I/O so it can be tested against synthetic
/// interface lists.
///
/// `resolve_route` is invoked at most once, and only when several candidates
/// remain — the probe costs a socket syscall, and most hosts never get here.
/// It yields the local address the kernel would send to `route_probe` from
/// (see [`route_source_address`]).
fn choose(
    interfaces: &[NetworkInterface],
    names: &[String],
    requested: Option<&str>,
    route_probe: Option<SocketAddrV4>,
    resolve_route: impl FnOnce(SocketAddrV4) -> Option<Ipv4Addr>,
) -> Result<(NetworkInterface, SelectionReason), SelectInterfaceError> {
    // --- 1. An explicit request wins, whatever the flags say. ---------------
    if let Some(requested) = requested {
        // An IPv4 literal is matched against addresses, anything else against
        // interface names — the operator may know either.
        let found = match requested.parse::<Ipv4Addr>() {
            Ok(address) => interfaces.iter().find(|i| i.address == address),
            Err(_) => interfaces.iter().find(|i| i.name == requested),
        };

        return match found {
            Some(interface) => {
                if let Some(why) = interface.disqualification() {
                    log::warn!("requested interface {interface} would not be picked automatically ({why})");
                }
                Ok((interface.clone(), SelectionReason::Requested))
            }
            None if names.iter().any(|name| name == requested) => {
                Err(SelectInterfaceError::NoIpv4 { requested: requested.to_owned() })
            }
            None => {
                Err(SelectInterfaceError::NotFound { requested: requested.to_owned(), available: interfaces.to_vec() })
            }
        };
    }

    // --- 2. Otherwise pick among the interfaces that could plausibly work. --
    let candidates: Vec<&NetworkInterface> = interfaces.iter().filter(|i| i.is_auto_candidate()).collect();
    match candidates.as_slice() {
        [] => Err(SelectInterfaceError::NoCandidates { available: interfaces.to_vec() }),
        [only] => Ok(((*only).clone(), SelectionReason::OnlyCandidate)),
        several => {
            // --- 3. Let the host's own routing table break the tie. ---------
            // A probe result pointing at something that is *not* a candidate
            // (a loopback or tunnel route) is no answer, so it stays an error
            // rather than being forced onto the nearest interface.
            let routed = route_probe.and_then(|destination| {
                let source = resolve_route(destination)?;
                let interface = several.iter().find(|i| i.address == source)?;
                Some((interface, *destination.ip()))
            });

            match routed {
                Some((interface, destination)) => {
                    let reason = SelectionReason::KernelRoute { destination, candidates: several.len() };
                    Ok(((*interface).clone(), reason))
                }
                None => {
                    let candidates = several.iter().map(|i| (*i).clone()).collect();
                    Err(SelectInterfaceError::Ambiguous { candidates })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An interface that passes the candidate filter.
    fn candidate(name: &str, address: [u8; 4]) -> NetworkInterface {
        NetworkInterface {
            name: name.to_owned(),
            address: Ipv4Addr::from(address),
            up: true,
            multicast: true,
            loopback: false,
            point_to_point: false,
        }
    }

    fn names(interfaces: &[NetworkInterface]) -> Vec<String> {
        interfaces.iter().map(|i| i.name.clone()).collect()
    }

    /// The KNX routing group, as the mains pass it.
    const PROBE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(224, 0, 23, 12), 3671);

    /// A probe that must never run — asserts the syscall is skipped.
    fn unreachable_probe(_: SocketAddrV4) -> Option<Ipv4Addr> {
        panic!("the routing probe must not run here")
    }

    /// A probe that finds no route.
    fn no_route(_: SocketAddrV4) -> Option<Ipv4Addr> {
        None
    }

    #[test]
    fn requested_by_name_wins() {
        let interfaces = vec![candidate("en0", [192, 168, 1, 42]), candidate("knxbr0", [10, 0, 42, 1])];
        let (chosen, reason) =
            choose(&interfaces, &names(&interfaces), Some("knxbr0"), Some(PROBE), unreachable_probe).unwrap();
        assert_eq!(chosen.name, "knxbr0");
        assert_eq!(reason, SelectionReason::Requested);
    }

    #[test]
    fn requested_by_ipv4_literal_wins() {
        let interfaces = vec![candidate("en0", [192, 168, 1, 42]), candidate("knxbr0", [10, 0, 42, 1])];
        let (chosen, _) =
            choose(&interfaces, &names(&interfaces), Some("10.0.42.1"), Some(PROBE), unreachable_probe).unwrap();
        assert_eq!(chosen.name, "knxbr0");
    }

    /// A requested interface is honoured even when it fails the candidate
    /// filter — the operator overrules the heuristic.
    #[test]
    fn requested_overrules_the_candidate_filter() {
        let mut down = candidate("knxbr0", [10, 0, 42, 1]);
        down.up = false;
        let interfaces = vec![candidate("en0", [192, 168, 1, 42]), down];
        let (chosen, _) =
            choose(&interfaces, &names(&interfaces), Some("knxbr0"), Some(PROBE), unreachable_probe).unwrap();
        assert_eq!(chosen.name, "knxbr0");
    }

    #[test]
    fn requested_interface_without_ipv4_is_distinguished_from_a_typo() {
        let interfaces = vec![candidate("en0", [192, 168, 1, 42])];
        let names = vec!["en0".to_owned(), "en5".to_owned()];

        let no_ipv4 = choose(&interfaces, &names, Some("en5"), Some(PROBE), unreachable_probe).unwrap_err();
        assert!(matches!(no_ipv4, SelectInterfaceError::NoIpv4 { .. }), "{no_ipv4}");

        let typo = choose(&interfaces, &names, Some("en9"), Some(PROBE), unreachable_probe).unwrap_err();
        assert!(matches!(typo, SelectInterfaceError::NotFound { .. }), "{typo}");
    }

    #[test]
    fn a_single_candidate_is_selected_without_probing() {
        let mut loopback = candidate("lo0", [127, 0, 0, 1]);
        loopback.loopback = true;
        let mut tunnel = candidate("utun3", [10, 8, 0, 2]);
        tunnel.point_to_point = true;
        let interfaces = vec![candidate("en0", [192, 168, 1, 42]), loopback, tunnel];

        let (chosen, reason) = choose(&interfaces, &names(&interfaces), None, Some(PROBE), unreachable_probe).unwrap();
        assert_eq!(chosen.name, "en0");
        assert_eq!(reason, SelectionReason::OnlyCandidate);
    }

    #[test]
    fn several_candidates_are_resolved_by_the_routing_probe() {
        let interfaces = vec![
            candidate("bridge100", [192, 168, 64, 1]),
            candidate("en0", [192, 168, 1, 42]),
            candidate("knxbr0", [10, 0, 42, 1]),
        ];
        let (chosen, reason) =
            choose(&interfaces, &names(&interfaces), None, Some(PROBE), |_| Some(Ipv4Addr::new(192, 168, 1, 42)))
                .unwrap();
        assert_eq!(chosen.name, "en0");
        assert_eq!(reason, SelectionReason::KernelRoute { destination: *PROBE.ip(), candidates: 3 });
    }

    /// The probe answering with an address that is not among the candidates
    /// (a loopback or point-to-point route) must not be forced into a choice.
    #[test]
    fn a_probe_result_outside_the_candidates_stays_ambiguous() {
        let interfaces = vec![candidate("en0", [192, 168, 1, 42]), candidate("knxbr0", [10, 0, 42, 1])];
        let error =
            choose(&interfaces, &names(&interfaces), None, Some(PROBE), |_| Some(Ipv4Addr::LOCALHOST)).unwrap_err();
        assert!(matches!(error, SelectInterfaceError::Ambiguous { ref candidates } if candidates.len() == 2));
    }

    #[test]
    fn several_candidates_without_a_probe_result_are_ambiguous() {
        let interfaces = vec![candidate("en0", [192, 168, 1, 42]), candidate("knxbr0", [10, 0, 42, 1])];
        let error = choose(&interfaces, &names(&interfaces), None, Some(PROBE), no_route).unwrap_err();
        assert!(matches!(error, SelectInterfaceError::Ambiguous { .. }), "{error}");
    }

    /// Without a configured probe destination, ambiguity is simply an error —
    /// no routing lookup happens at all.
    #[test]
    fn several_candidates_without_a_probe_are_ambiguous() {
        let interfaces = vec![candidate("en0", [192, 168, 1, 42]), candidate("knxbr0", [10, 0, 42, 1])];
        let error = choose(&interfaces, &names(&interfaces), None, None, unreachable_probe).unwrap_err();
        assert!(matches!(error, SelectInterfaceError::Ambiguous { .. }), "{error}");
    }

    #[test]
    fn no_candidate_reports_what_the_host_does_have() {
        let mut loopback = candidate("lo0", [127, 0, 0, 1]);
        loopback.loopback = true;
        let interfaces = vec![loopback];
        let error = choose(&interfaces, &names(&interfaces), None, Some(PROBE), no_route).unwrap_err();
        assert!(matches!(error, SelectInterfaceError::NoCandidates { ref available } if available.len() == 1));
    }

    /// Enumeration must not invent interfaces; on any host the loopback exists
    /// and never qualifies for automatic selection.
    #[test]
    fn enumeration_reports_the_hosts_interfaces() {
        let (interfaces, names) = enumerate().expect("getifaddrs works on any supported host");
        assert!(!names.is_empty(), "a host always has at least a loopback interface");
        assert!(interfaces.iter().filter(|i| i.loopback).all(|i| !i.is_auto_candidate()));
    }
}
