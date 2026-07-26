//! Startup resolution of the KNX/IP interface for host-target device shells.
//!
//! The policy itself lives in [`zweidraehte_platform::InterfaceSelector`];
//! this is the process-level glue around it — command line, environment,
//! console output, exit code — which the platform crate has no business
//! knowing about.

use core::net::{Ipv4Addr, SocketAddrV4};

use zweidraehte_device::{DEFAULT_MULTICAST_ADDR, KNX_PORT};
use zweidraehte_platform::{InterfaceSelector, SelectionReason};

/// Environment variable naming the KNX/IP interface.
pub const INTERFACE_ENV_VAR: &str = "KNX_INTERFACE";

/// Resolve the interface the KNX/IP stack binds to, or exit with a readable
/// message.
///
/// Accepts an interface name or an IPv4 literal from `--interface <x>`,
/// `--interface=<x>`, `-i <x>` or `$KNX_INTERFACE` (the flag wins); with
/// neither, the host is inspected and the interface picked automatically —
/// see [`InterfaceSelector`] for the exact policy. Both forms survive the
/// `exec()`-based restart, which re-runs the binary with its original
/// arguments and environment.
///
/// Returns the interface name and its IPv4 address: the stack needs both, the
/// name for `SO_BINDTODEVICE` and the TCP listener, the address for
/// `IP_MULTICAST_IF`, the multicast group membership and the control endpoint
/// HPAI.
///
/// # Panics / exit
///
/// Terminates the process with status 1 when no interface can be resolved.
/// This runs before any stack exists, so there is nothing to unwind or
/// persist, and a panic backtrace would only bury the explanation.
pub fn resolve_knx_interface() -> (&'static str, Ipv4Addr) {
    let requested = interface_from_args().or_else(|| std::env::var(INTERFACE_ENV_VAR).ok());

    // The routing multicast group is the destination that matters: asking the
    // kernel which interface it would send *there* from is what breaks a tie
    // between several usable interfaces.
    let probe = SocketAddrV4::new(DEFAULT_MULTICAST_ADDR, KNX_PORT);

    let (interface, reason) = match InterfaceSelector::new().requested(requested.as_deref()).route_probe(probe).select()
    {
        Ok(selected) => selected,
        Err(e) => {
            eprintln!("Cannot determine the KNX/IP interface: {e}");
            eprintln!("\nName one explicitly:\n  --interface <name|ip>\n  {INTERFACE_ENV_VAR}=<name|ip>");
            std::process::exit(1);
        }
    };

    // Announce the choice unconditionally. The automatic paths are heuristics,
    // and a device bound to the wrong interface does not fail loudly — it just
    // never shows up in ETS — so the operator has to be able to spot a wrong
    // guess in the startup output.
    println!("KNX/IP interface: {interface}");
    println!("  {reason}");
    if reason != SelectionReason::Requested {
        println!("  override with --interface <name|ip> or {INTERFACE_ENV_VAR}=<name|ip>");
    }

    let address = interface.address;
    // `KnxNetIpBuilder::new`, `UdpSocketOptions::interface` and
    // `TcpListenerOptions::interface` all take `&'static str`, since on a
    // device the interface is fixed for the process' lifetime. Leaking the one
    // name we resolved keeps that contract: it is a single allocation that
    // lives until exit anyway, and the alternative — threading a lifetime
    // parameter through the whole link-layer builder — buys nothing.
    (interface.name.leak(), address)
}

/// Scan `--interface <x>`, `--interface=<x>` and `-i <x>` out of the command
/// line.
///
/// Hand-rolled rather than pulled from a CLI crate: these binaries take
/// exactly one option, and a dependency on `clap` would outweigh the parsing
/// it saves. Unknown arguments are ignored, so the device shells stay
/// compatible with whatever else a caller passes.
fn interface_from_args() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--interface=") {
            return Some(value.to_owned());
        }
        if arg == "--interface" || arg == "-i" {
            let Some(value) = args.next() else {
                eprintln!("{arg} needs an interface name or IPv4 address");
                std::process::exit(1);
            };
            return Some(value);
        }
    }
    None
}
