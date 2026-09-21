//! Live tunnel-slot occupancy counter.
//!
//! Published by [`TunnelConnectionHandler`](super::tunnel::TunnelConnectionHandler)
//! on every connect/disconnect; read by the composite IP-Interface
//! address checker to decide whether to over-ACK group frames.

use portable_atomic::{AtomicU8, Ordering::Relaxed};

/// Counts how many tunnel connections are currently open.
///
/// Storage lives in [`KnxNetIpResources`](super::super::KnxNetIpResources)
/// so it outlives both the tunnel handler (which mutates it) and the
/// address checker (which reads it).
///
/// `Relaxed` ordering is sufficient. The only consumer reads
/// [`any_open`](Self::any_open) on the TPUART hot path; a race that
/// straddles a connect/disconnect transition costs at most one
/// spurious or missed bus ACK, which TP1 tolerates.
pub struct TunnelOccupancy {
    count: AtomicU8,
}

impl TunnelOccupancy {
    pub const fn new() -> Self {
        Self { count: AtomicU8::new(0) }
    }

    /// `true` if at least one tunnel connection is currently open.
    pub fn any_open(&self) -> bool {
        self.count.load(Relaxed) > 0
    }

    pub(super) fn on_connect(&self) {
        self.count.fetch_add(1, Relaxed);
    }

    /// Saturating decrement — guards against double-close races where
    /// a slot is freed via two different teardown paths (e.g.
    /// DISCONNECT_REQUEST racing with TCP close).
    pub(super) fn on_disconnect(&self) {
        let _ = self.count.fetch_update(Relaxed, Relaxed, |v| (v > 0).then_some(v - 1));
    }
}

impl Default for TunnelOccupancy {
    fn default() -> Self {
        Self::new()
    }
}

// Exercise the live ACK consumer here, where connection lifecycle hooks are
// accessible without exposing counter mutation outside the connection manager.
#[cfg(all(test, feature = "ip-interface"))]
mod tests {
    use super::TunnelOccupancy;
    use crate::layers::linklayers::address_check::{
        AddressChecker,
        tests::{TestAddressContext, headers},
    };
    use crate::layers::linklayers::ip_interface::IpInterfaceAddressChecker;
    use zweidraehte_proto::address::IndividualAddress;

    #[test]
    fn interface_checker_observes_primary_and_additional_address_changes() {
        let primary = IndividualAddress::new(1, 2, 3);
        let first_slot = IndividualAddress::new(1, 2, 4);
        let second_slot = IndividualAddress::new(1, 2, 5);
        let reassigned = IndividualAddress::new(1, 2, 6);
        let ctx = TestAddressContext::new(primary);
        ctx.additional.set([first_slot, second_slot]);
        let occupancy = TunnelOccupancy::new();
        let checker = IpInterfaceAddressChecker::new(&ctx, &occupancy);

        for (address, accept) in [(primary, true), (first_slot, true), (second_slot, true), (reassigned, false)] {
            for header in headers(address.as_bytes(), false) {
                assert_eq!(checker.should_ack(&header), accept);
            }
        }

        // ETS can rewrite both primary IA and tunneling slot assignments without
        // reconstructing the checker or restarting the TPUART task.
        ctx.ia.set(reassigned);
        ctx.additional.set([primary, second_slot]);
        for (address, accept) in [(primary, true), (first_slot, false), (second_slot, true), (reassigned, true)] {
            for header in headers(address.as_bytes(), false) {
                assert_eq!(checker.should_ack(&header), accept);
            }
        }
    }

    #[test]
    fn interface_checker_tracks_tunnel_occupancy_for_both_header_formats() {
        let ctx = TestAddressContext::new(IndividualAddress::new(1, 2, 3));
        let occupancy = TunnelOccupancy::new();
        let checker = IpInterfaceAddressChecker::new(&ctx, &occupancy);

        for header in headers(&[0x09, 0x03], true) {
            assert!(!checker.should_ack(&header));
            occupancy.on_connect();
            assert!(checker.should_ack(&header));
            occupancy.on_disconnect();
            assert!(!checker.should_ack(&header));
        }
    }
}
