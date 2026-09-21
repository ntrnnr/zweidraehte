//! Medium-neutral destination address checking.
//!
//! TP1 (TPUART), KNX-RF and KNX/IP must decide whether an incoming frame is
//! addressed to this device — TP1 to choose whether to `U_ACK_INF`,
//! KNX-RF and KNX/IP to choose whether to deliver the frame up
//! the stack. The decision is identical: accept broadcasts, group frames whose
//! Group Address is in the loaded address table, and individual frames matching
//! our own individual address. Keeping this policy outside the medium-specific
//! modules lets each medium use it without enabling another medium's feature.
//!
//! [`AddressChecker::should_ack`] parses the first six octets of either a
//! standard or extended L_Data frame. KNX/IP uses the same destination policy
//! after parsing its cEMI frame.

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::messages::knx::DestinationAddress;

use crate::context::{AddressTableContext, IndividualAddressContext};
use crate::objects::tables::{AddressTable, HasLoadStateMachine};

/// Trait for deciding whether an incoming frame is addressed to this device.
///
/// The link layer calls [`should_ack`](AddressChecker::should_ack) with the
/// 6-byte frame header. The header layout depends on the frame type (bit 7 of
/// the control byte):
///
/// - **Standard** (ctrl bit 7 = 1): `[ctrl, src_hi, src_lo, dst_hi, dst_lo, at_npci]`
/// - **Extended** (ctrl bit 7 = 0): `[ctrl, ext_ctrl, src_hi, src_lo, dst_hi, dst_lo]`
///
/// | Mode | Checker | Behaviour |
/// |------|---------|-----------|
/// | Normal device | [`DeviceAddressChecker`] | own individual address, loaded group addresses, broadcast |
/// | KNX/IP tunnel | [`AckAllChecker`] | accept everything (forward all traffic) |
/// | Bus monitor / test | [`NoAddressChecker`] | accept nothing |
///
/// # Implementation Notes
///
/// - Called synchronously during frame reception, so implementations must be
///   fast (e.g. using `RefCell`, not async).
/// - The header bytes are raw wire / internal-format bytes, not KNX-decoded.
pub trait AddressChecker {
    /// Decide whether a frame with this header is for this device.
    fn should_ack(&self, header: &[u8; 6]) -> bool;
}

/// Extract destination address and address-type flag from a 6-byte header,
/// handling both standard and extended frame formats.
///
/// Returns `(dst_hi, dst_lo, is_group_address)`. Shared with the TPUART link
/// layer (which also parses raw frame headers for its ACK decision).
pub(crate) fn extract_header_fields(header: &[u8; 6]) -> (u8, u8, bool) {
    let is_extended = (header[0] & 0x80) == 0;
    if is_extended {
        // Extended: [ctrl, ext_ctrl, src_hi, src_lo, dst_hi, dst_lo]
        // AT flag is in ext_ctrl (header[1]) bit 7.
        let dst_hi = header[4];
        let dst_lo = header[5];
        let is_group = (header[1] & 0x80) != 0;
        (dst_hi, dst_lo, is_group)
    } else {
        // Standard: [ctrl, src_hi, src_lo, dst_hi, dst_lo, at_npci]
        // AT flag is in at_npci (header[5]) bit 7.
        let dst_hi = header[3];
        let dst_lo = header[4];
        let is_group = (header[5] & 0x80) != 0;
        (dst_hi, dst_lo, is_group)
    }
}

/// A no-op address checker that accepts no frames.
///
/// Useful for bus monitor mode or testing, where the device must not interfere
/// with bus traffic.
pub struct NoAddressChecker;

impl AddressChecker for NoAddressChecker {
    fn should_ack(&self, _header: &[u8; 6]) -> bool {
        false
    }
}

/// An address checker that accepts every frame unconditionally.
///
/// Used by KNX/IP tunneling gateways that need to forward all bus traffic to the
/// tunnel client.
pub struct AckAllChecker;

impl AddressChecker for AckAllChecker {
    fn should_ack(&self, _header: &[u8; 6]) -> bool {
        true
    }
}

/// Address checker for normal KNX devices.
///
/// Accepts frames matching:
/// - The device's own individual address (via [`IndividualAddressContext`])
/// - Group addresses present in the loaded address table
/// - Broadcast destination (`0.0.0` / `0/0/0`)
///
/// Borrows the concrete context so address and table reads remain both live
/// and statically dispatched. The table type comes from `CTX::ADT`.
/// Unsized providers are deliberately excluded: a trait object would erase the
/// implementation selected by the device definition.
///
/// ```compile_fail
/// use zweidraehte_device::context::{AddressTableContext, IndividualAddressContext};
/// use zweidraehte_device::layers::linklayers::address_check::DeviceAddressChecker;
///
/// fn erase_provider<CTX: IndividualAddressContext + AddressTableContext + ?Sized>(context: &CTX) {
///     // Fails because the checker requires a concrete, Sized provider.
///     let _ = DeviceAddressChecker::new(context);
/// }
/// ```
pub struct DeviceAddressChecker<'a, CTX> {
    context: &'a CTX,
}

impl<'a, CTX: IndividualAddressContext + AddressTableContext> DeviceAddressChecker<'a, CTX> {
    /// Read the individual address and address table from `context` on each frame.
    pub fn new(context: &'a CTX) -> Self {
        Self { context }
    }

    /// Shared destination policy for raw link headers and parsed KNX/IP frames.
    pub(crate) fn accepts_destination(&self, destination: DestinationAddress) -> bool {
        match destination {
            DestinationAddress::Individual(addr) => addr == self.context.individual_address(),
            DestinationAddress::Group(ga) => {
                let table = self.context.address_table().borrow();
                // Loaded + empty accepts every group during the ETS programming
                // window, before individual entries have been written.
                table.is_loaded() && (table.entry_count() == 0 || table.contains(ga))
            }
            DestinationAddress::Broadcast | DestinationAddress::SystemBroadcast => true,
            // A connection number is an internal TSAP, never a link destination.
            DestinationAddress::ConnectionNr(_) => false,
        }
    }
}

impl<CTX: IndividualAddressContext + AddressTableContext> AddressChecker for DeviceAddressChecker<'_, CTX> {
    fn should_ack(&self, header: &[u8; 6]) -> bool {
        let (dst_hi, dst_lo, is_group_address) = extract_header_fields(header);

        // Broadcast: destination 0x0000 is broadcast regardless of address
        // type flag. Individual 0.0.0 and group 0/0/0 are both broadcast.
        if dst_hi == 0 && dst_lo == 0 {
            return true;
        }

        let destination = if is_group_address {
            DestinationAddress::Group(GroupAddress::from_bytes(&[dst_hi, dst_lo]))
        } else {
            DestinationAddress::Individual(IndividualAddress::from_bytes(&[dst_hi, dst_lo]))
        };
        self.accepts_destination(destination)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[cfg(feature = "ip-interface")]
    use crate::context::IpAdditionalIndividualAddressContext;
    use crate::objects::tables::{AddrTab7Impl, LoadState, Table};
    use core::cell::{Cell, RefCell};

    /// Shared live-provider fixture for the TP1, RF and KNX/IP address adapters.
    pub(crate) struct TestAddressContext {
        pub(crate) ia: Cell<IndividualAddress>,
        pub(crate) table: RefCell<Table<AddrTab7Impl<8>>>,
        #[cfg(feature = "ip-interface")]
        pub(crate) additional: Cell<[IndividualAddress; 2]>,
    }

    impl TestAddressContext {
        pub(crate) fn new(ia: IndividualAddress) -> Self {
            Self {
                ia: Cell::new(ia),
                table: RefCell::new(Table::new()),
                #[cfg(feature = "ip-interface")]
                additional: Cell::new([IndividualAddress::new(0, 0, 0); 2]),
            }
        }
    }

    impl IndividualAddressContext for TestAddressContext {
        fn individual_address(&self) -> IndividualAddress {
            self.ia.get()
        }
    }

    impl AddressTableContext for TestAddressContext {
        type ADT = Table<AddrTab7Impl<8>>;

        fn address_table(&self) -> &RefCell<Self::ADT> {
            &self.table
        }
    }

    #[cfg(feature = "ip-interface")]
    impl IpAdditionalIndividualAddressContext for TestAddressContext {
        fn write_additional_individual_addresses(&self, buf: &mut [IndividualAddress]) -> usize {
            let count = buf.len().min(2);
            buf[..count].copy_from_slice(&self.additional.get()[..count]);
            count
        }

        fn contains_additional_individual_address(&self, addr: IndividualAddress) -> bool {
            self.additional.get().contains(&addr)
        }
    }

    /// Standard and extended headers with the same destination and source 1.1.1.
    pub(crate) fn headers(dst: &[u8], group: bool) -> [[u8; 6]; 2] {
        let npci = if group { 0xe0 } else { 0x60 };
        [[0xbc, 0x11, 0x01, dst[0], dst[1], npci], [0x3c, npci, 0x11, 0x01, dst[0], dst[1]]]
    }

    #[test]
    fn checker_observes_address_assignment_without_rebuild() {
        let virgin = IndividualAddress::new(15, 15, 255);
        let assigned = IndividualAddress::new(1, 2, 3);
        let ctx = TestAddressContext::new(virgin);
        let checker = DeviceAddressChecker::new(&ctx);

        for address in [virgin, assigned] {
            ctx.ia.set(address);
            for candidate in [virgin, assigned] {
                for header in headers(candidate.as_bytes(), false) {
                    assert_eq!(checker.should_ack(&header), candidate == address);
                }
            }
        }
        for group in [false, true] {
            for header in headers(&[0, 0], group) {
                assert!(checker.should_ack(&header));
            }
        }
    }

    #[test]
    fn checker_observes_group_entries_and_load_state_without_rebuild() {
        let ctx = TestAddressContext::new(IndividualAddress::new(1, 2, 3));
        let checker = DeviceAddressChecker::new(&ctx);
        let first = [0x09, 0x03];
        let second = [0x09, 0x04];

        // An unloaded table accepts neither. Loaded entries, entry replacement,
        // the empty programming window and unloading must all be visible live.
        for (table, expected) in [
            (Table::new(), [false, false]),
            (Table::with_data(&[0, 1, 0x09, 0x03], 0), [true, false]),
            (Table::with_data(&[0, 1, 0x09, 0x04], 0), [false, true]),
            (Table::with_data(&[0, 0], 0), [true, true]),
        ] {
            *ctx.table.borrow_mut() = table;
            for (group, accept) in [first, second].into_iter().zip(expected) {
                for header in headers(&group, true) {
                    assert_eq!(checker.should_ack(&header), accept);
                }
            }
        }
        ctx.table.borrow_mut().set_load_state(LoadState::Unloaded);
        for header in headers(&first, true) {
            assert!(!checker.should_ack(&header));
        }
    }

    // A standard L_Data header — the layout the stack's internal frame format
    // and the TP1 standard wire header share, and what the KNX-RF link layer
    // hands to the checker. ctrl 0xBC has bit 7 set ⇒ standard.
    #[test]
    fn standard_header_decodes_individual_destination() {
        // ctrl, src 1.0.2, dst 1.2.1, at_npci 0x60 (bit7=0 ⇒ individual).
        let header = [0xBC, 0x10, 0x02, 0x12, 0x01, 0x60];
        assert_eq!(extract_header_fields(&header), (0x12, 0x01, false));
    }

    #[test]
    fn standard_header_decodes_group_destination() {
        // at_npci 0xE0 has bit 7 set ⇒ group.
        let header = [0xBC, 0x10, 0x02, 0x09, 0x03, 0xE0];
        assert_eq!(extract_header_fields(&header), (0x09, 0x03, true));
    }

    #[test]
    fn extended_header_decodes_destination_from_later_octets() {
        // ctrl 0x3C has bit 7 clear ⇒ extended: dst is header[4..6], AT in header[1].
        let header = [0x3C, 0x80, 0x10, 0x02, 0x12, 0x01];
        assert_eq!(extract_header_fields(&header), (0x12, 0x01, true));
    }
}
