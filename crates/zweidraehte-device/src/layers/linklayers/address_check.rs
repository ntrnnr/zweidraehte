//! Medium-neutral destination address checking.
//!
//! Both the TP1 (TPUART) and KNX-RF link layers must decide whether an incoming
//! frame is addressed to this device — TP1 to choose whether to `U_ACK_INF`,
//! KNX-RF (which has no Layer-2 ACK) to choose whether to deliver the frame up
//! the stack. The decision is identical: accept broadcasts, group frames whose
//! Group Address is in the loaded address table, and individual frames matching
//! our own individual address. This module holds that shared logic so neither
//! link layer has to reimplement it (and so KNX-RF can use it without depending
//! on the `tp1`-gated TPUART module).
//!
//! The header bytes passed to [`AddressChecker::should_ack`] are the first six
//! octets of a *standard* L_Data frame — `[ctrl, src_hi, src_lo, dst_hi, dst_lo,
//! at_npci]` — which the stack's internal frame format shares with the TP1
//! standard wire header, so both link layers can hand their respective buffers
//! to the same checker.

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use crate::context::IndividualAddressContext;
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
pub struct DeviceAddressChecker<'a, ADT: AddressTable + HasLoadStateMachine> {
    address_context: &'a dyn IndividualAddressContext,
    address_table: &'a core::cell::RefCell<ADT>,
}

impl<'a, ADT: AddressTable + HasLoadStateMachine> DeviceAddressChecker<'a, ADT> {
    pub fn new(address_context: &'a dyn IndividualAddressContext, address_table: &'a core::cell::RefCell<ADT>) -> Self {
        Self { address_context, address_table }
    }
}

impl<ADT: AddressTable + HasLoadStateMachine> AddressChecker for DeviceAddressChecker<'_, ADT> {
    fn should_ack(&self, header: &[u8; 6]) -> bool {
        let (dst_hi, dst_lo, is_group_address) = extract_header_fields(header);

        // Broadcast: destination 0x0000 is broadcast regardless of address
        // type flag. Individual 0.0.0 and group 0/0/0 are both broadcast.
        if dst_hi == 0 && dst_lo == 0 {
            return true;
        }

        if is_group_address {
            let ga = GroupAddress::from_bytes(&[dst_hi, dst_lo]);
            let table = self.address_table.borrow();
            // Loaded + empty table accepts all group frames.
            // This covers the ETS programming window where the table is loaded
            // but entries haven't been written yet.
            table.is_loaded() && (table.entry_count() == 0 || table.contains(ga))
        } else {
            let dst = IndividualAddress::from_bytes(&[dst_hi, dst_lo]);
            let our_addr = self.address_context.individual_address();
            dst == our_addr
        }
    }
}

#[cfg(test)]
mod tests {
    use super::extract_header_fields;

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
