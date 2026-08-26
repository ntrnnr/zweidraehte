//! Device Selector for KNX/IP Remote Configuration and Extended Search
//!
//! The Selector (KNX 3/8/7 §4.6) identifies which devices should respond
//! to remote diagnostic/configuration requests. The same type codes
//! (0x01 = PrgMode, 0x02 = MAC) are shared with Search Request Parameters
//! (SRP) in KNX 3/8/2, making this type reusable for extended search
//! filtering as well.

use core::mem;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, SplitByteSlice, SplitByteSliceMut, Unaligned};

use zweidraehte_platform::address::EthernetAddress;

use crate::messages::knxip::error::{ParseError, ParseResult};
use crate::util::packets::{BufferView, BufferViewMut, ParsablePacket, SerializablePacket};

use super::{DeviceInformation, DeviceStatus};

// ============================================================================
// INTERNAL WIRE FORMAT
// ============================================================================

mod raw {
    use super::*;

    /// Selector TLV header (2 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct SelectorHeader {
        pub struct_len: u8,
        pub selector_type: u8,
    }
}

// ============================================================================
// SELECTOR TYPE CODES
// ============================================================================

/// Selector type codes (KNX 3/8/7 §4.6).
///
/// These match the SRP type codes in 3/8/2 for the overlapping variants.
const SELECTOR_TYPE_PRGMODE: u8 = 0x01;
const SELECTOR_TYPE_MAC: u8 = 0x02;

// ============================================================================
// PUBLIC API
// ============================================================================

/// Device selector for remote configuration and diagnostic services.
///
/// Used to target specific devices in multicast/broadcast requests.
/// A device responds only if it matches the selector.
///
/// Wire format (TLV):
/// - PrgMode: `[0x02, 0x01]` — 2 bytes, selects devices in programming mode
/// - MAC: `[0x08, 0x02, mac0..mac5]` — 8 bytes, selects device by MAC address
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Selector {
    /// Select all devices currently in programming mode.
    PrgMode,
    /// Select a specific device by its MAC address.
    Mac(EthernetAddress),
}

impl Selector {
    /// Check whether a device matches this selector.
    ///
    /// Reusable for both remote config selectors (3/8/7 §4.6) and
    /// extended search SRPs (3/8/2) that use the same type codes.
    pub fn matches(&self, device_info: &DeviceInformation) -> bool {
        match self {
            Selector::PrgMode => device_info.device_status == DeviceStatus::ProgrammingMode,
            Selector::Mac(mac) => device_info.mac_address == *mac,
        }
    }
}

// ============================================================================
// PARSING
// ============================================================================

impl<B: SplitByteSlice> ParsablePacket<B, ()> for Selector {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> ParseResult<Self> {
        let header = buffer.take_obj_front::<raw::SelectorHeader>().ok_or_else(|| {
            debug!("too few bytes for Selector header");
            ParseError::Format
        })?;

        let body_len = header.struct_len.checked_sub(mem::size_of::<raw::SelectorHeader>() as u8).ok_or_else(|| {
            debug!("Selector struct_len {} too small", header.struct_len);
            ParseError::Format
        })?;

        match header.selector_type {
            SELECTOR_TYPE_PRGMODE => {
                // PrgMode selector has no body (struct_len = 2)
                if body_len != 0 {
                    debug!("PrgMode selector has unexpected body length {}", body_len);
                    return Err(ParseError::Format);
                }
                Ok(Selector::PrgMode)
            }
            SELECTOR_TYPE_MAC => {
                // MAC selector body is 6 bytes (struct_len = 8)
                if body_len != 6 {
                    debug!("MAC selector has unexpected body length {}", body_len);
                    return Err(ParseError::Format);
                }
                let mac = buffer.take_obj_front::<EthernetAddress>().ok_or_else(|| {
                    debug!("too few bytes for MAC selector body");
                    ParseError::Format
                })?;
                Ok(Selector::Mac(*mac))
            }
            other => {
                debug!("unknown Selector type: 0x{:02x}", other);
                Err(ParseError::Format)
            }
        }
    }
}

// ============================================================================
// SERIALIZATION
// ============================================================================

impl SerializablePacket for Selector {
    fn bytes_len(&self) -> usize {
        match self {
            Selector::PrgMode => mem::size_of::<raw::SelectorHeader>(),
            Selector::Mac(_) => mem::size_of::<raw::SelectorHeader>() + mem::size_of::<EthernetAddress>(),
        }
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let mut header = bv.take_obj_front_zero::<raw::SelectorHeader>().expect("too few bytes for Selector header");

        header.struct_len = self.bytes_len() as u8;

        match self {
            Selector::PrgMode => {
                header.selector_type = SELECTOR_TYPE_PRGMODE;
            }
            Selector::Mac(mac) => {
                header.selector_type = SELECTOR_TYPE_MAC;
                let mut mac_field =
                    bv.take_obj_front_zero::<EthernetAddress>().expect("too few bytes for MAC selector body");
                *mac_field = *mac;
            }
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::packets::{ParseBuffer, SerializeBuffer};

    #[test]
    fn parse_prgmode_selector() {
        let data: &[u8] = &[0x02, 0x01]; // len=2, type=PrgMode
        let mut buf = data;
        let selector: Selector = buf.parse().unwrap();
        assert_eq!(selector, Selector::PrgMode);
    }

    #[test]
    fn parse_mac_selector() {
        let data: &[u8] = &[0x08, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut buf = data;
        let selector: Selector = buf.parse().unwrap();
        let expected_mac = EthernetAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(selector, Selector::Mac(expected_mac));
    }

    #[test]
    fn prgmode_selector_round_trip() {
        let original = Selector::PrgMode;
        let mut buf = [0u8; 16];
        let mut write_buf = &mut buf[..];
        write_buf.serialize(&original);

        let written = &buf[..original.bytes_len()];
        assert_eq!(written, &[0x02, 0x01]);

        let mut read_buf = written;
        let parsed: Selector = read_buf.parse().unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn mac_selector_round_trip() {
        let mac = EthernetAddress([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let original = Selector::Mac(mac);
        let mut buf = [0u8; 16];
        let mut write_buf = &mut buf[..];
        write_buf.serialize(&original);

        let written = &buf[..original.bytes_len()];
        assert_eq!(written, &[0x08, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

        let mut read_buf = written;
        let parsed: Selector = read_buf.parse().unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn prgmode_selector_matches_device_in_programming_mode() {
        let mut device_info = test_device_info();
        device_info.device_status = DeviceStatus::ProgrammingMode;
        assert!(Selector::PrgMode.matches(&device_info));
    }

    #[test]
    fn prgmode_selector_does_not_match_normal_device() {
        let device_info = test_device_info();
        assert!(!Selector::PrgMode.matches(&device_info));
    }

    #[test]
    fn mac_selector_matches_correct_mac() {
        let device_info = test_device_info();
        let selector = Selector::Mac(device_info.mac_address);
        assert!(selector.matches(&device_info));
    }

    #[test]
    fn mac_selector_does_not_match_wrong_mac() {
        let device_info = test_device_info();
        let wrong_mac = EthernetAddress([0xFF; 6]);
        assert!(!Selector::Mac(wrong_mac).matches(&device_info));
    }

    #[test]
    fn parse_unknown_selector_type_fails() {
        let data: &[u8] = &[0x02, 0x99]; // unknown type
        let mut buf = data;
        assert!(buf.parse::<Selector>().is_err());
    }

    #[test]
    fn parse_truncated_mac_selector_fails() {
        let data: &[u8] = &[0x08, 0x02, 0xAA, 0xBB]; // only 2 of 6 MAC bytes
        let mut buf = data;
        assert!(buf.parse::<Selector>().is_err());
    }

    fn test_device_info() -> DeviceInformation {
        use crate::address::IndividualAddress;
        use crate::messages::knxip::substructs::KNXMedium;
        use core::net::Ipv4Addr;

        DeviceInformation {
            medium: KNXMedium::KNXIP,
            device_status: DeviceStatus::None,
            individual_address: IndividualAddress::new(1, 1, 0),
            project_installation_identifier: 0,
            knx_serial_number: [0; 6],
            routing_multicast_address: Ipv4Addr::new(224, 0, 23, 12),
            mac_address: EthernetAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            friendly_name: [0; 30],
        }
    }
}
