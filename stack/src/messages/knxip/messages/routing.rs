//! KNX/IP Routing Messages (ROUTING_INDICATION, ROUTING_BUSY, ROUTING_LOST_MESSAGE)
//!
//! These messages are used for KNX/IP routing multicast communication:
//! - RoutingIndication: Contains a cEMI L_Data frame for routing KNX telegrams
//! - RoutingBusy: Congestion control message indicating the device is busy
//! - RoutingLostMessage: Notification that messages were lost due to congestion

// FIXME: compare these with knx spec

use core::mem;

use zerocopy::{SplitByteSlice, SplitByteSliceMut, big_endian::U16};

use crate::{messages::knxip::error::*, util::packets::*};

use super::{KNXnetIPServiceType, KNXnetIPVersion, raw::KNXnetIPHeader};

// ============================================================================
// ROUTING INDICATION
// ============================================================================

/// KNXnet/IP ROUTING_INDICATION
///
/// Used to transmit KNX telegrams over IP multicast.
/// The payload is a complete cEMI L_Data frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingIndication<B: SplitByteSlice = &'static [u8]> {
    /// cEMI L_Data frame (the actual KNX telegram)
    pub cemi_frame: B,
}

impl<B: SplitByteSlice> RoutingIndication<B> {
    /// Create a new ROUTING_INDICATION with the given cEMI frame
    pub fn new(cemi_frame: B) -> Self {
        Self { cemi_frame }
    }

    /// Get the cEMI frame data
    pub fn cemi_data(&self) -> &[u8] {
        self.cemi_frame.deref()
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for RoutingIndication<B> {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        // Parse header
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        // Verify it's a ROUTING_INDICATION
        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::RoutingIndication
        {
            return Err(ParseError::Format);
        }

        // The remaining data is the cEMI frame
        let cemi_len = header.total_length.get() as usize - mem::size_of::<KNXnetIPHeader>();
        let cemi_frame = buffer.take_front(cemi_len).ok_or(ParseError::Format)?;

        Ok(RoutingIndication { cemi_frame })
    }
}

/// Builder for RoutingIndication message
pub struct RoutingIndicationBuilder<'a> {
    pub cemi_frame: &'a [u8],
}

impl<'a> RoutingIndicationBuilder<'a> {
    pub fn new(cemi_frame: &'a [u8]) -> Self {
        Self { cemi_frame }
    }
}

impl<'a> SerializablePacket for RoutingIndicationBuilder<'a> {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + self.cemi_frame.len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::RoutingIndication)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        // Write cEMI frame
        let mut cemi_buf = bv.take_front(self.cemi_frame.len()).expect("too few bytes for cEMI frame");
        cemi_buf.deref_mut().copy_from_slice(self.cemi_frame);
    }
}

// ============================================================================
// ROUTING BUSY
// ============================================================================

/// Device state in RoutingBusy message
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DeviceState {
    /// Raw device state byte
    pub raw: u8,
}

impl DeviceState {
    /// Create a new device state
    pub fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// No error condition
    pub fn none() -> Self {
        Self { raw: 0x00 }
    }

    /// KNX network layer buffer full
    pub fn is_knx_fault(&self) -> bool {
        self.raw & 0x01 != 0
    }
}

/// KNXnet/IP ROUTING_BUSY
///
/// Sent when a device cannot handle more routing messages due to congestion.
/// Contains a wait time indicating how long senders should pause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingBusy {
    /// Device state
    pub device_state: DeviceState,
    /// Wait time in milliseconds before sending next RoutingIndication
    pub wait_time: u16,
    /// Control field
    pub control_field: u16,
}

impl RoutingBusy {
    /// Create a new ROUTING_BUSY message
    pub fn new(device_state: DeviceState, wait_time: u16) -> Self {
        Self { device_state, wait_time, control_field: 0 }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for RoutingBusy {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        // Parse header
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        // Verify it's a ROUTING_BUSY
        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::RoutingBusy
        {
            return Err(ParseError::Format);
        }

        // Parse structure
        // Byte 0: Structure length (should be 6)
        let structure_length = buffer.take_byte_front().ok_or(ParseError::Format)?;
        if structure_length != 6 {
            return Err(ParseError::Format);
        }

        // Byte 1: Device state
        let device_state = DeviceState::new(buffer.take_byte_front().ok_or(ParseError::Format)?);

        // Bytes 2-3: Wait time in milliseconds (big endian)
        let wait_time_bytes = buffer.take_front(2).ok_or(ParseError::Format)?;
        let wait_time = u16::from_be_bytes([wait_time_bytes[0], wait_time_bytes[1]]);

        // Bytes 4-5: Control field
        let control_field_bytes = buffer.take_front(2).ok_or(ParseError::Format)?;
        let control_field = u16::from_be_bytes([control_field_bytes[0], control_field_bytes[1]]);

        Ok(RoutingBusy { device_state, wait_time, control_field })
    }
}

/// Builder for RoutingBusy message
pub struct RoutingBusyBuilder {
    pub device_state: DeviceState,
    pub wait_time: u16,
    pub control_field: u16,
}

impl RoutingBusyBuilder {
    pub fn new(device_state: DeviceState, wait_time: u16) -> Self {
        Self { device_state, wait_time, control_field: 0 }
    }
}

impl SerializablePacket for RoutingBusyBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + 6 // header + 6 byte structure
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::RoutingBusy)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        // Build the structure as a byte array
        let structure = [
            6,                             // Structure length
            self.device_state.raw,         // Device state
            (self.wait_time >> 8) as u8,   // Wait time high byte
            (self.wait_time & 0xFF) as u8, // Wait time low byte
            0,
            0,
        ];

        let mut struct_buf = bv.take_front(structure.len()).expect("too few bytes for structure");
        struct_buf.deref_mut().copy_from_slice(&structure);
    }
}

// ============================================================================
// ROUTING LOST MESSAGE
// ============================================================================

/// KNXnet/IP ROUTING_LOST_MESSAGE
///
/// Sent when a device has lost routing messages due to buffer overflow or other issues.
/// Contains a count of how many messages were lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingLostMessage {
    /// Device state
    pub device_state: DeviceState,
    /// Number of lost messages
    pub lost_message_count: u16,
}

impl RoutingLostMessage {
    /// Create a new ROUTING_LOST_MESSAGE
    pub fn new(device_state: DeviceState, lost_message_count: u16) -> Self {
        Self { device_state, lost_message_count }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for RoutingLostMessage {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        // Parse header
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        // Verify it's a ROUTING_LOST_MESSAGE
        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::RoutingLostMessage
        {
            return Err(ParseError::Format);
        }

        // Parse structure
        // Byte 0: Structure length (should be 4)
        let structure_length = buffer.take_byte_front().ok_or(ParseError::Format)?;
        if structure_length != 4 {
            return Err(ParseError::Format);
        }

        // Byte 1: Device state
        let device_state = DeviceState::new(buffer.take_byte_front().ok_or(ParseError::Format)?);

        // Bytes 2-3: Lost message count (big endian)
        let count_bytes = buffer.take_front(2).ok_or(ParseError::Format)?;
        let lost_message_count = u16::from_be_bytes([count_bytes[0], count_bytes[1]]);

        Ok(RoutingLostMessage { device_state, lost_message_count })
    }
}

/// Builder for RoutingLostMessage message
pub struct RoutingLostMessageBuilder {
    pub device_state: DeviceState,
    pub lost_message_count: u16,
}

impl RoutingLostMessageBuilder {
    pub fn new(device_state: DeviceState, lost_message_count: u16) -> Self {
        Self { device_state, lost_message_count }
    }
}

impl SerializablePacket for RoutingLostMessageBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + 4 // header + 4 byte structure
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::RoutingLostMessage)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        // Build the structure as a byte array
        let structure = [
            4,                                      // Structure length
            self.device_state.raw,                  // Device state
            (self.lost_message_count >> 8) as u8,   // Lost count high byte
            (self.lost_message_count & 0xFF) as u8, // Lost count low byte
        ];

        let mut struct_buf = bv.take_front(structure.len()).expect("too few bytes for structure");
        struct_buf.deref_mut().copy_from_slice(&structure);
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
    fn test_routing_indication_parse() {
        // Example cEMI frame: L_Data.ind from 1.1.1 to 1/0/1 with data 0x01
        let cemi_data = [
            0x29, // Message code: L_Data.ind
            0x00, // Additional info length
            0xbc, // Control field 1
            0xe0, // Control field 2
            0x11, 0x01, // Source: 1.1.1
            0x08, 0x01, // Destination: 1/0/1
            0x01, // Length
            0x00, 0x81, // TPCI/APCI + data
        ];

        let mut packet = heapless::Vec::<u8, 64>::new();
        packet
            .extend_from_slice(&[
                0x06, 0x10, 0x05, 0x30, // Header: ROUTING_INDICATION
                0x00, 0x11, // Total length: 17 bytes (6 header + 11 cEMI)
            ])
            .unwrap();
        packet.extend_from_slice(&cemi_data).unwrap();

        let mut buffer = packet.as_slice();
        let parsed = buffer.parse::<RoutingIndication<_>>().unwrap();

        assert_eq!(parsed.cemi_data(), &cemi_data);
    }

    #[test]
    fn test_routing_indication_serialize() {
        let cemi_data = [0x29, 0x00, 0xbc, 0xe0, 0x11, 0x01, 0x08, 0x01, 0x01, 0x00, 0x81];

        let builder = RoutingIndicationBuilder::new(&cemi_data);

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _remaining) = cursor.serialize(&builder);

        assert_eq!(written.len(), 17); // 6 header + 11 cEMI

        // Verify header
        assert_eq!(written[0], 0x06); // Header length
        assert_eq!(written[1], 0x10); // Protocol version
        assert_eq!(&written[2..4], &[0x05, 0x30]); // Service type: RoutingIndication
        assert_eq!(&written[4..6], &[0x00, 0x11]); // Total length: 17

        // Verify cEMI frame
        assert_eq!(&written[6..], cemi_data);
    }

    #[test]
    fn test_routing_busy_parse() {
        let data = [
            0x06, 0x10, 0x05, 0x32, // Header: ROUTING_BUSY
            0x00, 0x0e, // Total length: 14 bytes
            0x06, // Structure length
            0x00, // Device state: no error
            0x00, 0x64, // Wait time: 100ms
            0x00, 0x00, // Control field
        ];

        let mut buffer = &data[..];
        let parsed = buffer.parse::<RoutingBusy>().unwrap();

        assert_eq!(parsed.device_state.raw, 0x00);
        assert_eq!(parsed.wait_time, 100);
    }

    #[test]
    fn test_routing_busy_serialize() {
        let builder = RoutingBusyBuilder::new(DeviceState::none(), 100);

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _remaining) = cursor.serialize(&builder);

        let expected = [
            0x06, 0x10, 0x05, 0x32, // Header
            0x00, 0x0c, // Total length
            0x06, // Structure length
            0x00, // Device state
            0x00, 0x64, // Wait time: 100ms
            0x00, 0x00, // Control field
        ];

        assert_eq!(written, &expected[..]);
    }

    #[test]
    fn test_routing_busy_round_trip() {
        let original = RoutingBusy::new(DeviceState::new(0x01), 250);

        // Serialize
        let builder = RoutingBusyBuilder::new(original.device_state, original.wait_time);
        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<RoutingBusy>().unwrap();

        // Compare
        assert_eq!(parsed.device_state.raw, original.device_state.raw);
        assert_eq!(parsed.wait_time, original.wait_time);
    }

    #[test]
    fn test_routing_lost_message_parse() {
        let data = [
            0x06, 0x10, 0x05, 0x31, // Header: ROUTING_LOST_MESSAGE
            0x00, 0x0a, // Total length: 14 bytes
            0x04, // Structure length
            0x01, // Device state: KNX fault
            0x00, 0x0a, // Lost count: 10 messages
        ];

        let mut buffer = &data[..];
        let parsed = buffer.parse::<RoutingLostMessage>().unwrap();

        assert_eq!(parsed.device_state.raw, 0x01);
        assert!(parsed.device_state.is_knx_fault());
        assert_eq!(parsed.lost_message_count, 10);
    }

    #[test]
    fn test_routing_lost_message_serialize() {
        let builder = RoutingLostMessageBuilder::new(DeviceState::new(0x01), 10);

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _remaining) = cursor.serialize(&builder);

        let expected = [
            0x06, 0x10, 0x05, 0x31, // Header
            0x00, 0x0a, // Total length
            0x04, // Structure length
            0x01, // Device state
            0x00, 0x0a, // Lost count: 10
        ];

        assert_eq!(written, &expected[..]);
    }

    #[test]
    fn test_routing_lost_message_round_trip() {
        let original = RoutingLostMessage::new(DeviceState::new(0x01), 42);

        // Serialize
        let builder = RoutingLostMessageBuilder::new(original.device_state, original.lost_message_count);
        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<RoutingLostMessage>().unwrap();

        // Compare
        assert_eq!(parsed.device_state.raw, original.device_state.raw);
        assert_eq!(parsed.lost_message_count, original.lost_message_count);
    }

    #[test]
    fn test_device_state() {
        let normal = DeviceState::none();
        assert_eq!(normal.raw, 0x00);
        assert!(!normal.is_knx_fault());

        let fault = DeviceState::new(0x01);
        assert_eq!(fault.raw, 0x01);
        assert!(fault.is_knx_fault());
    }
}
