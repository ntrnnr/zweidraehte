//! Common External Message Interface (cEMI) message format
//!
//! cEMI is used in KNX/IP and USB interfaces to encapsulate KNX telegrams.
//! This module provides parsing and serialization for cEMI L_Data frames.
//!
//! cEMI L_Data Frame Structure:
//! ```text
//! Byte 0:      Message Code (0x11 = L_Data.req, 0x29 = L_Data.ind, 0x2e = L_Data.con)
//! Byte 1:      Additional Info Length (usually 0x00)
//! Byte 2+N:    Additional Info (N bytes, where N = Additional Info Length)
//! Byte 2+N:    Control Field 1
//! Byte 3+N:    Control Field 2
//! Byte 4+N:    Source Address (2 bytes)
//! Byte 6+N:    Destination Address (2 bytes)
//! Byte 8+N:    NPDU Length
//! Byte 9+N:    TPCI/APCI + Data
//! ```

use zerocopy::{SplitByteSlice, SplitByteSliceMut};

use crate::{
    messages::{buffers::MessageBuffer, knx::ServiceType, knxip::error::ParseError},
    util::packets::*,
};

// ============================================================================
// MESSAGE CODE
// ============================================================================

create_protocol_enum!(
    /// cEMI Message Code
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum CemiMessageCode: u8 {
        LDataReq, 0x11, "L_Data.req";
        LDataCon, 0x2e, "L_Data.con";
        LDataInd, 0x29, "L_Data.ind";
        _, "Unknown cEMI message code 0x{:x}";
    }
);

impl CemiMessageCode {
    /// Convert to ServiceType
    pub fn to_service_type(self) -> ServiceType {
        match self {
            CemiMessageCode::LDataReq => ServiceType::L_Data_Req,
            CemiMessageCode::LDataCon => ServiceType::L_Data_Con,
            CemiMessageCode::LDataInd => ServiceType::L_Data_Ind,
            CemiMessageCode::Other(_) => ServiceType::L_Data_Ind, // Default fallback
        }
    }

    /// Create from ServiceType
    pub fn from_service_type(service_type: ServiceType) -> Self {
        match service_type {
            ServiceType::L_Data_Req => CemiMessageCode::LDataReq,
            ServiceType::L_Data_Con => CemiMessageCode::LDataCon,
            ServiceType::L_Data_Ind => CemiMessageCode::LDataInd,
            _ => CemiMessageCode::LDataInd, // Default fallback for other types
        }
    }
}

// ============================================================================
// CEMI L_DATA
// ============================================================================

/// Parsed cEMI L_Data frame
///
/// This represents a cEMI frame that encapsulates a KNX telegram.
/// The additional_info and data fields contain slices into the original buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CemiLData<B: SplitByteSlice = &'static [u8]> {
    /// Message code (L_Data.req, L_Data.ind, L_Data.con)
    pub message_code: CemiMessageCode,
    /// Additional info (usually empty, preserved as opaque bytes)
    pub additional_info: B,
    /// The KNX frame data (control fields, addresses, TPCI/APCI, data)
    pub data: B,
}

impl<B: SplitByteSlice> CemiLData<B> {
    /// Create a new cEMI L_Data frame
    pub fn new(message_code: CemiMessageCode, additional_info: B, data: B) -> Self {
        Self { message_code, additional_info, data }
    }

    /// Get the message code
    pub fn message_code(&self) -> CemiMessageCode {
        self.message_code
    }

    /// Get the additional info
    pub fn additional_info(&self) -> &[u8] {
        self.additional_info.deref()
    }

    /// Get the KNX frame data
    pub fn data(&self) -> &[u8] {
        self.data.deref()
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for CemiLData<B> {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        // Parse message code (byte 0)
        let msg_code_byte = buffer.take_byte_front().ok_or(ParseError::Format)?;
        let message_code = CemiMessageCode::try_from(msg_code_byte).map_err(|_| ParseError::NotSupported)?;

        // Parse additional info length (byte 1)
        let add_info_len = buffer.take_byte_front().ok_or(ParseError::Format)?;

        // Parse additional info (N bytes)
        let additional_info = if add_info_len > 0 {
            buffer.take_front(add_info_len as usize).ok_or(ParseError::Format)?
        } else {
            buffer.take_front(0).ok_or(ParseError::Format)?
        };

        // The remaining data is the KNX frame (control fields, addresses, TPCI/APCI, data)
        let data = buffer.take_rest_front();

        Ok(CemiLData { message_code, additional_info, data })
    }
}

// ============================================================================
// BUILDER
// ============================================================================

/// Builder for cEMI L_Data message
pub struct CemiLDataBuilder<'a> {
    pub message_code: CemiMessageCode,
    pub additional_info: &'a [u8],
    pub data: &'a [u8],
}

impl<'a> CemiLDataBuilder<'a> {
    /// Create a new cEMI L_Data builder with just message code and data
    pub fn new(message_code: CemiMessageCode, data: &'a [u8]) -> Self {
        Self { message_code, additional_info: &[], data }
    }

    /// Create a new cEMI L_Data builder with additional info
    pub fn with_additional_info(message_code: CemiMessageCode, additional_info: &'a [u8], data: &'a [u8]) -> Self {
        Self { message_code, additional_info, data }
    }
}

impl<'a> SerializablePacket for CemiLDataBuilder<'a> {
    fn bytes_len(&self) -> usize {
        2 + self.additional_info.len() + self.data.len() // msg_code + add_info_len + add_info + data
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        // Write message code and additional info length as a 2-byte header
        let header = [self.message_code.into(), self.additional_info.len() as u8];
        let mut header_buf = bv.take_front(header.len()).expect("too few bytes for cEMI header");
        header_buf.deref_mut().copy_from_slice(&header);

        // Write additional info (if any)
        if !self.additional_info.is_empty() {
            let mut add_info_buf = bv.take_front(self.additional_info.len()).expect("too few bytes for add info");
            add_info_buf.deref_mut().copy_from_slice(self.additional_info);
        }

        // Write KNX frame data
        let mut data_buf = bv.take_front(self.data.len()).expect("too few bytes for data");
        data_buf.deref_mut().copy_from_slice(self.data);
    }
}

// ============================================================================
// CONVERSION FUNCTIONS
// ============================================================================

// FIXME: check this conversion and the cEMI format against the spec!

/// Convert cEMI L_Data frame to internal KNX message format
///
/// cEMI format:
/// - Control Field 1 (bits: FT, Reserved, R, SB, PR, PR, Confirm/Error, ACK)
/// - Control Field 2 (bits: AT, HC, HC, HC, Length, Length, Length, Length)
/// - Source Address (2 bytes)
/// - Destination Address (2 bytes)
/// - NPDU Length (1 byte)
/// - TPCI/APCI + Data
///
/// Internal KNX format:
/// - CTRL Field (bits: FT, -, R, SB, PR, PR, A, C) - single byte
/// - Source Address (2 bytes)
/// - Destination Address (2 bytes)
/// - AT/HC/EFF (1 byte)
/// - TPCI/APCI + Data
pub fn cemi_to_knx_message<B: MessageBuffer>(cemi: &CemiLData<impl SplitByteSlice>, buffer: &mut B) {
    let cemi_data = cemi.data();

    // cEMI has 2 control fields, we need to merge them into 1
    // cEMI Control Field 1: FT(7), Reserved(6), R(5), SB(4), PR(3-2), Confirm/Error(1), ACK(0)
    // cEMI Control Field 2: AT(7), HC(6-4), Length(3-0)
    //
    // Internal CTRL: FT(7), -(6), R(5), SB(4), PR(3-2), A(1), C(0)
    // Internal NPDU: AT(7), HC(6-4), EFF(3-0)

    if cemi_data.len() < 7 {
        // Too short, just copy what we have
        buffer.fill_from_slice(cemi_data);
        return;
    }

    let ctrl1 = cemi_data[0];
    let ctrl2 = cemi_data[1];

    // Merge control fields:
    // Keep FT(7), R(5), SB(4), PR(3-2), A(1), C(0) from ctrl1
    // Bit 6 is unused in internal format
    let ctrl = ctrl1 & 0xBF; // Clear bit 6 (reserved in cEMI)

    // Start filling buffer
    buffer.set_len(0);
    buffer.push(ctrl); // Byte 0: CTRL

    // Copy source address (2 bytes)
    buffer.push(cemi_data[2]);
    buffer.push(cemi_data[3]);

    // Copy destination address (2 bytes)
    buffer.push(cemi_data[4]);
    buffer.push(cemi_data[5]);

    // NPDU field: AT from ctrl2(7), HC from ctrl2(6-4), EFF = 0 for standard frames
    // The length field in ctrl2(3-0) is not used in internal format
    let npdu = ctrl2 & 0xF0; // Keep AT and HC, clear length field
    buffer.push(npdu);

    // Copy TPCI/APCI + data (everything from byte 7 onwards)
    for i in 7..cemi_data.len() {
        buffer.push(cemi_data[i]);
    }
}

/// Convert internal KNX message to cEMI L_Data frame
///
/// Internal KNX format:
/// - CTRL Field (bits: FT, -, R, SB, PR, PR, A, C)
/// - Source Address (2 bytes)
/// - Destination Address (2 bytes)
/// - AT/HC/EFF (1 byte)
/// - TPCI/APCI + Data
///
/// cEMI format:
/// - Control Field 1 (bits: FT, Reserved, R, SB, PR, PR, Confirm/Error, ACK)
/// - Control Field 2 (bits: AT, HC, HC, HC, Length, Length, Length, Length)
/// - Source Address (2 bytes)
/// - Destination Address (2 bytes)
/// - NPDU Length (1 byte)
/// - TPCI/APCI + Data
pub fn knx_to_cemi_message<B1: MessageBuffer, B2: MessageBuffer>(
    knx_msg: &B1,
    message_code: CemiMessageCode,
    cemi_buffer: &mut B2,
) {
    if knx_msg.len() < 7 {
        // Too short
        return;
    }

    let ctrl = knx_msg[0];
    let npdu = knx_msg[5];

    // Split into cEMI control fields:
    // Control Field 1: FT(7), Reserved(6)=0, R(5), SB(4), PR(3-2), Confirm/Error(1), ACK(0)
    let ctrl1 = ctrl & 0xBF; // Ensure bit 6 is 0 (reserved)

    // Control Field 2: AT(7), HC(6-4), Length(3-0)
    // Length = NPDU length in cEMI = number of bytes after Control Field 2
    // That's: 2 (src) + 2 (dst) + 1 (npdu len) + TPCI/APCI/Data = knx_msg.len() - 1
    let data_len = knx_msg.len() - 1; // Everything except CTRL byte
    let ctrl2 = (npdu & 0xF0) | ((data_len - 5) as u8 & 0x0F); // AT|HC from npdu, add length

    // Start fresh
    cemi_buffer.set_len(0);

    // Write cEMI header
    cemi_buffer.push(message_code.into());
    cemi_buffer.push(0); // Additional info length

    // Write cEMI data
    cemi_buffer.push(ctrl1); // Control Field 1
    cemi_buffer.push(ctrl2); // Control Field 2

    // Copy source address (2 bytes)
    cemi_buffer.push(knx_msg[1]);
    cemi_buffer.push(knx_msg[2]);

    // Copy destination address (2 bytes)
    cemi_buffer.push(knx_msg[3]);
    cemi_buffer.push(knx_msg[4]);

    // NPDU length field (1 byte) - number of bytes after this field
    let npdu_len = (knx_msg.len() - 6) as u8; // TPCI/APCI + data
    cemi_buffer.push(npdu_len);

    // Copy TPCI/APCI + data
    for i in 6..knx_msg.len() {
        cemi_buffer.push(knx_msg[i]);
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cemi_ldata_parse() {
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

        let mut buffer = &cemi_data[..];
        let parsed = buffer.parse::<CemiLData<_>>().unwrap();

        assert_eq!(parsed.message_code, CemiMessageCode::LDataInd);
        assert_eq!(parsed.additional_info().len(), 0);
        assert_eq!(parsed.data(), &[0xbc, 0xe0, 0x11, 0x01, 0x08, 0x01, 0x01, 0x00, 0x81]);
    }

    #[test]
    fn test_cemi_ldata_parse_with_additional_info() {
        // cEMI frame with 2 bytes of additional info
        let cemi_data = [
            0x11, // Message code: L_Data.req
            0x02, // Additional info length
            0xAA, 0xBB, // Additional info
            0xbc, // Control field 1
            0xe0, // Control field 2
            0x11, 0x01, // Source: 1.1.1
            0x08, 0x01, // Destination: 1/0/1
            0x01, // Length
            0x00, 0x81, // TPCI/APCI + data
        ];

        let mut buffer = &cemi_data[..];
        let parsed = buffer.parse::<CemiLData<_>>().unwrap();

        assert_eq!(parsed.message_code, CemiMessageCode::LDataReq);
        assert_eq!(parsed.additional_info(), &[0xAA, 0xBB]);
        assert_eq!(parsed.data(), &[0xbc, 0xe0, 0x11, 0x01, 0x08, 0x01, 0x01, 0x00, 0x81]);
    }

    #[test]
    fn test_cemi_ldata_serialize() {
        let knx_data = [0xbc, 0xe0, 0x11, 0x01, 0x08, 0x01, 0x01, 0x00, 0x81];
        let builder = CemiLDataBuilder::new(CemiMessageCode::LDataInd, &knx_data);

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _remaining) = cursor.serialize(&builder);

        let expected = [
            0x29, // Message code
            0x00, // Additional info length
            0xbc, 0xe0, 0x11, 0x01, 0x08, 0x01, 0x01, 0x00, 0x81, // KNX data
        ];

        assert_eq!(written, &expected[..]);
    }

    #[test]
    fn test_cemi_ldata_serialize_with_additional_info() {
        let add_info = [0xAA, 0xBB];
        let knx_data = [0xbc, 0xe0, 0x11, 0x01, 0x08, 0x01, 0x01, 0x00, 0x81];
        let builder = CemiLDataBuilder::with_additional_info(CemiMessageCode::LDataReq, &add_info, &knx_data);

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _remaining) = cursor.serialize(&builder);

        let expected = [
            0x11, // Message code
            0x02, // Additional info length
            0xAA, 0xBB, // Additional info
            0xbc, 0xe0, 0x11, 0x01, 0x08, 0x01, 0x01, 0x00, 0x81, // KNX data
        ];

        assert_eq!(written, &expected[..]);
    }

    #[test]
    fn test_cemi_round_trip() {
        let original_data = [0x29, 0x00, 0xbc, 0xe0, 0x11, 0x01, 0x08, 0x01, 0x01, 0x00, 0x81];

        // Parse
        let mut parse_buffer = &original_data[..];
        let parsed = parse_buffer.parse::<CemiLData<_>>().unwrap();

        // Serialize
        let builder = CemiLDataBuilder::new(parsed.message_code, parsed.data());
        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        assert_eq!(written, &original_data[..]);
    }

    #[test]
    fn test_message_code_conversion() {
        assert_eq!(CemiMessageCode::LDataReq.to_service_type(), ServiceType::L_Data_Req);
        assert_eq!(CemiMessageCode::LDataInd.to_service_type(), ServiceType::L_Data_Ind);
        assert_eq!(CemiMessageCode::LDataCon.to_service_type(), ServiceType::L_Data_Con);

        assert_eq!(CemiMessageCode::from_service_type(ServiceType::L_Data_Req), CemiMessageCode::LDataReq);
        assert_eq!(CemiMessageCode::from_service_type(ServiceType::L_Data_Ind), CemiMessageCode::LDataInd);
        assert_eq!(CemiMessageCode::from_service_type(ServiceType::L_Data_Con), CemiMessageCode::LDataCon);
    }

    // Test buffer implementation for unit tests
    #[cfg(test)]
    struct TestBuffer {
        data: Vec<u8>,
    }

    #[cfg(test)]
    impl TestBuffer {
        fn new() -> Self {
            Self { data: Vec::new() }
        }

        fn from_slice(data: &[u8]) -> Self {
            Self { data: data.to_vec() }
        }
    }

    #[cfg(test)]
    impl MessageBuffer for TestBuffer {
        fn len(&self) -> usize {
            self.data.len()
        }

        fn set_len(&mut self, len: usize) {
            self.data.resize(len, 0);
        }

        fn capacity(&self) -> usize {
            usize::MAX
        }

        fn resize(&mut self, new_len: usize, fill_value: u8) {
            self.data.resize(new_len, fill_value)
        }
    }

    #[cfg(test)]
    impl core::ops::Deref for TestBuffer {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &self.data
        }
    }

    #[cfg(test)]
    impl core::ops::DerefMut for TestBuffer {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.data
        }
    }

    #[test]
    fn test_cemi_to_knx_conversion() {
        // cEMI frame: L_Data.ind from 1.1.1 to 1/0/1 with data 0x01
        // cEMI data portion:
        // - Control Field 1: 0xbc (FT=1, R=0, SB=1, PR=3, A=0, C=0)
        // - Control Field 2: 0xe0 (AT=1 group, HC=7, Length=0)
        // - Source: 0x11 0x01 (1.1.1)
        // - Dest: 0x08 0x01 (1/0/1)
        // - NPDU Length: 0x01
        // - TPCI/APCI + data: 0x00 0x81
        let cemi_data = [
            0x29, // Message code: L_Data.ind
            0x00, // Additional info length
            0xbc, 0xe0, // Control Field 1 and 2
            0x11, 0x01, // Source: 1.1.1
            0x08, 0x01, // Destination: 1/0/1
            0x01, // NPDU length
            0x00, 0x81, // TPCI/APCI + data
        ];

        // Parse cEMI
        let mut cemi_buffer = &cemi_data[..];
        let cemi = cemi_buffer.parse::<CemiLData<_>>().unwrap();

        // Convert to internal KNX format
        let mut knx_buffer = TestBuffer::new();
        cemi_to_knx_message(&cemi, &mut knx_buffer);

        // Expected internal KNX format:
        // - CTRL: 0xbc (FT=1, R=0, SB=1, PR=3, A=0, C=0) - same as ctrl1
        // - Source: 0x11 0x01
        // - Dest: 0x08 0x01
        // - NPDU: 0xe0 (AT=1, HC=7, EFF=0)
        // - TPCI/APCI + data: 0x00 0x81
        assert_eq!(knx_buffer.len(), 8);
        assert_eq!(knx_buffer[0], 0xbc); // CTRL
        assert_eq!(knx_buffer[1], 0x11); // Source high
        assert_eq!(knx_buffer[2], 0x01); // Source low
        assert_eq!(knx_buffer[3], 0x08); // Dest high
        assert_eq!(knx_buffer[4], 0x01); // Dest low
        assert_eq!(knx_buffer[5], 0xe0); // NPDU (AT|HC, no length)
        assert_eq!(knx_buffer[6], 0x00); // TPCI/APCI
        assert_eq!(knx_buffer[7], 0x81); // Data
    }

    #[test]
    fn test_knx_to_cemi_conversion() {
        // Internal KNX message: from 1.1.1 to 1/0/1 with data 0x01
        // - CTRL: 0xbc
        // - Source: 0x11 0x01 (1.1.1)
        // - Dest: 0x08 0x01 (1/0/1)
        // - NPDU: 0xe0 (AT=1 group, HC=7, EFF=0)
        // - TPCI/APCI + data: 0x00 0x81
        let knx_data = [0xbc, 0x11, 0x01, 0x08, 0x01, 0xe0, 0x00, 0x81];

        let mut knx_buffer = TestBuffer::from_slice(&knx_data);

        // Convert to cEMI
        let mut cemi_buffer = TestBuffer::new();
        knx_to_cemi_message(&knx_buffer, CemiMessageCode::LDataInd, &mut cemi_buffer);

        // Expected cEMI format:
        // - Message code: 0x29
        // - Add info len: 0x00
        // - Control Field 1: 0xbc (same as CTRL)
        // - Control Field 2: 0xe0 | (len-5)&0x0F = 0xe0 | (7-5)&0x0F = 0xe0 | 0x02 = 0xe2
        // - Source: 0x11 0x01
        // - Dest: 0x08 0x01
        // - NPDU Length: 0x02 (TPCI/APCI + data)
        // - TPCI/APCI + data: 0x00 0x81
        assert_eq!(cemi_buffer.len(), 11);
        assert_eq!(cemi_buffer[0], 0x29); // Message code
        assert_eq!(cemi_buffer[1], 0x00); // Add info len
        assert_eq!(cemi_buffer[2], 0xbc); // Control Field 1
        assert_eq!(cemi_buffer[3], 0xe2); // Control Field 2 (AT|HC + length)
        assert_eq!(cemi_buffer[4], 0x11); // Source high
        assert_eq!(cemi_buffer[5], 0x01); // Source low
        assert_eq!(cemi_buffer[6], 0x08); // Dest high
        assert_eq!(cemi_buffer[7], 0x01); // Dest low
        assert_eq!(cemi_buffer[8], 0x02); // NPDU length
        assert_eq!(cemi_buffer[9], 0x00); // TPCI/APCI
        assert_eq!(cemi_buffer[10], 0x81); // Data
    }
}
