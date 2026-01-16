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
// CEMI BUFFER WRAPPER
// ============================================================================

/// A buffer containing a cEMI frame
///
/// This wrapper provides typed access to cEMI frame contents without parsing
/// into a separate structure. It's used by the USB transport layer to send
/// and receive raw cEMI frames.
///
/// ## cEMI Frame Structure
///
/// ```text
/// Byte 0:      Message Code (0x11 = L_Data.req, 0x29 = L_Data.ind, 0x2e = L_Data.con, etc.)
/// Byte 1:      Additional Info Length (N)
/// Byte 2..2+N: Additional Info
/// Byte 2+N..:  Frame data (control fields, addresses, TPCI/APCI, data)
/// ```
#[derive(Debug)]
pub struct CemiBuffer<B> {
    inner: B,
}

impl<B: MessageBuffer> CemiBuffer<B> {
    /// Create a new CemiBuffer wrapping an existing buffer
    ///
    /// The buffer should already contain valid cEMI data.
    pub fn new(inner: B) -> Self {
        Self { inner }
    }

    /// Create a CemiBuffer by building a cEMI frame from components
    pub fn build(mut inner: B, message_code: CemiMessageCode, additional_info: &[u8], frame_data: &[u8]) -> Self {
        let total_len = 2 + additional_info.len() + frame_data.len();
        inner.resize(total_len, 0);

        inner[0] = message_code.into();
        inner[1] = additional_info.len() as u8;

        if !additional_info.is_empty() {
            inner[2..2 + additional_info.len()].copy_from_slice(additional_info);
        }

        let frame_start = 2 + additional_info.len();
        inner[frame_start..frame_start + frame_data.len()].copy_from_slice(frame_data);

        Self { inner }
    }

    /// Get the message code
    pub fn message_code(&self) -> CemiMessageCode {
        if self.inner.len() > 0 {
            CemiMessageCode::try_from(self.inner[0]).unwrap_or(CemiMessageCode::Other(self.inner[0]))
        } else {
            CemiMessageCode::Other(0)
        }
    }

    /// Get the additional info length
    pub fn additional_info_len(&self) -> usize {
        if self.inner.len() > 1 {
            self.inner[1] as usize
        } else {
            0
        }
    }

    /// Get the additional info bytes
    pub fn additional_info(&self) -> &[u8] {
        let add_len = self.additional_info_len();
        if self.inner.len() >= 2 + add_len {
            &self.inner[2..2 + add_len]
        } else {
            &[]
        }
    }

    /// Get the frame data (everything after message code and additional info)
    ///
    /// This is the KNX frame starting from the control fields.
    pub fn frame_data(&self) -> &[u8] {
        let add_len = self.additional_info_len();
        let start = 2 + add_len;
        if self.inner.len() > start {
            &self.inner[start..]
        } else {
            &[]
        }
    }

    /// Get the frame data mutably
    pub fn frame_data_mut(&mut self) -> &mut [u8] {
        let add_len = self.additional_info_len();
        let start = 2 + add_len;
        if self.inner.len() > start {
            &mut self.inner[start..]
        } else {
            &mut []
        }
    }

    /// Get the raw cEMI frame bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner[..]
    }

    /// Get the raw cEMI frame bytes mutably
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.inner[..]
    }

    /// Get the total length of the cEMI frame
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Unwrap and return the inner buffer
    pub fn into_inner(self) -> B {
        self.inner
    }

    /// Get a reference to the inner buffer
    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Get a mutable reference to the inner buffer
    pub fn inner_mut(&mut self) -> &mut B {
        &mut self.inner
    }

    /// Check if this is an L_Data.req message
    pub fn is_l_data_req(&self) -> bool {
        matches!(self.message_code(), CemiMessageCode::LDataReq)
    }

    /// Check if this is an L_Data.ind message
    pub fn is_l_data_ind(&self) -> bool {
        matches!(self.message_code(), CemiMessageCode::LDataInd)
    }

    /// Check if this is an L_Data.con message
    pub fn is_l_data_con(&self) -> bool {
        matches!(self.message_code(), CemiMessageCode::LDataCon)
    }

    /// Check if this is a local device management message (M_PropRead/Write)
    pub fn is_device_management(&self) -> bool {
        matches!(
            self.inner.get(0),
            Some(0xFC) | Some(0xFB) | Some(0xF6) | Some(0xF5)
        )
    }
}

impl<B: MessageBuffer + Clone> Clone for CemiBuffer<B> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

// ============================================================================
// CONVERSION FUNCTIONS
// ============================================================================

/// Convert cEMI L_Data frame to internal KNX message format
///
/// cEMI format:
/// - Message Code (1 byte)
/// - Additional Info Length (1 byte)
/// - Additional Info (N bytes)
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
pub fn cemi_to_knx_message<B: MessageBuffer>(mut msg: B) -> B {
    let len = msg.len();

    // Skip message code (byte 0) and additional info length (byte 1)
    let add_info_len = msg[1] as usize;
    let data_start = 2 + add_info_len;

    if len < data_start + 7 {
        // Not enough data after additional info
        return msg;
    }

    let ctrl1 = msg[data_start];
    let ctrl2 = msg[data_start + 1];

    // Merge control fields:
    // Keep FT(7), R(5), SB(4), PR(3-2), A(1), C(0) from ctrl1
    // Bit 6 is unused in internal format
    let ctrl = ctrl1 & 0xBF; // Clear bit 6 (reserved in cEMI)

    // NPDU field: AT from ctrl2(7), HC from ctrl2(6-4), EFF = 0 for standard frames
    // The length field in ctrl2(3-0) is not used in internal format
    let npdu = ctrl2 & 0xF0; // Keep AT and HC, clear length field

    // Shift data in place to remove cEMI header and merge control fields
    // We need to remove: msg_code(1) + add_info_len(1) + add_info(N) + one ctrl field(1) + npdu_len(1)
    // That's data_start + 1 (for ctrl2) + 1 (for npdu_len after dest addr)

    msg[0] = ctrl; // CTRL field

    // Copy source address (from data_start+2 to position 1-2)
    msg[1] = msg[data_start + 2];
    msg[2] = msg[data_start + 3];

    // Copy destination address (from data_start+4 to position 3-4)
    msg[3] = msg[data_start + 4];
    msg[4] = msg[data_start + 5];

    msg[5] = npdu; // NPDU field

    // Copy TPCI/APCI + data (skip npdu_len byte at data_start+6, start from data_start+7)
    let tpci_start = data_start + 7;
    for i in 0..(len - tpci_start) {
        msg[6 + i] = msg[tpci_start + i];
    }

    // New length: CTRL(1) + SrcAddr(2) + DstAddr(2) + NPDU(1) + TPCI/APCI/Data
    let new_len = len - data_start - 1; // Remove everything up to ctrl2 and the npdu_len byte
    msg.set_len(new_len);

    msg
}

/// Convert internal KNX message to cEMI format in-place at a specified offset.
///
/// The KNX message data should already be present at `buffer[offset..]`.
/// The buffer must have room for expansion (3 extra bytes for cEMI header + ctrl2).
///
/// # KNX to cEMI Transformation
///
/// KNX format (at `offset`):
/// ```text
///   [ctrl1][src_hi][src_lo][dst_hi][dst_lo][npdu][tpci/apci...]
/// ```
///
/// cEMI format (after conversion, at `offset`):
/// ```text
///   [msg_code][add_info_len=0][ctrl1][ctrl2][src_hi][src_lo][dst_hi][dst_lo][npdu_len][tpci/apci...]
/// ```
///
/// # Arguments
/// * `buffer` - The buffer containing KNX data at `offset` with room for expansion
/// * `offset` - Starting offset where the cEMI frame should begin (use 0 for no offset)
/// * `knx_len` - Length of the KNX message data
/// * `message_code` - The cEMI message code (L_Data.req, L_Data.ind, etc.)
///
/// # Returns
/// The final length of the cEMI frame (original knx_len + 3)
pub fn knx_to_cemi_message(
    buffer: &mut [u8],
    offset: usize,
    knx_len: usize,
    message_code: CemiMessageCode,
) -> usize {
    // Save the original NPDU value before shifting (needed for ctrl2)
    let orig_npdu = buffer[offset + 5];

    // Shift data to make room for cEMI header (2 bytes) and ctrl2 (1 byte)
    // Everything shifts right by 3, but ctrl1 only shifts by 2 (to make room for msg_code and add_info_len)
    for i in (0..knx_len).rev() {
        if i == 0 {
            buffer[offset + i + 2] = buffer[offset + i]; // ctrl1 shifts by 2
        } else {
            buffer[offset + i + 3] = buffer[offset + i]; // everything else shifts by 3
        }
    }

    // Set cEMI header
    buffer[offset] = message_code.into();     // msg_code
    buffer[offset + 1] = 0;                   // add_info_len = 0

    // ctrl1 is now at offset + 2 (was shifted)
    // Set ctrl2 at offset + 3
    buffer[offset + 3] = orig_npdu;           // ctrl2: AT/HC/EFF from original npdu

    // Set npdu_len at offset + 8 (after ctrl1, ctrl2, src(2), dst(2))
    buffer[offset + 8] = (knx_len - 7) as u8; // Length of TPCI/APCI + data

    // Return final cEMI length
    knx_len + 3
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

    use core::ops::{Deref, DerefMut};

    #[derive(Debug)]
    struct TestBuffer {
        data: Vec<u8>,
    }

    impl TestBuffer {
        fn new(data: &[u8]) -> Self {
            Self { data: data.to_vec() }
        }
    }

    impl MessageBuffer for TestBuffer {
        fn len(&self) -> usize {
            self.data.len()
        }

        fn set_len(&mut self, len: usize) {
            // For Vec, we need to handle both growing and shrinking
            if len > self.data.len() {
                // When growing, we use reserve + set_len to avoid filling with zeros
                // This matches the semantics of a fixed-size buffer where set_len
                // doesn't initialize the new bytes
                self.data.reserve(len - self.data.len());
                unsafe { self.data.set_len(len); }
            } else {
                self.data.truncate(len);
            }
        }

        fn capacity(&self) -> usize {
            self.data.capacity()
        }

        fn headroom(&self) -> usize {
            0 // Vec-based buffer has no headroom
        }

        fn grow_front(&mut self, count: usize) {
            // For Vec, we need to insert at the front
            self.data.splice(0..0, core::iter::repeat(0).take(count));
        }

        fn shrink_front(&mut self, count: usize) {
            self.data.drain(0..count);
        }

        fn spare_capacity_mut(&mut self) -> &mut [u8] {
            // Vec grows dynamically, so we reserve some space
            let len = self.data.len();
            self.data.reserve(64);
            let cap = self.data.capacity();
            // This is unsafe but okay for tests - return slice of reserved capacity
            unsafe { core::slice::from_raw_parts_mut(self.data.as_mut_ptr().add(len), cap - len) }
        }

        fn resize(&mut self, new_len: usize, fill_value: u8) {
            self.data.resize(new_len, fill_value)
        }
    }

    impl Deref for TestBuffer {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &self.data
        }
    }

    impl DerefMut for TestBuffer {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.data
        }
    }

    #[test]
    fn test_cemi_to_knx_conversion() {
        // cEMI frame: L_Data.ind from 1.1.1 to 1/0/1 with data 0x01
        // cEMI data portion:
        // - Message code: 0x29
        // - Additional info length: 0x00
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

        // Convert to internal KNX format
        let buffer = TestBuffer::new(&cemi_data);
        let result = cemi_to_knx_message(buffer);

        println!("cemi_to_knx result: {:x?}", result);

        // Expected internal KNX format:
        // - CTRL: 0xbc (FT=1, R=0, SB=1, PR=3, A=0, C=0) - same as ctrl1
        // - Source: 0x11 0x01
        // - Dest: 0x08 0x01
        // - NPDU: 0xe0 (AT=1, HC=7, EFF=0)
        // - TPCI/APCI + data: 0x00 0x81
        assert_eq!(result.len(), 8);
        assert_eq!(result[0], 0xbc); // CTRL
        assert_eq!(result[1], 0x11); // Source high
        assert_eq!(result[2], 0x01); // Source low
        assert_eq!(result[3], 0x08); // Dest high
        assert_eq!(result[4], 0x01); // Dest low
        assert_eq!(result[5], 0xe0); // NPDU (AT|HC, no length)
        assert_eq!(result[6], 0x00); // TPCI/APCI
        assert_eq!(result[7], 0x81); // Data
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
        let knx_len = knx_data.len();

        // Create buffer with room for expansion (3 extra bytes)
        let mut buffer = [0u8; 11];
        buffer[..knx_len].copy_from_slice(&knx_data);

        // Convert to cEMI in-place
        let cemi_len = knx_to_cemi_message(&mut buffer, 0, knx_len, CemiMessageCode::LDataInd);

        println!("{:x?}", &buffer[..cemi_len]);

        // Expected cEMI format:
        // - Message code: 0x29
        // - Add info len: 0x00
        // - Control Field 1: 0xbc (same as CTRL)
        // - Control Field 2: 0xe0 | (len-5)&0x0F = 0xe0 | (7-5)&0x0F = 0xe0 | 0x02 = 0xe2
        // - Source: 0x11 0x01
        // - Dest: 0x08 0x01
        // - NPDU Length: 0x02 (TPCI/APCI + data)
        // - TPCI/APCI + data: 0x00 0x81
        assert_eq!(cemi_len, 11);
        assert_eq!(buffer[0], 0x29); // Message code
        assert_eq!(buffer[1], 0x00); // Add info len
        assert_eq!(buffer[2], 0xbc); // Control Field 1
        assert_eq!(buffer[3], 0xe0); // Control Field 2 (AT|HC + length)
        assert_eq!(buffer[4], 0x11); // Source high
        assert_eq!(buffer[5], 0x01); // Source low
        assert_eq!(buffer[6], 0x08); // Dest high
        assert_eq!(buffer[7], 0x01); // Dest low
        assert_eq!(buffer[8], 0x01); // NPDU length
        assert_eq!(buffer[9], 0x00); // TPCI/APCI
        assert_eq!(buffer[10], 0x81); // Data
    }
}
