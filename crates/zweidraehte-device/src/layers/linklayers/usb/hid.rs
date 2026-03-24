//! KNX USB HID Report handling
//!
//! This module implements the HID report framing layer for KNX USB communication.
//! HID reports are 64 bytes max, with a 3-byte header leaving 61 bytes for payload.
//! Frames larger than 61 bytes must be fragmented across multiple reports.

/// KNX HID Report ID (fixed per spec)
pub const REPORT_ID: u8 = 0x01;

/// Maximum HID report size
pub const MAX_REPORT_SIZE: usize = 64;

/// Maximum payload per HID report (after 3-byte header)
pub const MAX_PAYLOAD_SIZE: usize = 61;

/// Maximum KNX frame size (extended frame format on TP1)
pub const MAX_KNX_FRAME_SIZE: usize = 263;

/// Maximum number of HID reports needed for largest KNX frame
pub const MAX_REPORTS: usize = 5;

/// Packet type flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketType(u8);

impl PacketType {
    /// Start packet flag
    pub const START: u8 = 0x01;
    /// End packet flag
    pub const END: u8 = 0x02;
    /// Partial packet flag
    pub const PARTIAL: u8 = 0x04;

    /// Start and end in one packet (single packet transfer)
    pub const START_END: PacketType = PacketType(Self::START | Self::END);
    /// Start and partial (first of multiple)
    pub const START_PARTIAL: PacketType = PacketType(Self::START | Self::PARTIAL);
    /// Partial only (middle packet)
    pub const PARTIAL_ONLY: PacketType = PacketType(Self::PARTIAL);
    /// Partial and end (last of multiple)
    pub const PARTIAL_END: PacketType = PacketType(Self::PARTIAL | Self::END);

    pub fn new(value: u8) -> Self {
        Self(value & 0x07)
    }

    pub fn is_start(&self) -> bool {
        (self.0 & Self::START) != 0
    }

    pub fn is_end(&self) -> bool {
        (self.0 & Self::END) != 0
    }

    pub fn is_partial(&self) -> bool {
        (self.0 & Self::PARTIAL) != 0
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

/// Packet info byte (sequence number in high nibble, packet type in low nibble)
#[derive(Debug, Clone, Copy)]
pub struct PacketInfo(u8);

impl PacketInfo {
    pub fn new(sequence: u8, packet_type: PacketType) -> Self {
        debug_assert!((1..=5).contains(&sequence), "Sequence number must be 1-5");
        Self((sequence << 4) | packet_type.as_u8())
    }

    pub fn from_byte(byte: u8) -> Self {
        Self(byte)
    }

    pub fn sequence_number(&self) -> u8 {
        self.0 >> 4
    }

    pub fn packet_type(&self) -> PacketType {
        PacketType::new(self.0 & 0x0F)
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

/// A parsed HID report
#[derive(Debug)]
pub struct HidReport<'a> {
    pub report_id: u8,
    pub packet_info: PacketInfo,
    pub data_length: u8,
    pub data: &'a [u8],
}

impl<'a> HidReport<'a> {
    /// Parse an HID report from a 64-byte buffer
    pub fn parse(buf: &'a [u8]) -> Result<Self, HidReportError> {
        if buf.len() < 3 {
            return Err(HidReportError::TooShort);
        }

        let report_id = buf[0];
        if report_id != REPORT_ID {
            return Err(HidReportError::InvalidReportId(report_id));
        }

        let packet_info = PacketInfo::from_byte(buf[1]);
        let data_length = buf[2];

        // Validate sequence number
        let seq = packet_info.sequence_number();
        if seq == 0 || seq > 5 {
            return Err(HidReportError::InvalidSequence(seq));
        }

        // Validate packet type
        let pt = packet_info.packet_type();
        let valid_types = [
            PacketType::START_END,
            PacketType::START_PARTIAL,
            PacketType::PARTIAL_ONLY,
            PacketType::PARTIAL_END,
        ];
        if !valid_types.contains(&pt) {
            return Err(HidReportError::InvalidPacketType(pt.as_u8()));
        }

        // Validate data length
        if data_length as usize > MAX_PAYLOAD_SIZE {
            return Err(HidReportError::DataLengthExceeded(data_length));
        }

        let data_end = 3 + data_length as usize;
        if buf.len() < data_end {
            return Err(HidReportError::TooShort);
        }

        Ok(Self {
            report_id,
            packet_info,
            data_length,
            data: &buf[3..data_end],
        })
    }
}

/// Error parsing HID report
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidReportError {
    /// Report buffer too short
    TooShort,
    /// Invalid report ID (expected 0x01)
    InvalidReportId(u8),
    /// Invalid sequence number (must be 1-5)
    InvalidSequence(u8),
    /// Invalid packet type combination
    InvalidPacketType(u8),
    /// Data length exceeds maximum (61)
    DataLengthExceeded(u8),
}

/// Builder for constructing HID reports
pub struct HidReportBuilder {
    buf: [u8; MAX_REPORT_SIZE],
    data_len: usize,
}

impl HidReportBuilder {
    pub fn new(sequence: u8, packet_type: PacketType) -> Self {
        let mut buf = [0u8; MAX_REPORT_SIZE];
        buf[0] = REPORT_ID;
        buf[1] = PacketInfo::new(sequence, packet_type).as_u8();
        // buf[2] will be set when we finalize
        Self { buf, data_len: 0 }
    }

    /// Append data to the report payload
    pub fn append(&mut self, data: &[u8]) -> usize {
        let available = MAX_PAYLOAD_SIZE - self.data_len;
        let to_copy = data.len().min(available);
        self.buf[3 + self.data_len..3 + self.data_len + to_copy].copy_from_slice(&data[..to_copy]);
        self.data_len += to_copy;
        to_copy
    }

    /// Finalize and get the report buffer
    pub fn finish(mut self) -> [u8; MAX_REPORT_SIZE] {
        self.buf[2] = self.data_len as u8;
        self.buf
    }

    /// Get current data length
    pub fn data_len(&self) -> usize {
        self.data_len
    }

    /// Check if report is full
    pub fn is_full(&self) -> bool {
        self.data_len >= MAX_PAYLOAD_SIZE
    }
}

/// Reassembly buffer for multi-packet frames
pub struct ReassemblyBuffer {
    buf: [u8; MAX_KNX_FRAME_SIZE],
    len: usize,
    expected_seq: u8,
    in_progress: bool,
}

impl Default for ReassemblyBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl ReassemblyBuffer {
    pub const fn new() -> Self {
        Self {
            buf: [0u8; MAX_KNX_FRAME_SIZE],
            len: 0,
            expected_seq: 1,
            in_progress: false,
        }
    }

    /// Reset the reassembly state
    pub fn reset(&mut self) {
        self.len = 0;
        self.expected_seq = 1;
        self.in_progress = false;
    }

    /// Process an incoming HID report
    ///
    /// Returns `Some(&[u8])` when a complete frame is assembled, `None` otherwise.
    pub fn process(&mut self, report: &HidReport<'_>) -> Result<Option<&[u8]>, ReassemblyError> {
        let seq = report.packet_info.sequence_number();
        let pt = report.packet_info.packet_type();

        // Handle start of new frame
        if pt.is_start() {
            // If we were in progress on another frame, discard it (per spec)
            if self.in_progress && seq == 1 {
                warn!("USB HID: Discarding incomplete frame, new transfer started");
            }
            self.reset();
            self.in_progress = true;
        }

        // Validate sequence
        if seq != self.expected_seq {
            let err = ReassemblyError::SequenceMismatch {
                expected: self.expected_seq,
                received: seq,
            };
            self.reset();
            return Err(err);
        }

        // Must be in progress to receive data
        if !self.in_progress {
            return Err(ReassemblyError::UnexpectedPacket);
        }

        // Append data
        let remaining = MAX_KNX_FRAME_SIZE - self.len;
        if report.data.len() > remaining {
            self.reset();
            return Err(ReassemblyError::BufferOverflow);
        }
        self.buf[self.len..self.len + report.data.len()].copy_from_slice(report.data);
        self.len += report.data.len();

        // Check if complete
        if pt.is_end() {
            self.in_progress = false;
            self.expected_seq = 1;
            return Ok(Some(&self.buf[..self.len]));
        }

        // Expect next sequence
        self.expected_seq = seq + 1;
        Ok(None)
    }

    /// Check if reassembly is in progress
    pub fn is_in_progress(&self) -> bool {
        self.in_progress
    }
}

/// Error during frame reassembly
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassemblyError {
    /// Sequence number mismatch
    SequenceMismatch { expected: u8, received: u8 },
    /// Received packet without start
    UnexpectedPacket,
    /// Frame too large for buffer
    BufferOverflow,
}

/// Fragment a frame into HID reports
///
/// Returns an iterator over HID report buffers.
pub fn fragment_frame(data: &[u8]) -> FragmentIterator<'_> {
    FragmentIterator {
        data,
        offset: 0,
        sequence: 1,
    }
}

/// Iterator that yields HID report buffers for a fragmented frame
pub struct FragmentIterator<'a> {
    data: &'a [u8],
    offset: usize,
    sequence: u8,
}

impl<'a> Iterator for FragmentIterator<'a> {
    type Item = [u8; MAX_REPORT_SIZE];

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        let remaining = self.data.len() - self.offset;
        let chunk_size = remaining.min(MAX_PAYLOAD_SIZE);
        let is_first = self.offset == 0;
        let is_last = self.offset + chunk_size >= self.data.len();

        let packet_type = match (is_first, is_last) {
            (true, true) => PacketType::START_END,
            (true, false) => PacketType::START_PARTIAL,
            (false, true) => PacketType::PARTIAL_END,
            (false, false) => PacketType::PARTIAL_ONLY,
        };

        let mut builder = HidReportBuilder::new(self.sequence, packet_type);
        builder.append(&self.data[self.offset..self.offset + chunk_size]);

        self.offset += chunk_size;
        self.sequence += 1;

        Some(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_info() {
        let info = PacketInfo::new(1, PacketType::START_END);
        assert_eq!(info.sequence_number(), 1);
        assert!(info.packet_type().is_start());
        assert!(info.packet_type().is_end());
        assert!(!info.packet_type().is_partial());
        assert_eq!(info.as_u8(), 0x13);
    }

    #[test]
    fn test_single_packet_frame() {
        let data = [0x11, 0x00, 0x00, 0x00]; // Small cEMI frame
        let reports: Vec<_> = fragment_frame(&data).collect();

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0][0], REPORT_ID);
        assert_eq!(reports[0][1], 0x13); // seq=1, start+end
        assert_eq!(reports[0][2], 4);    // data length
        assert_eq!(&reports[0][3..7], &data);
    }

    #[test]
    fn test_multi_packet_frame() {
        // Create a 100-byte frame (needs 2 packets: 61 + 39)
        let data = [0xAA; 100];
        let reports: Vec<_> = fragment_frame(&data).collect();

        assert_eq!(reports.len(), 2);

        // First packet: seq=1, start+partial
        assert_eq!(reports[0][1], 0x15); // seq=1, start+partial
        assert_eq!(reports[0][2], 61);   // max payload

        // Second packet: seq=2, partial+end
        assert_eq!(reports[1][1], 0x26); // seq=2, partial+end
        assert_eq!(reports[1][2], 39);   // remaining
    }

    #[test]
    fn test_reassembly_single() {
        let data = [0x11, 0x00, 0x00, 0x00];
        let reports: Vec<_> = fragment_frame(&data).collect();

        let mut reassembly = ReassemblyBuffer::new();
        let report = HidReport::parse(&reports[0]).unwrap();
        let result = reassembly.process(&report).unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap(), &data);
    }

    #[test]
    fn test_reassembly_multi() {
        let data = [0xBB; 100];
        let reports: Vec<_> = fragment_frame(&data).collect();

        let mut reassembly = ReassemblyBuffer::new();

        // First packet
        let report1 = HidReport::parse(&reports[0]).unwrap();
        let result1 = reassembly.process(&report1).unwrap();
        assert!(result1.is_none());
        assert!(reassembly.is_in_progress());

        // Second packet
        let report2 = HidReport::parse(&reports[1]).unwrap();
        let result2 = reassembly.process(&report2).unwrap();
        assert!(result2.is_some());
        assert_eq!(result2.unwrap(), &data);
        assert!(!reassembly.is_in_progress());
    }

    #[test]
    fn test_reassembly_sequence_error() {
        let mut reassembly = ReassemblyBuffer::new();

        // Send packet with seq=2 without seq=1 first
        let mut buf = [0u8; 64];
        buf[0] = REPORT_ID;
        buf[1] = 0x26; // seq=2, partial+end
        buf[2] = 10;

        let report = HidReport::parse(&buf).unwrap();
        let result = reassembly.process(&report);

        assert!(matches!(result, Err(ReassemblyError::SequenceMismatch { expected: 1, received: 2 })));
    }
}
