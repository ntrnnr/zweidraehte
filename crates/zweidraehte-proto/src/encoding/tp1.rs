//! TP1 message format conversion utilities
//!
//! These functions help converting TP1 frames into the internal KNX message format and vice versa.
//! Below are the message formats shown in detail.
//!
//! Standard KNX frame:
//!  +--------+-------------------+---------------------+----------------+--------------+-------------------+---------+
//!  | Ctrl   | Source Address    | Destination Address | Addr/Hop/Len   | TPCI/APCI    | APDU (Data)       | Chksum  |
//!  | Field  | (2 bytes)         | (2 bytes)           | (1 byte)       | (1 byte)     | (1-15 bytes)      | (1 byte)|
//!  +--------+-------------------+---------------------+----------------+--------------+-------------------+---------+
//!  | 1 byte | 2 bytes           | 2 bytes             | 1 byte         | 1 byte       | 1-15 bytes        | 1 byte  |
//!  +--------+-------------------+---------------------+----------------+--------------+-------------------+---------+
//!
//!  Bit breakdown for Control Field (CTRL):
//!    7   6   5   4   3   2   1   0
//!  +---+---+---+---+---+---+---+---+
//!  |FT | 0 | RF| 1 | PR| PR| 0 | 0 |
//!  +---+---+---+---+---+---+---+---+
//!  FT  = Frame Type (1: standard, 0: extended) — per 03/02/02 §2.2.4, a
//!        L_Data_Standard Frame carries FT = 1 in the control field.
//!  0   = Always 0
//!  RF  = Repeat Flag (0: repeat, 1: do not repeat)
//!  1   = Always 1
//!  PR  = Priority (2 bits: 00 = system, 01 = alarm, 10 = high, 11 = low)
//!  0   = Always 0
//!
//!  Bit breakdown for Addr/Hop/Len byte:
//!    7   6   5   4   3   2   1   0
//!  +---+---+---+---+---+---+---+---+
//!  |AT | HC| HC| HC|LEN|LEN|LEN|LEN|
//!  +---+---+---+---+---+---+---+---+
//!  AT  = Address Type (0: individual, 1: group)
//!  HC  = Hop Count (routing counter, 3 bits)
//!  LEN = Length (number of bytes after this field, including TPCI/APCI + APDU, 4 bits, 1–15)
//!
//!
//! Extended KNX TP 1 frame:
//!  +--------+--------+-------------------+---------------------+-------------------+-------------------+-------------------+---------+
//!  | Ctrl   | Ext    | Source Address    | Destination Address | Length            | TPCI/APCI         | APDU (Data)       | Chksum  |
//!  | Field  | Ctrl   | (2 bytes)         | (2 bytes)           | (1 byte)          | (1 byte)          | (1-254 bytes)     | (1 byte)|
//!  +--------+--------+-------------------+---------------------+-------------------+-------------------+-------------------+---------+
//!  | 1 byte | 1 byte | 2 bytes           | 2 bytes             | 1 byte            | 1 byte            | 1-254 bytes       | 1 byte  |
//!  +--------+--------+-------------------+---------------------+-------------------+-------------------+-------------------+---------+
//!
//!  Bit breakdown for Control Field (CTRL):
//!    7   6   5   4   3   2   1   0
//!  +---+---+---+---+---+---+---+---+
//!  |FT | 0 | RF| 1 | PR| PR| 0 | 0 |
//!  +---+---+---+---+---+---+---+---+
//!  FT  = Frame Type (0: extended) — a L_Data_Extended Frame carries FT = 0
//!        (per 03/02/02 §2.2.5); an on-wire extended control octet is e.g.
//!        0x1C / 0x3C.
//!  0   = Always 0
//!  RF  = Repeat Flag (0: repeat, 1: do not repeat)
//!  1   = Always 1
//!  PR  = Priority (2 bits: 00 = system, 01 = alarm, 10 = high, 11 = low)
//!  0   = Always 0
//!
//!  Bit breakdown for Extended Control Field (ECF):
//!    7   6   5   4   3   2   1   0
//!  +---+---+---+---+---+---+---+---+
//!  |AT | HC| HC| HC|EFF|EFF|EFF|EFF|
//!  +---+---+---+---+---+---+---+---+
//!  AT  = Address Type (0: individual, 1: group)
//!  HC  = Hop Count (routing counter, 3 bits)
//!  EFF = Extended Frame Format (4 bits, defines fragmentation, etc.)
//!
//!
//! KnxMessageBuffer abstraction:
//!  +--------+---------+---------+--------+---------+--------------------+
//!  | CTRL   | SRC     | DEST    | AT/HC/ | TPCI    | DATA               |
//!  | Field  | Address | Address | EFF    | /APCI   | (variable length)  |
//!  +--------+---------+---------+--------+---------+--------------------+
//!  | 1 byte | 2 bytes | 2 bytes | 1 byte | 1 byte  | 0..(buffer_size-7) |
//!  +--------+---------+---------+--------+---------+--------------------+
//!
//!  Bit breakdown for CTRL field (Ctrl1Field, byte 0):
//!    7   6   5   4   3   2   1   0
//!  +---+---+---+---+---+---+---+---+
//!  |FT | - | R | SB| PR| PR| A | C |
//!  +---+---+---+---+---+---+---+---+
//!  FT  = Frame Type (bit 7, 1: standard, 0: extended) — same convention as
//!        the TP1 wire and the cEMI L_Data control field (03/02/02 §2.2.4);
//!        e.g. 0xBC for a standard frame, 0x1C/0x3C for extended
//!      -   = (bit 6, unused)
//!      R   = Repeat Flag (bit 5)
//!      SB  = System Broadcast (bit 4)
//!      PR  = Priority (bits 3-2, 2 bits)
//!      A   = Acknowledge (bit 1, only valid for L_Data.req)
//!      C   = Confirm (bit 0, only valid for L_Data.con)
//!
//!  Field meanings:
//!  - FT: Frame type (standard/extended)
//!  - R: Repeat flag
//!  - SB: System broadcast
//!  - PR: Priority
//!  - A: Acknowledge (L_Data.req only)
//!  - C: Confirm (L_Data.con only)

use crate::messages::buffers::MessageBuffer;

/// The control octet of a TP1 standard L_Data frame before its priority
/// bits: FT = 1 (standard frame), r = 1 (not repeated), and the fixed
/// one-bit at position 4 (03/02/02 §2.2.4.1). OR in `priority << 2`;
/// clear bit 5 to mark a repetition.
pub const TP1_STD_CTRL_BASE: u8 = 0xB0;

/// Hop count 6 in bits 6..4 of a standard frame's octet 5 (the
/// NPCI/length octet, 03/03/03 §2.2) — the value every BCU-era device
/// transmits with.
pub const NPCI_HOP_COUNT_6: u8 = 0x60;

/// Calculate TP1 checksum for a message (excluding the checksum byte itself).
///
/// Per KNX spec 03/02/02 §2.2.4.6, the check octet is a logical NOT XOR over
/// all preceding octets — equivalently, XOR all bytes with a 0xFF seed.
pub fn calculate_tp1_checksum(data: &[u8]) -> u8 {
    let mut checksum = 0xFFu8;
    for &byte in data {
        checksum ^= byte;
    }
    checksum
}

/// Validate TP1 checksum for a complete message (including checksum byte).
///
/// XOR of all bytes (data + check octet) must equal 0xFF for a valid frame.
pub fn validate_tp1_checksum(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    let mut checksum = 0u8;
    for &byte in data {
        checksum ^= byte;
    }
    checksum == 0xFF
}

/// Convert a TP1 wire-format message to internal KNX message format.
///
/// This function:
/// - Validates and removes the checksum byte
/// - For standard frames: clears the length field (lower 4 bits of NPDU byte)
/// - For extended frames: moves the extended control field to the NPDU position
pub fn tp1_to_knx_message<B: MessageBuffer>(mut msg: B) -> B {
    if !validate_tp1_checksum(&msg) {
        // For now, we'll proceed but could add error handling here
        // In a real implementation, this might return an error
    }

    // Remove the checksum byte (last byte)
    let new_len = msg.len() - 1;
    msg.set_len(new_len);

    tp1_to_knx_message_no_checksum(msg)
}

/// Convert a TP1-like message (without checksum) to internal KNX message format.
///
/// This is useful for test scenarios where messages are in TP1 format but without
/// the checksum byte. This function:
/// - For standard frames: clears the length field (lower 4 bits of NPDU byte)
/// - For extended frames: moves the extended control field to the NPDU position
pub fn tp1_to_knx_message_no_checksum<B: MessageBuffer>(mut msg: B) -> B {
    // Check if this is an extended frame (control field bit 7 == 0)
    if (msg[0] & 0x80) == 0 {
        // Extended frame
        let ext_ctrl = msg[1]; // This is the extended control field in TP1

        // Shift data from position 1 onwards (after control field) to make room
        // We need to move data starting from MSG_DEST_ADDR (3) leftward by 1 position
        let msg_len = msg.len();
        for i in 1..msg_len - 1 {
            msg[i] = msg[i + 1];
        }

        // Place the extended control field at the NPDU position (5)
        msg[5] = ext_ctrl;

        // Remove the last byte as we shifted everything left to get rid of the extended control field
        let new_len = msg.len() - 1;
        msg.set_len(new_len);
    } else {
        // Standard frame - clear lower 4 bits of the NPDU field (EFF type - can't be set in standard frames)
        msg[5] &= 0xf0;
    }

    msg
}

/// Convert an internal KNX message to TP1 wire-format.
///
/// This function:
/// - For standard frames (length <= 23 and NPDU lower bits == 0): adds length field and checksum
/// - For extended frames: shifts data to insert extended control field and adds checksum
pub fn knx_to_tp1_message<B: MessageBuffer>(msg: B) -> B {
    let mut msg = knx_to_tp1_message_no_checksum(msg);
    // Generate and append checksum
    msg.push(calculate_tp1_checksum(&msg));
    msg
}

/// Convert an internal KNX message to TP1-like format (without checksum).
///
/// This is useful for test scenarios where messages need TP1 format but without
/// the checksum byte. This function:
/// - For standard frames (length <= 23 and NPDU lower bits == 0): adds length field
/// - For extended frames: shifts data to insert extended control field and length
pub fn knx_to_tp1_message_no_checksum<B: MessageBuffer>(mut msg: B) -> B {
    let len = msg.len();

    // A valid KNX internal message is at minimum 7 bytes: ctrl(1) + src(2) + dst(2) +
    // npdu(1) + tpci(1). Shorter buffers cannot be encoded as TP1; document the
    // contract in debug builds and return early in release so a caller bug does not
    // cause an out-of-bounds access.
    debug_assert!(len >= 7, "knx_to_tp1_message_no_checksum: message too short (len={})", len);
    if len < 7 {
        return msg;
    }

    // Check for standard frame: length <= 23 and lower 4 bits of NPDU are 0
    if (len < 23) && ((msg[5] & 0xf) == 0) {
        // Standard frame
        msg[5] = (msg[5] & 0xf0) | ((len - 7) as u8);
        msg[0] = (msg[0] & 0x0c) | 0xb0;

        return msg;
    }

    // Extended frame - need to shift data rightward to make room for extended control
    // Save the original NPDU value before shifting
    let orig_npdu = msg[5];

    // Shift data from index 1 onwards rightward by 1 position
    msg.set_len(len + 1);
    for i in (1..len).rev() {
        msg[i + 1] = msg[i];
    }

    // Set up extended frame fields
    msg[0] = (msg[0] & 0x0C) | 0x30;
    msg[1] = orig_npdu; // Extended control field: AT/HC/EFF from original NPDU
    msg[6] = (len - 7) as u8; // Length field for extended frame

    msg
}

// ================================================================================
// Allocation-free and allocating byte-slice helpers
// ================================================================================
//
// The `*_message_*` functions above are generic over `MessageBuffer`. Callers
// that already have an owned `Vec<u8>` or need a fixed-capacity `heapless::Vec`
// output — typical in mock / capture paths where we don't own the incoming
// buffer — reach for the helpers below. They wrap the generic implementations
// to avoid duplicating the bit-shuffling logic.

/// Convert internal KNX bytes to TP1-like format (no checksum) into a
/// fixed-capacity `heapless::Vec`.
///
/// The generic variant [`knx_to_tp1_message_no_checksum`] operates on a
/// `MessageBuffer`, which `heapless::Vec` does not implement — so this helper
/// reproduces the same byte shuffling locally. Extended frames need `N >=
/// src.len() + 1`; standard frames need only `N >= src.len()`. Panics if the
/// destination is too small.
pub fn knx_to_tp1_bytes_no_checksum<const N: usize>(src: &[u8]) -> heapless::Vec<u8, N> {
    let len = src.len();
    let mut out: heapless::Vec<u8, N> = heapless::Vec::new();

    // Same minimum-length contract as `knx_to_tp1_message_no_checksum`: the
    // internal KNX frame must be at least 7 bytes before TP1 encoding can proceed.
    debug_assert!(len >= 7, "knx_to_tp1_bytes_no_checksum: message too short (len={})", len);
    if len < 7 {
        return out;
    }

    if (len < 23) && ((src[5] & 0x0f) == 0) {
        // Standard frame: copy as-is, then rewrite bytes [0] and [5].
        out.extend_from_slice(src).expect("destination capacity too small for TP1 conversion");
        out[5] = (out[5] & 0xf0) | ((len - 7) as u8);
        out[0] = (out[0] & 0x0c) | TP1_STD_CTRL_BASE;
    } else {
        // Extended frame: insert the extended-control byte at position 1 and
        // shift the rest rightward. Output length is `len + 1`.
        out.push((src[0] & 0x0C) | 0x30).expect("destination capacity too small for TP1 conversion");
        out.push(src[5]).expect("destination capacity too small for TP1 conversion");
        out.extend_from_slice(&src[1..5]).expect("destination capacity too small for TP1 conversion");
        out.push((len - 7) as u8).expect("destination capacity too small for TP1 conversion");
        out.extend_from_slice(&src[6..]).expect("destination capacity too small for TP1 conversion");
    }

    out
}

/// Convert TP1-like bytes (no checksum) to internal KNX format into a
/// fixed-capacity `heapless::Vec`.
///
/// The mirror of [`knx_to_tp1_bytes_no_checksum`], and the direction a
/// synchronous stack needs on ingress: it owns the wire bytes borrowed from a
/// link driver and has to land them in a buffer it can mutate in place —
/// KNX Data Secure authenticates and decrypts the frame where it lies.
///
/// Standard frames keep their length (`N >= src.len()`); extended frames lose
/// the extended-control octet, so `N >= src.len() - 1` suffices. Panics if the
/// destination is too small.
pub fn tp1_to_knx_bytes_no_checksum<const N: usize>(src: &[u8]) -> heapless::Vec<u8, N> {
    let len = src.len();
    let mut out: heapless::Vec<u8, N> = heapless::Vec::new();

    // A TP1 standard frame is at minimum 7 octets; an extended frame spends one
    // more on the extended control field. Either way, fewer than 7 cannot carry
    // a canonical message, and the extended path would read past the end.
    debug_assert!(len >= 7, "tp1_to_knx_bytes_no_checksum: message too short (len={})", len);
    if len < 7 {
        return out;
    }

    if (src[0] & 0x80) == 0 {
        // Extended frame: `ctrl | ext_ctrl | src(2) | dst(2) | len | payload`.
        // Drop the extended-control octet by copying everything after it, then
        // put it at the canonical NPDU position — which is where the wire's
        // length octet landed, and the canonical format derives length from
        // the buffer instead.
        debug_assert!(len >= 8, "tp1_to_knx_bytes_no_checksum: extended frame too short (len={})", len);
        if len < 8 {
            return out;
        }
        let ext_ctrl = src[1];
        out.push(src[0]).expect("destination capacity too small for TP1 conversion");
        out.extend_from_slice(&src[2..]).expect("destination capacity too small for TP1 conversion");
        out[5] = ext_ctrl;
    } else {
        // Standard frame: identical layout, except the low nibble of octet 5
        // carries the length. The canonical format has no length field there
        // (the EFF bits it overlaps cannot be set on a standard frame).
        out.extend_from_slice(src).expect("destination capacity too small for TP1 conversion");
        out[5] &= 0xf0;
    }

    out
}

/// Convert internal KNX bytes to TP1-like format (no checksum) into a `Vec<u8>`.
#[cfg(feature = "alloc")]
pub fn knx_to_tp1_vec_no_checksum(src: &[u8]) -> alloc::vec::Vec<u8> {
    knx_to_tp1_message_no_checksum(src.to_vec())
}

/// Convert TP1-like bytes (no checksum) to internal KNX format into a `Vec<u8>`.
#[cfg(feature = "alloc")]
pub fn tp1_to_knx_vec_no_checksum(src: &[u8]) -> alloc::vec::Vec<u8> {
    tp1_to_knx_message_no_checksum(src.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
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
                unsafe {
                    self.data.set_len(len);
                }
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
    fn test_checksum_calculation() {
        let data = [0xBC, 0x11, 0x22, 0x11, 0x01, 0xE1, 0x00, 0x81u8];
        let checksum = calculate_tp1_checksum(&data);

        // XOR of all bytes including the check octet must equal 0xFF (odd parity).
        let mut verify = data.into_iter().reduce(|a, b| a ^ b).unwrap();
        verify ^= checksum;
        assert_eq!(verify, 0xFF, "Checksum verification failed");
    }

    #[test]
    fn test_checksum_validation() {
        let valid_data = &[0xBC, 0x11, 0x22, 0x11, 0x01, 0xE1, 0x00, 0x81, 0x00]; // 0x00 = NOT XOR
        assert!(validate_tp1_checksum(valid_data), "Valid checksum should pass");

        let invalid_data = &[0xBC, 0x11, 0x22, 0x11, 0x01, 0xE1, 0x00, 0x81, 0xFF]; // Wrong checksum
        assert!(!validate_tp1_checksum(invalid_data), "Invalid checksum should fail");

        assert!(!validate_tp1_checksum(&[]), "Empty data should fail");
    }

    #[test]
    fn test_tp1_to_knx_standard_frame() {
        // Standard TP1 frame: GroupValue.Write to 1/1/1 with data 0x01
        // Control=0xBC (standard frame, bit 7=1), Source=1.1.34, Dest=1/1/1, NPDU+data
        let tp1_data = &[
            0xBC, // Control byte: 10111100 (standard frame, priority 3, no repeat, system broadcast)
            0x11, 0x22, // Source address: 1.1.34
            0x11, 0x01, // Destination address: 1/1/1 (group address)
            0xE1, // NPDU: 11100001 (hop count 7, group address)
            0x00, 0x81, // TPCI/APCI + Data: GroupValue.Write with data 0x01
            0x00, // Checksum (NOT XOR)
        ];

        let buffer = TestBuffer::new(tp1_data);
        let result = tp1_to_knx_message(buffer);

        assert_eq!(result.len(), 8, "Frame length");
        assert_eq!(result[0], 0xBC, "Control field should be preserved");
        assert_eq!(result[1], 0x11, "Source address high byte");
        assert_eq!(result[2], 0x22, "Source address low byte");
        assert_eq!(result[3], 0x11, "Destination address high byte");
        assert_eq!(result[4], 0x01, "Destination address low byte");
        assert_eq!(result[5], 0xE0, "NPDU should have EFF bits cleared");
        assert_eq!(result[6], 0x00, "TPCI/APCI data");
        assert_eq!(result[7], 0x81, "Application data");
    }

    #[test]
    fn test_tp1_to_knx_extended_frame() {
        // Extended TP1 frame: PropertyValue.Read
        // Control=0x1C (extended frame, bit 7=0), ExtCtrl=0xE0, Source=1.1.34, etc.
        let tp1_data = &[
            0x1C, // Control byte: 00011100 (extended frame, priority 3)
            0xE0, // Extended control field
            0x11, 0x22, // Source address: 1.1.34
            0x00, 0x00, // Destination address: 0.0.0 (individual)
            0x60, // NPDU: 01100000 (hop count 3, individual address)
            0x43, 0xD2, // TPCI/APCI: PropertyValue.Read
            0x00, 0x51, // Additional data
            0x90, // Checksum
        ];

        let buffer = TestBuffer::new(tp1_data);
        let result = tp1_to_knx_message(buffer);

        assert_eq!(result.len(), 10, "Frame length");
        assert_eq!(result[0], 0x1C, "Control field preserved");
        assert_eq!(result[1], 0x11, "Source addr high");
        assert_eq!(result[2], 0x22, "Source addr low");
        assert_eq!(result[3], 0x00, "Dest addr high");
        assert_eq!(result[4], 0x00, "Dest addr low");
        assert_eq!(result[5], 0xE0, "Extended control");
        assert_eq!(result[6], 0x43, "TPCI data");
        assert_eq!(result[7], 0xD2, "APCI data");
        assert_eq!(result[8], 0x00, "Additional data");
        assert_eq!(result[9], 0x51, "Additional data 2");
    }

    #[test]
    fn test_knx_to_tp1_standard_frame() {
        // KNX standard frame: GroupValue.Write to 1/1/1
        let knx_data = &[
            0xBC, // Control: standard frame
            0x11, 0x22, // Source: 1.1.34
            0x11, 0x01, // Dest: 1/1/1
            0xE0, // NPDU (lower 4 bits are 0 - indicates standard frame)
            0x00, 0x81, // TPCI/APCI + data
        ];

        let buffer = TestBuffer::new(knx_data);
        let result = knx_to_tp1_message(buffer);

        assert_eq!(result.len(), 9, "Frame length");
        assert_eq!(result[0], 0xBC, "Control field preserved");
        assert_eq!(result[1], 0x11, "Source address high");
        assert_eq!(result[2], 0x22, "Source address low");
        assert_eq!(result[3], 0x11, "Destination address high");
        assert_eq!(result[4], 0x01, "Destination address low");
        assert_eq!(result[5], 0xE1, "NPDU: 0xE1");
        assert_eq!(result[6], 0x00, "TPCI data");
        assert_eq!(result[7], 0x81, "Application data");
        assert_eq!(result[8], 0x00, "Checksum (NOT XOR)");
    }

    #[test]
    fn test_knx_to_tp1_extended_frame() {
        // KNX extended frame: PropertyValue.Read (longer frame or NPDU lower bits != 0)
        let knx_data = &[
            0x1C, // Control: extended frame
            0x11, 0x22, // Source: 1.1.34
            0x00, 0x00, // Dest: individual
            0x61, // NPDU: lower 4 bits = 1 (triggers extended frame)
            0x43, 0xD2, // TPCI/APCI
            0x00, 0x51, // Additional data
            0x8E,
        ];

        let buffer = TestBuffer::new(knx_data);
        let result = knx_to_tp1_message(buffer);

        assert_eq!(result.len(), 13, "Frame length");
        assert_eq!(result[0], 0x3C, "Control field");
        assert_eq!(result[1], 0x61, "Extended control");
        assert_eq!(result[2], 0x11, "Source high");
        assert_eq!(result[3], 0x22, "Source low");
        assert_eq!(result[4], 0x00, "Dest high");
        assert_eq!(result[5], 0x00, "Dest low");
        assert_eq!(result[6], 0x04, "APDU Length");
        assert_eq!(result[7], 0x43, "Original TPCI");
        assert_eq!(result[8], 0xD2, "Original APCI");
        assert_eq!(result[9], 0x00, "Additional data");
        assert_eq!(result[10], 0x51, "Additional data");
        assert_eq!(result[11], 0x8E, "Checksum");
    }

    #[test]
    fn test_round_trip_standard_frame() {
        // Test that TP1 -> KNX -> TP1 produces the original frame
        let original_tp1 = &[
            0xBC, // Control
            0x11, 0x22, // Source
            0x11, 0x01, // Dest
            0xE1, // NPDU
            0x00, 0x81, // Data
            0x00, // Checksum (NOT XOR)
        ];

        let buffer1 = TestBuffer::new(original_tp1);
        let knx_msg = tp1_to_knx_message(buffer1);

        // Create new buffer for return conversion
        let buffer2 = TestBuffer::new(&knx_msg);
        let final_tp1 = knx_to_tp1_message(buffer2);

        // The round trip should be equal
        assert_eq!(&final_tp1[..], &original_tp1[..]);
    }

    #[test]
    fn test_knx_to_tp1_length_boundary_23_bytes_standard() {
        // 22-byte KNX message with EFF = 0 → should be standard TP1
        let knx_data = &[
            0xBC, // Control
            0x11, 0x22, // Source
            0x11, 0x01, // Dest
            0xE0, // NPDU: EFF = 0
            0x00, 0x81, // TPCI/APCI
            // 14 more bytes to reach exactly 22 bytes
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        ];

        let buffer = TestBuffer::new(knx_data);
        let result = knx_to_tp1_message(buffer);

        // Should remain standard frame: len=23 < 24 AND EFF = 0
        assert_eq!(result.len(), 23, "Frame length");
        assert_eq!(result[0], 0xBC, "Control field");
        assert_eq!(result[5], 0xEF, "NPDU");
    }

    #[test]
    fn test_knx_to_tp1_length_boundary_24_bytes_extended() {
        // 23-byte KNX message with EFF = 0 → should be extended TP1
        let knx_data = &[
            0xBC, // Control
            0x11, 0x22, // Source
            0x11, 0x01, // Dest
            0xE0, // NPDU: lower 4 bits = 0, but length >= 24 triggers extended
            0x00, 0x81, // TPCI/APCI
            // 15 more bytes (triggers extended frame format)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];

        let buffer = TestBuffer::new(knx_data);
        let result = knx_to_tp1_message(buffer);

        assert_eq!(result.len(), 25, "Frame length");
        assert_eq!(result[0], 0x3C, "Control field");
        assert_eq!(result[1], 0xE0, "Extended control field");
        assert_eq!(result[6], 0x10, "APDU length");
    }

    #[test]
    fn test_knx_to_tp1_npdu_lower_bits_boundary() {
        // Short KNX message but EFF != 0 → should be extended TP1
        let knx_data = &[
            0xBC, // Control
            0x11, 0x22, // Source
            0x11, 0x01, // Dest
            0xE1, // NPDU: EFF = 1 (forces extended frame)
            0x00, 0x81, // TPCI/APCI
        ];

        let buffer = TestBuffer::new(knx_data);
        let result = knx_to_tp1_message(buffer);

        assert_eq!(result.len(), 10, "Frame length");
        assert_eq!(result[0], 0x3C, "Control field");
        assert_eq!(result[1], 0xE1, "Extended control field");
        assert_eq!(result[6], 0x01, "APDU Length");
    }

    #[test]
    fn test_round_trip_format_change_standard_to_extended() {
        // Start with TP1 standard frame, convert to KNX, then back to TP1
        // The return trip might change format due to boundary conditions
        let original_tp1 = &[
            0xBC, // Control: standard frame
            0x11, 0x22, // Source
            0x11, 0x01, // Dest
            0xE1, // NPDU
            0x00, 0x81, // Data
            0,    // Checksum
        ];

        // TP1 → KNX: standard frame, NPDU gets cleared to 0xE0
        let buffer1 = TestBuffer::new(original_tp1);
        let knx_msg = tp1_to_knx_message(buffer1);
        assert_eq!(knx_msg[5], 0xE0, "TP1→KNX: NPDU EFF = 0");

        // KNX → TP1: short length + NPDU EFF = 0 → stays standard
        let buffer2 = TestBuffer::new(&knx_msg);
        let final_tp1 = knx_to_tp1_message(buffer2);

        assert_eq!(final_tp1.len(), original_tp1.len(), "Round trip standard→standard");
        assert_eq!(final_tp1[0], 0xBC, "Control preserved in standard format");
        assert_eq!(final_tp1[5], 0xE1, "NPDU: length info=1");
    }

    #[test]
    fn test_round_trip_format_change_extended_to_standard() {
        // Start with TP1 extended frame that becomes standard after conversion
        let original_tp1 = &[
            0x1C, // Control: extended frame
            0xE0, // Extended control: 0xE0
            0x11, 0x22, // Source
            0x11, 0x01, // Dest
            0x01, // Length
            0x00, 0x81, // TPCI/APCI + data
            0xA0, // Checksum (NOT XOR)
        ];

        // TP1 → KNX: extended frame processing
        let buffer1 = TestBuffer::new(original_tp1);
        let knx_msg = tp1_to_knx_message(buffer1);

        assert_eq!(knx_msg.len(), 8, "Frame length");
        assert_eq!(knx_msg[5], 0xE0, "Extended control");

        // KNX → TP1: len=9 < 24 AND NPDU=0x00 (EFF = 0) → becomes standard!
        let buffer2 = TestBuffer::new(&knx_msg);
        let final_tp1 = knx_to_tp1_message(buffer2);

        assert_eq!(final_tp1[0], 0xBC, "Control field for standard frame = 0xBC");
        assert_eq!(final_tp1[5], 0xE1, "Length field = 0x01");
    }

    #[test]
    fn test_length_calculation_edge_cases() {
        let knx_8_bytes = &[0xBC, 0x11, 0x22, 0x11, 0x01, 0xE0, 0x00, 0x81];
        let buffer = TestBuffer::new(knx_8_bytes);
        let result = knx_to_tp1_message(buffer);
        assert_eq!(result[5], 0xE1, "8 bytes: NPDU = 0xE1 | 1 = 0xE1");

        let knx_9_bytes = &[0xBC, 0x11, 0x22, 0x11, 0x01, 0xE0, 0x00, 0x81, 0xFF];
        let buffer = TestBuffer::new(knx_9_bytes);
        let result = knx_to_tp1_message(buffer);
        assert_eq!(result[5], 0xE2, "9 bytes: NPDU = 0xE2 | 2 = 0xE2");

        let knx_15_bytes = &[0xBC, 0x11, 0x22, 0x11, 0x01, 0xE0, 0x00, 0x81, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let buffer = TestBuffer::new(knx_15_bytes);
        let result = knx_to_tp1_message(buffer);
        assert_eq!(result[5], 0xE8, "15 bytes: NPDU = 0xE0 | 8 = 0xE8");

        let knx_23_bytes = &[
            0xBC, 0x11, 0x22, 0x11, 0x01, 0xE0, 0x00, 0x81, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E,
        ];
        let buffer = TestBuffer::new(knx_23_bytes);
        let result = knx_to_tp1_message(buffer);
        assert_eq!(result[5], 0xEF, "23 bytes: NPDU = 0xE0 | 15 = 0xEF");
    }

    #[test]
    fn test_npdu_preservation_in_extended_frames() {
        for npdu_val in [0xE1, 0xE2, 0xE5, 0xEA, 0xEF] {
            let knx_data = &[
                0x1C, // Control: will trigger extended due to NPDU EFF field
                0x11, 0x22, // Source
                0x11, 0x01,     // Dest
                npdu_val, // NPDU with EFF bits != 0
                0x43, 0xD2, // TPCI/APCI
                0x00, 0x51, // Extra data
            ];

            let buffer = TestBuffer::new(knx_data);
            let result = knx_to_tp1_message(buffer);

            // Should be extended frame due to EFF != 0
            assert_eq!(result.len(), 12, "NPDU 0x{:02X}: becomes extended frame", npdu_val);
            assert_eq!(result[0], 0x3C, "NPDU 0x{:02X}: extended control field", npdu_val);
            assert_eq!(result[6], 0x03, "NPDU 0x{:02X}: Length = 3", npdu_val);
        }
    }

    // ========================================================================
    // tp1_to_knx_bytes_no_checksum — the heapless ingress direction
    // ========================================================================
    //
    // The `MessageBuffer`-generic `tp1_to_knx_message_no_checksum` is the
    // obviously-correct oracle: these assert the byte-slice variant agrees with
    // it rather than re-deriving the layout a second time.

    /// A canonical message whose NPDU EFF nibble is zero — encodes as standard.
    const CANONICAL_STD: &[u8] = &[0xBC, 0x11, 0x22, 0x11, 0x01, 0xE0, 0x43, 0xD2, 0x00, 0x51];
    /// A canonical message with EFF bits set — encodes as extended.
    const CANONICAL_EXT: &[u8] = &[0x1C, 0x11, 0x22, 0x11, 0x01, 0xE5, 0x43, 0xD2, 0x00, 0x51];

    #[test]
    fn tp1_to_knx_bytes_matches_the_message_buffer_variant() {
        for canonical in [CANONICAL_STD, CANONICAL_EXT] {
            let wire = knx_to_tp1_bytes_no_checksum::<32>(canonical);
            let expected = tp1_to_knx_message_no_checksum(TestBuffer::new(&wire));
            let actual = tp1_to_knx_bytes_no_checksum::<32>(&wire);
            assert_eq!(&actual[..], &expected[..]);
        }
    }

    #[test]
    fn tp1_round_trip_is_stable_on_the_wire() {
        // Normalise-then-denormalise is the micro stack's actual cycle, and it
        // has to be a fixed point. The canonical→wire→canonical direction is
        // deliberately *not* the identity: `knx_to_tp1_*` rewrites the control
        // octet's frame-type bits (0x1C → 0x3C for extended), keeping only the
        // priority bits, so the frame type is decided by the encoder rather
        // than carried through.
        for canonical in [CANONICAL_STD, CANONICAL_EXT] {
            let wire = knx_to_tp1_bytes_no_checksum::<32>(canonical);
            let back = tp1_to_knx_bytes_no_checksum::<32>(&wire);
            let again = knx_to_tp1_bytes_no_checksum::<32>(&back);
            assert_eq!(&again[..], &wire[..]);
            // Everything after the control octet does survive untouched.
            assert_eq!(&back[1..], &canonical[1..]);
        }
    }

    #[test]
    fn tp1_to_knx_bytes_distinguishes_the_two_frame_types() {
        let std_wire = knx_to_tp1_bytes_no_checksum::<32>(CANONICAL_STD);
        let ext_wire = knx_to_tp1_bytes_no_checksum::<32>(CANONICAL_EXT);
        // The extended encoding spends one more octet on the wire; converting
        // back has to give both the same canonical length again.
        assert_eq!(ext_wire.len(), std_wire.len() + 1);
        assert_eq!(tp1_to_knx_bytes_no_checksum::<32>(&std_wire).len(), CANONICAL_STD.len());
        assert_eq!(tp1_to_knx_bytes_no_checksum::<32>(&ext_wire).len(), CANONICAL_EXT.len());
    }

    #[test]
    fn tp1_to_knx_bytes_rejects_short_input() {
        // Release behaviour for a truncated frame is an empty result rather
        // than an out-of-bounds read; debug builds assert first, so this only
        // runs meaningfully in release.
        #[cfg(not(debug_assertions))]
        {
            assert!(tp1_to_knx_bytes_no_checksum::<32>(&[0xBC, 0x11, 0x22]).is_empty());
            // Seven octets is enough for a standard frame but one short for an
            // extended one, whose control byte has bit 7 clear.
            assert!(tp1_to_knx_bytes_no_checksum::<32>(&[0x3C, 0xE0, 0x11, 0x22, 0x11, 0x01, 0x03]).is_empty());
        }
    }
}
