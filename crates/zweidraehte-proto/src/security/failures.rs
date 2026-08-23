//! Security failure categories and the failures log (03/05/01 §6.3.9).
//!
//! The log is what `PID_SECURITY_FAILURES_LOG` (55) serves: four saturating
//! 16-bit counters plus a ring buffer of the eight most recent failures. It is
//! plain data with no I/O — a device persists it through whatever config store
//! it owns, because §6.3.9.2 requires the log saved at power-down and restored
//! at power-up.

use serde::{Deserialize, Serialize};

/// Security failure type indices per KNX spec.
///
/// The failures log maintains the four fields from 03/05/01 Figure 77:
/// reserved, sequence-number, cryptographic, and access/roles. Error Type
/// encodings are a different numbering (02h, 03h, 04h), so neither the enum
/// discriminant nor the counter index is a wire representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// `#[non_exhaustive]`: downstream crates stay insulated from new variants,
/// while in-crate exhaustiveness checking is preserved.
#[non_exhaustive]
pub enum SecurityFailureType {
    /// Invalid SCF field (unsupported algorithm, reserved bits set).
    ScfError = 0,
    /// MAC verification failed (wrong key or tampered message).
    CryptoError = 1,
    /// Sequence number check failed (replay or out-of-order).
    SeqNrError = 2,
    /// Sender not found in Security Individual Address Table.
    RoleError = 3,
    /// Access denied by access policy after successful verification.
    AccessError = 4,
}

impl SecurityFailureType {
    /// Map a failure type to its Figure 77 counter index.
    fn counter_index(self) -> Option<usize> {
        match self {
            // The first field is reserved and shall remain zero. Invalid SCF
            // has no standardized counter in this version of the resource.
            Self::ScfError => None,
            Self::SeqNrError => Some(1),
            Self::CryptoError => Some(2),
            Self::RoleError | Self::AccessError => Some(3),
        }
    }

    /// Error Type stored in the latest-failure record (Figure 78).
    fn error_type(self) -> u8 {
        match self {
            // 01h is reserved for Invalid SCF and is not otherwise used.
            Self::ScfError => 0x01,
            Self::SeqNrError => 0x02,
            Self::CryptoError => 0x03,
            Self::RoleError | Self::AccessError => 0x04,
        }
    }
}

/// A single failure log entry recording a security event.
///
/// Each entry stores the source address of the offending device, the first
/// 9 bytes of the offending frame (for diagnostic purposes), and the
/// failure type code (see [`SecurityFailureType`]).
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct SecurityFailureEntry {
    /// Source individual address of the offending message.
    pub source_addr: u16,
    /// First 9 bytes of the offending frame (zero-padded if shorter).
    pub frame_fragment: [u8; 9],
    /// Standardized Error Type code from Figure 78.
    pub failure_type: u8,
}

/// Security failures log with 4 × 16-bit counters and a ring buffer
/// of recent failure entries.
///
/// Accessed via Function Property on PID 55:
/// - **StateRead(id=0, info=0)**: Returns 4 × 2-byte BE counters (8 bytes).
/// - **StateRead(id=1, info=N)**: Returns the Nth most recent 12-byte entry.
/// - **Command(id=0, info=0)**: Clears all counters and entries.
///
/// Counter layout (4 counters, each 16-bit big-endian):
/// - \[0\] reserved (always zero)
/// - \[1\] sequence-number errors
/// - \[2\] cryptographic errors
/// - \[3\] access + role errors
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SecurityFailuresLog {
    /// 4 × 16-bit failure counters (saturating at 0xFFFF).
    counters: [u16; 4],
    /// Ring buffer of recent failure entries.
    entries: [SecurityFailureEntry; 8],
    /// Write index into the ring buffer.
    write_idx: u8,
    /// Number of entries stored (capped at 8).
    count: u8,
}

impl SecurityFailuresLog {
    /// Record a security failure.
    ///
    /// `frame_fragment` should be the first 9 bytes of the offending
    /// secure frame (zero-padded if shorter). These are stored in the
    /// entry for diagnostic purposes.
    pub fn log_failure(&mut self, failure_type: SecurityFailureType, source_addr: u16, frame_fragment: &[u8]) {
        // Increment the 16-bit counter for this failure type (saturating).
        if let Some(idx) = failure_type.counter_index() {
            self.counters[idx] = self.counters[idx].saturating_add(1);
        }

        // Build the 9-byte fragment (zero-padded if input is shorter).
        let mut frag = [0u8; 9];
        let copy_len = frame_fragment.len().min(9);
        frag[..copy_len].copy_from_slice(&frame_fragment[..copy_len]);

        // Add to ring buffer.
        let entry = SecurityFailureEntry { source_addr, frame_fragment: frag, failure_type: failure_type.error_type() };
        self.entries[self.write_idx as usize] = entry;
        self.write_idx = (self.write_idx + 1) % 8;
        if self.count < 8 {
            self.count += 1;
        }
    }

    /// Get the 4 × 16-bit failure counters.
    pub fn counters(&self) -> &[u16; 4] {
        &self.counters
    }

    /// Serialize counters as 8 bytes (4 × big-endian u16).
    pub fn counters_as_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        for (i, &c) in self.counters.iter().enumerate() {
            buf[i * 2..i * 2 + 2].copy_from_slice(&c.to_be_bytes());
        }
        buf
    }

    /// Get a failure entry by reverse index (0 = most recent).
    pub fn get_by_index(&self, index: u8) -> Option<&SecurityFailureEntry> {
        if index >= self.count {
            return None;
        }
        // Most recent is at (write_idx - 1), second most recent at (write_idx - 2), etc.
        let actual = (self.write_idx as i16 - 1 - index as i16).rem_euclid(8) as usize;
        Some(&self.entries[actual])
    }

    /// Clear all counters and entries.
    pub fn clear(&mut self) {
        self.counters = [0; 4];
        self.count = 0;
        self.write_idx = 0;
    }

    /// Overwrite the four 16-bit counters directly. Used by the
    /// manufacturer-specific test PID (203) so the conformance suite can
    /// set them to a known value (typically FFFFh) before provoking
    /// errors to verify the saturating-add behaviour of `log_failure`.
    pub fn set_counters(&mut self, counters: [u16; 4]) {
        self.counters = counters;
    }
}
