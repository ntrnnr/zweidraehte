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
/// The failures log maintains 4 × 16-bit counters. Types 0–2 each map
/// to their own counter; types 3 and 4 both increment counter 3 (the
/// "access & role" counter). The type value is also stored in the per-entry
/// ring buffer so that individual failures can be distinguished.
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
    /// Map a failure type to its counter index (0–3).
    ///
    /// Types 0–2 map 1:1 to their respective counters. Types 3 (Role)
    /// and 4 (Access) both map to counter 3.
    fn counter_index(self) -> Option<usize> {
        match self as u8 {
            0..=2 => Some(self as usize),
            3 | 4 => Some(3),
            _ => None,
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
    /// Failure type code (discriminant of [`SecurityFailureType`]).
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
/// - \[0\] SCF errors (type 0)
/// - \[1\] Crypto/MAC errors (type 1)
/// - \[2\] Sequence number errors (type 2)
/// - \[3\] Access + Role errors (types 3 and 4)
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
        let entry = SecurityFailureEntry { source_addr, frame_fragment: frag, failure_type: failure_type as u8 };
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
