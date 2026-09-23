//! Security failure categories and the failures log (03/05/01 §6.3.9).
//!
//! The log is what `PID_SECURITY_FAILURES_LOG` (55) serves: one reserved field,
//! three saturating 16-bit counters and the eight most recent failures. It is
//! plain data with no I/O — a device persists it through whatever config store
//! it owns, because §6.3.9.2 requires the log saved at power-down and restored
//! at power-up.

use serde::{Deserialize, Serialize};

use crate::crypto::scf::{SecureServiceType, SecurityControlField};
use crate::messages::apdu::secure;

/// Security failure type indices per KNX spec.
///
/// The failures log maintains the four fields from 03/05/01 Figure 77:
/// reserved, sequence-number, cryptographic, and access/roles. Error Type
/// encodings are a different numbering (02h, 03h, 04h), so neither the enum
/// discriminant nor the counter index is a wire representation.
/// Invalid SCF has no variant: 03/03/07 requires a silent drop and Figure 78
/// reserves error type 01h rather than permitting it as a failure record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// `#[non_exhaustive]`: downstream crates stay insulated from new variants,
/// while in-crate exhaustiveness checking is preserved.
#[non_exhaustive]
pub enum SecurityFailureType {
    /// Invalid secure length or MAC verification failure.
    CryptoError = 1,
    /// Sequence number check failed (replay or out-of-order).
    SeqNrError = 2,
    /// Access denied because required roles are missing.
    RoleError = 3,
    /// Access denied by access policy after successful verification.
    AccessError = 4,
}

impl SecurityFailureType {
    /// Map a failure type to its Figure 77 counter index.
    fn counter_index(self) -> usize {
        match self {
            Self::SeqNrError => 1,
            Self::CryptoError => 2,
            Self::RoleError | Self::AccessError => 3,
        }
    }

    /// Error Type stored in the latest-failure record (Figure 78).
    fn error_type(self) -> u8 {
        match self {
            Self::SeqNrError => 0x02,
            Self::CryptoError => 0x03,
            Self::RoleError | Self::AccessError => 0x04,
        }
    }
}

/// A single failure log entry recording a security event.
///
/// Figure 78 stores the sender's address and sequence number, with three
/// unused octets between them, followed by the failure type code.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct SecurityFailureEntry {
    /// Source individual address of the offending message.
    pub source_addr: u16,
    /// Three unused zero octets followed by the sender's six-octet sequence.
    /// The legacy field name and storage layout are retained for snapshots.
    pub frame_fragment: [u8; 9],
    /// Standardized Error Type code from Figure 78.
    pub failure_type: u8,
}

/// Security failures log with four 16-bit fields and a ring buffer
/// of recent failure entries.
///
/// Accessed via Function Property on PID 55:
/// - **StateRead(id=0, info=0)**: Returns the reserved field and three counters (8 bytes).
/// - **StateRead(id=1, info=N)**: Returns the Nth most recent 12-byte entry.
/// - **Command(id=0, info=0)**: Clears all counters and entries.
///
/// Counter layout (four fields, each 16-bit big-endian):
/// - \[0\] reserved (always zero)
/// - \[1\] sequence-number errors
/// - \[2\] cryptographic errors
/// - \[3\] access + role errors
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SecurityFailuresLog {
    /// Reserved zero followed by three saturating 16-bit failure counters.
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
    /// `frame` is the offending frame in internal KNX format, before removing
    /// the secure envelope. Missing sequence fields are recorded as zero.
    /// Access/role failures may pass an empty slice: Figure 78 explicitly
    /// leaves their sequence field uninterpreted, including for plain access.
    pub fn log_failure(&mut self, failure_type: SecurityFailureType, source_addr: u16, frame: &[u8]) {
        // Increment the 16-bit counter for this failure type (saturating).
        let idx = failure_type.counter_index();
        self.counters[idx] = self.counters[idx].saturating_add(1);

        // Figure 78 is not a raw header capture. Keep its unused octets zero
        // and retain the sequence even when a truncated frame has no MAC.
        // SyncRes has Challenge XOR Random here, not a sender sequence.
        let mut frag = [0u8; 9];
        if !matches!(failure_type, SecurityFailureType::AccessError | SecurityFailureType::RoleError)
            && let Some(&scf) = frame.get(secure::SCF)
            && let Ok(scf) = SecurityControlField::parse(scf)
            && matches!(scf.service, SecureServiceType::Data | SecureServiceType::SyncRequest)
            && let Some(sequence) = frame.get(secure::SEQ_NR..secure::SEQ_NR + 6)
        {
            frag[3..].copy_from_slice(sequence);
        }

        // Add to ring buffer.
        let entry = SecurityFailureEntry { source_addr, frame_fragment: frag, failure_type: failure_type.error_type() };
        self.entries[self.write_idx as usize] = entry;
        self.write_idx = (self.write_idx + 1) % 8;
        if self.count < 8 {
            self.count += 1;
        }
    }

    /// Get the reserved field followed by the three failure counters.
    pub fn counters(&self) -> &[u16; 4] {
        &self.counters
    }

    /// Serialize the reserved field and counters as 8 bytes (4 × big-endian u16).
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

    /// Set counters from the four-field wire layout, keeping reserved zero.
    ///
    /// The first input field is ignored. The manufacturer-specific test PID
    /// (203) uses this to preload counters (typically FFFFh) before provoking
    /// errors to verify the saturating-add behaviour of `log_failure`.
    pub fn set_counters(&mut self, counters: [u16; 4]) {
        self.counters = [0, counters[1], counters[2], counters[3]];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_layout_and_error_codes_follow_figures_77_and_78() {
        let mut log = SecurityFailuresLog::default();
        log.set_counters([0, 0x0100, 0x0200, 0x0300]);

        // Distinct values expose swapped fields, unlike the all-one pattern
        // used by the vendor's general failure-log procedure.
        for (failure, error_type) in [
            (SecurityFailureType::SeqNrError, 0x02),
            (SecurityFailureType::CryptoError, 0x03),
            (SecurityFailureType::CryptoError, 0x03),
            (SecurityFailureType::RoleError, 0x04),
            (SecurityFailureType::AccessError, 0x04),
        ] {
            log.log_failure(failure, 0x1101, &[]);
            assert_eq!(log.get_by_index(0).expect("just logged").failure_type, error_type);
        }

        assert_eq!(log.counters_as_bytes(), [0, 0, 1, 1, 2, 2, 3, 2]);
    }

    #[test]
    fn saturated_counters_do_not_wrap_and_reserved_stays_zero() {
        let mut log = SecurityFailuresLog::default();
        // The manufacturer test PID receives four FFFFh fields from EITT.
        log.set_counters([u16::MAX; 4]);
        assert_eq!(*log.counters(), [0, u16::MAX, u16::MAX, u16::MAX]);

        for failure in
            [SecurityFailureType::SeqNrError, SecurityFailureType::CryptoError, SecurityFailureType::AccessError]
        {
            log.log_failure(failure, 0x1101, &[]);
        }

        assert_eq!(log.counters_as_bytes(), [0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }
}
