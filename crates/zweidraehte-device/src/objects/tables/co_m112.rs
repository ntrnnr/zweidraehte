//! Group object table in the System 7 (BIM M112) memory format.
//!
//! The spec assigns the System 7 masks no group-object-table
//! realisation — the 2705h mask document (06_01_33 §4.7.1) literally
//! says "Realisation Type ?", and the ETS master data locates the
//! `GroupObjectTable` resource for `MV-0705` with
//! `AddressSpace="None"`: the table has no device-side location
//! resource at all. Its address comes from the product database's
//! `ComObjectTable` segment binding, and its bytes are written by
//! ETS's own System 7 formatter. Both make ETS the normative source
//! for the format, which is (decoded byte-exactly from a download
//! trace, 2026-08-03):
//!
//! ```text
//! [count:1][RAM-flags table ptr:2][count × entry]
//! entry: [data ptr:2][config:1][type:1]
//! ```
//!
//! The entry index is the product database's ComObject Number — our
//! wire ASAP — and `count` covers indices `0..=max`. System 7 products
//! number from 0, so entry 0 is the first object; a device whose
//! numbering starts at 1 (the EITT conformance DUT, whose ASAPs the
//! vendor templates pin) simply leaves entry 0 zeroed. The config
//! octet is bit-identical to
//! [`ComObjectFlags`] and the type octet to the 0-based
//! [`ComObjectType`] coding.
//!
//! The RAM-flags table pointer and the per-entry data pointers are
//! wire-compat only: on real silicon they point the firmware at the
//! object values and communication flags in RAM, while this stack
//! keeps that runtime state in the device's `ComObjects` struct. They
//! are stored verbatim and never dereferenced.

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::{
    AbsoluteAlloc, ComObjectFlags, ComObjectTableEntry, ComObjectType, CommunicationObjectTable, Table, TableMemory,
};

/// Byte offset of the first entry (count + RAM-flags pointer).
const HEADER_LEN: usize = 3;
/// Byte size of one entry.
const ENTRY_LEN: usize = 4;

#[serde_as]
#[derive(Debug, Clone, ConstDefault, Serialize, Deserialize)]
pub struct CoTabM112Impl<const N: usize> {
    #[serde_as(as = "[_; N]")]
    data: [u8; N],
}

impl<const N: usize> TableMemory for CoTabM112Impl<N> {
    const MAX_SIZE: usize = N;
    fn data_ref(&self) -> &[u8] {
        &self.data
    }
    fn data_ref_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> Table<CoTabM112Impl<N>, AbsoluteAlloc> {
    /// Byte offset of entry `idx`, or `None` past the stored count or
    /// the physical capacity.
    fn entry_offset(&self, idx: u16) -> Option<usize> {
        // The count is bus-downloaded data and must not exceed the
        // physical capacity.
        let count = (self.table.data[0] as usize).min((N - HEADER_LEN) / ENTRY_LEN);
        let idx = idx as usize;
        if idx >= count {
            return None;
        }
        Some(HEADER_LEN + idx * ENTRY_LEN)
    }
}

impl<const N: usize> CommunicationObjectTable for Table<CoTabM112Impl<N>, AbsoluteAlloc> {
    fn max_entries(&self) -> usize {
        (N - HEADER_LEN) / ENTRY_LEN
    }

    fn entry_count(&self) -> u16 {
        (self.table.data[0] as u16).min(self.max_entries() as u16)
    }

    fn object(&self, idx: u16) -> Option<ComObjectTableEntry> {
        let off = self.entry_offset(idx)?;
        Some(ComObjectTableEntry {
            object_type: ComObjectType::from(self.table.data[off + 3]),
            flags: ComObjectFlags(self.table.data[off + 2]),
        })
    }

    fn object_type(&self, idx: u16) -> Option<ComObjectType> {
        self.object(idx).map(|e| e.object_type)
    }

    fn object_flags(&self, idx: u16) -> Option<ComObjectFlags> {
        self.object(idx).map(|e| e.flags)
    }

    fn set_object_flags(&mut self, idx: u16, flags: ComObjectFlags) -> bool {
        let Some(off) = self.entry_offset(idx) else {
            return false;
        };
        self.table.data[off + 2] = flags.0;
        true
    }
}

/// The M112 group object table sized for ASAPs `0..=MAX_ASAP`.
pub type CoTabM112<const MAX_ASAP: usize> = Table<CoTabM112Impl<{ 3 + (MAX_ASAP + 1) * 4 }>, AbsoluteAlloc>;

#[cfg(test)]
mod test {
    use crate::objects::tables::{ComObjectFlags, ComObjectType, CommunicationObjectTable, TableMemory};

    use super::CoTabM112;

    /// The exact bytes ETS's System 7 formatter wrote for the
    /// six-object light switch (download trace 2026-08-03): count 7
    /// (ASAPs 0-6, entry 0 unused), zero RAM-flags and data pointers,
    /// configs 47/D7/47/43/D3/00, and ASAP 3 carrying type 03 (Uint4).
    const ETS_BLOB: [u8; 31] = [
        0x07, 0x00, 0x00, // count, RAM-flags ptr
        0x00, 0x00, 0x00, 0x00, // ASAP 0 (unused)
        0x00, 0x00, 0x47, 0x00, // ASAP 1
        0x00, 0x00, 0xD7, 0x00, // ASAP 2
        0x00, 0x00, 0x47, 0x03, // ASAP 3
        0x00, 0x00, 0x43, 0x00, // ASAP 4
        0x00, 0x00, 0xD3, 0x00, // ASAP 5
        0x00, 0x00, 0x00, 0x00, // ASAP 6
    ];

    #[test]
    fn m112_parses_the_ets_blob() {
        let mut cot = CoTabM112::<6>::new();
        cot.write(0, &ETS_BLOB);

        assert_eq!(cot.entry_count(), 7);
        assert_eq!(cot.object_flags(1), Some(ComObjectFlags(0x47)));
        assert_eq!(cot.object_flags(2), Some(ComObjectFlags(0xD7)));
        assert_eq!(cot.object_type(3), Some(ComObjectType::Uint4));
        assert_eq!(cot.object_flags(5), Some(ComObjectFlags(0xD3)));
        assert_eq!(cot.object_type(1), Some(ComObjectType::Uint1));
        assert_eq!(cot.object_flags(7), None, "past the stored count");
    }

    #[test]
    fn m112_set_object_flags_round_trips() {
        let mut cot = CoTabM112::<6>::new();
        cot.write(0, &ETS_BLOB);

        assert!(cot.set_object_flags(1, ComObjectFlags(0x5F)));
        assert_eq!(cot.object_flags(1), Some(ComObjectFlags(0x5F)));
        // The type octet next door is untouched.
        assert_eq!(cot.object_type(1), Some(ComObjectType::Uint1));
        assert!(!cot.set_object_flags(7, ComObjectFlags(0)), "past the stored count");
    }

    /// A corrupt count larger than the physical capacity must be
    /// clamped, not index past the buffer.
    #[test]
    fn m112_count_is_clamped() {
        let mut cot = CoTabM112::<6>::new();
        cot.write(0, &[0xFF]);
        assert_eq!(cot.entry_count(), 7);
        assert_eq!(cot.object_flags(7), None);
    }
}
