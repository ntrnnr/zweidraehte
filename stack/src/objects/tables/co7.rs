use const_default::ConstDefault;
use zerocopy::big_endian::U16;

use super::{MemoryBackedTable, Table};

bitflags::bitflags! {
    /// Communication object configuration flags (according to KNX specification)
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ComObjectFlags: u8 {
        /// Transmission priority bitmask (bits 0-1)
        const TRANS_PRIORITY_MASK = 0x03;

        /// Group object configuration: communication enable
        const COMMUNICATION_ENABLE = 0x04;

        /// Group object configuration: read receive enable
        const READ_ENABLE = 0x08;

        /// Group object configuration: write receive enable
        const WRITE_ENABLE = 0x10;

        /// Group object configuration: send read on init (System B)
        const READ_ON_INIT = 0x20;

        /// Group object configuration: transmission enable (sending)
        const TRANSMIT_ENABLE = 0x40;

        /// Group object configuration: read response receive enable
        const READ_RESPONSE_ENABLE = 0x80;

        /// Common group object configuration: Transmit to bus (T)
        const CONFIG_T = Self::COMMUNICATION_ENABLE.bits() | Self::TRANSMIT_ENABLE.bits();

        /// Common group object configuration: Transmit to bus, read from bus (RT)
        const CONFIG_RT = Self::COMMUNICATION_ENABLE.bits() | Self::TRANSMIT_ENABLE.bits() | Self::READ_ENABLE.bits();

        /// Common group object configuration: Receive from bus (WU)
        const CONFIG_WU = Self::COMMUNICATION_ENABLE.bits() | Self::WRITE_ENABLE.bits() | Self::READ_RESPONSE_ENABLE.bits();

        /// Common group object configuration: Transmit to bus, receive, read from bus (RTWU)
        const CONFIG_RTWU = Self::COMMUNICATION_ENABLE.bits() | Self::TRANSMIT_ENABLE.bits() |
                           Self::WRITE_ENABLE.bits() | Self::READ_RESPONSE_ENABLE.bits() | Self::READ_ENABLE.bits();
    }
}

impl Default for ComObjectFlags {
    fn default() -> Self {
        // Default to CONFIG_RTWU - full communication capability
        Self::CONFIG_RTWU
    }
}

impl ComObjectFlags {
    /// Get the transmission priority (bits 0-1)
    pub fn trans_priority(&self) -> u8 {
        self.bits() & Self::TRANS_PRIORITY_MASK.bits()
    }

    /// Set the transmission priority (0-3)
    pub fn with_trans_priority(mut self, priority: u8) -> Self {
        // Clear existing priority bits and set new ones
        let priority = priority & Self::TRANS_PRIORITY_MASK.bits();
        self.remove(Self::TRANS_PRIORITY_MASK);
        self.insert(Self::from_bits_truncate(priority));
        self
    }
}

/// Communication object data type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ComObjectType {
    /// 1 bit
    Bit1 = 0,
    /// 2 bits
    Bit2 = 1,
    /// 3 bits
    Bit3 = 2,
    /// 4 bits
    Bit4 = 3,
    /// 5 bits
    Bit5 = 4,
    /// 6 bits
    Bit6 = 5,
    /// 7 bits
    Bit7 = 6,
    /// 1 byte
    Byte1 = 7,
    /// 2 bytes
    Byte2 = 8,
    /// 3 bytes
    Byte3 = 9,
    /// 4 bytes
    Byte4 = 10,
    /// 6 bytes
    Byte6 = 11,
    /// 8 bytes
    Byte8 = 12,
    /// 10 bytes
    Byte10 = 13,
    /// 14 bytes
    Byte14 = 14,
    /// Unknown type
    Unknown = 15,
}

impl From<u8> for ComObjectType {
    fn from(value: u8) -> Self {
        match value & 0x0F {
            0 => Self::Bit1,
            1 => Self::Bit2,
            2 => Self::Bit3,
            3 => Self::Bit4,
            4 => Self::Bit5,
            5 => Self::Bit6,
            6 => Self::Bit7,
            7 => Self::Byte1,
            8 => Self::Byte2,
            9 => Self::Byte3,
            10 => Self::Byte4,
            11 => Self::Byte6,
            12 => Self::Byte8,
            13 => Self::Byte10,
            14 => Self::Byte14,
            _ => Self::Unknown,
        }
    }
}

impl ComObjectType {
    /// Get the size in bytes for this object type
    pub const fn size_in_bytes(&self) -> usize {
        match self {
            Self::Bit1
            | Self::Bit2
            | Self::Bit3
            | Self::Bit4
            | Self::Bit5
            | Self::Bit6
            | Self::Bit7 => 1,
            Self::Byte1 => 1,
            Self::Byte2 => 2,
            Self::Byte3 => 3,
            Self::Byte4 => 4,
            Self::Byte6 => 6,
            Self::Byte8 => 8,
            Self::Byte10 => 10,
            Self::Byte14 => 14,
            Self::Unknown => 1,
        }
    }
}

/// Communication object descriptor containing type and flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComObjectDescriptor {
    /// Data type of this communication object
    pub object_type: ComObjectType,
    /// Configuration flags for this communication object
    pub flags: ComObjectFlags,
}

impl ComObjectDescriptor {
    /// Create a new descriptor from raw bytes
    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        Self {
            // Type is stored in lower 4 bits of the first byte
            object_type: ComObjectType::from(bytes[0] & 0x0F),
            // Flags are stored in the second byte
            flags: ComObjectFlags::from_bits_truncate(bytes[1]),
        }
    }

    /// Convert descriptor to raw bytes
    pub fn to_bytes(&self) -> [u8; 2] {
        [(self.object_type as u8) & 0x0F, self.flags.bits()]
    }
}

#[derive(Debug, ConstDefault)]
pub struct CoTab7Impl<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> Table<CoTab7Impl<N>> {
    pub fn max_entries(&self) -> usize {
        (N / 2) - 1
    }

    pub fn entry_count(&self) -> u16 {
        U16::from_bytes(self.table.data[0..2].try_into().unwrap()).get()
    }

    /// Check if the communication object table is empty
    pub fn is_empty(&self) -> bool {
        self.entry_count() == 0
    }

    /// Get the descriptor for communication object at the given index
    ///
    /// Note: idx is 1-indexed to match KNX conventions
    pub fn com_object(&self, idx: usize) -> Option<ComObjectDescriptor> {
        if idx == 0 || idx > self.entry_count() as usize {
            return None;
        }

        // Each entry is 2 bytes (type + flags)
        let offset = 2 + (idx - 1) * 2;
        let bytes = [self.table.data[offset], self.table.data[offset + 1]];

        Some(ComObjectDescriptor::from_bytes(bytes))
    }

    /// Set the descriptor for communication object at the given index
    ///
    /// Note: idx is 1-indexed to match KNX conventions
    pub fn set_com_object(
        &mut self,
        idx: usize,
        descriptor: ComObjectDescriptor,
    ) -> Result<(), ()> {
        if idx == 0 || idx > self.entry_count() as usize {
            return Err(());
        }

        // Each entry is 2 bytes (type + flags)
        let offset = 2 + (idx - 1) * 2;
        let bytes = descriptor.to_bytes();

        self.table.data[offset] = bytes[0];
        self.table.data[offset + 1] = bytes[1];

        Ok(())
    }

    /// Get object type for a communication object
    pub fn object_type(&self, idx: usize) -> Option<ComObjectType> {
        self.com_object(idx).map(|desc| desc.object_type)
    }

    /// Get flags for a communication object
    pub fn object_flags(&self, idx: usize) -> Option<ComObjectFlags> {
        self.com_object(idx).map(|desc| desc.flags)
    }

    /// Check if a communication object has specific properties using a closure
    pub fn object_has_property<F>(&self, idx: usize, predicate: F) -> bool
    where
        F: FnOnce(ComObjectFlags) -> bool,
    {
        self.object_flags(idx).map_or(false, predicate)
    }
}

impl<const N: usize> MemoryBackedTable for CoTab7Impl<N> {
    fn max_size() -> usize {
        N
    }

    fn data_ref(&self) -> &[u8] {
        &self.data
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    fn read(&self, offset: usize, data: &mut [u8]) {
        data.copy_from_slice(&self.data[offset..offset + data.len()]);
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        self.data[offset..offset + data.len()].copy_from_slice(data);
    }
}

pub type CoTab7<const MAX_ENTRIES: usize> = Table<CoTab7Impl<{ (MAX_ENTRIES + 1) * 2 }>>;

#[cfg(test)]
mod test {
    use crate::objects::tables::{LoadEvent, LoadState, MemoryBackedTable};

    use super::{CoTab7, ComObjectFlags, ComObjectType};

    #[test]
    fn co7_tab_alloc_load() {
        let mut ct = CoTab7::<10>::new();

        // Should start unloaded
        assert_eq!(ct.read_lsm(), [LoadState::Unloaded.into()]);

        // Begin loading
        ct.write_lsm(&[LoadEvent::StartLoading.into()]);
        assert_eq!(ct.read_lsm(), [LoadState::Loading.into()]);

        // Allocate a table with space for 3 communication objects
        ct.write_lsm(&[
            LoadEvent::AdditionalLoadControls.into(),
            0x0B,
            0x00,
            0x00,
            0x00,
            0x08, // 8 bytes total: 2 for length + 3*2 for objects
            0x01,
            0xff,
            0x00,
            0x00,
        ]);
        assert_eq!(ct.read_lsm(), [LoadState::Loading.into()]);
        assert_eq!(&ct.data_ref()[0..8], &[0xff; 8]);

        // Write data into the table:
        // - First 2 bytes: count = 3
        // - Com Object 1: Type=Bit1 (0x00), Flags=0xDC (RTWU config)
        // - Com Object 2: Type=Byte2 (0x08), Flags=0x44 (T config)
        // - Com Object 3: Type=Byte4 (0x0A), Flags=0x94 (WU config)
        ct.write(0, &[0x00, 0x03]); // Length: 3 entries
        ct.write(2, &[0x00, 0xDC]); // Com Object 1
        ct.write(4, &[0x08, 0x44]); // Com Object 2
        ct.write(6, &[0x0A, 0x94]); // Com Object 3

        // Verify raw table contents
        assert_eq!(
            &ct.data_ref()[0..8],
            &[0x00, 0x03, 0x00, 0xDC, 0x08, 0x44, 0x0A, 0x94]
        );

        // Issue load complete
        ct.write_lsm(&[LoadEvent::LoadCompleted.into()]);
        assert_eq!(ct.read_lsm(), [LoadState::Loaded.into()]);
    }

    #[test]
    fn co7_object_access() {
        let mut ct = CoTab7::<10>::new();

        // Setup a test table with 3 com objects
        ct.write_lsm(&[LoadEvent::StartLoading.into()]);
        ct.write_lsm(&[
            LoadEvent::AdditionalLoadControls.into(),
            0x0B,
            0x00,
            0x00,
            0x00,
            0x08,
            0x01,
            0xff,
            0x00,
            0x00,
        ]);

        ct.write(0, &[0x00, 0x03]); // Length: 3 entries
        ct.write(2, &[0x00, 0xDC]); // Com Object 1: Bit1, RTWU config
        ct.write(4, &[0x08, 0x44]); // Com Object 2: Byte2, T config
        ct.write(6, &[0x0A, 0x94]); // Com Object 3: Byte4, WU config
        ct.write_lsm(&[LoadEvent::LoadCompleted.into()]);

        // Test accessing each object
        let obj1 = ct.com_object(1).unwrap();
        assert_eq!(obj1.object_type, ComObjectType::Bit1);
        assert!(obj1.flags.contains(ComObjectFlags::COMMUNICATION_ENABLE));
        assert!(obj1.flags.contains(ComObjectFlags::READ_ENABLE));
        assert!(obj1.flags.contains(ComObjectFlags::WRITE_ENABLE));
        assert!(obj1.flags.contains(ComObjectFlags::TRANSMIT_ENABLE));
        assert!(obj1.flags.contains(ComObjectFlags::READ_RESPONSE_ENABLE));

        let obj2 = ct.com_object(2).unwrap();
        assert_eq!(obj2.object_type, ComObjectType::Byte2);
        assert!(obj2.flags.contains(ComObjectFlags::COMMUNICATION_ENABLE));
        assert!(!obj2.flags.contains(ComObjectFlags::READ_ENABLE));
        assert!(!obj2.flags.contains(ComObjectFlags::WRITE_ENABLE));
        assert!(obj2.flags.contains(ComObjectFlags::TRANSMIT_ENABLE));
        assert!(!obj2.flags.contains(ComObjectFlags::READ_RESPONSE_ENABLE));

        let obj3 = ct.com_object(3).unwrap();
        assert_eq!(obj3.object_type, ComObjectType::Byte4);
        assert!(obj3.flags.contains(ComObjectFlags::COMMUNICATION_ENABLE));
        assert!(!obj3.flags.contains(ComObjectFlags::READ_ENABLE)); // WU doesn't include READ_ENABLE
        assert!(obj3.flags.contains(ComObjectFlags::WRITE_ENABLE));
        assert!(!obj3.flags.contains(ComObjectFlags::TRANSMIT_ENABLE));
        assert!(obj3.flags.contains(ComObjectFlags::READ_RESPONSE_ENABLE));

        // Test accessing out of bounds
        assert!(ct.com_object(0).is_none());
        assert!(ct.com_object(4).is_none());
    }

    #[test]
    fn co7_object_modification() {
        let mut ct = CoTab7::<10>::new();

        // Setup a test table with 1 com object
        ct.write_lsm(&[LoadEvent::StartLoading.into()]);
        ct.write_lsm(&[
            LoadEvent::AdditionalLoadControls.into(),
            0x0B,
            0x00,
            0x00,
            0x00,
            0x04,
            0x01,
            0xff,
            0x00,
            0x00,
        ]);

        ct.write(0, &[0x00, 0x01]); // Length: 1 entry
        ct.write(2, &[0x00, 0xDC]); // Com Object 1: Bit1, RTWU config
        ct.write_lsm(&[LoadEvent::LoadCompleted.into()]);

        // Get original object
        let original = ct.com_object(1).unwrap();
        assert_eq!(original.object_type, ComObjectType::Bit1);

        // Modify object to T config
        let mut new_obj = original;
        new_obj.object_type = ComObjectType::Byte2;
        new_obj.flags = ComObjectFlags::CONFIG_T;

        // Save changes
        assert!(ct.set_com_object(1, new_obj).is_ok());

        // Verify changes
        let modified = ct.com_object(1).unwrap();
        assert_eq!(modified.object_type, ComObjectType::Byte2);
        assert!(
            modified
                .flags
                .contains(ComObjectFlags::COMMUNICATION_ENABLE)
        );
        assert!(!modified.flags.contains(ComObjectFlags::READ_ENABLE));
        assert!(!modified.flags.contains(ComObjectFlags::WRITE_ENABLE));
        assert!(modified.flags.contains(ComObjectFlags::TRANSMIT_ENABLE));
        assert!(
            !modified
                .flags
                .contains(ComObjectFlags::READ_RESPONSE_ENABLE)
        );
    }

    #[test]
    fn co7_object_properties() {
        let mut ct = CoTab7::<10>::new();

        // Setup a test table with 4 com objects with different flags
        ct.write_lsm(&[LoadEvent::StartLoading.into()]);
        ct.write_lsm(&[
            LoadEvent::AdditionalLoadControls.into(),
            0x0B,
            0x00,
            0x00,
            0x00,
            0x0A,
            0x01,
            0xff,
            0x00,
            0x00,
        ]);

        ct.write(0, &[0x00, 0x04]); // Length: 4 entries
        ct.write(2, &[0x00, 0xDC]); // Com Object 1: RTWU config
        ct.write(4, &[0x08, 0x44]); // Com Object 2: T config
        ct.write(6, &[0x0A, 0x94]); // Com Object 3: WU config
        ct.write(8, &[0x07, 0x4C]); // Com Object 4: RT config
        ct.write_lsm(&[LoadEvent::LoadCompleted.into()]);

        // Test checking object properties
        assert!(ct.object_has_property(1, |flags| {
            flags.contains(ComObjectFlags::COMMUNICATION_ENABLE)
        }));
        assert!(ct.object_has_property(1, |flags| flags.contains(ComObjectFlags::TRANSMIT_ENABLE)));
        assert!(ct.object_has_property(1, |flags| flags.contains(ComObjectFlags::WRITE_ENABLE)));

        assert!(ct.object_has_property(2, |flags| flags.contains(ComObjectFlags::CONFIG_T)));
        assert!(!ct.object_has_property(2, |flags| flags.contains(ComObjectFlags::WRITE_ENABLE)));

        assert!(ct.object_has_property(3, |flags| flags.contains(ComObjectFlags::CONFIG_WU)));
        assert!(
            !ct.object_has_property(3, |flags| flags.contains(ComObjectFlags::TRANSMIT_ENABLE))
        );

        assert!(ct.object_has_property(4, |flags| flags.contains(ComObjectFlags::CONFIG_RT)));

        // Test transmission priority
        let obj1 = ct.com_object(1).unwrap();
        assert_eq!(obj1.flags.trans_priority(), 0);

        // Test object that doesn't exist
        assert!(!ct.object_has_property(5, |flags| {
            flags.contains(ComObjectFlags::COMMUNICATION_ENABLE)
        }));
    }

    #[test]
    fn co7_transmission_priority() {
        // Create flags with different priority levels
        let flags0 = ComObjectFlags::CONFIG_T.with_trans_priority(0);
        let flags1 = ComObjectFlags::CONFIG_T.with_trans_priority(1);
        let flags2 = ComObjectFlags::CONFIG_T.with_trans_priority(2);
        let flags3 = ComObjectFlags::CONFIG_T.with_trans_priority(3);

        // Check priorities are correctly set
        assert_eq!(flags0.trans_priority(), 0);
        assert_eq!(flags1.trans_priority(), 1);
        assert_eq!(flags2.trans_priority(), 2);
        assert_eq!(flags3.trans_priority(), 3);

        // Check other bits remain unchanged
        assert!(flags0.contains(ComObjectFlags::COMMUNICATION_ENABLE));
        assert!(flags0.contains(ComObjectFlags::TRANSMIT_ENABLE));

        // Test priority wrapping (values > 3 should be masked)
        let flags_overflow = ComObjectFlags::CONFIG_T.with_trans_priority(5);
        assert_eq!(flags_overflow.trans_priority(), 1); // 5 & 0x03 = 1
    }
}
