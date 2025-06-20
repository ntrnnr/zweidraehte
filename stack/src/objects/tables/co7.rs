use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zerocopy::big_endian::U16;

use super::{ComObjectFlags, ComObjectTableEntry, ComObjectType, CommunicationObjectTable, Table, TableMemory};

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
        Self { object_type: ComObjectType::from(bytes[0]), flags: ComObjectFlags(bytes[1]) }
    }

    /// Convert descriptor to raw bytes
    pub fn to_bytes(&self) -> [u8; 2] {
        [u8::from(self.object_type), self.flags.0]
    }
}

#[serde_as]
#[derive(Debug, ConstDefault, Serialize, Deserialize)]
pub struct CoTab7Impl<const N: usize> {
    #[serde_as(as = "[_; N]")]
    data: [u8; N],
}

impl<const N: usize> Table<CoTab7Impl<N>> {
    /// Get the descriptor for communication object at the given index
    fn com_object(&self, idx: u16) -> Option<ComObjectDescriptor> {
        //trace!("Getting communication object at index {}", idx);

        if idx >= self.entry_count() {
            return None;
        }

        // Each entry is 2 bytes (type + flags)
        let offset = 2 + ((idx as usize) * 2);
        let bytes = [self.table.data[offset], self.table.data[offset + 1]];

        Some(ComObjectDescriptor::from_bytes(bytes))
    }
}

impl<const N: usize> TableMemory for CoTab7Impl<N> {
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

impl<const N: usize> CommunicationObjectTable for Table<CoTab7Impl<N>> {
    fn max_entries(&self) -> usize {
        (N / 2) - 1
    }

    fn entry_count(&self) -> u16 {
        U16::from_bytes(self.table.data[0..2].try_into().unwrap()).get()
    }

    fn get_object(&self, idx: u16) -> Option<ComObjectTableEntry> {
        self.com_object(idx).map(|desc| ComObjectTableEntry { object_type: desc.object_type, flags: desc.flags })
    }

    /// Get object type for a communication object
    fn object_type(&self, idx: u16) -> Option<ComObjectType> {
        self.com_object(idx).map(|desc| desc.object_type)
    }

    /// Get flags for a communication object
    fn object_flags(&self, idx: u16) -> Option<ComObjectFlags> {
        self.com_object(idx).map(|desc| desc.flags)
    }
}

pub type CoTab7<const MAX_ENTRIES: usize> = Table<CoTab7Impl<{ (MAX_ENTRIES + 1) * 2 }>>;

#[cfg(test)]
mod test {
    use crate::objects::tables::{CommunicationObjectTable, LoadEvent, LoadState, LoadableTable, TableMemory};

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
        assert_eq!(&ct.data_ref()[0..8], &[0x00, 0x03, 0x00, 0xDC, 0x08, 0x44, 0x0A, 0x94]);

        // Issue load complete
        ct.write_lsm(&[LoadEvent::LoadCompleted.into()]);
        assert_eq!(ct.read_lsm(), [LoadState::Loaded.into()]);
    }

    #[test]
    fn co7_object_access() {
        let mut ct = CoTab7::<10>::new();

        // Setup a test table with 3 com objects
        ct.write_lsm(&[LoadEvent::StartLoading.into()]);
        ct.write_lsm(&[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x08, 0x01, 0xff, 0x00, 0x00]);

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
        ct.write_lsm(&[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x04, 0x01, 0xff, 0x00, 0x00]);

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
        assert!(modified.flags.contains(ComObjectFlags::COMMUNICATION_ENABLE));
        assert!(!modified.flags.contains(ComObjectFlags::READ_ENABLE));
        assert!(!modified.flags.contains(ComObjectFlags::WRITE_ENABLE));
        assert!(modified.flags.contains(ComObjectFlags::TRANSMIT_ENABLE));
        assert!(!modified.flags.contains(ComObjectFlags::READ_RESPONSE_ENABLE));
    }

    #[test]
    fn co7_object_properties() {
        let mut ct = CoTab7::<10>::new();

        // Setup a test table with 4 com objects with different flags
        ct.write_lsm(&[LoadEvent::StartLoading.into()]);
        ct.write_lsm(&[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x0A, 0x01, 0xff, 0x00, 0x00]);

        ct.write(0, &[0x00, 0x04]); // Length: 4 entries
        ct.write(2, &[0x00, 0xDC]); // Com Object 1: RTWU config
        ct.write(4, &[0x08, 0x44]); // Com Object 2: T config
        ct.write(6, &[0x0A, 0x94]); // Com Object 3: WU config
        ct.write(8, &[0x07, 0x4C]); // Com Object 4: RT config
        ct.write_lsm(&[LoadEvent::LoadCompleted.into()]);

        // Test checking object properties
        assert!(ct.object_has_property(1, |flags| { flags.contains(ComObjectFlags::COMMUNICATION_ENABLE) }));
        assert!(ct.object_has_property(1, |flags| flags.contains(ComObjectFlags::TRANSMIT_ENABLE)));
        assert!(ct.object_has_property(1, |flags| flags.contains(ComObjectFlags::WRITE_ENABLE)));

        assert!(ct.object_has_property(2, |flags| flags.contains(ComObjectFlags::CONFIG_T)));
        assert!(!ct.object_has_property(2, |flags| flags.contains(ComObjectFlags::WRITE_ENABLE)));

        assert!(ct.object_has_property(3, |flags| flags.contains(ComObjectFlags::CONFIG_WU)));
        assert!(!ct.object_has_property(3, |flags| flags.contains(ComObjectFlags::TRANSMIT_ENABLE)));

        assert!(ct.object_has_property(4, |flags| flags.contains(ComObjectFlags::CONFIG_RT)));

        // Test transmission priority
        let obj1 = ct.com_object(1).unwrap();
        assert_eq!(obj1.flags.trans_priority(), 0);

        // Test object that doesn't exist
        assert!(!ct.object_has_property(5, |flags| { flags.contains(ComObjectFlags::COMMUNICATION_ENABLE) }));
    }
}
