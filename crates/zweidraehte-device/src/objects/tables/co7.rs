use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zerocopy::big_endian::U16;

use super::{
    ComObjectFlags, ComObjectTableEntry, ComObjectType, CommunicationObjectTable, LoadControlPolicy, Table, TableMemory,
};

/// Communication object descriptor containing type and flags.
///
/// Per KNX spec (Table 87), the Group Object Descriptor is a big-endian
/// 16-bit value where bits 15-8 are configuration flags and bits 7-0 are
/// the value field type code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComObjectDescriptor {
    /// Data type of this communication object
    pub object_type: ComObjectType,

    /// Configuration flags for this communication object
    pub flags: ComObjectFlags,
}

impl ComObjectDescriptor {
    /// Decode a descriptor from its big-endian 16-bit representation.
    pub fn from_u16(raw: U16) -> Self {
        let val = raw.get();
        Self { flags: ComObjectFlags::from_byte((val >> 8) as u8), object_type: ComObjectType::from(val as u8) }
    }

    /// Encode the descriptor as a big-endian 16-bit value.
    pub fn to_u16(&self) -> U16 {
        U16::new(((self.flags.to_byte() as u16) << 8) | u8::from(self.object_type) as u16)
    }
}

#[serde_as]
#[derive(Debug, Clone, ConstDefault, Serialize, Deserialize)]
pub struct CoTab7Impl<const N: usize> {
    #[serde_as(as = "[_; N]")]
    data: [u8; N],
}

impl<const N: usize, P: LoadControlPolicy> Table<CoTab7Impl<N>, P> {
    /// Get the descriptor for communication object at the given index.
    fn com_object(&self, idx: u16) -> Option<ComObjectDescriptor> {
        if idx == 0 || idx > self.entry_count() {
            return None;
        }

        // Each entry is a big-endian U16 descriptor
        let offset = 2 + (((idx - 1) as usize) * 2);
        let raw = U16::from_bytes(self.table.data[offset..offset + 2].try_into().expect("slice is exactly 2 bytes"));

        Some(ComObjectDescriptor::from_u16(raw))
    }
}

impl<const N: usize> TableMemory for CoTab7Impl<N> {
    const MAX_SIZE: usize = N;
    fn data_ref(&self) -> &[u8] {
        &self.data
    }
    fn data_ref_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize, P: LoadControlPolicy> CommunicationObjectTable for Table<CoTab7Impl<N>, P> {
    fn max_entries(&self) -> usize {
        (N / 2) - 1
    }

    fn entry_count(&self) -> u16 {
        // The count is bus-downloaded data and must not exceed physical capacity.
        U16::from_bytes(self.table.data[0..2].try_into().expect("slice is exactly 2 bytes"))
            .get()
            .min(self.max_entries() as u16)
    }

    fn object(&self, idx: u16) -> Option<ComObjectTableEntry> {
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

    fn read_on_init(&self, idx: u16) -> bool {
        self.object_flags(idx).is_some_and(|flags| flags.read_on_init())
    }

    /// Set the configuration flags for a communication object at runtime.
    fn set_object_flags(&mut self, idx: u16, flags: ComObjectFlags) -> bool {
        if idx == 0 || idx > self.entry_count() {
            return false;
        }

        // Read the existing descriptor, replace flags, write back
        let offset = 2 + (((idx - 1) as usize) * 2);
        let raw = U16::from_bytes(self.table.data[offset..offset + 2].try_into().expect("slice is exactly 2 bytes"));
        let mut desc = ComObjectDescriptor::from_u16(raw);
        desc.flags = flags;
        self.table.data[offset..offset + 2].copy_from_slice(&desc.to_u16().to_bytes());
        true
    }
}

pub type CoTab7<const MAX_ENTRIES: usize> = Table<CoTab7Impl<{ (MAX_ENTRIES + 1) * 2 }>>;

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod test {
    use crate::objects::tables::{CommunicationObjectTable, HasLoadStateMachine, LoadEvent, LoadState, TableMemory};
    use zweidraehte_proto::messages::knx::Priority;

    use super::{CoTab7, ComObjectFlags, ComObjectType};

    #[test]
    fn co7_tab_alloc_load() {
        let mut ct = CoTab7::<10>::new();

        // Should start unloaded
        assert_eq!(ct.read_lsm(), [u8::from(LoadState::Unloaded)]);

        // Begin loading
        ct.write_lsm(&[LoadEvent::StartLoading.into()], None);
        assert_eq!(ct.read_lsm(), [u8::from(LoadState::Loading)]);

        // Allocate a table with space for 3 communication objects
        ct.write_lsm(
            &[
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
            ],
            None,
        );
        assert_eq!(ct.read_lsm(), [u8::from(LoadState::Loading)]);
        assert_eq!(&ct.data_ref()[0..8], &[0xff; 8]);

        // Write data into the table:
        // - First 2 bytes: count = 3
        // Per spec (Table 87): each descriptor is [flags, type] (high byte = flags, low byte = type)
        // - Com Object 1: Flags=0xDC (RTWU config), Type=Uint1 (0x00)
        // - Com Object 2: Flags=0x44 (T config), Type=Byte2 (0x08)
        // - Com Object 3: Flags=0x94 (WU config), Type=Byte4 (0x0A)
        ct.write(0, &[0x00, 0x03]); // Length: 3 entries
        ct.write(2, &[0xDC, 0x00]); // Com Object 1
        ct.write(4, &[0x44, 0x08]); // Com Object 2
        ct.write(6, &[0x94, 0x0A]); // Com Object 3

        // Verify raw table contents
        assert_eq!(&ct.data_ref()[0..8], &[0x00, 0x03, 0xDC, 0x00, 0x44, 0x08, 0x94, 0x0A]);

        // Issue load complete
        ct.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        assert_eq!(ct.read_lsm(), [u8::from(LoadState::Loaded)]);
    }

    #[test]
    fn co7_object_access() {
        let mut ct = CoTab7::<10>::new();

        // Setup a test table with 3 com objects
        ct.write_lsm(&[LoadEvent::StartLoading.into()], None);
        ct.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x08, 0x01, 0xff, 0x00, 0x00],
            None,
        );

        ct.write(0, &[0x00, 0x03]); // Length: 3 entries
        ct.write(2, &[0xDC, 0x00]); // Com Object 1: RTWU config, Uint1
        ct.write(4, &[0x44, 0x08]); // Com Object 2: T config, Byte2
        ct.write(6, &[0x94, 0x0A]); // Com Object 3: WU config, Byte4
        ct.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        // Test accessing each object
        let obj1 = ct.com_object(1).unwrap();
        assert_eq!(obj1.object_type, ComObjectType::Uint1);
        assert!(obj1.flags.communication_enable());
        assert!(obj1.flags.read_enable());
        assert!(obj1.flags.write_enable());
        assert!(obj1.flags.transmission_enable());
        assert!(obj1.flags.update_enable());

        let obj2 = ct.com_object(2).unwrap();
        assert_eq!(obj2.object_type, ComObjectType::Byte2);
        assert!(obj2.flags.communication_enable());
        assert!(!obj2.flags.read_enable());
        assert!(!obj2.flags.write_enable());
        assert!(obj2.flags.transmission_enable());
        assert!(!obj2.flags.update_enable());

        let obj3 = ct.com_object(3).unwrap();
        assert_eq!(obj3.object_type, ComObjectType::Byte4);
        assert!(obj3.flags.communication_enable());
        assert!(!obj3.flags.read_enable()); // WU doesn't include read
        assert!(obj3.flags.write_enable());
        assert!(!obj3.flags.transmission_enable()); // WU doesn't include transmit
        assert!(obj3.flags.update_enable());

        // Test accessing out of bounds
        assert!(ct.com_object(0).is_none());
        assert!(ct.com_object(4).is_none());
    }

    #[test]
    fn co7_object_modification() {
        let mut ct = CoTab7::<10>::new();

        // Setup a test table with 1 com object
        ct.write_lsm(&[LoadEvent::StartLoading.into()], None);
        ct.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x04, 0x01, 0xff, 0x00, 0x00],
            None,
        );

        ct.write(0, &[0x00, 0x01]); // Length: 1 entry
        ct.write(2, &[0xDC, 0x00]); // Com Object 1: RTWU config, Uint1
        ct.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        // Get original object
        let original = ct.com_object(1).unwrap();
        assert_eq!(original.object_type, ComObjectType::Uint1);

        // Modify object to T config
        let mut new_obj = original;
        new_obj.object_type = ComObjectType::Byte2;
        new_obj.flags = ComObjectFlags::from_byte(ComObjectFlags::CONFIG_T);

        // Save changes
        // Note: set_com_object method doesn't exist, so we'll test the modified object directly
        let test_flags = ComObjectFlags::from_byte(ComObjectFlags::CONFIG_T);

        // Verify changes
        // Test that flags match expected T configuration
        assert_eq!(new_obj.object_type, ComObjectType::Byte2);
        assert!(test_flags.communication_enable());
        assert!(!test_flags.read_enable());
        assert!(!test_flags.write_enable());
        assert!(test_flags.transmission_enable());

        assert!(!ct.read_on_init(1));

        let with_read_on_init = ComObjectFlags::from_byte(ComObjectFlags::CONFIG_T | ComObjectFlags::ROI_FLAG_MASK);

        assert!(ct.set_object_flags(1, with_read_on_init));
        assert!(ct.read_on_init(1));
    }

    #[test]
    fn co7_object_properties() {
        let mut ct = CoTab7::<10>::new();

        // Setup a test table with 4 com objects with different flags
        ct.write_lsm(&[LoadEvent::StartLoading.into()], None);
        ct.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x0A, 0x01, 0xff, 0x00, 0x00],
            None,
        );

        ct.write(0, &[0x00, 0x04]); // Length: 4 entries
        ct.write(2, &[0xDC, 0x00]); // Com Object 1: RTWU config, Uint1
        ct.write(4, &[0x44, 0x08]); // Com Object 2: T config, Byte2
        ct.write(6, &[0x94, 0x0A]); // Com Object 3: WU config, Byte4
        ct.write(8, &[0x4C, 0x07]); // Com Object 4: RT config, Octet1
        ct.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        // Test object 1 properties (RTWU config)
        let obj1 = ct.com_object(1).unwrap();
        assert!(obj1.flags.contains(ComObjectFlags::CE_FLAG_MASK));
        assert!(obj1.flags.contains(ComObjectFlags::TE_FLAG_MASK));
        assert!(obj1.flags.contains(ComObjectFlags::WE_FLAG_MASK));

        // Test object 2 properties (T config)
        let obj2 = ct.com_object(2).unwrap();
        assert!(obj2.flags.contains(ComObjectFlags::CONFIG_T));
        assert!(!obj2.flags.contains(ComObjectFlags::WE_FLAG_MASK));

        // Test object 3 properties (WU config)
        let obj3 = ct.com_object(3).unwrap();
        assert!(obj3.flags.contains(ComObjectFlags::CONFIG_WU));
        assert!(!obj3.flags.contains(ComObjectFlags::TE_FLAG_MASK));

        // Test object 4 properties (RT config)
        let obj4 = ct.com_object(4).unwrap();
        assert!(obj4.flags.contains(ComObjectFlags::CONFIG_RT));

        // Test transmission priority
        assert_eq!(obj1.flags.priority(), Priority::System);

        // Test object that doesn't exist
        assert!(ct.com_object(5).is_none());
    }
}

/// The Type 7 group object table under the System 7 load-control policy.
///
/// Same byte format as [`CoTab7`]; the policy only changes which
/// `AdditionalLoadControls` records the load state machine accepts.
pub type CoTab7Alloc<const MAX_ENTRIES: usize> =
    Table<CoTab7Impl<{ (MAX_ENTRIES + 1) * 2 }>, crate::objects::tables::AbsoluteAlloc>;
