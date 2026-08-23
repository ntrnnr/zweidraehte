//! `System7DeviceState` behaviour: the 16-level authorization model, the
//! individual address living inside the RT8 address table, and the
//! config round-trip carrying the IA through the table blob.
//!
//! The stack definition here is the minimal test double — the router and
//! link layer are never constructed.

use const_default::ConstDefault;

use zweidraehte_device::bcus::system_7::{
    System7DeviceConfig, System7DeviceState, System7InterfaceObjectsFor, create_system_7_objects, table_sizes,
};
use zweidraehte_device::bcus::system_b::{ExtensionAugmentFor, SystemBDeviceModel};
use zweidraehte_device::context::layer::LayerContext;
use zweidraehte_device::extension::Extension;
use zweidraehte_device::layers::linklayers::mock::MockLinkLayerBuilder;
use zweidraehte_device::layers::transport::TlStyle;
use zweidraehte_device::memory::NoMemoryMap;
use zweidraehte_device::objects::comm::{
    ComObjectBusHook, ComObjectIndex, ComObjectInfo, ComObjectInfoMut, ComObjects,
};
use zweidraehte_device::storage::{HasDeviceConfig, StaticIdentity};
use zweidraehte_device::{HasAuthorization, HasPersistence, StackState};
use zweidraehte_device::{PlainDeviceBuilder, StackDefinition};

use zerocopy::{Immutable, IntoBytes, KnownLayout};
use zweidraehte_device::restart::EraseCode;
use zweidraehte_proto::AccessContext;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};

// ============================================================================
// Minimal device descriptor — System 7 TP1, tiny tables.
// ============================================================================

const S7_DEVICE: DeviceDescriptor = DeviceDescriptor::new(
    MaskVersion::System7Tp1, // 0x0705
    0x00FA,                  // arbitrary manufacturer id
    [0u8; 6],                // hardware type
    0xF002,                  // application id
    0x01,                    // application version
    4,                       // max address table entries
    4,                       // max association table entries
    4,                       // max comm objects
    0,                       // pei type
);

const SIZES: (usize, usize, usize) = table_sizes(4, 4, 4);
const ADT: usize = SIZES.0;
const AST: usize = SIZES.1;
const COT: usize = SIZES.2;

// ============================================================================
// Zero-comm-object placeholder (see rf_retransmitter_property_scan.rs).
// ============================================================================

#[derive(Clone, Copy)]
enum NoCoIndex {}

impl ComObjectIndex for NoCoIndex {
    fn from_index(_idx: u16) -> Option<Self> {
        None
    }

    fn index(&self) -> u16 {
        match *self {}
    }
}

struct NoCo;

impl ComObjects for NoCo {
    type Index = NoCoIndex;

    fn new() -> Self {
        NoCo
    }

    fn info(&self, _idx: u16) -> Option<ComObjectInfo<'_>> {
        None
    }

    fn info_mut(&mut self, _idx: u16) -> Option<ComObjectInfoMut<'_>> {
        None
    }
}

impl ComObjectBusHook for NoCo {}

#[derive(Clone, serde::Serialize, serde::Deserialize, IntoBytes, KnownLayout, Immutable)]
struct NoParams;

impl ConstDefault for NoParams {
    const DEFAULT: Self = NoParams;
}

// ============================================================================
// The test stack definition.
// ============================================================================

#[derive(Clone, Copy)]
struct S7TestStack;

type S7TestState = System7DeviceState<ADT, AST, COT, S7TestStack>;

impl zweidraehte_device::bcus::system_7::System7ProductLayout for S7TestStack {
    const COT_ADDRESS: u16 = 0x4200;
}

impl StackDefinition for S7TestStack {
    const DEVICE: &'static DeviceDescriptor = &S7_DEVICE;
    const TL_STYLE: TlStyle = TlStyle::Style3;
    const FIRST_ASAP: u16 = 0;

    type P = NoParams;
    type CO = NoCo;
    type LLB = MockLinkLayerBuilder<1>;
    type ES = ();
    type State = S7TestState;
    type StateInit = ();
    type Mem = NoMemoryMap;

    fn create_state(_init: ()) -> Self::State {
        System7DeviceState::new(StaticIdentity::new([0u8; 6]), NoCo::new(), ())
    }

    type InterfaceObjects<'a> = System7InterfaceObjectsFor<'a, Self>;
    type Augments<'a> = ExtensionAugmentFor<'a, Self>;

    fn create_interface_objects<'a>(
        state: &'a Self::State,
        _platform: &'a Self::Platform,
        layer_ctx: &'a LayerContext<Self>,
        augments: &'a Self::Augments<'a>,
    ) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        create_system_7_objects::<Self, _>(state, layer_ctx, augments)
    }

    type DeviceModel<'a> = SystemBDeviceModel<'a, Self>;

    fn create_device_model<'a>(
        state: &'a Self::State,
        layer_context: &'a LayerContext<Self>,
        interface_objects: &'a Self::InterfaceObjects<'static>,
    ) -> Self::DeviceModel<'a>
    where
        Self::State: 'a,
    {
        SystemBDeviceModel::new(state, layer_context, interface_objects)
    }

    fn create_augments<'a>(
        state: &'a Self::State,
        platform: &'a Self::Platform,
        _layer_ctx: &'a LayerContext<Self>,
    ) -> Self::Augments<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        state.extension_state().create_augment::<Self>(platform)
    }

    type AlExtensions = ();
    type LayerBuilder = PlainDeviceBuilder;
}

fn fresh_state() -> S7TestState {
    S7TestStack::create_state(())
}

// ============================================================================
// 16-level authorization
// ============================================================================

#[test]
fn authorize_scans_fifteen_keys() {
    let state = fresh_state();

    // Factory: every key is the default key, so the default key matches
    // at level 0 — the "no protected areas → highest level" rule.
    assert_eq!(state.max_access_levels(), 16);
    assert_eq!(state.authorize(&[0xFF; 4]), 0);

    // Configure distinct keys on the top and bottom settable levels.
    let ctx = AccessContext::new(0);
    assert_eq!(state.key_write(0, &[0xAA; 4], ctx), 0);
    assert_eq!(state.key_write(14, &[0xBB; 4], ctx), 14);

    assert_eq!(state.authorize(&[0xAA; 4]), 0);
    assert_eq!(state.authorize(&[0xBB; 4]), 14);
    // An unknown key falls through to the free level.
    assert_eq!(state.authorize(&[0x12, 0x34, 0x56, 0x78]), 15);
}

#[test]
fn key_write_enforces_level_rules() {
    let state = fresh_state();

    // Level 15 has no key slot.
    assert_eq!(state.key_write(15, &[0xAA; 4], AccessContext::new(0)), 0xFF);

    // A caller may only write keys at or below its own privilege:
    // ctx level 5 cannot set the level-3 key…
    assert_eq!(state.key_write(3, &[0xAA; 4], AccessContext::new(5)), 0xFF);
    // …but can set the level-7 key.
    assert_eq!(state.key_write(7, &[0xAA; 4], AccessContext::new(5)), 7);
}

// ============================================================================
// Individual address lives in the RT8 table
// ============================================================================

#[test]
fn individual_address_delegates_to_address_table() {
    let state = fresh_state();

    // Factory default from the seeded FF FF slot.
    assert_eq!(state.individual_address(), IndividualAddress::new(15, 15, 255));

    // The service path writes through to the table bytes…
    state.set_individual_address(IndividualAddress::new(1, 2, 3));
    assert_eq!(state.adt.borrow().individual_address(), IndividualAddress::new(1, 2, 3));
    assert!(state.is_dirty());

    // …and a download rewriting the blob moves the state's answer.
    {
        use zweidraehte_device::objects::tables::TableMemory;
        state.adt.borrow_mut().write(1, &[0x11, 0x05]);
    }
    assert_eq!(state.individual_address(), IndividualAddress::from_bytes(&[0x11, 0x05]));
}

#[test]
fn reset_links_preserves_the_ia() {
    let state = fresh_state();
    state.set_individual_address(IndividualAddress::new(1, 2, 3));

    HasPersistence::apply_erase_code(&state, EraseCode::ResetLinks);
    assert_eq!(state.individual_address(), IndividualAddress::new(1, 2, 3));

    HasPersistence::apply_erase_code(&state, EraseCode::FactoryReset);
    assert_eq!(state.individual_address(), IndividualAddress::new(15, 15, 255));
}

// ============================================================================
// Config round-trip
// ============================================================================

#[test]
fn config_round_trip_carries_ia_in_table_blob() {
    let state = fresh_state();
    state.set_individual_address(IndividualAddress::new(1, 0, 5));
    state.key_write(2, &[0xCC; 4], AccessContext::new(0));
    state.set_option_reg(0x42);

    let config: System7DeviceConfig<ADT, AST, COT, NoParams, ()> = state.to_config();
    let restored = S7TestState::from_config(StaticIdentity::new([0u8; 6]), config, ());

    assert_eq!(restored.individual_address(), IndividualAddress::new(1, 0, 5));
    assert_eq!(restored.authorize(&[0xCC; 4]), 2);
    assert_eq!(restored.option_reg(), 0x42);
    assert!(!restored.is_dirty());
}

// ============================================================================
// System7MemoryMap
// ============================================================================

mod memory_map {
    use super::*;
    use zweidraehte_device::bcus::system_7::System7MemoryMap;
    use zweidraehte_device::memory::{MemoryError, MemoryMap};
    use zweidraehte_device::objects::tables::{AddressTable, LoadState};

    const MAP: System7MemoryMap = System7MemoryMap::new();
    const CTX: AccessContext = AccessContext::MAX_ACCESS;

    fn read1(state: &S7TestState, addr: u16) -> u8 {
        let mut buf = [0u8; 1];
        MAP.read(state, addr, &mut buf, CTX).expect("mapped address");
        buf[0]
    }

    /// Programming mode: memory byte at 0060h and the property view are
    /// one flag, and only parity-consistent writes flip it.
    #[test]
    fn programming_mode_byte_at_0060() {
        let state = fresh_state();
        assert_eq!(read1(&state, 0x0060), 0x00);

        MAP.write(&state, 0x0060, &[0x81], CTX).expect("progmode write");
        assert!(state.is_programming_mode());
        assert_eq!(read1(&state, 0x0060), 0x81);

        // Bad parity (bit 0 without bit 7): the write lands but the
        // mode stays.
        MAP.write(&state, 0x0060, &[0x01], CTX).expect("write accepted");
        assert!(state.is_programming_mode());

        MAP.write(&state, 0x0060, &[0x00], CTX).expect("progmode clear");
        assert!(!state.is_programming_mode());
    }

    #[test]
    fn option_reg_at_0100() {
        let state = fresh_state();
        MAP.write(&state, 0x0100, &[0x42], CTX).expect("optionreg write");
        assert_eq!(state.option_reg(), 0x42);
        assert_eq!(read1(&state, 0x0100), 0x42);
    }

    #[test]
    fn ram_window_at_0700() {
        let state = fresh_state();
        MAP.write(&state, 0x0710, &[0xAB, 0xCD], CTX).expect("ram write");
        let mut buf = [0u8; 2];
        MAP.read(&state, 0x0710, &mut buf, CTX).expect("ram read");
        assert_eq!(buf, [0xAB, 0xCD]);
    }

    /// A download writing the GA table blob at 4000h is visible through
    /// the runtime address-table view.
    #[test]
    fn adt_window_at_4000() {
        let state = fresh_state();
        // [len=2: IA + one GA][IA 1.0.1][GA 0/0/1]
        MAP.write(&state, 0x4000, &[0x02, 0x10, 0x01, 0x00, 0x01], CTX).expect("table blob write");
        assert_eq!(state.adt.borrow().entry_count(), 1);
        assert_eq!(state.individual_address(), IndividualAddress::from_bytes(&[0x10, 0x01]));
    }

    /// The load-control window drives the per-machine LSMs; their state
    /// reads back at B6EAh-B6EDh.
    #[test]
    fn load_control_window_drives_the_lsms() {
        let state = fresh_state();
        assert_eq!(read1(&state, 0xB6EA), u8::from(LoadState::Unloaded));

        // Machine 1 (ADT): StartLoading, then AllocAbsDataSeg at 4000h
        // — the memory spelling with its segment ID octet
        // (03/05/02 §3.31.2: [L3][type][ID][start:2][length:2]…).
        MAP.write(&state, 0x0104, &[0x11], CTX).expect("start loading");
        assert_eq!(read1(&state, 0xB6EA), u8::from(LoadState::Loading));
        MAP.write(&state, 0x0104, &[0x13, 0x00, 0x00, 0x40, 0x00, 0x00, 0x09, 0xFF, 0x03, 0x80, 0x00], CTX)
            .expect("alloc record");
        assert_eq!(state.adt.borrow().table_reference(), 0x4000);

        // LoadCompleted; other machines untouched.
        MAP.write(&state, 0x0104, &[0x12], CTX).expect("load completed");
        assert_eq!(read1(&state, 0xB6EA), u8::from(LoadState::Loaded));
        assert_eq!(read1(&state, 0xB6EB), u8::from(LoadState::Unloaded));

        // Machine 3 (application) start + complete via the window.
        MAP.write(&state, 0x0104, &[0x31], CTX).expect("app start");
        MAP.write(&state, 0x0104, &[0x32], CTX).expect("app complete");
        assert_eq!(read1(&state, 0xB6EC), u8::from(LoadState::Loaded));

        // The status bytes are read-only.
        assert_eq!(MAP.write(&state, 0xB6EA, &[0x00], CTX), Err(MemoryError::WriteProtected));
    }

    #[test]
    fn unmapped_addresses_error() {
        let state = fresh_state();
        let mut buf = [0u8; 1];
        assert_eq!(MAP.read(&state, 0x0000, &mut buf, CTX), Err(MemoryError::NotAccessible));
        assert_eq!(MAP.read(&state, 0x9000, &mut buf, CTX), Err(MemoryError::NotAccessible));
        assert_eq!(MAP.write(&state, 0x9000, &[0], CTX), Err(MemoryError::NotAccessible));
    }

    /// The association table region only exists once located by its
    /// allocation record.
    #[test]
    fn ast_region_appears_after_allocation() {
        let state = fresh_state();
        let mut buf = [0u8; 1];
        assert_eq!(MAP.read(&state, 0x4100, &mut buf, CTX), Err(MemoryError::NotAccessible));

        // Machine 2 (AST): StartLoading + AllocAbsDataSeg at 4100h,
        // in the memory spelling (segment ID octet after the type).
        MAP.write(&state, 0x0104, &[0x21], CTX).expect("ast start");
        MAP.write(&state, 0x0104, &[0x23, 0x00, 0x00, 0x41, 0x00, 0x00, 0x07, 0xFF, 0x03, 0x80, 0x00], CTX)
            .expect("ast alloc");

        // [count=1][TSAP 1 -> ASAP 1]
        MAP.write(&state, 0x4100, &[0x01, 0x01, 0x01], CTX).expect("ast blob");
        use zweidraehte_device::objects::tables::AssociationTable;
        assert_eq!(state.ast.borrow().entry_count(), 1);
        assert_eq!(state.ast.borrow().sending_tsap(1), Some(1));
    }
}

// ============================================================================
// System7Objects
// ============================================================================

mod objects {
    use super::*;
    use static_cell::StaticCell;
    use zweidraehte_device::objects::interface::{
        FullPropertyReadRequest, FullPropertyWriteRequest, PropertyServiceHandler, pid,
    };
    use zweidraehte_device::objects::tables::{HasLoadStateMachine, LoadEvent, LoadState};
    use zweidraehte_proto::dpt::InterfaceObjectType;
    use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};

    /// All assertions live in one function: the buffer manager lives in a
    /// `StaticCell`, whose `init` panics on a second call.
    #[test]
    fn system_7_object_roster_and_dispatch() {
        static BUFFERS: StaticCell<[[u8; 64]; 4]> = StaticCell::new();
        static BUF_MGR: StaticCell<BufferManager<4>> = StaticCell::new();

        let buffers = BUFFERS.init([[0u8; 64]; 4]);
        // SAFETY: single-threaded test, buffers live for the whole test.
        let buffer_manager = BUF_MGR.init(unsafe { BufferManager::new(buffers) });
        let dyn_bm = buffer_manager.dyn_buffer_manager();
        // SAFETY: the buffer manager lives in a StaticCell ('static).
        let dyn_bm: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_bm) };

        let lctx = LayerContext::<S7TestStack>::new(dyn_bm, ());
        let state = S7TestStack::create_state(());
        let augments = S7TestStack::create_augments(&state, &(), &lctx);
        let objects = S7TestStack::create_interface_objects(&state, &(), &lctx, &augments);

        // Roster: the four mandatory objects plus the optional Interface
        // Program (Type 4) at index 4.
        assert_eq!(objects.object_count(), 5);
        assert_eq!(objects.object_type_at(0), Some(InterfaceObjectType::Device));
        assert_eq!(objects.object_type_at(1), Some(InterfaceObjectType::AddressTable));
        assert_eq!(objects.object_type_at(2), Some(InterfaceObjectType::AssociationTable));
        assert_eq!(objects.object_type_at(3), Some(InterfaceObjectType::ApplicationProgram));
        assert_eq!(objects.object_type_at(4), Some(InterfaceObjectType::InterfaceProgram));
        assert_eq!(objects.object_type_at(5), None);

        // The Device Object answers the System 7 mask.
        let read = FullPropertyReadRequest {
            object_idx: 0,
            pid: pid::device::DEVICE_DESCRIPTOR,
            start_idx: 1,
            count: 1,
            ctx: AccessContext::new(0),
        };
        let mut buf = [0u8; 4];
        let len = objects.property_value_read(&read, &mut buf).expect("device descriptor readable");
        assert_eq!(&buf[..len], &0x0705u16.to_be_bytes());

        for object in 0..=4 {
            let desc = objects.property_description_read(object, pid::OBJECT_TYPE, 0).expect("object type described");
            assert_eq!(desc.read_level, 3);
        }

        // Annex A expresses MV-0705's 3/3 as controller access on both
        // sides. Runtime remains the distinct free level 15.
        let desc = objects.property_description_read(0, pid::DEVICE_CONTROL, 0).expect("device control described");
        assert_eq!(desc.read_level, 3);
        assert_eq!(desc.write_level, 3);
        for property in [pid::device::PROGMODE, pid::device::ROUTING_COUNT] {
            let desc = objects.property_description_read(0, property, 0).expect("optional property described");
            assert_eq!(desc.read_level, 3);
            assert_eq!(desc.write_level, 3);
        }

        for property in [pid::SERIAL_NUMBER, pid::MANUFACTURER_ID, pid::device::HARDWARE_TYPE] {
            let desc = objects.property_description_read(0, property, 0).expect("identity property described");
            assert_eq!(desc.read_level, 3);
        }
        for object in [1, 2] {
            for property in [pid::LOAD_STATE_CONTROL, pid::TABLE_REFERENCE] {
                let desc = objects.property_description_read(object, property, 0).expect("table property described");
                assert_eq!((desc.read_level, desc.write_level), (3, 3));
            }
        }
        for property in [pid::LOAD_STATE_CONTROL, pid::RUN_STATE_CONTROL, pid::PROGRAM_VERSION, pid::PEI_TYPE] {
            let desc = objects.property_description_read(3, property, 0).expect("application property described");
            assert_eq!(desc.read_level, 3);
        }

        // Index 3 and index 4 drive independent load state machines.
        let write = |idx: u16, data: &[u8]| {
            let req = FullPropertyWriteRequest {
                object_idx: idx,
                pid: pid::LOAD_STATE_CONTROL,
                count: 1,
                start_idx: 1,
                data,
                ctx: AccessContext::new(0),
            };
            objects.property_value_write(&req).expect("LSM write");
        };
        write(3, &[LoadEvent::StartLoading.into()]);
        assert_eq!(state.app.borrow().read_lsm(), [LoadState::Loading.into()]);
        assert_eq!(state.app2.borrow().read_lsm(), [LoadState::Unloaded.into()]);

        write(4, &[LoadEvent::StartLoading.into()]);
        write(4, &[LoadEvent::LoadCompleted.into()]);
        assert_eq!(state.app.borrow().read_lsm(), [LoadState::Loading.into()]);
        assert_eq!(state.app2.borrow().read_lsm(), [LoadState::Loaded.into()]);

        // A free level-15 caller cannot drive the level-3 table LSM.
        let req = FullPropertyWriteRequest {
            object_idx: 1,
            pid: pid::LOAD_STATE_CONTROL,
            count: 1,
            start_idx: 1,
            data: &[LoadEvent::StartLoading.into()],
            ctx: AccessContext::new(15),
        };
        assert!(objects.property_value_write(&req).is_err());
    }
}

// ============================================================================
// The macro pair: system7_stack_config! + system_7_standard_stack!
// ============================================================================

mod macros {
    use super::*;
    use zweidraehte_device::bcus::system_7::Tp1StateFor7;
    use zweidraehte_device::objects::tables::{AddressTable, AssociationTable, ComObjectType};
    use zweidraehte_proto::address::GroupAddress;

    zweidraehte_device::system7_stack_config! {
        name: MacroConfig,
        individual_address: "1.0.5",
        group_addresses: {
            1 => "0/0/1",
            2 => "0/0/2",
        },
        comm_objects: {
            0 => (ComObjectType::Uint1 as u8, zweidraehte_device::config::CE | zweidraehte_device::config::TE),
            1 => (ComObjectType::Uint1 as u8, zweidraehte_device::config::CE | zweidraehte_device::config::WE),
        },
        associations: {
            1 => [0],
            2 => [1],
        },
    }

    const MACRO_DEVICE: DeviceDescriptor = DeviceDescriptor::new(
        MaskVersion::System7Tp1,
        0x00FA,
        [0u8; 6],
        0xF003,
        0x01,
        MacroConfig::NUM_GROUP_ADDRS as u16,
        MacroConfig::NUM_ASSOCIATIONS as u16,
        MacroConfig::NUM_COMM_OBJECTS as u16,
        0,
    );

    #[derive(Clone, Copy)]
    struct MacroStack;

    zweidraehte_device::system_7_standard_stack! {
        stack: MacroStack,
        device: &MACRO_DEVICE,
        cot_address: 0x4200,
        params: NoParams,
        com_objects: NoCo,
        link_layer_builder: MockLinkLayerBuilder<1>,
        platform: (),
        extension_state: zweidraehte_device::bcus::system_7::Tp1ExtensionState,
        state: Tp1StateFor7<MacroStack>,
        al_extensions: (),
        layer_builder: PlainDeviceBuilder,
    }

    /// The macro pair produces a working device: factory state via
    /// `from_init`, config-built RT8 tables loadable into it, lookups
    /// consistent with the declared configuration.
    #[test]
    fn macro_built_stack_loads_config_tables() {
        use zweidraehte_device::bcus::system_7::System7StateInit;
        use zweidraehte_device::storage::StaticIdentity;

        let state = MacroStack::create_state(System7StateInit::new(StaticIdentity::new([0u8; 6]), None));
        assert_eq!(state.individual_address(), IndividualAddress::new(15, 15, 255));

        let (adt, ast, cot) = MacroConfig::create_tables(0x4100, 0x4200);
        *state.adt.borrow_mut() = adt;
        *state.ast.borrow_mut() = ast;
        *state.cot.borrow_mut() = cot;

        // The config's individual address travelled inside the table blob.
        assert_eq!(state.individual_address(), IndividualAddress::new(1, 0, 5));
        assert_eq!(state.adt.borrow().table_reference(), 0x4000);
        assert_eq!(state.adt.borrow().tsap(GroupAddress::from_three_level(0, 0, 2)), Some(2));
        assert_eq!(state.ast.borrow().sending_tsap(1), Some(2));
    }
}

// ============================================================================
// The Group Object Table Object a secure System 7 device has to grow
// ============================================================================

/// 06 Profiles v02.02.01 §9.2.1.1.1.1 lists the Group Object Table
/// Object (Type 9) as **M** for the GO Diagnostics profile module, and
/// §9.1.2.4 row 6.2 footnote b makes GO Diagnostics itself mandatory for
/// S-Mode Data Secure devices that have Group Objects. System 7's base
/// roster stops at five objects, so a secure System 7 device composes
/// `GroupObjectTableAugment` to give PID_GO_DIAGNOSTICS (66) a home.
///
/// The end-to-end path — PID 66 arriving on object index 5 and reaching
/// `DiagnosticsAugment` — is exercised by the System 7 secure DUT; what
/// is pinned here is the contract the container relies on.
mod go_table_object {
    use super::S7TestStack;
    use zweidraehte_device::bcus::system_b::GroupObjectTableAugment;
    use zweidraehte_device::objects::interface::pid;
    use zweidraehte_device::service::Augment;
    use zweidraehte_proto::access::AccessLevel;
    use zweidraehte_proto::dpt::InterfaceObjectType;

    type Aug = GroupObjectTableAugment;

    #[test]
    fn contributes_exactly_the_group_object_table_object() {
        let augment = Aug::new();
        assert_eq!(<Aug as Augment<S7TestStack>>::additional_object_count(&augment), 1);
        assert_eq!(
            <Aug as Augment<S7TestStack>>::additional_object_type_at(&augment, 0),
            Some(InterfaceObjectType::GroupObjectTable)
        );
        assert_eq!(<Aug as Augment<S7TestStack>>::additional_object_type_at(&augment, 1), None);
    }

    #[test]
    fn answers_the_mandatory_object_type_property() {
        let augment = Aug::new();
        let d = <Aug as Augment<S7TestStack>>::property_descriptor(
            &augment,
            InterfaceObjectType::GroupObjectTable,
            pid::OBJECT_TYPE,
        )
        .expect("PID_OBJECT_TYPE is mandatory on every interface object");
        // Resolved against System 7's 16 levels: runtime read is 15.
        assert_eq!(d.read_level, 15);
    }

    /// §9.1.2.6.3 gives this object PID_OBJECT_TYPE (M) and
    /// PID_OBJECT_NAME (O) and nothing else. No load state machine in
    /// particular: the System 7 group object table is written by absolute
    /// memory writes, so a PID_LOAD_STATE_CONTROL here would invent a
    /// fifth load state machine no product database drives.
    #[test]
    fn carries_no_load_state_machine() {
        let pids: [u16; 2] = core::array::from_fn(|i| Aug::DESCRIPTORS[i].1.pid);
        assert_eq!(Aug::DESCRIPTORS.len(), 2);
        assert_eq!(pids, [pid::OBJECT_TYPE, pid::OBJECT_NAME]);
    }

    /// Composing this augment on a profile that already has Object
    /// Type 9 in its base roster — System B, where it sits at index 3 —
    /// would list the type twice in `PID_IO_LIST` and give two object
    /// indexes the same type. That is how a Management Client discovers
    /// the Security Interface Object (§9.1.2.6.2), so the object
    /// containers assert against it on construction.
    #[test]
    #[should_panic(expected = "would appear twice in PID_IO_LIST")]
    fn is_rejected_on_a_profile_that_already_has_the_object() {
        use zweidraehte_proto::dpt::InterfaceObjectType as Iot;
        let augment = Aug::new();
        zweidraehte_device::service::debug_assert_no_duplicate_object_types::<S7TestStack, _>(
            // System B's base roster, which already carries Type 9.
            &[Iot::Device, Iot::AddressTable, Iot::AssociationTable, Iot::GroupObjectTable, Iot::ApplicationProgram],
            &augment,
        );
    }

    /// System 7's own roster stops before Type 9, so the same augment is
    /// exactly what that profile is missing.
    #[test]
    fn is_accepted_on_a_profile_that_lacks_it() {
        use zweidraehte_proto::dpt::InterfaceObjectType as Iot;
        let augment = Aug::new();
        zweidraehte_device::service::debug_assert_no_duplicate_object_types::<S7TestStack, _>(
            &[Iot::Device, Iot::AddressTable, Iot::AssociationTable, Iot::ApplicationProgram, Iot::InterfaceProgram],
            &augment,
        );
    }

    /// The levels are symbolic on the augment, because the augment does
    /// not know which profile will host it.
    #[test]
    fn levels_stay_symbolic_until_a_device_resolves_them() {
        let (_, d) = Aug::DESCRIPTORS.iter().find(|(_, d)| d.pid == pid::OBJECT_TYPE).expect("declared");
        assert_eq!(d.read_level, AccessLevel::Runtime);
        assert_eq!(d.for_levels(4).read_level, 3);
        assert_eq!(d.for_levels(16).read_level, 15);
    }
}

// ============================================================================
// The `security:` arm of `system7_stack_config!`
// ============================================================================

/// The Group Object security flags table is *positional*: element n
/// carries the flags of the group object in table slot n (03/05/01
/// §6.3.15). The `go_flags` keys are written in the family's own ASAP
/// numbering, and the two families do not agree on where that starts —
/// System B numbers communication objects from 1, System 7 pins
/// `StackDefinition::FIRST_ASAP = 0` for the System 7 table. Subtract the
/// wrong base and every object is secured as its neighbour's, which no
/// type checks and which a running device reports as working.
mod security_config {
    use zweidraehte_device::config::{CE, TE, WE};
    use zweidraehte_device::objects::tables::ComObjectType;

    zweidraehte_device::system7_stack_config! {
        name: SecureConfig,
        individual_address: "1.0.5",
        group_addresses: {
            1 => "0/0/1",
            2 => "0/0/2",
        },
        comm_objects: {
            // ASAP 0 is a real, addressable object on System 7.
            0 => (ComObjectType::Uint1 as u8, CE | TE),
            1 => (ComObjectType::Uint1 as u8, CE | WE),
            2 => (ComObjectType::Uint1 as u8, CE | WE),
        },
        associations: {
            1 => [0],
            2 => [1],
        },
        security: {
            p2p_key_capacity: 0,
            siat_capacity: 4,
            tool_key: "000102030405060708090A0B0C0D0E0F",
            group_keys: {
                1 => "101112131415161718191A1B1C1D1E1F",
            },
            // Secure the first and the last object, leave the middle one
            // plain — an asymmetric pattern, so an off-by-one shows up.
            go_flags: {
                0 => 0x01,
                2 => 0x01,
            },
        },
    }

    #[test]
    fn go_flags_land_on_their_own_object() {
        let config = SecureConfig::create_security_config();
        let flags = |slot: u16| *config.go_flags.get(slot).expect("one entry per communication object");

        assert_eq!(flags(0), [0x01], "ASAP 0 is secured");
        assert_eq!(flags(1), [0x00], "ASAP 1 is plain");
        assert_eq!(flags(2), [0x01], "ASAP 2 is secured");
    }

    /// The table is sized to the object count and fully populated, so
    /// every group object has an entry — a missing one would read as
    /// "plain" rather than as an error.
    #[test]
    fn every_communication_object_has_an_entry() {
        let config = SecureConfig::create_security_config();
        assert_eq!(config.go_flags.count(), SecureConfig::NUM_COMM_OBJECTS as u16);
    }

    #[test]
    fn the_group_key_and_tool_key_survive_the_macro() {
        let config = SecureConfig::create_security_config();
        assert_eq!(config.tool_key, [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        ]);
        assert_eq!(config.grp_keys.count(), 1);
        let entry = config.grp_keys.get(0).expect("one group key");
        assert_eq!(&entry[..2], &1u16.to_be_bytes(), "keyed by TSAP");
        assert_eq!(&entry[2..], &[
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        ]);
    }

    /// Security Mode is off in a boot image; ETS turns it on during
    /// commissioning (06 Profiles §9.1.2.7 makes "enabled ex-factory"
    /// optional, and our devices do not).
    #[test]
    fn security_mode_is_off_in_the_boot_image() {
        assert!(!SecureConfig::create_security_config().security_mode_enabled);
    }
}
