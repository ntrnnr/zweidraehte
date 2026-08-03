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
        // [len=1][IA 1.0.1][GA 0/0/1]
        MAP.write(&state, 0x4000, &[0x01, 0x10, 0x01, 0x00, 0x01], CTX).expect("table blob write");
        assert_eq!(state.adt.borrow().entry_count(), 1);
        assert_eq!(state.individual_address(), IndividualAddress::from_bytes(&[0x10, 0x01]));
    }

    /// The load-control window drives the per-machine LSMs; their state
    /// reads back at B6EAh-B6EDh.
    #[test]
    fn load_control_window_drives_the_lsms() {
        let state = fresh_state();
        assert_eq!(read1(&state, 0xB6EA), u8::from(LoadState::Unloaded));

        // Machine 1 (ADT): StartLoading, then AllocAbsDataSeg at 4000h.
        MAP.write(&state, 0x0104, &[0x11], CTX).expect("start loading");
        assert_eq!(read1(&state, 0xB6EA), u8::from(LoadState::Loading));
        MAP.write(&state, 0x0104, &[0x13, 0x00, 0x40, 0x00, 0x00, 0x09, 0xFF, 0x03, 0x80, 0x00], CTX)
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

        // Machine 2 (AST): StartLoading + AllocAbsDataSeg at 4100h.
        MAP.write(&state, 0x0104, &[0x21], CTX).expect("ast start");
        MAP.write(&state, 0x0104, &[0x23, 0x00, 0x41, 0x00, 0x00, 0x07, 0xFF, 0x03, 0x80, 0x00], CTX)
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

        // Roster: exactly the five fixed-index objects, AppProg2 as
        // InterfaceProgram (Type 4) at index 4.
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
            ctx: AccessContext::new(15),
        };
        let mut buf = [0u8; 4];
        let len = objects.property_value_read(&read, &mut buf).expect("device descriptor readable");
        assert_eq!(&buf[..len], &0x0705u16.to_be_bytes());

        // Descriptors carry the 16-level access model: everyone = 15.
        let desc = objects.property_description_read(0, pid::DEVICE_CONTROL, 0).expect("device control described");
        assert_eq!(desc.read_level, 15);
        assert_eq!(desc.write_level, 1);

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

        // A level-15 caller may read everywhere but not drive the LSM
        // (write level 2 on the table objects).
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
    use zweidraehte_device::objects::tables::{AddressTable, AssociationTable};
    use zweidraehte_proto::address::GroupAddress;

    zweidraehte_device::system7_stack_config! {
        name: MacroConfig,
        individual_address: "1.0.5",
        group_addresses: {
            1 => "0/0/1",
            2 => "0/0/2",
        },
        comm_objects: {
            0 => (1, zweidraehte_device::config::CE | zweidraehte_device::config::TE),
            1 => (1, zweidraehte_device::config::CE | zweidraehte_device::config::WE),
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
        tl_style: TlStyle::Style3,
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
