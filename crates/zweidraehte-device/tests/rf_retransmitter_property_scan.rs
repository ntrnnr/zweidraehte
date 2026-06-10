//! Drives the merged `A_PropertyDescription_Read` ByIndex scan for an
//! RF-retransmitter device end to end.
//!
//! # What this covers
//!
//! The Tier-4 composition work made it possible for two augments to contribute
//! property descriptors to one interface object: `RfRetransmitterAugmentBundle`
//! composes the base [`RfAugment`] (RF Medium Object PID 1 / PID 56) with
//! [`RfRetransmitterAugment`] (RF Medium PID 57, plus an intercept of Device
//! Object PID 74). The `#[derive(ServiceRegistry)]` codegen merges the two
//! augments' descriptors into one property-index space, rebasing the
//! index-based scan per augment so the RF Medium Object enumerates PID 1, 56,
//! 57 in order even though the descriptors live in two different augments.
//!
//! That merge is type-checked and unit-tested at the `DESCRIPTORS`-table level
//! (`extensions/rf/retransmitter.rs` `pids_for` tests), but until now nothing
//! drove the actual [`PropertyServiceHandler::property_description_read`]
//! dispatch at runtime — there is no KNX-RF conformance DUT, and the
//! conformance harness only ships TP1 stacks. This test closes that gap with a
//! focused in-crate construction: a real [`SystemBObjects`] container built
//! over an RF-retransmitter device state, queried directly.
//!
//! # Why no forwarding boilerplate is needed
//!
//! `SystemBDeviceState<ADT, AST, COT, D, ES>` already implements every trait
//! [`create_system_b_objects`] requires (the table accessors, `StackState`,
//! `DeviceModelNotifier`, the RF accessors, …) generically over `ES`. So the
//! test uses `SystemBDeviceState<…, RfRetransmitterExtension>` *directly* as
//! the stack's `State`, with zero hand-written forwarding impls.
//!
//! [`RfAugment`]: zweidraehte_device::bcus::system_b::RfAugment

use const_default::ConstDefault;
use static_cell::StaticCell;

use zweidraehte_device::InsecureDeviceBuilder;
use zweidraehte_device::StackDefinition;
use zweidraehte_device::bcus::system_b::{
    ExtensionAugmentFor, MemoryLayout, RfRetransmitterExtension, SystemBDeviceState, SystemBInterfaceObjectsFor,
    SystemBMemoryMap, SystemBStackDefinition, create_system_b_objects,
};
use zweidraehte_device::context::layer::LayerContext;
use zweidraehte_device::layers::linklayers::mock::MockLinkLayerBuilder;
use zweidraehte_device::layers::transport::TlStyle;
use zweidraehte_device::objects::comm::{
    ComObjectBusHook, ComObjectIndex, ComObjectInfo, ComObjectInfoMut, ComObjects,
};
use zweidraehte_device::objects::interface::{PropertyServiceHandler, pid};
use zweidraehte_device::storage::StaticIdentity;

use zerocopy::{Immutable, IntoBytes, KnownLayout};
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};
use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};
use zweidraehte_proto::properties::PropertyError;

// ============================================================================
// Minimal device descriptor — System B KNX-RF, no tables, no comm objects.
// ============================================================================

const RF_DEVICE: DeviceDescriptor = DeviceDescriptor::new(
    MaskVersion::SystemBRf, // 0x27B0 — pulls in the RF Medium Object
    0x00FA,                 // arbitrary manufacturer id
    [0u8; 6],               // hardware type
    0xF001,                 // application id
    0x01,                   // application version
    1,                      // max address table entries (minimal)
    1,                      // max association table entries
    1,                      // max comm objects
    0,                      // pei type
);

// Table sizes (byte lengths) derived from the descriptor; minimal but valid.
const ADT: usize = RF_DEVICE.address_table_size();
const AST: usize = RF_DEVICE.association_table_size();
const COT: usize = RF_DEVICE.comm_object_table_size();

// ============================================================================
// Zero-comm-object placeholder.
// ============================================================================
//
// `property_description_read` never touches comm objects, so `info`/`info_mut`
// are unreachable — they exist only to satisfy the `ComObjects` bound. The
// index type is uninhabited (no valid comm-object indices exist), mirroring the
// empty-CO pattern used by the IP Interface device.

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
        // The property-description test has no comm objects.
        None
    }

    fn info_mut(&mut self, _idx: u16) -> Option<ComObjectInfoMut<'_>> {
        None
    }
}

// Both bus-hook methods default to no-ops.
impl ComObjectBusHook for NoCo {}

// ============================================================================
// Trivial parameters.
// ============================================================================

#[derive(Clone, serde::Serialize, serde::Deserialize, IntoBytes, KnownLayout, Immutable)]
struct NoParams;

impl ConstDefault for NoParams {
    const DEFAULT: Self = NoParams;
}

// ============================================================================
// The test stack definition.
// ============================================================================
//
// Only the interface-object surface matters here; the async router and the link
// layer are never constructed. `type LLB = MockLinkLayerBuilder` satisfies the
// bound with a context-generic `LinkLayerBuilder` impl and is never built.

#[derive(Clone, Copy)]
struct RfTestStack;

type RfTestState = SystemBDeviceState<ADT, AST, COT, RfTestStack, RfRetransmitterExtension>;

impl SystemBStackDefinition for RfTestStack {}

impl StackDefinition for RfTestStack {
    const DEVICE: &'static DeviceDescriptor = &RF_DEVICE;
    const TL_STYLE: TlStyle = TlStyle::Style1;

    type P = NoParams;
    type CO = NoCo;
    type LLB = MockLinkLayerBuilder<1>;
    type ES = RfRetransmitterExtension;
    type State = RfTestState;
    type StateInit = ();
    type Mem = SystemBMemoryMap;

    fn create_state(_init: ()) -> Self::State {
        // `RfRetransmitterExtension::Resources = ()`; identity is irrelevant to
        // the property-description surface, so any serial number works.
        SystemBDeviceState::new(StaticIdentity::new([0u8; 6]), NoCo::new(), ())
    }

    type InterfaceObjects<'a> = SystemBInterfaceObjectsFor<'a, Self>;
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
        create_system_b_objects::<Self, _>(state, layer_ctx, &RF_MEMORY_LAYOUT, augments)
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
        use zweidraehte_device::bcus::system_b::Extension;
        state.extension_state().create_augment::<Self>(platform)
    }

    type AlExtensions = ();
    type LayerBuilder = InsecureDeviceBuilder;
}

const RF_MEMORY_LAYOUT: MemoryLayout = MemoryLayout::calculate(0x0100, 0, 0, 0, 0);

// ============================================================================
// The test.
// ============================================================================
//
// All assertions live in one function: the buffer manager lives in a
// `StaticCell`, whose `init` panics on a second call, so the stack is built
// exactly once.

#[test]
fn rf_medium_object_index_scan_spans_both_augments() {
    // A `LayerContext` needs a `DynBufferManager<'static>`; back it with a
    // `StaticCell` so the buffer pool genuinely outlives the borrow. None of
    // these buffers are actually drawn from during a property-description read.
    static BUFFERS: StaticCell<[[u8; 64]; 4]> = StaticCell::new();
    static BUF_MGR: StaticCell<BufferManager<4>> = StaticCell::new();

    let buffers = BUFFERS.init([[0u8; 64]; 4]);
    // SAFETY: single-threaded test, buffers live for the whole test.
    let buffer_manager = BUF_MGR.init(unsafe { BufferManager::new(buffers) });
    let dyn_bm = buffer_manager.dyn_buffer_manager();
    // SAFETY: the buffer manager lives in a StaticCell ('static); the borrow it
    // hands out is therefore also valid for 'static. Mirrors the conformance DUT.
    let dyn_bm: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_bm) };

    let lctx = LayerContext::<RfTestStack>::new(dyn_bm);
    let state = RfTestStack::create_state(());
    let augments = RfTestStack::create_augments(&state, &(), &lctx);
    let objects = RfTestStack::create_interface_objects(&state, &(), &lctx, &augments);

    // ------------------------------------------------------------------------
    // Object-index layout: base objects occupy 0..=5 (Device, AddressTable,
    // AssociationTable, GroupObjectTable, ApplicationProgram, PeiProgram). The
    // RF Medium Object is the first augment-provided object, at index 6.
    // ------------------------------------------------------------------------
    const RF_MEDIUM_OBJECT_IDX: u16 = 6;
    const DEVICE_OBJECT_IDX: u16 = 0;

    // --- RF Medium Object, ByIndex scan (prop_id == 0) ----------------------
    // This is the path that exercises the cross-augment index merge: indices 0
    // and 1 resolve inside `RfAugment`, index 2 rebases into
    // `RfRetransmitterAugment`.
    let p0 = objects.property_description_read(RF_MEDIUM_OBJECT_IDX, 0, 0).expect("RF Medium index 0");
    assert_eq!(p0.prop_id, pid::OBJECT_TYPE, "RF Medium index 0 → OBJECT_TYPE (PID 1)");
    assert_eq!(p0.prop_idx, 0);

    let p1 = objects.property_description_read(RF_MEDIUM_OBJECT_IDX, 0, 1).expect("RF Medium index 1");
    assert_eq!(p1.prop_id, pid::rf::RF_DOMAIN_ADDRESS, "RF Medium index 1 → RF_DOMAIN_ADDRESS (PID 56)");
    assert_eq!(p1.prop_idx, 1);

    let p2 = objects.property_description_read(RF_MEDIUM_OBJECT_IDX, 0, 2).expect("RF Medium index 2");
    assert_eq!(
        p2.prop_id,
        pid::rf::RF_RETRANSMITTER,
        "RF Medium index 2 → RF_RETRANSMITTER (PID 57), the second augment's descriptor"
    );
    assert_eq!(p2.prop_idx, 2);

    // Index 3 is past the merged table — the scan must terminate cleanly.
    // (`PropertyDescriptionResponse` is not `PartialEq`, so match on the error.)
    match objects.property_description_read(RF_MEDIUM_OBJECT_IDX, 0, 3) {
        Err(PropertyError::InvalidPropertyId) => {}
        other => panic!("RF Medium index 3 should be past both augments, got {other:?}"),
    }

    // --- RF Medium Object, ByPid (prop_id != 0) -----------------------------
    // PID 57 lives in the *second* augment; a by-PID lookup must still find it
    // through the bundle's or_else chain.
    let by_pid = objects
        .property_description_read(RF_MEDIUM_OBJECT_IDX, pid::rf::RF_RETRANSMITTER, 0)
        .expect("RF Medium PID 57 by id");
    assert_eq!(by_pid.prop_id, pid::rf::RF_RETRANSMITTER);
    assert_eq!(by_pid.object_idx, RF_MEDIUM_OBJECT_IDX);

    // --- Device Object intercept, ByPid -------------------------------------
    // The retransmitter augment intercepts PID 74 on the base Device Object.
    let repeat_counter = objects
        .property_description_read(DEVICE_OBJECT_IDX, pid::device::RF_REPEAT_COUNTER, 0)
        .expect("Device Object PID 74 by id");
    assert_eq!(repeat_counter.prop_id, pid::device::RF_REPEAT_COUNTER, "Device PID 74 → RF_REPEAT_COUNTER");
    assert_eq!(repeat_counter.object_idx, DEVICE_OBJECT_IDX);
}
