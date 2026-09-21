#![cfg(feature = "tp1")]
#![feature(min_adt_const_params)]

//! Application consumption uses the generated field type and keeps protocol
//! state intact while hiding container borrows and update acknowledgement.

use core::cell::RefCell;

use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
use zweidraehte_device::{
    DeviceDefinition, NoParams, Stack, StackResources,
    bcus::system_b::{SystemBStateInit, Tp1},
    layers::linklayers::mock::{InjectedFrame, MockLinkLayerBuilder},
    objects::{
        comm::ComObjectStatus,
        tables::{
            HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasLoadStateMachine,
            HasRunStateMachine, LoadEvent, RunEvent,
        },
    },
    storage::StaticIdentity,
};
use zweidraehte_ets_model::ets_com_objects;
use zweidraehte_proto::messages::buffers::BufferManager;
use zweidraehte_proto::{
    device::{DeviceDescriptor, MaskVersion},
    dpt::{DPT_Scaling, DPT_Switch},
};

#[ets_com_objects]
pub struct AmbientObjects {
    #[ets(index = 0, flags = C | W | R | LOW)]
    pub white: DPT_Scaling,

    #[ets(index = 1, flags = C | W | R | LOW)]
    pub enabled: DPT_Switch,
}

const DEVICE: DeviceDescriptor = DeviceDescriptor::new(MaskVersion::SystemBTp1, 0x00FA, [0; 6], 0xF001, 1, 2, 2, 2, 0);

// Extra storage exercises BUFFER_SIZE forwarding independently of the APDU limit.
struct AmbientDevice<const BUFFER_BYTES: usize = 320>;

impl<const BUFFER_BYTES: usize> DeviceDefinition for AmbientDevice<BUFFER_BYTES> {
    type Buffers = BufferManager<4>;
    const DEVICE: &'static DeviceDescriptor = &DEVICE;
    const BUFFER_SIZE: usize = BUFFER_BYTES;

    type Params = NoParams;
    type ComObjects = AmbientObjects;
    type LinkLayer = MockLinkLayerBuilder<1>;
}

type Definition = Tp1<AmbientDevice>;

fn stack() -> Stack<'static, Definition> {
    let resources = Box::leak(Box::new(StackResources::<Definition>::new()));
    let injection = Box::leak(Box::new(Channel::<NoopRawMutex, InjectedFrame, 1>::new()));
    let (link, _) = MockLinkLayerBuilder::new(injection);
    let (stack, _) = zweidraehte_device::new(
        resources,
        link,
        SystemBStateInit::new(StaticIdentity::new([0; 6]), None),
        (),
        Definition::memory_map(),
        (),
    );

    // The authoring definition's capacity must reach the preset and factory.
    assert_eq!(stack.buffer_pool_status().1, 4);

    stack
}

#[test]
#[should_panic(expected = "buffer size must cover the device's maximum APDU and framing")]
fn undersized_definition_cannot_back_the_advertised_apdu_limit() {
    let _ = StackResources::<Tp1<AmbientDevice<16>>>::new();
}

#[test]
fn resources_use_the_definitions_buffer_size() {
    // The type assertion catches a preset or resource default recomputing the
    // minimum size instead of preserving the device's explicit storage choice.
    let _: StackResources<Definition, 320> = StackResources::<Definition>::new();
}

#[test]
#[should_panic(expected = "buffer size must match StackDefinition::BUFFER_SIZE")]
fn resource_size_cannot_override_the_definition() {
    let _ = StackResources::<Definition, 384>::new();
}

fn load<T: HasLoadStateMachine>(resource: &RefCell<T>) {
    let mut resource = resource.borrow_mut();

    resource.write_lsm(&[LoadEvent::StartLoading.into()], None);
    resource.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
}

fn start_application(stack: Stack<'_, Definition>) {
    let state = stack.state();

    load(state.app());
    state.app().borrow_mut().handle_run_event(RunEvent::Loaded);
    state.app().borrow_mut().handle_run_event(RunEvent::ReadyToRun);
}

fn load_tables(stack: Stack<'_, Definition>) {
    let state = stack.state();

    load(state.adt());
    load(state.ast());
    load(state.cot());
}

#[test]
fn consumption_returns_an_owned_typed_value_and_acknowledges_only_that_object() {
    let stack = stack();
    start_application(stack);
    load_tables(stack);

    {
        let mut objects = stack.objects().borrow_mut();
        objects.white.value = 255.into();
        objects.white.status = ComObjectStatus::Updated;
        objects.enabled.value = true.into();
        objects.enabled.status = ComObjectStatus::Updated;
    }

    let value: DPT_Scaling = stack.consume_object(|objects| &mut objects.white).expect("application operational");

    // A new mutable borrow proves the returned value owns its data. Consuming
    // an update must retain the commanded value for subsequent KNX reads.
    let mut objects = stack.objects().borrow_mut();
    assert_eq!(u8::from(objects.white.value), 255);
    assert_eq!(objects.white.status, ComObjectStatus::IdleOk);
    assert_eq!(objects.enabled.status, ComObjectStatus::Updated);

    objects.white.value = 42.into();

    assert_eq!(u8::from(value), 255);
}

#[test]
fn first_download_and_table_unload_make_values_unavailable_without_consuming_them() {
    let stack = stack();

    {
        let mut objects = stack.objects().borrow_mut();
        objects.white.value = 128.into();
        objects.white.status = ComObjectStatus::Updated;
    }

    assert!(stack.consume_object(|objects| &mut objects.white).is_none());

    start_application(stack);
    assert!(stack.is_running(), "APP alone can run before the tables are loaded");
    assert!(stack.consume_object(|objects| &mut objects.white).is_none());
    assert_eq!(stack.objects().borrow().white.status, ComObjectStatus::Updated);

    load_tables(stack);

    assert_eq!(stack.consume_object(|objects| &mut objects.white).map(u8::from), Some(128));

    stack.state().ast().borrow_mut().write_lsm(&[LoadEvent::Unload.into()], None);
    stack.objects().borrow_mut().white.status = ComObjectStatus::Updated;

    assert!(stack.is_running(), "table unload does not rewrite the APP run state");
    assert_eq!(stack.consume_object(|objects| &mut objects.white).map_or(0, u8::from), 0);
    assert_eq!(stack.objects().borrow().white.status, ComObjectStatus::Updated);
    assert_eq!(u8::from(stack.objects().borrow().white.value), 128);

    load(stack.state().ast());

    assert_eq!(stack.consume_object(|objects| &mut objects.white).map(u8::from), Some(128));
}

#[test]
fn repeated_consumption_keeps_read_and_transmission_statuses() {
    let stack = stack();
    start_application(stack);
    load_tables(stack);

    for status in [ComObjectStatus::ReadRequest, ComObjectStatus::Busy, ComObjectStatus::WriteRequestError] {
        stack.objects().borrow_mut().white.status = status;

        // Zero is a valid value, including before the first brightness telegram.
        for _ in 0..2 {
            assert_eq!(stack.consume_object(|objects| &mut objects.white).map(u8::from), Some(0));
            assert_eq!(stack.objects().borrow().white.status, status);
        }
    }
}
