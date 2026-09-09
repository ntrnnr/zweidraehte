//! Exercise the real group-data handlers against retained, invalid tables.

use core::cell::RefCell;

use crate::{
    DeviceDefinition, NoParams, Stack, StackDefinition, StackResources,
    bcus::system_b::{SystemBStateInit, Tp1},
    config::buffer_size_for_apdu,
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
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
use zweidraehte_ets_model::ets_com_objects;
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

struct AmbientDevice;

impl DeviceDefinition for AmbientDevice {
    const DEVICE: &'static DeviceDescriptor = &DEVICE;

    type Params = NoParams;
    type ComObjects = AmbientObjects;
    type LinkLayer = MockLinkLayerBuilder<1>;
}

type Definition = Tp1<AmbientDevice>;

fn stack() -> Stack<'static, Definition> {
    const BUFFER_SIZE: usize = buffer_size_for_apdu(<Definition as StackDefinition>::MAX_APDU_LENGTH);

    let resources = Box::leak(Box::new(StackResources::<Definition, BUFFER_SIZE, 4>::new()));
    let injection = Box::leak(Box::new(Channel::<NoopRawMutex, InjectedFrame, 1>::new()));
    let (link, _) = MockLinkLayerBuilder::new(injection);
    let (stack, _) = crate::new(
        resources,
        link,
        SystemBStateInit::new(StaticIdentity::new([0; 6]), None),
        (),
        Definition::memory_map(),
        (),
    );

    stack
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
fn unloaded_retained_tables_block_group_input_output_and_read_on_init() {
    use crate::{
        context::layer::LayerContext, layers::application::group_data::GroupDataProvider, objects::tables::TableMemory,
    };
    use zweidraehte_proto::messages::{
        apdu::group_value::GroupValueWriteRequest,
        buffers::BufferManager,
        builder::MessageBuilder,
        knx::{ApciCode, DestinationAddress, Priority, ServiceType},
    };

    for unloaded in 0..4 {
        let stack = stack();
        let state = stack.state();
        state.adt().borrow_mut().write(0, &[0, 1, 0x10, 1]);
        state.ast().borrow_mut().write(0, &[0, 1, 0, 1, 0, 1]);
        state.cot().borrow_mut().write(0, &[0, 2, 0xdf, 7, 0xdf, 0]);
        start_application(stack);
        load_tables(stack);

        let buffers = Box::leak(Box::new([[0u8; 128]; 4]));
        // SAFETY: both manager and backing memory live for the whole test run.
        let manager = Box::leak(Box::new(unsafe { BufferManager::new(buffers) }));
        let context = LayerContext::<Definition>::new(manager.dyn_buffer_manager(), ());
        let group = GroupDataProvider::new(state, &context);
        let frame = |value| {
            MessageBuilder::new_request(
                manager
                    .dyn_buffer_manager()
                    .try_alloc_with_size(GroupValueWriteRequest::full_msg_len(1))
                    .expect("small test pool"),
                ServiceType::T_GroupData_Ind,
                Priority::Low,
                DestinationAddress::ConnectionNr(1),
            )
            .with_application(ApciCode::GroupValueWrite)
            .with_data(|buffer| GroupValueWriteRequest::write_full(buffer, &[value]))
            .into_inner()
        };

        group.handle_write_or_response(&mut frame(99), ApciCode::GroupValueWrite);
        assert_eq!(u8::from(stack.objects().borrow().white.value), 99);

        match unloaded {
            0 => state.adt().borrow_mut().write_lsm(&[LoadEvent::Unload.into()], None),
            1 => state.ast().borrow_mut().write_lsm(&[LoadEvent::Unload.into()], None),
            2 => state.cot().borrow_mut().write_lsm(&[LoadEvent::Unload.into()], None),
            _ => state.app().borrow_mut().write_lsm(&[LoadEvent::Unload.into()], None),
        };

        group.handle_write_or_response(&mut frame(37), ApciCode::GroupValueWrite);
        assert_eq!(u8::from(stack.objects().borrow().white.value), 99, "unloaded resource {unloaded}");

        stack.objects().borrow_mut().white.status = ComObjectStatus::ReadRequest;
        group.send_group_value_request(0, true);
        assert_eq!(manager.dyn_buffer_manager().allocated_count(), 0, "unloaded resource {unloaded} must not send");

        stack.objects().borrow_mut().white.status = ComObjectStatus::Uninitialized;
        assert!(group.next_deadline().is_none(), "unloaded resource {unloaded} must not start ROI");

        // Completing loading reuses the retained configuration without a rewrite.
        load_tables(stack);
        start_application(stack);
        assert!(group.next_deadline().is_some());

        group.handle_write_or_response(&mut frame(37), ApciCode::GroupValueWrite);
        assert_eq!(u8::from(stack.objects().borrow().white.value), 37);

        stack.objects().borrow_mut().white.status = ComObjectStatus::ReadRequest;
        group.send_group_value_request(0, true);
        assert_eq!(manager.dyn_buffer_manager().allocated_count(), 1, "loaded configuration can send");
    }
}
