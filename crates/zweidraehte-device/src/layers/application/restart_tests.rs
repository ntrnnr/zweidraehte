//! Exercise plain-profile restart responses and application side effects.
//! The secure DUT is covered by conformance M-2.9 and 3.7.2.9, with Security
//! Mode off and on respectively, through the real secure wrapper.

use super::*;
use crate::{
    DeviceDefinition, NoParams,
    bcus::system_b::{SystemBStateInit, Tp1},
    layers::linklayers::mock::MockLinkLayerBuilder,
    objects::comm::NoComObjects,
    stack_core::StackCore,
    storage::StaticIdentity,
};
use zweidraehte_proto::{
    device::{DeviceDescriptor, MaskVersion},
    messages::{
        apdu::restart::{RestartParsed, RestartResponse},
        buffers::BufferManager,
        builder::MessageBuilder,
    },
};

const DEVICE: DeviceDescriptor = DeviceDescriptor::new(MaskVersion::SystemBTp1, 0x00FA, [0; 6], 1, 1, 2, 2, 2, 0);

struct RestartDevice;

impl DeviceDefinition for RestartDevice {
    const DEVICE: &'static DeviceDescriptor = &DEVICE;
    type Params = NoParams;
    type ComObjects = NoComObjects;
    type LinkLayer = MockLinkLayerBuilder<1>;
}

type Definition = Tp1<RestartDevice>;

fn context() -> StackContext<'static, Definition> {
    let buffers = Box::leak(Box::new([[0u8; 64]; 4]));
    // SAFETY: the manager and its exclusive backing storage outlive the test.
    let manager = Box::leak(Box::new(unsafe { BufferManager::new(buffers) }));
    let lctx = Box::leak(Box::new(LayerContext::new(manager.dyn_buffer_manager(), ())));
    let core = Box::leak(Box::new(StackCore::<Definition> {
        state: Definition::create_state(SystemBStateInit::new(StaticIdentity::new([0; 6]), None)),
        platform: (),
        memory_map: Definition::memory_map(),
        layer_context: lctx,
    }));
    let augments = Box::leak(Box::new(Definition::create_augments(&core.state, &(), lctx)));
    let objects = Box::leak(Box::new(Definition::create_interface_objects(&core.state, &(), lctx, augments)));

    StackContext::new(core, objects)
}

fn check_restart(
    al: &mut ApplicationLayer<'_, Definition>,
    code: EraseCode,
    channel: u8,
    access_level: u8,
    expected: RestartError,
) {
    let mut request = MessageBuilder::new_request(
        al.buffer_manager()
            .try_alloc_with_size(RestartParsed::MASTER_MIN_MSG_LEN)
            .expect("one request and response fit the pool"),
        ServiceType::T_DataUnack_Ind,
        Priority::Low,
        DestinationAddress::ConnectionNr(1),
    )
    .with_application(ApciCode::Restart)
    .with_data(|buf| RestartParsed::write_master_reset(buf, code, channel))
    .into_inner();
    request.set_access_source(AccessSource::Explicit(AccessContext::new(access_level)));

    al.process(request);

    let response = al.lctx.outbox.borrow_mut().take_next().expect("master reset has a response");
    assert_eq!(RestartResponse::parse(response.buf()), Some((expected, 0)), "{code:?}");
    let queued = al.lctx.restart_channel.try_receive();
    if expected == RestartError::NoError {
        let queued = queued.expect("accepted restart reaches the application");
        assert_eq!(queued.erase_code, code);
        assert_eq!(queued.channel, channel);
    } else {
        assert!(queued.is_err(), "rejected restart must have no application side effect");
    }
}

#[test]
fn plain_profile_accepts_known_codes_and_preserves_validation_order() {
    let ctx = context();
    let mut al = ApplicationLayer::new(&ctx);
    assert!(!al.state.security_mode_enabled());

    for code in 1..=7 {
        check_restart(&mut al, code.into(), 0, 0, RestartError::NoError);
    }
    check_restart(&mut al, EraseCode::Other(0xFE), 1, 15, RestartError::UnsupportedEraseCode);
    check_restart(&mut al, EraseCode::ResetAP, 1, 0, RestartError::InvalidChannel);
    check_restart(&mut al, EraseCode::ResetAP, 0, 15, RestartError::AccessDenied);
}
