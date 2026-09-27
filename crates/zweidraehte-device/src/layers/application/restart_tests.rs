//! A_Restart of every standard TP1 preset, checked erase code by erase code
//! against the specification.
//!
//! Every request — the basic restart, and master resets with erase codes
//! 00h-08h and FEh — is issued by every caller class: plain at each legacy
//! level, and the Roles and the Tool with authentication only and with
//! confidentiality, with Security Mode off and on on the secure presets.
//! The outcome is compared with what the specification's tables give,
//! written out below independently of the code under test:
//!
//! - **Support:** 03/05/02 §3.7.1.2.3 Table 4 defines 01h-08h and reserves
//!   00h and 09h-FFh; 06 Profiles §9.1.2.5.1 excludes ResetIA (03h) and
//!   ResetAP (04h) from every Data Secure profile. 08h is optional and not
//!   implemented.
//! - **Access Policy:** AN193 v04 §2.2.4.3.
//! - **Legacy level:** device-defined (03/05/02 §3.7 Table 5). A restart
//!   that erases nothing is free, every erasing master reset needs level 0.
//!
//! The application layer takes the caller as an explicit `AccessContext`,
//! so the Roles need no point-to-point provisioning here; how the Secure
//! Application Layer classifies a frame is covered on the bus. A secure
//! preset's layer is built with `from_context`, the constructor the secure
//! wrapper uses, so it carries the definition's secure erase-code policy.

use core::marker::PhantomData;

use super::*;
use crate::{
    DeviceDefinition, NoParams, Rng,
    bcus::{
        system_7::{self, System7StateInit},
        system_b::{self, SystemBDeviceState, SystemBStateInit, Tp1ExtensionState},
    },
    layers::linklayers::mock::MockLinkLayerBuilder,
    objects::comm::NoComObjects,
    security::{SecureExtensionState, SecureResources},
    stack_core::StackCore,
    storage::{
        ConfigStoreBackend, HasDeviceConfig, SecureStorage, StaticIdentity, StaticSecureIdentity, kv::KeyValueStore,
        views::SiatStore,
    },
};
use zweidraehte_proto::{
    access::{ClientRole, SecurityMode},
    device::{DeviceDescriptor, MaskVersion},
    messages::{
        apdu::restart::{RestartParsed, RestartResponse},
        buffers::BufferManager,
        builder::MessageBuilder,
    },
};

// ============================================================================
// Presets
// ============================================================================

/// A key-value backend that stores nothing.
struct NoKv;

impl KeyValueStore for NoKv {
    type Error = core::convert::Infallible;

    fn get(&self, _namespace: u8, _key: &[u8], _buffer: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Ok(None)
    }

    fn put(&mut self, _namespace: u8, _key: &[u8], _value: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn remove(&mut self, _namespace: u8, _key: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn for_each(&self, _namespace: u8, _visitor: &mut dyn FnMut(&[u8], &[u8])) {}
}

/// A config store that never persists, for any device state `S`.
struct NoConfigStore<S>(PhantomData<fn() -> S>);

impl<S: HasDeviceConfig> ConfigStoreBackend for NoConfigStore<S> {
    type State = S;
    type Config = S::Config;
    type Error = core::convert::Infallible;

    fn snapshot(&self, state: &Self::State) -> Self::Config {
        state.to_config()
    }

    fn save(&mut self, _config: &Self::Config) -> Result<(), Self::Error> {
        Ok(())
    }

    fn load(&mut self) -> Option<Self::Config> {
        None
    }
}

type SequenceStore = SiatStore<NoKv, 4, 0>;

/// Deterministic stand-in for the platform RNG; secure stacks refuse `NoRng`.
struct TestRng;

impl Rng for TestRng {
    fn fill(buffer: &mut [u8]) {
        buffer.fill(0xA5);
    }
}

const FDSK: [u8; 16] = [0xAA; 16];
const COT_ADDRESS: u16 = 0x4200;

const fn descriptor(mask: MaskVersion) -> DeviceDescriptor {
    DeviceDescriptor::new(mask, 0x00FA, [0; 6], 0xF003, 0x01, 4, 4, 4, 0)
}

fn secure_identity() -> StaticSecureIdentity {
    StaticSecureIdentity::new([0x00, 0xFA, 0x01, 0x02, 0x03, 0x04], FDSK)
}

macro_rules! plain_definition {
    ($name:ident, $mask:expr) => {
        struct $name;

        impl DeviceDefinition for $name {
            const DEVICE: &'static DeviceDescriptor = &descriptor($mask);
            type Params = NoParams;
            type ComObjects = NoComObjects;
            type LinkLayer = MockLinkLayerBuilder<1>;
        }
    };
}

macro_rules! secure_definition {
    ($name:ident, $mask:expr, $storage:ident, $state:ty) => {
        struct $name;

        type $storage = SecureStorage<NoConfigStore<$state>, SequenceStore>;

        impl DeviceDefinition for $name {
            const DEVICE: &'static DeviceDescriptor = &descriptor($mask);
            type Rng = TestRng;
            type Params = NoParams;
            type ComObjects = NoComObjects;
            type LinkLayer = MockLinkLayerBuilder<1>;
            type Identity = StaticSecureIdentity;
            type Storage = &'static $storage;
        }
    };
}

// The System B secure state is spelled out with literal table sizes: the
// `SecureTp1StateFor` alias projects them through the stack, which the
// storage type the definition declares cannot name without a cycle.
const ADT: usize = descriptor(MaskVersion::SystemBTp1).address_table_size();
const AST: usize = descriptor(MaskVersion::SystemBTp1).association_table_size();
const COT: usize = descriptor(MaskVersion::SystemBTp1).comm_object_table_size();

plain_definition!(SystemBDevice, MaskVersion::SystemBTp1);
type SystemBTp1 = system_b::Tp1<SystemBDevice>;

secure_definition!(
    SecureSystemBDevice,
    MaskVersion::SystemBTp1,
    SecureSystemBStorage,
    SystemBDeviceState<ADT, AST, COT, SecureSystemBTp1, SecureExtensionState<Tp1ExtensionState, 4, 0, 4>>
);
type SecureSystemBTp1 = system_b::SecureTp1<SecureSystemBDevice>;

plain_definition!(System7Device, MaskVersion::System7Tp1);
type System7Tp1 = system_7::Tp1<System7Device, COT_ADDRESS>;

secure_definition!(
    SecureSystem7Device,
    MaskVersion::System7Tp1,
    SecureSystem7Storage,
    system_7::SecureTp1State<SecureSystem7Device, COT_ADDRESS>
);
type SecureSystem7Tp1 = system_7::SecureTp1<SecureSystem7Device, COT_ADDRESS>;

/// Build `D` as its runner would, with every part leaked for the test.
fn context<D: StackDefinition<Platform = ()>>(
    init: D::StateInit,
    storage: D::Storage,
    memory_map: D::Mem,
) -> (StackContext<'static, D>, &'static D::State) {
    let buffers = Box::leak(Box::new([[0u8; 64]; 4]));
    // SAFETY: the manager and its exclusive backing storage outlive the test.
    let manager = Box::leak(Box::new(unsafe { BufferManager::new(buffers) }));
    let lctx = Box::leak(Box::new(LayerContext::new(manager.dyn_buffer_manager(), storage)));
    let core = Box::leak(Box::new(StackCore::<D> {
        state: D::create_state(init),
        platform: (),
        memory_map,
        layer_context: lctx,
    }));
    let augments = Box::leak(Box::new(D::create_augments(&core.state, &core.platform, lctx)));
    let objects = Box::leak(Box::new(D::create_interface_objects(&core.state, &core.platform, lctx, augments)));

    (StackContext::new(core, objects), &core.state)
}

fn secure_storage<C: ConfigStoreBackend>(config: C) -> &'static SecureStorage<C, SequenceStore> {
    Box::leak(Box::new(SecureStorage::new(config, SequenceStore::boot(NoKv).expect("the empty backend cannot fail"))))
}

// ============================================================================
// The specification
// ============================================================================

#[derive(Clone, Copy, Debug)]
enum Request {
    /// restart_type 0: no erase code, no response.
    Basic,
    /// restart_type 1 with this erase code.
    Master(u8),
}

const REQUESTS: [Request; 11] = [
    Request::Basic,
    Request::Master(0x00),
    Request::Master(0x01),
    Request::Master(0x02),
    Request::Master(0x03),
    Request::Master(0x04),
    Request::Master(0x05),
    Request::Master(0x06),
    Request::Master(0x07),
    Request::Master(0x08),
    Request::Master(0xFE),
];

impl Request {
    /// 03/05/02 §3.7.1.2.3 Table 4 and 06 Profiles §9.1.2.5.1.
    fn supported(self, secure: bool) -> bool {
        match self {
            Self::Basic => true,
            Self::Master(0x01 | 0x02 | 0x05..=0x07) => true,
            Self::Master(0x03 | 0x04) => !secure,
            Self::Master(_) => false,
        }
    }

    /// AN193 v04 §2.2.4.3 as `(Security Mode off, on)`. AN193 omits 04h,
    /// which gets the other erasing master resets' `3FF/00C`.
    fn policy(self) -> (u16, u16) {
        match self {
            Self::Basic | Self::Master(0x01) => (0x3FF, 0x0CC),
            Self::Master(0x03) => (0x3FF, 0x000),
            Self::Master(_) => (0x3FF, 0x00C),
        }
    }

    /// Nothing erased is free; every erasing master reset needs level 0.
    fn required_level(self, max_levels: u8) -> u8 {
        match self {
            Self::Basic | Self::Master(0x01) => max_levels - 1,
            Self::Master(_) => 0,
        }
    }

    /// What the server must answer, or `None` for the unanswered basic
    /// restart; and whether the restart is carried out.
    fn expected(
        self,
        ctx: &AccessContext,
        security_mode: bool,
        secure: bool,
        max_levels: u8,
    ) -> (Option<RestartError>, bool) {
        let answer = if !self.supported(secure) {
            RestartError::UnsupportedEraseCode
        } else if !permits(self.policy(), ctx, security_mode) || ctx.access_level > self.required_level(max_levels) {
            RestartError::AccessDenied
        } else {
            RestartError::NoError
        };
        let executed = answer == RestartError::NoError;
        match self {
            Self::Basic => (None, executed),
            Self::Master(_) => (Some(answer), executed),
        }
    }
}

/// Whether the caller's W bit is set, in the notation of 03/04/01 §6.2
/// Table 3: ten bits, most significant first, in the W/R pairs Unlisted,
/// Role A+C, Role A, Tool A+C, Tool A.
fn permits((off, on): (u16, u16), ctx: &AccessContext, security_mode: bool) -> bool {
    let write_bit = match (ctx.role, ctx.security) {
        (_, SecurityMode::Plain) | (ClientRole::Unlisted, _) => 9,
        (ClientRole::Roles(_), SecurityMode::AuthConf) => 7,
        (ClientRole::Roles(_), SecurityMode::AuthOnly) => 5,
        (ClientRole::Tool, SecurityMode::AuthConf) => 3,
        (ClientRole::Tool, SecurityMode::AuthOnly) => 1,
    };
    let half = if security_mode { on } else { off };
    half & (1 << write_bit) != 0
}

/// Every caller class: plain at each legacy level and, on a secure preset,
/// the Roles and the Tool (secured requests carry level 0).
fn callers(max_levels: u8, secure: bool) -> Vec<AccessContext> {
    let mut callers: Vec<AccessContext> = (0..max_levels).map(AccessContext::new).collect();
    if secure {
        for role in [ClientRole::Roles(0x0001), ClientRole::Tool] {
            for security in [SecurityMode::AuthOnly, SecurityMode::AuthConf] {
                callers.push(AccessContext::with_security(0, security, role));
            }
        }
    }
    callers
}

// ============================================================================
// The checks
// ============================================================================

fn send<D: StackDefinition>(al: &mut ApplicationLayer<'_, D>, request: Request, channel: u8, ctx: AccessContext) {
    let len = match request {
        Request::Basic => RestartParsed::BASIC_MIN_MSG_LEN,
        Request::Master(_) => RestartParsed::MASTER_MIN_MSG_LEN,
    };
    let mut message = MessageBuilder::new_request(
        al.buffer_manager().try_alloc_with_size(len).expect("one request and response fit the pool"),
        ServiceType::T_DataUnack_Ind,
        Priority::Low,
        DestinationAddress::ConnectionNr(1),
    )
    .with_application(ApciCode::Restart)
    .with_data(|buf| {
        if let Request::Master(code) = request {
            RestartParsed::write_master_reset(buf, code.into(), channel);
        }
    })
    .into_inner();
    message.set_access_source(AccessSource::Explicit(ctx));

    al.process(message);
}

/// Every request by every caller in every Security Mode.
fn check<D: StackDefinition>(
    name: &str,
    al: &mut ApplicationLayer<'_, D>,
    secure: bool,
    set_security_mode: &dyn Fn(bool),
) {
    let max_levels = al.state.max_access_levels();
    let security_modes: &[bool] = if secure { &[false, true] } else { &[false] };
    let mut failures = Vec::new();

    for &security_mode in security_modes {
        set_security_mode(security_mode);
        for ctx in callers(max_levels, secure) {
            for request in REQUESTS {
                send(al, request, 0, ctx);

                let response = al.lctx.outbox.borrow_mut().take_next();
                let answer = response.map(|response| RestartResponse::parse(response.buf()).map(|(error, _)| error));
                let executed = al.lctx.restart_channel.try_receive().is_ok();

                let (expected_answer, expected_executed) = request.expected(&ctx, security_mode, secure, max_levels);
                if answer != expected_answer.map(Some) || executed != expected_executed {
                    failures.push(format!(
                        "{request:?} by {ctx:?}, Security Mode {security_mode}: answered {answer:?}, executed \
                         {executed}; expected {expected_answer:?}, executed {expected_executed}"
                    ));
                }
            }
        }
    }
    set_security_mode(false);

    assert!(failures.is_empty(), "{name}: {} failure(s)\n  {}", failures.len(), failures.join("\n  "));
}

#[test]
fn system_b_tp1() {
    let (ctx, _) =
        context::<SystemBTp1>(SystemBStateInit::new(StaticIdentity::new([0; 6]), None), (), SystemBTp1::memory_map());
    check("System B TP1", &mut ApplicationLayer::new(&ctx), false, &|_| {});
}

#[test]
fn system_b_secure_tp1() {
    let init =
        SystemBStateInit { identity: secure_identity(), loaded_config: None, resources: SecureResources::simple(FDSK) };
    let (ctx, state) =
        context::<SecureSystemBTp1>(init, secure_storage(NoConfigStore(PhantomData)), SecureSystemBTp1::memory_map());
    let set = |on| state.extension_state().security.set_security_mode_enabled(on);
    check("System B secure TP1", &mut ApplicationLayer::from_context(&ctx), true, &set);
}

#[test]
fn system_7_tp1() {
    let (ctx, _) =
        context::<System7Tp1>(System7StateInit::new(StaticIdentity::new([0; 6]), None), (), System7Tp1::memory_map());
    check("System 7 TP1", &mut ApplicationLayer::new(&ctx), false, &|_| {});
}

#[test]
fn system_7_secure_tp1() {
    let init =
        System7StateInit { identity: secure_identity(), loaded_config: None, resources: SecureResources::simple(FDSK) };
    let (ctx, state) =
        context::<SecureSystem7Tp1>(init, secure_storage(NoConfigStore(PhantomData)), SecureSystem7Tp1::memory_map());
    let set = |on| state.extension_state().security.set_security_mode_enabled(on);
    check("System 7 secure TP1", &mut ApplicationLayer::from_context(&ctx), true, &set);
}

/// Support precedes the channel, and the channel precedes access: an
/// unsupported code with a bad channel is unsupported, and a supported one
/// with a bad channel is refused for the channel even when access would be
/// denied.
#[test]
fn plain_profile_preserves_validation_order() {
    let (ctx, _) =
        context::<SystemBTp1>(SystemBStateInit::new(StaticIdentity::new([0; 6]), None), (), SystemBTp1::memory_map());
    let mut al = ApplicationLayer::new(&ctx);

    for (request, channel, level, expected) in [
        (Request::Master(0xFE), 1, 3, RestartError::UnsupportedEraseCode),
        (Request::Master(0x04), 1, 0, RestartError::InvalidChannel),
        (Request::Master(0x04), 1, 3, RestartError::InvalidChannel),
        (Request::Master(0x04), 0, 3, RestartError::AccessDenied),
    ] {
        send(&mut al, request, channel, AccessContext::new(level));
        let response = al.lctx.outbox.borrow_mut().take_next().expect("master reset has a response");
        assert_eq!(RestartResponse::parse(response.buf()), Some((expected, 0)), "{request:?} channel {channel}");
        assert!(al.lctx.restart_channel.try_receive().is_err(), "a rejected restart has no side effect");
    }
}
