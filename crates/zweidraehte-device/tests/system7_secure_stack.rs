//! A System 7 device with KNX Data Secure assembles.
//!
//! KNX Data Security is a profile module (06 Profiles v02.02.01 §9.1)
//! composed onto a base profile, and every piece of machinery it needs
//! — `SecureApplicationLayer`, `SecureDeviceBuilder`,
//! `SecureExtensionState`, `SecurityAugment`, `SiatStore`,
//! `SecureStorage` — is family-neutral. What this pins is that the
//! *composition* holds for System 7 too: the `SecureDeviceBuilder`
//! bounds are satisfiable by `System7DeviceState`, the
//! `system_7_standard_stack!` `resources:` and `augments:` slots carry
//! what a secure device needs, and the object roster comes out the way
//! §9.1.2.6.1 and §9.2.1.1.1.1 require.
//!
//! The stack is never run — the link layer and router are not
//! constructed. Everything here is either a type-level assertion or a
//! read off a constructed object container.

#![allow(dead_code)]

use const_default::ConstDefault;
use zerocopy::{Immutable, IntoBytes, KnownLayout};

use zweidraehte_device::bcus::system_7::{
    SecureTp1StateFor7, System7StackDefinition, System7StateInit, Tp1Augment, Tp1ExtensionState,
};
use zweidraehte_device::bcus::system_b::{DiagnosticsAugment, GroupObjectTableAugment, WithSecureGoSend};
use zweidraehte_device::context::layer::LayerContext;
use zweidraehte_device::layers::application::services::StandardSecureAlServices;
use zweidraehte_device::layers::linklayers::mock::MockLinkLayerBuilder;
use zweidraehte_device::layers::transport::TlStyle;
use zweidraehte_device::objects::comm::{
    ComObjectBusHook, ComObjectIndex, ComObjectInfo, ComObjectInfoMut, ComObjects,
};
use zweidraehte_device::security::{SecureAugmentBundle, SecureResources};
use zweidraehte_device::service::{Augment, ServiceRegistry};
use zweidraehte_device::storage::kv::KeyValueStore;
use zweidraehte_device::storage::views::SiatStore;
use zweidraehte_device::storage::{ConfigStoreBackend, HasDeviceConfig, SecureStorage, StaticSecureIdentity};
use zweidraehte_device::{HasSecurityState, SecureDeviceBuilder, StackDefinition};
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};
use zweidraehte_proto::dpt::InterfaceObjectType;

// ============================================================================
// Device: System 7 TP1, Data Secure, group-only (no P2P partners)
// ============================================================================

const S7_SECURE_DEVICE: DeviceDescriptor = DeviceDescriptor::new(
    MaskVersion::System7Tp1, // 0x0705 — Data Secure is not in the mask
    0x00FA,
    [0u8; 6],
    0xF003,
    0x01,
    4, // max address table entries
    4, // max association table entries
    4, // max comm objects
    0, // pei type
);

/// §9.1.2.6.4 footnote c: the P2P Key Table is only mandatory when P2P
/// communication uses a key other than the Tool Key or the FDSK. A
/// group-only device compiles it to zero width.
const P2P_SIZE: usize = 0;

/// SIAT capacity — one Last Valid SeqNr slot per non-tool secure sender
/// (03/03/07 §5.3), which includes group-only senders.
const SIAT_SIZE: usize = 4;

// ----------------------------------------------------------------------------
// Test doubles for the platform-shaped slots
// ----------------------------------------------------------------------------

/// The emptiest possible key-value backend; the assertions never read
/// or write through it.
struct NoKv;

impl KeyValueStore for NoKv {
    type Error = core::convert::Infallible;
    fn get(&self, _ns: u8, _key: &[u8], _buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Ok(None)
    }
    fn put(&mut self, _ns: u8, _key: &[u8], _val: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
    fn remove(&mut self, _ns: u8, _key: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
    fn for_each(&self, _ns: u8, _f: &mut dyn FnMut(&[u8], &[u8])) {}
}

type Seq = SiatStore<NoKv, SIAT_SIZE, 0>;

/// A config store that never persists — the device always boots fresh.
struct NoConfigStore;

impl ConfigStoreBackend for NoConfigStore {
    type State = SecureState;
    type Config = <SecureState as HasDeviceConfig>::Config;
    fn save(&mut self, _state: &Self::State) {}
    fn load(&mut self) -> Option<Self::Config> {
        None
    }
}

type DeviceStorage = SecureStorage<NoConfigStore, Seq>;

/// A deterministic stand-in for the platform RNG. `SecureDeviceBuilder`
/// refuses `NoRng` at compile time so that a device cannot reach the
/// first `S-A_Sync` with no source of challenges.
struct TestRng;

impl zweidraehte_device::rng::Rng for TestRng {
    fn fill(buf: &mut [u8]) {
        buf.fill(0xA5);
    }
}

impl zweidraehte_device::rng::SecureRng for TestRng {}

// ----------------------------------------------------------------------------
// Zero communication objects — the roster is what this file is about
// ----------------------------------------------------------------------------

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
struct NoDeviceParams;

impl ConstDefault for NoDeviceParams {
    const DEFAULT: Self = NoDeviceParams;
}

// ============================================================================
// The stack definition
// ============================================================================

#[derive(Clone, Copy)]
struct S7SecureStack;

type SecureState = SecureTp1StateFor7<S7SecureStack, P2P_SIZE>;

type SecAugment<'a> = SecureAugmentBundle<
    'a,
    Tp1Augment<'a>,
    Seq,
    { <S7SecureStack as System7StackDefinition>::ADT_ENTRIES },
    P2P_SIZE,
    { <S7SecureStack as System7StackDefinition>::COT_ENTRIES },
>;

/// The augment chain a secure System 7 device needs:
///
/// - `sec` — the Security Interface Object (Type 17), mandatory per
///   §9.1.2.6.1.
/// - `go_table` — the Group Object Table Object (Type 9). System B has
///   it in its base roster; System 7 does not, and §9.2.1.1.1.1 makes it
///   mandatory once GO Diagnostics is implemented, which §9.1.2.4
///   footnote b requires of an S-Mode secure device with group objects.
/// - `diag` — PID_OPERATION_MODE and PID_GO_DIAGNOSTICS, with the
///   secure send strategy.
#[derive(ServiceRegistry)]
struct S7SecureAugments<'a> {
    #[service(augment)]
    sec: SecAugment<'a>,
    #[service(augment)]
    go_table: GroupObjectTableAugment,
    #[service(augment)]
    diag: DiagnosticsAugment<'a, WithSecureGoSend>,
}

zweidraehte_device::system_7_standard_stack! {
    stack: S7SecureStack,
    device: &S7_SECURE_DEVICE,
    cot_address: 0x4200,
    tl_style: TlStyle::Style3,
    params: NoDeviceParams,
    com_objects: NoCo,
    link_layer_builder: MockLinkLayerBuilder<1>,
    platform: (),
    extension_state: zweidraehte_device::security::SecureExtensionState<
        Tp1ExtensionState,
        { Self::ADT_ENTRIES },
        P2P_SIZE,
        { Self::COT_ENTRIES },
    >,
    state: SecureState,
    // §9.1.2.3.1 items 6-7 make the Extended Property services and
    // `A_MemoryExtended_Read`/`_Write` mandatory for a Data Secure
    // device, which is what this tuple adds over `StandardAlServices`.
    al_extensions: StandardSecureAlServices,
    layer_builder: SecureDeviceBuilder,
    resources: SecureResources<Tp1ExtensionState>,
    augments: {
        bundle: S7SecureAugments,
        create: |state, platform, layer_ctx| S7SecureAugments {
            sec: state.extension_state().create_secure_augment(platform, layer_ctx),
            go_table: GroupObjectTableAugment::new(),
            diag: DiagnosticsAugment::<WithSecureGoSend>::new(&state.operation_mode),
        },
    },
    extra {
        type Identity = StaticSecureIdentity;
        type Rng = TestRng;
        type Storage = &'static DeviceStorage;
    },
}

// ============================================================================
// Assertions
// ============================================================================

/// `SecureDeviceBuilder`'s where-clause is the real gate: it demands
/// `HasSeqStore` storage, a `SecureDeviceIdentity`, an extension state
/// with `HasSecurityState`, and a `SecureRng`. Naming it as the layer
/// builder above already proves the System 7 state satisfies all four —
/// this makes the dependency explicit rather than incidental.
fn _secure_layer_stack_is_buildable()
where
    SecureDeviceBuilder: zweidraehte_device::LayerStackBuilder<S7SecureStack>,
{
}

fn _augment_chain_implements_augment<'a>()
where
    S7SecureAugments<'a>: Augment<S7SecureStack>,
{
}

fn fdsk_identity() -> StaticSecureIdentity {
    StaticSecureIdentity::new([0xFE, 0xED, 0x07, 0x05, 0xCA, 0xFE], [0xAA; 16])
}

fn fresh_state() -> SecureState {
    // `System7StateInit::new` is the plain-stack shortcut (`R = ()`); a
    // secure device fills the resources slot with its FDSK, which is
    // what seeds the tool key on a factory-fresh boot.
    S7SecureStack::create_state(System7StateInit {
        identity: fdsk_identity(),
        loaded_config: None,
        resources: SecureResources::simple([0xAA; 16]),
    })
}

/// A fresh secure device seeds its tool key from the FDSK: 03/05/01
/// §6.1.4 has the Management Client fall back to the FDSK until a Tool
/// Key has been programmed, so a device that booted with an all-zero
/// persisted key must answer under the FDSK rather than under zeros.
#[test]
fn a_fresh_device_is_keyed_with_its_fdsk() {
    let state = fresh_state();
    assert_eq!(state.extension_state().security.tool_key(), [0xAA; 16]);
}

/// Security Mode is off out of the factory — §9.1.2.7 lists "enabled
/// ex-factory" as optional and we do not take it.
#[test]
fn security_mode_is_off_out_of_the_factory() {
    use zweidraehte_device::HasSecurityMode;
    assert!(!fresh_state().security_mode_enabled());
}

/// The roster a secure System 7 device presents: the five fixed-index
/// base objects, then the augment-provided ones. The Security Interface
/// Object lands at index 5, which is what
/// `SEC_INTF_OBJ_INDEX` has to be set to in the conformance profile
/// (the template defaults to 6, System B's position).
#[test]
fn the_secure_object_roster_puts_security_at_index_five() {
    use static_cell::StaticCell;
    use zweidraehte_device::objects::interface::PropertyServiceHandler;
    use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};

    static BUFFERS: StaticCell<[[u8; 64]; 4]> = StaticCell::new();
    static BUF_MGR: StaticCell<BufferManager<4>> = StaticCell::new();

    let buffers = BUFFERS.init([[0u8; 64]; 4]);
    // SAFETY: single-threaded test, buffers live for the whole test.
    let buffer_manager = BUF_MGR.init(unsafe { BufferManager::new(buffers) });
    let dyn_bm = buffer_manager.dyn_buffer_manager();
    // SAFETY: the buffer manager lives in a StaticCell ('static).
    let dyn_bm: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_bm) };

    static STORAGE: StaticCell<DeviceStorage> = StaticCell::new();
    let storage: &'static DeviceStorage =
        STORAGE.init(SecureStorage::new(NoConfigStore, Seq::boot(NoKv).expect("the empty backend cannot fail")));

    let lctx = LayerContext::<S7SecureStack>::new(dyn_bm, storage);
    let state = fresh_state();
    let augments = S7SecureStack::create_augments(&state, &(), &lctx);
    let objects = S7SecureStack::create_interface_objects(&state, &(), &lctx, &augments);

    assert_eq!(objects.object_type_at(0), Some(InterfaceObjectType::Device));
    assert_eq!(objects.object_type_at(1), Some(InterfaceObjectType::AddressTable));
    assert_eq!(objects.object_type_at(2), Some(InterfaceObjectType::AssociationTable));
    assert_eq!(objects.object_type_at(3), Some(InterfaceObjectType::ApplicationProgram));
    assert_eq!(objects.object_type_at(4), Some(InterfaceObjectType::InterfaceProgram));
    // Mandatory per §9.1.2.6.1.
    assert_eq!(objects.object_type_at(5), Some(InterfaceObjectType::Security));
    // Mandatory once GO Diagnostics is implemented (§9.2.1.1.1.1).
    assert_eq!(objects.object_type_at(6), Some(InterfaceObjectType::GroupObjectTable));
    assert_eq!(objects.object_type_at(7), None);
    assert_eq!(objects.object_count(), 7);
}

// ============================================================================
// Erase codes (06 Profiles v02.02.01 §9.1.2.5.1, 03/05/01 §6.1.4)
// ============================================================================

/// The secure profile's DM_Restart table makes 01h, 02h and 07h
/// mandatory, forbids 03h and 04h, and allows 05h + 06h only as a pair
/// (footnote O1 — a device with group objects may not implement
/// ResetParam without ResetLinks). What the codes *do* to the security
/// resources is 03/05/01 §6.1.4's business, and the two factory resets
/// differ on exactly two of them: 02h makes the tool key inactive so the
/// FDSK becomes the active key again and disables Security Mode, while
/// 07h leaves both untouched.
///
/// System 7 reaches all of that through the same family-neutral
/// `SecureExtensionState::on_erase` System B uses; this pins that the
/// System 7 device state actually drives it, and that the individual
/// address — which on System 7 lives inside the RT8 address-table blob
/// rather than in a cell of its own — survives the codes that must
/// preserve it.
mod erase_codes {
    use super::*;
    use zweidraehte_device::restart::EraseCode;
    use zweidraehte_device::{HasPersistence, StackState};
    use zweidraehte_proto::address::IndividualAddress;

    const TOOL_KEY: [u8; 16] = [0x11; 16];
    const FDSK: [u8; 16] = [0xAA; 16];

    /// A commissioned device: a tool key written by ETS, Security Mode
    /// on, and an individual address away from the factory default.
    fn commissioned() -> SecureState {
        let state = fresh_state();
        state.set_individual_address(IndividualAddress::new(1, 0, 5));
        state.extension_state().security.set_tool_key(TOOL_KEY);
        state.extension_state().security.set_security_mode_enabled(true);
        state
    }

    #[test]
    fn factory_reset_reverts_the_tool_key_to_the_fdsk() {
        let state = commissioned();
        state.apply_erase_code(EraseCode::FactoryReset);

        assert_eq!(state.extension_state().security.tool_key(), FDSK, "§6.3.10 + §6.1.4");
        assert!(!state.extension_state().security.security_mode_enabled(), "§6.3.5.4");
        assert_eq!(state.individual_address(), IndividualAddress::new(15, 15, 255), "02h resets the IA");
    }

    #[test]
    fn factory_reset_without_ia_keeps_the_key_the_mode_and_the_address() {
        let state = commissioned();
        state.apply_erase_code(EraseCode::FactoryResetKeepIA);

        // "Not influenced" for both, so a tool that wrote TK1 keeps
        // talking under it across a 07h.
        assert_eq!(state.extension_state().security.tool_key(), TOOL_KEY);
        assert!(state.extension_state().security.security_mode_enabled());
        // The System 7 twist: the IA lives in the RT8 table blob, so
        // "keep the IA" has to survive the table reset around it.
        assert_eq!(state.individual_address(), IndividualAddress::new(1, 0, 5));
    }

    /// 05h and 06h are the O1 pair. Both are implemented, and neither
    /// disturbs the device's identity or its keying — they are about the
    /// application's links and parameters.
    #[test]
    fn the_optional_pair_preserves_identity_and_keys() {
        for code in [EraseCode::ResetParam, EraseCode::ResetLinks] {
            let state = commissioned();
            state.apply_erase_code(code);

            assert_eq!(state.individual_address(), IndividualAddress::new(1, 0, 5), "{code:?}");
            assert_eq!(state.extension_state().security.tool_key(), TOOL_KEY, "{code:?}");
            assert!(state.extension_state().security.security_mode_enabled(), "{code:?}");
        }
    }

    /// Basic and Confirmed restart are state-preserving by definition —
    /// they restart the device, they do not erase anything.
    #[test]
    fn a_plain_restart_erases_nothing() {
        for code in [EraseCode::Basic, EraseCode::Confirmed] {
            let state = commissioned();
            state.apply_erase_code(code);

            assert_eq!(state.individual_address(), IndividualAddress::new(1, 0, 5), "{code:?}");
            assert_eq!(state.extension_state().security.tool_key(), TOOL_KEY, "{code:?}");
            assert!(state.extension_state().security.security_mode_enabled(), "{code:?}");
        }
    }
}
