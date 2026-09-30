//! The persistent sections of a System B device cover its whole
//! configuration data model, and restore it exactly.
//!
//! The oracle is the `to_config` projection: a state built from a
//! non-default configuration is copied section by section into a
//! factory-fresh state, and both must project to identical configurations.
//! Every extension composition runs the same check, so an extension field
//! that has no section cannot hide.

use std::vec::Vec;

use const_default::ConstDefault;
use zerocopy::{Immutable, IntoBytes, KnownLayout};
use zweidraehte_device::DeviceDefinition;
use zweidraehte_device::bcus::system_b::{
    DeviceConfig, ExtensionConfig, RfExtensionConfig, RfExtensionState, RfRetransmitterConfig,
    RfRetransmitterExtension, SecureExtensionConfig, SecureExtensionState, SecureResources, SecurityConfig,
    SecurityFailuresLog, SystemBDeviceState, Tp1, Tp1ExtensionConfig, Tp1ExtensionState,
};
use zweidraehte_device::layers::linklayers::mock::MockLinkLayerBuilder;
use zweidraehte_device::objects::comm::{ComObjects, NoComObjects};
use zweidraehte_device::objects::tables::app::PeiApplication;
use zweidraehte_device::objects::tables::{RunnableApplication, Table};
use zweidraehte_device::sections::{ExtensionSections, PersistentSections, Section, SectionError, SectionKind};
use zweidraehte_device::storage::{HasDeviceConfig, StaticIdentity};
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};
use zweidraehte_proto::security::SecurityFailureType;

// ============================================================================
// Test device
// ============================================================================

const DEVICE: DeviceDescriptor =
    DeviceDescriptor::new(MaskVersion::SystemBTp1, 0x00FA, [0; 6], 0xF001, 0x01, 3, 5, 7, 0);

/// Non-empty application parameters, so the parameter section has bytes.
#[derive(Clone, Copy, Debug, PartialEq, ConstDefault, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
struct TestParams {
    bytes: [u8; 24],
}

#[derive(Clone, Copy)]
struct TestDefinition;

impl DeviceDefinition for TestDefinition {
    const DEVICE: &'static DeviceDescriptor = &DEVICE;

    type Params = TestParams;
    type ComObjects = NoComObjects;
    type LinkLayer = MockLinkLayerBuilder<1>;
}

type Stack = Tp1<TestDefinition>;

const ADT: usize = DEVICE.address_table_size();
const AST: usize = DEVICE.association_table_size();
const COT: usize = DEVICE.comm_object_table_size();

/// The System B device state with any extension state: the device core is
/// the same, which is what lets one test device carry every extension.
type State<ES> = SystemBDeviceState<ADT, AST, COT, Stack, ES>;

const FDSK: [u8; 16] = [0xF0; 16];

// ============================================================================
// Helpers
// ============================================================================

/// A small deterministic byte source (xorshift32).
struct Bytes(u32);

impl Bytes {
    fn next(&mut self) -> u8 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0 as u8
    }

    fn fill<const N: usize>(&mut self) -> [u8; N] {
        core::array::from_fn(|_| self.next())
    }

    fn vec(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next()).collect()
    }
}

/// A device configuration that differs from the factory default in every
/// field the device core persists.
fn device_config<C: ExtensionConfig>(
    extension_config: C,
    bytes: &mut Bytes,
) -> DeviceConfig<ADT, AST, COT, TestParams, C> {
    let mut config = DeviceConfig::factory_default();
    config.individual_address = IndividualAddress::new(1, 2, 3);
    config.auth_keys = [bytes.fill(), bytes.fill(), bytes.fill()];
    config.routing_count = 5;
    config.address_table = Table::with_data(&bytes.vec(ADT), 0x4000);
    config.association_table = Table::with_data(&bytes.vec(AST), 0x4100);
    config.group_object_table = Table::with_data(&bytes.vec(COT), 0x4200);
    config.application = RunnableApplication::from_table(Table::with_data(&bytes.vec(24), 0x4300));
    config.pei_program = PeiApplication::from_table(Table::with_data(&[], 0x4400));
    config.program_version = bytes.fill();
    config.pei_type = 0x14;
    config.pei_program_version = bytes.fill();
    config.extension_config = extension_config;
    config
}

fn sections<S: PersistentSections>(state: &S) -> Vec<Section> {
    let mut sections = Vec::new();
    state.for_each_section(&mut |section| sections.push(section));
    sections
}

/// Copy every section of `from` into `to`. Image sections go over in
/// chunks of varying size when `chunked`, the way range writes arrive.
fn copy_sections<S: PersistentSections>(from: &S, to: &S, chunked: Option<&mut Bytes>) {
    let mut chunks = chunked;
    for section in sections(from) {
        let mut image = vec![0u8; usize::from(section.len)];
        from.read_section(section.id, 0, &mut image);

        match (section.kind, chunks.as_deref_mut()) {
            (SectionKind::Image, Some(bytes)) => {
                let mut offset = 0usize;
                while offset < image.len() {
                    let len = (usize::from(bytes.next()) % 17 + 1).min(image.len() - offset);
                    to.apply_section(section.id, offset as u16, &image[offset..offset + len]).expect("image chunk");
                    offset += len;
                }
            }
            _ => to.apply_section(section.id, 0, &image).expect("whole section"),
        }
    }
}

/// The oracle check: a configured state copied section by section into a
/// fresh one projects identically — once whole, once in chunks.
fn assert_sections_restore<ES>(extension_config: ES::Config, resources: impl Fn() -> ES::Resources)
where
    ES: ExtensionSections,
    ES::Config: core::fmt::Debug + PartialEq,
{
    let mut bytes = Bytes(0x1234_5678);
    let configured =
        State::<ES>::from_config(StaticIdentity::new([0; 6]), device_config(extension_config, &mut bytes), resources());
    let expected = configured.to_config();

    let fresh = State::<ES>::new(StaticIdentity::new([0; 6]), NoComObjects::new(), resources());
    assert_ne!(fresh.to_config(), expected, "the test configuration must differ from factory");
    copy_sections(&configured, &fresh, None);
    assert_eq!(fresh.to_config(), expected, "whole-section copy differs");

    let chunked = State::<ES>::new(StaticIdentity::new([0; 6]), NoComObjects::new(), resources());
    copy_sections(&configured, &chunked, Some(&mut bytes));
    assert_eq!(chunked.to_config(), expected, "chunked copy differs");
}

fn security_config<const GRP: usize, const P2P: usize, const GO: usize>(
    bytes: &mut Bytes,
) -> SecurityConfig<GRP, P2P, GO> {
    let mut config = SecurityConfig {
        security_mode_enabled: true,
        tool_key: bytes.fill(),
        security_report: 0x01,
        security_report_enabled: true,
        ..SecurityConfig::default()
    };
    config.grp_keys.write_entries(0, &bytes.vec(2 * 18)).expect("two group keys fit");
    config.p2p_keys.write_entries(0, &bytes.vec(20)).expect("one P2P key fits");
    config.go_flags.write_entries(0, &bytes.vec(3)).expect("three GO flags fit");
    let mut log = SecurityFailuresLog::default();
    log.log_failure(SecurityFailureType::SeqNrError, 0x1101, &[]);
    log.log_failure(SecurityFailureType::AccessError, 0x1102, &[]);
    config.failures_log = log;
    config
}

// ============================================================================
// Oracle round trips, one per extension composition
// ============================================================================

#[test]
fn plain_device_core_restores() {
    assert_sections_restore::<()>((), || ());
}

#[test]
fn tp1_restores() {
    assert_sections_restore::<Tp1ExtensionState>(Tp1ExtensionConfig { max_retry_count: 0x21 }, || ());
}

#[test]
fn rf_restores() {
    assert_sections_restore::<RfExtensionState>(RfExtensionConfig { rf_domain_address: [1, 2, 3, 4, 5, 6] }, || ());
}

#[test]
fn rf_retransmitter_restores() {
    assert_sections_restore::<RfRetransmitterExtension>(
        (RfExtensionConfig { rf_domain_address: [9; 6] }, RfRetransmitterConfig {
            rf_retransmitter: true,
            rf_repeat_counter_limit: 3,
        }),
        || (),
    );
}

#[test]
fn secure_tp1_restores() {
    type Secure = SecureExtensionState<Tp1ExtensionState, 8, 4, 8>;
    let mut bytes = Bytes(0xCAFE);
    let config = SecureExtensionConfig::new(Tp1ExtensionConfig { max_retry_count: 0x12 }, security_config(&mut bytes));
    assert_sections_restore::<Secure>(config, || SecureResources { inner: (), fdsk: FDSK });
}

#[test]
fn secure_rf_retransmitter_restores() {
    type Secure = SecureExtensionState<RfRetransmitterExtension, 8, 4, 8>;
    let mut bytes = Bytes(0xBEEF);
    let inner = (RfExtensionConfig { rf_domain_address: [7; 6] }, RfRetransmitterConfig {
        rf_retransmitter: true,
        rf_repeat_counter_limit: 2,
    });
    let config = SecureExtensionConfig::new(inner, security_config(&mut bytes));
    assert_sections_restore::<Secure>(config, || SecureResources { inner: (), fdsk: FDSK });
}

#[cfg(feature = "knxip")]
mod ip {
    use super::*;
    use zweidraehte_device::bcus::system_b::{
        IpExtensionConfig, IpExtensionState, IpInterfaceExtension, TunnellingExtensionConfig,
    };

    pub(super) fn ip_config(bytes: &mut Bytes) -> IpExtensionConfig {
        IpExtensionConfig {
            friendly_name: bytes.fill(),
            friendly_name_len: 12,
            configured_ip: [192, 168, 1, 50],
            configured_subnet: [255, 255, 255, 0],
            configured_gateway: [192, 168, 1, 1],
            ip_assignment_method: 1,
            routing_multicast: [224, 0, 23, 13],
            ttl: 32,
            project_installation_id: 0x1234,
            routing_busy_wait_time: 42,
        }
    }

    pub(super) fn tunnelling_config() -> TunnellingExtensionConfig<4> {
        let mut config = TunnellingExtensionConfig::default();
        config.additional_individual_addresses[0] = [0x11, 0x0A];
        config.additional_individual_addresses[1] = [0x11, 0x0B];
        config.additional_individual_addresses_len = 2;
        config
    }

    #[test]
    fn ip_restores() {
        assert_sections_restore::<IpExtensionState<0>>(ip_config(&mut Bytes(7)), || ());
    }

    #[test]
    fn ip_interface_restores() {
        assert_sections_restore::<IpInterfaceExtension<4, 0>>((ip_config(&mut Bytes(8)), tunnelling_config()), || ());
    }
}

#[cfg(feature = "ip-secure")]
mod ip_secure {
    use super::ip::{ip_config, tunnelling_config};
    use super::*;
    use zweidraehte_device::bcus::system_b::{IpSecureExtensionConfig, IpSecureInterfaceExtension, IpSecureResources};

    #[test]
    fn secure_ip_interface_restores() {
        type Secure = SecureExtensionState<IpSecureInterfaceExtension<4, 0, 4, 4>, 8, 4, 8>;
        let mut bytes = Bytes(0xD00D);

        let mut ip_secure = IpSecureExtensionConfig::<4, 4> {
            backbone_key: bytes.fill(),
            device_authentication_code: bytes.fill(),
            secured_tunnelling: 1,
            multicast_latency_tolerance_ms: 2500,
            sync_latency_fraction: 20,
            ..Default::default()
        };
        ip_secure.password_hashes.write_entries(1, &bytes.vec(16)).expect("hash fits");
        ip_secure.tunnelling_users.write_entries(0, &[1, 1]).expect("user fits");

        let inner = ((ip_config(&mut bytes), tunnelling_config()), ip_secure);
        let config = SecureExtensionConfig::new(inner, security_config(&mut bytes));
        assert_sections_restore::<Secure>(config, || SecureResources {
            inner: IpSecureResources { fdsk: FDSK },
            fdsk: FDSK,
        });
    }
}

// ============================================================================
// Rejection and reset
// ============================================================================

#[test]
fn torn_records_are_rejected_and_reset_to_factory() {
    let state = State::<Tp1ExtensionState>::new(StaticIdentity::new([0; 6]), NoComObjects::new(), ());
    let fresh_control = {
        let mut control = [0u8; 14];
        state.read_section(0x03, 0, &mut control);
        control
    };

    // A load state that is no load state.
    let mut torn = fresh_control;
    torn[0] = 0x7F;
    assert_eq!(state.apply_section(0x03, 0, &torn), Err(SectionError::Malformed));
    // A partial record.
    assert_eq!(state.apply_section(0x03, 0, &fresh_control[..5]), Err(SectionError::Malformed));
    assert_eq!(state.apply_section(0x03, 4, &fresh_control[..10]), Err(SectionError::Malformed));
    // An id nobody owns.
    assert_eq!(state.apply_section(0x1F, 0, &[0]), Err(SectionError::UnknownSection));
    // A range past an image's end.
    assert_eq!(state.apply_section(0x08, ADT as u16, &[0]), Err(SectionError::Malformed));

    // Reset restores factory content.
    state.apply_section(0x01, 0, &[0x12; 15]).expect("device record");
    state.reset_section(0x01);
    let mut device = [0u8; 15];
    state.read_section(0x01, 0, &mut device);
    assert_eq!(&device[..3], &[0xFF, 0xFF, 6], "IA 15.15.255, routing count 6");
    assert!(device[3..].iter().all(|&b| b == 0xFF), "default auth keys");
}

/// A table whose data section is lost is unloaded with it: a store that
/// resets a torn image must not leave a "Loaded" table over zeroes.
#[test]
fn resetting_table_data_unloads_the_table() {
    let mut bytes = Bytes(0x55AA);
    let state = State::<Tp1ExtensionState>::from_config(
        StaticIdentity::new([0; 6]),
        device_config(Tp1ExtensionConfig { max_retry_count: 0x21 }, &mut bytes),
        (),
    );
    let load_state = |id| {
        let mut control = [0u8; 14];
        state.read_section(id, 0, &mut control);
        control[0]
    };

    for (data, control) in [(0x08, 0x03), (0x09, 0x04), (0x0A, 0x05), (0x0B, 0x06)] {
        assert_eq!(load_state(control), 0x01, "section {control:#04x} starts loaded");
        state.reset_section(data);
        assert_eq!(load_state(control), 0x00, "resetting {data:#04x} left its table loaded");
    }
}

// ============================================================================
// Format guard
// ============================================================================

/// The section tables are the on-media format. A change here is a format
/// change: devices in the field start factory-fresh after the update.
#[test]
fn section_layouts_are_stable() {
    fn table<S: PersistentSections>(state: &S) -> String {
        let mut out = String::new();
        for section in sections(state) {
            out.push_str(&format!("{:#04x} {:?} {}\n", section.id, section.kind, section.len));
        }
        out.push_str(&format!("fingerprint {:#010x}\n", state.layout_fingerprint()));
        out
    }

    let tp1 = State::<Tp1ExtensionState>::new(StaticIdentity::new([0; 6]), NoComObjects::new(), ());
    insta::assert_snapshot!("system_b_tp1_sections", table(&tp1));

    let secure = State::<SecureExtensionState<Tp1ExtensionState, 8, 4, 8>>::new(
        StaticIdentity::new([0; 6]),
        NoComObjects::new(),
        SecureResources { inner: (), fdsk: FDSK },
    );
    insta::assert_snapshot!("system_b_secure_tp1_sections", table(&secure));
}

// ============================================================================
// Write-through: every mutation path persists
// ============================================================================
//
// Each case mutates a configured state the way the stack does, flushes it
// into a store, boots a fresh state from the same medium, and requires the
// same `to_config` bytes. The flusher is told nothing: Records are found by
// comparing with the store's durable copy, Images by their owners' dirty
// ranges. A path that changes configuration without either would fail here.

mod write_through {
    use super::*;
    use zweidraehte_device::memory::MemoryMap;
    use zweidraehte_device::objects::interface::{HasMaxRetryCount, HasRoutingCount};
    use zweidraehte_device::objects::tables::{HasAddressTable, HasApplication, HasLoadStateMachine};
    use zweidraehte_device::restart::EraseCode;
    use zweidraehte_device::{HasAuthorization, HasPersistence, StackDefinition, StackState};
    use zweidraehte_nv::mock::{Backing, MockBytes, MockFlash};
    use zweidraehte_nv::{ByteNv, FlashLog, Flusher, LogGeometry, NvStore};
    use zweidraehte_proto::AccessContext;
    use zweidraehte_proto::messages::apdu::load_control::LoadEvent;

    type Secure = SecureExtensionState<Tp1ExtensionState, 8, 4, 8>;

    fn secure_state(configured: bool) -> State<Secure> {
        let resources = || SecureResources { inner: (), fdsk: FDSK };
        if configured {
            let mut bytes = Bytes(0x7777);
            let security = security_config(&mut bytes);
            let config = SecureExtensionConfig::new(Tp1ExtensionConfig { max_retry_count: 0x21 }, security);
            State::<Secure>::from_config(StaticIdentity::new([0; 6]), device_config(config, &mut bytes), resources())
        } else {
            State::<Secure>::new(StaticIdentity::new([0; 6]), NoComObjects::new(), resources())
        }
    }

    /// A medium and a store over it, reopened for each boot.
    trait Medium {
        type Store: NvStore<Error = ()>;
        fn new() -> Self;
        fn open(&self) -> Self::Store;
    }

    struct Bytes_(Backing);

    impl Medium for Bytes_ {
        type Store = ByteNv<MockBytes>;
        fn new() -> Self {
            Self(Backing::new(4096, 1))
        }
        fn open(&self) -> Self::Store {
            ByteNv::new(self.0.open_bytes(), 0, 4096)
        }
    }

    struct Flash_(Backing);

    const GEOMETRY: LogGeometry = LogGeometry { offset: 0, sector_size: 2048, sectors_per_bank: 1, banks: 2 };

    impl Medium for Flash_ {
        type Store = FlashLog<MockFlash<8>, 264>;
        fn new() -> Self {
            Self(Backing::new(4096, 2048))
        }
        fn open(&self) -> Self::Store {
            FlashLog::new(self.0.open_aligned(), GEOMETRY)
        }
    }

    /// Boot a configured state onto a fresh medium, apply `mutate`, flush,
    /// reboot, and compare.
    fn persists<M: Medium>(mutate: impl FnOnce(&State<Secure>)) {
        let medium = M::new();
        let state = secure_state(true);
        let mut store = medium.open();
        store.load(&state).expect("format with the configured state");
        let flusher = Flusher::new();

        mutate(&state);
        flusher.flush(&state, &mut store).expect("flush");
        let expected = state.to_config();
        drop(store);

        let rebooted = secure_state(false);
        medium.open().load(&rebooted).expect("reboot");
        assert_eq!(rebooted.to_config(), expected);
    }

    /// A plain management memory write. The configured device has Security
    /// Mode on, which refuses plain writes, so it is switched off first —
    /// itself one more Record change the flush must find.
    fn memory_write(state: &State<Secure>, address: u32, data: &[u8]) {
        state.extension_state().security.set_security_mode_enabled(false);
        Stack::memory_map().write_config(state, address, data, AccessContext::MAX_ACCESS).expect("memory write");
    }

    macro_rules! paths {
        ($($name:ident => $mutate:expr),* $(,)?) => {
            mod bytes {
                use super::*;
                $( #[test] fn $name() { persists::<Bytes_>($mutate); } )*
            }
            mod flash {
                use super::*;
                $( #[test] fn $name() { persists::<Flash_>($mutate); } )*
            }
        };
    }

    paths!(
        individual_address => |s: &State<Secure>| s.set_individual_address(IndividualAddress::new(3, 4, 5)),
        routing_count => |s: &State<Secure>| s.set_routing_count(2),
        auth_key => |s: &State<Secure>| {
            s.key_write(1, &[1, 2, 3, 4], AccessContext::MAX_ACCESS);
        },
        address_table_memory_write => |s: &State<Secure>| {
            memory_write(s, Stack::memory_map().layout().adt_address() + 2, &[0x0A, 0x0B, 0x0C])
        },
        parameter_memory_write => |s: &State<Secure>| {
            memory_write(s, Stack::memory_map().layout().app_address() + 5, &[0x55; 7])
        },
        table_unload => |s: &State<Secure>| {
            s.adt().borrow_mut().write_lsm(&[LoadEvent::Unload.into()], None);
        },
        application_unload => |s: &State<Secure>| {
            s.app().borrow_mut().write_lsm(&[LoadEvent::Unload.into()], None);
        },
        reset_parameters => |s: &State<Secure>| s.apply_erase_code(EraseCode::ResetParam),
        factory_reset => |s: &State<Secure>| s.apply_erase_code(EraseCode::FactoryReset),
        factory_reset_keep_ia => |s: &State<Secure>| s.apply_erase_code(EraseCode::FactoryResetKeepIA),
        reset_links => |s: &State<Secure>| s.apply_erase_code(EraseCode::ResetLinks),
        group_key_write => |s: &State<Secure>| {
            s.extension_state().security.grp_keys().borrow_mut().write_entries(3, &[0x3C; 18]).expect("fits");
        },
        go_flag_write => |s: &State<Secure>| {
            s.extension_state().security.go_flags().borrow_mut().write_entries(0, &[7]).expect("fits");
        },
        retry_count => |s: &State<Secure>| s.set_max_retry_count(0x11),
        no_change => |_: &State<Secure>| {},
    );

    /// The Application Program run state is volatile (03/05/01 §4.24.2.2):
    /// a `Terminated` application boots `Halted` after a reset (note d of
    /// §4.24.2.3.3), which the power-up cascade in `SystemBDeviceModel::init`
    /// needs and vendor conformance case 2.5.6 tests. Its load state is
    /// persistent, so the cascade still has an application to start.
    #[test]
    fn the_run_state_does_not_survive_a_reboot() {
        use zweidraehte_device::objects::tables::{HasRunStateMachine, RunConditions, RunEvent, RunState};

        let medium = Bytes_::new();
        let state = secure_state(true);
        let mut store = medium.open();
        store.load(&state).expect("format with the configured state");

        {
            let mut app = state.app().borrow_mut();
            app.handle_run_event(RunEvent::Loaded, RunConditions::Fulfilled);
            app.handle_run_event(RunEvent::ReadyToRun, RunConditions::Fulfilled);
            app.write_rsm(&[RunEvent::Stop.into()], RunConditions::Fulfilled);
            assert_eq!(app.run_state(), RunState::Terminated);
        }
        Flusher::new().flush(&state, &mut store).expect("flush");
        drop(store);

        let rebooted = secure_state(false);
        medium.open().load(&rebooted).expect("reboot");
        let app = rebooted.app().borrow();
        assert!(app.is_loaded());
        assert_eq!(app.run_state(), RunState::Halted);
    }

    /// The same persistence through a device's storage handle: an
    /// [`NvConfig`] in the stores struct, as firmware wires it.
    mod nv_config {
        use super::*;
        use zweidraehte_device::storage::{ConfigStorage, DeviceStorage, NvConfig};

        type Handle = ConfigStorage<NvConfig<ByteNv<MockBytes>>>;

        // The router flushes only through storage that asks for it: the
        // write-through backend does, storage without a config store not.
        const _: () = assert!(<Handle as DeviceStorage<State<Secure>>>::WRITE_THROUGH);
        const _: () = assert!(!<ConfigStorage<()> as DeviceStorage<State<Secure>>>::WRITE_THROUGH);

        /// A configured device booted onto a fresh medium through the handle.
        fn boot(backing: &Backing) -> (State<Secure>, Handle) {
            let state = secure_state(true);
            let handle = ConfigStorage::new(NvConfig::new(ByteNv::new(backing.open_bytes(), 0, 4096)));
            handle.config.load(&state).expect("format with the configured state");
            (state, handle)
        }

        /// The configuration a reboot from `backing` restores.
        fn reboot(backing: &Backing) -> <State<Secure> as HasDeviceConfig>::Config {
            let rebooted = secure_state(false);
            let handle: Handle = ConfigStorage::new(NvConfig::new(ByteNv::new(backing.open_bytes(), 0, 4096)));
            handle.config.load(&rebooted).expect("reboot");
            rebooted.to_config()
        }

        /// The router's path: changes made by a dispatch are durable after
        /// the handle's flush.
        #[test]
        fn the_router_flush_persists_through_the_handle() {
            let backing = Backing::new(4096, 1);
            let (state, handle) = boot(&backing);

            state.set_individual_address(IndividualAddress::new(3, 4, 5));
            memory_write(&state, Stack::memory_map().layout().ast_address() + 1, &[0x21, 0x22]);
            handle.flush(&state).expect("flush");

            assert_eq!(reboot(&backing), state.to_config());
        }

        /// The storage task's path after a restart: an erase code is durable
        /// after the handle's flush.
        #[test]
        fn the_flush_after_an_erase_persists_it() {
            let backing = Backing::new(4096, 1);
            let (state, handle) = boot(&backing);

            state.apply_erase_code(EraseCode::FactoryReset);
            handle.flush(&state).expect("flush");

            assert_eq!(reboot(&backing), state.to_config());
        }

        /// A medium that fails reports the flush as failed, so the router and
        /// the storage task keep the change pending.
        #[test]
        fn a_failing_medium_fails_the_flush() {
            let backing = Backing::new(4096, 1);
            let (state, handle) = boot(&backing);

            backing.set_failing(true);
            state.set_individual_address(IndividualAddress::new(6, 7, 8));

            assert!(handle.flush(&state).is_err());
        }
    }

    /// The flash config region firmware places: a two-bank `FlashLog` behind
    /// an `NvConfig`, opened through the storage layout like on a device.
    mod config_log_region {
        use super::*;
        use std::cell::RefCell;
        use zweidraehte_device::storage::region::{Chip, ConfigLogRegion, RegionSpec};
        use zweidraehte_device::storage::{ConfigStorage, DeviceStorage, Placed, SectorIo, StorageLayout, StoreOf};

        const SECTOR: u32 = 2048;
        const REGION: usize = 16 * 1024;
        const BANK: usize = REGION / 2;

        /// A `Copy` handle over a mock flash, as a chip's `Io` must be.
        #[derive(Clone, Copy)]
        struct TestIo(&'static RefCell<MockFlash<8>>);

        impl SectorIo for TestIo {
            type Error = ();
            const WRITE_ALIGN: usize = 8;
            fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), ()> {
                self.0.borrow_mut().read(offset, buf)
            }
            fn erase(&mut self, start: u32, end: u32) -> Result<(), ()> {
                self.0.borrow_mut().erase(start, end)
            }
            fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), ()> {
                self.0.borrow_mut().write(offset, data)
            }
        }

        struct TestChip;
        impl Chip for TestChip {
            const TAG: u32 = 0;
            const BASE: u32 = 0;
            const CAPACITY: u32 = REGION as u32;
            const SECTOR_SIZE: u32 = SECTOR;
            type Io = TestIo;
        }

        struct Map;
        type Cfg = Placed<ConfigLogRegion<REGION>, TestChip, Map>;
        impl StorageLayout for Map {
            const REGIONS: &'static [RegionSpec] = &[Cfg::SPEC];
        }
        type Handle = ConfigStorage<StoreOf<Cfg>>;

        fn open(backing: &Backing) -> Handle {
            let flash: &'static RefCell<MockFlash<8>> = Box::leak(Box::new(RefCell::new(backing.open_aligned())));
            ConfigStorage::new(Cfg::open(TestIo(flash)).expect("opening records the placement"))
        }

        /// The generation of the bank header at `offset`, if a bank starts
        /// there under this log's magic.
        fn bank_generation(backing: &Backing, offset: usize, magic: &[u8]) -> Option<u32> {
            let bytes = backing.bytes();
            (&bytes[offset..offset + 4] == magic)
                .then(|| u32::from_be_bytes(bytes[offset + 4..offset + 8].try_into().expect("four bytes")))
        }

        /// Flushes, the storage task's compaction and a reboot all go through
        /// the device's handle; the log alternates between two banks of half
        /// the region.
        #[test]
        fn the_region_persists_compacts_and_reboots_through_the_handle() {
            let backing = Backing::new(REGION, SECTOR as usize);
            let state = secure_state(true);
            let handle = open(&backing);
            handle.config.load(&state).expect("format with the configured state");
            // The boot snapshot starts a bank at one of the two boundaries.
            let magic = [0, BANK]
                .into_iter()
                .map(|offset| backing.bytes()[offset..offset + 4].to_vec())
                .find(|bytes| bytes != &[0xFF; 4])
                .expect("the boot snapshot starts a bank at a bank boundary");

            // Keep changing the parameters until the log asks for compaction.
            let mut flushes = 0;
            while !DeviceStorage::<State<Secure>>::needs_compaction(&handle) {
                memory_write(&state, Stack::memory_map().layout().app_address(), &[flushes as u8; 8]);
                handle.flush(&state).expect("flush");
                flushes += 1;
                assert!(flushes < 1000, "the log never asked for compaction");
            }
            handle.compact(&state).expect("compact");
            assert!(!DeviceStorage::<State<Secure>>::needs_compaction(&handle), "compaction leaves room for appends");

            let generations = (bank_generation(&backing, 0, &magic), bank_generation(&backing, BANK, &magic));
            assert!(
                matches!(generations, (Some(a), Some(b)) if a != b),
                "both halves hold banks of different generations: {generations:?}"
            );
            let expected = state.to_config();
            drop(handle);

            let rebooted = secure_state(false);
            open(&backing).config.load(&rebooted).expect("reboot");
            assert_eq!(rebooted.to_config(), expected);
        }
    }

    // Silence the unused-import lint for traits the macro bodies use.
    #[allow(dead_code)]
    fn _in_scope<T: HasApplication + HasAddressTable + HasPersistence + StackState + HasLoadStateMachine>() {}
    #[allow(dead_code)]
    fn _stack<T: StackDefinition>() {}
    #[allow(dead_code)]
    fn _retry<T: HasMaxRetryCount + HasRoutingCount>() {}
}
