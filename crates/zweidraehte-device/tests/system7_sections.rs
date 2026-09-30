//! The persistent sections of a System 7 device cover its whole
//! configuration data model, restore it exactly, and write-through
//! persistence reaches every mutation path — including the memory-mapped
//! load controls and the individual address kept inside the address table.

use std::vec::Vec;

use const_default::ConstDefault;
use zerocopy::{Immutable, IntoBytes, KnownLayout};
use zweidraehte_device::DeviceDefinition;
use zweidraehte_device::bcus::system_7::{
    System7DeviceConfig, System7DeviceState, Tp1, Tp1ExtensionConfig, Tp1ExtensionState,
};
use zweidraehte_device::bcus::system_b::{
    SecureExtensionConfig, SecureExtensionState, SecureResources, SecurityConfig,
};
use zweidraehte_device::layers::linklayers::mock::MockLinkLayerBuilder;
use zweidraehte_device::objects::comm::{ComObjects, NoComObjects};
use zweidraehte_device::objects::tables::{RunnableApplication, Table};
use zweidraehte_device::sections::{PersistentSections, Section, SectionKind};
use zweidraehte_device::storage::{HasDeviceConfig, StaticIdentity};
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};

// ============================================================================
// Test device
// ============================================================================

const DEVICE: DeviceDescriptor =
    DeviceDescriptor::new(MaskVersion::System7Tp1, 0x00FA, [0; 6], 0xF003, 0x01, 3, 5, 7, 0);

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

const COT_ADDRESS: u16 = 0x4200;
type Stack = Tp1<TestDefinition, COT_ADDRESS>;

const ADT: usize = 3 + DEVICE.max_address_table_entries as usize * 2;
const AST: usize = 1 + DEVICE.max_association_table_entries as usize * 2;
const COT: usize = 3 + DEVICE.max_com_objects as usize * 4;

type State<ES> = System7DeviceState<ADT, AST, COT, Stack, ES>;
type Secure = SecureExtensionState<Tp1ExtensionState, 8, 4, 8>;

const FDSK: [u8; 16] = [0xF0; 16];
const AST_ADDRESS: u32 = 0x4100;
const APP_ADDRESS: u32 = 0x4300;

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

/// A configuration that differs from the factory default everywhere the
/// device core persists something, with the IA 1.2.3 in the address table.
fn device_config<C: zweidraehte_device::bcus::system_b::ExtensionConfig>(
    extension_config: C,
    bytes: &mut Bytes,
) -> System7DeviceConfig<ADT, AST, COT, TestParams, C> {
    let mut config = System7DeviceConfig::factory_default();
    let mut adt = bytes.vec(ADT);
    adt[1..3].copy_from_slice(IndividualAddress::new(1, 2, 3).as_bytes());
    config.auth_keys = core::array::from_fn(|_| bytes.fill());
    config.routing_count = 5;
    config.option_reg = 0x42;
    config.address_table = Table::with_data(&adt, 0x4000);
    config.association_table = Table::with_data(&bytes.vec(AST), AST_ADDRESS);
    config.group_object_table = Table::with_data(&bytes.vec(COT), u32::from(COT_ADDRESS));
    config.application = RunnableApplication::from_table(Table::with_data(&bytes.vec(24), APP_ADDRESS));
    config.application2 = RunnableApplication::from_table(Table::with_data(&[], 0));
    config.program_version = bytes.fill();
    config.pei_type = 0x14;
    config.program2_version = bytes.fill();
    config.extension_config = extension_config;
    config
}

fn sections<S: PersistentSections>(state: &S) -> Vec<Section> {
    let mut sections = Vec::new();
    state.for_each_section(&mut |section| sections.push(section));
    sections
}

fn copy_sections<S: PersistentSections>(from: &S, to: &S) {
    for section in sections(from) {
        let mut image = vec![0u8; usize::from(section.len)];
        from.read_section(section.id, 0, &mut image);
        to.apply_section(section.id, 0, &image).expect("whole section");
    }
}

fn security_config(bytes: &mut Bytes) -> SecurityConfig<8, 4, 8> {
    let mut config =
        SecurityConfig { security_mode_enabled: true, tool_key: bytes.fill(), ..SecurityConfig::default() };
    config.grp_keys.write_entries(0, &bytes.vec(2 * 18)).expect("two group keys fit");
    config.go_flags.write_entries(0, &bytes.vec(3)).expect("three GO flags fit");
    config
}

fn plain_state(configured: bool) -> State<Tp1ExtensionState> {
    if configured {
        let config = device_config(Tp1ExtensionConfig { max_retry_count: 0x21 }, &mut Bytes(0x1234));
        State::from_config(StaticIdentity::new([0; 6]), config, ())
    } else {
        State::new(StaticIdentity::new([0; 6]), NoComObjects::new(), ())
    }
}

fn secure_state(configured: bool) -> State<Secure> {
    let resources = || SecureResources { inner: (), fdsk: FDSK };
    if configured {
        let mut bytes = Bytes(0x5678);
        let security = security_config(&mut bytes);
        let config = SecureExtensionConfig::new(Tp1ExtensionConfig { max_retry_count: 0x21 }, security);
        State::from_config(StaticIdentity::new([0; 6]), device_config(config, &mut bytes), resources())
    } else {
        State::new(StaticIdentity::new([0; 6]), NoComObjects::new(), resources())
    }
}

// ============================================================================
// Oracle round trips and format guard
// ============================================================================

#[test]
fn plain_system7_restores() {
    let configured = plain_state(true);
    let fresh = plain_state(false);
    assert_ne!(fresh.to_config(), configured.to_config());
    copy_sections(&configured, &fresh);
    assert_eq!(fresh.to_config(), configured.to_config());
}

#[test]
fn secure_system7_restores() {
    let configured = secure_state(true);
    let fresh = secure_state(false);
    copy_sections(&configured, &fresh);
    assert_eq!(fresh.to_config(), configured.to_config());
}

/// Losing the address table's data unloads the table but must not
/// re-address the device: the IA slot survives, as with `ResetLinks`.
#[test]
fn resetting_address_table_data_keeps_the_ia_and_unloads() {
    use zweidraehte_device::StackState;

    let state = plain_state(true);
    state.reset_section(0x08);
    assert_eq!(state.individual_address(), IndividualAddress::new(1, 2, 3));
    let mut control = [0u8; 14];
    state.read_section(0x03, 0, &mut control);
    assert_eq!(control[0], 0x00, "the address table stayed loaded over zeroes");
}

/// The section tables are the on-media format of a System 7 device.
#[test]
fn section_layouts_are_stable() {
    fn table<S: PersistentSections>(state: &S) -> String {
        let mut out = String::new();
        for section in sections(state) {
            let kind = if section.kind == SectionKind::Image { "Image" } else { "Record" };
            out.push_str(&format!("{:#04x} {} {}\n", section.id, kind, section.len));
        }
        out.push_str(&format!("fingerprint {:#010x}\n", state.layout_fingerprint()));
        out
    }

    insta::assert_snapshot!("system7_tp1_sections", table(&plain_state(false)));
    insta::assert_snapshot!("system7_secure_tp1_sections", table(&secure_state(false)));
}

// ============================================================================
// Write-through: every mutation path persists
// ============================================================================

mod write_through {
    use super::*;
    use zweidraehte_device::StackDefinition;
    use zweidraehte_device::StackState;
    use zweidraehte_device::memory::MemoryMap;
    use zweidraehte_device::restart::EraseCode;
    use zweidraehte_nv::mock::{Backing, MockBytes, MockFlash};
    use zweidraehte_nv::{ByteNv, FlashLog, Flusher, LogGeometry, NvStore};
    use zweidraehte_proto::AccessContext;

    trait Medium {
        type Store: NvStore<Error = ()>;
        fn new() -> Self;
        fn open(&self) -> Self::Store;
    }

    struct ByteMedium(Backing);

    impl Medium for ByteMedium {
        type Store = ByteNv<MockBytes>;
        fn new() -> Self {
            Self(Backing::new(4096, 1))
        }
        fn open(&self) -> Self::Store {
            ByteNv::new(self.0.open_bytes(), 0, 4096)
        }
    }

    struct FlashMedium(Backing);

    const GEOMETRY: LogGeometry = LogGeometry { offset: 0, sector_size: 2048, sectors_per_bank: 1, banks: 2 };

    impl Medium for FlashMedium {
        type Store = FlashLog<MockFlash<8>, 264>;
        fn new() -> Self {
            Self(Backing::new(4096, 2048))
        }
        fn open(&self) -> Self::Store {
            FlashLog::new(self.0.open_aligned(), GEOMETRY)
        }
    }

    /// Mutate a configured state, flush, reboot a fresh one from the
    /// medium, and require the same configuration.
    fn persists<M: Medium>(mutate: impl FnOnce(&State<Secure>)) {
        let medium = M::new();
        let state = secure_state(true);
        let mut store = medium.open();
        store.load(&state).expect("format with the configured state");

        mutate(&state);
        Flusher::new().flush(&state, &mut store).expect("flush");
        let expected = state.to_config();
        drop(store);

        let rebooted = secure_state(false);
        medium.open().load(&rebooted).expect("reboot");
        assert_eq!(rebooted.to_config(), expected);
    }

    /// A plain management memory write. Security Mode would refuse it, so
    /// it is switched off first (itself a Record change to find).
    fn memory_write(state: &State<Secure>, address: u32, data: &[u8]) {
        state.extension_state().security.set_security_mode_enabled(false);
        Stack::memory_map().write(state, address, data, AccessContext::MAX_ACCESS).expect("memory write");
    }

    macro_rules! paths {
        ($($name:ident => $mutate:expr),* $(,)?) => {
            mod bytes {
                use super::*;
                $( #[test] fn $name() { persists::<ByteMedium>($mutate); } )*
            }
            mod flash {
                use super::*;
                $( #[test] fn $name() { persists::<FlashMedium>($mutate); } )*
            }
        };
    }

    paths!(
        individual_address => |s: &State<Secure>| s.set_individual_address(IndividualAddress::new(3, 4, 5)),
        individual_address_by_memory => |s: &State<Secure>| memory_write(s, 0x4001, &[0x34, 0x05]),
        option_reg_by_memory => |s: &State<Secure>| memory_write(s, 0x0100, &[0x99]),
        load_control_unload => |s: &State<Secure>| memory_write(s, 0x0104, &[0x14]),
        association_table_window => |s: &State<Secure>| memory_write(s, AST_ADDRESS + 1, &[0xA1, 0xA2]),
        group_object_window => |s: &State<Secure>| memory_write(s, u32::from(COT_ADDRESS) + 3, &[0xC3; 4]),
        application_window => |s: &State<Secure>| memory_write(s, APP_ADDRESS + 5, &[0x5A; 6]),
        reset_ia => |s: &State<Secure>| s.apply_erase_code(EraseCode::ResetIA),
        reset_links => |s: &State<Secure>| s.apply_erase_code(EraseCode::ResetLinks),
        reset_parameters => |s: &State<Secure>| s.apply_erase_code(EraseCode::ResetParam),
        factory_reset => |s: &State<Secure>| s.apply_erase_code(EraseCode::FactoryReset),
        factory_reset_keep_ia => |s: &State<Secure>| s.apply_erase_code(EraseCode::FactoryResetKeepIA),
        group_key_write => |s: &State<Secure>| {
            s.extension_state().security.grp_keys().borrow_mut().write_entries(3, &[0x3C; 18]).expect("fits");
        },
        no_change => |_: &State<Secure>| {},
    );

    #[allow(dead_code)]
    fn _in_scope<T: StackState + StackDefinition>() {}
}
