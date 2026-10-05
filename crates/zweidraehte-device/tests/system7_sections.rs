//! The persistent sections of a System 7 device restore it exactly, and
//! write-through persistence reaches every mutation path — including the
//! memory-mapped load controls and the individual address kept inside the
//! address table.

use std::vec::Vec;

use const_default::ConstDefault;
use zerocopy::{Immutable, IntoBytes, KnownLayout};
use zweidraehte_device::DeviceDefinition;
use zweidraehte_device::HasAuthorization;
use zweidraehte_device::bcus::system_7::{System7DeviceState, Tp1, Tp1ExtensionState};
use zweidraehte_device::bcus::system_b::{SecureExtensionState, SecureResources};
use zweidraehte_device::extension::ExtensionState;
use zweidraehte_device::layers::linklayers::mock::MockLinkLayerBuilder;
use zweidraehte_device::objects::comm::{ComObjects, NoComObjects};
use zweidraehte_device::objects::interface::{HasMaxRetryCount, HasRoutingCount};
use zweidraehte_device::objects::tables::{
    HasCommunicationObjectTable, HasLoadStateMachine, LoadError, LoadState, RunnableApplication, Table,
};
use zweidraehte_device::sections::SectionId;
use zweidraehte_device::sections::{PersistentSections, Section, SectionKind};
use zweidraehte_device::storage::StaticIdentity;
use zweidraehte_proto::AccessContext;
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

/// Configure the device core away from its factory state everywhere it
/// persists something, with the IA 1.2.3 in the address table and every
/// table loaded at its product-database address, as a download leaves it.
fn configure_core<ES: ExtensionState>(state: &State<ES>, bytes: &mut Bytes)
where
    State<ES>: HasAuthorization + HasRoutingCount,
{
    let mut adt = bytes.vec(ADT);
    adt[1..3].copy_from_slice(IndividualAddress::new(1, 2, 3).as_bytes());
    for level in 0..15 {
        state.key_write(level, &bytes.fill(), AccessContext::MAX_ACCESS);
    }
    state.set_routing_count(5);
    state.set_option_reg(0x42);
    *state.adt.borrow_mut() = Table::with_data(&adt, 0x4000);
    *state.ast.borrow_mut() = Table::with_data(&bytes.vec(AST), AST_ADDRESS);
    *state.cot.borrow_mut() = Table::with_data(&bytes.vec(COT), u32::from(COT_ADDRESS));
    *state.app.borrow_mut() = RunnableApplication::from_table(Table::with_data(&bytes.vec(24), APP_ADDRESS));
    *state.app2.borrow_mut() = RunnableApplication::from_table(Table::with_data(&[], 0));
    *state.program_version.borrow_mut() = bytes.fill();
    state.pei_type.set(0x14);
    *state.program2_version.borrow_mut() = bytes.fill();
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

/// Every section's current bytes: what a store would persist.
fn dump<S: PersistentSections>(state: &S) -> Vec<(SectionId, Vec<u8>)> {
    sections(state)
        .into_iter()
        .map(|section| {
            let mut bytes = vec![0u8; usize::from(section.len)];
            state.read_section(section.id, 0, &mut bytes);
            (section.id, bytes)
        })
        .collect()
}

fn plain_state(configured: bool) -> State<Tp1ExtensionState> {
    let state = State::<Tp1ExtensionState>::new(StaticIdentity::new([0; 6]), NoComObjects::new(), ());
    if configured {
        configure_core(&state, &mut Bytes(0x1234));
        state.extension_state().set_max_retry_count(0x21);
    }
    state
}

fn secure_state(configured: bool) -> State<Secure> {
    let state = State::<Secure>::new(StaticIdentity::new([0; 6]), NoComObjects::new(), SecureResources::simple(FDSK));
    if configured {
        let mut bytes = Bytes(0x5678);
        configure_core(&state, &mut bytes);
        let security = &state.extension_state().security;
        security.set_security_mode_enabled(true);
        security.set_tool_key(bytes.fill());
        security.grp_keys().borrow_mut().write_entries(0, &bytes.vec(2 * 18)).expect("two group keys fit");
        security.go_flags().borrow_mut().write_entries(0, &bytes.vec(3)).expect("three GO flags fit");
        state.extension_state().set_max_retry_count(0x21);
    }
    state
}

// ============================================================================
// Oracle round trips and format guard
// ============================================================================

#[test]
fn plain_system7_restores() {
    let configured = plain_state(true);
    let fresh = plain_state(false);
    assert_ne!(dump(&fresh), dump(&configured));
    copy_sections(&configured, &fresh);
    assert_eq!(dump(&fresh), dump(&configured));
}

#[test]
fn secure_system7_restores() {
    let configured = secure_state(true);
    let fresh = secure_state(false);
    assert_ne!(dump(&fresh), dump(&configured));
    copy_sections(&configured, &fresh);
    assert_eq!(dump(&fresh), dump(&configured));
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

/// System 7's COT Image is governed by the application load control.
#[test]
fn corrupt_cot_image_marks_application_error() {
    use zweidraehte_nv::mock::Backing;
    use zweidraehte_nv::{ByteNv, NvStore};

    let medium = Backing::new(4096, 1);
    let configured = plain_state(true);
    ByteNv::new(medium.open_bytes(), 0, 4096).load(&configured).expect("format");

    let mut at = 10usize;
    let mut cot_at = None;
    configured.for_each_section(&mut |section| {
        if section.id == 0x0A {
            cot_at = Some(at);
        }
        let len = usize::from(section.len);
        at += match section.kind {
            SectionKind::Record => 2 * (1 + len + 2),
            SectionKind::Image => len + 2,
        };
    });
    let cot_at = cot_at.expect("COT Image is in this layout");
    let mut expected = configured.cot.borrow().data_image().to_vec();
    expected[3] ^= 0x5A;
    medium.poke(cot_at + 3, &expected[3..4]);

    let restored = plain_state(false);
    ByteNv::new(medium.open_bytes(), 0, 4096).load(&restored).expect("restore");
    assert_eq!(restored.app.borrow().load_state(), LoadState::Err);
    assert_eq!(restored.app.borrow().last_error_code(), LoadError::CrcError as u8);
    assert_eq!(restored.cot_load_state(), LoadState::Err);
    assert_eq!(restored.cot.borrow().data_image(), expected);

    let again = plain_state(false);
    ByteNv::new(medium.open_bytes(), 0, 4096).load(&again).expect("reboot");
    assert_eq!(again.app.borrow().load_state(), LoadState::Err);
    assert_eq!(again.cot.borrow().data_image(), expected);
}

/// The family forwards a security Image mismatch to the Security IO.
#[test]
fn corrupt_security_key_image_marks_security_object_error() {
    use zweidraehte_nv::mock::Backing;
    use zweidraehte_nv::{ByteNv, NvStore};

    const GROUP_KEYS: SectionId = 0x22;

    let medium = Backing::new(4096, 1);
    let configured = secure_state(true);
    configured.extension_state().security.set_load_state(LoadState::Loaded);
    ByteNv::new(medium.open_bytes(), 0, 4096).load(&configured).expect("format");

    let mut at = 10usize;
    let mut keys_at = None;
    configured.for_each_section(&mut |section| {
        if section.id == GROUP_KEYS {
            keys_at = Some(at);
        }
        let len = usize::from(section.len);
        at += match section.kind {
            SectionKind::Record => 2 * (1 + len + 2),
            SectionKind::Image => len + 2,
        };
    });
    let keys_at = keys_at.expect("group key Image is in this layout");
    let mut expected = [0u8; 2 * 18];
    configured.read_section(GROUP_KEYS, 0, &mut expected);
    expected[5] ^= 0x5A;
    medium.poke(keys_at + 5, &expected[5..6]);

    let restored = secure_state(false);
    ByteNv::new(medium.open_bytes(), 0, 4096).load(&restored).expect("restore");

    let mut keys = [0u8; 2 * 18];
    restored.read_section(GROUP_KEYS, 0, &mut keys);
    assert_eq!(restored.extension_state().security.load_state(), LoadState::Err);
    assert_eq!(keys, expected);
    assert_eq!(restored.app.borrow().load_state(), LoadState::Loaded);

    let again = secure_state(false);
    ByteNv::new(medium.open_bytes(), 0, 4096).load(&again).expect("reboot");
    assert_eq!(again.extension_state().security.load_state(), LoadState::Err);
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
    /// medium, and require the same section bytes.
    fn persists<M: Medium>(mutate: impl FnOnce(&State<Secure>)) {
        let medium = M::new();
        let state = secure_state(true);
        let mut store = medium.open();
        store.load(&state).expect("format with the configured state");

        mutate(&state);
        Flusher::new().flush(&state, &mut store).expect("flush");
        let expected = dump(&state);
        drop(store);

        let rebooted = secure_state(false);
        medium.open().load(&rebooted).expect("reboot");
        assert_eq!(dump(&rebooted), expected);
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
