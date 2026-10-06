//! The persistent sections of a System B device restore it exactly.
//!
//! The oracle is the section dump: a state configured through the stack's
//! own paths is copied section by section into a factory-fresh state, and
//! both must then read back identical bytes for every section. Every
//! extension composition runs the same check. That every persistent field
//! has a section at all is `tests/persistent_fields.rs`' job.

use std::vec::Vec;

use const_default::ConstDefault;
use zerocopy::{Immutable, IntoBytes, KnownLayout};
use zweidraehte_device::DeviceDefinition;
use zweidraehte_device::bcus::system_b::{
    RfExtensionState, RfRetransmitterExtension, SecureExtensionState, SecureResources, SystemBDeviceState, Tp1,
    Tp1ExtensionState,
};
use zweidraehte_device::layers::linklayers::mock::MockLinkLayerBuilder;
use zweidraehte_device::objects::comm::{ComObjects, NoComObjects};
use zweidraehte_device::objects::interface::{
    HasMaxRetryCount, HasRfDomainAddress, HasRfRetransmitter, HasRoutingCount,
};
use zweidraehte_device::objects::tables::{
    HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasLoadStateMachine,
    HasPeiApplication, LoadError, LoadEvent, LoadState, TableMemory,
};
use zweidraehte_device::sections::{PersistentSections, Section, SectionError, SectionId, SectionKind, ids};
use zweidraehte_device::storage::StaticIdentity;
use zweidraehte_device::{HasAuthorization, StackState};
use zweidraehte_proto::AccessContext;
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

/// Take a factory table or application through a complete load.
fn load<T: HasLoadStateMachine>(table: &mut T) {
    table.write_lsm(&[LoadEvent::StartLoading.into()], None);
    table.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
}

/// Configure the device core away from its factory state through the
/// stack's own paths: IA, routing count, every key, every table's data,
/// loaded tables and application program 2, and the three program
/// identities.
macro_rules! configure_core {
    ($state:expr, $bytes:expr) => {{
        let (state, bytes) = ($state, $bytes);
        state.set_individual_address(IndividualAddress::new(1, 2, 3));
        state.set_routing_count(5);
        for level in 0..3 {
            state.key_write(level, &bytes.fill(), AccessContext::MAX_ACCESS);
        }
        state.adt().borrow_mut().write(0, &bytes.vec(ADT));
        state.ast().borrow_mut().write(0, &bytes.vec(AST));
        state.cot().borrow_mut().write(0, &bytes.vec(COT));
        state.app().borrow_mut().params_mut().bytes = bytes.fill();
        load(&mut *state.adt().borrow_mut());
        load(&mut *state.ast().borrow_mut());
        load(&mut *state.cot().borrow_mut());
        load(&mut *state.app().borrow_mut());
        load(&mut *state.pei().borrow_mut());
        *state.program_version().borrow_mut() = bytes.fill();
        state.program_pei_type().set(0x14);
        *state.pei_program_version().borrow_mut() = bytes.fill();
    }};
}

/// Configure a Data Secure extension's security state away from factory.
macro_rules! configure_security {
    ($security:expr, $bytes:expr) => {{
        let (security, bytes) = ($security, $bytes);
        security.set_security_mode_enabled(true);
        security.set_tool_key(bytes.fill());
        security.set_security_report(0x01);
        security.set_security_report_enabled(true);
        security.grp_keys().borrow_mut().write_entries(0, &bytes.vec(2 * 18)).expect("two group keys fit");
        security.p2p_keys().borrow_mut().write_entries(0, &bytes.vec(20)).expect("one P2P key fits");
        security.go_flags().borrow_mut().write_entries(0, &bytes.vec(3)).expect("three GO flags fit");
        let mut log = security.failures_log().borrow_mut();
        log.log_failure(SecurityFailureType::SeqNrError, 0x1101, &[]);
        log.log_failure(SecurityFailureType::AccessError, 0x1102, &[]);
    }};
}

fn sections<S: PersistentSections>(state: &S) -> Vec<Section> {
    let mut sections = Vec::new();
    state.for_each_section(&mut |section| sections.push(section));
    sections
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
/// factory-fresh one reads back the same bytes — once whole, once in
/// chunks.
fn assert_sections_restore<S: PersistentSections>(configured: impl Fn() -> S, fresh: impl Fn() -> S) {
    let expected = dump(&configured());
    assert_ne!(dump(&fresh()), expected, "the test configuration must differ from factory");

    let whole = fresh();
    copy_sections(&configured(), &whole, None);
    assert_eq!(dump(&whole), expected, "whole-section copy differs");

    let chunked = fresh();
    copy_sections(&configured(), &chunked, Some(&mut Bytes(0x1234_5678)));
    assert_eq!(dump(&chunked), expected, "chunked copy differs");
}

fn fresh<ES: zweidraehte_device::extension::ExtensionState>(resources: ES::Resources) -> State<ES> {
    State::<ES>::new(StaticIdentity::new([0; 6]), NoComObjects::new(), resources)
}

// ============================================================================
// Oracle round trips, one per extension composition
// ============================================================================

#[test]
fn plain_device_core_restores() {
    let configured = || {
        let state = fresh::<()>(());
        configure_core!(&state, &mut Bytes(0x1234));
        state
    };
    assert_sections_restore(configured, || fresh::<()>(()));
}

#[test]
fn tp1_restores() {
    let configured = || {
        let state = fresh::<Tp1ExtensionState>(());
        configure_core!(&state, &mut Bytes(0x1234));
        state.extension_state().set_max_retry_count(0x21);
        state
    };
    assert_sections_restore(configured, || fresh::<Tp1ExtensionState>(()));
}

#[test]
fn rf_restores() {
    let configured = || {
        let state = fresh::<RfExtensionState>(());
        configure_core!(&state, &mut Bytes(0x1234));
        state.extension_state().set_rf_domain_address(&[1, 2, 3, 4, 5, 6]);
        state
    };
    assert_sections_restore(configured, || fresh::<RfExtensionState>(()));
}

#[test]
fn rf_retransmitter_restores() {
    let configured = || {
        let state = fresh::<RfRetransmitterExtension>(());
        configure_core!(&state, &mut Bytes(0x1234));
        let extension = state.extension_state();
        extension.set_rf_domain_address(&[9; 6]);
        extension.set_rf_retransmit_enabled(true);
        extension.set_rf_repeat_counter_limit(3);
        state
    };
    assert_sections_restore(configured, || fresh::<RfRetransmitterExtension>(()));
}

#[test]
fn secure_tp1_restores() {
    type Secure = SecureExtensionState<Tp1ExtensionState, 8, 4, 8>;
    let configured = || {
        let state = fresh::<Secure>(SecureResources::simple(FDSK));
        let mut bytes = Bytes(0xCAFE);
        configure_core!(&state, &mut bytes);
        configure_security!(&state.extension_state().security, &mut bytes);
        state.extension_state().set_max_retry_count(0x12);
        state
    };
    assert_sections_restore(configured, || fresh::<Secure>(SecureResources::simple(FDSK)));
}

#[test]
fn secure_rf_retransmitter_restores() {
    type Secure = SecureExtensionState<RfRetransmitterExtension, 8, 4, 8>;
    let configured = || {
        let state = fresh::<Secure>(SecureResources::simple(FDSK));
        let mut bytes = Bytes(0xBEEF);
        configure_core!(&state, &mut bytes);
        let extension = state.extension_state();
        configure_security!(&extension.security, &mut bytes);
        extension.set_rf_domain_address(&[7; 6]);
        extension.set_rf_retransmit_enabled(true);
        extension.set_rf_repeat_counter_limit(2);
        state
    };
    assert_sections_restore(configured, || fresh::<Secure>(SecureResources::simple(FDSK)));
}

#[cfg(feature = "knxip")]
mod ip {
    use super::*;
    use core::net::Ipv4Addr;
    use zweidraehte_device::IpStateView;
    use zweidraehte_device::bcus::system_b::{IpExtensionState, IpInterfaceExtension, TunnellingExtension};

    pub(super) fn configure_ip<const CAPS: u16>(ip: &IpExtensionState<CAPS>) {
        ip.set_friendly_name(b"Lobby gateway");
        ip.set_configured_ip_address(Ipv4Addr::new(192, 168, 1, 50));
        ip.set_configured_subnet_mask(Ipv4Addr::new(255, 255, 255, 0));
        ip.set_configured_default_gateway(Ipv4Addr::new(192, 168, 1, 1));
        ip.set_ip_assignment_method(1);
        ip.set_routing_multicast_address(Ipv4Addr::new(224, 0, 23, 13));
        ip.set_ttl(32);
        ip.set_project_installation_id(0x1234);
        ip.set_routing_busy_wait_time(42);
    }

    pub(super) fn configure_tunnelling<const N: usize>(tunnelling: &TunnellingExtension<N>) {
        tunnelling
            .set_additional_individual_addresses(&[IndividualAddress::new(1, 1, 10), IndividualAddress::new(1, 1, 11)])
            .expect("two addresses fit");
    }

    #[test]
    fn ip_restores() {
        let configured = || {
            let state = fresh::<IpExtensionState<0>>(());
            configure_core!(&state, &mut Bytes(7));
            configure_ip(state.extension_state());
            state
        };
        assert_sections_restore(configured, || fresh::<IpExtensionState<0>>(()));
    }

    #[test]
    fn ip_interface_restores() {
        let configured = || {
            let state = fresh::<IpInterfaceExtension<4, 0>>(());
            configure_core!(&state, &mut Bytes(8));
            configure_ip(&state.extension_state().ip);
            configure_tunnelling(&state.extension_state().tunnelling);
            state
        };
        assert_sections_restore(configured, || fresh::<IpInterfaceExtension<4, 0>>(()));
    }
}

#[cfg(feature = "ip-secure")]
mod ip_secure {
    use super::ip::{configure_ip, configure_tunnelling};
    use super::*;
    use zweidraehte_device::bcus::system_b::{IpSecureInterfaceExtension, IpSecureResources};
    use zweidraehte_proto::messages::knxip::substructs::ServiceFamily;

    #[test]
    fn secure_ip_interface_restores() {
        type Secure = SecureExtensionState<IpSecureInterfaceExtension<4, 0, 4, 4>, 8, 4, 8>;
        let resources = || SecureResources { inner: IpSecureResources { fdsk: FDSK }, fdsk: FDSK };
        let configured = || {
            let state = fresh::<Secure>(resources());
            let mut bytes = Bytes(0xD00D);
            configure_core!(&state, &mut bytes);
            let extension = state.extension_state();
            configure_security!(&extension.security, &mut bytes);
            configure_ip(&extension.inner.ip.ip);
            configure_tunnelling(&extension.inner.ip.tunnelling);
            let ip_secure = &extension.inner.ip_secure;
            ip_secure.set_backbone_key(bytes.fill());
            ip_secure.set_secured_service_family(ServiceFamily::Tunneling, 1);
            ip_secure.password_hashes().borrow_mut().write_entries(1, &bytes.vec(16)).expect("hash fits");
            ip_secure.tunnelling_users().borrow_mut().write_entries(0, &[1, 1]).expect("user fits");
            state
        };
        assert_sections_restore(configured, || fresh::<Secure>(resources()));
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
    let state = fresh::<Tp1ExtensionState>(());
    configure_core!(&state, &mut Bytes(0x55AA));
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

/// Offset of an Image's payload in the fixed ByteNv layout.
fn byte_image_offset<S: PersistentSections>(state: &S, id: SectionId) -> usize {
    let mut offset = 10;
    let mut found = None;
    state.for_each_section(&mut |section| {
        if section.id == id {
            found = Some(offset);
        }
        let len = usize::from(section.len);
        offset += match section.kind {
            SectionKind::Record => 2 * (1 + len + 2),
            SectionKind::Image => len + 2,
        };
    });
    found.expect("image is in this layout")
}

#[test]
fn loaded_byte_image_crc_error_is_durable_without_erasing_data() {
    use zweidraehte_nv::mock::Backing;
    use zweidraehte_nv::{ByteNv, NvError, NvStore};

    let medium = Backing::new(4096, 1);
    let configured = fresh::<Tp1ExtensionState>(());
    let mut bytes = Bytes(0x7777);
    configure_core!(&configured, &mut bytes);
    ByteNv::new(medium.open_bytes(), 0, 4096).load(&configured).expect("format");

    let image_at = byte_image_offset(&configured, 0x08);
    let mut expected = configured.adt().borrow().data_image().to_vec();
    expected[3] ^= 0x5A;
    medium.poke(image_at + 3, &expected[3..4]);

    // A failed control write must stop boot; otherwise the next boot could
    // still see Loaded while the image remains corrupt.
    medium.set_failing(true);
    let failed = fresh::<Tp1ExtensionState>(());
    assert_eq!(ByteNv::new(medium.open_bytes(), 0, 4096).load(&failed), Err(NvError::Io(())));
    medium.set_failing(false);

    let restored = fresh::<Tp1ExtensionState>(());
    let mut store = ByteNv::new(medium.open_bytes(), 0, 4096);
    store.load(&restored).expect("restore");
    assert_eq!(restored.adt().borrow().load_state(), LoadState::Err);
    assert_eq!(restored.adt().borrow().last_error_code(), LoadError::CrcError as u8);
    assert_eq!(restored.adt().borrow().data_image(), expected);
    assert_eq!(restored.ast().borrow().load_state(), LoadState::Loaded);

    // Persisting only one later byte refreshes the image CRC. It must not
    // make the Error control look Loaded on the next boot.
    expected[4] ^= 0x33;
    restored.adt().borrow_mut().data_image_mut()[4] = expected[4];
    store.persist(&restored, 0x08, 4, 1).expect("partial image write");
    drop(store);

    let again = fresh::<Tp1ExtensionState>(());
    ByteNv::new(medium.open_bytes(), 0, 4096).load(&again).expect("reboot");
    assert_eq!(again.adt().borrow().load_state(), LoadState::Err);
    assert_eq!(again.adt().borrow().last_error_code(), LoadError::CrcError as u8);
    assert_eq!(again.adt().borrow().data_image(), expected);
}

#[test]
fn interrupted_byte_image_keeps_loading_state() {
    use zweidraehte_nv::mock::Backing;
    use zweidraehte_nv::{ByteNv, NvStore};

    let medium = Backing::new(4096, 1);
    let configured = fresh::<Tp1ExtensionState>(());
    let mut bytes = Bytes(0x8888);
    configure_core!(&configured, &mut bytes);
    let mut store = ByteNv::new(medium.open_bytes(), 0, 4096);
    store.load(&configured).expect("format");
    configured.adt().borrow_mut().write_lsm(&[LoadEvent::StartLoading.into()], None);
    store.persist(&configured, 0x03, 0, 14).expect("persist Loading");
    drop(store);

    let image_at = byte_image_offset(&configured, 0x08);
    let changed = configured.adt().borrow().data_image()[3] ^ 0x5A;
    medium.poke(image_at + 3, &[changed]);

    let restored = fresh::<Tp1ExtensionState>(());
    ByteNv::new(medium.open_bytes(), 0, 4096).load(&restored).expect("restore");
    assert_eq!(restored.adt().borrow().load_state(), LoadState::Loading);
    assert_eq!(restored.adt().borrow().last_error_code(), 0);
    assert_eq!(restored.adt().borrow().data_image()[3], changed);
}

/// A secure device with the Security IO in `load_state`, formatted onto a
/// fresh byte medium.
fn secure_on_medium(
    medium: &zweidraehte_nv::mock::Backing,
    load_state: LoadState,
) -> State<SecureExtensionState<Tp1ExtensionState, 8, 4, 8>> {
    use zweidraehte_nv::{ByteNv, NvStore};

    let state = fresh::<SecureExtensionState<Tp1ExtensionState, 8, 4, 8>>(SecureResources::simple(FDSK));
    let mut bytes = Bytes(0x9999);
    configure_core!(&state, &mut bytes);
    configure_security!(&state.extension_state().security, &mut bytes);
    state.extension_state().security.set_load_state(load_state);
    ByteNv::new(medium.open_bytes(), 0, 4096).load(&state).expect("format");

    state
}

/// The Security IO's key tables follow the same rule as the other tables,
/// through the object's own load state (03/05/01 §6.3.4).
#[test]
fn loaded_security_key_image_crc_error_marks_the_security_object_error() {
    use zweidraehte_nv::mock::Backing;
    use zweidraehte_nv::{ByteNv, NvError, NvStore};

    const GROUP_KEYS: SectionId = ids::DATA_SECURE_GROUP_KEYS;

    let medium = Backing::new(4096, 1);
    let configured = secure_on_medium(&medium, LoadState::Loaded);

    let image_at = byte_image_offset(&configured, GROUP_KEYS);
    let mut expected = [0u8; 2 * 18];
    configured.read_section(GROUP_KEYS, 0, &mut expected);
    expected[5] ^= 0x5A;
    medium.poke(image_at + 5, &expected[5..6]);

    let reboot = || {
        let state = fresh::<SecureExtensionState<Tp1ExtensionState, 8, 4, 8>>(SecureResources::simple(FDSK));
        let result = ByteNv::new(medium.open_bytes(), 0, 4096).load(&state);
        (state, result)
    };

    medium.set_failing(true);
    assert_eq!(reboot().1, Err(NvError::Io(())), "an unpersisted Error must stop boot");
    medium.set_failing(false);

    let (restored, result) = reboot();
    result.expect("restore");

    let mut keys = [0u8; 2 * 18];
    restored.read_section(GROUP_KEYS, 0, &mut keys);
    assert_eq!(restored.extension_state().security.load_state(), LoadState::Err);
    assert_eq!(keys, expected, "the key bytes are kept");
    assert_eq!(restored.adt().borrow().load_state(), LoadState::Loaded);

    let (again, result) = reboot();
    result.expect("reboot");
    assert_eq!(again.extension_state().security.load_state(), LoadState::Err);
}

/// A Security IO download interrupted in Loading is already invalid.
#[test]
fn interrupted_security_image_keeps_loading_state() {
    use zweidraehte_nv::mock::Backing;
    use zweidraehte_nv::{ByteNv, NvStore};

    const GO_FLAGS: SectionId = ids::DATA_SECURE_GO_FLAGS;

    let medium = Backing::new(4096, 1);
    let configured = secure_on_medium(&medium, LoadState::Loading);

    let image_at = byte_image_offset(&configured, GO_FLAGS);
    let mut flags = [0u8; 8];
    configured.read_section(GO_FLAGS, 0, &mut flags);
    medium.poke(image_at + 1, &[flags[1] ^ 0x03]);

    let restored = fresh::<SecureExtensionState<Tp1ExtensionState, 8, 4, 8>>(SecureResources::simple(FDSK));
    ByteNv::new(medium.open_bytes(), 0, 4096).load(&restored).expect("restore");

    let mut restored_flags = [0u8; 8];
    restored.read_section(GO_FLAGS, 0, &mut restored_flags);
    assert_eq!(restored.extension_state().security.load_state(), LoadState::Loading);
    assert_eq!(restored_flags[1], flags[1] ^ 0x03);
}

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

/// The same product after an update that changed what its parameter bytes
/// mean, not their length.
#[derive(Clone, Copy)]
struct RevisedDefinition;

impl DeviceDefinition for RevisedDefinition {
    const DEVICE: &'static DeviceDescriptor = &DEVICE;
    const CONFIG_REVISION: u16 = 1;

    type Params = TestParams;
    type ComObjects = NoComObjects;
    type LinkLayer = MockLinkLayerBuilder<1>;
}

/// A product's `CONFIG_REVISION` reaches the fingerprint through the preset:
/// the section list is unchanged, yet stored bytes no longer match.
#[test]
fn a_config_revision_moves_the_fingerprint() {
    let current = State::<Tp1ExtensionState>::new(StaticIdentity::new([0; 6]), NoComObjects::new(), ());
    let revised = SystemBDeviceState::<ADT, AST, COT, Tp1<RevisedDefinition>, Tp1ExtensionState>::new(
        StaticIdentity::new([0; 6]),
        NoComObjects::new(),
        (),
    );

    assert_eq!(sections(&current), sections(&revised));
    assert_ne!(current.layout_fingerprint(), revised.layout_fingerprint());
}

// ============================================================================
// Write-through: every mutation path persists
// ============================================================================
//
// Each case mutates a configured state the way the stack does, flushes it
// into a store, boots a fresh state from the same medium, and requires the
// same section bytes. The flusher is told nothing: Records are found by
// comparing with the store's durable copy, Images by their owners' dirty
// ranges. A path that changes configuration without either would fail here.

mod write_through {
    use super::*;
    use zweidraehte_device::memory::MemoryMap;
    use zweidraehte_device::restart::EraseCode;
    use zweidraehte_device::{HasPersistence, StackDefinition};
    use zweidraehte_nv::mock::{Backing, MockBytes, MockFlash};
    use zweidraehte_nv::{ByteNv, FlashLog, Flusher, LogGeometry, NvStore};

    type Secure = SecureExtensionState<Tp1ExtensionState, 8, 4, 8>;

    fn secure_state(configured: bool) -> State<Secure> {
        let state = fresh::<Secure>(SecureResources::simple(FDSK));
        if configured {
            let mut bytes = Bytes(0x7777);
            configure_core!(&state, &mut bytes);
            configure_security!(&state.extension_state().security, &mut bytes);
            state.extension_state().set_max_retry_count(0x21);
        }
        state
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
        let expected = dump(&state);
        drop(store);

        let rebooted = secure_state(false);
        medium.open().load(&rebooted).expect("reboot");
        assert_eq!(dump(&rebooted), expected);
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
        fn reboot(backing: &Backing) -> Vec<(SectionId, Vec<u8>)> {
            let rebooted = secure_state(false);
            let handle: Handle = ConfigStorage::new(NvConfig::new(ByteNv::new(backing.open_bytes(), 0, 4096)));
            handle.config.load(&rebooted).expect("reboot");
            dump(&rebooted)
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

            assert_eq!(reboot(&backing), dump(&state));
        }

        /// The storage task's path after a restart: an erase code is durable
        /// after the handle's flush.
        #[test]
        fn the_flush_after_an_erase_persists_it() {
            let backing = Backing::new(4096, 1);
            let (state, handle) = boot(&backing);

            state.apply_erase_code(EraseCode::FactoryReset);
            handle.flush(&state).expect("flush");

            assert_eq!(reboot(&backing), dump(&state));
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

    /// The flash config log firmware places: a two-bank `FlashLog` behind an
    /// `NvConfig`, opened over an area like on a device.
    mod config_log_region {
        use super::*;
        use std::cell::RefCell;
        use zweidraehte_device::storage::{ConfigLog, ConfigStorage, DeviceStorage, LogGeometry, NvConfig, SectorIo};
        use zweidraehte_nv::FlashLog;

        const SECTOR: u32 = 2048;
        const REGION: usize = 16 * 1024;
        const BANK: usize = REGION / 2;

        /// A `Copy` handle over a mock flash, as a platform's flash `Io` is.
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

        type Handle = ConfigStorage<ConfigLog<TestIo>>;

        fn open(backing: &Backing) -> Handle {
            let flash: &'static RefCell<MockFlash<8>> = Box::leak(Box::new(RefCell::new(backing.open_aligned())));
            let geometry = LogGeometry::two_banks(0, REGION as u32, SECTOR);
            ConfigStorage::new(NvConfig::new(FlashLog::new(TestIo(flash), geometry)))
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
            let expected = dump(&state);
            drop(handle);

            let rebooted = secure_state(false);
            open(&backing).config.load(&rebooted).expect("reboot");
            assert_eq!(dump(&rebooted), expected);
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
