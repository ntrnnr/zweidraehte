//! The persistent sections of a System B device cover everything the
//! whole-config blob persists, and restore it exactly.
//!
//! The oracle is the existing `to_config` snapshot: a state built from a
//! non-default configuration is copied section by section into a
//! factory-fresh state, and both must serialise to identical bytes. Every
//! extension composition runs the same check, so an extension field that
//! has no section cannot hide.

use std::vec::Vec;

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
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
#[derive(Clone, Copy, ConstDefault, IntoBytes, KnownLayout, Immutable, Serialize, Deserialize)]
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

fn snapshot_bytes<T: Serialize>(config: &T) -> Vec<u8> {
    let mut buf = vec![0u8; 16 * 1024];
    let len = postcard::to_slice(config, &mut buf).expect("config fits the buffer").len();
    buf.truncate(len);
    buf
}

/// The oracle check: a configured state copied section by section into a
/// fresh one serialises identically — once whole, once in chunks.
fn assert_sections_restore<ES>(extension_config: ES::Config, resources: impl Fn() -> ES::Resources)
where
    ES: ExtensionSections,
    ES::Config: Serialize,
{
    let mut bytes = Bytes(0x1234_5678);
    let configured =
        State::<ES>::from_config(StaticIdentity::new([0; 6]), device_config(extension_config, &mut bytes), resources());
    let expected = snapshot_bytes(&configured.to_config());

    let fresh = State::<ES>::new(StaticIdentity::new([0; 6]), NoComObjects::new(), resources());
    assert_ne!(snapshot_bytes(&fresh.to_config()), expected, "the test configuration must differ from factory");
    copy_sections(&configured, &fresh, None);
    assert_eq!(snapshot_bytes(&fresh.to_config()), expected, "whole-section copy differs");

    let chunked = State::<ES>::new(StaticIdentity::new([0; 6]), NoComObjects::new(), resources());
    copy_sections(&configured, &chunked, Some(&mut bytes));
    assert_eq!(snapshot_bytes(&chunked.to_config()), expected, "chunked copy differs");
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
