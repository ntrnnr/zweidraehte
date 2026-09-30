//! Guard for the `#[derive(ExtensionState)]` config mirrors.
//!
//! The generated `*Config` type is each leaf extension's configuration data
//! model and, through the derived section impls, its persisted Record. These
//! tests pin that `from_config`/`to_config` round-trips, that the factory
//! `Default` keeps its values (including the `#[config(default = …)]` ones),
//! and the byte layout of the derived section.

use zweidraehte_device::bcus::system_b::{RfExtensionConfig, RfExtensionState, Tp1ExtensionConfig, Tp1ExtensionState};
use zweidraehte_device::extension::ExtensionState;

// ===========================================================================
// TP1 extension (also exercises stacking the derive with
// `#[interface_object_augment]` on the same struct)
// ===========================================================================

/// `Default` yields the factory retry count (0x33 = 3 busy / 3 NAK retries).
#[test]
fn tp1_config_default_is_factory_value() {
    assert_eq!(Tp1ExtensionConfig::default().max_retry_count, 0x33);
}

/// `from_config` → `to_config` round-trips a populated config unchanged.
#[test]
fn tp1_state_config_round_trip() {
    let original = Tp1ExtensionConfig { max_retry_count: 0x21 };
    let state = Tp1ExtensionState::from_config(original.clone(), ());
    let recovered = state.to_config();
    assert_eq!(recovered.max_retry_count, original.max_retry_count);
}

// ===========================================================================
// RF extension
// ===========================================================================

/// `Default` yields the factory RF Domain Address (all zero).
#[test]
fn rf_config_default_is_factory_value() {
    assert_eq!(RfExtensionConfig::default().rf_domain_address, [0u8; 6]);
}

/// `from_config` → `to_config` round-trips a populated config unchanged.
#[test]
fn rf_state_config_round_trip() {
    let original = RfExtensionConfig { rf_domain_address: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] };
    let state = RfExtensionState::from_config(original.clone(), ());
    let recovered = state.to_config();
    assert_eq!(recovered.rf_domain_address, original.rf_domain_address);
}

// ===========================================================================
// IP extension (the hardest case: type-diverging fields, a runtime-only
// channel, and hand-written `Default` / `on_erase` via opt-out attributes)
// ===========================================================================

#[cfg(feature = "knxip")]
mod ip {
    use zweidraehte_device::bcus::system_b::{IpExtensionConfig, IpExtensionState};
    use zweidraehte_device::extension::ExtensionState;

    /// `from_config` → `to_config` round-trips every field, exercising both
    /// directions of each type conversion (`u8`↔`usize`, `[u8;4]`↔`Ipv4Addr`).
    #[test]
    fn ip_state_config_round_trip() {
        let mut original = IpExtensionConfig::default();
        original.friendly_name[..4].copy_from_slice(b"KNX!");
        original.friendly_name_len = 4;
        original.configured_ip = [192, 168, 1, 50];
        original.configured_subnet = [255, 255, 255, 0];
        original.configured_gateway = [192, 168, 1, 1];
        original.ip_assignment_method = 0x01;
        original.routing_multicast = [224, 0, 23, 13];
        original.ttl = 8;
        original.project_installation_id = 0xABCD;

        let state = <IpExtensionState>::from_config(original.clone(), ());
        let recovered = state.to_config();

        assert_eq!(recovered.friendly_name, original.friendly_name);
        assert_eq!(recovered.friendly_name_len, original.friendly_name_len);
        assert_eq!(recovered.configured_ip, original.configured_ip);
        assert_eq!(recovered.configured_subnet, original.configured_subnet);
        assert_eq!(recovered.configured_gateway, original.configured_gateway);
        assert_eq!(recovered.ip_assignment_method, original.ip_assignment_method);
        assert_eq!(recovered.routing_multicast, original.routing_multicast);
        assert_eq!(recovered.ttl, original.ttl);
        assert_eq!(recovered.project_installation_id, original.project_installation_id);
    }
}

// ===========================================================================
// Generated persistent sections
// ===========================================================================

/// The derive emits one Record section whose length is the sum of the
/// config fields' fixed encodings, and whose bytes are those fields in
/// declaration order.
#[test]
fn derived_section_is_the_config_fields_in_order() {
    use zweidraehte_device::sections::{ExtensionSections, SectionBytes, SectionKind};

    assert_eq!(<RfExtensionConfig as SectionBytes>::LEN, 6);
    let state = RfExtensionState::from_config(RfExtensionConfig { rf_domain_address: [1, 2, 3, 4, 5, 6] }, ());

    let mut sections = Vec::new();
    state.for_each_section(0x40, &mut |section| sections.push(section));
    assert_eq!(sections.len(), 1);
    assert_eq!((sections[0].id, sections[0].len, sections[0].kind), (0x40, 6, SectionKind::Record));

    let mut record = [0u8; 6];
    state.read_section(0, 0, &mut record);
    assert_eq!(record, [1, 2, 3, 4, 5, 6]);
}

/// Applying a record restores the fields; a partial record is rejected and
/// changes nothing; a reset restores the factory default.
#[test]
fn derived_section_applies_whole_records_only() {
    use zweidraehte_device::sections::{ExtensionSections, SectionError};

    let state = Tp1ExtensionState::from_config(Tp1ExtensionConfig::default(), ());
    state.apply_section(0, 0, &[0x21]).expect("whole record");
    assert_eq!(state.to_config().max_retry_count, 0x21);

    assert_eq!(state.apply_section(0, 0, &[]), Err(SectionError::Malformed));
    assert_eq!(state.apply_section(1, 0, &[0x11]), Err(SectionError::UnknownSection));
    assert_eq!(state.to_config().max_retry_count, 0x21);

    state.reset_section(0);
    assert_eq!(state.to_config().max_retry_count, 0x33);
}
