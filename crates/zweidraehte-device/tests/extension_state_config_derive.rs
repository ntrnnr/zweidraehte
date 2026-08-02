//! Serde-stability guard for the `#[derive(ExtensionState)]` config mirrors.
//!
//! Workstream A replaced the hand-written `*Config` structs (TP1, RF, …)
//! with config types *generated* by `#[derive(ExtensionState)]`. The
//! generated type is **persisted** — ETS-loaded device state is serialised
//! to it and read back on boot — so its serde shape (field names, serde
//! defaults) must match the hand-written struct it replaced, or a saved
//! config stops round-tripping after the refactor.
//!
//! These tests pin that shape by asserting the JSON the generated config
//! serialises to, and that `from_config`/`to_config` round-trips and the
//! factory `Default` are unchanged. They use `serde_json` (hence `std`)
//! because JSON is exactly what the device's `JsonStorage` backend writes.

use zweidraehte_device::bcus::system_b::{RfExtensionConfig, RfExtensionState, Tp1ExtensionConfig, Tp1ExtensionState};
use zweidraehte_device::extension::ExtensionState;

// ===========================================================================
// TP1 extension (also exercises stacking the derive with
// `#[interface_object_augment]` on the same struct)
// ===========================================================================

/// The generated `Tp1ExtensionConfig` serialises with the same field name
/// (`max_retry_count`) and scalar shape as the hand-written struct.
#[test]
fn tp1_config_json_shape_is_stable() {
    let config = Tp1ExtensionConfig { max_retry_count: 0x33 };
    let json = serde_json::to_string(&config).expect("serialize Tp1ExtensionConfig");
    assert_eq!(json, r#"{"max_retry_count":51}"#);

    let back: Tp1ExtensionConfig = serde_json::from_str(&json).expect("deserialize Tp1ExtensionConfig");
    assert_eq!(back.max_retry_count, config.max_retry_count);
}

/// `#[serde(default = "default_max_retry_count")]` (0x33) fills a missing field.
#[test]
fn tp1_config_serde_default_fills_missing_field() {
    let config: Tp1ExtensionConfig = serde_json::from_str("{}").expect("deserialize empty object");
    assert_eq!(config.max_retry_count, 0x33);
}

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

/// The generated `RfExtensionConfig` serialises with the same single field
/// name (`rf_domain_address`) and value shape (a 6-element byte array) as
/// the hand-written struct.
#[test]
fn rf_config_json_shape_is_stable() {
    let config = RfExtensionConfig { rf_domain_address: [1, 2, 3, 4, 5, 6] };
    let json = serde_json::to_string(&config).expect("serialize RfExtensionConfig");
    assert_eq!(json, r#"{"rf_domain_address":[1,2,3,4,5,6]}"#);

    // And it deserialises back identically.
    let back: RfExtensionConfig = serde_json::from_str(&json).expect("deserialize RfExtensionConfig");
    assert_eq!(back.rf_domain_address, config.rf_domain_address);
}

/// The `#[serde(default = "default_rf_domain_address")]` carried through by
/// the derive lets an empty object deserialise to the factory default
/// (all-zero DoA), exactly as the hand-written `#[serde(default = ...)]` did.
#[test]
fn rf_config_serde_default_fills_missing_field() {
    let config: RfExtensionConfig = serde_json::from_str("{}").expect("deserialize empty object");
    assert_eq!(config.rf_domain_address, [0u8; 6]);
}

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

    /// The generated `IpExtensionConfig` keeps the hand-written struct's field
    /// names and wire types — note `friendly_name_len` persists as a number
    /// (a `u8`, not a `usize`) and the IP addresses persist as 4-byte arrays
    /// (not `Ipv4Addr`), via the `#[config(ty = …, from, to)]` conversions.
    /// `rebind_channel` is `#[runtime_only]` and must NOT appear.
    #[test]
    fn ip_config_json_shape_is_stable() {
        let config = IpExtensionConfig::default();
        let json = serde_json::to_string(&config).expect("serialize IpExtensionConfig");
        // Field order matches declaration order; values match the factory
        // `Default` (DHCP method 4, 224.0.23.12 multicast, /24 subnet, ttl 16).
        let expected = concat!(
            r#"{"friendly_name":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"#,
            r#""friendly_name_len":0,"#,
            r#""configured_ip":[0,0,0,0],"#,
            r#""configured_subnet":[255,255,255,0],"#,
            r#""configured_gateway":[0,0,0,0],"#,
            r#""ip_assignment_method":4,"#,
            r#""routing_multicast":[224,0,23,12],"#,
            r#""ttl":16,"#,
            r#""project_installation_id":0}"#,
        );
        assert_eq!(json, expected);
        // No `rebind_channel` key leaked into the persisted form.
        assert!(!json.contains("rebind_channel"));
    }

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

    /// A config that omits a field still deserialises — `IpExtensionConfig` has
    /// no per-field `#[serde(default)]` (the hand-written struct never did),
    /// so a *missing* field is a serde error; but a present-but-reordered
    /// object round-trips. This pins that we did NOT silently add serde
    /// defaults that would change the deserialisation contract.
    #[test]
    fn ip_config_has_no_injected_serde_defaults() {
        // All fields present, reordered → ok.
        let reordered = r#"{"ttl":16,"friendly_name":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"friendly_name_len":0,"configured_ip":[0,0,0,0],"configured_subnet":[255,255,255,0],"configured_gateway":[0,0,0,0],"ip_assignment_method":4,"routing_multicast":[224,0,23,12],"project_installation_id":0}"#;
        let ok: Result<IpExtensionConfig, _> = serde_json::from_str(reordered);
        assert!(ok.is_ok(), "fully-specified reordered object must deserialise");

        // A missing field is an error (no injected `#[serde(default)]`).
        let missing_ttl = r#"{"friendly_name":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"friendly_name_len":0,"configured_ip":[0,0,0,0],"configured_subnet":[255,255,255,0],"configured_gateway":[0,0,0,0],"ip_assignment_method":4,"routing_multicast":[224,0,23,12],"project_installation_id":0}"#;
        let err: Result<IpExtensionConfig, _> = serde_json::from_str(missing_ttl);
        assert!(err.is_err(), "a missing field must be an error — no serde defaults were injected");
    }
}
