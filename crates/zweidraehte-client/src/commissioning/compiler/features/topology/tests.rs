use super::routing::{encode_filter_bitmap, legacy_group_selector, modern_group_selector};
use crate::commissioning::error::CompileErrorKind;
use crate::commissioning::test_support::architecture::resolve_profile;
use crate::commissioning::test_support::architecture::{catalog, compile, product};
use crate::configuration::TopologyConfiguration;

use std::collections::BTreeSet;
use zweidraehte_project::CouplerRoutingPolicy;

use zweidraehte_proto::address::GroupAddress;

use super::*;
use crate::commissioning::catalog::profile::testing::fixture_profile;

fn filter_profile(length: u32) -> ResolvedProfile {
    fixture_profile(
        "MV-091A",
        "Bcu1",
        "MT-0",
        &format!(
            r#"<Resources><Resource Name="GroupFilterTable"><Location AddressSpace="LcFilterMemory" StartAddress="0"/><ResourceType Length="{length}"/><AccessRights Read="Runtime" Write="Configuration"/></Resource></Resources>"#
        ),
    )
}

#[test]
fn selective_filter_uses_lsb_first_group_address_bits() {
    let addresses = BTreeSet::from([
        GroupAddress::from_bytes(&[0x00, 0x01]),
        GroupAddress::from_bytes(&[0x00, 0x08]),
        GroupAddress::from_bytes(&[0x00, 0x0f]),
    ]);

    let profile = filter_profile(2);
    let resource = profile.resource("GroupFilterTable").expect("resource lookup").expect("filter resource");
    let encoded =
        encode_filter_bitmap(&resource, CouplerRoutingPolicy::Filter, &addresses, 0x0f, false).expect("filter encodes");

    assert_eq!(encoded, [0b0000_0010, 0b1000_0001]);
}

#[test]
fn routing_selectors_do_not_fabricate_filter_bits() {
    let profile = filter_profile(2);
    let resource = profile.resource("GroupFilterTable").expect("resource lookup").expect("filter resource");

    assert_eq!(
        encode_filter_bitmap(&resource, CouplerRoutingPolicy::RouteAll, &BTreeSet::new(), 0x0f, false)
            .expect("route-all encodes"),
        [0x00, 0x00]
    );
    assert_eq!(
        encode_filter_bitmap(&resource, CouplerRoutingPolicy::BlockAll, &BTreeSet::new(), 0x0f, false)
            .expect("block-all encodes"),
        [0x00, 0x00]
    );

    assert_eq!(legacy_group_selector(CouplerRoutingPolicy::Filter), 0x33);
    assert_eq!(legacy_group_selector(CouplerRoutingPolicy::RouteAll), 0x11);
    assert_eq!(legacy_group_selector(CouplerRoutingPolicy::BlockAll), 0x22);
    assert_eq!(modern_group_selector(CouplerRoutingPolicy::Filter), 0x0f);
    assert_eq!(modern_group_selector(CouplerRoutingPolicy::RouteAll), 0x05);
    assert_eq!(modern_group_selector(CouplerRoutingPolicy::BlockAll), 0x0a);
}

#[test]
fn rf_profiles_require_an_authored_domain_before_plan_compilation() {
    let catalog = catalog(23);
    let product = product("MV-27B0", "DefaultProcedure", true, false);
    let profile = resolve_profile(&catalog, 0x27b0, None, &product);
    let error = compile(&catalog, profile, &product, TopologyConfiguration::default())
        .expect_err("an RF plan without its line domain is incomplete");

    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert_eq!(error.message, "profile requires an open-medium domain address, but the project line has none");
}
