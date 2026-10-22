use super::routing::{encode_filter_bitmap, legacy_group_selector, modern_group_selector};
use crate::commissioning::error::CompileErrorKind;
use crate::commissioning::input::DownloadMode;
use crate::commissioning::procedure::ProcedureStep;
use crate::commissioning::test_support::architecture::resolve_profile;
use crate::commissioning::test_support::architecture::{catalog, compile, compile_with_mode, product, rf_topology};
use crate::configuration::{MaterializedDevice, TopologyConfiguration};
use zweidraehte_proto::address::IndividualAddress as DeviceAddress;

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

fn rf_multi_type_steps(steps: &[ProcedureStep]) -> Vec<&ProcedureStep> {
    let target = property_target(&RF_MEDIUM_OBJECT, RF_MULTI_TYPE, 1).expect("builtin property selector");
    steps
        .iter()
        .filter(
            |step| matches!(&step.operation, ProcedureOperation::Write { target: written, .. } if written == &target),
        )
        .collect()
}

#[test]
fn full_rf_downloads_state_the_multi_type_and_leave_the_domain_out_of_the_image() {
    let product = product("MV-27B0", "DefaultProcedure", true, false);
    let profile = fixture_profile(
        "MV-27B0",
        "SystemB",
        "MT-2",
        r#"<Resources>
             <Resource Name="DomainAddress"><Location AddressSpace="SystemProperty" InterfaceObjectRef="0" PropertyID="82" StartAddress="0"/><ResourceType Length="6"/><AccessRights Read="Configuration" Write="Configuration"/></Resource>
             <Resource Name="RfDeviceMode"><Location AddressSpace="Property" InterfaceObjectRef="19" PropertyID="51" StartAddress="0"/><ResourceType Length="1"/><AccessRights Read="Runtime" Write="Configuration"/></Resource>
           </Resources>"#,
    );

    for (mode, value) in [(RfDeviceMode::Ready, 0), (RfDeviceMode::Multi, 1)] {
        let mut topology = rf_topology();
        topology.rf_device_mode = Some(mode);
        let configuration = MaterializedDevice::fixture(DeviceAddress::new(1, 1, 10), Some(15)).with_topology(topology);
        let (image, steps) =
            super::super::compile_fixture(&profile, &product, &configuration, None, None, |compiler| {
                compiler.contribute_topology()
            });

        // A Ready device may lack PID 51 and its refusal is ignored; an RF
        // Multi device must accept its type.
        let [multi_type] = rf_multi_type_steps(&steps)[..] else {
            panic!("a full RF download writes PID 51 exactly once");
        };
        assert!(
            matches!(&multi_type.operation, ProcedureOperation::Write { data: OperationData::Inline(data), .. } if data == &[value])
        );
        let ignored = [ErrorHandler { cause: LoadControlCause::ResourceNotFound, action: ErrorAction::Ignore }];
        assert_eq!(multi_type.on_error, if mode == RfDeviceMode::Multi { &[][..] } else { &ignored[..] });

        // The domain address is network configuration, not an image resource.
        assert!(image.image.segments().is_empty(), "{mode:?} must not own the DomainAddress resource");
    }
}

#[test]
fn partial_rf_downloads_do_not_state_the_multi_type() {
    let catalog = catalog(23);
    let product = product("MV-27B0", "DefaultProcedure", true, false);

    for sections in [ProgramSections::CONFIGURATION, ProgramSections::PARAMETERS.union(ProgramSections::CONFIGURATION)]
    {
        let profile = resolve_profile(&catalog, 0x27b0, None, &product);
        let plan = compile_with_mode(&catalog, profile, &product, rf_topology(), DownloadMode::Partial(sections))
            .expect("partial RF download compiles");
        let steps = plan.procedure().map_or(&[][..], |procedure| &procedure.steps[..]);
        assert!(rf_multi_type_steps(steps).is_empty(), "{sections:?} must not write PID 51");
    }
}
