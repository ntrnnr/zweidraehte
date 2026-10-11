use super::*;
use crate::commissioning::catalog::profile::{ProfileDiscovery, ProfileDisposition, ProfileRequest, VariantHint};
use crate::commissioning::error::CompileErrorKind;
use crate::commissioning::procedure::operands::{MemoryAddress, MemoryService, OperationTarget, StandardMemoryService};
use crate::commissioning::test_support::architecture::resolve_profile;
use crate::commissioning::test_support::architecture::{
    SYSTEM_300_EXECUTABLE_DESCRIPTOR, SYSTEM_300_PLUGIN_DESCRIPTOR, catalog, product as architecture_product,
};
use std::collections::BTreeSet;

#[test]
fn pl110_system_b_does_not_exclude_supported_management_services() {
    for (id, model, expected) in [
        ("MV-17B0", "SystemB", ProfileDisposition::ProductProcedureRequired),
        ("MV-17B0", "Bcu1", ProfileDisposition::ExcludedPowerLine),
        ("MV-1900", "SystemB", ProfileDisposition::ExcludedPowerLine),
    ] {
        let profile =
            crate::commissioning::catalog::profile::testing::fixture_profile(id, model, "MT-1", "<Resources/>");

        assert_eq!(profile.disposition(), &expected);
    }
}

#[test]
fn ambiguous_dd0_requires_pid_72() {
    let catalog = ProgrammingCatalog::from_xml(AMBIGUOUS_0300).expect("catalog parses");
    let error = catalog
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery { dd0: 0x0300, management_descriptor_01: None, management_style: None },
            product: None,
            variant_hint: VariantHint::Automatic,
        })
        .expect_err("DD0 alone must not select the base entry");

    assert_eq!(error.kind, CompileErrorKind::MissingEvidence);
    assert!(error.message.contains("DD0 0300") && error.message.contains("PID 72"));
}

#[test]
fn pid_72_selects_the_exact_0300_profile() {
    let catalog = ProgrammingCatalog::from_xml(AMBIGUOUS_0300).expect("catalog parses");

    for (descriptor, expected_id) in [
        ([1, 0, 0, 0, 0, 0, 0, 0, 0, 0], "MV-0300-01000000000000000000"),
        ([1, 0, 0, 1, 0, 0, 0, 0, 0, 0], "MV-0300-01000001000000000000"),
    ] {
        let profile = catalog
            .resolve(ProfileRequest {
                discovery: ProfileDiscovery {
                    dd0: 0x0300,
                    management_descriptor_01: Some(descriptor),
                    management_style: None,
                },
                product: None,
                variant_hint: VariantHint::Automatic,
            })
            .expect("descriptor identifies one exact profile");

        assert_eq!(profile.mask.full_id, expected_id);
        assert_eq!(profile.mask.management_descriptor_01, Some(descriptor));
    }

    let error = catalog
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery {
                dd0: 0x0300,
                management_descriptor_01: Some([0xff; 10]),
                management_style: None,
            },
            product: None,
            variant_hint: VariantHint::Automatic,
        })
        .expect_err("an unknown descriptor must not fall back to the selector");

    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert!(error.message.contains("DD0 0300 has no profile matching observed PID 72"));
}

#[test]
fn descriptor_qualified_entries_preserve_their_procedure_requirement() {
    let catalog = ProgrammingCatalog::from_xml(AMBIGUOUS_0300).expect("catalog parses");
    let masks = &catalog.master_data.mask_versions().expect("fixture masks").versions;
    assert_eq!(masks.len(), 3);
    assert!(masks[0].hawk_configs.is_empty());
    assert_eq!(
        super::super::classify_variant(&masks[1], &masks[1].hawk_configs[0]),
        ProfileDisposition::ProductProcedureRequired
    );
}

#[test]
fn topology_dependent_profiles_use_the_builtin_compiler() {
    let profile = ProgrammingCatalog::from_xml(TOPOLOGY_DEPENDENT_PROFILE)
        .expect("catalog parses")
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery { dd0: 0x0900, management_descriptor_01: None, management_style: None },
            product: None,
            variant_hint: VariantHint::Automatic,
        })
        .expect("profile resolves");
    assert_eq!(profile.disposition, ProfileDisposition::Executable);
}

#[test]
fn coupler_model_20_requires_its_product_routing_extension() {
    let xml = TOPOLOGY_DEPENDENT_PROFILE
        .replace("MV-0900", "MV-2920")
        .replace("MaskVersion=\"2304\"", "MaskVersion=\"10528\"")
        .replace("ManagementModel=\"Bcu1\"", "ManagementModel=\"SystemB\"")
        .replace("MediumTypeRefId=\"MT-0\"", "MediumTypeRefId=\"MT-0\" OtherMediumTypeRefId=\"MT-2\"");
    let catalog = ProgrammingCatalog::from_xml(&xml).expect("catalog parses");
    let mask = catalog.master_data.get_mask_version("MV-2920").expect("fixture mask");
    assert_eq!(super::super::classify_variant(mask, &mask.hawk_configs[0]), ProfileDisposition::CouplerRoutingRequired);
}

#[test]
fn descriptor_query_is_required_only_for_ambiguous_dd0() {
    let catalog = ProgrammingCatalog::from_xml(AMBIGUOUS_0300).expect("catalog parses");

    assert!(catalog.requires_management_descriptor_01(0x0300).expect("DD0 is known"));
    assert!(
        matches!(catalog.requires_management_descriptor_01(0x1234), Err(error) if error.kind == CompileErrorKind::Unsupported && error.message.contains("DD0 1234"))
    );
}

#[test]
fn bcu2_product_style_selects_target_instead_of_installed_style() {
    let xml = RESOURCE_SELECTION
        .replace("MV-0012", "MV-0020")
        .replace("MaskVersion=\"18\"", "MaskVersion=\"32\"")
        .replace("ManagementModel=\"Bcu1\"", "ManagementModel=\"Bcu2\"");
    let product = product("MV-0020", "ProductProcedure", false);
    let profile = ProgrammingCatalog::from_xml(&xml)
        .expect("catalog parses")
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery {
                dd0: 0x0020,
                management_descriptor_01: None,
                management_style: Some(ResourceManagementStyle::Simple),
            },
            product: Some(&product),
            variant_hint: VariantHint::Automatic,
        })
        .expect("replacement profile resolves");

    assert_eq!(profile.management_style, Some(ResourceManagementStyle::LoadStateMachine));
}

#[test]
fn bcu2_target_style_does_not_hide_unique_execution_resources() {
    let load_control = r#"
      <Resource Name="GroupAddressTableLoadControl" Access="remote" MgmtStyle="lsm">
        <Location AddressSpace="SystemProperty" InterfaceObjectRef="0" PropertyID="54" StartAddress="0" />
        <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
        <AccessRights Read="Runtime" Write="Configuration" />
      </Resource>
    "#;
    let xml = RESOURCE_SELECTION
        .replace("MV-0012", "MV-0020")
        .replace("MaskVersion=\"18\"", "MaskVersion=\"32\"")
        .replace("ManagementModel=\"Bcu1\"", "ManagementModel=\"Bcu2\"")
        .replace("<Resources>", &format!("<Resources>{load_control}"));
    let product = product("MV-0020", "DefaultProcedure", false);
    let profile = ProgrammingCatalog::from_xml(&xml)
        .expect("catalog parses")
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery {
                dd0: 0x0020,
                management_descriptor_01: None,
                management_style: Some(ResourceManagementStyle::LoadStateMachine),
            },
            product: Some(&product),
            variant_hint: VariantHint::Automatic,
        })
        .expect("BCU1-style replacement profile resolves");

    assert_eq!(profile.management_style, Some(ResourceManagementStyle::Simple));
    assert_eq!(
        profile
            .resource("Chosen")
            .expect("selection")
            .expect("simple target resource")
            .read(StandardMemoryService::Classic)
            .expect("read binds")
            .target,
        OperationTarget::Memory { service: MemoryService::Classic, address: MemoryAddress::Fixed(32) }
    );
    assert_eq!(
        profile
            .resource("GroupAddressTableLoadControl")
            .expect("selection")
            .expect("remote procedure load-control resource remains available")
            .source
            .management_style
            .as_ref()
            .expect("qualified resource")
            .contains_name("lsm"),
        true
    );
}

#[test]
fn bcu2_management_style_probe_uses_the_selected_resource() {
    let probe_resource = r#"
      <Resource Name="ManagementStyle" Access="remote">
        <Location AddressSpace="StandardMemory" StartAddress="4660" />
        <ResourceType Length="1" Flavour="ManagementStyle_Bcu2" />
        <AccessRights Read="Runtime" Write="None" />
      </Resource>
    "#;
    let xml = RESOURCE_SELECTION
        .replace("MV-0012", "MV-0020")
        .replace("MaskVersion=\"18\"", "MaskVersion=\"32\"")
        .replace("ManagementModel=\"Bcu1\"", "ManagementModel=\"Bcu2\"")
        .replace("<Resources>", &format!("<Resources>{probe_resource}"));
    let profile = ProgrammingCatalog::from_xml(&xml)
        .expect("catalog parses")
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery {
                dd0: 0x0020,
                management_descriptor_01: None,
                management_style: Some(ResourceManagementStyle::Simple),
            },
            product: None,
            variant_hint: VariantHint::Automatic,
        })
        .expect("profile resolves");
    let probe = profile.resource("ManagementStyle").expect("selection").expect("BCU2 probe resource");

    assert_eq!(probe.read(StandardMemoryService::Classic).expect("read binds").target, OperationTarget::Memory {
        service: MemoryService::Classic,
        address: MemoryAddress::Fixed(4660)
    });
    assert_eq!(
        probe.flavour().expect("known flavour"),
        Some(crate::commissioning::catalog::profile::ResourceFlavour::ManagementStyleBcu2)
    );
}

#[test]
fn reversed_091a_variant_order_is_not_a_selector() {
    for (mask, variants) in [
        ("0912", "<HawkConfigurationData /><HawkConfigurationData LegacyVersion=\"1\" />"),
        ("091A", "<HawkConfigurationData LegacyVersion=\"1\" /><HawkConfigurationData />"),
    ] {
        let xml = coupler_catalog(mask, variants);
        let modern = product(&format!("MV-{mask}"), "DefaultProcedure", true);
        let legacy = product(&format!("MV-{mask}"), "DefaultProcedure", false);
        let catalog = ProgrammingCatalog::from_xml(&xml).expect("catalog parses");
        let dd0 = u16::from_str_radix(mask, 16).expect("hex mask");

        let modern_profile = catalog
            .resolve(ProfileRequest {
                discovery: ProfileDiscovery { dd0, management_descriptor_01: None, management_style: None },
                product: Some(&modern),
                variant_hint: VariantHint::Automatic,
            })
            .expect("modern profile resolves");
        let legacy_profile = catalog
            .resolve(ProfileRequest {
                discovery: ProfileDiscovery { dd0, management_descriptor_01: None, management_style: None },
                product: Some(&legacy),
                variant_hint: VariantHint::Automatic,
            })
            .expect("legacy profile resolves");

        assert_eq!(modern_profile.variant.legacy_version.unwrap_or(0), 0);
        assert_eq!(legacy_profile.variant.legacy_version, Some(1));
    }
}

#[test]
fn procedure_ownership_does_not_select_a_legacy_system_b_profile() {
    for mask_id in ["07B0", "17B0"] {
        for variants in [
            "<HawkConfigurationData /><HawkConfigurationData LegacyVersion=\"1\" />",
            "<HawkConfigurationData LegacyVersion=\"1\" /><HawkConfigurationData />",
        ] {
            let xml =
                coupler_catalog(mask_id, variants).replace("ManagementModel=\"Bcu1\"", "ManagementModel=\"SystemB\"");
            let catalog = ProgrammingCatalog::from_xml(&xml).expect("catalog parses");
            let mask = catalog.master_data.get_mask_version(&format!("MV-{mask_id}")).expect("mask exists");

            for style in ["DefaultProcedure", "ProductProcedure", "MergedProcedure"] {
                let product = product(&format!("MV-{mask_id}"), style, false);
                let (_, automatic) = super::super::select_variant(mask, Some(&product), VariantHint::Automatic)
                    .expect("automatic profile resolves independently of procedure style");
                let (_, explicit) = super::super::select_variant(mask, Some(&product), VariantHint::LegacyVersion(1))
                    .expect("explicit legacy profile remains supported");

                assert_eq!(automatic.legacy_version.unwrap_or(0), 0, "{mask_id}: {style}");
                assert_eq!(explicit.legacy_version, Some(1), "{mask_id}: {style}");
            }

            let error = super::super::select_variant(mask, None, VariantHint::Automatic)
                .expect_err("a bare device still requires evidence to select among variants");
            assert_eq!(error.kind, CompileErrorKind::MissingEvidence);
        }
    }
}

#[test]
fn catalog_generations_preserve_exact_profile_selection() {
    let mut fingerprints = BTreeSet::new();
    for version in 20..=23 {
        let catalog = catalog(version);
        fingerprints.insert(catalog.fingerprint());
        for (mask, dd0, descriptor, relative, expected) in [
            ("MV-0012", 0x0012, None, false, ProfileDisposition::Executable),
            ("MV-0020", 0x0020, None, false, ProfileDisposition::Executable),
            (
                "MV-0300-01000000000000000000",
                0x0300,
                Some(SYSTEM_300_PLUGIN_DESCRIPTOR),
                false,
                ProfileDisposition::UnsupportedPlugin { plugin: "vendor.system300".to_owned() },
            ),
            (
                "MV-0300-01000001000000000000",
                0x0300,
                Some(SYSTEM_300_EXECUTABLE_DESCRIPTOR),
                false,
                ProfileDisposition::Executable,
            ),
            ("MV-0705", 0x0705, None, false, ProfileDisposition::ProductProcedureRequired),
            ("MV-07B0", 0x07b0, None, true, ProfileDisposition::Executable),
            ("MV-2705", 0x2705, None, false, ProfileDisposition::ProductProcedureRequired),
            ("MV-27B0", 0x27b0, None, true, ProfileDisposition::Executable),
            ("MV-2920", 0x2920, None, true, ProfileDisposition::CouplerRoutingRequired),
            ("MV-5705", 0x5705, None, false, ProfileDisposition::ProductProcedureRequired),
            ("MV-57B0", 0x57b0, None, true, ProfileDisposition::Executable),
        ] {
            let product = architecture_product(mask, "DefaultProcedure", relative, false);
            let profile = resolve_profile(&catalog, dd0, descriptor, &product);
            assert_eq!(profile.mask().full_id, mask, "project-{version}");
            assert_eq!(profile.disposition(), &expected, "project-{version}: {mask}");
        }
        assert!(matches!(
            catalog.resolve(ProfileRequest {
                discovery: ProfileDiscovery { dd0: 0x0300, management_descriptor_01: None, management_style: None },
                product: None,
                variant_hint: VariantHint::Automatic,
            }),
            Err(error) if error.kind == CompileErrorKind::MissingEvidence && error.message.contains("DD0 0300") && error.message.contains("PID 72")
        ));
    }
    // Namespace provenance keeps otherwise identical catalog generations distinct.
    assert_eq!(fingerprints.len(), 4);
}
