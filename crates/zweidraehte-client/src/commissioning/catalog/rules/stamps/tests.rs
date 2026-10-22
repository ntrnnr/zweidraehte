//! Exact family stamp coverage and output geometry.

use super::*;
use crate::commissioning::catalog::profile::ProfileDisposition;
use crate::commissioning::catalog::profile::testing::{append_xml, edit_profile, fixture_profile};
use crate::commissioning::catalog_testing::*;
use crate::commissioning::error::ProfileErrorKind;
use std::num::NonZeroU16;

fn output(profile: &ResolvedProfile) -> Result<DownloadStampOutput, ProfileError> {
    let candidates = resolved_download_stamp_resources(profile, StandardMemoryService::Classic)?;
    super::resolved_download_stamp_output(profile, candidates)
}

fn stamp_xml(index: u16) -> String {
    let name = if index == 5 { "PeiprogStamp".to_owned() } else { format!("Stamp{index}") };
    format!(
        r#"<Resource Name="{name}" Access="remote" Optional="{}">
        <Location AddressSpace="SystemProperty" InterfaceObjectRef="{index}" PropertyID="27" StartAddress="0" />
        <ResourceType Length="8" Flavour="Stamp_SystemB" />
        <AccessRights Read="Runtime" Write="None" /></Resource>"#,
        index == 5
    )
}

fn stamp_profile() -> ResolvedProfile {
    let resources: String = (1..=6).map(stamp_xml).collect();
    fixture_profile(
        "MV-07B0",
        "SystemB",
        "MT-0",
        &format!(
            r#"
        <Features><Feature Name="DownloadStamp" Value="1" /><Feature Name="FirstAppObjectIdx" Value="6" /></Features>
        <Resources><Resource Name="ManagementStyle"><Location AddressSpace="Constant" StartAddress="2" />
          <ResourceType Length="1" /></Resource>{resources}</Resources>"#
        ),
    )
}

#[test]
fn system_b_stamp_output_selects_final_properties_without_changing_read_resources() {
    let profile = stamp_profile();
    let original = profile.clone();
    let resources =
        resolved_download_stamp_resources(&profile, StandardMemoryService::Classic).expect("stamp candidates resolve");
    assert_eq!(resources.iter().map(|resource| resource.id.0.as_str()).collect::<Vec<_>>(), ["Stamp3", "Stamp4"]);
    let output = output(&profile).expect("stamp output resolves");
    assert_eq!(output, DownloadStampOutput::ImageProperties(resources));
    assert_eq!(profile, original);
}

#[test]
fn system_b_stamp_output_requires_known_flavour_and_selection_bound() {
    for bound in [None, Some(3)] {
        let mut profile = stamp_profile();
        edit_profile(&mut profile, |xml| {
            xml.replace(
                r#"<Feature Name="FirstAppObjectIdx" Value="6" />"#,
                &bound
                    .map_or(String::new(), |value| format!(r#"<Feature Name="FirstAppObjectIdx" Value="{value}" />"#)),
            )
        });
        // Flavour 1 walks indices 3..FirstAppObjectIdx. Without the feature the
        // bound reads as 1, so that walk, like an end of 3, selects no stamp.
        assert_eq!(output(&profile).expect("an empty walk resolves"), DownloadStampOutput::None);
        assert!(
            resolved_download_stamp_resources(&profile, StandardMemoryService::Classic)
                .expect("an empty walk resolves")
                .is_empty()
        );
    }
    for flavour in [2, u32::MAX] {
        let mut profile = stamp_profile();
        edit_profile(&mut profile, |xml| {
            xml.replace(r#"Name="DownloadStamp" Value="1""#, &format!(r#"Name="DownloadStamp" Value="{flavour}""#))
        });
        assert!(resolved_download_stamp_resources(&profile, StandardMemoryService::Classic).is_err());
        assert!(output(&profile).is_err());
    }
    for feature in [r#"<Feature Name="DownloadStamp" Value="0" />"#, ""] {
        let mut profile = stamp_profile();
        edit_profile(&mut profile, |xml| {
            xml.replace(r#"<Feature Name="DownloadStamp" Value="1" />"#, feature)
                .replace(r#"<Feature Name="FirstAppObjectIdx" Value="6" />"#, "")
        });
        assert_eq!(output(&profile).expect("disabled stamp output"), DownloadStampOutput::None);
        assert!(
            resolved_download_stamp_resources(&profile, StandardMemoryService::Classic)
                .expect("disabled candidates")
                .is_empty()
        );
    }
}

#[test]
fn system_b_stamp_binding_rejects_aliases_duplicate_ids_and_inexact_geometry() {
    let original = stamp_profile();
    for resource in [
        stamp_xml(3).replace("PropertyID=\"27\"", "PropertyID=\"28\""),
        stamp_xml(3).replace("StartAddress=\"0\"", "StartAddress=\"1\""),
        stamp_xml(3).replace("AddressSpace=\"SystemProperty\"", "AddressSpace=\"Property\" Occurrence=\"0\""),
        stamp_xml(3).replace("Length=\"8\"", "Length=\"16\""),
    ] {
        let mut profile = original.clone();
        edit_profile(&mut profile, |xml| xml.replace(&stamp_xml(3), &resource));
        assert!(output(&profile).is_err());
    }
    let mut profile = original.clone();
    append_xml(&mut profile, "Resources", &stamp_xml(3));
    assert!(output(&profile).expect_err("duplicate declaration rejects").message.contains("ambiguous"));

    let mut profile = original;
    edit_profile(&mut profile, |xml| {
        xml.replace(&stamp_xml(4), &stamp_xml(4).replace("InterfaceObjectRef=\"4\"", "InterfaceObjectRef=\"3\""))
    });
    assert!(output(&profile).expect_err("aliased property rejects").message.contains("aliases"));
}

#[test]
fn system7_selects_final_image_properties_like_system_b() {
    // System 7 declares DownloadStamp flavour 1 with FirstAppObjectIdx 5, so
    // only objects 3 and 4 lie in the output range. Objects 1 and 2 are never
    // read just to record a stamp.
    let mut profile = stamp_profile();
    edit_profile(&mut profile, |xml| {
        xml.replace("ManagementModel=\"SystemB\"", "ManagementModel=\"BimM112\"").replace(
            r#"<Feature Name="FirstAppObjectIdx" Value="6" />"#,
            r#"<Feature Name="FirstAppObjectIdx" Value="5" />"#,
        )
    });
    let resources =
        resolved_download_stamp_resources(&profile, StandardMemoryService::Classic).expect("stamp candidates resolve");
    assert_eq!(resources.iter().map(|resource| resource.id.0.as_str()).collect::<Vec<_>>(), ["Stamp3", "Stamp4"]);
    assert_eq!(output(&profile).expect("stamp output resolves"), DownloadStampOutput::ImageProperties(resources));

    edit_profile(&mut profile, |xml| {
        xml.replace(r#"Name="DownloadStamp" Value="1""#, r#"Name="DownloadStamp" Value="2""#)
    });
    let error = output(&profile).expect_err("unknown flavours stay unsupported on every family");
    assert_eq!(error.kind, ProfileErrorKind::Unsupported);
}

#[test]
fn coupler_model_20_derives_its_exact_procedure_owned_download_stamp() {
    for version in [20, 23] {
        let xml = coupler_2920_download_stamp_catalog(version);
        let catalog = parse_master_data(&xml).expect("catalog parses");
        let profile = resolve_catalog_profile(&catalog, None, &ProfileSelection {
            discovery: ProfileDiscovery { dd0: 0x2920, management_descriptor_01: None, management_style: None },
            variant_hint: VariantHint::Automatic,
        })
        .expect("exact Coupler Model 2.0 profile resolves");
        assert_eq!(profile.disposition, ProfileDisposition::CouplerRoutingRequired);
        let stamp = super::procedure_download_stamp(&profile).expect("procedure-owned descriptor binds");
        // Without FirstAppObjectIdx the indexed flavour-1 walk is empty, so the
        // type-addressed router stamp is never selected as download output.
        assert!(
            resolved_download_stamp_resources(&profile, StandardMemoryService::Classic)
                .expect("an empty walk resolves")
                .is_empty()
        );

        assert_eq!(stamp.id.0, "ProcedureDownloadStamp");
        assert_eq!(stamp.read.extent.byte_length, 8);
        assert!(!stamp.optional);
        assert_eq!(stamp.image_location, ImageLocation {
            space: ImageSpace::Property {
                object: ObjectSelector::Type {
                    object_type: 6,
                    occurrence: Occurrence::Positive { value: NonZeroU16::new(1).expect("one is nonzero") },
                },
                property_id: 27,
            },
            offset: 0
        });
    }
}

#[test]
fn procedure_owned_download_stamp_rejects_conflicting_selectors() {
    let xml = coupler_2920_download_stamp_catalog(23).replace(
        r#"<LdCtrlLoadImageProp ObjType="6" Occurrence="1" PropId="27" />"#,
        r#"<LdCtrlLoadImageProp ObjType="6" Occurrence="1" PropId="27" />
          <LdCtrlLoadImageProp ObjType="6" Occurrence="0" PropId="27" />"#,
    );
    let profile = resolve_catalog_profile(&parse_master_data(&xml).expect("catalog parses"), None, &ProfileSelection {
        discovery: ProfileDiscovery { dd0: 0x2920, management_descriptor_01: None, management_style: None },
        variant_hint: VariantHint::Automatic,
    })
    .expect("profile selection preserves source controls");
    let error =
        super::procedure_download_stamp(&profile).expect_err("different procedure stamp selectors are ambiguous");

    assert_eq!(error.kind, ProfileErrorKind::Invalid);
    assert!(
        error.message.contains("multiple procedure-owned download-stamp targets")
            && error.message.contains("Zero")
            && error.message.contains("Positive { value: 1 }")
    );
}

#[test]
fn procedure_owned_download_stamp_ignores_known_non_full_applies_to_sections() {
    let xml = coupler_2920_download_stamp_catalog(23).replace(
        r#"<LdCtrlLoadImageProp ObjType="6" Occurrence="1" PropId="27" />"#,
        r#"<LdCtrlLoadImageProp AppliesTo="cfg,config,ap1,ap2" ObjType="6" Occurrence="0" PropId="27" />
          <LdCtrlLoadImageProp ObjType="6" Occurrence="1" PropId="27" />"#,
    );
    let profile = resolve_catalog_profile(&parse_master_data(&xml).expect("catalog parses"), None, &ProfileSelection {
        discovery: ProfileDiscovery { dd0: 0x2920, management_descriptor_01: None, management_style: None },
        variant_hint: VariantHint::Automatic,
    })
    .expect("non-full AppliesTo sections do not create a full-download stamp target");
    let stamp = super::procedure_download_stamp(&profile).expect("full-download descriptor binds");

    assert_eq!(stamp.id.0, "ProcedureDownloadStamp");
}

fn coupler_2920_download_stamp_catalog(version: u8) -> String {
    format!(
        r#"<KNX xmlns="http://knx.org/xml/project/{version}">
          <MasterData Id="MD" Version="1">
            <PropertyDataTypes>
              <PropertyDataType Id="PDT-24" Number="24" Name="PDT_GENERIC_08" Size="8" />
            </PropertyDataTypes>
            <MaskVersions>
              <MaskVersion Id="MV-2920" MaskVersion="10528" Name="Coupler 2920" ManagementModel="SystemB"
                MediumTypeRefId="MT-0" OtherMediumTypeRefId="MT-2">
                <HawkConfigurationData>
                  <Features><Feature Name="DownloadStamp" Value="1" /></Features>
                  <Resources>
                    <Resource Name="ManagementStyle" Access="remote">
                      <Location AddressSpace="Constant" StartAddress="2" />
                      <ResourceType Length="1" />
                      <AccessRights Read="Runtime" Write="None" />
                    </Resource>
                  </Resources>
                  <Procedures>
                    <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
                      <LdCtrlConnect />
                      <LdCtrlLoadImageProp ObjType="6" Occurrence="1" PropId="27" />
                      <LdCtrlDisconnect />
                    </Procedure>
                  </Procedures>
                  <InterfaceObjects>
                    <InterfaceObject ObjectType="6">
                      <Property PropertyID="27" PropertyDataType="PDT_GENERIC_08" />
                    </InterfaceObject>
                  </InterfaceObjects>
                </HawkConfigurationData>
              </MaskVersion>
            </MaskVersions>
          </MasterData>
        </KNX>"#
    )
}

use crate::commissioning::catalog::profile::ReadAccess;
use crate::commissioning::catalog::rules::resolved_download_stamp_resources as download_stamp_resources;
use crate::commissioning::compiler::binding::tests::preparation_support::{
    authorization_profile, indexed_stamp_resource, set_feature, set_resources, stamp_resource,
};
use crate::commissioning::procedure::operands::StandardMemoryService;

#[test]
fn profiles_without_download_stamps_select_no_resources() {
    let profile = authorization_profile("Bcu1", None);

    assert!(
        download_stamp_resources(&profile, StandardMemoryService::Classic)
            .expect("stamp selection succeeds")
            .is_empty()
    );
}

#[test]
fn download_stamp_selection_keeps_eligible_runtime_stamps_in_profile_order() {
    let mut profile = authorization_profile("SystemB", None);
    set_feature(&mut profile, "DownloadStamp", 1);
    set_resources(&mut profile, vec![
        indexed_stamp_resource("group", 3, ReadAccess::Runtime, false),
        stamp_resource("configuration-only", ReadAccess::Configuration, false),
        indexed_stamp_resource("application", 4, ReadAccess::Runtime, true),
        indexed_stamp_resource("address", 1, ReadAccess::Runtime, false),
    ]);

    let selected = download_stamp_resources(&profile, StandardMemoryService::Classic).expect("stamp resources resolve");
    let ids: Vec<_> = selected.into_iter().map(|resource| resource.id.0).collect();

    assert_eq!(ids, ["group", "application"]);
}

#[test]
fn secondary_stamp_metadata_is_not_an_output_candidate() {
    let mut profile = authorization_profile("SystemB", None);
    set_feature(&mut profile, "DownloadStamp", 1);
    let application = indexed_stamp_resource("application", 4, ReadAccess::Runtime, false);
    let mut peiprog = indexed_stamp_resource("peiprog", 5, ReadAccess::Runtime, false);
    peiprog = peiprog.replace("Name=\"peiprog\"", "Name=\"PeiprogStamp\"");
    set_resources(&mut profile, vec![application, peiprog]);

    let ap1_only =
        download_stamp_resources(&profile, StandardMemoryService::Classic).expect("AP1-only stamp resources resolve");
    assert_eq!(ap1_only.iter().map(|resource| resource.id.0.as_str()).collect::<Vec<_>>(), ["application"]);
}

#[test]
fn enabled_download_stamps_fail_closed_when_no_runtime_stamp_resolves() {
    let mut profile = authorization_profile("SystemB", None);
    set_feature(&mut profile, "DownloadStamp", 1);
    set_resources(&mut profile, vec![stamp_resource("configuration-only", ReadAccess::Configuration, false)]);

    let error = download_stamp_resources(&profile, StandardMemoryService::Classic)
        .expect_err("missing runtime stamp must fail");

    assert!(error.to_string().contains("no runtime-readable Stamp_SystemB resource"), "{error}");
}

#[test]
fn ap1_only_product_may_filter_the_profiles_only_peiprog_candidate() {
    let mut profile = authorization_profile("SystemB", None);
    set_feature(&mut profile, "DownloadStamp", 1);
    let mut peiprog = indexed_stamp_resource("peiprog", 5, ReadAccess::Runtime, false);
    peiprog = peiprog.replace("Name=\"peiprog\"", "Name=\"PeiprogStamp\"");
    set_resources(&mut profile, vec![peiprog]);

    assert!(
        download_stamp_resources(&profile, StandardMemoryService::Classic)
            .expect("the raw profile candidate is valid")
            .is_empty()
    );
}
