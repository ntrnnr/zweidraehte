//! Exact, synthetic Master Data for target capability tests.

use super::*;
use crate::commissioning::catalog_testing::*;

// These tests isolate consumer behavior from catalog selection. Keep synthetic
// fact overrides behind cfg(test); production callers always resolve a profile.
impl ResolvedProfile {
    pub(crate) fn set_test_disposition(&mut self, disposition: ProfileDisposition) {
        self.disposition = disposition;
    }

    pub(crate) fn set_test_management_style(&mut self, style: Option<ResourceManagementStyle>) {
        self.management_style = style;
    }

    pub(crate) fn set_test_management_model(&mut self, model: ManagementModel) {
        self.management_model = model;
    }
}

pub(crate) fn association_profile(flavour: &str) -> ResolvedProfile {
    association_profile_xml(&format!(
        r#"<Resource Name="GroupAssociationTable" Access="remote">
        <Location AddressSpace="StandardMemory" StartAddress="256" />
        <ResourceType Length="2" Flavour="{flavour}" />
        <AccessRights Read="Runtime" Write="Configuration" />
      </Resource>"#
    ))
}

pub(crate) fn association_profile_xml(resources: &str) -> ResolvedProfile {
    resolve_catalog_profile(&parse_master_data(&format!(r#"<KNX xmlns="http://knx.org/xml/project/23"><MasterData Id="test" Version="1">
      <MaskVersions><MaskVersion Id="MV-07B0" MaskVersion="1968" Name="test" ManagementModel="SystemB">
      <HawkConfigurationData><Resources>
      <Resource Name="ManagementStyle"><Location AddressSpace="Constant" StartAddress="2"/><ResourceType Length="1"/></Resource>
      {resources}</Resources></HawkConfigurationData></MaskVersion></MaskVersions>
      </MasterData></KNX>"#)).expect("synthetic catalogue parses"), None, &ProfileSelection { discovery: ProfileDiscovery { dd0: 0x07b0, management_descriptor_01: None, management_style: None }, variant_hint: VariantHint::Automatic }).expect("synthetic profile resolves")
}

pub(crate) fn fixture_profile(mask: &str, model: &str, medium: &str, body: &str) -> ResolvedProfile {
    let dd0 = u16::from_str_radix(mask.trim_start_matches("MV-"), 16).expect("fixture mask is hexadecimal");
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23"><MasterData Id="fixture" Version="1">
      <PropertyDataTypes><PropertyDataType Id="PDT_UNSIGNED_LONG" Name="PDT_UNSIGNED_LONG" Size="4" /></PropertyDataTypes>
      <MaskVersions><MaskVersion Id="{mask}" MaskVersion="{dd0}" Name="fixture" ManagementModel="{model}" MediumTypeRefId="{medium}">
      <HawkConfigurationData>{body}</HawkConfigurationData></MaskVersion></MaskVersions>
      </MasterData></KNX>"#
    );
    resolve_catalog_profile(&parse_master_data(&xml).expect("fixture catalogue parses"), None, &ProfileSelection {
        discovery: ProfileDiscovery {
            dd0,
            management_descriptor_01: None,
            management_style: Some(if model == "Bcu1" {
                ResourceManagementStyle::Simple
            } else {
                ResourceManagementStyle::LoadStateMachine
            }),
        },
        variant_hint: VariantHint::Automatic,
    })
    .expect("fixture profile resolves")
}

pub(crate) fn edit_profile(profile: &mut ResolvedProfile, edit: impl FnOnce(String) -> String) {
    let xml = edit(profile.master_data.source_xml().to_owned());
    let catalog = parse_master_data(&xml).expect("edited fixture catalogue parses");
    let mut replacement = resolve_catalog_profile(&catalog, None, &ProfileSelection {
        discovery: ProfileDiscovery {
            dd0: profile.mask.dd0,
            management_descriptor_01: profile.mask.management_descriptor_01,
            management_style: profile.management_style,
        },
        variant_hint: VariantHint::Automatic,
    })
    .expect("edited fixture profile resolves");
    replacement.tool_managed_ip = profile.tool_managed_ip;
    replacement.association_entry_size = profile.association_entry_size;
    replacement.observed_property_types = profile.observed_property_types.clone();
    replacement.declared_property_types = profile.declared_property_types.clone();
    *profile = replacement;
}

pub(crate) fn append_xml(profile: &mut ResolvedProfile, parent: &str, value: &str) {
    edit_profile(profile, |xml| xml.replacen(&format!("</{parent}>"), &format!("{value}</{parent}>"), 1));
}

pub(crate) fn selector_xml(object: &ObjectSelector) -> String {
    match object {
        ObjectSelector::Index { index } => format!(r#"InterfaceObjectRef="{index}""#),
        ObjectSelector::Type { object_type, occurrence } => {
            let occurrence = match occurrence {
                Occurrence::Absent => String::new(),
                Occurrence::Zero => r#" Occurrence="0""#.into(),
                Occurrence::Positive { value } => format!(r#" Occurrence="{value}""#),
            };
            format!(r#"InterfaceObjectRef="{object_type}"{occurrence}"#)
        }
    }
}

pub(crate) fn location_xml(object: &ObjectSelector, property_id: u16, offset: u32, relative: bool) -> String {
    let space = match (relative, object) {
        (false, ObjectSelector::Index { .. }) => "SystemProperty",
        (false, ObjectSelector::Type { .. }) => "Property",
        (true, ObjectSelector::Index { .. }) => "RelativeMemory",
        (true, ObjectSelector::Type { .. }) => "RelativeMemoryByObjectType",
    };
    format!(r#"AddressSpace="{space}" {} PropertyID="{property_id}" StartAddress="{offset}""#, selector_xml(object))
}

pub(crate) fn declare_property(
    profile: &mut ResolvedProfile,
    object: &ObjectSelector,
    pid: u16,
    width: u32,
    read_width: u32,
) {
    let token = format!("FIXTURE_{width}_{read_width}");
    let identity = match object {
        ObjectSelector::Index { index } => format!(r#"Index="{index}""#),
        ObjectSelector::Type { object_type, .. } => format!(r#"ObjectType="{object_type}""#),
    };
    edit_profile(profile, |xml| {
        xml.replacen("</PropertyDataTypes>", &format!(r#"<PropertyDataType Id="{token}" Name="{token}" Size="{width}" ReadSize="{read_width}" /></PropertyDataTypes>"#), 1)
        .replacen("</InterfaceObjects>", &format!(r#"<InterfaceObject {identity}><Property PropertyID="{pid}" PropertyDataType="{token}" /></InterfaceObject></InterfaceObjects>"#), 1)
    });
}
