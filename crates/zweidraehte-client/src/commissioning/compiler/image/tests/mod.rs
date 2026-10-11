use crate::commissioning::catalog::ProgrammingCatalog;
use crate::commissioning::compiler::image::application_identity_resource_value;
use crate::commissioning::compiler::image::parameters::encode_parameter;
use crate::commissioning::compiler::image::tables::{
    AssociationTable, NativeObjectFormat, NativeObjectTable, TableCodec, TableInput,
};
use crate::commissioning::compiler::image::*;
use crate::commissioning::error::{CompileError, CompileErrorKind};
use crate::commissioning::image::RequiredImageRange;
use crate::configuration::LoweredDeviceConfiguration;
use crate::configuration::ParameterValue;
use zweidraehte_ets_files::product::ParameterLocation;
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};

use zweidraehte_ets_files::product::fixtures::BCU1_MTXML;
use zweidraehte_ets_files::product::{
    ApplicationIdentity, ApplicationProgram2Binding, ApplicationProgramRelationIdentity,
};
use zweidraehte_ets_files::product::{ComObjectDef, ParameterByteOrder};
use zweidraehte_proto::address::IndividualAddress;

use crate::commissioning::catalog::profile::{ProfileDiscovery, ProfileRequest, ResourceFlavour, VariantHint};
use crate::configuration::GroupLink;

mod identity;
mod ownership;
mod reservations;
mod scoped;
mod tables;

fn plain_fixture() -> (ProgrammingCatalog, ResolvedProfile, ProductData, LoweredDeviceConfiguration) {
    // These tests exercise image behavior. Remove the independently tested
    // ROM fixup so an unrelated Master Data function is not a dependency.
    let (before, tail) = BCU1_MTXML.split_once("<FixupList>").expect("fixture has fixups");
    let (_, after) = tail.split_once("</FixupList>").expect("fixture closes fixups");
    let xml = format!("{before}{after}");
    let product = ProductData::from_mtxml_str(&xml).expect("fixture parses");
    let mut segments = product.segments().to_vec();
    segments[0].data[80] = 2;
    let product = product.with_fixture_segments(segments);
    let catalog = ProgrammingCatalog::from_xml(r#"<KNX xmlns="http://knx.org/xml/project/20"><MasterData Id="MD" Version="1"><MaskVersions /></MasterData></KNX>"#).expect("empty catalog parses");
    let mut project = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
    project.links.push(GroupLink { group_address: GroupAddress::from_three_level(1, 2, 3), com_object: 0 });
    let configuration = project.with_com_objects(product.com_objects().to_vec());
    (catalog, table_profile(), product, configuration)
}

// Image tests provide a selected scope directly so source selection cannot
// mask a byte ownership or allocation error in the canonical image builder.
fn image_input(
    product: &ProductData,
    configuration: &LoweredDeviceConfiguration,
    unloading: bool,
) -> crate::commissioning::ProgrammingInput {
    use crate::commissioning::{CompileOptions, DownloadMode, ProgrammingInput, TargetSelection, UnloadMode};
    use crate::configuration::MaterializedDevice;
    use crate::configuration::ResolvedKeyMaterial;
    let device =
        MaterializedDevice::new(product.clone(), configuration.clone(), Vec::new(), ResolvedKeyMaterial::new(None));
    ProgrammingInput::new(
        device,
        if unloading {
            CommissioningIntent::Unload(UnloadMode::Application)
        } else {
            CommissioningIntent::Download(DownloadMode::Full)
        },
        CompileOptions {
            target: TargetSelection::ExistingAddress(configuration.individual_address),
            automatic_sections: None,
            progress_messages_by_reference: Default::default(),
            progress_messages_by_id: Default::default(),
        },
    )
}

fn image_context<'a>(
    input: &'a crate::commissioning::ProgrammingInput,
    profile: &ResolvedProfile,
    unload: Option<&[RequiredImageRange]>,
) -> crate::commissioning::compiler::ProgramCompiler<'a> {
    crate::commissioning::compiler::ProgramCompiler {
        profile: profile.clone(),
        input,
        standard_memory_service: crate::commissioning::procedure::operands::StandardMemoryService::Classic,
        restart_kind: crate::commissioning::procedure::RestartKind::Basic,
        image: ProgramImage::new(input.device().product()),
        recipes: crate::commissioning::compiler::selection::RecipeSet::Automatic,
        unload_required_ranges: unload.unwrap_or_default().to_vec(),
        feature_sections: if unload.is_some() { ProgramSections::empty() } else { ProgramSections::all() },
    }
}

fn compile_unload(
    _catalog: &ProgrammingCatalog,
    profile: &ResolvedProfile,
    product: &ProductData,
    configuration: &LoweredDeviceConfiguration,
    required: &[RequiredImageRange],
) -> Result<ProgramImage, CompileError> {
    let input = image_input(product, configuration, true);
    let mut context = image_context(&input, profile, Some(required));
    context.build_image()?;
    Ok(context.image)
}

fn compile_full_image(
    _catalog: &ProgrammingCatalog,
    profile: &ResolvedProfile,
    product: &ProductData,
    configuration: &LoweredDeviceConfiguration,
) -> Result<ProgramImage, CompileError> {
    crate::commissioning::compiler::application_identity::validate_application_metadata(profile, product)?;
    let input = image_input(product, configuration, false);
    let mut context = image_context(&input, profile, None);
    context.build_image()?;
    Ok(context.image)
}

fn compile_partial_image(
    profile: &ResolvedProfile,
    product: &ProductData,
    configuration: &LoweredDeviceConfiguration,
    sections: ProgramSections,
) -> Result<ProgramImage, CompileError> {
    use crate::commissioning::compiler::binding::procedure::ParsedProcedure;
    use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureRequest, RecipeSet};
    let input = image_input(product, configuration, false);
    let mut context = image_context(&input, profile, None);
    context.feature_sections = sections;
    context.recipes = RecipeSet::Exact {
        request: ProcedureRequest {
            procedure_type: "Load",
            subtype: "all",
            applicability: ProcedureApplicability::partial(sections),
        },
        procedure: Box::new(ParsedProcedure::feature_fixture(profile)),
    };
    context.build_image()?;
    Ok(context.image)
}

fn table_profile() -> ResolvedProfile {
    table_profile_with_flavours("AddressTable_Bcu1", "AssociationTable_Bcu1")
}

fn table_profile_with_flavours(address: &str, association: &str) -> ResolvedProfile {
    table_profile_for_mask(0x0012, "Bcu1", address, association)
}

fn table_profile_for_mask(mask: u16, model: &str, address: &str, association: &str) -> ResolvedProfile {
    // A one-byte resource length describes the count header, not table extent.
    let resources: String = [
        ("GroupAddressTable", address),
        ("GroupAssociationTable", association),
        ("GroupObjectTable", "GroupObjectTable_Bcu11"),
    ]
    .into_iter()
    .map(|(name, flavour)| {
        format!(
            r#"
        <Resource Name="{name}" Access="remote">
          <ResourceType Length="1" Flavour="{flavour}" />
          <AccessRights Read="Runtime" Write="Configuration" />
        </Resource>"#
        )
    })
    .collect();
    let catalog = ProgrammingCatalog::from_xml(&format!(
        r#"
        <KNX xmlns="http://knx.org/xml/project/20"><MasterData Id="MD" Version="1"><MaskVersions>
          <MaskVersion Id="MV-{mask:04X}" MaskVersion="{mask}" Name="Image fixture" ManagementModel="{model}" MediumTypeRefId="MT-0">
            <HawkConfigurationData><Resources>{resources}</Resources>
              <Procedures><Procedure ProcedureType="Load" ProcedureSubType="all" /></Procedures>
            </HawkConfigurationData>
          </MaskVersion>
        </MaskVersions></MasterData></KNX>"#
    ))
    .expect("image catalogue parses");
    catalog
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery {
                dd0: mask,
                management_descriptor_01: None,
                management_style: Some(if model == "Bcu1" {
                    crate::commissioning::catalog::profile::ResourceManagementStyle::Simple
                } else {
                    crate::commissioning::catalog::profile::ResourceManagementStyle::LoadStateMachine
                }),
            },
            product: None,
            variant_hint: VariantHint::Automatic,
        })
        .expect("image profile resolves")
}

#[test]
fn memory_coverage_merges_adjacent_and_overlapping_declarations_per_space() {
    use crate::commissioning::image::ImageSpace;

    // System 7: an 8 KB window at 0x4000 touches the optional one at 0x6000.
    // BCU 2.5: product segments at 800 and 1312 extend the 880-byte window
    // starting at 256, and overlap it. User memory stays separate.
    let coverage = merged_coverage(
        [
            (ImageSpace::StandardMemory, 0x6000, 22016),
            (ImageSpace::StandardMemory, 0x4000, 8192),
            (ImageSpace::StandardMemory, 256, 880),
            (ImageSpace::StandardMemory, 800, 512),
            (ImageSpace::StandardMemory, 1312, 736),
            (ImageSpace::StandardMemory, 15360, 1024),
            (ImageSpace::UserMemory, 256, 16),
        ]
        .into_iter(),
    );

    // 15360 + 1024 is exactly 0x4000, so that segment joins the windows too.
    assert_eq!(coverage, vec![
        (ImageSpace::StandardMemory, 256, 2048),
        (ImageSpace::StandardMemory, 15360, 0x6000 + 22016),
        (ImageSpace::UserMemory, 256, 272),
    ]);
}
