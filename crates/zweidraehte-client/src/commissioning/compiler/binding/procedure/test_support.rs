//! Shared synthetic target and program fixtures.

use crate::commissioning::catalog::profile::testing::{append_xml, declare_property, fixture_profile, location_xml};
use crate::commissioning::catalog::profile::{ObjectSelector, ProcedureId, ResolvedProfile};
use crate::commissioning::compiler::binding::procedure::{ProcedureInput, lower_procedure_with_tables};
use crate::commissioning::compiler::features::ModuleProcedureFragment;
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageLocation, ImageSpace, SparseDeviceImage};
use crate::commissioning::procedure::operands::{MemoryAddress, MemoryService, StandardMemoryService};
use crate::commissioning::procedure::{
    ControlPath, NormalizedProcedure, OperationExtent, OperationTarget, ProcedureSourceId, RestartKind, ToolState,
};
use crate::configuration::ProcedureParameter;
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ApplicationIdentity;
use zweidraehte_ets_files::schema::LoadProcedure;

pub(in crate::commissioning) fn compile_fixture(
    procedure: LoadProcedure,
    extension_operations: Vec<ModuleProcedureFragment>,
) -> Result<NormalizedProcedure, CompileError> {
    compile_fixture_with_image(procedure, extension_operations, SparseDeviceImage::new())
}

pub(in crate::commissioning) fn compile_fixture_with_parameters(
    procedure: LoadProcedure,
    parameter_values: BTreeMap<String, ProcedureParameter>,
) -> Result<NormalizedProcedure, CompileError> {
    compile_procedure(ProcedureCompileContext {
        profile: minimal_profile(),
        procedure_id: root_path().procedure,
        composition: ProcedureComposition::Default,
        procedure,
        product_merge_fragments: Vec::new(),
        parameter_values,
        applicability: ProcedureApplicability::full(),
        image: SparseDeviceImage::new(),
        property_image_facts: Vec::new(),
        relative_memory_facts: Vec::new(),
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
        initial_tool_state: ToolState::default(),
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        extension_operations: Vec::new(),
    })
}

pub(in crate::commissioning) fn compile_fixture_with_image(
    procedure: LoadProcedure,
    extension_operations: Vec<ModuleProcedureFragment>,
    image: SparseDeviceImage,
) -> Result<NormalizedProcedure, CompileError> {
    compile_fixture_with_profile(minimal_profile(), procedure, extension_operations, image)
}

pub(in crate::commissioning) fn compile_fixture_with_profile(
    profile: ResolvedProfile,
    procedure: LoadProcedure,
    extension_operations: Vec<ModuleProcedureFragment>,
    image: SparseDeviceImage,
) -> Result<NormalizedProcedure, CompileError> {
    compile_fixture_with_profile_and_composition(
        profile,
        ProcedureComposition::Default,
        procedure,
        extension_operations,
        image,
    )
}

pub(in crate::commissioning) fn compile_fixture_with_profile_and_composition(
    profile: ResolvedProfile,
    composition: ProcedureComposition,
    procedure: LoadProcedure,
    extension_operations: Vec<ModuleProcedureFragment>,
    image: SparseDeviceImage,
) -> Result<NormalizedProcedure, CompileError> {
    compile_procedure(ProcedureCompileContext {
        profile,
        procedure_id: root_path().procedure,
        composition,
        procedure,
        product_merge_fragments: Vec::new(),
        parameter_values: BTreeMap::new(),
        applicability: ProcedureApplicability::full(),
        image,
        property_image_facts: Vec::new(),
        relative_memory_facts: Vec::new(),
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
        initial_tool_state: ToolState::default(),
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        extension_operations,
    })
}

pub(in crate::commissioning) fn root_path() -> ControlPath {
    ControlPath {
        mask_id: "MV-TEST".to_owned(),
        variant_index: 2,
        procedure: ProcedureSourceId::MasterData(ProcedureId {
            procedure_type: "Load".to_owned(),
            subtype: Some("all".to_owned()),
            management_style: None,
            source_index: 4,
        }),
        contribution: None,
        control_indices: Vec::new(),
    }
}

pub(in crate::commissioning) fn minimal_profile() -> ResolvedProfile {
    fixture_profile(
        "MV-0705",
        "BimM112",
        "MT-0",
        r#"<Features><Feature Name="PropertyMappedLsms" Value="1"/><Feature Name="FirstAppObjectIdx" Value="5"/></Features><Resources></Resources><InterfaceObjects></InterfaceObjects>"#,
    )
}

/// Complete, owned input for lowering one exact procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commissioning) struct PropertyImageFact {
    pub object: ObjectSelector,
    pub property_id: u16,
    pub first_element: u16,
    pub element_size: u32,
    pub image_location: ImageLocation,
}

/// Source metadata supplied through XML by these parser fixtures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commissioning) struct ProcedureCompileContext {
    pub profile: ResolvedProfile,
    pub procedure_id: ProcedureSourceId,
    pub composition: ProcedureComposition,
    pub procedure: LoadProcedure,
    pub product_merge_fragments: Vec<LoadProcedure>,
    pub parameter_values: BTreeMap<String, ProcedureParameter>,
    pub applicability: ProcedureApplicability,
    pub image: SparseDeviceImage,
    pub property_image_facts: Vec<PropertyImageFact>,
    pub relative_memory_facts: Vec<(ObjectSelector, u16)>,
    pub progress_messages_by_reference: BTreeMap<String, String>,
    pub progress_messages_by_id: BTreeMap<u32, String>,
    pub initial_tool_state: ToolState,
    pub restart_kind: RestartKind,
    pub application_identity: ApplicationIdentity,
    pub extension_operations: Vec<ModuleProcedureFragment>,
}

// Test fixtures intentionally collect both stage inputs in one value. Production
// callers must obtain the composed artifact from the preceding compiler stage.
pub(in crate::commissioning) fn compile_procedure(
    context: ProcedureCompileContext,
) -> Result<NormalizedProcedure, CompileError> {
    compile_procedure_with_tables(context, &[])
}

/// Compile with the encoded communication-table spans of the desired image.
pub(in crate::commissioning) fn compile_procedure_with_tables(
    mut context: ProcedureCompileContext,
    table_spans: &[crate::commissioning::compiler::image::CompiledTableSpan],
) -> Result<NormalizedProcedure, CompileError> {
    // Geometry fixtures enter through the same declared resource metadata as
    // real products. The compiler has no injected property-layout table.
    for (index, fact) in context.property_image_facts.iter().enumerate() {
        let online =
            location_xml(&fact.object, fact.property_id, u32::from(fact.first_element - 1) * fact.element_size, false);
        let image = match &fact.image_location.space {
            ImageSpace::Property { object, property_id } => {
                location_xml(object, *property_id, fact.image_location.offset, false)
            }
            ImageSpace::StandardMemory => {
                format!(r#"AddressSpace="StandardMemory" StartAddress="{}""#, fact.image_location.offset)
            }
            _ => panic!("fixture property has a property or memory image"),
        };
        append_xml(
            &mut context.profile,
            "Resources",
            &format!(
                r#"<Resource Name="ImageProperty{index}"><Location {online}/><ImgLocation {image}/><ResourceType Length="{}"/><AccessRights Read="Runtime" Write="Configuration"/></Resource>"#,
                fact.element_size
            ),
        );
        if context
            .profile
            .property_element_size(&fact.object, fact.property_id, false)
            .expect("fixture metadata resolves")
            .is_none()
        {
            declare_property(
                &mut context.profile,
                &fact.object,
                fact.property_id,
                fact.element_size,
                fact.element_size,
            );
        }
    }
    for (index, (object, property_id)) in context.relative_memory_facts.iter().enumerate() {
        let location = location_xml(object, *property_id, 0, true);
        append_xml(
            &mut context.profile,
            "Resources",
            &format!(
                r#"<Resource Name="RelativeBase{index}"><Location {location}/><ResourceType Length="4"/><AccessRights Read="Runtime" Write="Configuration"/></Resource>"#
            ),
        );
        if context
            .profile
            .property_element_size(object, *property_id, false)
            .expect("fixture metadata resolves")
            .is_none()
        {
            declare_property(&mut context.profile, object, *property_id, 4, 4);
        }
    }
    let configuration_anchor = (context.profile).configuration_anchor();
    let input = ProcedureInput {
        profile: &context.profile,
        procedure_id: context.procedure_id,
        composition: context.composition,
        controls: &context.procedure.controls,
        product_merge_fragments: context.product_merge_fragments.iter().collect(),
        secondary_merge_fragments: Vec::new(),
        secondary_product_procedure: None,
        secondary_application_id: None,
        module_procedures: Vec::new(),
        feature_property_objects: Vec::new(),
        omitted_controls: Vec::new(),
        parameter_values: &context.parameter_values,
        applicability: context.applicability,
        configuration_anchor,
        download_stamps: crate::commissioning::catalog::rules::resolved_download_stamp_resources(
            &context.profile,
            StandardMemoryService::Classic,
        )?,
        property_parameters: &[],
        peiprog_identity_reference: false,
        application_program_2_present: false,
        progress_messages_by_reference: &context.progress_messages_by_reference,
        progress_messages_by_id: &context.progress_messages_by_id,
        message_sources: Vec::new(),
        initial_tool_state: context.initial_tool_state,
        standard_memory_service: StandardMemoryService::Classic,
        restart_kind: context.restart_kind,
        application_identity: context.application_identity,
        secondary_application_identity: None,
        extended_property_descriptions: false,
    };
    lower_procedure_with_tables(&input, &context.image, context.extension_operations, table_spans)
}

pub(in crate::commissioning) fn memory_target(object: Option<ObjectSelector>, offset: u32) -> OperationTarget {
    let service = if object.is_some() { MemoryService::Standard } else { MemoryService::Classic };
    let address = match object {
        None => MemoryAddress::Fixed(offset),
        Some(object) => MemoryAddress::Pointer {
            read: Box::new(crate::commissioning::procedure::ServiceRead {
                target: crate::commissioning::procedure::operands::property_target(&object, 7, 1)
                    .expect("fixture property"),
                extent: OperationExtent::property(4, 1),
            }),
            space: ImageSpace::RelativeMemory { object },
            offset,
            encoding: crate::commissioning::procedure::operands::PointerEncoding::Absolute,
        },
    };
    OperationTarget::Memory { service, address }
}
