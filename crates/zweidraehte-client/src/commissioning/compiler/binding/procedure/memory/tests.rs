use crate::commissioning::catalog::profile::ObjectSelector;
use crate::commissioning::catalog::profile::testing::append_xml;
use crate::commissioning::compiler::binding::procedure::test_support::{
    ProcedureCompileContext, compile_fixture_with_image, compile_fixture_with_profile, compile_procedure,
    memory_target, minimal_profile, root_path,
};
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
use crate::commissioning::image::{ImageLocation, ImageSpace, SparseDeviceImage};
use crate::commissioning::procedure::operands::{MemoryAddress, MemoryService};
use crate::commissioning::procedure::{
    Comparison, ComparisonPadding, OperationData, OperationExtent, OperationTarget, ProcedureOperation, RestartKind,
    ToolState,
};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ApplicationIdentity;
use zweidraehte_ets_files::schema::{
    LdCtrlConnect, LdCtrlDisconnect, LdCtrlWriteMem, LdCtrlWriteRelMem, LoadControl, LoadProcedure,
};

#[test]
fn memory_controls_bind_services_from_their_selected_extent() {
    use zweidraehte_ets_files::schema::{LdCtrlCompareMem, LdCtrlLoadImageMem};
    for (address, size, expected) in [
        (0xffff, 1, MemoryService::Classic),
        (0xfffe, 2, MemoryService::Classic),
        (0xffff, 2, MemoryService::Extended),
        (0x10000, 1, MemoryService::Extended),
    ] {
        let bytes = vec![0x5a; size as usize];
        let inline = Some("5A".repeat(size as usize));
        let procedure = LoadProcedure {
            merge_id: None,
            controls: vec![
                LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                LoadControl::LdCtrlWriteMem(LdCtrlWriteMem {
                    address,
                    size,
                    inline_data: inline.clone(),
                    ..Default::default()
                }),
                LoadControl::LdCtrlCompareMem(LdCtrlCompareMem {
                    address,
                    size,
                    inline_data: inline,
                    ..Default::default()
                }),
                LoadControl::LdCtrlLoadImageMem(LdCtrlLoadImageMem { address, size, ..Default::default() }),
                LoadControl::LdCtrlWriteMem(LdCtrlWriteMem { address, size, ..Default::default() }),
                LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
            ],
        };
        let mut image = SparseDeviceImage::new();
        image.apply_owned(ImageLocation::standard_memory(address), bytes).expect("image range fits");
        let program = compile_fixture_with_image(procedure, Vec::new(), image).expect("selected controls bind");
        let mut transfers = 0;
        for step in &program.steps {
            let target = match &step.operation {
                ProcedureOperation::Write { target, .. }
                | ProcedureOperation::Compare { target, .. }
                | ProcedureOperation::ReadIntoImage { target, .. } => target,
                _ => continue,
            };
            assert_eq!(target, &OperationTarget::Memory { service: expected, address: MemoryAddress::Fixed(address) });
            transfers += 1;
        }
        assert_eq!(transfers, 4, "inline writes, comparisons, reads and image writes share one rule");
    }
}

#[test]
fn absolute_and_relative_comparisons_use_the_preceding_working_image_read() {
    use crate::commissioning::procedure::CachePolicy;
    use zweidraehte_ets_files::schema::{
        LdCtrlCompareMem, LdCtrlCompareRelMem, LdCtrlLoadImageMem, LdCtrlLoadImageRelMem,
    };

    let object = ObjectSelector::Index { index: 3 };
    for relative in [false, true] {
        let (read, compare, space, target) = if relative {
            (
                LoadControl::LdCtrlLoadImageRelMem(LdCtrlLoadImageRelMem {
                    obj_idx: Some(3),
                    offset: 24,
                    size: 4,
                    ..Default::default()
                }),
                LoadControl::LdCtrlCompareRelMem(LdCtrlCompareRelMem {
                    obj_idx: Some(3),
                    offset: 24,
                    size: 4,
                    invert: Some(true),
                    allow_cached_value: Some(true),
                    retry_interval: Some(3),
                    time_out: Some(40),
                    ..Default::default()
                }),
                ImageSpace::RelativeMemory { object: object.clone() },
                memory_target(Some(object.clone()), 24),
            )
        } else {
            (
                LoadControl::LdCtrlLoadImageMem(LdCtrlLoadImageMem { address: 24, size: 4, ..Default::default() }),
                LoadControl::LdCtrlCompareMem(LdCtrlCompareMem {
                    address: 24,
                    size: 4,
                    invert: Some(true),
                    allow_cached_value: Some(true),
                    retry_interval: Some(3),
                    time_out: Some(40),
                    ..Default::default()
                }),
                ImageSpace::StandardMemory,
                memory_target(None, 24),
            )
        };
        let normalized = compile_procedure(ProcedureCompileContext {
            profile: minimal_profile(),
            procedure_id: root_path().procedure,
            composition: ProcedureComposition::Default,
            procedure: LoadProcedure {
                merge_id: None,
                controls: vec![
                    LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                    read,
                    compare,
                    LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
                ],
            },
            product_merge_fragments: Vec::new(),
            parameter_values: BTreeMap::new(),
            applicability: ProcedureApplicability::full(),
            // The read supplies all comparison bytes; the desired image owns none.
            image: SparseDeviceImage::new(),
            property_image_facts: Vec::new(),
            relative_memory_facts: vec![(object.clone(), 7)],
            progress_messages_by_reference: BTreeMap::new(),
            progress_messages_by_id: BTreeMap::new(),
            initial_tool_state: ToolState::default(),
            restart_kind: RestartKind::Basic,
            application_identity: ApplicationIdentity::default(),
            secure_only: false,
            extension_operations: Vec::new(),
        })
        .expect("a device read supplies the comparison's working image");

        assert_eq!(normalized.steps.len(), 4);
        let location = ImageLocation { space, offset: 24 };
        assert_eq!(normalized.steps[1].operation, ProcedureOperation::ReadIntoImage {
            target: target.clone(),
            image_location: location.clone(),
            extent: OperationExtent::bytes(4),
            cache: CachePolicy::Populate,
            capture_as: None,
        });
        assert_eq!(normalized.steps[2].operation, ProcedureOperation::Compare {
            target: target,
            comparison: Comparison::Exact {
                data: OperationData::Buffer { location, length: 4, fallback: None },
                mask: None,
                padding: ComparisonPadding::None,
            },
            extent: OperationExtent::bytes(4),
            cache: CachePolicy::UseAndPopulate,
            invert: true,
            retry_interval_milliseconds: Some(3),
            timeout_milliseconds: Some(40),
        });
    }
}

#[test]
fn relative_pointer_uses_explicit_resource_width_when_interface_metadata_is_absent() {
    let mut profile = minimal_profile();
    append_xml(
        &mut profile,
        "Resources",
        r#"<Resource Name="ApplicationDataPtr"><Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="7" StartAddress="0"/><ResourceType Length="4" Flavour="Ptr_StandardMemory"/><AccessRights Read="Runtime" Write="Configuration"/></Resource>"#,
    );
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlWriteRelMem(LdCtrlWriteRelMem {
                obj_idx: Some(4),
                offset: 12,
                size: 1,
                inline_data: Some("A5".into()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let program = compile_fixture_with_profile(profile, procedure, Vec::new(), SparseDeviceImage::new())
        .expect("the selected pointer resource declares its complete geometry");
    let ProcedureOperation::Write {
        target: OperationTarget::Memory { address: MemoryAddress::Pointer { read, offset, .. }, .. },
        ..
    } = &program.steps[1].operation
    else {
        panic!("deferred pointer")
    };
    assert_eq!(*offset, 12);
    assert_eq!(read.extent, OperationExtent::property(4, 1));
}
