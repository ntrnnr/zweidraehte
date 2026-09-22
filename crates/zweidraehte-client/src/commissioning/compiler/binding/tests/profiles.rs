use crate::commissioning::catalog::ProgrammingCatalog;
use crate::commissioning::catalog::profile::{ManagementModel, ObjectSelector, Occurrence, ResourceManagementStyle};
use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::image::ImageSpace;
use crate::commissioning::procedure::operands::{MemoryAddress, MemoryService, PropertyAddress};
use crate::commissioning::procedure::{
    OperationData, OperationTarget, ProcedureOperation, ProcedureSourceId, WriteIntent, WritePolicy,
};
use crate::commissioning::test_support::architecture::resolve_profile;
use crate::commissioning::test_support::architecture::{
    SYSTEM_300_EXECUTABLE_DESCRIPTOR, catalog, compile, ip_topology, product, rf_topology,
};
use crate::configuration::{GroupFilterConfiguration, TopologyConfiguration};
use std::collections::{BTreeMap, BTreeSet};
use zweidraehte_project::CouplerRoutingPolicy;
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::pid;

#[derive(Debug, PartialEq, Eq)]
struct ProfilePlanGolden {
    name: &'static str,
    mask: String,
    management_model: ManagementModel,
    management_style: Option<ResourceManagementStyle>,
    medium: Option<String>,
    image_space: &'static str,
    procedure_source: &'static str,
}

#[test]
fn representative_profiles_images_and_plans_have_deterministic_shapes() {
    let catalog = catalog(23);
    let cases = [
        PlanCase::absolute("BCU1", "MV-0012", 0x0012, None, "DefaultProcedure", None),
        PlanCase::absolute("BCU1 on BCU2", "MV-0020", 0x0020, None, "DefaultProcedure", None),
        PlanCase::absolute("native BCU2", "MV-0020", 0x0020, None, "ProductProcedure", None),
        PlanCase::absolute(
            "System 300",
            "MV-0300-01000001000000000000",
            0x0300,
            Some(SYSTEM_300_EXECUTABLE_DESCRIPTOR),
            "DefaultProcedure",
            None,
        ),
        PlanCase::absolute("System 7 TP", "MV-0705", 0x0705, None, "ProductProcedure", None),
        PlanCase::relative("System B TP", "MV-07B0", 0x07b0, "DefaultProcedure", None),
        PlanCase::absolute("System 7 RF", "MV-2705", 0x2705, None, "ProductProcedure", Some(rf_topology())),
        PlanCase::relative("System B RF", "MV-27B0", 0x27b0, "DefaultProcedure", Some(rf_topology())),
        PlanCase::absolute("System 7 IP", "MV-5705", 0x5705, None, "ProductProcedure", Some(ip_topology())),
        PlanCase::relative("System B IP", "MV-57B0", 0x57b0, "DefaultProcedure", Some(ip_topology())),
    ];
    let actual = cases.iter().map(|case| compile_plan_case(&catalog, case)).collect::<Vec<_>>();

    assert_eq!(actual, [
        ProfilePlanGolden {
            name: "BCU1",
            mask: "MV-0012".to_owned(),
            management_model: ManagementModel::Bcu1,
            management_style: Some(ResourceManagementStyle::Simple),
            medium: Some("MT-0".to_owned()),
            image_space: "standard",
            procedure_source: "master-data",
        },
        ProfilePlanGolden {
            name: "BCU1 on BCU2",
            mask: "MV-0020".to_owned(),
            management_model: ManagementModel::Bcu2,
            management_style: Some(ResourceManagementStyle::Simple),
            medium: Some("MT-0".to_owned()),
            image_space: "standard",
            procedure_source: "master-data",
        },
        ProfilePlanGolden {
            name: "native BCU2",
            mask: "MV-0020".to_owned(),
            management_model: ManagementModel::Bcu2,
            management_style: Some(ResourceManagementStyle::LoadStateMachine),
            medium: Some("MT-0".to_owned()),
            image_space: "standard",
            procedure_source: "product",
        },
        ProfilePlanGolden {
            name: "System 300",
            mask: "MV-0300-01000001000000000000".to_owned(),
            management_model: ManagementModel::PropertyBased,
            management_style: Some(ResourceManagementStyle::Simple),
            medium: Some("MT-0".to_owned()),
            image_space: "standard",
            procedure_source: "master-data",
        },
        ProfilePlanGolden {
            name: "System 7 TP",
            mask: "MV-0705".to_owned(),
            management_model: ManagementModel::System7,
            management_style: Some(ResourceManagementStyle::LoadStateMachine),
            medium: Some("MT-0".to_owned()),
            image_space: "standard",
            procedure_source: "product",
        },
        ProfilePlanGolden {
            name: "System B TP",
            mask: "MV-07B0".to_owned(),
            management_model: ManagementModel::SystemB,
            management_style: Some(ResourceManagementStyle::LoadStateMachine),
            medium: Some("MT-0".to_owned()),
            image_space: "relative:3",
            procedure_source: "master-data",
        },
        ProfilePlanGolden {
            name: "System 7 RF",
            mask: "MV-2705".to_owned(),
            management_model: ManagementModel::System7,
            management_style: Some(ResourceManagementStyle::LoadStateMachine),
            medium: Some("MT-2".to_owned()),
            image_space: "standard",
            procedure_source: "product",
        },
        ProfilePlanGolden {
            name: "System B RF",
            mask: "MV-27B0".to_owned(),
            management_model: ManagementModel::SystemB,
            management_style: Some(ResourceManagementStyle::LoadStateMachine),
            medium: Some("MT-2".to_owned()),
            image_space: "relative:3",
            procedure_source: "master-data",
        },
        ProfilePlanGolden {
            name: "System 7 IP",
            mask: "MV-5705".to_owned(),
            management_model: ManagementModel::System7,
            management_style: Some(ResourceManagementStyle::LoadStateMachine),
            medium: Some("MT-5".to_owned()),
            image_space: "standard+ot11",
            procedure_source: "product",
        },
        ProfilePlanGolden {
            name: "System B IP",
            mask: "MV-57B0".to_owned(),
            management_model: ManagementModel::SystemB,
            management_style: Some(ResourceManagementStyle::LoadStateMachine),
            medium: Some("MT-5".to_owned()),
            image_space: "relative:3+ot11",
            procedure_source: "master-data",
        },
    ]);
}

#[test]
fn legacy_and_modern_couplers_compile_different_exact_filter_layouts() {
    let catalog = catalog(23);
    let filter_address = GroupAddress::from_three_level(1, 2, 3);

    for (modern, expected_length, expected_config, expected_masks, use_function_property) in
        [(false, 3584, [0x00, 0x33], [0x10, 0x33], false), (true, 8192, [0x0f, 0x0f], [0x0f, 0x0f], true)]
    {
        let product = product("MV-0912", "DefaultProcedure", false, modern);
        let profile = resolve_profile(&catalog, 0x0912, None, &product);
        let mut topology = TopologyConfiguration::default();
        topology.group_filter = Some(GroupFilterConfiguration {
            policy: CouplerRoutingPolicy::Filter,
            addresses: BTreeSet::from([filter_address]),
        });
        let plan = compile(&catalog, profile, &product, topology).expect("coupler plan compiles");

        let standard = plan
            .image()
            .segments()
            .into_iter()
            .find(|segment| {
                segment.location().space == ImageSpace::StandardMemory && segment.location().offset == 0x108
            })
            .expect("routing selectors are in the standard-memory image");
        assert_eq!(standard.data(), expected_config);
        assert_eq!(standard.mask(), expected_masks);

        let filter = plan
            .image()
            .segments()
            .into_iter()
            .find(|segment| segment.location().space == ImageSpace::LineCouplerFilter)
            .expect("filter bitmap is in line-coupler filter memory");
        assert_eq!(filter.data().len(), expected_length);
        assert_eq!(filter.mask(), vec![u8::MAX; expected_length]);

        let raw = u16::from_be_bytes([filter_address.as_bytes()[0], filter_address.as_bytes()[1]]);
        assert_eq!(filter.data()[usize::from(raw / 8)], 1 << (raw % 8));
        assert_eq!(filter.data().iter().filter(|octet| **octet != 0).count(), 1);

        let procedure = plan.procedure().expect("download has a procedure");
        let clear_sequence = procedure
            .steps
            .iter()
            .filter_map(|step| match &step.operation {
                ProcedureOperation::ClearLineCouplerFilter { address } => Some(address.is_some()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(clear_sequence, if use_function_property { vec![true, false] } else { vec![false] });

        let open_index = procedure
            .steps
            .iter()
            .rposition(|step| matches!(&step.operation, ProcedureOperation::ClearLineCouplerFilter { address: None }))
            .expect("filter-memory access is explicitly opened");
        let write_index = procedure
            .steps
            .iter()
            .position(|step| {
                matches!(
                    &step.operation,
                    ProcedureOperation::Write {
                        target: OperationTarget::Memory { service: MemoryService::Filter, address: MemoryAddress::Fixed(0) },
                        data: OperationData::ImageWindow { maximum: length, .. },
                        ..
                    } if *length == expected_length as u32
                )
            })
            .expect("the compiled filter image is written");
        assert!(open_index < write_index);
    }
}

struct PlanCase {
    name: &'static str,
    mask: &'static str,
    dd0: u16,
    descriptor: Option<[u8; 10]>,
    load_style: &'static str,
    relative: bool,
    topology: Option<TopologyConfiguration>,
}

impl PlanCase {
    fn absolute(
        name: &'static str,
        mask: &'static str,
        dd0: u16,
        descriptor: Option<[u8; 10]>,
        load_style: &'static str,
        topology: Option<TopologyConfiguration>,
    ) -> Self {
        Self { name, mask, dd0, descriptor, load_style, relative: false, topology }
    }

    fn relative(
        name: &'static str,
        mask: &'static str,
        dd0: u16,
        load_style: &'static str,
        topology: Option<TopologyConfiguration>,
    ) -> Self {
        Self { name, mask, dd0, descriptor: None, load_style, relative: true, topology }
    }
}

fn compile_plan_case(catalog: &ProgrammingCatalog, case: &PlanCase) -> ProfilePlanGolden {
    let product = product(case.mask, case.load_style, case.relative, false);
    let profile = resolve_profile(catalog, case.dd0, case.descriptor, &product);
    let plan = compile(catalog, profile, &product, case.topology.clone().unwrap_or_default())
        .unwrap_or_else(|error| panic!("{} plan compiles: {error:#?}", case.name));
    let has_ip_overlay = plan.topology().ip.is_some();
    if has_ip_overlay {
        assert_tool_ip_image_and_procedure(&plan, case.relative);
    } else {
        assert_basic_image_and_procedure(&plan, case.relative);
    }

    let procedure_source = match &plan.procedure().expect("download has a procedure").id {
        ProcedureSourceId::MasterData(_) => "master-data",
        ProcedureSourceId::Product { .. } => "product",
        source => panic!("unexpected generated procedure source {source:?}"),
    };
    let image_space = match (case.relative, has_ip_overlay) {
        (false, false) => "standard",
        (true, false) => "relative:3",
        (false, true) => "standard+ot11",
        (true, true) => "relative:3+ot11",
    };

    ProfilePlanGolden {
        name: case.name,
        mask: plan.profile().mask().full_id.clone(),
        management_model: plan.profile().management_model().clone(),
        management_style: plan.profile().management_style(),
        medium: plan.profile().mask_source().medium_type_ref_id.clone(),
        image_space,
        procedure_source,
    }
}

fn assert_basic_image_and_procedure(plan: &CompiledProgram, relative: bool) {
    let segments = plan.image().segments();
    let [segment] = segments.as_slice() else {
        panic!("representative plan must have exactly one application segment");
    };
    assert_eq!(segment.location().offset, if relative { 0 } else { 0x100 });
    assert_eq!(segment.data(), [1, 2, 3, 4]);
    assert_eq!(segment.mask(), [u8::MAX; 4]);
    assert_eq!(image_space_name(&segment.location().space), if relative { "relative:3" } else { "standard" });

    let procedure = plan.procedure().expect("download has a procedure");
    assert_eq!(procedure.steps.len(), 3);
    assert!(matches!(&procedure.steps[0].operation, ProcedureOperation::Connect));
    assert!(matches!(&procedure.steps[2].operation, ProcedureOperation::Disconnect));
    let ProcedureOperation::Write { data: OperationData::ImageWindow { location, maximum: length }, extent, .. } =
        &procedure.steps[1].operation
    else {
        panic!("middle operation must write the compiled image");
    };
    assert_eq!(*length, 4);
    assert_eq!(extent.byte_length, 4);
    assert_eq!(location, segment.location());
}

fn assert_tool_ip_image_and_procedure(plan: &CompiledProgram, relative: bool) {
    let segments = plan.image().segments();
    let expected_application_space = if relative { "relative:3" } else { "standard" };
    let application = segments
        .iter()
        .find(|segment| image_space_name(&segment.location().space) == expected_application_space)
        .expect("IP plan retains its application image");
    assert_eq!(application.location().offset, if relative { 0 } else { 0x100 });
    assert_eq!(application.data(), [1, 2, 3, 4]);
    assert_eq!(application.mask(), [u8::MAX; 4]);

    let ip_object = ObjectSelector::Type { object_type: 11, occurrence: Occurrence::Zero };
    let properties = segments
        .iter()
        .filter_map(|segment| match &segment.location().space {
            ImageSpace::Property { object, property_id } if object == &ip_object => {
                Some((*property_id, segment.data().to_vec()))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let mut friendly_name = b"Architecture IP".to_vec();
    friendly_name.resize(30, 0);
    assert_eq!(
        properties,
        BTreeMap::from([
            (pid::ip::PROJECT_INSTALLATION_ID, vec![0x12, 0x34]),
            (pid::ip::ADDITIONAL_INDIVIDUAL_ADDRESSES, vec![0x11, 0x0b, 0xff, 0xff]),
            (pid::ip::IP_ASSIGNMENT_METHOD, vec![1]),
            (pid::ip::IP_ADDRESS, vec![192, 0, 2, 10]),
            (pid::ip::SUBNET_MASK, vec![255, 255, 255, 0]),
            (pid::ip::DEFAULT_GATEWAY, vec![192, 0, 2, 1]),
            (pid::ip::ROUTING_MULTICAST_ADDRESS, vec![224, 0, 23, 12]),
            (pid::ip::TTL, vec![16]),
            (pid::ip::FRIENDLY_NAME, friendly_name),
        ])
    );
    assert!(!properties.contains_key(&pid::ip::MAC_ADDRESS));

    let procedure = plan.procedure().expect("IP download has a procedure");
    assert!(matches!(&procedure.steps[0].operation, ProcedureOperation::Connect));
    assert!(matches!(
        &procedure.steps.last().expect("procedure is nonempty").operation,
        ProcedureOperation::Disconnect
    ));
    assert!(procedure.steps.iter().any(|step| {
        matches!(
            &step.operation,
            ProcedureOperation::Write { data: OperationData::ImageWindow { location, maximum: 4 }, .. }
                if location == application.location()
        )
    }));

    let ip_writes = procedure
        .steps
        .iter()
        .filter_map(|step| match &step.operation {
            ProcedureOperation::Write {
                target:
                    OperationTarget::Property {
                        address: PropertyAddress::Extended { object_type, object_instance: 1, property_id },
                        start_element: 1,
                    },
                data: OperationData::Image { .. },
                policy: WriteIntent::Explicit(WritePolicy::ReadBack),
                ..
            } if u16::from(*object_type) == 11 => Some(*property_id),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(ip_writes, properties.keys().copied().collect());
    assert!(procedure.steps.iter().any(|step| {
        matches!(
            &step.operation,
            ProcedureOperation::ReadIntoImage {
                target: OperationTarget::Property {
                    address:PropertyAddress::Extended{object_type,object_instance:1,property_id: pid::ip::MAC_ADDRESS},
                    start_element: 1,
                },
                extent,
                ..
            } if u16::from(*object_type) == 11 && extent.byte_length == 6 && extent.property_elements == Some(1)
        )
    }));
    assert!(
        !procedure.steps.iter().any(|step| {
            matches!(&step.operation, ProcedureOperation::Write { data: OperationData::Secret(_), .. })
        })
    );
    assert!(plan.topology().domain_address.is_none());
}

fn image_space_name(space: &ImageSpace) -> &'static str {
    match space {
        ImageSpace::StandardMemory => "standard",
        ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 3 } } => "relative:3",
        _ => "other",
    }
}
