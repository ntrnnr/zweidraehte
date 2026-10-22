use super::*;
use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence};
use crate::commissioning::catalog_testing::*;
use crate::commissioning::error::CompileError;
use crate::commissioning::image::ImageSpace;
use crate::commissioning::image::{ImageLocation, ImageSegment, NativeImageRegion, SparseDeviceImage};
use crate::commissioning::input::{CommissioningIntent, ProgrammingInput, TargetSelection};
use crate::commissioning::test_support::architecture::{catalog, product};
use crate::commissioning::{CompileOptions, DownloadMode};
use crate::configuration::ResolvedKeyMaterial;
use crate::configuration::{LoweredDeviceConfiguration, MaterializedDevice};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_ets_files::product::Segment;
use zweidraehte_proto::address::IndividualAddress;

#[test]
fn preview_retains_every_property_occurrence_and_ownership_mask() {
    let placements = [
        ImageSpace::Property { object: ObjectSelector::Index { index: 12 }, property_id: 23 },
        ImageSpace::Property {
            object: ObjectSelector::Type { object_type: 17, occurrence: Occurrence::Absent },
            property_id: 23,
        },
        ImageSpace::Property {
            object: ObjectSelector::Type { object_type: 17, occurrence: Occurrence::Zero },
            property_id: 23,
        },
        ImageSpace::Property {
            object: ObjectSelector::Type { object_type: 17, occurrence: Occurrence::from_option(Some(2)) },
            property_id: 23,
        },
    ];
    let mut image = SparseDeviceImage::new();
    let regions = placements
        .iter()
        .map(|space| {
            let segment = ImageSegment::new(ImageLocation { space: space.clone(), offset: 5 }, vec![0x53], vec![0x0f])
                .expect("data and mask widths match");
            image.apply(&segment);
            NativeImageRegion {
                source_id: None,
                memory_type: None,
                seed: Vec::new(),
                location: segment.location().clone(),
                length: segment.data().len() as u32,
            }
        })
        .collect();
    let image = ProgramImage {
        image,
        regions,
        manifest: Default::default(),
        table_spans: Vec::new(),
        product_fingerprint: [0; 32],
        requirements: Vec::new(),
    };
    assert!(image.is_complete());
    assert_eq!(image.regions().len(), placements.len());
    for placement in placements {
        let (region, bytes) = image
            .projected_regions()
            .find(|(region, _)| region.location.space == placement)
            .expect("exact selector is preserved");
        assert_eq!(region.location.offset, 5);
        assert_eq!(bytes.mask(), [0x0f]);
    }
}

#[test]
fn exact_frontend_previews_cover_classic_programming_families() {
    let catalog = catalog(23);
    let cases = [
        ("BCU1", "MV-0012", "DefaultProcedure", false),
        ("BCU2", "MV-0020", "ProductProcedure", false),
        ("System 7", "MV-0705", "ProductProcedure", false),
        ("System B", "MV-07B0", "DefaultProcedure", true),
    ];

    for (name, mask, load_style, relative) in cases {
        let product = product(mask, load_style, relative, false);
        let configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15))
            .with_com_objects(product.com_objects().to_vec());
        let preview = configuration_preview(&catalog, &product, &configuration)
            .unwrap_or_else(|error| panic!("{name} exact preview must compile: {error}"));

        assert!(!preview.regions().is_empty(), "{name} preview has no compiled image spans");
        assert!(
            preview.regions().iter().any(|segment| {
                matches!(
                    (relative, &segment.location.space),
                    (false, ImageSpace::StandardMemory) | (true, ImageSpace::RelativeMemory { .. })
                )
            }),
            "{name} preview does not retain its exact profile address space"
        );
    }
}

#[test]
fn pending_full_preview_does_not_invent_table_width_or_block_address_only_preview() {
    let catalog = catalog(23);
    let xml = catalog.source_xml().replace(
        "<Resource Name=\"ApplicationDataPtr\"",
        r#"<Resource Name="GroupAssociationTable" Access="remote">
          <Location AddressSpace="StandardMemory" StartAddress="1024"/>
          <ResourceType Length="2" Flavour="AssociationTable_SystemB"/>
        </Resource><Resource Name="ApplicationDataPtr""#,
    );
    let catalog = parse_master_data(&xml).expect("pending capability fixture parses");
    let product = product("MV-07B0", "DefaultProcedure", true, false);
    let configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15))
        .with_com_objects(product.com_objects().to_vec());
    let pending = configuration_preview(&catalog, &product, &configuration).expect("unobserved width is pending");
    assert!(!pending.is_complete());
    assert!(pending.regions().is_empty());
    assert!(matches!(pending.requirements(), [
        crate::commissioning::ImageRequirement::AssociationTableEntrySize { .. }
    ]));

    let device = MaterializedDevice::new(product, configuration, Vec::new(), ResolvedKeyMaterial::new(None))
        .bind_master_data(std::sync::Arc::clone(&catalog))
        .expect("fixture catalogue binds");
    let input = ProgrammingInput::new(device, CommissioningIntent::AssignAddress, CompileOptions {
        target: TargetSelection::ExistingAddress(IndividualAddress::new(1, 1, 1)),
        automatic_sections: None,
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
    });
    let selection = ProfileSelection {
        discovery: ProfileDiscovery { dd0: 0x07b0, management_descriptor_01: None, management_style: None },
        variant_hint: VariantHint::Automatic,
    };
    let image = input.preview_selection(&selection).expect("address-only preview never needs table width");
    assert!(image.is_complete());
    assert!(image.image().is_empty());
}

#[test]
fn frontend_preview_preserves_product_segment_boundaries_and_capacity() {
    let catalog = catalog(23);
    let product = product("MV-0705", "ProductProcedure", false, false).with_fixture_segments(vec![
        Segment {
            id: "application-a".to_owned(),
            address: Some(0x100),
            size: 4,
            memory_type: Some("EEPROM".to_owned()),
            user_memory: None,
            load_state_machine: None,
            data: vec![0x11],
            mask: None,
        },
        Segment {
            id: "application-b".to_owned(),
            address: Some(0x104),
            size: 3,
            memory_type: None,
            user_memory: None,
            load_state_machine: None,
            data: Vec::new(),
            mask: None,
        },
    ]);
    let configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15))
        .with_com_objects(product.com_objects().to_vec());

    let preview = configuration_preview(&catalog, &product, &configuration).expect("preview compiles");
    let application = preview
        .projected_regions()
        .filter(|(region, _)| region.display_id().starts_with("application-"))
        .collect::<Vec<_>>();

    assert_eq!(application.len(), 2, "adjacent product segments must not be coalesced");
    assert_eq!(application[0].1.data(), [0x11, 0, 0, 0]);
    assert_eq!(application[1].1.data(), [0, 0, 0]);
    assert_eq!(application[0].0.length, 4);
    assert_eq!(application[1].0.length, 3);
}

fn configuration_preview(
    catalog: &std::sync::Arc<MasterData>,
    product: &ProductData,
    configuration: &LoweredDeviceConfiguration,
) -> Result<crate::commissioning::ProgramImage, CompileError> {
    let device =
        MaterializedDevice::new(product.clone(), configuration.clone(), Vec::new(), ResolvedKeyMaterial::new(None))
            .bind_master_data(std::sync::Arc::clone(catalog))
            .expect("exact fixture catalogue binds");
    let selection = ProfileSelection {
        discovery: ProfileDiscovery {
            dd0: product.mask_version().expect("fixture mask").as_u16(),
            management_descriptor_01: None,
            management_style: None,
        },
        variant_hint: VariantHint::Automatic,
    };
    let input = ProgrammingInput::new(device, CommissioningIntent::Download(DownloadMode::Automatic), CompileOptions {
        target: TargetSelection::ExistingAddress(configuration.individual_address),
        automatic_sections: None,
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
    });
    input.preview_selection(&selection)
}
