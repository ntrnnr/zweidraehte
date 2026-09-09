//! Check the serialized separator contract in device and reusable-module pages.

use super::*;
use crate::definition::page_layout::{ModuleLayoutElement, ModuleLayoutItem};
use crate::{ets_module_pages, ets_pages};
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};

const HELP: &str = "Use the programming button to return to the loader.";

fn config() -> ApplicationProgramConfig<'static> {
    const DEVICE: DeviceDescriptor =
        DeviceDescriptor::new(MaskVersion::SystemBTp1, 0x00fa, [0; 6], 0xf001, 1, 8, 8, 8, 0);

    ApplicationProgramConfig {
        name: "Ambient light",
        device: &DEVICE,
        params: &[],
        virtual_params: None,
        param_defaults: &[],
        comm_objects: &[],
        comm_object_refs: &[],
        union_fields: None,
        channel_name: "General",
        absolute_segment_address: None,
        system7_layout: None,
        bcu2_layout: None,
        application_hash: None,
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        page_layout: None,
        modules: None,
        baggages: None,
        translations: None,
        bus_interfaces: None,
        additional_addresses_count: None,
        ip_config: None,
        is_secure_enabled: None,
        max_user_entries: None,
        max_tunneling_user_entries: None,
        max_security_individual_address_entries: None,
        max_security_group_key_table_entries: None,
        max_security_p2p_key_table_entries: None,
    }
}

fn check_notes(notes: &[&ParameterSeparator]) {
    let expected = [
        ("", None),
        ("Startup", None),
        ("", Some("HorizontalRuler")),
        ("Recovery", Some("Headline")),
        (HELP, Some("Information")),
        ("Configuration incomplete", Some("Error")),
        (HELP, None),
    ];

    assert_eq!(notes.len(), expected.len());

    for (note, (text, hint)) in notes.iter().zip(expected) {
        assert_eq!(note.text.as_deref(), Some(text));
        assert_eq!(note.ui_hint.as_deref(), hint);
    }

    let ids: std::collections::HashSet<_> = notes.iter().map(|note| &note.id).collect();

    assert_eq!(ids.len(), notes.len(), "each translated separator needs its own ID");
}

#[test]
fn device_hints_survive_xml_serialization_without_changing_plain_separators() {
    let mut config = config();
    config.page_layout = Some(ets_pages! {
        device {
            block "general" => "General" {
                sep
                sep "Startup"
                sep ui_hint HorizontalRuler
                sep "Recovery" ui_hint Headline
                sep (HELP) ui_hint Information
                sep (concat!("Configuration ", "incomplete")) ui_hint Error
                sep (HELP)
            }
        }
    });

    let xml = MtxmlGenerator::generate(&config, None).expect("valid device layout");
    let document: Knx = zweidraehte_ets_files::xml::from_str(&xml).expect("generated XML parses");
    let dynamic = document.manufacturer_data.manufacturer.application_programs.programs[0]
        .dynamic
        .as_ref()
        .expect("device pages");
    let ChannelIndependentItem::ParameterBlock(block) =
        &dynamic.channel_independent_block().expect("device settings").items[0]
    else {
        panic!("General is a parameter block");
    };
    let notes: Vec<_> = block
        .items
        .iter()
        .filter_map(|item| match item {
            ParameterBlockItem::ParameterSeparator(note) => Some(note),
            _ => None,
        })
        .collect();

    check_notes(&notes);
}

#[test]
fn module_hints_survive_both_block_and_conditional_serialization() {
    let layout = ets_module_pages! {
        block "general" => "General" {
            sep
            sep "Startup"
            sep ui_hint HorizontalRuler
            sep "Recovery" ui_hint Headline
            sep (HELP) ui_hint Information
            sep (concat!("Configuration ", "incomplete")) ui_hint Error
            sep (HELP)
        }
    };
    let ModuleLayoutElement::Block(block) = &layout.elements[0] else { panic!("General block") };
    let module = StoredModuleDef {
        name: "Ambient output".into(),
        arguments: vec![],
        internal_description: None,
        params: None,
        virtual_params: None,
        comm_objects: None,
        page_layout: None,
    };
    let pictures = HashMap::new();
    let mut counter = 0;

    let items = MtxmlGenerator::convert_module_layout_items(
        "M-00FA_A-F001-01-0000_MD-1",
        &module,
        0,
        &block.items,
        &mut counter,
        &pictures,
    );
    let xml = zweidraehte_ets_files::xml::to_string(&ChannelIndependentBlock {
        items: vec![ChannelIndependentItem::ParameterBlock(ParameterBlock {
            id: "block".into(),
            name: None,
            text: None,
            text_parameter_ref_id: None,
            param_ref_id: None,
            internal_description: None,
            access: None,
            inline: None,
            show_in_com_object_tree: None,
            layout: None,
            items,
        })],
    })
    .expect("module block serializes");
    let parsed: ChannelIndependentBlock = zweidraehte_ets_files::xml::from_str(&xml).expect("module block parses");
    let ChannelIndependentItem::ParameterBlock(parsed) = &parsed.items[0] else { panic!("module block") };
    let notes: Vec<_> = parsed
        .items
        .iter()
        .filter_map(|item| match item {
            ParameterBlockItem::ParameterSeparator(note) => Some(note),
            _ => None,
        })
        .collect();

    check_notes(&notes);

    let items = MtxmlGenerator::convert_module_layout_items_to_when(
        "M-00FA_A-F001-01-0000_MD-1",
        &module,
        0,
        &block.items,
        &mut counter,
        &pictures,
    );
    let xml = zweidraehte_ets_files::xml::to_string(&When {
        test: Some("1".into()),
        default: None,
        internal_description: None,
        items,
    })
    .expect("conditional notes serialize");
    let parsed: When = zweidraehte_ets_files::xml::from_str(&xml).expect("conditional notes parse");
    let notes: Vec<_> = parsed
        .items
        .iter()
        .filter_map(|item| match item {
            WhenItem::ParameterSeparator(note) => Some(note),
            _ => None,
        })
        .collect();

    check_notes(&notes);

    assert!(matches!(block.items[4], ModuleLayoutItem::Separator { ui_hint: Some(_), .. }));
}
