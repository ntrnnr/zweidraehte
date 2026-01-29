//! Generate MTXML from MDT Push Button Lite device definition.
//!
//! This binary generates a complete set of MTXML files from
//! the MDT Push Button Lite device definition.
//!
//! Use --knxprod flag to also generate a signed .knxprod package.

use std::env;
use std::fs;

use knxprod::signing::{create_knxprod, MasterDataSource, SigningConfig};
use testutil::devices::mdt_push_button_lite::{DEVICE_DESCRIPTOR, MdtParams, MdtStack, SERIAL_NUMBER, comm_objs};
use testutil::mtxml_gen::page_layout::EtsPageLayout;
use testutil::mtxml_gen::{
    ApplicationProgramConfig, CatalogGenerator, HardwareGenerator, MtxmlGenerator, System7MemoryLayout, System7Segment,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Get default parameter values as bytes
    let defaults: MdtParams = Default::default();
    let param_bytes = unsafe {
        core::slice::from_raw_parts(&defaults as *const MdtParams as *const u8, core::mem::size_of::<MdtParams>())
    };

    // System 7 memory layout matching MDT original (MV-0705)
    // Addresses from the original MDT M-0083_A-009B-14-E59D.xml:
    // - AS-4000 @ 16384 (0x4000): Address Table, size 513
    // - AS-4201 @ 16897 (0x4201): Association Table, size 511
    // - AS-4400 @ 17408 (0x4400): ComObject Table, size 364
    // - AS-456C @ 17772 (0x456C): Parameters (EEPROM), size 498
    // - AS-0700 @ 1792 (0x0700): RAM segment, size 316
    // - AS-083C @ 2108 (0x083C): RAM segment, size 1
    let system7_layout = System7MemoryLayout {
        segments: vec![
            System7Segment {
                name: "4000",
                address: 16384,
                size: 513,
                memory_type: None,       // Default
                data: Some(param_bytes), // Address table initial data
                mask: None,              // TODO: Add mask if needed
            },
            System7Segment {
                name: "4201",
                address: 16897,
                size: 511,
                memory_type: None,
                data: None, // Association table - populated by ETS
                mask: None,
            },
            System7Segment {
                name: "4400",
                address: 17408,
                size: 364,
                memory_type: None,
                data: None, // ComObject table
                mask: None,
            },
            System7Segment {
                name: "456C",
                address: 17772,
                size: 498,
                memory_type: Some("EEPROM"),
                data: Some(param_bytes), // Parameters
                mask: None,
            },
            System7Segment {
                name: "0700",
                address: 1792,
                size: 316,
                memory_type: Some("RAM"),
                data: None, // RAM - no initial data
                mask: None,
            },
            System7Segment { name: "083C", address: 2108, size: 1, memory_type: Some("RAM"), data: None, mask: None },
        ],
        address_table_segment: "4000",
        association_table_segment: "4201",
        address_table_offset: 0,
        association_table_offset: 0,
        address_table_max_entries: 255,
        association_table_max_entries: 255,
    };

    let config = ApplicationProgramConfig {
        name: "Push Button Lite 55 1-fold Basic",
        device: &DEVICE_DESCRIPTOR,
        schema_version: None, // Use default V20
        params: MdtParams::ETS_PARAMS_EXT,
        virtual_params: None,
        param_defaults: param_bytes,
        comm_objects: comm_objs::MdtComObjects::ETS_COMM_OBJECTS,
        comm_object_refs: comm_objs::MdtComObjects::ETS_COMM_OBJECT_REFS,
        union_fields: Some(MdtParams::ETS_UNIONS),
        channel_name: "Push Button",
        absolute_segment_address: None, // Using system7_layout instead
        system7_layout: Some(system7_layout),
        application_hash: Some("E59D"), // MDT uses E59D suffix
        non_reg_relevant_data_version: Some(28),
        replaces_versions: Some("18 19"),
        application_data_hash: None, // Hash changes with content, would be generated later

        // Hardware/Catalog configuration
        serial_number: SERIAL_NUMBER,
        hardware_version: 1,
        hardware_name: "Push Button Lite 55 1-fold Basic",
        product_name: "MDT Push Button Lite 55 1-fold Basic",
        order_number: "KP_BE_01",
        is_rail_mounted: false,
        catalog_section: "KNX Push Buttons",

        // Use the page layout from MdtStack
        page_layout: Some(MdtStack::page_layout()),
        modules: None,
    };

    // Generate ApplicationProgram MTXML
    let app_xml = MtxmlGenerator::generate(&config)?;
    let app_path = "MdtApplicationProgram1.mtxml";
    fs::write(app_path, &app_xml)?;
    eprintln!("Generated: {}", app_path);

    // Generate Hardware MTXML
    let hw_xml = HardwareGenerator::generate(&config)?;
    let hw_path = "MdtHardware1.mtxml";
    fs::write(hw_path, &hw_xml)?;
    eprintln!("Generated: {}", hw_path);

    // Generate Catalog MTXML
    let cat_xml = CatalogGenerator::generate(&config)?;
    let cat_path = "MdtCatalog1.mtxml";
    fs::write(cat_path, &cat_xml)?;
    eprintln!("Generated: {}", cat_path);

    eprintln!("\nAll MDT MTXML files generated successfully!");

    // Check if --knxprod flag is provided
    let generate_knxprod = env::args().any(|arg| arg == "--knxprod");

    if generate_knxprod {
        eprintln!("\nGenerating signed .knxprod package...");

        // Build the application program ID from the device descriptor
        // MDT uses a custom hash suffix (E59D) in their app IDs
        let manufacturer_id = format!("{:04X}", DEVICE_DESCRIPTOR.manufacturer_id);
        let app_number = format!("{:04X}", DEVICE_DESCRIPTOR.application_id);
        let app_version = format!("{:02X}", DEVICE_DESCRIPTOR.application_version);
        let app_hash = config.application_hash.unwrap_or("0000");
        let application_program_id = format!(
            "M-{}_A-{}-{}-{}",
            manufacturer_id, app_number, app_version, app_hash
        );

        let signing_config = SigningConfig {
            manufacturer_id: manufacturer_id.clone(),
            application_program: app_xml.clone(),
            application_program_id,
            hardware: hw_xml.clone(),
            catalog: cat_xml.clone(),
            baggage_files: vec![],
        };

        let knxprod_bytes = create_knxprod(&signing_config, MasterDataSource::Download)?;
        // Use a safe filename (no spaces)
        let output_path = "MdtPushButtonLite.knxprod";
        fs::write(output_path, &knxprod_bytes)?;
        eprintln!("Generated: {} ({} bytes)", output_path, knxprod_bytes.len());
        eprintln!("\nVerify with: python3 manuf_tool_data/knx_verifier.py all .");
    } else {
        eprintln!("\nTip: Use --knxprod flag to also generate a signed .knxprod package");
    }

    Ok(())
}
