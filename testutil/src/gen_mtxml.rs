//! Generate MTXML from Rust device definitions.
//!
//! This binary generates a complete set of MTXML files from
//! the demo device definitions:
//! - ApplicationProgram1.mtxml - Application program definition
//! - Hardware1.mtxml - Hardware and product definition
//! - Catalog1.mtxml - Catalog section and item

use std::fs;

use const_default::ConstDefault;

use testutil::devices::{DEVICE_DESCRIPTOR, DemoParams, SERIAL_NUMBER, comm_objs, DemoStack};
use testutil::mtxml_gen::{ApplicationProgramConfig, MtxmlGenerator, HardwareGenerator, CatalogGenerator};
use testutil::mtxml_gen::page_layout::EtsPageLayout;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Get default parameter values as bytes
    let defaults = DemoParams::DEFAULT;
    let param_bytes = unsafe {
        core::slice::from_raw_parts(
            &defaults as *const DemoParams as *const u8,
            core::mem::size_of::<DemoParams>(),
        )
    };

    let config = ApplicationProgramConfig {
        name: "DerGeraet",
        device: &DEVICE_DESCRIPTOR,
        params: DemoParams::ETS_PARAMS_EXT,
        virtual_params: None,
        param_defaults: param_bytes,
        comm_objects: comm_objs::DemoComObjects::ETS_COMM_OBJECTS,
        comm_object_refs: comm_objs::DemoComObjects::ETS_COMM_OBJECT_REFS,
        union_fields: Some(DemoParams::ETS_UNIONS),
        channel_name: "General",
        absolute_segment_address: None, // System B uses relative segments
        system7_layout: None, // System B doesn't use System 7 layout
        application_hash: None, // Use default 0000
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,

        // Hardware/Catalog configuration
        serial_number: SERIAL_NUMBER,
        hardware_version: 1,
        hardware_name: "System B IP device",
        product_name: "My System B IP device",
        order_number: "1234",
        is_rail_mounted: false,
        catalog_section: "KNX/IP Devices",

        // Use the page layout from DemoStack
        page_layout: Some(DemoStack::page_layout()),
        modules: None,
    };

    // Generate ApplicationProgram MTXML
    let app_xml = MtxmlGenerator::generate(&config)?;
    let app_path = "ApplicationProgram1.mtxml";
    fs::write(app_path, &app_xml)?;
    println!("Generated: {}", app_path);

    // Generate Hardware MTXML
    let hw_xml = HardwareGenerator::generate(&config)?;
    let hw_path = "Hardware1.mtxml";
    fs::write(hw_path, &hw_xml)?;
    println!("Generated: {}", hw_path);

    // Generate Catalog MTXML
    let cat_xml = CatalogGenerator::generate(&config)?;
    let cat_path = "Catalog1.mtxml";
    fs::write(cat_path, &cat_xml)?;
    println!("Generated: {}", cat_path);

    println!("\nAll MTXML files generated successfully!");
    println!("\nApplicationProgram preview (first 1500 chars):\n{}", &app_xml[..app_xml.len().min(1500)]);

    Ok(())
}
