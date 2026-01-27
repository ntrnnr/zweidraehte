//! Generate MTXML from the module test device definition.
//!
//! This binary generates a complete set of MTXML files demonstrating
//! KNX module support with a 4-channel dimmer device:
//! - ModuleApplicationProgram1.mtxml - Application program with ModuleDefs
//! - ModuleHardware1.mtxml - Hardware and product definition
//! - ModuleCatalog1.mtxml - Catalog section and item

use std::fs;

use testutil::devices::module_test_device::{
    DEVICE_DESCRIPTOR, GlobalParams, ModuleTestDevice, SERIAL_NUMBER,
};
use testutil::mtxml_gen::{ApplicationProgramConfig, MtxmlGenerator, HardwareGenerator, CatalogGenerator};
use testutil::mtxml_gen::page_layout::EtsPageLayout;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Get default parameter values as bytes
    let defaults = GlobalParams::default();
    let param_bytes = unsafe {
        core::slice::from_raw_parts(
            &defaults as *const GlobalParams as *const u8,
            core::mem::size_of::<GlobalParams>(),
        )
    };

    // Create module collection
    let modules = ModuleTestDevice::create_modules();

    let config = ApplicationProgramConfig {
        name: "ModuleDimmer4Ch",
        device: &DEVICE_DESCRIPTOR,
        params: GlobalParams::ETS_PARAMS_EXT,
        param_defaults: param_bytes,
        comm_objects: &[], // No global comm objects for this test
        comm_object_refs: &[],
        union_fields: None,
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
        hardware_name: "4-Channel Dimmer Module Test",
        product_name: "4-Ch Dimmer (Module Test)",
        order_number: "MOD-DIM-4CH",
        is_rail_mounted: false,
        catalog_section: "Dimmer Actuators",

        // Use the page layout from ModuleTestDevice
        page_layout: Some(ModuleTestDevice::page_layout()),
        modules: Some(modules),
    };

    // Generate ApplicationProgram MTXML
    let app_xml = MtxmlGenerator::generate(&config)?;
    let app_path = "ModuleApplicationProgram1.mtxml";
    fs::write(app_path, &app_xml)?;
    println!("Generated: {}", app_path);

    // Generate Hardware MTXML
    let hw_xml = HardwareGenerator::generate(&config)?;
    let hw_path = "ModuleHardware1.mtxml";
    fs::write(hw_path, &hw_xml)?;
    println!("Generated: {}", hw_path);

    // Generate Catalog MTXML
    let cat_xml = CatalogGenerator::generate(&config)?;
    let cat_path = "ModuleCatalog1.mtxml";
    fs::write(cat_path, &cat_xml)?;
    println!("Generated: {}", cat_path);

    println!("\nAll MTXML files generated successfully!");

    // Print sections with ModuleDefs and Module instances
    println!("\n=== ModuleDefs Section ===");
    if let Some(start) = app_xml.find("<ModuleDefs>") {
        if let Some(end) = app_xml.find("</ModuleDefs>") {
            println!("{}", &app_xml[start..end + "</ModuleDefs>".len()]);
        }
    } else {
        println!("(ModuleDefs section not found)");
    }

    println!("\n=== Module Instances (first few) ===");
    let mut count = 0;
    let mut search_start = 0;
    while count < 4 {
        if let Some(pos) = app_xml[search_start..].find("<Module ") {
            let abs_pos = search_start + pos;
            if let Some(end) = app_xml[abs_pos..].find("</Module>") {
                let module_xml = &app_xml[abs_pos..abs_pos + end + "</Module>".len()];
                println!("{}", module_xml);
                println!();
                search_start = abs_pos + end + "</Module>".len();
                count += 1;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    if count == 0 {
        println!("(No Module instances found in Dynamic section)");
    }

    Ok(())
}
