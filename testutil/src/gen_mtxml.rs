//! Generate MTXML from Rust device definitions.
//!
//! This binary generates a complete set of MTXML files from
//! the demo device definitions:
//! - ApplicationProgram1.mtxml - Application program definition
//! - Hardware1.mtxml - Hardware and product definition
//! - Catalog1.mtxml - Catalog section and item
//!
//! Use --knxprod flag to also generate a signed .knxprod package.

use std::env;
use std::fs;
use std::path::PathBuf;

use const_default::ConstDefault;

use knxprod::signing::KnxSchemaVersion;
use knxprod::signing::{MasterDataSource, SigningConfig, create_knxprod};
use testutil::devices::{DEVICE_DESCRIPTOR, DemoParams, DemoStack, SERIAL_NUMBER, comm_objs};
use testutil::mtxml_gen::page_layout::EtsPageLayout;
use testutil::mtxml_gen::{ApplicationProgramConfig, CatalogGenerator, HardwareGenerator, MtxmlGenerator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Get default parameter values as bytes
    let defaults = DemoParams::DEFAULT;
    let param_bytes = unsafe {
        core::slice::from_raw_parts(&defaults as *const DemoParams as *const u8, core::mem::size_of::<DemoParams>())
    };

    let config = ApplicationProgramConfig {
        name: "DerGeraet",
        device: &DEVICE_DESCRIPTOR,
        schema_version: Some(KnxSchemaVersion::V20),
        params: DemoParams::ETS_PARAMS_EXT,
        virtual_params: None,
        param_defaults: param_bytes,
        comm_objects: comm_objs::DemoComObjects::ETS_COMM_OBJECTS,
        comm_object_refs: comm_objs::DemoComObjects::ETS_COMM_OBJECT_REFS,
        union_fields: Some(DemoParams::ETS_UNIONS),
        channel_name: "General",
        absolute_segment_address: None, // System B uses relative segments
        system7_layout: None,           // System B doesn't use System 7 layout
        application_hash: None,         // Use default 0000
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
        baggages: None,
    };

    // Create output directory structure: out/<device>/M-XXXX/
    let manufacturer_id = format!("{:04X}", DEVICE_DESCRIPTOR.manufacturer_id);
    let out_dir: PathBuf = ["out", config.name, &format!("M-{}", manufacturer_id)].iter().collect();
    fs::create_dir_all(&out_dir)?;
    println!("Output directory: {}", out_dir.display());

    // Generate ApplicationProgram MTXML
    let app_xml = MtxmlGenerator::generate(&config)?;
    let app_path = out_dir.join("ApplicationProgram1.mtxml");
    fs::write(&app_path, &app_xml)?;
    println!("Generated: {}", app_path.display());

    // Generate Hardware MTXML
    let hw_xml = HardwareGenerator::generate(&config)?;
    let hw_path = out_dir.join("Hardware1.mtxml");
    fs::write(&hw_path, &hw_xml)?;
    println!("Generated: {}", hw_path.display());

    // Generate Catalog MTXML
    let cat_xml = CatalogGenerator::generate(&config)?;
    let cat_path = out_dir.join("Catalog1.mtxml");
    fs::write(&cat_path, &cat_xml)?;
    println!("Generated: {}", cat_path.display());

    println!("\nAll MTXML files generated successfully!");

    // Check if --knxprod flag is provided
    let generate_knxprod = env::args().any(|arg| arg == "--knxprod");

    if generate_knxprod {
        println!("\nGenerating signed .knxprod package...");

        // Build the application program ID from the device descriptor
        let app_number = format!("{:04X}", DEVICE_DESCRIPTOR.application_id);
        let app_version = format!("{:02X}", DEVICE_DESCRIPTOR.application_version);
        let application_program_id = format!("M-{}_A-{}-{}-0000", manufacturer_id, app_number, app_version);

        let signing_config = SigningConfig {
            manufacturer_id: manufacturer_id.clone(),
            application_program: app_xml.clone(),
            application_program_id,
            hardware: hw_xml.clone(),
            catalog: cat_xml.clone(),
            baggage_files: vec![],
        };

        let knxprod_bytes = create_knxprod(&signing_config, MasterDataSource::Download)?;
        // Write knxprod to out/<device>/<name>.knxprod
        let device_out_dir: PathBuf = ["out", config.name].iter().collect();
        let output_path = device_out_dir.join(format!("{}.knxprod", config.name));
        fs::write(&output_path, &knxprod_bytes)?;
        println!("Generated: {} ({} bytes)", output_path.display(), knxprod_bytes.len());
        println!("\nVerify with: python3 manuf_tool_data/knx_verifier.py all .");
    } else {
        println!("\nTip: Use --knxprod flag to also generate a signed .knxprod package");
        println!("\nApplicationProgram preview (first 1500 chars):\n{}", &app_xml[..app_xml.len().min(1500)]);
    }

    Ok(())
}
