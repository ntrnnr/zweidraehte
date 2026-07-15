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
use std::path::PathBuf;

use const_default::ConstDefault;

use devices::system_b_demo::{DEVICE_DESCRIPTOR, DemoParams, DemoStack, SERIAL_NUMBER, comm_objs};
use zweidraehte_knxprod::definition::page_layout::EtsPageLayout;
use zweidraehte_knxprod::signing::{KnxSchemaVersion, MasterDataSource};
use zweidraehte_knxprod::{ApplicationProgramDef, KnxprodBuilder, SingleDeviceDef};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Get default parameter values as bytes
    let defaults = DemoParams::DEFAULT;
    let param_bytes = unsafe {
        core::slice::from_raw_parts(&defaults as *const DemoParams as *const u8, core::mem::size_of::<DemoParams>())
    };

    let app = ApplicationProgramDef {
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
        system7_layout: None,           // System B doesn't use System 7 layout
        application_hash: None,         // Use default 0000
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        page_layout: Some(DemoStack::page_layout()),
        modules: None,
        baggages: None,
        translations: None,
        bus_interfaces: None,
        additional_addresses_count: None,
        ip_config: None,
        is_secure_enabled: None,
        max_security_individual_address_entries: None,
        max_security_group_key_table_entries: None,
        max_security_p2p_key_table_entries: None,
    };

    // Output directory: out/<device>/
    let out_dir: PathBuf = ["out", app.name].iter().collect();

    let builder = KnxprodBuilder::single_device(SingleDeviceDef {
        app: &app,
        serial_number: SERIAL_NUMBER,
        hardware_version: 1,
        hardware_name: "System B IP device",
        product_name: "My System B IP device",
        order_number: "1234",
        is_rail_mounted: false,
        catalog_section: "KNX/IP Devices",
        is_ip_enabled: Some(true),
        is_rf_retransmitter: None,
        rf_rx_capabilities: None,
        rf_tx_capabilities: None,
    })
    .output_dir(&out_dir)
    .schema_version(KnxSchemaVersion::V20);

    // Check if --knxprod flag is provided
    let generate_knxprod = env::args().any(|arg| arg == "--knxprod");

    if generate_knxprod {
        // Use KnxprodBuilder to generate everything including signed package
        let (output, knxprod_path) = builder.master_data(MasterDataSource::Download).build_all()?;

        // Print what was generated
        let manuf_dir = out_dir.join(format!("M-{}", output.manufacturer_id));
        println!("Output directory: {}", manuf_dir.display());
        for (filename, _) in output.xml_files() {
            println!("Generated: {}", manuf_dir.join(filename).display());
        }
        println!("\nGenerated: {} ({} bytes)", knxprod_path.display(), std::fs::metadata(&knxprod_path)?.len());
        println!("\nVerify with: python3 manuf_tool_data/knx_verifier.py all .");
    } else {
        // Just generate MTXML files
        let (output, paths) = builder.write_mtxml_with_paths()?;

        let manuf_dir = out_dir.join(format!("M-{}", output.manufacturer_id));
        println!("Output directory: {}", manuf_dir.display());
        for path in &paths {
            println!("Generated: {}", path.display());
        }

        println!("\nAll MTXML files generated successfully!");
        println!("\nTip: Use --knxprod flag to also generate a signed .knxprod package");
    }

    Ok(())
}
