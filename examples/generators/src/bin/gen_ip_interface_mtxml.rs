//! Generate MTXML / knxprod from the IP Interface device definition.
//!
//! Produces a single-device package for a KNX IP Interface with 4
//! tunneling channels. The device uses mask version 07B0 (System B TP1)
//! since the primary bus connection is TP1.
//!
//! Usage:
//!   cargo run --bin gen_ip_interface_mtxml              # MTXML only
//!   cargo run --bin gen_ip_interface_mtxml -- --knxprod  # signed .knxprod package

use std::env;
use std::path::PathBuf;

use devices::ip_interface::{DEVICE_DESCRIPTOR, IpInterfaceDevice, IpInterfaceParams, SERIAL_NUMBER};
use zweidraehte_knxprod::signing::{KnxSchemaVersion, MasterDataSource};
use zweidraehte_knxprod::{ApplicationProgramDef, BusAccessType, BusInterfaceDef, KnxprodBuilder, SingleDeviceDef};

/// Generate bus interface definitions for the tunneling channels.
///
/// Each channel gets a `BusInterfaceDef` with a 1-based address index
/// matching the slot in the device's additional IA table (PID 53).
fn tunneling_bus_interfaces() -> Vec<BusInterfaceDef> {
    (1..=IpInterfaceDevice::ADDITIONAL_IA_COUNT)
        .map(|i| BusInterfaceDef { address_index: i, access_type: BusAccessType::Tunneling, text: None })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Empty parameters — zero bytes.
    let defaults = IpInterfaceParams::default();
    let param_bytes = zweidraehte_generators::params_as_bytes(&defaults);

    let bus_interfaces = tunneling_bus_interfaces();

    let app = ApplicationProgramDef {
        name: "IpInterface",
        device: &DEVICE_DESCRIPTOR,
        params: IpInterfaceParams::ETS_PARAMS_EXT,
        virtual_params: None,
        param_defaults: param_bytes,
        comm_objects: &[],
        comm_object_refs: &[],
        union_fields: None,
        channel_name: "General",
        absolute_segment_address: None,
        bcu2_layout: None,
        system7_layout: None,
        application_hash: None,
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        page_layout: None,
        modules: None,
        baggages: None,
        translations: None,
        bus_interfaces: Some(&bus_interfaces),
        additional_addresses_count: Some(IpInterfaceDevice::ADDITIONAL_IA_COUNT as u32),
        ip_config: Some("Tool"),
        is_secure_enabled: None,
        max_user_entries: None,
        max_tunneling_user_entries: None,
        max_security_individual_address_entries: None,
        max_security_group_key_table_entries: None,
        max_security_p2p_key_table_entries: None,
    };

    let out_dir: PathBuf = ["out", app.name].iter().collect();

    let builder = KnxprodBuilder::single_device(SingleDeviceDef {
        app: &app,
        serial_number: SERIAL_NUMBER,
        hardware_version: 1,
        hardware_name: "KNX IP Interface",
        product_name: "IP Interface (4 tunnels)",
        order_number: "IP-IF-004",
        is_rail_mounted: false,
        catalog_section: "KNX/IP Interfaces",
        is_ip_enabled: Some(true),
        is_rf_retransmitter: None,
        rf_rx_capabilities: None,
        rf_tx_capabilities: None,
    })
    .output_dir(&out_dir)
    .schema_version(KnxSchemaVersion::V20);

    let generate_knxprod = env::args().any(|arg| arg == "--knxprod");

    if generate_knxprod {
        let (output, knxprod_path) = builder.master_data(MasterDataSource::Download).build_all()?;

        let manuf_dir = out_dir.join(format!("M-{}", output.manufacturer_id));
        println!("Output directory: {}", manuf_dir.display());
        for (filename, _) in output.xml_files() {
            println!("Generated: {}", manuf_dir.join(filename).display());
        }
        println!("\nGenerated: {} ({} bytes)", knxprod_path.display(), std::fs::metadata(&knxprod_path)?.len());
    } else {
        let (output, paths) = builder.write_mtxml_with_paths()?;

        let manuf_dir = out_dir.join(format!("M-{}", output.manufacturer_id));
        println!("Output directory: {}", manuf_dir.display());
        for path in &paths {
            println!("Generated: {}", path.display());
        }

        println!("\nAll MTXML files generated successfully!");
        println!("Tip: Use --knxprod flag to also generate a signed .knxprod package");
    }

    Ok(())
}
