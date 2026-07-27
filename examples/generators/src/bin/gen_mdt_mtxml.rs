//! Generate MTXML from MDT Push Button Lite device definition.
//!
//! This binary generates a complete set of MTXML files from
//! the MDT Push Button Lite device definition.
//!
//! Use --knxprod flag to also generate a signed .knxprod package.

use std::env;
use std::path::PathBuf;

use const_default::ConstDefault;

use devices::mdt_push_button_lite::{
    DEVICE_DESCRIPTOR, MDT_TRANSLATIONS_DE, MdtParams, MdtPushButtonLiteDevice, SERIAL_NUMBER, comm_objs,
};
use zweidraehte_knxprod::definition::page_layout::EtsPageLayout;
use zweidraehte_knxprod::signing::{KnxSchemaVersion, MasterDataSource};
use zweidraehte_knxprod::{
    ApplicationProgramDef, KnxprodBuilder, SingleDeviceDef, System7MemoryLayout, System7Segment,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Get default parameter values as bytes.
    //
    // A `static` rather than a local, because `System7Segment::data` is
    // `Option<&'static [u8]>`. The previous `from_raw_parts` cast satisfied
    // that only by producing an unbounded lifetime out of a raw pointer —
    // which happened to be sound here (the local outlived every use) but was
    // unchecked. Anchoring the value in static storage makes the borrow real.
    static DEFAULTS: MdtParams = MdtParams::DEFAULT;
    let param_bytes = zweidraehte_generators::params_as_bytes(&DEFAULTS);

    // System 7 memory layout matching MDT original (MV-0705)
    // Addresses from the original MDT M-0083_A-009B-14-E59D.xml:
    // - AS-4000 @ 16384 (0x4000): Address Table, size 513
    // - AS-4201 @ 16897 (0x4201): Association Table, size 511
    // - AS-4400 @ 17408 (0x4400): ComObject Table, size 364
    // - AS-456C @ 17772 (0x456C): Parameters (EEPROM), size 498
    // - AS-0700 @ 1792 (0x0700): RAM segment, size 316
    // - AS-083C @ 2108 (0x083C): RAM segment, size 1
    //
    // Every size below is the original's except the parameter segment, which is
    // sized to what `MdtParams` actually occupies rather than being written out
    // as a literal. Deriving it means it cannot drift from the struct, and
    // `validate_param_offsets` rejects a parameter placed past the end of its
    // own segment, so a literal that fell behind a struct change would fail the
    // build rather than silently mis-declare the layout. Reaching exactly MDT's
    // 498 is the parity goal: it arrives when the struct is laid out on MDT's
    // offsets, reserved gaps included.
    let system7_layout = System7MemoryLayout {
        segments: vec![
            System7Segment {
                name: "4000",
                address: 16384,
                size: 513,
                memory_type: None, // Default
                // No initial data: ETS builds the address table from the group
                // addresses assigned in the project, exactly as for the
                // association and communication object tables below.
                data: None,
                mask: None, // TODO: Add mask if needed
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
                size: param_bytes.len() as u32,
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
        serial_number: SERIAL_NUMBER,
    };

    let app = ApplicationProgramDef {
        name: "Push Button Lite 55 1-fold Basic",
        device: &DEVICE_DESCRIPTOR,
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
        page_layout: Some(MdtPushButtonLiteDevice::page_layout()),
        modules: None,
        baggages: None,
        translations: Some(MDT_TRANSLATIONS_DE),
        bus_interfaces: None,
        additional_addresses_count: None,
        ip_config: None,
        is_secure_enabled: None,
        max_user_entries: None,
        max_tunneling_user_entries: None,
        max_security_individual_address_entries: None,
        max_security_group_key_table_entries: None,
        max_security_p2p_key_table_entries: None,
    };

    // Output directory: out/<device>/
    let device_name = "MdtPushButtonLite";
    let out_dir: PathBuf = ["out", device_name].iter().collect();

    let builder = KnxprodBuilder::single_device(SingleDeviceDef {
        app: &app,
        serial_number: SERIAL_NUMBER,
        hardware_version: 1,
        hardware_name: "Push Button Lite 55 1-fold Basic",
        product_name: "MDT Push Button Lite 55 1-fold Basic",
        order_number: "KP_BE_01",
        is_rail_mounted: false,
        catalog_section: "KNX Push Buttons",
        is_ip_enabled: None,
        is_rf_retransmitter: None,
        rf_rx_capabilities: None,
        rf_tx_capabilities: None,
    })
    .output_dir(&out_dir)
    .file_prefix("Mdt")
    .schema_version(KnxSchemaVersion::V20);

    // Check if --knxprod flag is provided
    let generate_knxprod = env::args().any(|arg| arg == "--knxprod");

    if generate_knxprod {
        // Use KnxprodBuilder to generate everything including signed package
        let (output, knxprod_path) = builder.master_data(MasterDataSource::Download).build_all()?;

        // Print what was generated
        let manuf_dir = out_dir.join(format!("M-{}", output.manufacturer_id));
        eprintln!("Output directory: {}", manuf_dir.display());
        for (filename, _) in output.xml_files() {
            eprintln!("Generated: {}", manuf_dir.join(filename).display());
        }
        eprintln!("\nGenerated: {} ({} bytes)", knxprod_path.display(), std::fs::metadata(&knxprod_path)?.len());
        eprintln!("\nVerify with: python3 manuf_tool_data/knx_verifier.py all .");
    } else {
        // Just generate MTXML files
        let (output, paths) = builder.write_mtxml_with_paths()?;

        let manuf_dir = out_dir.join(format!("M-{}", output.manufacturer_id));
        eprintln!("Output directory: {}", manuf_dir.display());
        for path in &paths {
            eprintln!("Generated: {}", path.display());
        }

        eprintln!("\nAll MDT MTXML files generated successfully!");
        eprintln!("\nTip: Use --knxprod flag to also generate a signed .knxprod package");
    }

    Ok(())
}
