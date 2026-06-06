//! Generate MTXML / knxprod / knxproj from the light switch device definition.
//!
//! Produces a multi-device package containing KNX/IP, TP1 (TPUART),
//! TP1 Data Secure, KNX-RF, and KNX-RF Data Secure variants of the same
//! light switch. All share the same application logic, parameters, and
//! page layout — they differ only in mask version (medium type) and
//! whether Data Secure is declared.
//!
//! Usage:
//!   cargo run --bin gen_light_switch_mtxml              # MTXML only
//!   cargo run --bin gen_light_switch_mtxml -- --knxprod  # signed .knxprod package
//!   cargo run --bin gen_light_switch_mtxml -- --knxproj  # signed .knxproj test project

use std::env;
use std::path::PathBuf;

use const_default::ConstDefault;

use devices::light_switch::{
    DEVICE_DESCRIPTOR_IP, DEVICE_DESCRIPTOR_RF, DEVICE_DESCRIPTOR_RF_SECURE, DEVICE_DESCRIPTOR_TP1,
    DEVICE_DESCRIPTOR_TP1_SECURE, LightSwitchDevice, LightSwitchParams, comm_objs, params::LIGHT_SWITCH_VIRTUAL_PARAMS,
    translations::LIGHT_SWITCH_TRANSLATIONS,
};
use zweidraehte_knxprod::definition::page_layout::EtsPageLayout;
use zweidraehte_knxprod::signing::{KnxSchemaVersion, MasterDataSource};
use zweidraehte_knxprod::{
    ApplicationProgramDef, CatalogEntryDef, CatalogSectionDef, DeviceInstanceDef, HardwareDef, KnxprodBuilder,
    ProductDef, RfRxCapabilities, RfTxCapabilities,
};

/// Hardware serial for the KNX/IP variant.
const SERIAL_NUMBER_IP: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x03];

/// Hardware serial for the TP1 variant.
const SERIAL_NUMBER_TP1: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x04];

/// Hardware serial for the Data Secure TP1 variant.
const SERIAL_NUMBER_TP1_SECURE: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x05];

/// Hardware serial for the KNX-RF variant. Pairs with the
/// `stm32g0_knxrf_device` firmware.
const SERIAL_NUMBER_RF: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x06];

/// Hardware serial for the Data Secure KNX-RF variant. No firmware yet —
/// the device definition exists so the variant can be generated.
const SERIAL_NUMBER_RF_SECURE: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x07];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Get default parameter values as raw bytes for the knxprod.
    let defaults = LightSwitchParams::DEFAULT;
    let param_bytes = unsafe {
        core::slice::from_raw_parts(
            &defaults as *const LightSwitchParams as *const u8,
            core::mem::size_of::<LightSwitchParams>(),
        )
    };

    let page_layout = LightSwitchDevice::page_layout();

    // Both variants share the same application logic — only the device
    // descriptor (and thus the mask version / medium type) differs.
    let app_ip = ApplicationProgramDef {
        name: "LightSwitch2",
        device: &DEVICE_DESCRIPTOR_IP,
        params: LightSwitchParams::ETS_PARAMS_EXT,
        virtual_params: Some(LIGHT_SWITCH_VIRTUAL_PARAMS),
        param_defaults: param_bytes,
        comm_objects: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECTS,
        comm_object_refs: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECT_REFS,
        union_fields: Some(LightSwitchParams::ETS_UNIONS),
        channel_name: "General",
        absolute_segment_address: None,
        system7_layout: None,
        application_hash: None,
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        page_layout: Some(page_layout.clone()),
        modules: None,
        baggages: None,
        translations: Some(LIGHT_SWITCH_TRANSLATIONS),
        bus_interfaces: None,
        additional_addresses_count: None,
        ip_config: None,
        is_secure_enabled: None,
        max_security_individual_address_entries: None,
        max_security_group_key_table_entries: None,
        max_security_p2p_key_table_entries: None,
    };

    let app_tp1 = ApplicationProgramDef {
        name: "LightSwitch2TP",
        device: &DEVICE_DESCRIPTOR_TP1,
        params: LightSwitchParams::ETS_PARAMS_EXT,
        virtual_params: Some(LIGHT_SWITCH_VIRTUAL_PARAMS),
        param_defaults: param_bytes,
        comm_objects: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECTS,
        comm_object_refs: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECT_REFS,
        union_fields: Some(LightSwitchParams::ETS_UNIONS),
        channel_name: "General",
        absolute_segment_address: None,
        system7_layout: None,
        application_hash: None,
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        page_layout: Some(page_layout.clone()),
        modules: None,
        baggages: None,
        translations: Some(LIGHT_SWITCH_TRANSLATIONS),
        bus_interfaces: None,
        additional_addresses_count: None,
        ip_config: None,
        is_secure_enabled: None,
        max_security_individual_address_entries: None,
        max_security_group_key_table_entries: None,
        max_security_p2p_key_table_entries: None,
    };

    // Data Secure TP1 variant: same application logic as `app_tp1` but
    // declared secure-capable to ETS. Table sizes match what the
    // `stm32g0_tp1_secure_light_switch` firmware can hold — see
    // `SIAT_SIZE` / `P2P_SIZE` in that crate's `main.rs`.
    //
    // Per 03/03/07 §5.3 the SIAT stores LastValidSeqNr for every
    // non-tool secure sender — group senders included, not only P2P
    // partners. So even this tool-access + group-only device needs
    // `SIAT > 0`; ETS writes one SIAT slot per secure sender IA
    // during commissioning. `P2P = 0` because we do not carry P2P
    // key material (no secure P2P traffic with partner devices).
    let app_tp1_secure = ApplicationProgramDef {
        name: "LightSwitch2TPSecure",
        device: &DEVICE_DESCRIPTOR_TP1_SECURE,
        params: LightSwitchParams::ETS_PARAMS_EXT,
        virtual_params: Some(LIGHT_SWITCH_VIRTUAL_PARAMS),
        param_defaults: param_bytes,
        comm_objects: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECTS,
        comm_object_refs: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECT_REFS,
        union_fields: Some(LightSwitchParams::ETS_UNIONS),
        channel_name: "General",
        absolute_segment_address: None,
        system7_layout: None,
        application_hash: None,
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        page_layout: Some(page_layout),
        modules: None,
        baggages: None,
        translations: Some(LIGHT_SWITCH_TRANSLATIONS),
        bus_interfaces: None,
        additional_addresses_count: None,
        ip_config: None,
        is_secure_enabled: Some(true),
        max_security_individual_address_entries: Some(32),
        max_security_group_key_table_entries: Some(10),
        max_security_p2p_key_table_entries: Some(0),
    };

    // KNX-RF variant: same application logic as the others, but with the
    // RF mask version (`SystemBRf` / 0x27B0) so ETS files it under the RF
    // medium (MT-2). Pairs with the `stm32g0_knxrf_device` firmware.
    let app_rf = ApplicationProgramDef {
        name: "LightSwitch2RF",
        device: &DEVICE_DESCRIPTOR_RF,
        params: LightSwitchParams::ETS_PARAMS_EXT,
        virtual_params: Some(LIGHT_SWITCH_VIRTUAL_PARAMS),
        param_defaults: param_bytes,
        comm_objects: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECTS,
        comm_object_refs: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECT_REFS,
        union_fields: Some(LightSwitchParams::ETS_UNIONS),
        channel_name: "General",
        absolute_segment_address: None,
        system7_layout: None,
        application_hash: None,
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        page_layout: Some(LightSwitchDevice::page_layout()),
        modules: None,
        baggages: None,
        translations: Some(LIGHT_SWITCH_TRANSLATIONS),
        bus_interfaces: None,
        additional_addresses_count: None,
        ip_config: None,
        is_secure_enabled: None,
        max_security_individual_address_entries: None,
        max_security_group_key_table_entries: None,
        max_security_p2p_key_table_entries: None,
    };

    // Data Secure KNX-RF variant: the RF analogue of `app_tp1_secure`.
    // Same secure-capable declaration and table sizes, but on the RF mask
    // (`SystemBRf` / 0x27B0). No firmware implements it yet — the
    // definition exists so ETS can already see a secure RF product.
    let app_rf_secure = ApplicationProgramDef {
        name: "LightSwitch2RFSecure",
        device: &DEVICE_DESCRIPTOR_RF_SECURE,
        params: LightSwitchParams::ETS_PARAMS_EXT,
        virtual_params: Some(LIGHT_SWITCH_VIRTUAL_PARAMS),
        param_defaults: param_bytes,
        comm_objects: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECTS,
        comm_object_refs: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECT_REFS,
        union_fields: Some(LightSwitchParams::ETS_UNIONS),
        channel_name: "General",
        absolute_segment_address: None,
        system7_layout: None,
        application_hash: None,
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        page_layout: Some(LightSwitchDevice::page_layout()),
        modules: None,
        baggages: None,
        translations: Some(LIGHT_SWITCH_TRANSLATIONS),
        bus_interfaces: None,
        additional_addresses_count: None,
        ip_config: None,
        is_secure_enabled: Some(true),
        max_security_individual_address_entries: Some(32),
        max_security_group_key_table_entries: Some(10),
        max_security_p2p_key_table_entries: Some(0),
    };

    // Build a multi-device package: five application programs, five
    // hardware definitions (IP, TP1, TP1-Secure, RF, RF-Secure), and a
    // single catalog section with all five.
    let mut builder = KnxprodBuilder::new(LightSwitchDevice::MANUFACTURER_ID);
    let app_ip_ref = builder.application_program(&app_ip);
    let app_tp1_ref = builder.application_program(&app_tp1);
    let app_tp1_secure_ref = builder.application_program(&app_tp1_secure);
    let app_rf_ref = builder.application_program(&app_rf);
    let app_rf_secure_ref = builder.application_program(&app_rf_secure);

    let hw_ip_ref = builder.hardware(HardwareDef {
        serial_number: SERIAL_NUMBER_IP,
        hardware_version: 1,
        name: "2-Button Light Switch IP",
        bus_current: None,
        is_ip_enabled: Some(true),
        is_rf_retransmitter: None,
        rf_rx_capabilities: None,
        rf_tx_capabilities: None,
        products: vec![ProductDef {
            name: "Light Switch 2-fold (IP)",
            order_number: "LS-0002-IP",
            is_rail_mounted: false,
            visible_description: None,
        }],
        application_programs: vec![app_ip_ref],
    });

    let hw_tp1_ref = builder.hardware(HardwareDef {
        serial_number: SERIAL_NUMBER_TP1,
        hardware_version: 1,
        name: "2-Button Light Switch TP1",
        bus_current: Some(10),
        is_ip_enabled: None,
        is_rf_retransmitter: None,
        rf_rx_capabilities: None,
        rf_tx_capabilities: None,
        products: vec![ProductDef {
            name: "Light Switch 2-fold (TP1)",
            order_number: "LS-0002-TP",
            is_rail_mounted: false,
            visible_description: None,
        }],
        application_programs: vec![app_tp1_ref],
    });

    let hw_tp1_secure_ref = builder.hardware(HardwareDef {
        serial_number: SERIAL_NUMBER_TP1_SECURE,
        hardware_version: 1,
        name: "2-Button Light Switch TP1 Secure",
        bus_current: Some(10),
        is_ip_enabled: None,
        is_rf_retransmitter: None,
        rf_rx_capabilities: None,
        rf_tx_capabilities: None,
        products: vec![ProductDef {
            name: "Light Switch 2-fold (TP1, Secure)",
            order_number: "LS-0002-TP-SEC",
            is_rail_mounted: false,
            visible_description: None,
        }],
        application_programs: vec![app_tp1_secure_ref],
    });

    // The RF light switch is a battery/bus-less end device: not a
    // retransmitter, and a plain `Ready` capability class for both
    // directions — the SX1211 firmware uses standard KNX-RF timing.
    let hw_rf_ref = builder.hardware(HardwareDef {
        serial_number: SERIAL_NUMBER_RF,
        hardware_version: 1,
        name: "2-Button Light Switch RF",
        bus_current: None,
        is_ip_enabled: None,
        is_rf_retransmitter: Some(false),
        rf_rx_capabilities: Some(RfRxCapabilities::Ready),
        rf_tx_capabilities: Some(RfTxCapabilities::Ready),
        products: vec![ProductDef {
            name: "Light Switch 2-fold (RF)",
            order_number: "LS-0002-RF",
            is_rail_mounted: false,
            visible_description: None,
        }],
        application_programs: vec![app_rf_ref],
    });

    // Secure RF hardware: identical RF radio characteristics to `hw_rf_ref`,
    // linked to the secure-enabled RF application program.
    let hw_rf_secure_ref = builder.hardware(HardwareDef {
        serial_number: SERIAL_NUMBER_RF_SECURE,
        hardware_version: 1,
        name: "2-Button Light Switch RF Secure",
        bus_current: None,
        is_ip_enabled: None,
        is_rf_retransmitter: Some(false),
        rf_rx_capabilities: Some(RfRxCapabilities::Ready),
        rf_tx_capabilities: Some(RfTxCapabilities::Ready),
        products: vec![ProductDef {
            name: "Light Switch 2-fold (RF, Secure)",
            order_number: "LS-0002-RF-SEC",
            is_rail_mounted: false,
            visible_description: None,
        }],
        application_programs: vec![app_rf_secure_ref],
    });

    builder.catalog(CatalogSectionDef {
        name: "Push Buttons",
        entries: vec![
            CatalogEntryDef {
                name: "Light Switch 2-fold (IP)",
                hardware: hw_ip_ref,
                product_order_number: "LS-0002-IP",
                application_program: app_ip_ref,
            },
            CatalogEntryDef {
                name: "Light Switch 2-fold (TP1)",
                hardware: hw_tp1_ref,
                product_order_number: "LS-0002-TP",
                application_program: app_tp1_ref,
            },
            CatalogEntryDef {
                name: "Light Switch 2-fold (TP1, Secure)",
                hardware: hw_tp1_secure_ref,
                product_order_number: "LS-0002-TP-SEC",
                application_program: app_tp1_secure_ref,
            },
            CatalogEntryDef {
                name: "Light Switch 2-fold (RF)",
                hardware: hw_rf_ref,
                product_order_number: "LS-0002-RF",
                application_program: app_rf_ref,
            },
            CatalogEntryDef {
                name: "Light Switch 2-fold (RF, Secure)",
                hardware: hw_rf_secure_ref,
                product_order_number: "LS-0002-RF-SEC",
                application_program: app_rf_secure_ref,
            },
        ],
        subsections: vec![],
    });

    let generate_knxproj = env::args().any(|arg| arg == "--knxproj");
    let generate_knxprod = env::args().any(|arg| arg == "--knxprod");

    // Register device instances for knxproj generation. This must happen
    // before the builder is consumed by the chainable configuration methods.
    if generate_knxproj {
        builder.device_instance(DeviceInstanceDef {
            name: "2-Button Light Switch IP",
            hardware: hw_ip_ref,
            product_order_number: "LS-0002-IP",
            application_program: app_ip_ref,
        });
        builder.device_instance(DeviceInstanceDef {
            name: "2-Button Light Switch TP1",
            hardware: hw_tp1_ref,
            product_order_number: "LS-0002-TP",
            application_program: app_tp1_ref,
        });
        builder.device_instance(DeviceInstanceDef {
            name: "2-Button Light Switch TP1 Secure",
            hardware: hw_tp1_secure_ref,
            product_order_number: "LS-0002-TP-SEC",
            application_program: app_tp1_secure_ref,
        });
        builder.device_instance(DeviceInstanceDef {
            name: "2-Button Light Switch RF",
            hardware: hw_rf_ref,
            product_order_number: "LS-0002-RF",
            application_program: app_rf_ref,
        });
        builder.device_instance(DeviceInstanceDef {
            name: "2-Button Light Switch RF Secure",
            hardware: hw_rf_secure_ref,
            product_order_number: "LS-0002-RF-SEC",
            application_program: app_rf_secure_ref,
        });
    }

    let out_dir: PathBuf = ["out", "LightSwitch2"].iter().collect();
    let builder = builder.output_dir(&out_dir).schema_version(KnxSchemaVersion::V20);

    if generate_knxproj {
        let knxproj_path = builder
            .project_name("Test Project LightSwitch2fold")
            .master_data(MasterDataSource::Download)
            .write_knxproj()?;

        println!("Generated: {} ({} bytes)", knxproj_path.display(), std::fs::metadata(&knxproj_path)?.len());
    } else if generate_knxprod {
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
        println!("Tip: Use --knxprod or --knxproj flag for signed packages");
    }

    Ok(())
}
