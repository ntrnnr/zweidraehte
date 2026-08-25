//! The conformance System 7 DUT's product file, generated in-process.
//!
//! The DUT exists only as the `system7_stack_config!` macro in
//! [`super::system7_stack`] — there is no `.knxprod` for it, because it
//! is a test fixture rather than a shipping product. But the client's
//! download engine takes its product layer from a real product file,
//! so the configuration runner generates one here, from the same
//! constants the DUT stack is built from, and reads it straight back.
//!
//! That closes a loop no unit test can:
//!
//! ```text
//!   system7_stack_config!  ──► this generator ──► MTXML
//!            │                                      │
//!            │                       ProductData (ets-files normalizes)
//!            ▼                                      ▼
//!     the running DUT  ◄────── download ◄─────  KnxBus
//! ```
//!
//! A disagreement anywhere — generator writing what the parser cannot
//! read, or either drifting from the device's actual memory map —
//! surfaces as a failed download rather than as a silently wrong file.

use zweidraehte_ets_model::{EtsCommObjectDef, EtsCommObjectRefDef};
use zweidraehte_knxprod::{
    ApplicationProgramDef, KnxprodBuilder, SingleDeviceDef, System7MemoryLayout, System7Segment,
};

use super::system7_stack::{AST_ADDRESS, COT_ADDRESS, device_info};

/// The DUT's group objects, mirroring the `comm_objects` block of
/// `System7ConformanceConfig` (see [`super::system7_stack`]): ASAPs
/// 1–7, sizes 1/4/7/7/7/7/1 bits, full communication flags.
///
/// The size codes there are the raw octets the macro stores; here they
/// are expressed as ETS bit widths, which is what an MTXML `ObjectSize`
/// spells out.
const COM_OBJECTS: &[EtsCommObjectDef] = &[
    com_object(1, "GO0", 1),
    com_object(2, "GO1", 4),
    com_object(3, "GO2", 8),
    com_object(4, "GO3", 8),
    com_object(5, "GO4", 8),
    com_object(6, "GO5", 8),
    com_object(7, "GO6", 1),
];

/// All flags enabled — `CE | TE | RE | WE | UE`, the DUT's
/// configuration for every object.
const ALL_FLAGS: u8 = 0b1101_1100;

const fn com_object(index: u16, name: &'static str, size_bits: u8) -> EtsCommObjectDef {
    EtsCommObjectDef {
        index,
        name,
        display_name: name,
        function_text: "conformance",
        // DPT 1.001 for the 1-bit objects, 5.010 for the wider ones —
        // the DUT does not act on datapoint types, but MTXML requires
        // one and ETS uses it to pick an object size.
        dpt_main: if size_bits == 1 { 1 } else { 5 },
        dpt_sub: if size_bits == 1 { 1 } else { 10 },
        size_bits,
        default_flags: ALL_FLAGS,
        object_size_override: None,
        text_template: None,
    }
}

const COM_OBJECT_REFS: &[EtsCommObjectRefDef] = &[];

/// Generate the DUT's application program as MTXML.
///
/// Segment sizes come from the same `System7ConformanceConfig`
/// constants that size the device's tables, so the product file cannot
/// claim a capacity the DUT does not have.
pub fn generate_mtxml() -> Result<String, String> {
    generate_mtxml_for(false)
}

/// Generate the full-stack System 7 fixture with Data Secure declared.
///
/// The secure composition has a larger backing table, but this small product
/// intentionally uses the same seven application objects as the plain DUT.
/// Security IO capacity is independent of the chosen application roster.
pub fn generate_secure_mtxml() -> Result<String, String> {
    generate_mtxml_for(true)
}

fn generate_mtxml_for(secure: bool) -> Result<String, String> {
    let device = if secure { &super::system7_secure_stack::device_info::DEVICE } else { &device_info::DEVICE };
    let (adt_size, ast_size, cot_size) = if secure {
        (
            super::system7_secure_stack::table_sizes::ADT,
            super::system7_secure_stack::table_sizes::AST,
            super::system7_secure_stack::table_sizes::COT,
        )
    } else {
        (
            super::system7_stack::table_sizes::ADT,
            super::system7_stack::table_sizes::AST,
            super::system7_stack::table_sizes::COT,
        )
    };

    let layout = System7MemoryLayout {
        segments: vec![
            System7Segment {
                name: "4000",
                address: 0x4000,
                size: adt_size as u32,
                memory_type: Some("EEPROM"),
                data: None,
                mask: None,
            },
            System7Segment {
                name: "4100",
                address: AST_ADDRESS,
                size: ast_size as u32,
                memory_type: Some("EEPROM"),
                data: None,
                mask: None,
            },
            System7Segment {
                name: "4200",
                address: COT_ADDRESS,
                size: cot_size as u32,
                memory_type: Some("EEPROM"),
                data: None,
                mask: None,
            },
        ],
        address_table_segment: "4000",
        association_table_segment: "4100",
        address_table_offset: 0,
        association_table_offset: 0,
        address_table_max_entries: device.max_address_table_entries,
        association_table_max_entries: device.max_association_table_entries,
        // The identity guard the generated procedure emits: the DUT's
        // PID_HARDWARE_TYPE, which its snapshot reports.
        serial_number: device.hardware_type,
    };

    // The DUT has no ETS-visible parameters — it is configured by the
    // macro, not by a project — so the parameter segment the shipping
    // products carry is absent here.
    let app = ApplicationProgramDef {
        name: if secure { "ConformanceSystem7Secure" } else { "ConformanceSystem7" },
        device,
        params: &[],
        virtual_params: None,
        param_defaults: &[],
        comm_objects: COM_OBJECTS,
        comm_object_refs: COM_OBJECT_REFS,
        union_fields: None,
        channel_name: "Conformance",
        absolute_segment_address: None,
        bcu2_layout: None,
        system7_layout: Some(layout),
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
        is_secure_enabled: secure.then_some(true),
        max_user_entries: None,
        max_tunneling_user_entries: None,
        max_security_group_key_table_entries: secure.then_some(18),
        max_security_individual_address_entries: secure.then_some(8),
        max_security_p2p_key_table_entries: secure.then_some(8),
    };

    // A full package needs hardware and catalogue entries; the
    // single-device builder supplies them from the one device. Only
    // the application program is read back — the download does not
    // care about catalogue metadata — but generating the whole thing
    // exercises the same path a real product goes through.
    let output = KnxprodBuilder::single_device(SingleDeviceDef {
        app: &app,
        serial_number: device.hardware_type,
        hardware_version: 1,
        hardware_name: if secure { "Conformance Secure System 7 DUT" } else { "Conformance System 7 DUT" },
        product_name: if secure { "Conformance Secure System 7 DUT" } else { "Conformance System 7 DUT" },
        order_number: if secure { "CONF-0705-SEC" } else { "CONF-0705" },
        is_rail_mounted: false,
        catalog_section: "Conformance",
        is_ip_enabled: None,
        is_rf_retransmitter: None,
        rf_rx_capabilities: None,
        rf_tx_capabilities: None,
    })
    .generate_all()
    .map_err(|e| format!("generating the DUT product file: {e}"))?;

    output
        .application_programs
        .into_iter()
        .next()
        .map(|(_, xml)| xml)
        .ok_or_else(|| "the generator produced no application program".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_variant_uses_the_secure_hardware_identity() {
        let product = zweidraehte_ets_files::product::ProductData::from_mtxml_str(
            &generate_secure_mtxml().expect("secure product generates"),
        )
        .expect("secure product parses");
        assert_eq!(product.mask_version(), Some(zweidraehte_proto::device::MaskVersion::System7Tp1));
        assert!(product.supports_data_secure());
        assert_eq!(product.max_security_group_key_table_entries(), Some(18));
        assert_eq!(product.address_table_max_entries(), Some(254));
    }
}
