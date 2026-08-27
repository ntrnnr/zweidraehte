//! The micro-System-7 DUT's product file, generated in-process.
//!
//! Same round-trip idea as [`super::system7_product`]: the product
//! layer the client's download engine consumes is generated from the
//! very definition the DUT boots from, so generator, parser, and
//! device cannot drift apart. The full-fat System 7 DUT already proved
//! this path through `KnxprodBuilder`'s `System7MemoryLayout`; the
//! micro DUT reuses it with its own (much smaller) capacities and the
//! micro fixture's segment placement.

use zweidraehte_ets_model::{EtsCommObjectDef, EtsCommObjectRefDef};
use zweidraehte_knxprod::{
    ApplicationProgramDef, KnxprodBuilder, SingleDeviceDef, System7MemoryLayout, System7Segment,
};
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};

use super::micro_system7_stack::{self, MicroSystem7DutFamily};
use zweidraehte_microdevice::family::MicroDeviceFamily;

/// The DUT's device descriptor, from the fixture's definition. The
/// table capacities are the conformance image's (14/18/12), not the mask
/// maxima — the product file must not claim capacity the DUT's 1 KiB backing
/// does not have. The downloadable product uses seven of those object slots;
/// the remaining four non-spare slots belong to the Management fixture.
fn device_descriptor() -> DeviceDescriptor {
    let def = micro_system7_stack::definition();
    DeviceDescriptor {
        mask_version: MaskVersion::System7Tp1,
        manufacturer_id: def.manufacturer_id,
        hardware_type: micro_system7_stack::HARDWARE_TYPE,
        application_id: def.device_type,
        application_version: def.version,
        max_address_table_entries: u16::from(def.max_group_addresses),
        max_association_table_entries: u16::from(def.max_associations),
        max_com_objects: def.comm_objects.len() as u16,
        pei_type: 0,
    }
}

/// The DUT's group objects as ETS sees them: the same seven-object
/// roster the full-fat System 7 DUT's product declares (numbers 1..=7,
/// System 7 slot 0 spare), so both products drive the same fixture
/// shape.
const COM_OBJECTS: &[EtsCommObjectDef] = &[
    com_object(1, "GO0", 1, ALL_FLAGS),
    com_object(2, "GO1", 4, ALL_FLAGS),
    com_object(3, "GO2", 8, ALL_FLAGS),
    com_object(4, "GO3", 8, ALL_FLAGS),
    com_object(5, "GO4", 8, ALL_FLAGS),
    com_object(6, "GO5", 8, ALL_FLAGS),
    com_object(7, "GO6", 1, ALL_FLAGS),
];

/// `CE | TE | RE | WE | UE` — the fixture's all-flags objects.
const ALL_FLAGS: u8 = 0b1101_1100;

const fn com_object(index: u16, name: &'static str, size_bits: u8, flags: u8) -> EtsCommObjectDef {
    EtsCommObjectDef {
        index,
        name,
        display_name: name,
        function_text: "conformance",
        // DPT 1.001 for the 1-bit objects, 5.010 for the wider ones —
        // the DUT does not act on datapoint types, but MTXML requires
        // one.
        dpt_main: if size_bits == 1 { 1 } else { 5 },
        dpt_sub: if size_bits == 1 { 1 } else { 10 },
        size_bits,
        default_flags: flags,
        object_size_override: None,
        text_template: None,
    }
}

const COM_OBJECT_REFS: &[EtsCommObjectRefDef] = &[];

/// Generate the DUT's application program as MTXML.
pub fn generate_mtxml() -> Result<String, String> {
    generate_mtxml_for(false)
}

/// Generate the same micro System 7 fixture with Data Secure declared.
///
/// Security is a profile module: mask, RT8 layout, application tables and
/// product identity remain identical. Only the secure capability and bounded
/// Security IO table capacities differ.
pub fn generate_secure_mtxml() -> Result<String, String> {
    generate_mtxml_for(true)
}

fn generate_mtxml_for(secure: bool) -> Result<String, String> {
    let def = micro_system7_stack::definition();
    let device = device_descriptor();
    let base = MicroSystem7DutFamily::EEPROM_BASE as u32;

    // Segment sizes from the definition's capacities, placement from
    // the fixture — the same numbers `build_eeprom` lays down.
    let adt_size = 3 + u32::from(def.max_group_addresses) * 2;
    let ast_size = 1 + u32::from(def.max_associations) * 2;
    let cot_size = 3 + def.comm_objects.len() as u32 * 4;
    let layout = System7MemoryLayout {
        segments: vec![
            System7Segment {
                name: "4000",
                address: base,
                size: adt_size,
                memory_type: Some("EEPROM"),
                data: None,
                mask: None,
            },
            System7Segment {
                name: "4100",
                address: base + def.ast_offset as u32,
                size: ast_size,
                memory_type: Some("EEPROM"),
                data: None,
                mask: None,
            },
            System7Segment {
                name: "4200",
                address: 0x4200,
                size: cot_size,
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
        // PID_HARDWARE_TYPE.
        serial_number: micro_system7_stack::HARDWARE_TYPE,
    };

    let app = ApplicationProgramDef {
        name: if secure { "ConformanceMicroSystem7Secure" } else { "ConformanceMicroSystem7" },
        device: &device,
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
        max_security_group_key_table_entries: secure.then_some(8),
        max_security_individual_address_entries: secure.then_some(8),
        max_security_p2p_key_table_entries: secure.then_some(0),
    };

    let output = KnxprodBuilder::single_device(SingleDeviceDef {
        app: &app,
        serial_number: micro_system7_stack::HARDWARE_TYPE,
        hardware_version: 1,
        hardware_name: if secure { "Conformance Secure Micro System 7 DUT" } else { "Conformance Micro System 7 DUT" },
        product_name: if secure { "Conformance Secure Micro System 7 DUT" } else { "Conformance Micro System 7 DUT" },
        order_number: if secure { "CONF-M0705-SEC" } else { "CONF-M0705" },
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
