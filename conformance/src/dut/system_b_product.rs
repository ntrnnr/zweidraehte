//! The conformance System B DUT's product file, generated in-process.
//!
//! The System B counterpart to [`super::system7_product`]: the plain
//! DUT (`conformance-dut-systemb`) exists only as `knx_stack_config!`, so the
//! configuration runner generates its product file from the same
//! constants and reads it back through the client's parser.
//!
//! The shape differs from System 7 in the way the two management
//! models differ. A System B product declares **relative** segments —
//! sizes without addresses, because the device allocates — and its
//! load procedures are `MergedProcedure` *fragments* that ETS splices
//! into the mask's own Load template at `LdCtrlMerge` points, rather
//! than one self-contained `ProductProcedure`.

use zweidraehte_ets_model::{EtsCommObjectDef, EtsCommObjectRefDef};
use zweidraehte_knxprod::{ApplicationProgramDef, KnxprodBuilder, SingleDeviceDef};

use super::systemb_stack::device_info;

/// The DUT's first four group objects, mirroring the `comm_objects`
/// block of the plain conformance config: wire ASAPs 1–4 at 1/4/8/8
/// bits with full communication flags.
///
/// The indexes here are **0-based logical** indexes: the generator
/// writes `Number = index + MaskFamily::com_object_start_index()`, and
/// System B starts at 1 because its RT7 table cannot express ASAP 0.
/// So 0..3 here become wire ASAPs 1..4 — which is what the DUT's own
/// `comm_objects` block numbers them. (System 7 starts at 0, so its
/// product file in `system7_product` uses the ASAPs directly.)
///
/// The fixture defines more (the BYTE3 set, the security objects);
/// four is enough to exercise a download and keeps the generated file
/// readable.
const COM_OBJECTS: &[EtsCommObjectDef] =
    &[com_object(0, "GO0", 1), com_object(1, "GO1", 4), com_object(2, "GO2", 8), com_object(3, "GO3", 8)];

/// `CE | TE | RE | WE | UE` in the device-side flag layout.
const ALL_FLAGS: u8 = 0b1101_1100;

const fn com_object(index: u16, name: &'static str, size_bits: u8) -> EtsCommObjectDef {
    EtsCommObjectDef {
        index,
        name,
        display_name: name,
        function_text: "conformance",
        dpt_main: if size_bits == 1 { 1 } else { 5 },
        dpt_sub: if size_bits == 1 { 1 } else { 10 },
        size_bits,
        default_flags: ALL_FLAGS,
        object_size_override: None,
        text_template: None,
    }
}

const COM_OBJECT_REFS: &[EtsCommObjectRefDef] = &[];

/// Generate the plain DUT's application program as MTXML.
pub fn generate_mtxml() -> Result<String, String> {
    generate_mtxml_for(false)
}

/// Generate the same application with the Data Secure profile enabled.
///
/// System B security is an application capability, not a different mask.
/// Keeping both variants here proves that the compiler selects security from
/// the product while retaining the ordinary 07B0 load procedure.
pub fn generate_secure_mtxml() -> Result<String, String> {
    generate_mtxml_for(true)
}

fn generate_mtxml_for(secure: bool) -> Result<String, String> {
    // No `system7_layout`: on System B the generator emits relative
    // segments and merge fragments instead of absolute segments and a
    // product procedure.
    let app = ApplicationProgramDef {
        name: if secure { "ConformanceSystemBSecure" } else { "ConformanceSystemB" },
        device: &device_info::DEVICE,
        params: &[],
        virtual_params: None,
        param_defaults: &[],
        comm_objects: COM_OBJECTS,
        comm_object_refs: COM_OBJECT_REFS,
        union_fields: None,
        channel_name: "Conformance",
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

    let output = KnxprodBuilder::single_device(SingleDeviceDef {
        app: &app,
        serial_number: device_info::DEVICE.hardware_type,
        hardware_version: 1,
        hardware_name: if secure { "Conformance Secure System B DUT" } else { "Conformance System B DUT" },
        product_name: if secure { "Conformance Secure System B DUT" } else { "Conformance System B DUT" },
        order_number: if secure { "CONF-07B0-SEC" } else { "CONF-07B0" },
        is_rail_mounted: false,
        catalog_section: "Conformance",
        is_ip_enabled: None,
        is_rf_retransmitter: None,
        rf_rx_capabilities: None,
        rf_tx_capabilities: None,
    })
    .generate_all()
    .map_err(|e| format!("generating the System B DUT product file: {e}"))?;

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

    /// What the generator actually emits for a System B product —
    /// relative segments and merge fragments, not absolute segments
    /// and a self-contained procedure.
    #[test]
    fn generates_a_merged_procedure_product() {
        let xml = generate_mtxml().expect("the DUT product file generates");
        let knx = zweidraehte_knxprod::parse_application_program(&xml).expect("it parses back");
        let program = &knx.manufacturer_data.manufacturer.application_programs.programs[0];

        assert_eq!(program.mask_version, "MV-07B0");
        assert_eq!(program.load_procedure_style, "MergedProcedure");

        // The 0-based logical indexes must come out as wire ASAPs 1-4,
        // matching the DUT's own group object numbering.
        let numbers: Vec<u16> = program
            .static_section
            .com_object_table
            .as_ref()
            .expect("a ComObjectTable")
            .objects
            .iter()
            .map(|o| o.number)
            .collect();
        assert_eq!(numbers, [1, 2, 3, 4], "System B adds its start index of 1 to the logical index");

        let code = program.static_section.code.as_ref().expect("a Code section");
        eprintln!("absolute segments: {}", code.absolute_segments.len());
        for seg in &code.relative_segments {
            eprintln!("relative segment {} lsm={} size={}", seg.id, seg.load_state_machine, seg.size);
        }
        for proc in &program.static_section.load_procedures.as_ref().expect("load procedures").procedures {
            eprintln!("fragment merge_id={:?}: {} controls", proc.merge_id, proc.controls.len());
            for c in &proc.controls {
                eprintln!("    {c:?}");
            }
        }
    }

    #[test]
    fn secure_variant_keeps_system_b_and_declares_capacities() {
        let product = zweidraehte_client::download::ProductData::from_mtxml_str(
            &generate_secure_mtxml().expect("secure product generates"),
        )
        .expect("secure product parses");
        assert_eq!(product.mask_version, Some(zweidraehte_proto::device::MaskVersion::SystemBTp1));
        assert!(product.is_secure_enabled);
        assert_eq!(product.max_security_group_key_table_entries, Some(18));
        assert_eq!(product.max_security_individual_address_entries, Some(8));
    }
}
