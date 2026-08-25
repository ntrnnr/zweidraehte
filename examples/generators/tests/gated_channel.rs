//! Round trip for choose-gated channels: generate the demo System B
//! device's MTXML in memory, parse it back with the runtime parser,
//! and assert the gated Diagnostics tab obeys ETS semantics — present
//! in the channel roster, its contents hidden until the gate parameter
//! is set. This pins generator ↔ runtime agreement on the ETS6 idiom
//! (`choose` directly under `Dynamic` with the `Channel` in a `when`)
//! without any licensed vendor data.

use const_default::ConstDefault;
use devices::system_b_demo::{DEVICE_DESCRIPTOR, DemoParams, SERIAL_NUMBER, SystemBDemoDevice, comm_objs};
use zweidraehte_ets_files::runtime::model::ParameterValue;
use zweidraehte_ets_files::signing::KnxSchemaVersion;
use zweidraehte_ets_files::{Device, parse_application_program};
use zweidraehte_knxprod::definition::page_layout::EtsPageLayout;
use zweidraehte_knxprod::{ApplicationProgramDef, KnxprodBuilder, SingleDeviceDef};

#[test]
fn gated_channel_round_trips_through_generated_mtxml() {
    // The same definition gen_mtxml uses, generated in memory.
    let defaults = DemoParams::DEFAULT;
    let param_bytes = zweidraehte_generators::params_as_bytes(&defaults);

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
        absolute_segment_address: None,
        system7_layout: None,
        bcu2_layout: None,
        application_hash: None,
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        page_layout: Some(SystemBDemoDevice::page_layout()),
        modules: None,
        baggages: None,
        translations: None,
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
    .schema_version(KnxSchemaVersion::V20);

    let output = builder.generate_all().expect("the demo device generates");
    let xml = output
        .xml_files()
        .into_iter()
        .find(|(name, _)| name == "ApplicationProgram1.mtxml")
        .expect("an application program is generated")
        .1
        .to_string();

    let knx = parse_application_program(&xml).expect("our own output parses");
    let program =
        knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next().expect("one program");
    let mut device = Device::new(program, None);

    // The roster sees the gated channel regardless of visibility.
    let channel_texts: Vec<String> =
        device.program().dynamic.as_ref().expect("dynamic").all_channels().iter().map(|c| c.name.clone()).collect();
    assert_eq!(channel_texts, ["Outputs", "Diagnostics"]);

    // Resolve the two parameters by name, as the ids are generated.
    let param_id = |device: &Device, name: &str| -> String {
        use zweidraehte_ets_files::schema::ParameterItem;
        let params = device.program().static_section.parameters.as_ref().expect("parameters");
        params
            .items
            .iter()
            .find_map(|item| match item {
                ParameterItem::Parameter(p) if p.name == name => Some(p.id.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("parameter {name} exists"))
    };
    let gate_id = param_id(&device, "show_diagnostics");
    let heartbeat_id = param_id(&device, "heartbeat_interval");

    let heartbeat_visible = |device: &Device| device.visible_param_refs().any(|r| r.ref_id == heartbeat_id);

    // Factory default: the gate is 0, the tab's contents are hidden.
    assert!(!heartbeat_visible(&device), "the Diagnostics content must start hidden");

    // Enable the page: the gated channel's contents appear.
    device.set_parameter_value(&gate_id, ParameterValue::Integer(1));
    assert!(heartbeat_visible(&device), "setting the gate must surface the Diagnostics content");

    // And disappear again when disabled.
    device.set_parameter_value(&gate_id, ParameterValue::Integer(0));
    assert!(!heartbeat_visible(&device));
}
