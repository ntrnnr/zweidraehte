//! Configuration-download conformance runner.
//!
//! The third runner besides `conformance-runner` (hand-written suites)
//! and `conformance-eitt` (vendor XML templates): where those two
//! drive the DUT with scripted telegrams, this one runs the **real
//! `zweidraehte-client` library** — `KnxBus`, `DeviceConnection`, the
//! download engine — against the System 7 and System B DUTs through
//! the [`client_bridge`]. The scenarios are the end-to-end tier for
//! the ETS-style configuration download (roadmap items 4 + 5):
//! from-zero addressing, full download, re-download, unload, error
//! paths — each family driving its own load-control path.
//!
//! Preferred workspace command:
//!   cargo xtask conformance configuration [filter...]
//!
//! Direct runner invocation, after building every conformance binary:
//!   cargo run -p zweidraehte-conformance --bin conformance-configuration [filter...]
//!
//! Arguments:
//!   filter      Optional case-insensitive substring filters on
//!               scenario names.
//!
//! Environment:
//!   RUST_LOG    Log level (error, warn, info, debug, trace)
//!   LIVE_LOGS   Print logs in real time instead of buffering
//!
//! The DUT always runs with spec-true timeouts (`KNX_TIME_DIVISOR=1`):
//! the client library on the other side uses real spec timers, so a
//! time-scaled DUT would disconnect mid-procedure.

use std::env;
use std::process::ExitCode;
use std::time::Duration;

use log::LevelFilter;

use zweidraehte_client::download::{
    DeviceImage, DownloadScope, Downloader, GroupLink, GroupObjectProtection, GroupObjectSecurity, Instruction,
    LoadControlPath, LoweredDeviceConfiguration, LsmTarget, MaskDb, MemoryResources, ParameterValue, ProcedureKind,
    ProjectConfig, SecurityConfig as DownloadSecurityConfig, assemble, compile,
};
use zweidraehte_client::{
    AddressingMode, BatchSelection, ConnectorInfo, DeviceConnection, DeviceProgrammer, Error as ClientError,
    GroupAddress, GroupService, GroupValueEncoding, IndividualAddress, InterfaceObjectType, KnxBus, MachineRef,
    MaskVersion, ProgrammingOptions, ProgrammingReport, ProgrammingRequest, ProgrammingScope, ProjectPlanRequest,
    ProjectProduct, ProjectProgrammer, SecurityEntry,
};
use zweidraehte_conformance::dut::fixture_common::SECURE_FDSK;
use zweidraehte_conformance::dut::{
    bcu1_product, bcu1_stack, bcu2_light_switch_product, bcu2_product, bcu2_stack, micro_system7_product,
    micro_system7_stack, system_b_product, system7_product, system7_stack, systemb_stack,
};
use zweidraehte_conformance::harness::client_bridge::{self, DutControl};
use zweidraehte_conformance::harness::{ChildLifecycle, DutMode};
use zweidraehte_conformance::logger;
use zweidraehte_ets_files::keyring::{Keyring, KeyringDevice, KeyringInterface, KeyringInterfaceType};
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_project::{
    AuthoredProject, KeyEncoding, KeyEpoch, KeyId, KeyKind, KeyMaterialSource, KeyMetadata, KeyOrigin, KeyRecord,
    KeyScope, KeyState, KeyStoreError, ProjectDeviceId, SecretBytes,
};
use zweidraehte_proto::messages::apdu::load_control::{AbsSegment, LoadEvent, LoadState, LsmMachine, RelSegment};
use zweidraehte_proto::pid;

// ============================================================================
// DUT constants (see conformance/src/dut/system7_stack.rs)
// ============================================================================

/// The DUT's snapshot identity (BDUT).
fn dut_ia() -> IndividualAddress {
    IndividualAddress::new(1, 0, 1)
}

/// The bus address this runner's client sends from (EDI, 10.15.254).
fn tester_ia() -> IndividualAddress {
    IndividualAddress::new(10, 15, 254)
}

fn default_configuration(product: &ProductData, project: &ProjectConfig) -> LoweredDeviceConfiguration {
    LoweredDeviceConfiguration::from_product_defaults(project.clone(), product)
}

/// The mask layer, resolved the way the library does it: an explicit
/// `KNX_MASTER_DATA`, else the cache/download.
///
/// The licensed `knx_master.xml` is not in this repository, so a clean
/// machine needs one of those — the error says which.
fn mask_db() -> Result<MaskDb, String> {
    MaskDb::resolve().map_err(|e| format!("{e}"))
}

/// The DUT's memory resources, read out of the mask like everything
/// else — no constants in this runner.
fn dut_resources(masks: &MaskDb) -> Result<MemoryResources, String> {
    masks
        .mask(MaskVersion::System7Tp1)
        .ok_or_else(|| "the master data does not describe MV-0705".to_string())?
        .memory_resources()
        .ok_or_else(|| "MV-0705 is not memory-mapped in this master data".to_string())
}

// ============================================================================
// Entry point
// ============================================================================

#[tokio::main]
async fn main() -> ExitCode {
    let filters: Vec<String> = env::args().skip(1).map(|f| f.to_lowercase()).collect();

    let log_level = match env::var("RUST_LOG").ok().as_deref() {
        Some("error") => LevelFilter::Error,
        Some("warn") => LevelFilter::Warn,
        Some("info") => LevelFilter::Info,
        Some("debug") => LevelFilter::Debug,
        Some("trace") => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };
    let live_logs = env::var("LIVE_LOGS").is_ok();
    logger::init(log_level, live_logs);

    // Spec-true DUT timers; see the module docs.
    // SAFETY: single-threaded at this point, before the child spawns.
    unsafe { env::set_var("KNX_TIME_DIVISOR", "1") };

    println!("╔═════════════════════════════════════════════════════════════╗");
    println!("║           KNX Configuration Download Test Runner            ║");
    println!("╚═════════════════════════════════════════════════════════════╝\n");

    // ------------------------------------------------------------------
    // Scenarios are grouped by device family: each group brings up its
    // own DUT and its own bus, because the two families are different
    // devices with different masks. Each scenario starts from a
    // factory-fresh DUT (full reset) and must close every connection
    // it opens — a leaked TL connection would wedge the
    // single-connection client.
    // ------------------------------------------------------------------
    type ScenarioGroup = (&'static str, DutMode, &'static [(&'static str, Scenario)]);
    let groups: &[ScenarioGroup] = &[
        ("BCU1 (mask 0012)", DutMode::Bcu1, &[(
            "BCU1 programming-button download through DeviceProgrammer",
            scenario_bcu1_programmer_download,
        )]),
        ("System 7 (mask 0705)", DutMode::System7, &[
            ("device descriptor smoke read", scenario_system7_descriptor),
            ("programming-mode individual addressing", scenario_system7_programming_mode_addressing),
            ("full download rewires the device", scenario_system7_full_download),
            ("unload-all declares the tables invalid", scenario_system7_unload_all),
            ("oversized segment allocation fails typed", scenario_system7_oversized_segment),
        ]),
        ("System 7 (mask 0705, Data Secure capable)", DutMode::System7Secure, &[(
            "secure System 7 commissioning through DeviceProgrammer",
            scenario_system7_secure_programmer,
        )]),
        ("BCU2 (mask 0020)", DutMode::Bcu2, &[
            ("BCU2 descriptor smoke read", scenario_bcu2_descriptor),
            ("BCU2 mandatory configuration properties", scenario_bcu2_required_properties),
            ("BCU2 programming-mode individual addressing", scenario_bcu2_programming_mode_addressing),
            ("BCU2 download over the property path", scenario_bcu2_full_download),
            ("BCU2 light-switch product download with parameters", scenario_bcu2_light_switch_download),
            ("BCU2 unload-all invalidates the tables", scenario_bcu2_unload_all),
        ]),
        ("BCU2 (mask 0021, Data Secure capable)", DutMode::Bcu2Secure, &[
            ("BCU2 0021 descriptor smoke read", scenario_bcu2_0021_descriptor),
            ("BCU2 0021 programming-mode individual addressing", scenario_bcu2_programming_mode_addressing),
            ("BCU2 0021 plain download over the property path", scenario_bcu2_0021_full_download),
            ("BCU2 0021 plain light-switch download with parameters", scenario_bcu2_0021_light_switch_download),
            ("BCU2 0021 unload-all invalidates the tables", scenario_bcu2_0021_unload_all),
            ("BCU2 0021 low-level secure table and group regression", scenario_bcu2_secure_commission),
        ]),
        ("BCU2 (mask 0021, DeviceProgrammer isolation)", DutMode::Bcu2Secure, &[(
            "BCU2 0021 secure commissioning through DeviceProgrammer",
            scenario_bcu2_secure_programmer,
        )]),
        ("Micro System 7 (mask 0705, micro stack)", DutMode::MicroSystem7, &[
            ("micro-S7 descriptor smoke read", scenario_micro_s7_descriptor),
            ("micro-S7 programming-mode individual addressing", scenario_micro_s7_programming_mode_addressing),
            ("micro-S7 download over the property path", scenario_micro_s7_full_download),
            ("micro-S7 unload-all over the memory window", scenario_micro_s7_unload_all),
            ("micro-S7 oversized segment allocation fails typed", scenario_micro_s7_oversized_segment),
        ]),
        ("Micro System 7 (mask 0705, Data Secure capable)", DutMode::MicroSystem7Secure, &[
            ("micro-S7 secure composition descriptor in plain mode", scenario_micro_s7_secure_plain_descriptor),
            (
                "micro-S7 secure composition individual addressing in plain mode",
                scenario_micro_s7_secure_plain_addressing,
            ),
            ("micro-S7 secure composition plain download", scenario_micro_s7_secure_plain_download),
            ("micro-S7 secure composition plain unload", scenario_micro_s7_secure_plain_unload),
            ("micro-S7 secure composition oversized allocation fails typed", scenario_micro_s7_secure_plain_oversized),
            ("micro-S7 low-level secure persistence and group regression", scenario_micro_s7_secure_commission),
        ]),
        ("Micro System 7 (DeviceProgrammer isolation)", DutMode::MicroSystem7Secure, &[(
            "micro-S7 secure commissioning through DeviceProgrammer",
            scenario_micro_s7_secure_programmer,
        )]),
        ("System B (mask 07B0)", DutMode::SystemB, &[
            ("system B descriptor smoke read", scenario_system_b_descriptor),
            ("system B download over the property path", scenario_system_b_full_download),
            ("system B unload-all via the property path", scenario_system_b_unload_all),
            ("system B oversized relative allocation fails typed", scenario_system_b_oversized_segment),
            ("system B re-download without factory reset", scenario_system_b_redownload),
        ]),
        ("System B (mask 07B0, Data Secure capable)", DutMode::SystemBSecure, &[(
            "secure System B commissioning through DeviceProgrammer",
            scenario_system_b_secure_programmer,
        )]),
    ];

    let mut passed = 0usize;
    let mut failed = 0usize;

    for (group_name, dut_mode, scenarios) in groups {
        let selected: Vec<_> = scenarios
            .iter()
            .filter(|(name, _)| filters.is_empty() || filters.iter().any(|f| name.to_lowercase().contains(f)))
            .collect();
        if selected.is_empty() {
            continue;
        }

        println!("── {group_name}");

        let mut lifecycle = match ChildLifecycle::new(*dut_mode) {
            Ok(lifecycle) => lifecycle,
            Err(e) => {
                eprintln!("failed to set up the {group_name} DUT lifecycle: {e}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(e) = lifecycle.spawn_and_wait_roi().await {
            eprintln!("failed to spawn the {group_name} DUT: {e}");
            return ExitCode::FAILURE;
        }

        let (connector, control) = client_bridge::spawn(lifecycle);
        let bus = KnxBus::with_connector(connector, ConnectorInfo { assigned_address: tester_ia(), max_apdu: 254 });

        for (name, scenario) in selected {
            print!("• {name} ... ");
            logger::start_test(name);
            if let Err(e) = control.full_reset().await {
                println!("FAIL (DUT reset: {e})");
                logger::end_test();
                failed += 1;
                continue;
            }
            match scenario(&bus, &control).await {
                Ok(()) => {
                    println!("PASS");
                    logger::end_test();
                    passed += 1;
                }
                Err(e) => {
                    println!("FAIL\n    {e}");
                    logger::print_logs(&logger::end_test(), "    ");
                    failed += 1;
                }
            }
        }

        let _ = bus.disconnect().await;
        println!();
    }

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  {passed} passed, {failed} failed");
    println!("═══════════════════════════════════════════════════════════════");
    if failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

type Scenario =
    for<'a> fn(&'a KnxBus, &'a DutControl) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>>;

/// Best-effort close that never masks the scenario's own error.
async fn close_quietly(conn: DeviceConnection) {
    let _ = conn.close().await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecureFixtureKeySources {
    Direct,
    KeyringOnly,
    MatchingProjectAndKeyring,
    RejectedConflictThenKeyring,
}

fn fixture_keyring(serial_number: [u8; 6], group: GroupAddress, tool_key: [u8; 16], group_key: [u8; 16]) -> Keyring {
    let raw_group = u16::from_be_bytes(group.0);
    Keyring::new("configuration conformance".to_string(), "zweidraehte".to_string(), "2026-08-24T00:00:00Z".to_string())
        .with_interfaces(vec![
            KeyringInterface::new(KeyringInterfaceType::Usb, tester_ia())
                .with_group_addresses(vec![(raw_group, vec![tester_ia()])]),
        ])
        .with_group_keys([(raw_group, group_key)].into_iter().collect())
        .with_devices(vec![
            KeyringDevice::new(dut_ia())
                .with_tool_key(Some(tool_key))
                .with_fdsk(Some(SECURE_FDSK))
                .with_serial(Some(serial_number)),
        ])
}

#[derive(Default)]
struct FixtureKeySource {
    values: std::collections::BTreeMap<KeyId, [u8; 16]>,
}

impl FixtureKeySource {
    fn secure(tool_key: [u8; 16], group_key: [u8; 16]) -> Self {
        Self {
            values: [
                (KeyId { scope: KeyScope::Device("dut".into()), kind: KeyKind::Fdsk }, SECURE_FDSK),
                (KeyId { scope: KeyScope::Device("dut".into()), kind: KeyKind::ToolKey }, tool_key),
                (KeyId { scope: KeyScope::Group("test".into()), kind: KeyKind::GroupKey }, group_key),
            ]
            .into_iter()
            .collect(),
        }
    }
}

impl KeyMaterialSource for FixtureKeySource {
    fn list(&self) -> Result<Vec<KeyMetadata>, KeyStoreError> {
        self.values.iter().map(|(id, value)| Ok(fixture_key_record(id.clone(), *value).metadata)).collect()
    }

    fn read(&self, id: &KeyId, _epoch: Option<KeyEpoch>) -> Result<Option<KeyRecord>, KeyStoreError> {
        Ok(self.values.get(id).map(|value| fixture_key_record(id.clone(), *value)))
    }
}

fn fixture_key_record(id: KeyId, value: [u8; 16]) -> KeyRecord {
    let value = SecretBytes::new(value);
    KeyRecord {
        metadata: KeyMetadata {
            id,
            epoch: None,
            origin: KeyOrigin::Manual,
            encoding: KeyEncoding::Binary,
            state: KeyState::Active,
            fingerprint: value.fingerprint(),
        },
        value,
        embedded_serial: None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn program_plain_project_fixture(
    bus: &KnxBus,
    masks: &MaskDb,
    mtxml: &str,
    desired_address: IndividualAddress,
    serial_number: Option<[u8; 6]>,
    group: GroupAddress,
    dpt: &str,
    com_object: u16,
    max_apdu: u16,
    addressing: AddressingMode,
) -> Result<ProgrammingReport, String> {
    let knx = zweidraehte_ets_files::runtime::parser::parse_application_program(mtxml)
        .map_err(|error| format!("parsing plain fixture MTXML: {error}"))?;
    let program = knx
        .manufacturer_data
        .manufacturer
        .application_programs
        .programs
        .into_iter()
        .next()
        .ok_or_else(|| "plain fixture MTXML has no application program".to_string())?;
    let product =
        ProductData::from_program(&program).map_err(|error| format!("extracting plain fixture product: {error}"))?;
    let serial = serial_number
        .map(|serial| format!("\n            serial \"{}\"", zweidraehte_project::format_serial(&serial)))
        .unwrap_or_default();
    let source = format!(
        r#"ga test = {group}
net test : {dpt} {{ security plain }}
area {} conformance {{
    line {} main {{
        medium tp1
        device dut {{
            product local:"fixture.mtxml"
            address {desired_address}{serial}
            max_apdu {max_apdu}
            object {com_object} {{ on test }}
        }}
    }}
}}
"#,
        desired_address.area(),
        desired_address.line(),
    );
    let authored = AuthoredProject::parse(source).map_err(|error| format!("parsing plain fixture project: {error}"))?;
    let id = ProjectDeviceId("dut".into());
    let products = [(id.clone(), ProjectProduct { program, product })].into_iter().collect();
    let plan = ProjectProgrammer::new()
        .plan(ProjectPlanRequest {
            project: &authored,
            state: None,
            selected: std::slice::from_ref(&id),
            selection: BatchSelection::Selected { include_affected: true, force_single: false },
            products: &products,
            keys: &FixtureKeySource::default(),
            keyring: None,
            scope: ProgrammingScope::AddressAndApplication,
        })
        .map_err(|error| format!("planning plain project fixture: {error}"))?;
    let planned = plan.devices.into_iter().next().ok_or_else(|| "plain project plan is empty".to_string())?;
    DeviceProgrammer::new()
        .program(
            bus,
            masks,
            ProgrammingRequest::new(planned.product, planned.configuration, planned.key_material)
                .with_download_scope(DownloadScope::Full)
                .with_options(ProgrammingOptions {
                    addressing,
                    scan_window: Duration::from_millis(150),
                    restart_delay: Duration::from_millis(50),
                    ..ProgrammingOptions::default()
                }),
            None,
        )
        .await
        .map_err(|error| format!("plain project programming pipeline: {error}"))
}

fn scenario_bcu1_programmer_download<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let desired = IndividualAddress::new(1, 0, 55);
        let group = GroupAddress::from_three_level(3, 1, 1);
        let masks = mask_db()?;
        control.set_programming_mode(true).await.map_err(|error| format!("prog mode on: {error}"))?;
        let report = program_plain_project_fixture(
            bus,
            &masks,
            &bcu1_product::generate_mtxml(),
            desired,
            Some(bcu1_stack::SERIAL_NUMBER),
            group,
            "1.001",
            1,
            15,
            AddressingMode::ProgrammingButton,
        )
        .await?;
        if report.device_mask != MaskVersion::Bcu1Tp1 || report.load_control_path != LoadControlPath::Direct {
            return Err(format!(
                "unexpected programming report: mask {:?}, path {:?}",
                report.device_mask, report.load_control_path
            ));
        }
        if !report.address_assignment.is_some_and(|assignment| assignment.changed) {
            return Err("the programming-button assignment did not move the BCU1".to_string());
        }

        let mut connection = bus.connect_device(desired).await.map_err(|error| format!("reconnect: {error}"))?;
        let association_offset = 0x0100 + definition_offset(bcu1_stack::definition().assoc_table_offset())?;
        let association = connection
            .memory_read(association_offset, 5)
            .await
            .map_err(|error| format!("association table: {error}"))?;
        close_quietly(connection).await;
        if association != [2, 0xFE, 0, 1, 1] {
            return Err(format!(
                "association table {association:02X?}, expected the unused-object placeholder and TSAP 1 -> ASAP 1"
            ));
        }

        let mut events = bus.group_events();
        control.trigger_group_write(1).await.map_err(|error| format!("trigger: {error}"))?;
        let telegram = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .map_err(|_| "no BCU1 group telegram after trigger".to_string())?
            .map_err(|error| format!("group events: {error}"))?;
        if telegram.group != group {
            return Err(format!("telegram on {}, expected {group}", telegram.group));
        }
        Ok(())
    })
}

// Each argument is one fixture-specific protocol field or key source. Keeping
// them explicit makes secure fixture differences visible at the call sites.
#[allow(clippy::too_many_arguments)]
async fn program_secure_fixture(
    bus: &KnxBus,
    control: &DutControl,
    mtxml: String,
    serial_number: [u8; 6],
    group: GroupAddress,
    dpt: &str,
    com_object: u16,
    tool_key: [u8; 16],
    group_key: [u8; 16],
    max_apdu: u16,
    key_sources: SecureFixtureKeySources,
) -> Result<ProgrammingReport, String> {
    // Erase code 02 is the secure-device factory state: FDSK active,
    // Security Mode off, and IA 15.15.255. The programmer must find the
    // serial and restore the project IA before loading the application.
    control.master_reset(2).await.map_err(|error| format!("factory reset: {error}"))?;
    let masks = mask_db()?;
    let knx = zweidraehte_ets_files::runtime::parser::parse_application_program(&mtxml)
        .map_err(|error| format!("parsing secure fixture MTXML: {error}"))?;
    let program = knx
        .manufacturer_data
        .manufacturer
        .application_programs
        .programs
        .into_iter()
        .next()
        .ok_or_else(|| "secure fixture MTXML has no application program".to_string())?;
    let product =
        ProductData::from_program(&program).map_err(|error| format!("extracting secure fixture product: {error}"))?;
    let project_source = format!(
        r#"ga test = {group}
net test : {dpt} {{
    security authentication_confidentiality
}}

external_sender conformance_client {{
    address {}
    data_secure enabled
    on test
}}

area 1 conformance {{
    line 0 main {{
        medium tp1

        device dut {{
            product local:"fixture.mtxml"
            address {}
            serial "{}"
            max_apdu {max_apdu}
            data_secure enabled

            object {com_object} {{
                on test
                flags {{
                    communication true
                    transmit true
                }}
            }}
        }}
    }}
}}
"#,
        tester_ia(),
        dut_ia(),
        zweidraehte_project::format_serial(&serial_number),
    );
    let authored =
        AuthoredProject::parse(project_source).map_err(|error| format!("parsing secure fixture project: {error}"))?;
    let products =
        [(ProjectDeviceId("dut".into()), ProjectProduct { program, product: product.clone() })].into_iter().collect();
    let keyring = fixture_keyring(serial_number, group, tool_key, group_key);
    let direct = FixtureKeySource::secure(tool_key, group_key);
    let empty = FixtureKeySource::default();
    let programmer = ProjectProgrammer::new();
    let selected = [ProjectDeviceId("dut".into())];
    let selection = BatchSelection::Selected { include_affected: true, force_single: false };
    let (source, imported) = match key_sources {
        SecureFixtureKeySources::Direct => (&direct as &dyn KeyMaterialSource, None),
        SecureFixtureKeySources::KeyringOnly => (&empty as &dyn KeyMaterialSource, Some(&keyring)),
        SecureFixtureKeySources::MatchingProjectAndKeyring => (&direct as &dyn KeyMaterialSource, Some(&keyring)),
        SecureFixtureKeySources::RejectedConflictThenKeyring => {
            let mut conflicting_key = group_key;
            conflicting_key[0] ^= 0xFF;
            let conflicting = FixtureKeySource::secure(tool_key, conflicting_key);
            if programmer
                .plan(ProjectPlanRequest {
                    project: &authored,
                    state: None,
                    selected: &selected,
                    selection,
                    products: &products,
                    keys: &conflicting,
                    keyring: Some(&keyring),
                    scope: ProgrammingScope::AddressAndApplication,
                })
                .is_ok()
            {
                return Err("conflicting project and keyring group keys were accepted".to_string());
            }
            (&empty as &dyn KeyMaterialSource, Some(&keyring))
        }
    };
    let mut batch = programmer
        .plan(ProjectPlanRequest {
            project: &authored,
            state: None,
            selected: &selected,
            selection,
            products: &products,
            keys: source,
            keyring: imported,
            scope: ProgrammingScope::AddressAndApplication,
        })
        .map_err(|error| format!("planning secure project fixture: {error}"))?;
    let planned = batch.devices.pop().ok_or_else(|| "secure project plan is empty".to_string())?;
    let configuration = planned.configuration;
    let key_material = planned.key_material;
    let options = ProgrammingOptions {
        addressing: AddressingMode::Automatic,
        scan_window: Duration::from_millis(150),
        restart_delay: Duration::from_millis(50),
        ..ProgrammingOptions::default()
    };
    let programmer = DeviceProgrammer::new();
    let request = || {
        ProgrammingRequest::new(product.clone(), configuration.clone(), key_material.clone())
            .with_download_scope(DownloadScope::Full)
            .with_options(options.clone())
    };

    let first = programmer
        .program(bus, &masks, request(), None)
        .await
        .map_err(|error| format!("first secure commission: {error}"))?;
    if !first.security.is_some_and(|security| security.security_mode) {
        return Err("the programming report did not verify Security Mode".to_string());
    }

    // Reboot, then use the same persisted tool key for a complete second
    // invocation. This covers both durable device state and retry access.
    control.power_cycle().await.map_err(|error| format!("power cycle: {error}"))?;
    programmer.program(bus, &masks, request(), None).await.map_err(|error| format!("repeat secure download: {error}"))
}

fn scenario_system7_secure_programmer<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        const TOOL_KEY: [u8; 16] = [0x72; 16];
        const GROUP_KEY: [u8; 16] = [0x73; 16];
        let group = GroupAddress::from_three_level(3, 4, 5);
        let report = program_secure_fixture(
            bus,
            control,
            system7_product::generate_secure_mtxml()?,
            zweidraehte_conformance::dut::system7_secure_stack::device_info::SERIAL_NUMBER,
            group,
            "5.010",
            3,
            TOOL_KEY,
            GROUP_KEY,
            254,
            SecureFixtureKeySources::MatchingProjectAndKeyring,
        )
        .await?;
        if report.device_mask != MaskVersion::System7Tp1 {
            return Err(format!("secure System 7 reported mask {:?}", report.device_mask));
        }
        verify_secure_group_trigger(bus, control, group, 3).await
    })
}

fn scenario_system_b_secure_programmer<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        const TOOL_KEY: [u8; 16] = [0xB2; 16];
        const GROUP_KEY: [u8; 16] = [0xB3; 16];
        let group = GroupAddress::from_three_level(3, 4, 6);
        let report = program_secure_fixture(
            bus,
            control,
            system_b_product::generate_secure_mtxml()?,
            zweidraehte_conformance::dut::systemb_secure_stack::SECURE_SERIAL_NUMBER,
            group,
            "1.001",
            1,
            TOOL_KEY,
            GROUP_KEY,
            254,
            SecureFixtureKeySources::KeyringOnly,
        )
        .await?;
        if report.device_mask != MaskVersion::SystemBTp1 {
            return Err(format!("secure System B reported mask {:?}", report.device_mask));
        }
        verify_secure_group_trigger(bus, control, group, 1).await
    })
}

fn scenario_bcu2_secure_programmer<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        const TOOL_KEY: [u8; 16] = [0x22; 16];
        const GROUP_KEY: [u8; 16] = [0x23; 16];
        let group = GroupAddress::from_three_level(3, 5, 1);
        let report = program_secure_fixture(
            bus,
            control,
            bcu2_light_switch_product::generate_secure_mtxml()?,
            bcu2_stack::SERIAL_NUMBER,
            group,
            "1.001",
            0,
            TOOL_KEY,
            GROUP_KEY,
            40,
            SecureFixtureKeySources::RejectedConflictThenKeyring,
        )
        .await?;
        if report.device_mask.as_u16() != 0x0021 {
            return Err(format!("secure BCU2 reported mask {:?}", report.device_mask));
        }
        verify_secure_group_trigger(bus, control, group, 0).await
    })
}

fn scenario_micro_s7_secure_programmer<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        const TOOL_KEY: [u8; 16] = [0x77; 16];
        const GROUP_KEY: [u8; 16] = [0x78; 16];
        let group = GroupAddress::from_three_level(3, 5, 2);
        let report = program_secure_fixture(
            bus,
            control,
            micro_system7_product::generate_secure_mtxml()?,
            micro_system7_stack::SERIAL_NUMBER,
            group,
            "5.010",
            3,
            TOOL_KEY,
            GROUP_KEY,
            40,
            SecureFixtureKeySources::Direct,
        )
        .await?;
        if report.device_mask != MaskVersion::System7Tp1 {
            return Err(format!("secure micro System 7 reported mask {:?}", report.device_mask));
        }
        verify_secure_group_trigger(bus, control, group, 3).await
    })
}

async fn verify_secure_group_trigger(
    bus: &KnxBus,
    control: &DutControl,
    group: GroupAddress,
    com_object: u16,
) -> Result<(), String> {
    let mut events = bus.group_events();
    control.trigger_group_write(com_object).await.map_err(|error| format!("secure group trigger: {error}"))?;
    let telegram = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .map_err(|_| "no secure group telegram after trigger".to_string())?
        .map_err(|error| format!("secure group events: {error}"))?;
    if telegram.group != group || !telegram.secured {
        return Err(format!("unexpected secure group telegram: {telegram:?}"));
    }
    Ok(())
}

fn definition_offset(offset: usize) -> Result<u16, String> {
    u16::try_from(offset).map_err(|_| "BCU1 table offset does not fit the address space".to_string())
}

// ============================================================================
// Scenarios
// ============================================================================

fn scenario_system7_descriptor<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        let result = conn.device_descriptor_read(0).await;
        close_quietly(conn).await;
        let descriptor = result.map_err(|e| format!("descriptor read: {e}"))?;
        if descriptor != [0x07, 0x05] {
            return Err(format!("descriptor {descriptor:02X?}, expected mask 0705"));
        }
        Ok(())
    })
}

fn scenario_system7_programming_mode_addressing<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let new_ia = IndividualAddress::new(1, 0, 66);

        control.set_programming_mode(true).await.map_err(|e| format!("prog mode on: {e}"))?;
        let nm = bus.network_management();
        nm.write_individual_address(new_ia).await.map_err(|e| format!("IA write: {e}"))?;
        control.set_programming_mode(false).await.map_err(|e| format!("prog mode off: {e}"))?;

        // The device must now answer connected management on its new
        // address — the strongest form of "the write landed".
        let mut conn = bus.connect_device(new_ia).await.map_err(|e| format!("connect at new IA: {e}"))?;
        let result = conn.device_descriptor_read(0).await;
        close_quietly(conn).await;
        result.map_err(|e| format!("descriptor at new IA: {e}"))?;
        Ok(())
    })
}

fn scenario_system7_full_download<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let rewired_ga = GroupAddress::from_three_level(3, 1, 1);

        // The three layers, exactly as ETS has them: the mask from
        // master data, the product from its (generated) product file,
        // and the project from what this test wants.
        let masks = mask_db()?;
        let report = program_plain_project_fixture(
            bus,
            &masks,
            &system7_product::generate_mtxml()?,
            dut_ia(),
            Some(system7_stack::device_info::SERIAL_NUMBER),
            rewired_ga,
            "1.001",
            1,
            254,
            AddressingMode::Automatic,
        )
        .await?;
        if report.device_mask != MaskVersion::System7Tp1 || report.load_control_path != LoadControlPath::Property {
            return Err(format!(
                "unexpected programming report: mask {:?}, path {:?}",
                report.device_mask, report.load_control_path
            ));
        }

        // The procedure ended in a restart — the DUT respawned from
        // its flushed state. Everything must have survived the reboot.
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("reconnect: {e}"))?;
        let checks = async {
            let states = conn.memory_read(0xB6EA, 3).await.map_err(|e| format!("load states: {e}"))?;
            if states != [u8::from(LoadState::Loaded); 3] {
                return Err(format!("load states {states:02X?}, expected all Loaded"));
            }
            // ADT: length 2 for the IA and one group address.
            let adt = conn.memory_read(0x4000, 5).await.map_err(|e| format!("ADT read: {e}"))?;
            if adt != [2, 0x10, 0x01, 0x19, 0x01] {
                return Err(format!("ADT {adt:02X?}, expected [02 10 01 19 01]"));
            }
            // AST: the single link, TSAP 1 → object 1.
            let ast = conn.memory_read(0x4100, 3).await.map_err(|e| format!("AST read: {e}"))?;
            if ast != [1, 1, 1] {
                return Err(format!("AST {ast:02X?}, expected [01 01 01]"));
            }
            // COT: built from the product file's object definitions,
            // so ASAP 1 carries the flags the generator declared.
            let cot = conn.memory_read(0x4200, 11).await.map_err(|e| format!("COT read: {e}"))?;
            if cot[0] < 2 {
                return Err(format!("COT count {} covers no objects", cot[0]));
            }
            if cot[9] == 0 {
                return Err("COT object 1 has no flags — the product's definitions did not land".to_string());
            }
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        checks?;

        // And the wiring is *live*: the DUT transmitting on ASAP 1
        // must now hit the rewired group address — its own tables did
        // the TSAP lookup.
        let mut events = bus.group_events();
        control.trigger_group_write(1).await.map_err(|e| format!("trigger: {e}"))?;
        let telegram = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .map_err(|_| "no group telegram after trigger".to_string())?
            .map_err(|e| format!("group events: {e}"))?;
        if telegram.group != rewired_ga || telegram.service != GroupService::Write {
            return Err(format!("unexpected telegram {:?} on {}", telegram.service, telegram.group));
        }
        Ok(())
    })
}

fn scenario_system7_unload_all<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let masks = mask_db()?;
        let mask = masks
            .mask(MaskVersion::System7Tp1)
            .ok_or_else(|| "the master data does not describe MV-0705".to_string())?;
        let resources = dut_resources(&masks)?;

        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        let result = async {
            let unload = assemble(&mask, &ProductData::default(), ProcedureKind::UnloadAll)
                .map_err(|e| format!("assembling Unload-all from the mask: {e}"))?;
            let mut downloader = Downloader::new(&mut conn, resources, 254);
            downloader.run(&unload, &DeviceImage::new()).await.map_err(|e| format!("unload: {e}"))?;

            let states = conn.memory_read(0xB6EA, 4).await.map_err(|e| format!("load states: {e}"))?;
            if states != [u8::from(LoadState::Unloaded); 4] {
                return Err(format!("load states {states:02X?}, expected all Unloaded"));
            }
            // Unload clears the loadable data but spares the IA slot
            // (the device would otherwise lose its own address
            // mid-procedure).
            let adt = conn.memory_read(0x4000, 3).await.map_err(|e| format!("ADT read: {e}"))?;
            if adt != [0x01, 0x10, 0x01] {
                return Err(format!("ADT head {adt:02X?}, expected IA-only mute length"));
            }
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        result
    })
}

fn scenario_system7_oversized_segment<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let resources = dut_resources(&mask_db()?)?;

        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        let result = async {
            let mut downloader = Downloader::new(&mut conn, resources, 254);
            // 255 bytes into a 17-byte address table: the allocation
            // must be rejected and throw the machine into Error.
            let doomed = [
                Instruction::LsmEvent { lsm: LsmTarget::Index(1), event: LoadEvent::StartLoading },
                Instruction::AbsSegment { lsm: LsmTarget::Index(1), segment: AbsSegment::eeprom(0x4000, 255) },
            ];
            match downloader.run(&doomed, &DeviceImage::new()).await {
                Err(ClientError::LoadState {
                    machine: MachineRef::Machine(LsmMachine::AddressTable),
                    state: LoadState::Err,
                    ..
                }) => {}
                other => return Err(format!("expected a LoadState error, got {other:?}")),
            }
            // Recovery: Unload brings the machine back to a defined
            // state.
            let mut downloader = Downloader::new(&mut conn, resources, 254);
            downloader
                .run(
                    &[Instruction::LsmEvent { lsm: LsmTarget::Index(1), event: LoadEvent::Unload }],
                    &DeviceImage::new(),
                )
                .await
                .map_err(|e| format!("recovery unload: {e}"))?;
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        result
    })
}

// ============================================================================
// BCU2 scenarios
// ============================================================================
//
// The BCU2 DUT is the no-async `zweidraehte-microdevice` stack behind
// `conformance-dut-bcu2`. Its download is the MV-0020 mask template
// end-to-end: authorize on connect, the halt-before-LSM RunError
// write, machine 3 cycled over PID_LOAD_STATE_CONTROL with the task
// records, then the verify-mode memory phase over 0100h–046Fh with
// diffed writes, and a restart. This is the software closure of
// BCU2_PLAN.md's "end-to-end hardware test pending".

/// Security is a Profile Module which may be composed with a base mask;
/// 0021h does not mean that every application download is secure. Keep mask
/// selection independent from the application's security declaration so the
/// secure-capable DUT exercises both ordinary and secure configuration.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Bcu2Target {
    Mask0020,
    Mask0021,
}

impl Bcu2Target {
    const fn mask_version(self) -> u16 {
        match self {
            Self::Mask0020 => 0x0020,
            Self::Mask0021 => 0x0021,
        }
    }

    const fn max_apdu(self) -> u16 {
        match self {
            Self::Mask0020 => 15,
            Self::Mask0021 => 40,
        }
    }

    fn product_mtxml(self) -> Result<String, String> {
        match self {
            Self::Mask0020 => bcu2_product::generate_mtxml(),
            Self::Mask0021 => bcu2_product::generate_plain_0021_mtxml(),
        }
    }

    fn light_switch_mtxml(self) -> Result<String, String> {
        match self {
            Self::Mask0020 => bcu2_light_switch_product::generate_mtxml(),
            Self::Mask0021 => bcu2_light_switch_product::generate_plain_0021_mtxml(),
        }
    }
}

/// The BCU2 DUT's product layer, generated from the same definition
/// the selected DUT boots (see `dut::bcu2_product`).
fn bcu2_dut_product(target: Bcu2Target) -> Result<ProductData, String> {
    let mtxml = target.product_mtxml()?;
    ProductData::from_mtxml_str(&mtxml).map_err(|e| format!("reading the generated product file back: {e}"))
}

fn bcu2_mask(masks: &MaskDb, target: Bcu2Target) -> Result<zweidraehte_client::download::MaskData<'_>, String> {
    let mask = target.mask_version();
    masks.mask(MaskVersion::from(mask)).ok_or_else(|| format!("the master data does not describe MV-{mask:04X}"))
}

fn scenario_bcu2_descriptor<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(run_bcu2_descriptor(bus, Bcu2Target::Mask0020))
}

fn scenario_bcu2_0021_descriptor<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(run_bcu2_descriptor(bus, Bcu2Target::Mask0021))
}

async fn run_bcu2_descriptor(bus: &KnxBus, target: Bcu2Target) -> Result<(), String> {
    let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
    let result = async {
        let descriptor = conn.device_descriptor_read(0).await.map_err(|e| format!("descriptor read: {e}"))?;
        let expected = target.mask_version().to_be_bytes();
        if descriptor != expected {
            return Err(format!("descriptor {descriptor:02X?}, expected mask {:04X}", target.mask_version()));
        }
        // Volume 9 calls 0115h UsrSavPtr. The ETS mask fixtures use
        // 48h there, alongside the factory level-0 authorization key.
        let user_save = conn.memory_read(0x0115, 1).await.map_err(|e| format!("UsrSavPtr: {e}"))?;
        if user_save != [0x48] {
            return Err(format!("UsrSavPtr {user_save:02X?}, expected 48h"));
        }
        let level = conn.authorize(&[0xFF; 4]).await.map_err(|e| format!("authorize: {e}"))?;
        if level != 0 {
            return Err(format!("authorize granted level {level}, expected 0"));
        }
        Ok(())
    }
    .await;
    close_quietly(conn).await;
    result
}

fn scenario_bcu2_required_properties<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    type RequiredProperty<'a> = (u8, u16, &'a [u8], &'a [u8], &'a str);

    Box::pin(async move {
        let values: &[RequiredProperty<'_>] = &[
            // The MCU has no EMI, so its eight service-disable bits remain
            // set even when a client writes a different high octet.
            (0, pid::SERVICE_CONTROL, &[0xA5, 0x04], &[0xFF, 0x04], "Service Control"),
            (0, pid::PORT_CONFIGURATION, &[0x5A], &[0x5A], "Port Configuration"),
            (0, pid::POLL_GROUP_SETTINGS, &[0x12, 0x34, 0x8A], &[0x12, 0x34, 0x8A], "Poll Group Settings"),
            (3, pid::PEI_TYPE, &[0x11], &[0x11], "application PEI Type"),
        ];

        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        let result = async {
            let level = conn.authorize(&[0xFF; 4]).await.map_err(|e| format!("authorize: {e}"))?;
            if level != 0 {
                return Err(format!("authorize granted level {level}, expected 0"));
            }
            for &(object, property, written, expected, name) in values {
                conn.property_write(object, property, 1, 1, written).await.map_err(|e| format!("write {name}: {e}"))?;
                let actual =
                    conn.property_read(object, property, 1, 1).await.map_err(|e| format!("read {name}: {e}"))?;
                if actual != expected {
                    return Err(format!("{name} readback {actual:02X?}, expected {expected:02X?}"));
                }
            }

            // The Device Object reports the physically connected PEI. This
            // MCU has none; object 3 above stores the application's required
            // PEI independently.
            let actual_pei =
                conn.property_read(0, pid::PEI_TYPE, 1, 1).await.map_err(|e| format!("device PEI: {e}"))?;
            if actual_pei != [0] {
                return Err(format!("device PEI {actual_pei:02X?}, expected none"));
            }
            conn.restart().await.map_err(|e| format!("restart: {e}"))
        }
        .await;
        close_quietly(conn).await;
        result?;

        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("reconnect: {e}"))?;
        let result = async {
            for &(object, property, _, expected, name) in values {
                let actual = conn
                    .property_read(object, property, 1, 1)
                    .await
                    .map_err(|e| format!("read persisted {name}: {e}"))?;
                if actual != expected {
                    return Err(format!("persisted {name} {actual:02X?}, expected {expected:02X?}"));
                }
            }
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        result
    })
}

fn scenario_bcu2_programming_mode_addressing<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let new_ia = IndividualAddress::new(1, 0, 77);

        control.set_programming_mode(true).await.map_err(|e| format!("prog mode on: {e}"))?;
        let nm = bus.network_management();
        nm.write_individual_address(new_ia).await.map_err(|e| format!("IA write: {e}"))?;
        control.set_programming_mode(false).await.map_err(|e| format!("prog mode off: {e}"))?;

        // On a BCU2 the IA lives inside the address table at 0117h —
        // connected management at the new address proves the write,
        // a memory read shows where it landed.
        let mut conn = bus.connect_device(new_ia).await.map_err(|e| format!("connect at new IA: {e}"))?;
        let result = async {
            let slot = conn.memory_read(0x0117, 2).await.map_err(|e| format!("IA slot read: {e}"))?;
            if slot != new_ia.as_bytes() {
                return Err(format!("IA slot {slot:02X?}, expected {:02X?}", new_ia.as_bytes()));
            }
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        result
    })
}

fn scenario_bcu2_full_download<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(run_bcu2_full_download(bus, control, Bcu2Target::Mask0020))
}

fn scenario_bcu2_0021_full_download<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(run_bcu2_full_download(bus, control, Bcu2Target::Mask0021))
}

async fn run_bcu2_full_download(bus: &KnxBus, control: &DutControl, target: Bcu2Target) -> Result<(), String> {
    let rewired_ga = GroupAddress::from_three_level(3, 1, 1);

    if target == Bcu2Target::Mask0021 {
        // The secure DUT process boots the operator-provisioned EITT sample
        // app. A plain-product scenario starts from the device's actual local
        // factory state instead: Security IO unloaded, FDSK active, IA kept.
        control.master_reset(7).await.map_err(|e| format!("factory reset while retaining IA: {e}"))?;
    }

    let masks = mask_db()?;
    let mask = bcu2_mask(&masks, target)?;
    let product = bcu2_dut_product(target)?;

    let mut project = ProjectConfig::new(dut_ia());
    // GO3 is the transmit-capable status object of the fixture.
    project.links = vec![GroupLink { group_address: rewired_ga, com_object: 3 }];
    project.max_apdu = target.max_apdu();

    // Sanity: this compiles to the property path with the halt
    // preceding the LSM cycle (the wedge the model row exists for).
    let compiled =
        compile(&mask, &product, &default_configuration(&product, &project)).map_err(|e| format!("compile: {e}"))?;
    if compiled.path() != LoadControlPath::Property {
        return Err("a BCU2 must compile to the property load-control path".to_string());
    }
    if !matches!(compiled.instructions.get(1), Some(Instruction::WriteMemory { address: 0x010D, .. })) {
        return Err("the RunError halt must directly follow Connect".to_string());
    }

    let report = program_plain_project_fixture(
        bus,
        &masks,
        &target.product_mtxml()?,
        dut_ia(),
        Some(bcu2_stack::SERIAL_NUMBER),
        rewired_ga,
        "1.001",
        3,
        target.max_apdu(),
        AddressingMode::Automatic,
    )
    .await?;
    if report.device_mask.as_u16() != target.mask_version() {
        return Err(format!(
            "programmer selected mask {:?}, expected {:04X}",
            report.device_mask,
            target.mask_version()
        ));
    }

    // The procedure ended in a restart; everything must have
    // survived the respawn.
    let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("reconnect: {e}"))?;
    let checks = async {
        let state = conn
            .property_read(3, pid::LOAD_STATE_CONTROL, 1, 1)
            .await
            .map_err(|e| format!("application load state: {e}"))?;
        if state.first() != Some(&u8::from(LoadState::Loaded)) {
            return Err(format!("application load state {state:02X?}, expected Loaded"));
        }
        // The RT2 address table at 0116h: length counts the IA
        // slot, then the IA, then the single rewired GA.
        let adt = conn.memory_read(0x0116, 5).await.map_err(|e| format!("ADT read: {e}"))?;
        if adt != [0x02, 0x10, 0x01, 0x19, 0x01] {
            return Err(format!("ADT {adt:02X?}, expected [02 10 01 19 01]"));
        }
        // RunError cleared back to FFh — the application runs.
        let run_error = conn.memory_read(0x010D, 1).await.map_err(|e| format!("RunError: {e}"))?;
        if run_error != [0xFF] {
            return Err(format!("RunError {run_error:02X?}, expected FFh"));
        }
        Ok(())
    }
    .await;
    close_quietly(conn).await;
    checks?;

    // The wiring is live: GO3 transmitting must hit the rewired GA.
    let mut events = bus.group_events();
    control.trigger_group_write(3).await.map_err(|e| format!("trigger: {e}"))?;
    let telegram = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .map_err(|_| "no group telegram after trigger".to_string())?
        .map_err(|e| format!("group events: {e}"))?;
    if telegram.group != rewired_ga || telegram.service != GroupService::Write {
        return Err(format!("unexpected telegram {:?} on {}", telegram.service, telegram.group));
    }
    Ok(())
}

/// The real light-switch product (six objects, ETS parameters) against
/// the BCU2 DUT: the download must carry the product's table page —
/// group object pointers included — into the device, and patch the
/// overridden parameter bytes into the 0200h segment. This is the
/// end-to-end proof of the `Bcu2MemoryLayout` generator path and of
/// the parameter delivery the micro light-switch firmware reads.
fn scenario_bcu2_light_switch_download<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(run_bcu2_light_switch_download(bus, control, Bcu2Target::Mask0020))
}

fn scenario_bcu2_0021_light_switch_download<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(run_bcu2_light_switch_download(bus, control, Bcu2Target::Mask0021))
}

async fn run_bcu2_light_switch_download(bus: &KnxBus, control: &DutControl, target: Bcu2Target) -> Result<(), String> {
    if target == Bcu2Target::Mask0021 {
        control.master_reset(7).await.map_err(|e| format!("factory reset while retaining IA: {e}"))?;
    }
    let masks = mask_db()?;
    let mask = bcu2_mask(&masks, target)?;
    let mtxml = target.light_switch_mtxml()?;
    let product =
        ProductData::from_mtxml_str(&mtxml).map_err(|e| format!("reading the light-switch product back: {e}"))?;

    let mut project = ProjectConfig::new(dut_ia());
    // Button 1's primary object onto a group address.
    project.links = vec![GroupLink { group_address: GroupAddress::from_three_level(3, 2, 1), com_object: 0 }];
    project.max_apdu = target.max_apdu();
    // Two overrides on top of the defaults: debounce 150 ms (4),
    // long press 1000 ms (3). Parameter ids are ordinal in the
    // generated MTXML, so the memory offset — the struct layout,
    // pinned by `DEFAULT_PARAM_BYTES` — is the stable selector:
    // offset 0 is `debounce_time`, offset 1 `long_press_time`.
    let param_id = |offset: u32| {
        product
            .parameters()
            .iter()
            .find(|p| p.offset == offset)
            .map(|p| p.id.clone())
            .ok_or_else(|| format!("the product lacks a parameter at offset {offset}"))
    };
    project.parameters =
        vec![ParameterValue { id: param_id(0)?, value: vec![4] }, ParameterValue { id: param_id(1)?, value: vec![3] }];

    bus.configure_device(&mask, &product, &default_configuration(&product, &project))
        .await
        .map_err(|e| format!("download: {e}"))?;

    let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("reconnect: {e}"))?;
    let checks = async {
        // The group object table at 0146h (offset 46h in the table
        // page): count, RAM-flags pointer and the six data
        // pointers must be the product's — the download preserves
        // them through the overlay, it cannot synthesize them.
        // Classic A_Memory_Read carries a four-bit count. The APDU-15
        // MV-0020 device therefore needs two requests for this 20-byte table;
        // the APDU-40 secure composition could accept one, but exercising the
        // common BCU2 path keeps the scenario profile-neutral.
        let mut cot = conn.memory_read(0x0146, 10).await.map_err(|e| format!("COT read: {e}"))?;
        cot.extend(conn.memory_read(0x0150, 10).await.map_err(|e| format!("COT tail read: {e}"))?);
        if cot[0] != 6 || cot[1] != 0xD0 {
            return Err(format!("COT header {:02X?}, expected count 6, RAM flags D0h", &cot[..2]));
        }
        for (i, row) in cot[2..].chunks(3).enumerate() {
            if row[0] != 0xC6 + i as u8 {
                return Err(format!("object {i} data pointer {:02X}, expected {:02X}", row[0], 0xC6 + i as u8));
            }
        }
        // The parameter block at 0200h: the defaults with the two
        // overridden bytes.
        let params = conn.memory_read(0x0200, 8).await.map_err(|e| format!("param read: {e}"))?;
        if params != [4, 3, 1, 0, 0, 0, 0, 0] {
            return Err(format!("params {params:02X?}, expected [04 03 01 00 00 00 00 00]"));
        }
        Ok(())
    }
    .await;
    close_quietly(conn).await;
    checks
}

fn scenario_bcu2_unload_all<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(run_bcu2_unload_all(bus, Bcu2Target::Mask0020))
}

fn scenario_bcu2_0021_unload_all<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(run_bcu2_unload_all(bus, Bcu2Target::Mask0021))
}

async fn run_bcu2_unload_all(bus: &KnxBus, target: Bcu2Target) -> Result<(), String> {
    let masks = mask_db()?;
    let mask = bcu2_mask(&masks, target)?;

    let unload = assemble(&mask, &ProductData::default(), ProcedureKind::UnloadAll)
        .map_err(|e| format!("assembling Unload-all from the mask: {e}"))?;

    let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
    let result = async {
        let mut downloader = Downloader::with_path(&mut conn, LoadControlPath::Property, target.max_apdu());
        downloader.run(&unload, &DeviceImage::new()).await.map_err(|e| format!("unload: {e}"))?;

        for obj in [1u8, 2, 3] {
            let state = conn
                .property_read(obj, pid::LOAD_STATE_CONTROL, 1, 1)
                .await
                .map_err(|e| format!("load state of object {obj}: {e}"))?;
            if state.first() != Some(&u8::from(LoadState::Unloaded)) {
                return Err(format!("object {obj} load state {state:02X?}, expected Unloaded"));
            }
        }
        // The address table collapsed to the mute length with the
        // IA intact, and the ApplicationID's DevType is zeroed —
        // the device is unconfigured but still commissioned.
        let adt = conn.memory_read(0x0116, 3).await.map_err(|e| format!("ADT read: {e}"))?;
        if adt != [0x01, 0x10, 0x01] {
            return Err(format!("ADT head {adt:02X?}, expected mute length with IA intact"));
        }
        let dev_type = conn.memory_read(0x0105, 3).await.map_err(|e| format!("DevType read: {e}"))?;
        if dev_type != [0x00, 0x00, 0x00] {
            return Err(format!("ApplicationID tail {dev_type:02X?}, expected zeroed"));
        }
        Ok(())
    }
    .await;
    close_quietly(conn).await;
    result
}

fn scenario_bcu2_secure_commission<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        const TOOL_KEY: [u8; 16] = [0x22; 16];
        const GROUP_KEY: [u8; 16] = [0x33; 16];
        const SECURITY_IO: InterfaceObjectType = InterfaceObjectType::Security;
        const SECURITY_OCCURRENCE: u16 = 1;

        let rewired_ga = GroupAddress::from_three_level(3, 1, 1);

        // `full_reset` restores the loaded conformance application, just as
        // it does for the full-stack DUTs. This scenario is specifically a
        // first commission, so enter the device's own unprovisioned state
        // while retaining the already assigned IA.
        control.master_reset(7).await.map_err(|e| format!("factory reset while retaining IA: {e}"))?;
        bus.set_device_security(dut_ia(), SecurityEntry::secure_with_fdsk(SECURE_FDSK, bcu2_stack::SERIAL_NUMBER))
            .await
            .map_err(|e| format!("install FDSK: {e}"))?;

        // First contact authenticates under the FDSK. The confirmation to
        // PID_TOOL_KEY is already protected by TOOL_KEY, which exercises the
        // client's mid-request channel rotation rather than merely changing a
        // keyring between connections.
        let mut first = bus.connect_device(dut_ia()).await.map_err(|e| format!("FDSK sync: {e}"))?;
        let descriptor = first.device_descriptor_read(0).await.map_err(|e| format!("secure descriptor: {e}"))?;
        if descriptor != [0x00, 0x21] {
            close_quietly(first).await;
            return Err(format!("descriptor {descriptor:02X?}, expected mask 0021"));
        }
        first.write_tool_key(TOOL_KEY).await.map_err(|e| format!("tool-key rotation: {e}"))?;
        close_quietly(first).await;

        // The device rate-limits sync responses to one per second. This is a
        // protocol window, not harness slack: the application download opens
        // a fresh secure connection under the newly persisted key.
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let masks = mask_db()?;
        let mask = bcu2_mask(&masks, Bcu2Target::Mask0021)?;
        let product = ProductData::from_mtxml_str(&bcu2_light_switch_product::generate_secure_mtxml()?)
            .map_err(|e| format!("reading secure BCU2 light-switch product back: {e}"))?;

        let mut project = ProjectConfig::new(dut_ia());
        // The light-switch primary object transmits; its status sibling
        // receives. Link both to the same GA so the bidirectional secure test
        // follows the real product flags instead of relying on the fixture's
        // all-flags-enabled object zero.
        project.links = vec![GroupLink { group_address: rewired_ga, com_object: 0 }, GroupLink {
            group_address: rewired_ga,
            com_object: 1,
        }];
        project.max_apdu = 40;
        let param_id = |offset: u32| {
            product
                .parameters()
                .iter()
                .find(|parameter| parameter.offset == offset)
                .map(|parameter| parameter.id.clone())
                .ok_or_else(|| format!("the secure product lacks a parameter at offset {offset}"))
        };
        project.parameters = vec![ParameterValue { id: param_id(0)?, value: vec![4] }, ParameterValue {
            id: param_id(1)?,
            value: vec![3],
        }];
        project.security = Some(DownloadSecurityConfig::new(
            vec![(rewired_ga, GROUP_KEY)],
            // The client itself is the secure group sender in the second
            // half of the scenario, so its IA must have a replay-counter row.
            vec![(tester_ia(), 0)],
            vec![
                GroupObjectSecurity { com_object: 0, protection: GroupObjectProtection::AuthenticationConfidentiality },
                GroupObjectSecurity { com_object: 1, protection: GroupObjectProtection::AuthenticationConfidentiality },
            ],
        ));

        bus.configure_device(&mask, &product, &default_configuration(&product, &project))
            .await
            .map_err(|e| format!("secure download: {e}"))?;
        bus.set_group_key(rewired_ga, GROUP_KEY).await.map_err(|e| format!("install group key: {e}"))?;

        // The restart at the end of the download must preserve the Tool Key,
        // the loaded Security IO, its tables and enabled Security Mode.
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("post-download sync: {e}"))?;
        let checks = async {
            let load_state = conn
                .property_ext_read(SECURITY_IO, SECURITY_OCCURRENCE, pid::LOAD_STATE_CONTROL, 1, 1)
                .await
                .map_err(|e| format!("Security IO load state: {e}"))?;
            if load_state != [u8::from(LoadState::Loaded)] {
                return Err(format!("Security IO state {load_state:02X?}, expected Loaded"));
            }

            for (property, expected, name) in [
                (pid::security::GROUP_KEY_TABLE, 1u16, "group-key table"),
                (pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 1u16, "SIAT"),
                (pid::security::GO_SECURITY_FLAGS, 6u16, "GO security flags"),
            ] {
                let count = conn
                    .property_ext_read(SECURITY_IO, SECURITY_OCCURRENCE, property, 0, 1)
                    .await
                    .map_err(|e| format!("{name} count: {e}"))?;
                if count != expected.to_be_bytes() {
                    return Err(format!("{name} count {count:02X?}, expected {expected}"));
                }
            }

            let mode = conn
                .function_property_ext_state_read(SECURITY_IO, SECURITY_OCCURRENCE, pid::security::SECURITY_MODE, &[
                    0, 0,
                ])
                .await
                .map_err(|e| format!("Security Mode: {e}"))?;
            if mode.return_code != 0 || mode.data != [0, 1] {
                return Err(format!(
                    "Security Mode response code {:02X}, data {:02X?}; expected enabled",
                    mode.return_code, mode.data
                ));
            }

            // This is the shipping light-switch product rather than the
            // four-object DUT fixture: its RT2 table and parameter block must
            // survive the secure download and restart as well.
            let cot = conn.memory_read(0x0146, 20).await.map_err(|e| format!("COT read: {e}"))?;
            if cot[0] != 6 || cot[1] != 0xD0 {
                return Err(format!("COT header {:02X?}, expected six objects at D0h", &cot[..2]));
            }
            let params = conn.memory_read(0x0200, 8).await.map_err(|e| format!("parameter read: {e}"))?;
            if params != [4, 3, 1, 0, 0, 0, 0, 0] {
                return Err(format!("parameters {params:02X?}, expected secure light-switch overrides"));
            }
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        checks?;

        // Drive both directions. The secure client write updates the product's
        // status input (GO1); triggering that object back proves the device
        // accepted it and used the commissioned group key and PID 61 level.
        bus.group_write(rewired_ga, &[1], GroupValueEncoding::Short)
            .await
            .map_err(|e| format!("secure group write to DUT: {e}"))?;
        // Group writes are connectionless: `group_write` confirms that the
        // bridge emitted the frame, not that the DUT process has consumed it.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut events = bus.group_events();
        control.trigger_group_write(1).await.map_err(|e| format!("secure group trigger: {e}"))?;
        let telegram = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .map_err(|_| "no secure group telegram after trigger".to_string())?
            .map_err(|e| format!("group events: {e}"))?;
        if telegram.group != rewired_ga
            || telegram.service != GroupService::Write
            || telegram.data != [1]
            || !telegram.secured
        {
            return Err(format!("unexpected post-commission group telegram: {telegram:?}"));
        }
        Ok(())
    })
}

// ============================================================================
// Micro System 7 scenarios
// ============================================================================
//
// The micro-System-7 DUT is the no-async `zweidraehte-microdevice`
// stack behind `conformance-dut-micro-system7` — the same MV-0705
// mask the full-fat System 7 DUT runs, so the download compiles from
// the same master-data template with the System 7 model row (forced
// property path). The unload scenario deliberately goes the other way:
// `Downloader::new` with the mask's memory resources drives the
// 0104h load-control window and reads the B6EAh status bytes, so both
// of the micro stack's load-control paths see real client traffic.

/// The micro DUT's product layer, generated from the same definition
/// the DUT boots (see `dut::micro_system7_product`).
fn micro_s7_dut_product() -> Result<ProductData, String> {
    let mtxml = micro_system7_product::generate_mtxml()?;
    ProductData::from_mtxml_str(&mtxml).map_err(|e| format!("reading the generated product file back: {e}"))
}

fn micro_s7_mask(masks: &MaskDb) -> Result<zweidraehte_client::download::MaskData<'_>, String> {
    masks.mask(MaskVersion::System7Tp1).ok_or_else(|| "the master data does not describe MV-0705".to_string())
}

fn scenario_micro_s7_descriptor<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        let result = async {
            let descriptor = conn.device_descriptor_read(0).await.map_err(|e| format!("descriptor read: {e}"))?;
            if descriptor != [0x07, 0x05] {
                return Err(format!("descriptor {descriptor:02X?}, expected mask 0705"));
            }
            // The System 7 signature reads: the plain (uninverted)
            // OptionReg at 0100h, and sixteen-level authorization with
            // the factory key granting level 0.
            let option_reg = conn.memory_read(0x0100, 1).await.map_err(|e| format!("OptionReg: {e}"))?;
            if option_reg != [0x00] {
                return Err(format!("OptionReg {option_reg:02X?}, expected 00h uninverted"));
            }
            let level = conn.authorize(&[0xFF; 4]).await.map_err(|e| format!("authorize: {e}"))?;
            if level != 0 {
                return Err(format!("authorize granted level {level}, expected 0"));
            }

            // 06 Profiles v02.02.01 Annex A.2.2/A.2.3/A.2.6: these
            // objects and identity Properties are mandatory for MV-0705.
            for object in 0..=3 {
                let object_type = conn
                    .property_read(object, pid::OBJECT_TYPE, 1, 1)
                    .await
                    .map_err(|e| format!("object {object} type: {e}"))?;
                if object_type != u16::from(object).to_be_bytes() {
                    return Err(format!("object {object} type {object_type:02X?}, expected {object:04X}"));
                }
            }

            for (object, property, expected, name) in [
                (0, pid::SERIAL_NUMBER, &micro_system7_stack::SERIAL_NUMBER[..], "serial number"),
                (0, pid::MANUFACTURER_ID, &[0x00, 0xFA][..], "manufacturer ID"),
                (0, pid::device::HARDWARE_TYPE, &micro_system7_stack::HARDWARE_TYPE[..], "hardware type"),
                (3, pid::PROGRAM_VERSION, &[0x00, 0xFA, 0x0B, 0x70, 0x01][..], "program version"),
                (3, pid::PEI_TYPE, &[0x00][..], "application PEI type"),
            ] {
                let actual = conn.property_read(object, property, 1, 1).await.map_err(|e| format!("{name}: {e}"))?;
                if actual != expected {
                    return Err(format!("{name} {actual:02X?}, expected {expected:02X?}"));
                }
            }
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        result
    })
}

fn scenario_micro_s7_programming_mode_addressing<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let new_ia = IndividualAddress::new(1, 0, 88);

        control.set_programming_mode(true).await.map_err(|e| format!("prog mode on: {e}"))?;
        let nm = bus.network_management();
        nm.write_individual_address(new_ia).await.map_err(|e| format!("IA write: {e}"))?;
        control.set_programming_mode(false).await.map_err(|e| format!("prog mode off: {e}"))?;

        // RT8 keeps the IA at bytes 1–2 of the address table blob
        // (4001h) — connected management at the new address proves the
        // write, a memory read shows where it landed.
        let mut conn = bus.connect_device(new_ia).await.map_err(|e| format!("connect at new IA: {e}"))?;
        let result = async {
            let slot = conn.memory_read(0x4001, 2).await.map_err(|e| format!("IA slot read: {e}"))?;
            if slot != new_ia.as_bytes() {
                return Err(format!("IA slot {slot:02X?}, expected {:02X?}", new_ia.as_bytes()));
            }
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        result
    })
}

fn scenario_micro_s7_full_download<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let rewired_ga = GroupAddress::from_three_level(3, 1, 1);

        let masks = mask_db()?;
        let mask = micro_s7_mask(&masks)?;
        let product = micro_s7_dut_product()?;

        let mut project = ProjectConfig::new(dut_ia());
        // GO3 is the transmit-capable status object of the fixture.
        project.links = vec![GroupLink { group_address: rewired_ga, com_object: 3 }];
        project.max_apdu = 15; // the micro stack talks standard frames only

        // Sanity: System 7 compiles to the property path — the
        // forced-property override modeled on real 0705h silicon.
        let compiled = compile(&mask, &product, &default_configuration(&product, &project))
            .map_err(|e| format!("compile: {e}"))?;
        if compiled.path() != LoadControlPath::Property {
            return Err("a System 7 download must compile to the property load-control path".to_string());
        }

        program_plain_project_fixture(
            bus,
            &masks,
            &micro_system7_product::generate_mtxml()?,
            dut_ia(),
            Some(micro_system7_stack::SERIAL_NUMBER),
            rewired_ga,
            "5.010",
            3,
            15,
            AddressingMode::Automatic,
        )
        .await?;

        // The procedure ended in a restart; everything must have
        // survived the respawn.
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("reconnect: {e}"))?;
        let checks = async {
            // The three machines the download drove, read through the
            // memory-mapped status bytes; App2 stays untouched.
            let states = conn.memory_read(0xB6EA, 4).await.map_err(|e| format!("load states: {e}"))?;
            if states[..3] != [u8::from(LoadState::Loaded); 3] || states[3] != u8::from(LoadState::Unloaded) {
                return Err(format!("load states {states:02X?}, expected [Loaded ×3, Unloaded]"));
            }
            // The RT8 address table at 4000h: length 2 counts the IA
            // and the single rewired GA.
            let adt = conn.memory_read(0x4000, 5).await.map_err(|e| format!("ADT read: {e}"))?;
            if adt != [0x02, 0x10, 0x01, 0x19, 0x01] {
                return Err(format!("ADT {adt:02X?}, expected [02 10 01 19 01]"));
            }
            // The System 7 group object table at the product address:
            // positional over ASAPs 0..=7 (slot 0 spare), so the count
            // covers all eight rows.
            let cot = conn.memory_read(0x4200, 3).await.map_err(|e| format!("COT read: {e}"))?;
            if cot[0] != 8 {
                return Err(format!("COT count {}, expected 8", cot[0]));
            }
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        checks?;

        // The wiring is live: GO3 transmitting must hit the rewired GA.
        let mut events = bus.group_events();
        control.trigger_group_write(3).await.map_err(|e| format!("trigger: {e}"))?;
        let telegram = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .map_err(|_| "no group telegram after trigger".to_string())?
            .map_err(|e| format!("group events: {e}"))?;
        if telegram.group != rewired_ga || telegram.service != GroupService::Write {
            return Err(format!("unexpected telegram {:?} on {}", telegram.service, telegram.group));
        }
        Ok(())
    })
}

fn scenario_micro_s7_secure_commission<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        const TOOL_KEY: [u8; 16] = [0x44; 16];
        const GROUP_KEY: [u8; 16] = [0x55; 16];
        const SECURITY_IO: InterfaceObjectType = InterfaceObjectType::Security;
        const SECURITY_OCCURRENCE: u16 = 1;

        let group = GroupAddress::from_three_level(3, 1, 1);

        // Enter the real unprovisioned state while retaining the assigned IA.
        control.master_reset(7).await.map_err(|e| format!("factory reset while retaining IA: {e}"))?;
        bus.set_device_security(
            dut_ia(),
            SecurityEntry::secure_with_fdsk(SECURE_FDSK, micro_system7_stack::SERIAL_NUMBER),
        )
        .await
        .map_err(|e| format!("install FDSK: {e}"))?;

        let mut first = bus.connect_device(dut_ia()).await.map_err(|e| format!("FDSK sync: {e}"))?;
        let descriptor = first.device_descriptor_read(0).await.map_err(|e| format!("secure descriptor: {e}"))?;
        if descriptor != [0x07, 0x05] {
            close_quietly(first).await;
            return Err(format!("descriptor {descriptor:02X?}, expected mask 0705"));
        }
        let max_apdu = first
            .property_read(0, pid::device::MAX_APDU_LENGTH, 1, 1)
            .await
            .map_err(|e| format!("maximum APDU: {e}"))?;
        if max_apdu != 40u16.to_be_bytes() {
            close_quietly(first).await;
            return Err(format!("secure maximum APDU {max_apdu:02X?}, expected 0028h"));
        }
        first.write_tool_key(TOOL_KEY).await.map_err(|e| format!("tool-key rotation: {e}"))?;
        close_quietly(first).await;

        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let masks = mask_db()?;
        let mask = micro_s7_mask(&masks)?;
        let product = ProductData::from_mtxml_str(&micro_system7_product::generate_secure_mtxml()?)
            .map_err(|e| format!("reading secure micro System 7 product back: {e}"))?;

        let mut project = ProjectConfig::new(dut_ia());
        // Object 3 is the fixture's byte-sized, fully enabled GO. System 7
        // has a real slot zero, so its GO-security flag is element four.
        project.links = vec![GroupLink { group_address: group, com_object: 3 }];
        project.max_apdu = 40;
        project.security = Some(DownloadSecurityConfig::new(vec![(group, GROUP_KEY)], vec![(tester_ia(), 0)], vec![
            GroupObjectSecurity { com_object: 3, protection: GroupObjectProtection::AuthenticationConfidentiality },
        ]));

        bus.configure_device(&mask, &product, &default_configuration(&product, &project))
            .await
            .map_err(|e| format!("secure System 7 download: {e}"))?;
        bus.set_group_key(group, GROUP_KEY).await.map_err(|e| format!("install group key: {e}"))?;

        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("post-download sync: {e}"))?;
        let checks = async {
            let load_state = conn
                .property_ext_read(SECURITY_IO, SECURITY_OCCURRENCE, pid::LOAD_STATE_CONTROL, 1, 1)
                .await
                .map_err(|e| format!("Security IO load state: {e}"))?;
            if load_state != [u8::from(LoadState::Loaded)] {
                return Err(format!("Security IO state {load_state:02X?}, expected Loaded"));
            }
            for (property, expected, name) in [
                (pid::security::GROUP_KEY_TABLE, 1u16, "group-key table"),
                (pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 1u16, "SIAT"),
                (pid::security::GO_SECURITY_FLAGS, 8u16, "GO security flags"),
            ] {
                let count = conn
                    .property_ext_read(SECURITY_IO, SECURITY_OCCURRENCE, property, 0, 1)
                    .await
                    .map_err(|e| format!("{name} count: {e}"))?;
                if count != expected.to_be_bytes() {
                    return Err(format!("{name} count {count:02X?}, expected {expected}"));
                }
            }
            let mode = conn
                .function_property_ext_state_read(SECURITY_IO, SECURITY_OCCURRENCE, pid::security::SECURITY_MODE, &[
                    0, 0,
                ])
                .await
                .map_err(|e| format!("Security Mode: {e}"))?;
            if mode.return_code != 0 || mode.data != [0, 1] {
                return Err(format!(
                    "Security Mode response code {:02X}, data {:02X?}; expected enabled",
                    mode.return_code, mode.data
                ));
            }
            let cot = conn.memory_read(0x4200, 3).await.map_err(|e| format!("COT read: {e}"))?;
            if cot[0] != 8 {
                return Err(format!("COT count {}, expected 8", cot[0]));
            }
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        checks?;

        bus.group_write(group, &[0x5A], GroupValueEncoding::Full)
            .await
            .map_err(|e| format!("secure group write to DUT: {e}"))?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut events = bus.group_events();
        control.trigger_group_write(3).await.map_err(|e| format!("secure group trigger: {e}"))?;
        let telegram = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .map_err(|_| "no secure group telegram after trigger".to_string())?
            .map_err(|e| format!("group events: {e}"))?;
        if telegram.group != group
            || telegram.service != GroupService::Write
            || telegram.data != [0x5A]
            || !telegram.secured
        {
            return Err(format!("unexpected post-commission group telegram: {telegram:?}"));
        }

        // Reboot the persisted split, then make the application download a
        // second time. A counter reset or a lost loaded/run state would make
        // the following button telegram disappear or be rejected as a replay.
        control.power_cycle().await.map_err(|e| format!("power cycle before re-download: {e}"))?;
        bus.configure_device(&mask, &product, &default_configuration(&product, &project))
            .await
            .map_err(|e| format!("secure System 7 re-download: {e}"))?;

        // Communication-object values are RAM and intentionally do not
        // survive the power cycle. Re-seed the fixture value before asking it
        // to transmit; the persistence assertion is about the tables and
        // replay counter, not volatile application data.
        bus.group_write(group, &[0x5A], GroupValueEncoding::Full)
            .await
            .map_err(|e| format!("secure group write after re-download: {e}"))?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut events = bus.group_events();
        control.trigger_group_write(3).await.map_err(|e| format!("post-re-download secure group trigger: {e}"))?;
        let telegram = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .map_err(|_| "no secure group telegram after power cycle and re-download".to_string())?
            .map_err(|e| format!("group events after re-download: {e}"))?;
        if telegram.group != group
            || telegram.service != GroupService::Write
            || telegram.data != [0x5A]
            || !telegram.secured
        {
            return Err(format!("unexpected post-re-download group telegram: {telegram:?}"));
        }
        Ok(())
    })
}

/// Run an ordinary mask-0705 scenario against the secure composition in its
/// uncommissioned state. `full_reset` restores the operator-provisioned AN158
/// image for EITT, so the configuration runner uses the device's local reset
/// path to disable Security Mode and revert to the FDSK first.
fn run_micro_s7_secure_plain<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
    scenario: Scenario,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        control.master_reset(7).await.map_err(|e| format!("factory reset while retaining IA: {e}"))?;
        scenario(bus, control).await
    })
}

fn scenario_micro_s7_secure_plain_descriptor<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    run_micro_s7_secure_plain(bus, control, scenario_micro_s7_descriptor)
}

fn scenario_micro_s7_secure_plain_addressing<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    run_micro_s7_secure_plain(bus, control, scenario_micro_s7_programming_mode_addressing)
}

fn scenario_micro_s7_secure_plain_download<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    run_micro_s7_secure_plain(bus, control, scenario_micro_s7_full_download)
}

fn scenario_micro_s7_secure_plain_unload<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    run_micro_s7_secure_plain(bus, control, scenario_micro_s7_unload_all)
}

fn scenario_micro_s7_secure_plain_oversized<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    run_micro_s7_secure_plain(bus, control, scenario_micro_s7_oversized_segment)
}

fn scenario_micro_s7_unload_all<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let masks = mask_db()?;
        let mask = micro_s7_mask(&masks)?;
        // The mask's memory resources put the Downloader on the
        // memory-mapped path: records to 0104h, states from B6EAh —
        // the micro stack's second load-control path under real
        // client traffic.
        let resources = dut_resources(&masks)?;

        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        let result = async {
            let unload = assemble(&mask, &ProductData::default(), ProcedureKind::UnloadAll)
                .map_err(|e| format!("assembling Unload-all from the mask: {e}"))?;
            let mut downloader = Downloader::new(&mut conn, resources, 15);
            downloader.run(&unload, &DeviceImage::new()).await.map_err(|e| format!("unload: {e}"))?;

            let states = conn.memory_read(0xB6EA, 4).await.map_err(|e| format!("load states: {e}"))?;
            if states != [u8::from(LoadState::Unloaded); 4] {
                return Err(format!("load states {states:02X?}, expected all Unloaded"));
            }
            // RT8 unload keeps only the IA slot in the length and
            // spares its bytes 1–2.
            let adt = conn.memory_read(0x4000, 3).await.map_err(|e| format!("ADT read: {e}"))?;
            if adt != [0x01, 0x10, 0x01] {
                return Err(format!("ADT head {adt:02X?}, expected IA-only mute length"));
            }
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        result
    })
}

fn scenario_micro_s7_oversized_segment<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let resources = dut_resources(&mask_db()?)?;

        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        let result = async {
            let mut downloader = Downloader::new(&mut conn, resources, 15);
            // The EITT-capable host fixture backs 4000h..7FFFh so its
            // management templates can probe certification memory. Request
            // 20 KiB from 4000h to cross that actual boundary: allocation
            // must be rejected and throw the machine into Error.
            let doomed = [
                Instruction::LsmEvent { lsm: LsmTarget::Index(1), event: LoadEvent::StartLoading },
                Instruction::AbsSegment { lsm: LsmTarget::Index(1), segment: AbsSegment::eeprom(0x4000, 0x5000) },
            ];
            match downloader.run(&doomed, &DeviceImage::new()).await {
                Err(ClientError::LoadState {
                    machine: MachineRef::Machine(LsmMachine::AddressTable),
                    state: LoadState::Err,
                    ..
                }) => {}
                other => return Err(format!("expected a LoadState error, got {other:?}")),
            }
            // Recovery: Unload brings the machine back to a defined
            // state.
            let mut downloader = Downloader::new(&mut conn, resources, 15);
            downloader
                .run(
                    &[Instruction::LsmEvent { lsm: LsmTarget::Index(1), event: LoadEvent::Unload }],
                    &DeviceImage::new(),
                )
                .await
                .map_err(|e| format!("recovery unload: {e}"))?;
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        result
    })
}

// ============================================================================
// System B scenarios
// ============================================================================

/// The System B DUT's product layer, generated in-process from the
/// same constants the plain DUT stack is built from.
fn system_b_product() -> Result<ProductData, String> {
    let mtxml = system_b_product::generate_mtxml()?;
    ProductData::from_mtxml_str(&mtxml).map_err(|e| format!("reading the generated product file back: {e}"))
}

fn scenario_system_b_descriptor<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        let result = conn.device_descriptor_read(0).await;
        close_quietly(conn).await;
        let descriptor = result.map_err(|e| format!("descriptor read: {e}"))?;
        if descriptor != [0x07, 0xB0] {
            return Err(format!("descriptor {descriptor:02X?}, expected mask 07B0"));
        }
        Ok(())
    })
}

/// The System B download: relative allocation over
/// `PID_LOAD_STATE_CONTROL`, bases read back from
/// `PID_TABLE_REFERENCE`, tables written where the *device* put them.
fn scenario_system_b_full_download<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let rewired_ga = GroupAddress::from_three_level(4, 2, 2);

        let masks = mask_db()?;
        let mask = masks
            .mask(MaskVersion::SystemBTp1)
            .ok_or_else(|| "the master data does not describe MV-07B0".to_string())?;
        let product = system_b_product()?;

        let mut project = ProjectConfig::new(dut_ia());
        project.links = vec![GroupLink { group_address: rewired_ga, com_object: 1 }];
        project.max_apdu = 254;

        // Sanity: this really is the relative path — no absolute
        // regions, content keyed by interface object instead. Compiled
        // once here for the assertion; `configure_device` compiles its
        // own, from the same inputs.
        let compiled = compile(&mask, &product, &default_configuration(&product, &project))
            .map_err(|e| format!("compile: {e}"))?;
        if compiled.image.regions().count() != 0 {
            return Err("a System B image must carry no absolute regions".to_string());
        }
        if compiled.image.relative(1).is_none() {
            return Err("no address table content compiled for object 1".to_string());
        }
        if compiled.path() != LoadControlPath::Property {
            return Err("System B must compile to the property load-control path".to_string());
        }

        // Drive it through the public API — the same call a real
        // caller makes — which now selects the property path itself.
        let report = program_plain_project_fixture(
            bus,
            &masks,
            &system_b_product::generate_mtxml()?,
            dut_ia(),
            Some(systemb_stack::device_info::SERIAL_NUMBER),
            rewired_ga,
            "1.001",
            1,
            254,
            AddressingMode::Automatic,
        )
        .await?;
        if report.device_mask != MaskVersion::SystemBTp1 || report.load_control_path != LoadControlPath::Property {
            return Err(format!(
                "unexpected programming report: mask {:?}, path {:?}",
                report.device_mask, report.load_control_path
            ));
        }

        // Reconnect to the restarted device and check what survived.
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("reconnect: {e}"))?;
        let checks = async {
            // Every table machine reports Loaded through the property
            // path it was driven with.
            for obj in [1u8, 2, 3] {
                let state = conn
                    .property_read(obj, pid::LOAD_STATE_CONTROL, 1, 1)
                    .await
                    .map_err(|e| format!("load state of object {obj}: {e}"))?;
                if state.first() != Some(&u8::from(LoadState::Loaded)) {
                    return Err(format!("object {obj} load state {state:02X?}, expected Loaded"));
                }
            }
            // Read each table back from the base the *device* chose,
            // which is the whole point of the relative path.
            let read_table = async |conn: &mut DeviceConnection, obj: u8, len: u8| -> Result<Vec<u8>, String> {
                let base = conn
                    .property_read(obj, pid::TABLE_REFERENCE, 1, 1)
                    .await
                    .map_err(|e| format!("base of {obj}: {e}"))?;
                let addr = u16::from_be_bytes([base[2], base[3]]);
                conn.memory_read(addr, len).await.map_err(|e| format!("read-back of object {obj}: {e}"))
            };

            // Address table: one entry, the rewired group address.
            let adt = read_table(&mut conn, 1, 4).await?;
            if adt != [0x00, 0x01, 0x22, 0x02] {
                return Err(format!("address table {adt:02X?}, expected one entry for 4/2/2"));
            }
            // Association table: TSAP 1 → ASAP 1, both 16-bit.
            let ast = read_table(&mut conn, 2, 6).await?;
            if ast != [0x00, 0x01, 0x00, 0x01, 0x00, 0x01] {
                return Err(format!("association table {ast:02X?}, expected TSAP 1 -> ASAP 1"));
            }
            // Group object table: object 1 must carry transmit-capable
            // flags, or the trigger below cannot produce a telegram.
            let cot = read_table(&mut conn, 3, 4).await?;
            if cot[0..2] != [0x00, 0x04] {
                return Err(format!("group object table count {:02X?}, expected 4 objects", &cot[0..2]));
            }
            if cot[2] & 0x40 == 0 {
                return Err(format!("object 1 flags {:02X} have transmit disabled", cot[2]));
            }
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        checks?;

        // The wiring is live: the DUT transmitting on ASAP 1 hits the
        // group address this download put in its tables.
        let mut events = bus.group_events();
        control.trigger_group_write(1).await.map_err(|e| format!("trigger: {e}"))?;
        let telegram = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .map_err(|_| "no group telegram after trigger".to_string())?
            .map_err(|e| format!("group events: {e}"))?;
        if telegram.group != rewired_ga {
            return Err(format!("telegram on {}, expected the rewired {rewired_ga}", telegram.group));
        }
        Ok(())
    })
}

/// Unload-all from the mask's own template, driven over
/// `PID_LOAD_STATE_CONTROL`.
///
/// The MV-07B0 template is the one with the `LdCtrlMapError` guards
/// around `LdCtrlUnload LsmIdx="5"` — the published shape, taken
/// as-is. On this DUT machine 5 (the PEI program) exists, so the
/// guarded step succeeds; the guards still exercise the MapError
/// window plumbing end to end.
fn scenario_system_b_unload_all<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let masks = mask_db()?;
        let mask = masks
            .mask(MaskVersion::SystemBTp1)
            .ok_or_else(|| "the master data does not describe MV-07B0".to_string())?;

        // Unload comes from the mask alone: tearing down needs no
        // product knowledge (unmatched merge points splice to nothing).
        let unload = assemble(&mask, &ProductData::default(), ProcedureKind::UnloadAll)
            .map_err(|e| format!("assembling Unload-all from the mask: {e}"))?;

        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        let result = async {
            let mut downloader = Downloader::with_path(&mut conn, LoadControlPath::Property, 254);
            downloader.run(&unload, &DeviceImage::new()).await.map_err(|e| format!("unload: {e}"))?;

            // Every machine reports Unloaded through the same property
            // it was driven with — including 5, which this DUT has.
            for obj in [1u8, 2, 3, 4, 5] {
                let state = conn
                    .property_read(obj, pid::LOAD_STATE_CONTROL, 1, 1)
                    .await
                    .map_err(|e| format!("load state of object {obj}: {e}"))?;
                if state.first() != Some(&u8::from(LoadState::Unloaded)) {
                    return Err(format!("object {obj} load state {state:02X?}, expected Unloaded"));
                }
            }
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        result
    })
}

/// The error path of relative allocation: a request the device cannot
/// hold must throw the machine into Error — surfaced as a typed
/// `LoadState` error read back over the property path — and Unload
/// must recover it.
fn scenario_system_b_oversized_segment<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        let result = async {
            // A 64 KiB address table into an arena of a few hundred
            // bytes: the allocation must be refused.
            let doomed = [
                Instruction::LsmEvent { lsm: LsmTarget::Index(1), event: LoadEvent::StartLoading },
                Instruction::RelSegment { lsm: LsmTarget::Index(1), segment: RelSegment::new(0xFFFF) },
            ];
            let mut downloader = Downloader::with_path(&mut conn, LoadControlPath::Property, 254);
            match downloader.run(&doomed, &DeviceImage::new()).await {
                Err(ClientError::LoadState { machine: MachineRef::Object(1), state: LoadState::Err, .. }) => {}
                other => return Err(format!("expected a LoadState error, got {other:?}")),
            }
            // Recovery: Unload brings the machine back to a defined
            // state.
            let mut downloader = Downloader::with_path(&mut conn, LoadControlPath::Property, 254);
            downloader
                .run(
                    &[Instruction::LsmEvent { lsm: LsmTarget::Index(1), event: LoadEvent::Unload }],
                    &DeviceImage::new(),
                )
                .await
                .map_err(|e| format!("recovery unload: {e}"))?;
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        result
    })
}

/// Re-commissioning without a factory reset — what a real ETS
/// re-download does. The device is Loaded, `PID_TABLE_REFERENCE` is
/// non-zero, and the Load-all template's own unload steps must tear
/// the old configuration down before the new allocation.
fn scenario_system_b_redownload<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let first_ga = GroupAddress::from_three_level(4, 2, 2);
        let second_ga = GroupAddress::from_three_level(5, 3, 3);

        let masks = mask_db()?;
        let mask = masks
            .mask(MaskVersion::SystemBTp1)
            .ok_or_else(|| "the master data does not describe MV-07B0".to_string())?;
        let product = system_b_product()?;

        let mut project = ProjectConfig::new(dut_ia());
        project.max_apdu = 254;

        // First commissioning, from factory state.
        project.links = vec![GroupLink { group_address: first_ga, com_object: 1 }];
        bus.configure_device(&mask, &product, &default_configuration(&product, &project))
            .await
            .map_err(|e| format!("first download: {e}"))?;

        // Second download straight onto the configured device.
        project.links = vec![GroupLink { group_address: second_ga, com_object: 1 }];
        bus.configure_device(&mask, &product, &default_configuration(&product, &project))
            .await
            .map_err(|e| format!("re-download: {e}"))?;

        // The old address must be *gone*, not shadowed: exactly one
        // table entry, and it is the new group address.
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("reconnect: {e}"))?;
        let checks = async {
            let base =
                conn.property_read(1, pid::TABLE_REFERENCE, 1, 1).await.map_err(|e| format!("table reference: {e}"))?;
            let addr = u16::from_be_bytes([base[2], base[3]]);
            let adt = conn.memory_read(addr, 4).await.map_err(|e| format!("address table read-back: {e}"))?;
            if adt != [0x00, 0x01, 0x2B, 0x03] {
                return Err(format!("address table {adt:02X?}, expected one entry for 5/3/3"));
            }
            Ok(())
        }
        .await;
        close_quietly(conn).await;
        checks?;

        // And the live proof: the DUT transmitting on ASAP 1 hits the
        // second download's address.
        let mut events = bus.group_events();
        control.trigger_group_write(1).await.map_err(|e| format!("trigger: {e}"))?;
        let telegram = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .map_err(|_| "no group telegram after trigger".to_string())?
            .map_err(|e| format!("group events: {e}"))?;
        if telegram.group != second_ga {
            return Err(format!("telegram on {}, expected the re-downloaded {second_ga}", telegram.group));
        }
        Ok(())
    })
}
