//! Configuration-download conformance runner.
//!
//! The third runner besides `conformance-runner` (hand-written suites)
//! and `conformance-eitt` (vendor XML templates): where those two
//! drive the DUT with scripted telegrams, this one runs the **real
//! `zweidraehte-client` library** — `KnxBus`, `DeviceConnection`, the
//! commissioning engine — against the System 7 and System B DUTs through
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

use std::collections::BTreeMap;
use std::env;
use std::process::ExitCode;
use std::time::Duration;

use log::LevelFilter;
use zweidraehte_project::ProgrammingSection;

use zweidraehte_client::commissioning::inspection::{MemoryAddress, MemoryService};
use zweidraehte_client::commissioning::inspection::{OperationData, OperationTarget, ProcedureOperation};
use zweidraehte_client::commissioning::{
    Commissioner, CommissionerOptions, CommissioningCancellation, CommissioningEvent, CommissioningIntent,
    CommissioningSectionOutcome, CommissioningStage, CompileOptions, CompiledProgram, DownloadMode, ExecutionReport,
    ImageSpace, ManagementAccessOptions, ManagementModel, MutationStatus, ObjectSelector, PreparationOptions,
    ProgramSections, ProgrammingInput, ProgrammingModePolling, ResourceManagementStyle, RestartKind, TargetSelection,
    UnloadMode,
};
use zweidraehte_client::configuration::ResolvedKeyMaterial;
use zweidraehte_client::configuration::{
    EncodedConfiguration, EncodedParameter, GroupObjectProtection, GroupObjectSecurity, InstallationConfiguration,
    MaterializedDevice, ObjectMembership, SecurityConfig as DownloadSecurityConfig,
};
use zweidraehte_client::project::{BatchSelection, ProjectMasterData, ProjectPlanner, ProjectProduct};
use zweidraehte_client::{
    ConnectorInfo, DeviceConnection, GroupAddress, GroupService, GroupValueEncoding, IndividualAddress,
    InterfaceObjectType, KnxBus, SecurityEntry,
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
use zweidraehte_ets_files::product::{ApplicationProgramRelation, ManufacturerContent, ProductData, SelectedProduct};
use zweidraehte_ets_files::runtime::parse_application_program;
use zweidraehte_ets_files::schema::HardwareKnx;
use zweidraehte_knxprod::KnxprodOutput;
use zweidraehte_microdevice::frame::{EXTENDED_APDU, SYSTEM7_APDU};
use zweidraehte_project::{
    AuthoredProject, KeyEncoding, KeyEpoch, KeyId, KeyKind, KeyMaterialSource, KeyMetadata, KeyOrigin, KeyRecord,
    KeyScope, KeyState, KeyStoreError, ProductReference, ProjectDeviceId, SecretBytes,
};
use zweidraehte_proto::messages::apdu::load_control::{
    AbsSegment, LoadControlRecord, LoadEvent, LoadState, LsmMachine, MemLoadControlRecord, RelSegment,
};
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

/// Run one complete application operation through the public commissioning
/// boundary. The product's mask and application metadata select the exact
/// profile inside the stable current Master Data catalog.
async fn commission_operation(
    bus: &KnxBus,
    device: MaterializedDevice,
    intent: CommissioningIntent,
    target: TargetSelection,
    allow_plaintext: bool,
    context: &str,
) -> Result<ExecutionReport, String> {
    commission_operation_with_sections(bus, device, intent, target, allow_plaintext, None, context).await
}

async fn commission_operation_with_sections(
    bus: &KnxBus,
    device: MaterializedDevice,
    intent: CommissioningIntent,
    target: TargetSelection,
    allow_plaintext: bool,
    automatic_sections: Option<ProgramSections>,
    context: &str,
) -> Result<ExecutionReport, String> {
    let commissioner = Commissioner::new(bus).with_options(CommissionerOptions {
        scan_window: Duration::from_millis(150),
        restart_delay: Duration::from_millis(50),
        ..CommissionerOptions::default()
    });
    let expected_target = target.clone();
    let input = ProgrammingInput::new(device, intent, CompileOptions {
        target,
        automatic_sections,
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
    });
    let options = PreparationOptions::new(ManagementAccessOptions::new().allow_plaintext(allow_plaintext));
    let cancellation = CommissioningCancellation::default();

    // Preparation is contractually read-only. Retaining its events makes the
    // conformance scenario prove that discovery, exact profile selection and
    // complete compilation all happened before execution was allowed.
    let mut preparation_events = Vec::new();
    let prepared = commissioner
        .prepare(input, options, &cancellation, |event| preparation_events.push(event))
        .await
        .map_err(|error| format!("{context}: preparing commissioning: {error}"))?;
    for expected in [
        CommissioningStage::DiscoveringTarget,
        CommissioningStage::IdentifyingProfile,
        CommissioningStage::CompilingPlan,
        CommissioningStage::ValidatingDifferential,
    ] {
        if !preparation_events
            .iter()
            .any(|event| matches!(event, CommissioningEvent::Stage(stage) if *stage == expected))
        {
            return Err(format!("{context}: preparation emitted no {expected:?} stage"));
        }
    }

    let mut execution_events = Vec::new();
    let report = commissioner
        .execute(prepared, &cancellation, |event| execution_events.push(event))
        .await
        .map_err(|error| format!("{context}: executing commissioning: {error}"))?;

    if report.plan.intent() != intent || report.plan.target() != &expected_target {
        return Err(format!(
            "{context}: report changed the requested intent or target: {:?}, {:?}",
            report.plan.intent(),
            report.plan.target()
        ));
    }
    match intent {
        CommissioningIntent::Download(DownloadMode::Full)
        | CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full) => {
            if !report.plan.is_full_program_scope() {
                return Err(format!(
                    "{context}: full download resolved a partial program scope {:?}",
                    report.plan.program_sections()
                ));
            }
        }
        CommissioningIntent::Unload(_) => {
            if report.plan.program_sections().is_some() {
                return Err(format!(
                    "{context}: unload unexpectedly selected application sections {:?}",
                    report.plan.program_sections()
                ));
            }
        }
        CommissioningIntent::Download(DownloadMode::Partial(sections)) => {
            if report.plan.program_sections() != Some(sections) || report.plan.is_full_program_scope() {
                return Err(format!("{context}: partial operation changed its exact scope"));
            }
        }
        CommissioningIntent::Download(DownloadMode::Automatic) => {
            let required = automatic_sections.ok_or_else(|| format!("{context}: missing automatic scope evidence"))?;
            if !report.plan.program_sections().is_some_and(|sections| sections.contains(required)) {
                return Err(format!("{context}: automatic operation omitted a requested section"));
            }
        }
        other => return Err(format!("{context}: unsupported conformance helper intent {other:?}")),
    }
    if report.effects().mutation_status() != MutationStatus::Complete {
        return Err(format!("{context}: successful report retained status {:?}", report.effects().mutation_status()));
    }
    if !execution_events.iter().any(|event| matches!(event, CommissioningEvent::Stage(CommissioningStage::Complete))) {
        return Err(format!("{context}: execution emitted no Complete stage"));
    }

    let procedure = report.procedure.as_ref().ok_or_else(|| format!("{context}: operation executed no procedure"))?;
    let planned_procedure =
        report.plan.procedure().ok_or_else(|| format!("{context}: operation compiled no procedure"))?;
    let planned_steps = planned_procedure.steps.len();
    if procedure.steps_completed != planned_steps {
        return Err(format!("{context}: procedure completed {}/{} steps", procedure.steps_completed, planned_steps));
    }

    // The completed procedure exercises the public Commissioner's selected
    // access policy. A System B target's confirmed-restart capability must not
    // silently replace Basic on a plain application load, while its separate
    // network phase retains the capability-derived service.
    if report.plan.profile().management_model() == ManagementModel::SystemB
        && matches!(intent, CommissioningIntent::Download(_) | CommissioningIntent::AssignAddressAndDownload(_))
    {
        let expected_restart =
            if report.discovered.secure_management { RestartKind::Confirmed } else { RestartKind::Basic };
        let program_restarts: Vec<_> = planned_procedure
            .steps
            .iter()
            .filter_map(|step| match &step.operation {
                ProcedureOperation::Restart { kind } => Some(*kind),
                _ => None,
            })
            .collect();
        if program_restarts.is_empty() || program_restarts.iter().any(|kind| *kind != expected_restart) {
            return Err(format!(
                "{context}: System B program restarts {program_restarts:?}, expected {expected_restart:?} \
                 for selected secure management {}",
                report.discovered.secure_management,
            ));
        }
        if report.plan.network_restart_kind() != RestartKind::Confirmed {
            return Err(format!(
                "{context}: System B network restart {:?}, expected Confirmed",
                report.plan.network_restart_kind(),
            ));
        }
    }

    if matches!(intent, CommissioningIntent::Download(DownloadMode::Partial(_) | DownloadMode::Automatic)) {
        let sections = report.plan.program_sections().expect("download selects sections");
        let expected = |section| {
            if sections.contains(section) {
                CommissioningSectionOutcome::Programmed
            } else {
                CommissioningSectionOutcome::NotRequested
            }
        };
        if report.section(ProgrammingSection::Address) != CommissioningSectionOutcome::NotRequested
            || [
                (ProgramSections::APPLICATION_PROGRAM_1, ProgrammingSection::ApplicationProgram1),
                (ProgramSections::APPLICATION_PROGRAM_2, ProgrammingSection::ApplicationProgram2),
                (ProgramSections::PARAMETERS, ProgrammingSection::Parameters),
                (ProgramSections::GROUP_COMMUNICATION, ProgrammingSection::GroupCommunication),
                (ProgramSections::CONFIGURATION, ProgrammingSection::Configuration),
            ]
            .into_iter()
            .any(|(flag, section)| report.section(section) != expected(flag))
        {
            return Err(format!(
                "{context}: scoped operation reported unrelated section outcomes: {:?}; {}",
                report.sections,
                image_evidence_gaps(&report)
            ));
        }
        return Ok(report);
    }

    let expected_sections = match intent {
        CommissioningIntent::Download(DownloadMode::Full) => {
            (CommissioningSectionOutcome::NotRequested, CommissioningSectionOutcome::Programmed)
        }
        CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full) => {
            (CommissioningSectionOutcome::Programmed, CommissioningSectionOutcome::Programmed)
        }
        CommissioningIntent::Unload(UnloadMode::Application) => {
            (CommissioningSectionOutcome::NotRequested, CommissioningSectionOutcome::Cleared)
        }
        CommissioningIntent::Unload(UnloadMode::AllConfiguration) => {
            (CommissioningSectionOutcome::Cleared, CommissioningSectionOutcome::Cleared)
        }
        other => return Err(format!("{context}: unsupported conformance helper intent {other:?}")),
    };
    if report.section(ProgrammingSection::Address) != expected_sections.0
        || [
            ProgrammingSection::ApplicationProgram1,
            ProgrammingSection::Parameters,
            ProgrammingSection::GroupCommunication,
            ProgrammingSection::Configuration,
        ]
        .into_iter()
        .any(|section| {
            // Legacy application unload invalidates the load machines while
            // preserving network configuration. A factory reset also clears it.
            let expected = if intent == CommissioningIntent::Unload(UnloadMode::Application)
                && section == ProgrammingSection::Configuration
                && !report.plan.procedure().is_some_and(|procedure| {
                    procedure.steps.iter().any(|step| {
                        matches!(step.operation, ProcedureOperation::MasterReset { erase_code: 2 | 7, channel: 0 })
                    })
                }) {
                CommissioningSectionOutcome::NotRequested
            } else {
                expected_sections.1
            };
            report.section(section) != expected
        })
    {
        return Err(format!(
            "{context}: unexpected successful section outcomes: {:?}; {}",
            report.sections,
            image_evidence_gaps(&report)
        ));
    }

    Ok(report)
}

fn image_evidence_gaps(report: &ExecutionReport) -> String {
    let desired = report.plan.image();
    let mut gaps = Vec::new();
    for owner in desired.ownership() {
        let mut unknown = 0;
        let mut different = 0;
        let mut differing_offsets = Vec::new();
        for (offset, mask) in owner.mask.iter().enumerate() {
            let mut at = owner.location.clone();
            at.offset += offset as u32;
            let wanted = desired.byte(&at).expect("owned byte is present").0;
            let (actual, known) = report.programmed_image.byte(&at).unwrap_or_default();
            unknown += (mask & !known).count_ones();
            let differing_bits = ((wanted ^ actual) & mask & known).count_ones();
            different += differing_bits;
            if differing_bits != 0 {
                differing_offsets.push(at.offset);
            }
        }
        if unknown != 0 || different != 0 {
            // Report geometry and bit counts only; credentials or image byte
            // values never belong in a failed conformance assertion.
            gaps.push(format!(
                "{:?} {:?}+{}: {unknown} unknown/{different} different bits at {differing_offsets:?}",
                owner.section,
                owner.location,
                owner.mask.len()
            ));
        }
    }
    gaps.join("; ")
}

/// Assemble a direct fixture device with the product's default object roster.
///
/// Planned project devices arrive bound; a direct fixture selects the
/// product's installation document here, before it is assembled.
fn materialized_device(
    product: &ProductData,
    installation: &InstallationConfiguration,
    parameters: Vec<EncodedParameter>,
    key_material: ResolvedKeyMaterial,
) -> Result<MaterializedDevice, String> {
    let document = zweidraehte_ets_files::master_data::MasterDataLoadRequest::Product(product)
        .load()
        .map_err(|error| format!("loading versioned Master Data: {error}"))?;
    let product =
        product.clone().bind_master_data(document).map_err(|error| format!("associating Master Data: {error}"))?;
    let encoded =
        EncodedConfiguration { parameters, com_objects: product.com_objects().to_vec(), ..Default::default() };
    Ok(MaterializedDevice::from_parts(product, installation.clone(), encoded).into_keyed(key_material))
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
            "BCU1 programming-button download through Commissioner",
            scenario_bcu1_programmer_download,
        )]),
        ("System 7 (mask 0705)", DutMode::System7, &[
            ("device descriptor smoke read", scenario_system7_descriptor),
            ("programming-mode individual addressing", scenario_system7_programming_mode_addressing),
            ("full download rewires the device", scenario_system7_full_download),
            ("unload-all declares the tables invalid", scenario_system7_unload_all),
            ("oversized segment allocation enters Error", scenario_system7_oversized_segment),
        ]),
        ("System 7 (mask 0705, Data Secure capable)", DutMode::System7Secure, &[(
            "secure System 7 commissioning through Commissioner",
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
        ("BCU2 (mask 0021, Commissioner isolation)", DutMode::Bcu2Secure, &[(
            "BCU2 0021 secure commissioning through Commissioner",
            scenario_bcu2_secure_programmer,
        )]),
        ("Micro System 7 (mask 0705, micro stack)", DutMode::MicroSystem7, &[
            ("micro-S7 descriptor smoke read", scenario_micro_s7_descriptor::<SYSTEM7_APDU>),
            ("micro-S7 programming-mode individual addressing", scenario_micro_s7_programming_mode_addressing),
            ("micro-S7 download over the memory path", scenario_micro_s7_full_download::<SYSTEM7_APDU>),
            ("micro-S7 unload-all over the memory window", scenario_micro_s7_unload_all),
            ("micro-S7 oversized segment allocation enters Error", scenario_micro_s7_oversized_segment),
        ]),
        ("Micro System 7 (mask 0705, Data Secure capable)", DutMode::MicroSystem7Secure, &[
            ("micro-S7 secure composition descriptor in plain mode", scenario_micro_s7_secure_plain_descriptor),
            (
                "micro-S7 secure composition individual addressing in plain mode",
                scenario_micro_s7_secure_plain_addressing,
            ),
            ("micro-S7 secure composition plain download", scenario_micro_s7_secure_plain_download),
            ("micro-S7 secure composition plain unload", scenario_micro_s7_secure_plain_unload),
            ("micro-S7 secure composition oversized allocation enters Error", scenario_micro_s7_secure_plain_oversized),
            ("micro-S7 low-level secure persistence and group regression", scenario_micro_s7_secure_commission),
        ]),
        ("Micro System 7 (Commissioner isolation)", DutMode::MicroSystem7Secure, &[(
            "micro-S7 secure commissioning through Commissioner",
            scenario_micro_s7_secure_programmer,
        )]),
        ("System B (mask 07B0)", DutMode::SystemB, &[
            ("system B descriptor smoke read", scenario_system_b_descriptor),
            ("system B download over the property path", scenario_system_b_full_download),
            ("system B application unload via confirmed reset", scenario_system_b_unload_all),
            ("system B oversized relative allocation enters Error", scenario_system_b_oversized_segment),
            ("system B re-download without factory reset", scenario_system_b_redownload),
            ("system B partial and automatic group downloads", scenario_system_b_scoped_downloads),
        ]),
        ("System B (mask 07B0, Data Secure capable)", DutMode::SystemBSecure, &[(
            "secure System B commissioning through Commissioner",
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
enum ExpectedLoadControlPath {
    Property,
    Memory,
}
fn assert_load_control_plan(
    plan: &CompiledProgram,
    expected_style: ResourceManagementStyle,
    expected_path: ExpectedLoadControlPath,
    context: &str,
) -> Result<(), String> {
    if plan.profile().management_style() != Some(expected_style) {
        return Err(format!(
            "{context}: expected {expected_style:?} target management, got {:?}",
            plan.profile().management_style()
        ));
    }
    let procedure = plan.procedure().ok_or_else(|| format!("{context}: plan has no procedure"))?;
    let records: Vec<_> = procedure
        .steps
        .iter()
        .filter_map(|step| match &step.operation {
            ProcedureOperation::LoadRecord(record) | ProcedureOperation::AbsoluteSegment { record, .. } => Some(record),
            _ => None,
        })
        .collect();
    if records.is_empty() {
        return Err(format!("{context}: procedure drives no load-state machine"));
    }

    // Inspect the actual bound services. Re-resolving an abstract machine here
    // would only repeat the compiler and could miss a wrong executable operand.
    // System 7 publishes memory-window metadata while PropertyMappedLsms
    // explicitly selects equivalent property services for online programming.
    let property_mapped =
        plan.profile().feature("PropertyMappedLsms").map_err(|error| format!("{context}: {error}"))?.unwrap_or(0) != 0;
    for record in records {
        for service in std::iter::once(&record.write).chain(record.poll.iter().map(|(read, _)| read)) {
            let matches = match expected_path {
                ExpectedLoadControlPath::Property => matches!(service.target, OperationTarget::Property { .. }),
                ExpectedLoadControlPath::Memory if property_mapped => {
                    matches!(service.target, OperationTarget::Property { .. })
                }
                ExpectedLoadControlPath::Memory => matches!(service.target, OperationTarget::Memory {
                    service: MemoryService::Classic,
                    address: MemoryAddress::Fixed(_),
                }),
            };
            if !matches {
                return Err(format!("{context}: expected {expected_path:?} load control, got {:?}", service.target));
            }
        }
    }
    Ok(())
}

fn assert_bcu2_run_error_window(plan: &CompiledProgram) -> Result<(), String> {
    let procedure = plan.procedure().ok_or_else(|| "BCU2 plan has no procedure".to_string())?;
    let connect = procedure
        .steps
        .iter()
        .position(|step| matches!(&step.operation, ProcedureOperation::Connect))
        .ok_or_else(|| "BCU2 procedure has no Connect step".to_string())?;
    let halt = procedure
        .steps
        .iter()
        .position(|step| {
            matches!(
                &step.operation,
                ProcedureOperation::Write {
                    target: OperationTarget::Memory { service: MemoryService::Classic, address: MemoryAddress::Fixed(0x010D) },
                    data: OperationData::Inline(data),
                    ..
                } if data == &[0x00]
            )
        })
        .ok_or_else(|| "BCU2 procedure never halts the application through RunError".to_string())?;
    let resume = procedure
        .steps
        .iter()
        .rposition(|step| {
            matches!(
                &step.operation,
                ProcedureOperation::Write {
                    target: OperationTarget::Memory { service: MemoryService::Classic, address: MemoryAddress::Fixed(0x010D) },
                    data: OperationData::Inline(data),
                    ..
                } if data == &[0xFF]
            )
        })
        .ok_or_else(|| "BCU2 procedure never releases RunError after writing the image".to_string())?;
    let restart = procedure
        .steps
        .iter()
        .rposition(|step| matches!(&step.operation, ProcedureOperation::Restart { .. }))
        .ok_or_else(|| "BCU2 procedure never restarts the loaded application".to_string())?;

    if !(connect < halt && halt < resume && resume < restart) {
        return Err(format!(
            "BCU2 RunError window is out of order: Connect {connect}, halt {halt}, resume {resume}, Restart {restart}"
        ));
    }

    // Segment declarations and task records precede this window. The
    // application only needs to be stopped while the mask procedure writes
    // actual image bytes into its live EEPROM image.
    let image_writes: Vec<_> = procedure
        .steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| {
            matches!(&step.operation, ProcedureOperation::Write {
                data: OperationData::Image { .. } | OperationData::Buffer { .. } | OperationData::ImageWindow { .. },
                ..
            })
            .then_some(index)
        })
        .collect();
    if image_writes.is_empty() {
        return Err("BCU2 procedure writes no compiled image data".to_string());
    }
    if image_writes.iter().any(|index| *index <= halt || *index >= resume) {
        return Err(format!("BCU2 image writes {image_writes:?} escape the RunError window {halt}..{resume}"));
    }

    Ok(())
}

fn assert_system_b_relative_image(plan: &CompiledProgram) -> Result<(), String> {
    let segments = plan.image().segments();
    if segments.iter().any(|segment| matches!(&segment.location().space, ImageSpace::StandardMemory)) {
        return Err("a System B image must carry no absolute standard-memory segments".to_string());
    }
    if !segments.iter().any(|segment| {
        matches!(&segment.location().space, ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 1 } })
    }) {
        return Err("no address-table image content compiled for System B object 1".to_string());
    }

    Ok(())
}

fn assert_confirmed_application_reset_plan(plan: &CompiledProgram, context: &str) -> Result<(), String> {
    let procedure = plan.procedure().ok_or_else(|| format!("{context}: plan has no procedure"))?;
    if !procedure
        .steps
        .iter()
        .any(|step| matches!(&step.operation, ProcedureOperation::MasterReset { erase_code: 7, .. }))
    {
        return Err(format!("{context}: confirmed-restart profile compiled no application-reset operation"));
    }

    Ok(())
}

fn decode_load_state(bytes: &[u8], context: &str) -> Result<LoadState, String> {
    let value = bytes.first().copied().ok_or_else(|| format!("{context}: empty load-state response"))?;

    LoadState::try_from(value).map_err(|_| format!("{context}: unknown load-state value {value:#04X}"))
}

async fn memory_load_state(
    connection: &mut DeviceConnection,
    machine: LsmMachine,
    context: &str,
) -> Result<LoadState, String> {
    const LOAD_STATUS_BASE: u16 = 0xB6EA;

    let offset = u16::from(machine as u8) - 1;
    let bytes = connection
        .memory_read(LOAD_STATUS_BASE + offset, 1)
        .await
        .map_err(|error| format!("{context}: reading memory load state: {error}"))?;

    decode_load_state(&bytes, context)
}

async fn property_load_state(
    connection: &mut DeviceConnection,
    object: u8,
    context: &str,
) -> Result<LoadState, String> {
    let bytes = connection
        .property_read(object, pid::LOAD_STATE_CONTROL, 1, 1)
        .await
        .map_err(|error| format!("{context}: reading property load state: {error}"))?;

    decode_load_state(&bytes, context)
}

/// Read and validate the micro-System-7 fixture's product-owned wide-pointer
/// communication-object table.
///
/// A standard-frame `A_Memory_Read` response carries at most 12 data octets
/// at this target's 15-octet APDU limit. The physical table is 51 octets, so
/// verification must use the same bounded chunking as a management client;
/// asking for the whole table produces a regular negative response.
async fn assert_micro_system7_cot(connection: &mut DeviceConnection, context: &str) -> Result<(), String> {
    const MAX_MEMORY_DATA: usize = 12;
    const COT_ADDRESS: u16 = 0x4200;

    let expected_cot = micro_system7_stack::COM_OBJECTS;
    let cot_len = 3 + expected_cot.len() * 4;
    let mut cot = Vec::with_capacity(cot_len);
    for offset in (0..cot_len).step_by(MAX_MEMORY_DATA) {
        let count = (cot_len - offset).min(MAX_MEMORY_DATA);
        let address = COT_ADDRESS
            .checked_add(u16::try_from(offset).map_err(|_| format!("{context}: COT offset exceeds u16"))?)
            .ok_or_else(|| format!("{context}: COT read address overflow"))?;
        let chunk = connection
            .memory_read(address, u8::try_from(count).expect("COT chunk is at most 12 octets"))
            .await
            .map_err(|error| format!("{context}: reading COT chunk at {address:04X}: {error}"))?;
        if chunk.len() != count {
            return Err(format!(
                "{context}: COT chunk at {address:04X} returned {} bytes, expected {count}",
                chunk.len()
            ));
        }
        cot.extend_from_slice(&chunk);
    }

    let expected_count = u8::try_from(expected_cot.len()).map_err(|_| format!("{context}: COT count exceeds u8"))?;
    if cot[0] != expected_count || cot[1..3] != [0x00, 0xD0] {
        return Err(format!(
            "{context}: COT header {:02X?}, expected count {expected_count} and RAM-flags pointer 00D0",
            &cot[..3]
        ));
    }
    for (asap, expected) in expected_cot.iter().enumerate() {
        let offset = 3 + asap * 4;
        let row = &cot[offset..offset + 4];
        if row[..2] != expected.data_ptr.to_be_bytes() {
            return Err(format!(
                "{context}: COT ASAP {asap} data pointer {:02X?}, expected {:04X}",
                &row[..2],
                expected.data_ptr
            ));
        }
        if (asap == 0 || asap >= 8) && row[2..] != [expected.config, expected.value_type] {
            return Err(format!(
                "{context}: COT undeclared ASAP {asap} config/type {:02X?}, expected {:02X?}",
                &row[2..],
                [expected.config, expected.value_type]
            ));
        }
    }

    Ok(())
}

async fn raw_memory_oversized_segment(
    connection: &mut DeviceConnection,
    segment: AbsSegment,
    context: &str,
) -> Result<(), String> {
    const LOAD_CONTROL_ADDRESS: u16 = 0x0104;
    const MACHINE: LsmMachine = LsmMachine::AddressTable;

    connection
        .memory_write(LOAD_CONTROL_ADDRESS, &MemLoadControlRecord::event(MACHINE, LoadEvent::StartLoading))
        .await
        .map_err(|error| format!("{context}: starting memory load: {error}"))?;
    if memory_load_state(connection, MACHINE, context).await? != LoadState::Loading {
        return Err(format!("{context}: address table did not enter Loading"));
    }

    connection
        .memory_write(LOAD_CONTROL_ADDRESS, &MemLoadControlRecord::abs_segment(MACHINE, &segment))
        .await
        .map_err(|error| format!("{context}: declaring oversized memory segment: {error}"))?;
    let rejected = memory_load_state(connection, MACHINE, context).await?;
    if rejected != LoadState::Err {
        return Err(format!("{context}: oversized segment left address table in {rejected:?}, expected Error"));
    }

    connection
        .memory_write(LOAD_CONTROL_ADDRESS, &MemLoadControlRecord::event(MACHINE, LoadEvent::Unload))
        .await
        .map_err(|error| format!("{context}: recovering memory load state: {error}"))?;
    let recovered = memory_load_state(connection, MACHINE, context).await?;
    if recovered != LoadState::Unloaded {
        return Err(format!("{context}: recovery left address table in {recovered:?}, expected Unloaded"));
    }

    Ok(())
}

async fn raw_property_oversized_segment(
    connection: &mut DeviceConnection,
    segment: RelSegment,
    context: &str,
) -> Result<(), String> {
    const OBJECT: u8 = 1;

    connection
        .property_write(OBJECT, pid::LOAD_STATE_CONTROL, 1, 1, &LoadControlRecord::event(LoadEvent::StartLoading))
        .await
        .map_err(|error| format!("{context}: starting property load: {error}"))?;
    if property_load_state(connection, OBJECT, context).await? != LoadState::Loading {
        return Err(format!("{context}: address table did not enter Loading"));
    }

    connection
        .property_write(OBJECT, pid::LOAD_STATE_CONTROL, 1, 1, &LoadControlRecord::rel_segment(&segment))
        .await
        .map_err(|error| format!("{context}: declaring oversized relative segment: {error}"))?;
    let rejected = property_load_state(connection, OBJECT, context).await?;
    if rejected != LoadState::Err {
        return Err(format!("{context}: oversized segment left address table in {rejected:?}, expected Error"));
    }

    connection
        .property_write(OBJECT, pid::LOAD_STATE_CONTROL, 1, 1, &LoadControlRecord::event(LoadEvent::Unload))
        .await
        .map_err(|error| format!("{context}: recovering property load state: {error}"))?;
    let recovered = property_load_state(connection, OBJECT, context).await?;
    if recovered != LoadState::Unloaded {
        return Err(format!("{context}: recovery left address table in {recovered:?}, expected Unloaded"));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecureFixtureKeySources {
    Direct,
    KeyringOnly,
    MatchingProjectAndKeyring,
    RejectedConflictThenKeyring,
}

fn fixture_keyring(serial_number: [u8; 6], tool_key: [u8; 16], group_keys: &[(GroupAddress, [u8; 16])]) -> Keyring {
    let group_addresses =
        group_keys.iter().map(|(group, _)| (u16::from_be_bytes(group.0), vec![tester_ia()])).collect();
    let group_keys = group_keys.iter().map(|(group, key)| (u16::from_be_bytes(group.0), *key)).collect();

    Keyring::new("configuration conformance".to_string(), "zweidraehte".to_string(), "2026-08-24T00:00:00Z".to_string())
        .with_interfaces(vec![
            KeyringInterface::new(KeyringInterfaceType::Usb, tester_ia()).with_group_addresses(group_addresses),
        ])
        .with_group_keys(group_keys)
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
    fn secure(tool_key: [u8; 16], group_keys: &[(&str, [u8; 16])]) -> Self {
        let mut values = [
            (KeyId { scope: KeyScope::Device("dut".into()), kind: KeyKind::Fdsk }, SECURE_FDSK),
            (KeyId { scope: KeyScope::Device("dut".into()), kind: KeyKind::ToolKey }, tool_key),
        ]
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();

        for (group, key) in group_keys {
            values.insert(KeyId { scope: KeyScope::Group((*group).into()), kind: KeyKind::GroupKey }, *key);
        }

        Self { values }
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

// These helpers inject already-parsed `ProjectProduct` values and therefore
// never open the project package store. Still author the same durable selector
// shape as a real project so conformance coverage cannot preserve removed
// loose-MTXML syntax by accident.
const FIXTURE_PACKAGE_ID: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const FIXTURE_CATALOG_ITEM_ID: &str = "conformance-fixture";

/// Resolve the same Catalog/Product/Hardware2Program chain a project package
/// loader would retain. The generated fixtures are complete package content;
/// throwing away Hardware.xml would make AP2 presence unknowable and would no
/// longer exercise the production commissioning boundary.
fn generated_fixture_product(output: KnxprodOutput, context: &str) -> Result<SelectedProduct, String> {
    let content = ManufacturerContent::from(&output);
    let catalogue_products =
        content.catalogue_products().map_err(|error| format!("{context}: resolving generated catalogue: {error}"))?;
    let [catalogue_product] = catalogue_products.as_slice() else {
        return Err(format!(
            "{context}: generated catalogue resolves {} products, expected one",
            catalogue_products.len()
        ));
    };
    let mtxml = output
        .application_programs
        .iter()
        .find(|(id, _)| id == &catalogue_product.application_program_id)
        .map(|(_, xml)| xml.clone())
        .ok_or_else(|| {
            format!(
                "{context}: generated catalogue selects missing application {}",
                catalogue_product.application_program_id
            )
        })?;
    let document = parse_application_program(&mtxml)
        .map_err(|error| format!("{context}: parsing generated application: {error}"))?;
    let program = document
        .manufacturer_data
        .manufacturer
        .application_programs
        .programs
        .first()
        .ok_or_else(|| format!("{context}: generated application document is empty"))?;
    let hardware: HardwareKnx = quick_xml::de::from_str(output.hardware.trim_start_matches('\u{feff}'))
        .map_err(|error| format!("{context}: parsing generated Hardware.xml: {error}"))?;
    let pairing = hardware
        .resolve_application_program_pairing(&program.id, Some(&program.program_type))
        .map_err(|error| format!("{context}: validating generated hardware relation: {error}"))?
        .ok_or_else(|| format!("{context}: Hardware.xml has no relation for {}", program.id))?;
    if pairing.hardware_id != catalogue_product.hardware_id
        || pairing.hardware2program_id != catalogue_product.hardware2program_id
    {
        return Err(format!(
            "{context}: Catalog.xml selects {}/{}, but Hardware.xml resolves {}/{}",
            catalogue_product.hardware_id,
            catalogue_product.hardware2program_id,
            pairing.hardware_id,
            pairing.hardware2program_id
        ));
    }
    let relation = ApplicationProgramRelation {
        product_id: Some(catalogue_product.product_id.clone()),
        catalog_item_id: Some(catalogue_product.catalogue_item_id.clone()),
        hardware: pairing,
    };
    SelectedProduct::from_document(document, Some(relation), None)
        .map_err(|error| format!("{context}: extracting generated product: {error}"))
}

/// Loose fixtures deliberately have no package-owned hardware relationship.
fn loose_fixture_product(mtxml: &str) -> Result<SelectedProduct, String> {
    let document = parse_application_program(mtxml).map_err(|error| format!("parsing fixture MTXML: {error}"))?;
    SelectedProduct::from_document(document, None, None)
        .map_err(|error| format!("extracting fixture product with schema provenance: {error}"))
}

fn parse_fixture_project(source: impl Into<String>, context: &str) -> Result<AuthoredProject, String> {
    let authored = AuthoredProject::parse(source).map_err(|error| format!("parsing {context} project: {error}"))?;
    let product = &authored
        .devices
        .get(&ProjectDeviceId("dut".into()))
        .ok_or_else(|| format!("{context} project has no `dut` device"))?
        .product;
    match product {
        ProductReference::Package { package, catalog_item }
            if package.to_string() == FIXTURE_PACKAGE_ID && catalog_item == FIXTURE_CATALOG_ITEM_ID => {}
        other => return Err(format!("{context} project parsed an unexpected product selector {other:?}")),
    }

    Ok(authored)
}

#[allow(clippy::too_many_arguments)]
async fn program_plain_project_fixture(
    bus: &KnxBus,
    product: SelectedProduct,
    desired_address: IndividualAddress,
    serial_number: Option<[u8; 6]>,
    group: GroupAddress,
    dpt: &str,
    com_object: u16,
    max_apdu: u16,
    intent: CommissioningIntent,
    target: TargetSelection,
) -> Result<ExecutionReport, String> {
    let serial = serial_number
        .map(|serial| format!("\n            serial \"{}\"", zweidraehte_project::format_serial(&serial)))
        .unwrap_or_default();
    let fixture_package = FIXTURE_PACKAGE_ID;
    let fixture_catalog_item = FIXTURE_CATALOG_ITEM_ID;
    let source = format!(
        r#"ga test = {group}
net test : {dpt} {{ security plain }}
area {} conformance {{
    line {} main {{
        medium tp1
        device dut {{
            product package:"{fixture_package}"
            catalog_item "{fixture_catalog_item}"
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
    let authored = parse_fixture_project(source, "plain fixture")?;
    let id = ProjectDeviceId("dut".into());
    let products = [(id.clone(), ProjectProduct::new(product))].into_iter().collect();
    let catalogs = ProjectMasterData::load_for(&products, None)
        .map_err(|error| format!("loading plain fixture catalog: {error}"))?;
    let plan = ProjectPlanner::new(&authored, None, &products, Some(&FixtureKeySource::default()), None)
        .with_master_data(&catalogs)
        .plan_commissioning(std::slice::from_ref(&id), BatchSelection::Selected, intent)
        .map_err(|error| format!("planning plain project fixture: {error}"))?;
    let planned = plan.devices().into_iter().next().ok_or_else(|| "plain project plan is empty".to_string())?;
    commission_operation(bus, planned.device().clone(), intent, target, true, "plain project commissioning pipeline")
        .await
}

fn scenario_bcu1_programmer_download<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let desired = IndividualAddress::new(1, 0, 55);
        let group = GroupAddress::from_three_level(3, 1, 1);
        control.set_programming_mode(true).await.map_err(|error| format!("prog mode on: {error}"))?;
        let report = program_plain_project_fixture(
            bus,
            loose_fixture_product(&bcu1_product::generate_mtxml())?,
            desired,
            Some(bcu1_stack::SERIAL_NUMBER),
            group,
            "1.001",
            1,
            15,
            CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full),
            TargetSelection::ProgrammingButton(ProgrammingModePolling {
                wait_when_none_found: false,
                ..ProgrammingModePolling::default()
            }),
        )
        .await?;
        if report.discovered.mask.dd0 != 0x0012
            || report.plan.profile().management_style() != Some(ResourceManagementStyle::Simple)
        {
            return Err(format!(
                "unexpected commissioning profile: {}, style {:?}",
                report.discovered.mask,
                report.plan.profile().management_style()
            ));
        }
        if !report.effects().address_assignment().is_some_and(|assignment| assignment.changed) {
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
    product: SelectedProduct,
    serial_number: [u8; 6],
    group: GroupAddress,
    dpt: &str,
    com_object: u16,
    tool_key: [u8; 16],
    group_key: [u8; 16],
    max_apdu: u16,
    key_sources: SecureFixtureKeySources,
) -> Result<ExecutionReport, String> {
    // Erase code 02 is the secure-device factory state: FDSK active,
    // Security Mode off, and IA 15.15.255. The commissioner must find the
    // serial and restore the project IA before loading the application.
    control.master_reset(2).await.map_err(|error| format!("factory reset: {error}"))?;
    let stale_group = GroupAddress::from_three_level(3, 7, 254);
    let mut stale_group_key = group_key;
    stale_group_key[0] ^= 0x5A;
    let fixture_package = FIXTURE_PACKAGE_ID;
    let fixture_catalog_item = FIXTURE_CATALOG_ITEM_ID;

    let project_source = |include_stale_group: bool| {
        let stale_declaration = if include_stale_group {
            format!(
                r#"ga stale = {stale_group}
net stale : {dpt} {{
    security authentication_confidentiality
}}
"#
            )
        } else {
            String::new()
        };
        let stale_sender_membership = if include_stale_group { "    on stale\n" } else { "" };
        let stale_object_membership = if include_stale_group { "                also on stale\n" } else { "" };

        format!(
            r#"ga test = {group}
net test : {dpt} {{
    security authentication_confidentiality
}}
{stale_declaration}

external_sender conformance_client {{
    address {}
    data_secure enabled
    on test
{stale_sender_membership}}}

area 1 conformance {{
    line 0 main {{
        medium tp1

        device dut {{
            product package:"{fixture_package}"
            catalog_item "{fixture_catalog_item}"
            address {}
            serial "{}"
            max_apdu {max_apdu}
            data_secure enabled

            object {com_object} {{
                on test
{stale_object_membership}                flags {{
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
        )
    };

    // Start from two real secured group addresses and then remove one from the
    // desired project. Both PID 53 rows therefore refer to valid, sorted Group
    // Address Table TSAPs as required by 03/05/01 §6.3.7. This catches stale
    // active rows without manufacturing an invalid table entry.
    let authored_with_stale = parse_fixture_project(project_source(true), "two-group secure fixture")?;
    let authored = parse_fixture_project(project_source(false), "one-group secure fixture")?;
    let products = [(ProjectDeviceId("dut".into()), ProjectProduct::new(product))].into_iter().collect();
    let group_keys = [(group, group_key), (stale_group, stale_group_key)];
    let source_group_keys = [("test", group_key), ("stale", stale_group_key)];
    let keyring = fixture_keyring(serial_number, tool_key, &group_keys);
    let direct = FixtureKeySource::secure(tool_key, &source_group_keys);
    let empty = FixtureKeySource::default();
    let catalogs = ProjectMasterData::load_for(&products, None)
        .map_err(|error| format!("loading secure fixture catalog: {error}"))?;
    let selected = [ProjectDeviceId("dut".into())];
    let selection = BatchSelection::Selected;
    let (source, imported) = match key_sources {
        SecureFixtureKeySources::Direct => (&direct as &dyn KeyMaterialSource, None),
        SecureFixtureKeySources::KeyringOnly => (&empty as &dyn KeyMaterialSource, Some(&keyring)),
        SecureFixtureKeySources::MatchingProjectAndKeyring => (&direct as &dyn KeyMaterialSource, Some(&keyring)),
        SecureFixtureKeySources::RejectedConflictThenKeyring => {
            let mut conflicting_key = group_key;
            conflicting_key[0] ^= 0xFF;
            let conflicting =
                FixtureKeySource::secure(tool_key, &[("test", conflicting_key), ("stale", stale_group_key)]);
            if ProjectPlanner::new(&authored_with_stale, None, &products, Some(&conflicting), Some(&keyring))
                .with_master_data(&catalogs)
                .plan_commissioning(
                    &selected,
                    selection,
                    CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full),
                )
                .is_ok()
            {
                return Err("conflicting project and keyring group keys were accepted".to_string());
            }
            (&empty as &dyn KeyMaterialSource, Some(&keyring))
        }
    };

    let plan = |project: &AuthoredProject| {
        let batch = ProjectPlanner::new(project, None, &products, Some(source), imported)
            .with_master_data(&catalogs)
            .plan_commissioning(&selected, selection, CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full))
            .map_err(|error| format!("planning secure project fixture: {error}"))?;
        let planned = batch.devices().first().ok_or_else(|| "secure project plan is empty".to_string())?;

        Ok::<_, String>(planned.device().clone())
    };
    let initial_device = plan(&authored_with_stale)?;
    let replacement_device = plan(&authored)?;

    let first = commission_operation(
        bus,
        initial_device,
        CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full),
        TargetSelection::SerialNumber(serial_number),
        false,
        "first secure commission",
    )
    .await?;
    if !first.discovered.secure_management
        || !first.effects().address_assignment().is_some_and(|assignment| assignment.changed)
    {
        return Err(
            "the secure commission did not authenticate the factory device and assign its project IA".to_string()
        );
    }

    // Confirm that the initial project really exercised both valid rows before
    // testing replacement. This assertion also guards the project/key-source
    // fixture against silently losing its additional membership.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let mut connection =
        bus.connect_device(dut_ia()).await.map_err(|error| format!("initial table check sync: {error}"))?;
    let initial_table_check = async {
        let count = connection
            .property_ext_read(InterfaceObjectType::Security, 1, pid::security::GROUP_KEY_TABLE, 0, 1)
            .await
            .map_err(|error| format!("reading initial PID 53 count: {error}"))?;
        if count != 2u16.to_be_bytes() {
            return Err(format!("initial PID 53 count {count:02X?}, expected two rows"));
        }
        let mode = connection
            .function_property_ext_state_read(InterfaceObjectType::Security, 1, pid::security::SECURITY_MODE, &[0, 0])
            .await
            .map_err(|error| format!("reading initial Security Mode: {error}"))?;
        if mode.return_code != 0 || mode.data != [0, 1] {
            return Err(format!(
                "initial Security Mode response code {:02X}, data {:02X?}; expected enabled",
                mode.return_code, mode.data
            ));
        }

        Ok(())
    }
    .await;
    close_quietly(connection).await;
    initial_table_check?;

    // Reboot, then use the same persisted tool key for a complete second
    // invocation whose valid project now contains one secured group address.
    // The client intentionally omits PID 53's spec-defined element-zero reset
    // for bench-device compatibility, so Security IO unload must still make
    // the removed row inactive before the replacement is streamed.
    control.power_cycle().await.map_err(|error| format!("power cycle: {error}"))?;
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let repeated = commission_operation(
        bus,
        replacement_device,
        CommissioningIntent::Download(DownloadMode::Full),
        TargetSelection::ExistingAddress(dut_ia()),
        false,
        "repeat secure download",
    )
    .await?;

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let mut connection =
        bus.connect_device(dut_ia()).await.map_err(|error| format!("replacement check sync: {error}"))?;
    let replacement_check = async {
        let count = connection
            .property_ext_read(InterfaceObjectType::Security, 1, pid::security::GROUP_KEY_TABLE, 0, 1)
            .await
            .map_err(|error| format!("reading replaced PID 53 count: {error}"))?;
        if count != 1u16.to_be_bytes() {
            return Err(format!("replaced PID 53 count {count:02X?}, expected one row"));
        }

        Ok(())
    }
    .await;
    close_quietly(connection).await;
    replacement_check?;

    // Commissioner programs one target and deliberately does not mutate the
    // caller-wide group-security context. Install the resolved fixture key in
    // this conformance client's receiver before asking it to authenticate the
    // device's secured telegram. The low-level secure scenarios establish the
    // same boundary explicitly.
    bus.set_group_key(group, group_key)
        .await
        .map_err(|error| format!("installing the local secure-group receive key: {error}"))?;

    Ok(repeated)
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
            loose_fixture_product(&system7_product::generate_secure_mtxml()?)?,
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
        if report.discovered.mask.dd0 != 0x0705 {
            return Err(format!("secure System 7 reported mask {}", report.discovered.mask));
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
        let fixture =
            generated_fixture_product(system_b_product::generate_secure_output()?, "secure System B fixture")?;
        let report = program_secure_fixture(
            bus,
            control,
            fixture,
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
        if report.discovered.mask.dd0 != 0x07B0 {
            return Err(format!("secure System B reported mask {}", report.discovered.mask));
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
            loose_fixture_product(&bcu2_light_switch_product::generate_secure_mtxml()?)?,
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
        if report.discovered.mask.dd0 != 0x0021 {
            return Err(format!("secure BCU2 reported mask {}", report.discovered.mask));
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
            loose_fixture_product(&micro_system7_product::generate_secure_mtxml()?)?,
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
        if report.discovered.mask.dd0 != 0x0705 {
            return Err(format!("secure micro System 7 reported mask {}", report.discovered.mask));
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
        let report = program_plain_project_fixture(
            bus,
            loose_fixture_product(&system7_product::generate_mtxml()?)?,
            dut_ia(),
            Some(system7_stack::device_info::SERIAL_NUMBER),
            rewired_ga,
            "1.001",
            1,
            254,
            CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full),
            TargetSelection::SerialNumber(system7_stack::device_info::SERIAL_NUMBER),
        )
        .await?;
        if report.discovered.mask.dd0 != 0x0705
            || report.plan.profile().management_style() != Some(ResourceManagementStyle::LoadStateMachine)
        {
            return Err(format!(
                "unexpected commissioning profile: {}, style {:?}",
                report.discovered.mask,
                report.plan.profile().management_style()
            ));
        }
        assert_load_control_plan(
            &report.plan,
            ResourceManagementStyle::LoadStateMachine,
            ExpectedLoadControlPath::Memory,
            "System 7 download",
        )?;

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
        // Capture the table before commissioning owns the connection so the
        // retention check covers the unload itself.
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        let original_adt = conn.memory_read(0x4000, 3).await.map_err(|e| format!("original ADT read: {e}"));
        close_quietly(conn).await;
        let original_adt = original_adt?;

        let report = program_plain_project_fixture(
            bus,
            loose_fixture_product(&system7_product::generate_mtxml()?)?,
            dut_ia(),
            Some(system7_stack::device_info::SERIAL_NUMBER),
            GroupAddress::from_three_level(3, 1, 1),
            "1.001",
            1,
            254,
            CommissioningIntent::Unload(UnloadMode::Application),
            TargetSelection::ExistingAddress(dut_ia()),
        )
        .await?;
        assert_load_control_plan(
            &report.plan,
            ResourceManagementStyle::LoadStateMachine,
            ExpectedLoadControlPath::Memory,
            "System 7 unload",
        )?;

        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("reconnect: {e}"))?;
        let result = async {
            let states = conn.memory_read(0xB6EA, 4).await.map_err(|e| format!("load states: {e}"))?;
            if states != [u8::from(LoadState::Unloaded); 4] {
                return Err(format!("load states {states:02X?}, expected all Unloaded"));
            }
            // Unload invalidates the table while retaining its bytes, including
            // the IA slot needed to keep this connection alive.
            let adt = conn.memory_read(0x4000, 3).await.map_err(|e| format!("ADT read: {e}"))?;
            if adt != original_adt {
                return Err(format!("ADT head {adt:02X?}, expected retained {original_adt:02X?}"));
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
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        // This is deliberately not an executable commissioning plan: a valid
        // compiler must reject or avoid this allocation. Drive the protocol
        // records directly so malformed test traffic cannot escape through a
        // public project-programming API.
        let result =
            raw_memory_oversized_segment(&mut conn, AbsSegment::eeprom(0x4000, 255), "System 7 oversized segment")
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
// end-to-end: authorize on connect, cycle machine 3 over
// PID_LOAD_STATE_CONTROL with its task records, then bracket the
// verify-mode memory phase over 0100h–046Fh with RunError and restart.
// This is the software closure of
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
        reset_secure_fixture(bus, control, &bcu2_stack::SERIAL_NUMBER).await?;
    }

    let report = program_plain_project_fixture(
        bus,
        loose_fixture_product(&target.product_mtxml()?)?,
        dut_ia(),
        Some(bcu2_stack::SERIAL_NUMBER),
        rewired_ga,
        "1.001",
        3,
        target.max_apdu(),
        CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full),
        TargetSelection::SerialNumber(bcu2_stack::SERIAL_NUMBER),
    )
    .await?;
    if report.discovered.mask.dd0 != target.mask_version() {
        return Err(format!(
            "commissioner selected mask {}, expected {:04X}",
            report.discovered.mask,
            target.mask_version()
        ));
    }
    assert_load_control_plan(
        &report.plan,
        ResourceManagementStyle::Simple,
        ExpectedLoadControlPath::Property,
        "BCU2 download",
    )?;
    assert_bcu2_run_error_window(&report.plan)?;

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
        reset_secure_fixture(bus, control, &bcu2_stack::SERIAL_NUMBER).await?;
    }
    let mtxml = target.light_switch_mtxml()?;
    let product =
        ProductData::from_mtxml_str(&mtxml).map_err(|e| format!("reading the light-switch product back: {e}"))?;

    let mut project = InstallationConfiguration { max_apdu: Some(15), ..InstallationConfiguration::new(dut_ia()) };
    // Button 1's primary object onto a group address.
    project.object_memberships = vec![ObjectMembership::primary(GroupAddress::from_three_level(3, 2, 1), 0)];
    project.max_apdu = Some(target.max_apdu());
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
    let parameters = vec![EncodedParameter { id: param_id(0)?, value: vec![4] }, EncodedParameter {
        id: param_id(1)?,
        value: vec![3],
    }];

    let configuration = project.clone();
    let report = commission_operation(
        bus,
        materialized_device(&product, &configuration, parameters.clone(), ResolvedKeyMaterial::default())?,
        CommissioningIntent::Download(DownloadMode::Full),
        TargetSelection::ExistingAddress(dut_ia()),
        true,
        "BCU2 light-switch download",
    )
    .await?;
    if report.discovered.mask.dd0 != target.mask_version() {
        return Err(format!(
            "BCU2 light-switch commissioner selected mask {}, expected {:04X}",
            report.discovered.mask,
            target.mask_version()
        ));
    }

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
    let report = program_plain_project_fixture(
        bus,
        loose_fixture_product(&target.product_mtxml()?)?,
        dut_ia(),
        Some(bcu2_stack::SERIAL_NUMBER),
        GroupAddress::from_three_level(3, 1, 1),
        "1.001",
        3,
        target.max_apdu(),
        CommissioningIntent::Unload(UnloadMode::Application),
        TargetSelection::ExistingAddress(dut_ia()),
    )
    .await?;
    assert_load_control_plan(
        &report.plan,
        ResourceManagementStyle::Simple,
        ExpectedLoadControlPath::Property,
        "BCU2 unload",
    )?;

    let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("reconnect: {e}"))?;
    let result = async {
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

async fn reset_secure_fixture(bus: &KnxBus, control: &DutControl, serial: &[u8; 6]) -> Result<(), String> {
    // 07h preserves the EITT fixture's Tool Key and Security Mode. A fresh
    // commission needs 02h, followed by assigning the test IA again.
    control.master_reset(2).await.map_err(|e| format!("factory reset: {e}"))?;
    bus.network_management()
        .assign_individual_address_by_serial(serial, dut_ia(), Duration::from_millis(200))
        .await
        .map_err(|e| format!("restore fixture IA after factory reset: {e}"))?;
    Ok(())
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

        reset_secure_fixture(bus, control, &bcu2_stack::SERIAL_NUMBER).await?;
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

        let product = ProductData::from_mtxml_str(&bcu2_light_switch_product::generate_secure_mtxml()?)
            .map_err(|e| format!("reading secure BCU2 light-switch product back: {e}"))?;

        let mut project = InstallationConfiguration { max_apdu: Some(15), ..InstallationConfiguration::new(dut_ia()) };
        // The light-switch primary object transmits; its status sibling
        // receives. Link both to the same GA so the bidirectional secure test
        // follows the real product flags instead of relying on the fixture's
        // all-flags-enabled object zero.
        project.object_memberships =
            vec![ObjectMembership::primary(rewired_ga, 0), ObjectMembership::primary(rewired_ga, 1)];
        project.max_apdu = Some(40);
        let param_id = |offset: u32| {
            product
                .parameters()
                .iter()
                .find(|parameter| parameter.offset == offset)
                .map(|parameter| parameter.id.clone())
                .ok_or_else(|| format!("the secure product lacks a parameter at offset {offset}"))
        };
        let parameters = vec![EncodedParameter { id: param_id(0)?, value: vec![4] }, EncodedParameter {
            id: param_id(1)?,
            value: vec![3],
        }];
        let application_security = DownloadSecurityConfig::new(
            vec![(rewired_ga, GROUP_KEY)],
            // The client itself is the secure group sender in the second
            // half of the scenario, so its IA must have a replay-counter row.
            vec![(tester_ia(), 0)],
            vec![
                GroupObjectSecurity { com_object: 0, protection: GroupObjectProtection::AuthenticationConfidentiality },
                GroupObjectSecurity { com_object: 1, protection: GroupObjectProtection::AuthenticationConfidentiality },
            ],
        );

        let configuration = project.clone();
        let report = commission_operation(
            bus,
            materialized_device(
                &product,
                &configuration,
                parameters.clone(),
                ResolvedKeyMaterial::default()
                    .with_serial_number(bcu2_stack::SERIAL_NUMBER)
                    .with_tool_key(TOOL_KEY)
                    .with_application_security(application_security.clone()),
            )?,
            CommissioningIntent::Download(DownloadMode::Full),
            TargetSelection::ExistingAddress(dut_ia()),
            false,
            "secure BCU2 download",
        )
        .await?;
        if report.discovered.mask.dd0 != 0x0021 || !report.discovered.secure_management {
            return Err(format!("secure BCU2 download used unexpected discovery facts: {:?}", report.discovered));
        }
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
// mask the full-fat System 7 DUT runs. Ordinary project operations use
// the same normalized profile and plan as every other device; only the
// deliberately invalid allocation scenario emits a raw memory-window
// load-control record.

fn scenario_micro_s7_descriptor<'a, const MAX_APDU: u16>(
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
                (0, pid::device::MAX_APDU_LENGTH, &MAX_APDU.to_be_bytes()[..], "maximum APDU"),
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

fn scenario_micro_s7_full_download<'a, const MAX_APDU: u16>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let rewired_ga = GroupAddress::from_three_level(3, 1, 1);

        let report = program_plain_project_fixture(
            bus,
            loose_fixture_product(&micro_system7_product::generate_mtxml()?)?,
            dut_ia(),
            Some(micro_system7_stack::SERIAL_NUMBER),
            rewired_ga,
            "5.010",
            3,
            MAX_APDU,
            CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full),
            TargetSelection::SerialNumber(micro_system7_stack::SERIAL_NUMBER),
        )
        .await?;
        assert_load_control_plan(
            &report.plan,
            ResourceManagementStyle::LoadStateMachine,
            ExpectedLoadControlPath::Memory,
            "micro System 7 download",
        )?;

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
            // Product-visible ASAPs 1..=7 share this physical table with
            // spare slot 0 and the DUT's management-only ASAPs 8..=11.
            assert_micro_system7_cot(&mut conn, "micro System 7 download").await?;
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

        reset_secure_fixture(bus, control, &micro_system7_stack::SERIAL_NUMBER).await?;
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

        let product = ProductData::from_mtxml_str(&micro_system7_product::generate_secure_mtxml()?)
            .map_err(|e| format!("reading secure micro System 7 product back: {e}"))?;

        let mut project = InstallationConfiguration { max_apdu: Some(15), ..InstallationConfiguration::new(dut_ia()) };
        // Object 3 is the fixture's byte-sized, fully enabled GO. System 7
        // has a real slot zero, so its GO-security flag is element four.
        project.object_memberships = vec![ObjectMembership::primary(group, 3)];
        project.max_apdu = Some(40);
        let application_security =
            DownloadSecurityConfig::new(vec![(group, GROUP_KEY)], vec![(tester_ia(), 0)], vec![GroupObjectSecurity {
                com_object: 3,
                protection: GroupObjectProtection::AuthenticationConfidentiality,
            }]);

        let configuration = project.clone();
        let report = commission_operation(
            bus,
            materialized_device(
                &product,
                &configuration,
                Vec::new(),
                ResolvedKeyMaterial::default()
                    .with_serial_number(micro_system7_stack::SERIAL_NUMBER)
                    .with_tool_key(TOOL_KEY)
                    .with_application_security(application_security.clone()),
            )?,
            CommissioningIntent::Download(DownloadMode::Full),
            TargetSelection::ExistingAddress(dut_ia()),
            false,
            "secure micro System 7 download",
        )
        .await?;
        if report.discovered.mask.dd0 != 0x0705 || !report.discovered.secure_management {
            return Err(format!("secure micro System 7 used unexpected discovery facts: {:?}", report.discovered));
        }
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
            assert_micro_system7_cot(&mut conn, "secure micro System 7 persistence").await?;
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
        commission_operation(
            bus,
            materialized_device(
                &product,
                &configuration,
                Vec::new(),
                ResolvedKeyMaterial::default()
                    .with_serial_number(micro_system7_stack::SERIAL_NUMBER)
                    .with_tool_key(TOOL_KEY)
                    .with_application_security(application_security.clone()),
            )?,
            CommissioningIntent::Download(DownloadMode::Full),
            TargetSelection::ExistingAddress(dut_ia()),
            false,
            "secure micro System 7 re-download",
        )
        .await?;

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
        reset_secure_fixture(bus, control, &micro_system7_stack::SERIAL_NUMBER).await?;
        scenario(bus, control).await
    })
}

fn scenario_micro_s7_secure_plain_descriptor<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    run_micro_s7_secure_plain(bus, control, scenario_micro_s7_descriptor::<EXTENDED_APDU>)
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
    run_micro_s7_secure_plain(bus, control, scenario_micro_s7_full_download::<EXTENDED_APDU>)
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
        let report = program_plain_project_fixture(
            bus,
            loose_fixture_product(&micro_system7_product::generate_mtxml()?)?,
            dut_ia(),
            Some(micro_system7_stack::SERIAL_NUMBER),
            GroupAddress::from_three_level(3, 1, 1),
            "5.010",
            3,
            15,
            CommissioningIntent::Unload(UnloadMode::Application),
            TargetSelection::ExistingAddress(dut_ia()),
        )
        .await?;
        assert_load_control_plan(
            &report.plan,
            ResourceManagementStyle::LoadStateMachine,
            ExpectedLoadControlPath::Memory,
            "micro System 7 unload",
        )?;

        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("reconnect: {e}"))?;
        let result = async {
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
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        // The EITT-capable host fixture backs 4000h..7FFFh so its
        // management templates can probe certification memory. Request
        // 20 KiB from 4000h to cross that actual boundary.
        let result = raw_memory_oversized_segment(
            &mut conn,
            AbsSegment::eeprom(0x4000, 0x5000),
            "micro System 7 oversized segment",
        )
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
    generated_fixture_product(system_b_product::generate_output()?, "System B fixture")
        .map(|fixture| fixture.into_parts().1)
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
        let fixture = generated_fixture_product(system_b_product::generate_output()?, "System B fixture")?;

        // Drive it through the public API — the same call a real
        // caller makes — which now selects the property path itself.
        let report = program_plain_project_fixture(
            bus,
            fixture,
            dut_ia(),
            Some(systemb_stack::device_info::SERIAL_NUMBER),
            rewired_ga,
            "1.001",
            1,
            254,
            CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full),
            TargetSelection::SerialNumber(systemb_stack::device_info::SERIAL_NUMBER),
        )
        .await?;
        if report.discovered.mask.dd0 != 0x07B0
            || report.plan.profile().management_style() != Some(ResourceManagementStyle::LoadStateMachine)
        {
            return Err(format!(
                "unexpected commissioning profile: {}, style {:?}",
                report.discovered.mask,
                report.plan.profile().management_style()
            ));
        }
        assert_load_control_plan(
            &report.plan,
            ResourceManagementStyle::LoadStateMachine,
            ExpectedLoadControlPath::Property,
            "System B download",
        )?;
        assert_system_b_relative_image(&report.plan)?;

        // The profile advertises a fixed PEI Program object, but the package
        // relation authoritatively declares that this product has no AP2.
        // Therefore neither compilation nor post-download evidence may turn
        // the mask capability into a fabricated PEI-program deployment.
        let pei_stamp_resource = report
            .plan
            .profile()
            .resource("PeiprogStamp")
            .map_err(|error| format!("resolve PEI stamp: {error}"))?
            .ok_or_else(|| "System B profile resolved no PEI application-program stamp resource".to_string())?;
        if report.device_stamps.iter().any(|stamp| stamp.resource == pei_stamp_resource.id) {
            return Err("System B AP1-only download captured a PEI application-program stamp".to_string());
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

/// Application unload through the profile-selected confirmed-restart path.
/// System B supports the scoped erase code, so the normalized plan deliberately
/// uses that standard operation instead of interpreting the fallback unload
/// template intended for devices without confirmed restart.
fn scenario_system_b_unload_all<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let fixture = generated_fixture_product(system_b_product::generate_output()?, "System B fixture")?;
        let report = program_plain_project_fixture(
            bus,
            fixture,
            dut_ia(),
            Some(systemb_stack::device_info::SERIAL_NUMBER),
            GroupAddress::from_three_level(4, 2, 2),
            "1.001",
            1,
            254,
            CommissioningIntent::Unload(UnloadMode::Application),
            TargetSelection::ExistingAddress(dut_ia()),
        )
        .await?;
        assert_confirmed_application_reset_plan(&report.plan, "System B unload")?;

        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("reconnect: {e}"))?;
        let result = async {
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
/// hold must throw the machine into Error when read back over the raw
/// property path, and Unload must recover it.
fn scenario_system_b_oversized_segment<'a>(
    bus: &'a KnxBus,
    _control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("connect: {e}"))?;
        // A 64 KiB address table into an arena of a few hundred bytes must
        // be refused. This invalid record is intentionally kept outside the
        // executable commissioning-plan surface.
        let result =
            raw_property_oversized_segment(&mut conn, RelSegment::new(0xFFFF), "System B oversized segment").await;
        close_quietly(conn).await;
        result
    })
}

/// Re-commissioning without a factory reset — what a real ETS
/// re-download does. The device is Loaded, `PID_TABLE_REFERENCE` is
/// non-zero, and the Load-all template's own unload steps must tear
/// the old configuration down before the new allocation.
fn scenario_system_b_scoped_downloads<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let product = system_b_product()?;
        let mut project = InstallationConfiguration { max_apdu: Some(15), ..InstallationConfiguration::new(dut_ia()) };
        project.max_apdu = Some(254);

        // Establish installed application identity before either scoped update.
        // Each update changes the group table and proves the live device uses it.
        for (mode, group, automatic_sections) in [
            (DownloadMode::Full, GroupAddress::from_three_level(4, 2, 1), None),
            (
                DownloadMode::Partial(ProgramSections::GROUP_COMMUNICATION),
                GroupAddress::from_three_level(4, 2, 2),
                None,
            ),
            (
                DownloadMode::Automatic,
                GroupAddress::from_three_level(4, 2, 3),
                Some(ProgramSections::GROUP_COMMUNICATION),
            ),
        ] {
            project.object_memberships = vec![ObjectMembership::primary(group, 1)];
            let configuration = project.clone();
            let report = commission_operation_with_sections(
                bus,
                materialized_device(&product, &configuration, Vec::new(), ResolvedKeyMaterial::default())?,
                CommissioningIntent::Download(mode),
                TargetSelection::ExistingAddress(dut_ia()),
                true,
                automatic_sections,
                "System B scoped group download",
            )
            .await?;
            if !matches!(mode, DownloadMode::Full)
                && report.plan.program_sections() != Some(ProgramSections::GROUP_COMMUNICATION)
            {
                return Err("System B group procedure unexpectedly widened its scope".to_owned());
            }

            let mut events = bus.group_events();
            control.trigger_group_write(1).await.map_err(|error| format!("trigger group write: {error}"))?;
            let telegram = tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .map_err(|_| "no group telegram after scoped download".to_owned())?
                .map_err(|error| format!("receive group telegram: {error}"))?;
            if telegram.group != group {
                return Err(format!("scoped download sent on {}, expected {group}", telegram.group));
            }
        }
        Ok(())
    })
}

fn scenario_system_b_redownload<'a>(
    bus: &'a KnxBus,
    control: &'a DutControl,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(async move {
        let first_ga = GroupAddress::from_three_level(4, 2, 2);
        let second_ga = GroupAddress::from_three_level(5, 3, 3);

        let product = system_b_product()?;

        let mut project = InstallationConfiguration { max_apdu: Some(15), ..InstallationConfiguration::new(dut_ia()) };
        project.max_apdu = Some(254);

        // First commissioning, from factory state.
        project.object_memberships = vec![ObjectMembership::primary(first_ga, 1)];
        let first_configuration = project.clone();
        commission_operation(
            bus,
            materialized_device(&product, &first_configuration, Vec::new(), ResolvedKeyMaterial::default())?,
            CommissioningIntent::Download(DownloadMode::Full),
            TargetSelection::ExistingAddress(dut_ia()),
            true,
            "first System B download",
        )
        .await?;

        // Second download straight onto the configured device.
        project.object_memberships = vec![ObjectMembership::primary(second_ga, 1)];
        let second_configuration = project.clone();
        commission_operation(
            bus,
            materialized_device(&product, &second_configuration, Vec::new(), ResolvedKeyMaterial::default())?,
            CommissioningIntent::Download(DownloadMode::Full),
            TargetSelection::ExistingAddress(dut_ia()),
            true,
            "System B re-download",
        )
        .await?;

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
