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
//! Usage:
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
    DeviceImage, Downloader, GroupLink, Instruction, LoadControlPath, MaskDb, MemoryResources, ProcedureKind,
    ProductData, ProjectConfig, assemble, compile,
};
use zweidraehte_client::{
    ConnectorInfo, DeviceConnection, Error as ClientError, GroupAddress, GroupService, IndividualAddress, KnxBus,
    MachineRef, MaskVersion,
};
use zweidraehte_conformance::dut::{system_b_product, system7_product};
use zweidraehte_conformance::harness::client_bridge::{self, DutControl};
use zweidraehte_conformance::harness::{ChildLifecycle, DutMode};
use zweidraehte_conformance::logger;
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

/// The DUT's product layer, generated in-process from the same
/// constants the DUT stack is built from and read straight back
/// through the client's parser — see
/// [`system7_product`](zweidraehte_conformance::dut::system7_product).
fn dut_product() -> Result<ProductData, String> {
    let mtxml = system7_product::generate_mtxml()?;
    ProductData::from_mtxml_str(&mtxml).map_err(|e| format!("reading the generated product file back: {e}"))
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
    let groups: &[(&str, DutMode, &[(&str, Scenario)])] = &[
        ("System 7 (mask 0705)", DutMode::System7, &[
            ("device descriptor smoke read", scenario_system7_descriptor),
            ("programming-mode individual addressing", scenario_system7_programming_mode_addressing),
            ("full download rewires the device", scenario_system7_full_download),
            ("unload-all declares the tables invalid", scenario_system7_unload_all),
            ("oversized segment allocation fails typed", scenario_system7_oversized_segment),
        ]),
        ("System B (mask 07B0)", DutMode::SystemB, &[
            ("system B descriptor smoke read", scenario_system_b_descriptor),
            ("system B download over the property path", scenario_system_b_full_download),
            ("system B unload-all via the property path", scenario_system_b_unload_all),
            ("system B oversized relative allocation fails typed", scenario_system_b_oversized_segment),
            ("system B re-download without factory reset", scenario_system_b_redownload),
        ]),
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
        let mask = masks
            .mask(MaskVersion::System7Tp1)
            .ok_or_else(|| "the master data does not describe MV-0705".to_string())?;
        let product = dut_product()?;

        let mut project = ProjectConfig::new(dut_ia());
        project.links = vec![GroupLink { group_address: rewired_ga, com_object: 1 }];
        project.max_apdu = 254; // the DUT talks extended frames

        bus.configure_device(&mask, &product, &project).await.map_err(|e| format!("download: {e}"))?;

        // The procedure ended in a restart — the DUT respawned from
        // its flushed state. Everything must have survived the reboot.
        let mut conn = bus.connect_device(dut_ia()).await.map_err(|e| format!("reconnect: {e}"))?;
        let checks = async {
            let states = conn.memory_read(0xB6EA, 3).await.map_err(|e| format!("load states: {e}"))?;
            if states != [u8::from(LoadState::Loaded); 3] {
                return Err(format!("load states {states:02X?}, expected all Loaded"));
            }
            // ADT: one group address, the DUT's own IA in TSAP 0.
            let adt = conn.memory_read(0x4000, 5).await.map_err(|e| format!("ADT read: {e}"))?;
            if adt != [1, 0x10, 0x01, 0x19, 0x01] {
                return Err(format!("ADT {adt:02X?}, expected [01 10 01 19 01]"));
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
            if adt != [0x00, 0x10, 0x01] {
                return Err(format!("ADT head {adt:02X?}, expected cleared count with IA intact"));
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
            let doomed = [Instruction::LsmEvent { lsm: 1, event: LoadEvent::StartLoading }, Instruction::AbsSegment {
                lsm: 1,
                segment: AbsSegment::eeprom(0x4000, 255),
            }];
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
                .run(&[Instruction::LsmEvent { lsm: 1, event: LoadEvent::Unload }], &DeviceImage::new())
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
        let compiled = compile(&mask, &product, &project).map_err(|e| format!("compile: {e}"))?;
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
        bus.configure_device(&mask, &product, &project).await.map_err(|e| format!("download: {e}"))?;

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
            let doomed = [Instruction::LsmEvent { lsm: 1, event: LoadEvent::StartLoading }, Instruction::RelSegment {
                lsm: 1,
                segment: RelSegment::new(0xFFFF),
            }];
            let mut downloader = Downloader::with_path(&mut conn, LoadControlPath::Property, 254);
            match downloader.run(&doomed, &DeviceImage::new()).await {
                Err(ClientError::LoadState { machine: MachineRef::Object(1), state: LoadState::Err, .. }) => {}
                other => return Err(format!("expected a LoadState error, got {other:?}")),
            }
            // Recovery: Unload brings the machine back to a defined
            // state.
            let mut downloader = Downloader::with_path(&mut conn, LoadControlPath::Property, 254);
            downloader
                .run(&[Instruction::LsmEvent { lsm: 1, event: LoadEvent::Unload }], &DeviceImage::new())
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
        bus.configure_device(&mask, &product, &project).await.map_err(|e| format!("first download: {e}"))?;

        // Second download straight onto the configured device.
        project.links = vec![GroupLink { group_address: second_ga, com_object: 1 }];
        bus.configure_device(&mask, &product, &project).await.map_err(|e| format!("re-download: {e}"))?;

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
