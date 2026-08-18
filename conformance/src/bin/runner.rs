//! KNX Conformance Test Runner.
//!
//! Drives `conformance-dut-systemb` / `conformance-dut-systemb-secure` child processes
//! over the new postcard IPC protocol (see
//! [`zweidraehte_conformance::ipc::protocol`]). Every inject/
//! trigger/programming-mode step is synchronous:
//! [`ChildLifecycle::step`](zweidraehte_conformance::harness::ChildLifecycle::step)
//! sends the command and waits for `StepComplete` before returning.
//! Outbox frames land in a per-lifecycle buffer that `Expect*` steps
//! consume via `pop_unsolicited` / `next_frame`.
//!
//! Usage:
//!   cargo run --bin conformance-runner [--realtime] [--non-secure] [filter...]
//!
//! Arguments:
//!   --realtime    Use spec-compliant timeouts (for real hardware testing).
//!                 Without this flag, timeouts are divided by 50 for fast
//!                 IPC-connected testing.
//!   --non-secure  Run against the plain (`conformance-dut-systemb`) DUT and SKIP
//!                 any suite that requires the secure stack
//!                 (`TestSuite::use_secure_dut == true`).
//!   filter        Optional filters (case-insensitive substring match)
//!
//! A filter matching a suite's name runs that suite in full; a filter
//! matching case names runs those cases in the suites they live in.
//! The two are decided per suite, so a filter that incidentally hits a
//! case name in one suite cannot narrow another suite it selected by
//! name (see [`engine::select_suite`]). A filter matching nothing at
//! all aborts the run before a DUT is spawned rather than quietly
//! reducing it — that failure mode looks exactly like a green run.
//!
//! Environment:
//!   RUST_LOG    Set log level (error, warn, info, debug, trace)
//!   LIVE_LOGS   If set, print logs in real-time instead of buffering
//!   KNX_TIME_DIVISOR  Exported from `--realtime` for the DUT child
//!                     so its TL timers scale identically.

use std::env;

use log::LevelFilter;

use zweidraehte_conformance::engine::{
    self, DEFAULT_TIME_DIVISOR, EngineOptions, SuiteSelection, matches_filter, select_suite,
};
use zweidraehte_conformance::harness::DutMode;
use zweidraehte_conformance::logger;
use zweidraehte_conformance::tests;

// ============================================================================
// Entry Point
// ============================================================================

#[tokio::main]
async fn main() {
    // Argument parsing — same surface as before: flags + filters.
    let args: Vec<String> = env::args().collect();
    let realtime = args.iter().any(|a| a == "--realtime");
    let non_secure = args.iter().any(|a| a == "--non-secure");
    let time_divisor: u64 = if realtime { 1 } else { DEFAULT_TIME_DIVISOR };
    let dut_mode = if non_secure { DutMode::SystemB } else { DutMode::SystemBSecure };

    // Export the divisor so the DUT child scales its TL timers to match.
    // SAFETY: single-threaded before any child is spawned.
    unsafe { env::set_var("KNX_TIME_DIVISOR", time_divisor.to_string()) };

    let filters: Vec<String> =
        args.iter().skip(1).filter(|s| *s != "--realtime" && *s != "--non-secure").cloned().collect();

    let log_level = match env::var("RUST_LOG").ok().as_deref() {
        Some("error") => LevelFilter::Error,
        Some("warn") => LevelFilter::Warn,
        Some("info") => LevelFilter::Info,
        Some("debug") => LevelFilter::Debug,
        Some("trace") => LevelFilter::Trace,
        _ => LevelFilter::Debug,
    };
    let live_logs = env::var("LIVE_LOGS").is_ok();
    logger::init(log_level, live_logs);

    println!("╔═════════════════════════════════════════════════════════════╗");
    println!("║                 KNX Conformance Test Runner                 ║");
    println!("╚═════════════════════════════════════════════════════════════╝\n");
    if time_divisor > 1 {
        println!("Time scale: {}x fast mode (use --realtime for spec timeouts)", time_divisor);
    } else {
        println!("Time scale: realtime (spec-compliant timeouts)");
    }
    println!("Log level: {:?}, Live logs: {}\n", log_level, live_logs);

    // Collect all test suites (unchanged from the old runner).
    let all_suites = vec![
        tests::network_layer::create_network_layer_suite(),
        tests::transport_layer_general::create_transport_layer_suite(),
        tests::transport_layer_timing::create_transport_layer_timing_suite(),
        tests::transport_layer_state_machine::create_transport_layer_state_machine_suite(),
        tests::group_objects::create_group_objects_uint1_suite(),
        tests::management::create_individual_address_read_suite(),
        tests::management::create_individual_address_write_suite(),
        tests::management::create_device_descriptor_type0_suite(),
        tests::management::create_device_descriptor_type2_suite(),
        tests::management::create_device_descriptor_illegal_types_suite(),
        tests::management::create_memory_read_suite(),
        tests::management::create_memory_write_suite(),
        tests::management::create_adc_read_suite(),
        tests::management::create_memorybit_write_suite(),
        tests::management::create_memorybit_write_verify_suite(),
        tests::management::create_authorization_suite(),
        tests::management::create_key_write_suite(),
        tests::management::create_restart_suite(),
        tests::management::create_individual_address_serial_number_write_suite(),
        tests::management::create_individual_address_serial_number_read_suite(),
        tests::management::create_system_network_parameter_read_suite(),
        tests::management::create_illegal_apci_suite(),
        tests::management::create_user_memory_read_suite(),
        tests::management::create_user_memory_write_suite(),
        tests::management::create_user_memory_write_verify_suite(),
        tests::management::create_user_manufacturer_info_read_suite(),
        tests::load_state_machines::create_preparation_suite(),
        tests::load_state_machines::create_unloaded_state_suite(),
        tests::load_state_machines::create_loaded_state_suite(),
        tests::load_state_machines::create_loading_state_suite(),
        tests::load_state_machines::create_error_state_suite(),
        tests::load_state_machines::create_no_access_rights_suite(),
        tests::run_state_machines::create_preparation_suite(),
        tests::run_state_machines::create_halted_state_suite(),
        tests::run_state_machines::create_running_state_suite(),
        tests::run_state_machines::create_ready_state_suite(),
        tests::run_state_machines::create_terminated_state_suite(),
        tests::security::section_3_1::create_section_3_1_suite(),
        tests::security::section_3_3::create_section_3_3_suite(),
        tests::security::section_3_4::create_section_3_4_suite(),
        tests::security::section_3_5::create_section_3_5_suite(),
        tests::security::section_3_6::create_section_3_6_suite(),
        tests::security::section_3_7::create_section_3_7_suite(),
        tests::security::section_3_9::create_section_3_9_suite(),
        tests::security::section_4_1::create_section_4_1_suite(),
        tests::security::section_4_2::create_section_4_2_suite(),
        tests::security::section_4_3::create_section_4_3_suite(),
        tests::security::section_4_4::create_section_4_4_suite(),
        tests::security::section_4_5::create_section_4_5_suite(),
        tests::security::section_3_8_1::create_section_3_8_1_suite(),
        tests::security::section_3_8_2::create_section_3_8_2_suite(),
        tests::security::section_3_8_3::create_section_3_8_3_suite(),
        tests::security::section_3_8_4::create_section_3_8_4_suite(),
        tests::security::section_3_8_5::create_section_3_8_5_suite(),
        tests::security::section_3_8_6::create_section_3_8_6_suite(),
        tests::security::section_3_8_7::create_section_3_8_7_suite(),
        tests::security::section_3_8_8::create_section_3_8_8_suite(),
        tests::security::section_3_8_9::create_section_3_8_9_suite(),
        tests::security::section_3_8_10::create_section_3_8_10_suite(),
        tests::security::section_3_8_11::create_section_3_8_11_suite(),
        tests::security::section_3_8_12::create_section_3_8_12_suite(),
        tests::security::section_3_8_13::create_section_3_8_13_suite(),
        tests::security::section_3_8_14::create_section_3_8_14_suite(),
        tests::security::section_3_8_15::create_section_3_8_15_suite(),
        tests::security::section_3_8_16::create_section_3_8_16_suite(),
        tests::security::section_3_8_17::create_section_3_8_17_suite(),
        tests::security::section_3_8_18::create_section_3_8_18_suite(),
        tests::security::section_4_6_4_7::create_section_4_6_4_7_suite(),
        tests::security::section_5::create_section_5_suite(),
        tests::security::section_6::create_section_6_suite(),
        tests::security::section_6::create_section_6_2_suite(),
        tests::security::section_3_2::create_section_3_2_suite(),
        tests::system7_smoke::create_system7_smoke_suite(),
        tests::system7_secure_smoke::create_system7_secure_smoke_suite(),
        tests::bcu2_smoke::create_bcu2_smoke_suite(),
    ];

    // The socket-level KNX IP Secure tests live outside the TP1 suite
    // list, so a filter can legitimately select nothing here and still
    // have selected work.
    let matches_ip_secure = |f: &String| {
        matches_filter("ip_secure", f) || tests::ip_secure::tests().iter().any(|t| matches_filter(t.name, f))
    };

    // Every filter has to select something. One that selects nothing is
    // almost always a typo or a stale name, and letting it through just
    // shrinks the run: filters are plain substrings, and a run that
    // executes fewer cases than asked for is indistinguishable from a
    // green one. Checked against the *unreduced* suite list and before
    // the DUT-mode retains below — a suite dropped because one run
    // drives one DUT binary is a different situation, and says so
    // itself.
    let unmatched: Vec<&String> = filters
        .iter()
        .filter(|f| {
            !matches_ip_secure(f)
                && !all_suites.iter().any(|s| select_suite(s, std::slice::from_ref(*f)) != SuiteSelection::None)
        })
        .collect();
    if !unmatched.is_empty() {
        for f in &unmatched {
            println!("❌ Filter {f:?} matched no suite or case name.");
        }
        std::process::exit(1);
    }

    let mut suites: Vec<_> =
        all_suites.into_iter().filter(|s| select_suite(s, &filters) != SuiteSelection::None).collect();

    // The System 7 suites need their own DUT binaries, and a run drives
    // exactly one binary. Resolution order: a pure System 7 *secure*
    // selection runs that DUT; otherwise the secure suite is dropped
    // first — so the filter "system 7", which matches both smoke
    // suites by name, still runs the plain System 7 ones — and a
    // then-pure System 7 selection runs the plain System 7 DUT.
    // Anything mixed beyond that falls back to the System B DUTs with
    // the System 7 suites dropped.
    let dut_mode = if !suites.is_empty() && suites.iter().all(|s| s.use_bcu2_dut) {
        DutMode::Bcu2
    } else if !suites.is_empty() && suites.iter().all(|s| s.use_system7_secure_dut) {
        DutMode::System7Secure
    } else {
        let before = suites.len();
        suites.retain(|s| !s.use_bcu2_dut);
        let skipped_bcu2 = before - suites.len();
        if skipped_bcu2 > 0 {
            if filters.is_empty() {
                println!("ℹ️  {} BCU2 suite(s) run separately: conformance-runner \"BCU2\"", skipped_bcu2);
            } else {
                println!("⚠️  Skipped {} BCU2 suite(s) — mixed-DUT runs are not supported", skipped_bcu2);
            }
        }
        let before = suites.len();
        suites.retain(|s| !s.use_system7_secure_dut);
        let skipped_secure = before - suites.len();
        if skipped_secure > 0 && !filters.is_empty() {
            println!("⚠️  Skipped {} System 7 secure suite(s): conformance-runner \"S7S\"", skipped_secure);
        }

        if !suites.is_empty() && suites.iter().all(|s| s.use_system7_dut) {
            DutMode::System7
        } else {
            let before = suites.len();
            suites.retain(|s| !s.use_system7_dut);
            let skipped = before - suites.len();
            if (skipped > 0 || skipped_secure > 0) && filters.is_empty() {
                println!(
                    "ℹ️  {} System 7 suite(s) run separately: conformance-runner \"System 7\" / \"S7S\"",
                    skipped + skipped_secure
                );
            } else if skipped > 0 {
                println!("⚠️  Skipped {} System 7 suite(s) — mixed-DUT runs are not supported", skipped);
            }
            dut_mode
        }
    };

    if dut_mode == DutMode::SystemB {
        let before = suites.len();
        suites.retain(|s| !s.use_secure_dut);
        let skipped = before - suites.len();
        if skipped > 0 {
            println!("⚠️  Skipped {} secure-only suite(s) because --non-secure is active", skipped);
        }
    }

    let ip_secure_matches = filters.is_empty() || filters.iter().any(matches_ip_secure);

    // Reachable only through the DUT-mode retains above — every filter
    // has already been shown to select something.
    if suites.is_empty() && !ip_secure_matches {
        println!("No suites left to run for filters {filters:?} once the DUT-mode skips above are applied.");
        std::process::exit(1);
    }

    // Filter matched only the IP Secure suite: skip the TP1 harness
    // entirely and run the socket-level tests on their own.
    if suites.is_empty() {
        let (passed, failed) = tests::ip_secure::run_all(&filters);
        println!("====================================================================");
        println!("SUMMARY");
        println!("====================================================================");
        println!("  Total Tests:  {}", passed + failed);
        println!("  Passed:       {} \u{2705}", passed);
        println!("  Failed:       {} \u{274c}", failed);
        println!("====================================================================");
        std::process::exit(if failed > 0 { 1 } else { 0 });
    }

    // Say per suite what the filters selected. An accidental substring
    // hit — the reason the selection is per suite at all — shows up
    // here as a suite running a surprising slice of its cases, before
    // the run rather than after it.
    if !filters.is_empty() {
        println!("Running {} suite(s) matching: {:?}", suites.len(), filters);
        for suite in &suites {
            println!("  {} — {}", suite.name, select_suite(suite, &filters).describe(suite));
        }
        println!();
    }
    let opts = EngineOptions { divisor: time_divisor, dut_mode, case_filters: filters.clone() };
    let mut summary = engine::run_suites(&suites, &opts).await;

    // ====================================================================
    // KNX IP Secure suite — socket-level, runs its own DUT process per
    // test (no TP1 IPC harness involvement).
    // ====================================================================
    if ip_secure_matches {
        let (ip_passed, ip_failed) = tests::ip_secure::run_all(&filters);
        summary.passed += ip_passed;
        summary.failed += ip_failed;
        summary.tests += ip_passed + ip_failed;
    }

    println!("====================================================================");
    println!("SUMMARY");
    println!("====================================================================");
    println!("  Test Suites:  {}", summary.suites);
    println!("  Total Tests:  {}", summary.tests);
    println!("  Passed:       {} ✅", summary.passed);
    println!("  Failed:       {} ❌", summary.failed);
    println!("  Total Steps:  {}", summary.steps);
    println!("====================================================================");
    if summary.failed > 0 {
        std::process::exit(1);
    }
    std::process::exit(0);
}
