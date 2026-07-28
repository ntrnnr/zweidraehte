//! KNX Conformance Test Runner.
//!
//! Drives `conformance-dut` / `conformance-dut-secure` child processes
//! over the new postcard IPC protocol (see
//! [`zweidraehte_conformance::harness::protocol`]). Every inject/
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
//!   --non-secure  Run against the plain (`conformance-dut`) DUT and SKIP
//!                 any suite that requires the secure stack
//!                 (`TestSuite::use_secure_dut == true`).
//!   filter        Optional filters (case-insensitive substring match)
//!
//! Environment:
//!   RUST_LOG    Set log level (error, warn, info, debug, trace)
//!   LIVE_LOGS   If set, print logs in real-time instead of buffering
//!   KNX_TIME_DIVISOR  Exported from `--realtime` for the DUT child
//!                     so its TL timers scale identically.

use std::env;

use log::LevelFilter;

use zweidraehte_conformance::engine::{self, DEFAULT_TIME_DIVISOR, EngineOptions, matches_filter};
use zweidraehte_conformance::harness::DutMode;
use zweidraehte_conformance::logger;
use zweidraehte_conformance::tests;

// ============================================================================
// Entry Point
// ============================================================================

#[embassy_executor::main]
async fn main(_spawner: embassy_executor::Spawner) {
    // Argument parsing — same surface as before: flags + filters.
    let args: Vec<String> = env::args().collect();
    let realtime = args.iter().any(|a| a == "--realtime");
    let non_secure = args.iter().any(|a| a == "--non-secure");
    let time_divisor: u64 = if realtime { 1 } else { DEFAULT_TIME_DIVISOR };
    let dut_mode = if non_secure { DutMode::Plain } else { DutMode::Secure };

    // Export the divisor so the DUT child scales its TL timers to match.
    // SAFETY: single-threaded before any child is spawned.
    unsafe { env::set_var("KNX_TIME_DIVISOR", time_divisor.to_string()) };

    let filters: Vec<&str> =
        args.iter().skip(1).filter(|s| *s != "--realtime" && *s != "--non-secure").map(|s| s.as_str()).collect();

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
    ];

    let has_test_case_filter =
        filters.iter().any(|f| all_suites.iter().any(|s| s.cases.iter().any(|c| matches_filter(&c.name, f))));

    let mut suites: Vec<_> = if filters.is_empty() {
        all_suites
    } else {
        all_suites
            .into_iter()
            .filter(|s| {
                let suite_matches = filters.iter().any(|f| matches_filter(&s.name, f));
                let case_matches = s.cases.iter().any(|c| filters.iter().any(|f| matches_filter(&c.name, f)));
                suite_matches || case_matches
            })
            .collect()
    };

    if dut_mode == DutMode::Plain {
        let before = suites.len();
        suites.retain(|s| !s.use_secure_dut);
        let skipped = before - suites.len();
        if skipped > 0 {
            println!("⚠️  Skipped {} secure-only suite(s) because --non-secure is active", skipped);
        }
    }

    // The socket-level KNX IP Secure suite lives outside the TP1 suite
    // list; a filter can match it alone.
    let ip_secure_matches = filters.is_empty()
        || filters.iter().any(|f| {
            matches_filter("ip_secure", f) || tests::ip_secure::tests().iter().any(|t| matches_filter(t.name, f))
        });

    if suites.is_empty() && !ip_secure_matches {
        println!("No suites or tests matched filters: {:?}", filters);
        std::process::exit(1);
    }

    // Filter matched only the IP Secure suite: skip the TP1 harness
    // entirely and run the socket-level tests on their own.
    if suites.is_empty() {
        let owned_filters: Vec<String> = filters.iter().map(|f| f.to_string()).collect();
        let (passed, failed) = tests::ip_secure::run_all(&owned_filters);
        println!("====================================================================");
        println!("SUMMARY");
        println!("====================================================================");
        println!("  Total Tests:  {}", passed + failed);
        println!("  Passed:       {} \u{2705}", passed);
        println!("  Failed:       {} \u{274c}", failed);
        println!("====================================================================");
        std::process::exit(if failed > 0 { 1 } else { 0 });
    }

    if !filters.is_empty() {
        if has_test_case_filter {
            println!("Running tests matching: {:?}\n", filters);
        } else {
            println!("Running {} suite(s) matching: {:?}\n", suites.len(), filters);
        }
    }
    let opts = EngineOptions {
        divisor: time_divisor,
        dut_mode,
        case_filters: filters.iter().map(|f| f.to_string()).collect(),
    };
    let mut summary = engine::run_suites(&suites, &opts).await;

    // ====================================================================
    // KNX IP Secure suite — socket-level, runs its own DUT process per
    // test (no TP1 IPC harness involvement).
    // ====================================================================
    if ip_secure_matches {
        let owned_filters: Vec<String> = filters.iter().map(|f| f.to_string()).collect();
        let (ip_passed, ip_failed) = tests::ip_secure::run_all(&owned_filters);
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
