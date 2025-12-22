//! KNX Conformance Test Runner
//!
//! This binary runs KNX conformance tests against the full stack with MockLinkLayer.
//! It injects telegrams into the stack and verifies the responses.
//!
//! Usage:
//!   cargo run --bin conformance-runner [filter...]
//!
//! Arguments:
//!   filter  Optional filters (case-insensitive substring match)
//!           - Suite filters: "network", "transport", "NL", "TL"
//!           - Test case filters: "2.1", "3.4", "broadcast"
//!           Multiple filters are OR'd together
//!
//! Examples:
//!   cargo run --bin conformance-runner              # Run all tests
//!   cargo run --bin conformance-runner network      # Run network layer suite
//!   cargo run --bin conformance-runner 2.3          # Run test 2.3 only
//!   cargo run --bin conformance-runner 2.1 2.3      # Run tests 2.1 and 2.3
//!   cargo run --bin conformance-runner broadcast    # Run tests with "broadcast" in name
//!
//! Environment:
//!   RUST_LOG    Set log level (error, warn, info, debug, trace)
//!   LIVE_LOGS   If set, print logs in real-time instead of buffering

use std::env;

use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};
use log::LevelFilter;

use knx_conformance::harness::mock::MockLinkLayerResources;
use knx_conformance::harness::stack::{ConformanceTestStack, FullStackHarness};
use knx_conformance::logger;
use knx_conformance::*;


use zweidraehte::Runner;

/// Run the stack in the background
#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, ConformanceTestStack>, ll_resources: &'static mut MockLinkLayerResources) {
    runner.run(ll_resources).await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // Parse command line arguments for filters
    let args: Vec<String> = env::args().collect();
    let filters: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    // Parse log level from RUST_LOG env var
    let log_level = match env::var("RUST_LOG").ok().as_deref() {
        Some("error") => LevelFilter::Error,
        Some("warn") => LevelFilter::Warn,
        Some("info") => LevelFilter::Info,
        Some("debug") => LevelFilter::Debug,
        Some("trace") => LevelFilter::Trace,
        _ => LevelFilter::Debug,
    };

    // Check if we should print logs live
    let live_logs = env::var("LIVE_LOGS").is_ok();

    // Initialize our custom logger
    logger::init(log_level, live_logs);

    println!("╔═════════════════════════════════════════════════════════════╗");
    println!("║                 KNX Conformance Test Runner                 ║");
    println!("╚═════════════════════════════════════════════════════════════╝\n");
    println!("Log level: {:?}, Live logs: {}\n", log_level, live_logs);

    // Collect all test suites
    let all_suites = vec![
        knx_conformance::tests::network_layer::create_network_layer_suite(),
        knx_conformance::tests::transport_layer_general::create_transport_layer_suite(),
        knx_conformance::tests::transport_layer_timing::create_transport_layer_timing_suite(),
        knx_conformance::tests::transport_layer_state_machine::create_transport_layer_state_machine_suite(),
        knx_conformance::tests::group_objects::create_group_objects_uint1_suite(),
        knx_conformance::tests::management::create_individual_address_read_suite(),
        knx_conformance::tests::management::create_individual_address_write_suite(),
        knx_conformance::tests::management::create_device_descriptor_type0_suite(),
        knx_conformance::tests::management::create_device_descriptor_type2_suite(),
        knx_conformance::tests::management::create_device_descriptor_illegal_types_suite(),
        knx_conformance::tests::management::create_memory_read_suite(),
        knx_conformance::tests::management::create_memory_write_suite(),
        knx_conformance::tests::management::create_adc_read_suite(),
        knx_conformance::tests::management::create_restart_suite(),
        knx_conformance::tests::management::create_memorybit_write_suite(),
        knx_conformance::tests::management::create_authorization_suite(),
        knx_conformance::tests::management::create_key_write_suite(),
        knx_conformance::tests::management::create_property_value_read_suite(),
        knx_conformance::tests::management::create_individual_address_serial_number_write_suite(),
        knx_conformance::tests::management::create_individual_address_serial_number_read_suite(),
        knx_conformance::tests::management::create_network_parameter_read_suite(),
        knx_conformance::tests::management::create_network_parameter_write_suite(),
        knx_conformance::tests::management::create_illegal_apci_suite(),
        knx_conformance::tests::management::create_user_memory_read_suite(),
        knx_conformance::tests::management::create_user_memory_write_suite(),
        knx_conformance::tests::management::create_user_manufacturer_info_read_suite(),
        knx_conformance::tests::group_objects::create_association_table_receiving_suite(),
        knx_conformance::tests::group_objects::create_association_table_sending_suite(),
    ];

    // Helper to check if a filter matches a suite or test name
    let matches_filter = |name: &str, filter: &str| -> bool {
        name.to_lowercase().contains(&filter.to_lowercase())
    };

    // Check if any filter matches a test case name in any suite
    let has_test_case_filter = filters.iter().any(|f| {
        all_suites.iter().any(|s| s.cases.iter().any(|c| matches_filter(c.name, f)))
    });

    // Filter suites - include if suite name matches OR if any test case matches
    let suites: Vec<_> = if filters.is_empty() {
        all_suites
    } else {
        all_suites
            .into_iter()
            .filter(|s| {
                // Include suite if its name matches any filter
                let suite_matches = filters.iter().any(|f| matches_filter(s.name, f));
                // Or if any of its test cases match any filter
                let case_matches = s.cases.iter().any(|c| filters.iter().any(|f| matches_filter(c.name, f)));
                suite_matches || case_matches
            })
            .collect()
    };

    if suites.is_empty() {
        println!("No suites or tests matched filters: {:?}", filters);
        println!();
        println!("Available suites:");
        println!("  - Network Layer Tests (3.1, 3.2, 3.3, 3.4)");
        println!("  - Transport Layer General Tests (2.1, 2.2, 2.3, 2.4, 2.5)");
        println!("  - Transport Layer Timing Tests (4.1, 4.2)");
        println!("  - Transport Layer State Machine Tests (6.2.x, 6.3.x, 6.4.x, 6.5.x)");
        println!("  - Group Objects UINT1 Tests (1.4.1.x)");
        println!("  - Association Table Tests (5.2.1, 5.2.2)");
        println!("  - Management Tests:");
        println!("      M-2.3 IndividualAddress_Read");
        println!("      M-2.4 IndividualAddress_Write");
        println!("      M-2.5 DeviceDescriptor (Type 0, Type 2, Illegal Types)");
        println!("      M-2.6 Memory_Read");
        println!("      M-2.7 Memory_Write");
        println!("      M-2.8 ADC_Read");
        println!("      M-2.9 Restart");
        println!("      M-2.10 MemoryBit_Write");
        println!("      M-2.11 Authorization");
        println!("      M-2.12 Key_Write");
        println!("      M-2.13 PropertyValue_Read");
        println!("      M-2.16 IndividualAddressSerialNumber_Write");
        println!("      M-2.17 IndividualAddressSerialNumber_Read");
        println!("      M-2.18 NetworkParameter_Read");
        println!("      M-2.19 NetworkParameter_Write");
        println!("      M-2.20 Illegal APCI");
        println!("      M-2.31 UserMemory_Read");
        println!("      M-2.32 UserMemory_Write");
        println!("      M-2.33 UserManufacturerInfo_Read");
        std::process::exit(1);
    }

    if !filters.is_empty() {
        if has_test_case_filter {
            println!("Running tests matching: {:?}\n", filters);
        } else {
            println!("Running {} suite(s) matching: {:?}\n", suites.len(), filters);
        }
    }

    // Create the full stack harness
    let (harness, runner, ll_resources) = FullStackHarness::new();
    spawner.spawn(run_stack(runner, ll_resources)).unwrap();
    Timer::after(Duration::from_millis(50)).await;

    let mut passed = 0;
    let mut failed = 0;
    let mut total_steps = 0;
    let mut total_tests = 0;

    for suite in &suites {
        println!("====================================================================");
        println!("Suite: {}", suite.name);
        println!("--------------------------------------------------------------------");
        println!("Variables:");
        for (name, var) in &suite.variables {
            println!("  #{}: {:02X?}", name, var.as_bytes());
        }
        println!();

        for test in &suite.cases {
            // Skip test if we have case-level filters and this test doesn't match
            if has_test_case_filter && !filters.iter().any(|f| matches_filter(test.name, f)) {
                continue;
            }

            total_tests += 1;

            // Drain any leftover captured messages from previous tests
            // Wait a bit for any in-flight messages to arrive, then drain again
            Timer::after(Duration::from_millis(100)).await;
            let drained = harness.drain_captured();
            if drained > 0 {
                println!("(Drained {} leftover messages from previous test)", drained);
            }

            logger::start_test(test.name);
            println!("Test: {}", test.name);
            println!("----------------------------------------------------------------------");
            let mut test_passed = true;
            for (i, step) in test.steps.iter().enumerate() {
                let resolved_step = match step.resolve(&suite.variables) {
                    Ok(s) => s,
                    Err(e) => {
                        println!("  [{}] ❌ Template error: {}", i, e);
                        test_passed = false;
                        continue;
                    }
                };
                match &resolved_step {
                    TestStep::Comment(text) => {
                        println!("  [{}] 💬 {}", i, text);
                    }
                    TestStep::Inject { telegram, delay_before_ms } => {
                        println!("  [{}] ⬇️  Inject: {:02X?}", i, telegram.data);
                        if *delay_before_ms > 0 {
                            println!("        (delay: {}ms)", delay_before_ms);
                            Timer::after(Duration::from_millis(*delay_before_ms as u64)).await;
                        }

                        // Create message and inject directly
                        let msg = harness.create_message(&telegram.data, zweidraehte::messages::knx::ServiceType::L_Data_Ind).await;
                        harness.inject(msg).await;

                        // Give stack time to process the message
                        Timer::after(Duration::from_millis(10)).await;
                    }
                    TestStep::Expect { matcher, timeout_ms } => {
                        println!("  [{}] ⬆️  Expect: {:02X?}", i, matcher.expected);
                        let timeout = Duration::from_millis(if *timeout_ms > 0 { *timeout_ms as u64 } else { 1000 });
                        let recv_fut = harness.receive_captured();
                        let timeout_fut = Timer::after(timeout);
                        match select(recv_fut, timeout_fut).await {
                            Either::First(Some(msg)) => {
                                if matcher.matches(&msg.data) {
                                    println!("        ✅ Matched: {:02X?}", msg.data.as_slice());
                                } else {
                                    println!("        ❌ Mismatch!");
                                    println!("           Expected: {:02X?}", matcher.expected);
                                    println!("           Got:      {:02X?}", msg.data.as_slice());
                                    test_passed = false;
                                }
                            }
                            Either::First(None) => {
                                println!("        ⚠️  Capture not available");
                                test_passed = false;
                            }
                            Either::Second(_) => {
                                println!("        ⏰ Timeout: No message received within {}ms", timeout.as_millis());
                                test_passed = false;
                            }
                        }
                    }
                    TestStep::Wait { duration_ms } => {
                        println!("  [{}] ⏳ Wait {}ms", i, duration_ms);
                        Timer::after(Duration::from_millis(*duration_ms as u64)).await;
                    }
                    TestStep::Custom => {
                        println!("  [{}] 🔧 Custom step", i);
                    }
                    TestStep::SetProgrammingMode(enabled) => {
                        println!("  [{}] 🔧 SetProgrammingMode({})", i, enabled);
                        harness.set_programming_mode(*enabled);
                    }
                    TestStep::TriggerRead { asap } => {
                        println!("  [{}] 📤 TriggerRead(ASAP {})", i, asap);
                        harness.stack().read_object_by_asap(*asap).await;
                        // Give stack time to process
                        Timer::after(Duration::from_millis(10)).await;
                    }
                    TestStep::TriggerWrite { asap } => {
                        println!("  [{}] 📤 TriggerWrite(ASAP {})", i, asap);
                        harness.stack().write_object_by_asap(*asap).await;
                        // Give stack time to process
                        Timer::after(Duration::from_millis(10)).await;
                    }
                    TestStep::ExpectNone { timeout_ms } => {
                        println!("  [{}] 🚫 ExpectNone (timeout {}ms)", i, timeout_ms);
                        let timeout = Duration::from_millis(*timeout_ms as u64);
                        let recv_fut = harness.receive_captured();
                        let timeout_fut = Timer::after(timeout);
                        match select(recv_fut, timeout_fut).await {
                            Either::First(Some(msg)) => {
                                println!("        ❌ Unexpected message received!");
                                println!("           Got: {:02X?}", msg.data.as_slice());
                                test_passed = false;
                            }
                            Either::First(None) => {
                                println!("        ✅ No message (capture not available)");
                            }
                            Either::Second(_) => {
                                println!("        ✅ No message received (as expected)");
                            }
                        }
                    }
                    TestStep::InjectTemplate { .. } | TestStep::ExpectTemplate { .. } => {
                        println!("  [{}] ❌ Unresolved template step", i);
                        test_passed = false;
                    }
                }
            }
            total_steps += test.steps.len();
            let logs = logger::end_test();
            println!("----------------------------------------------------------------------");
            if test_passed {
                println!("  ✅ PASSED");
                logger::print_log_summary(&logs, "  ");
                passed += 1;
            } else {
                println!("  ❌ FAILED");
                logger::print_log_summary(&logs, "  ");
                if !logs.is_empty() {
                    println!("  --- Stack Trace ---------------------------------------------------");
                    logger::print_logs(&logs, "    ");
                }
                failed += 1;
            }
            println!();
        }
    }
    println!("====================================================================");
    println!("SUMMARY");
    println!("====================================================================");
    println!("  Test Suites:  {}", suites.len());
    println!("  Total Tests:  {}", total_tests);
    println!("  Passed:       {} ✅", passed);
    println!("  Failed:       {} ❌", failed);
    println!("  Total Steps:  {}", total_steps);
    println!("====================================================================");
    if failed > 0 {
        std::process::exit(1);
    }
    std::process::exit(0);
}
