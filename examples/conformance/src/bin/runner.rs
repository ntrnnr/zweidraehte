//! KNX Conformance Test Runner
//!
//! Runs KNX conformance tests against a DUT (Device Under Test) running in
//! a separate child process. The runner owns persistent device state in
//! shared memory and communicates with the DUT over a Unix socketpair.
//!
//! On restart, the DUT child flushes persistent state to shared memory and
//! exits. The runner detects EOF, respawns a fresh child, and the new child
//! starts with clean volatile state (transport connections, programming mode)
//! while persistent state survives in shared memory.
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

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};
use log::LevelFilter;

use zweidraehte_conformance::harness::MultiProcessHarness;
use zweidraehte_conformance::logger;
use zweidraehte_conformance::tests::security::context::SecurityTestContext;
use zweidraehte_conformance::tests::security::crypto;
use zweidraehte_conformance::*;

// ============================================================================
// TP1 ↔ Internal Format Conversion Helpers
// ============================================================================

/// Convert TP1 wire format bytes to internal KNX message format.
///
/// Wraps the `tp1_to_knx_message_no_checksum` function for use with `Vec<u8>`.
fn tp1_to_internal(tp1: &[u8]) -> Vec<u8> {
    use zweidraehte_device::encoding::tp1;
    let mut buf = tp1.to_vec();
    buf = tp1::tp1_to_knx_message_no_checksum(buf);
    buf
}

/// Convert internal KNX message format to TP1 wire format (no checksum).
///
/// Wraps the `knx_to_tp1_message_no_checksum` function for use with `Vec<u8>`.
fn internal_to_tp1(internal: &[u8]) -> Vec<u8> {
    use zweidraehte_device::encoding::tp1;
    let mut buf = internal.to_vec();
    buf = tp1::knx_to_tp1_message_no_checksum(buf);
    buf
}

/// Shrink a wildcards array to match the internal format of a TP1 frame.
///
/// For extended frames (CTRL bit 7 = 0), the TP1 ext ctrl byte at position 1
/// is removed during conversion, so we drop the wildcard at index 1.
/// For standard frames, the length stays the same.
fn tp1_shrink_wildcards(wildcards: &[bool], tp1_data: &[u8]) -> Vec<bool> {
    if tp1_data.is_empty() {
        return wildcards.to_vec();
    }
    // Extended frame: CTRL bit 7 = 0
    if (tp1_data[0] & 0x80) == 0 && wildcards.len() > 1 {
        // Remove the ext ctrl wildcard at index 1, and the length byte at
        // index 6 (which becomes index 5 after removal).
        let mut result: Vec<bool> = Vec::with_capacity(wildcards.len() - 1);
        result.push(wildcards[0]); // CTRL
        // Skip index 1 (ext ctrl — absorbed into position 5 by tp1_to_internal)
        result.extend_from_slice(&wildcards[2..]);
        // The length byte at TP1 index 6 became internal index 5. We need to
        // also remove it since tp1_to_internal overwrites position 5.
        // But actually tp1_to_internal moves ext_ctrl to position 5, overwriting
        // the byte that was at position 6 (length). So we need to drop one more.
        // Let me just shrink to match the internal length.
        let internal_len = tp1_data.len() - 1; // extended frames shrink by 1
        result.truncate(internal_len);
        result
    } else {
        wildcards.to_vec()
    }
}

// ============================================================================
// Step Execution
// ============================================================================
//
// Each test step is executed the same way whether it appears in preparation,
// the test body, or teardown. The only difference is how failures are
// reported (preparation failures skip the suite, test failures mark the
// test as failed, teardown failures are logged but don't affect results).

/// Execute a single resolved test step.
///
/// Returns `false` if the step failed (mismatch, timeout, error).
/// `sec_ctx` is `Some` for security test suites, `None` for non-secure.
/// `variables` is needed for resolving secure templates at execution time.
async fn execute_step(
    harness: &mut MultiProcessHarness,
    step: &TestStep,
    index: usize,
    sec_ctx: Option<&mut SecurityTestContext>,
    variables: &std::collections::BTreeMap<String, TestVariable>,
) -> bool {
    match step {
        TestStep::Comment(text) => {
            println!("  [{}] 💬 {}", index, text);
            true
        }

        TestStep::Inject { telegram, delay_before_ms } => {
            println!("  [{}] ⬇️  Inject: {:02X?}", index, telegram.data);
            if *delay_before_ms > 0 {
                println!("        (delay: {}ms)", delay_before_ms);
                Timer::after(Duration::from_millis(*delay_before_ms as u64)).await;
            }
            if let Err(e) = harness.inject(&telegram.data).await {
                println!("        ❌ Inject failed: {}", e);
                return false;
            }
            // Give the DUT time to process
            Timer::after(Duration::from_millis(10)).await;
            true
        }

        TestStep::Expect { matcher, timeout_ms } => {
            println!("  [{}] ⬆️  Expect: {:02X?}", index, matcher.expected);
            let timeout = Duration::from_millis(if *timeout_ms > 0 { *timeout_ms as u64 } else { 1000 });
            match select(harness.receive_captured(), Timer::after(timeout)).await {
                Either::First(Some(msg)) => {
                    if matcher.matches(&msg.data) {
                        println!("        ✅ Matched: {:02X?}", msg.data.as_slice());
                        true
                    } else {
                        println!("        ❌ Mismatch!");
                        println!("           Expected: {:02X?}", matcher.expected);
                        println!("           Got:      {:02X?}", msg.data.as_slice());
                        false
                    }
                }
                Either::First(None) => {
                    println!("        ⚠️  Capture not available (child exited?)");
                    false
                }
                Either::Second(_) => {
                    println!("        ⏰ Timeout: No message received within {}ms", timeout.as_millis());
                    false
                }
            }
        }

        TestStep::ExpectNone { timeout_ms } => {
            println!("  [{}] 🚫 ExpectNone (timeout {}ms)", index, timeout_ms);
            let timeout = Duration::from_millis(*timeout_ms as u64);
            match select(harness.receive_captured(), Timer::after(timeout)).await {
                Either::First(Some(msg)) => {
                    println!("        ❌ Unexpected message received!");
                    println!("           Got: {:02X?}", msg.data.as_slice());
                    false
                }
                Either::First(None) => {
                    // Child exited — no message, which is what we wanted
                    println!("        ✅ No message (child exited)");
                    true
                }
                Either::Second(_) => {
                    println!("        ✅ No message received (as expected)");
                    true
                }
            }
        }

        TestStep::Wait { duration_ms } => {
            println!("  [{}] ⏳ Wait {}ms", index, duration_ms);
            Timer::after(Duration::from_millis(*duration_ms as u64)).await;
            true
        }

        TestStep::Custom => {
            println!("  [{}] 🔧 Custom step", index);
            true
        }

        TestStep::SetProgrammingMode(enabled) => {
            println!("  [{}] 🔧 SetProgrammingMode({})", index, enabled);
            if let Err(e) = harness.set_programming_mode(*enabled).await {
                println!("        ❌ Failed: {}", e);
                return false;
            }
            true
        }

        TestStep::TriggerRead { asap } => {
            println!("  [{}] 📤 TriggerRead(ASAP {})", index, asap);
            if let Err(e) = harness.trigger_read(*asap).await {
                println!("        ❌ Failed: {}", e);
                return false;
            }
            // Give the DUT time to process
            Timer::after(Duration::from_millis(10)).await;
            true
        }

        TestStep::TriggerWrite { asap } => {
            println!("  [{}] 📤 TriggerWrite(ASAP {})", index, asap);
            if let Err(e) = harness.trigger_write(*asap).await {
                println!("        ❌ Failed: {}", e);
                return false;
            }
            // Give the DUT time to process
            Timer::after(Duration::from_millis(10)).await;
            true
        }

        TestStep::Drain { settle_ms } => {
            println!("  [{}] 🧹 Drain (settle {}ms)", index, settle_ms);
            Timer::after(Duration::from_millis(*settle_ms as u64)).await;
            let drained = harness.drain_captured();
            println!("        Drained {} messages", drained);
            true
        }

        TestStep::WaitForRestart { timeout_ms } => {
            println!("  [{}] 🔄 WaitForRestart (timeout {}ms)", index, timeout_ms);
            let timeout = Duration::from_millis(*timeout_ms as u64);
            if let Err(e) = harness.wait_for_restart(timeout).await {
                println!("        ❌ Failed: {}", e);
                return false;
            }
            println!("        ✅ DUT restarted");
            true
        }

        TestStep::InjectTemplate { .. } | TestStep::ExpectTemplate { .. } => {
            // These should have been resolved before reaching here
            println!("  [{}] ❌ Unresolved template", index);
            false
        }

        // ============================================================
        // Secure test steps — resolved at execution time
        // ============================================================

        TestStep::InjectSecure { template, sec_params, delay_before_ms } => {
            let Some(ctx) = sec_ctx else {
                println!("  [{}] ❌ InjectSecure used without SecurityTestContext", index);
                return false;
            };
            // Resolve the plaintext template (produces TP1 wire format bytes).
            let plaintext = match Telegram::parse(template, variables) {
                Ok(t) => t,
                Err(e) => {
                    println!("  [{}] ❌ Template error: {}", index, e);
                    return false;
                }
            };
            // Convert TP1 → internal format for wrap_secure.
            let internal = tp1_to_internal(&plaintext.data);
            // Wrap in secure APDU (internal format).
            let secure_internal = crypto::wrap_secure(&internal, sec_params, ctx);
            // Convert back to TP1 wire format for injection.
            let secure_tp1 = internal_to_tp1(&secure_internal);
            println!("  [{}] 🔒⬇️  InjectSecure ({:?}, key={}): {} bytes",
                index, sec_params.sec_type, sec_params.key_name, secure_tp1.len());
            if *delay_before_ms > 0 {
                Timer::after(Duration::from_millis(*delay_before_ms as u64)).await;
            }
            if let Err(e) = harness.inject(&secure_tp1).await {
                println!("        ❌ Inject failed: {}", e);
                return false;
            }
            true
        }

        TestStep::ExpectSecure { template, sec_params, timeout_ms } => {
            let Some(ctx) = sec_ctx else {
                println!("  [{}] ❌ ExpectSecure used without SecurityTestContext", index);
                return false;
            };
            let timeout = Duration::from_millis(if *timeout_ms == 0 { 1000 } else { *timeout_ms as u64 });
            println!("  [{}] 🔒⬆️  ExpectSecure ({:?}, key={}, timeout={}ms)",
                index, sec_params.sec_type, sec_params.key_name, timeout.as_millis());

            let captured = select(
                harness.receive_captured(),
                Timer::after(timeout),
            ).await;

            match captured {
                Either::First(Some(msg)) => {
                    // Captured data is in TP1 wire format. Convert to internal
                    // format for unwrap_secure.
                    let internal = tp1_to_internal(&msg.data);
                    // Decrypt the captured frame.
                    match crypto::unwrap_secure(&internal, sec_params, ctx) {
                        Some(plaintext_apdu) => {
                            // Reconstruct plaintext in internal format:
                            // header (6 bytes from captured frame) + decrypted APDU.
                            let mut plain_internal = internal[..6].to_vec();
                            plain_internal.extend_from_slice(&plaintext_apdu);

                            // Convert expected template from TP1 to internal format
                            // for matching (avoids standard/extended frame ambiguity).
                            let matcher = match TelegramMatcher::parse(template, variables) {
                                Ok(m) => m,
                                Err(e) => {
                                    println!("        ❌ Template error: {}", e);
                                    return false;
                                }
                            };
                            let expected_internal = tp1_to_internal(&matcher.expected);
                            let wildcards_internal = tp1_shrink_wildcards(&matcher.wildcards, &matcher.expected);
                            let internal_matcher = TelegramMatcher {
                                expected: expected_internal,
                                wildcards: wildcards_internal,
                            };
                            if internal_matcher.matches(&plain_internal) {
                                println!("        ✅ Secure response matches");
                                true
                            } else {
                                println!("        ❌ Plaintext mismatch:");
                                println!("           {}", internal_matcher.diff(&plain_internal));
                                false
                            }
                        }
                        None => {
                            println!("        ❌ Decryption/verification failed");
                            println!("           Raw: {:02X?}", msg.data);
                            false
                        }
                    }
                }
                Either::First(None) => {
                    println!("        ❌ DUT disconnected");
                    false
                }
                Either::Second(_) => {
                    println!("        ❌ Timeout (no secure response)");
                    false
                }
            }
        }

        TestStep::InjectSecureInvalid { template, sec_params, invalid, delay_before_ms } => {
            let Some(ctx) = sec_ctx else {
                println!("  [{}] ❌ InjectSecureInvalid used without SecurityTestContext", index);
                return false;
            };
            let plaintext = match Telegram::parse(template, variables) {
                Ok(t) => t,
                Err(e) => {
                    println!("  [{}] ❌ Template error: {}", index, e);
                    return false;
                }
            };
            let internal = tp1_to_internal(&plaintext.data);
            let secure_internal = crypto::wrap_secure_invalid(&internal, sec_params, ctx, invalid);
            let secure_tp1 = internal_to_tp1(&secure_internal);
            println!("  [{}] 🔒💥⬇️  InjectSecureInvalid ({:?}): {} bytes",
                index, invalid, secure_tp1.len());
            if *delay_before_ms > 0 {
                Timer::after(Duration::from_millis(*delay_before_ms as u64)).await;
            }
            if let Err(e) = harness.inject(&secure_tp1).await {
                println!("        ❌ Inject failed: {}", e);
                return false;
            }
            true
        }
    }
}

// ============================================================================
// Entry Point
// ============================================================================

#[embassy_executor::main]
async fn main(_spawner: embassy_executor::Spawner) {
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
        zweidraehte_conformance::tests::network_layer::create_network_layer_suite(),
        zweidraehte_conformance::tests::transport_layer_general::create_transport_layer_suite(),
        zweidraehte_conformance::tests::transport_layer_timing::create_transport_layer_timing_suite(),
        zweidraehte_conformance::tests::transport_layer_state_machine::create_transport_layer_state_machine_suite(),
        zweidraehte_conformance::tests::group_objects::create_group_objects_uint1_suite(),
        zweidraehte_conformance::tests::management::create_individual_address_read_suite(),
        zweidraehte_conformance::tests::management::create_individual_address_write_suite(),
        zweidraehte_conformance::tests::management::create_device_descriptor_type0_suite(),
        zweidraehte_conformance::tests::management::create_device_descriptor_type2_suite(),
        zweidraehte_conformance::tests::management::create_device_descriptor_illegal_types_suite(),
        zweidraehte_conformance::tests::management::create_memory_read_suite(),
        zweidraehte_conformance::tests::management::create_memory_write_suite(),
        zweidraehte_conformance::tests::management::create_adc_read_suite(),
        zweidraehte_conformance::tests::management::create_memorybit_write_suite(),
        zweidraehte_conformance::tests::management::create_memorybit_write_verify_suite(),
        zweidraehte_conformance::tests::management::create_authorization_suite(),
        zweidraehte_conformance::tests::management::create_key_write_suite(),
        // Restart suite placed after authorization/key_write because M-2.9.11
        // (access denied) requires the auth keys set up by M-2.11. Note that
        // destructive tests (factory reset, reset IA/AP/links) will corrupt
        // state for subsequent tests in the same suite.
        zweidraehte_conformance::tests::management::create_restart_suite(),
        //zweidraehte_conformance::tests::management::create_property_value_read_suite(),
        zweidraehte_conformance::tests::management::create_individual_address_serial_number_write_suite(),
        zweidraehte_conformance::tests::management::create_individual_address_serial_number_read_suite(),
        //zweidraehte_conformance::tests::management::create_network_parameter_read_suite(),
        //zweidraehte_conformance::tests::management::create_network_parameter_write_suite(),
        zweidraehte_conformance::tests::management::create_illegal_apci_suite(),
        zweidraehte_conformance::tests::management::create_user_memory_read_suite(),
        zweidraehte_conformance::tests::management::create_user_memory_write_suite(),
        zweidraehte_conformance::tests::management::create_user_memory_write_verify_suite(),
        zweidraehte_conformance::tests::management::create_user_manufacturer_info_read_suite(),
        // Load State Machine Tests
        zweidraehte_conformance::tests::load_state_machines::create_preparation_suite(),
        zweidraehte_conformance::tests::load_state_machines::create_unloaded_state_suite(),
        zweidraehte_conformance::tests::load_state_machines::create_loaded_state_suite(),
        zweidraehte_conformance::tests::load_state_machines::create_loading_state_suite(),
        zweidraehte_conformance::tests::load_state_machines::create_error_state_suite(),
        zweidraehte_conformance::tests::load_state_machines::create_no_access_rights_suite(),
        // Run State Machine Tests
        // NOTE: These tests use AbsoluteData (0x00) load segments in their preparation steps.
        // System B devices only support RelativeData (0x0b) segments, so these tests cannot
        // pass until we either: (a) add AbsoluteData support, or (b) rewrite the test
        // preparations to use RelativeData segments.
        zweidraehte_conformance::tests::run_state_machines::create_preparation_suite(),
        zweidraehte_conformance::tests::run_state_machines::create_halted_state_suite(),
        // Data Security conformance tests
        zweidraehte_conformance::tests::security::section_3_1::create_section_3_1_suite(),
        zweidraehte_conformance::tests::security::section_4_1::create_section_4_1_suite(),
        zweidraehte_conformance::tests::security::section_4_2::create_section_4_2_suite(),
        zweidraehte_conformance::tests::security::section_4_3::create_section_4_3_suite(),
        zweidraehte_conformance::tests::security::section_4_4::create_section_4_4_suite(),
        zweidraehte_conformance::tests::security::section_4_5::create_section_4_5_suite(),
        zweidraehte_conformance::tests::security::section_3_8_1::create_section_3_8_1_suite(),
        zweidraehte_conformance::tests::security::section_3_8_2::create_section_3_8_2_suite(),
        zweidraehte_conformance::tests::security::section_3_8_3::create_section_3_8_3_suite(),
        zweidraehte_conformance::tests::security::section_3_8_4::create_section_3_8_4_suite(),
        zweidraehte_conformance::tests::security::section_3_8_6::create_section_3_8_6_suite(),
        zweidraehte_conformance::tests::security::section_3_8_9::create_section_3_8_9_suite(),
        zweidraehte_conformance::tests::security::section_3_8_10::create_section_3_8_10_suite(),
        zweidraehte_conformance::tests::security::section_3_8_11::create_section_3_8_11_suite(),
        zweidraehte_conformance::tests::security::section_3_8_13::create_section_3_8_13_suite(),
        zweidraehte_conformance::tests::security::section_4_6_4_7::create_section_4_6_4_7_suite(),
        zweidraehte_conformance::tests::security::section_5::create_section_5_suite(),
        zweidraehte_conformance::tests::security::section_6::create_section_6_suite(),
        // zweidraehte_conformance::tests::run_state_machines::create_running_state_suite(),
        // zweidraehte_conformance::tests::run_state_machines::create_ready_state_suite(),
        // zweidraehte_conformance::tests::run_state_machines::create_terminated_state_suite(),
        // Manual intervention required
        //zweidraehte_conformance::tests::group_objects::create_association_table_receiving_suite(),
        //zweidraehte_conformance::tests::group_objects::create_association_table_sending_suite(),
    ];

    // Helper to check if a filter matches a suite or test name
    let matches_filter = |name: &str, filter: &str| -> bool { name.to_lowercase().contains(&filter.to_lowercase()) };

    // Check if any filter matches a test case name in any suite
    let has_test_case_filter =
        filters.iter().any(|f| all_suites.iter().any(|s| s.cases.iter().any(|c| matches_filter(c.name, f))));

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
        println!("  - Load State Machine Tests:");
        println!("      L-2.1 Test Preparation");
        println!("      L-2.2 Tests with initial state LOAD_STATE_UNLOADED");
        println!("      L-2.3 Tests with initial state LOAD_STATE_LOADED");
        println!("      L-2.4 Tests with initial state LOAD_STATE_LOADING");
        println!("      L-2.5 Tests with initial state LOAD_STATE_ERROR");
        println!("      L-2.6 Test without access rights");
        println!("  - Run State Machine Tests:");
        println!("      R-2.1 Test preparation");
        println!("      R-2.2 Tests with initial state RUNSTATE_HALTED");
        println!("      R-2.3 Tests with initial state RUNSTATE_RUNNING");
        println!("      R-2.4 Tests with initial state RUNSTATE_READY");
        println!("      R-2.5 Tests with initial state RUNSTATE_TERMINATED");
        std::process::exit(1);
    }

    if !filters.is_empty() {
        if has_test_case_filter {
            println!("Running tests matching: {:?}\n", filters);
        } else {
            println!("Running {} suite(s) matching: {:?}\n", suites.len(), filters);
        }
    }

    // Create the multi-process harness (shared memory + child management)
    let mut harness = MultiProcessHarness::new()
        .expect("create multi-process harness");

    // Track which DUT variant is currently running so we can switch
    // between secure and non-secure DUT binaries when needed.
    let mut current_dut_is_secure = false;

    // Spawn the initial (non-secure) DUT child process.
    // If the first suite needs the secure DUT, it will be switched below.
    harness.spawn_child().await
        .expect("spawn DUT child");

    // Drain read-on-init messages sent during startup. The ROI scan
    // processes one object per ~100ms tick, so we need to wait long enough
    // for all ROI-flagged objects to fire. Drain in a loop until no new
    // messages arrive within a settle window.
    let mut roi_drained = 0;
    loop {
        Timer::after(Duration::from_millis(500)).await;
        let batch = harness.drain_captured();
        roi_drained += batch;
        if batch == 0 {
            break;
        }
    }
    if roi_drained > 0 {
        println!("(Drained {} read-on-init messages from startup)\n", roi_drained);
    }

    let mut passed = 0;
    let mut failed = 0;
    let mut total_steps = 0;
    let mut total_tests = 0;

    for suite in &suites {
        // Switch DUT binary if the suite requires a different variant.
        if suite.use_secure_dut != current_dut_is_secure {
            println!("🔄 Switching to {} DUT...",
                if suite.use_secure_dut { "secure" } else { "non-secure" });

            // Kill the current child and respawn with the correct binary.
            harness.kill_child().await;
            if suite.use_secure_dut {
                harness.reset_shared_memory_secure().expect("reset shared memory for secure DUT");
            } else {
                harness.reset_shared_memory().expect("reset shared memory for DUT");
            }

            if suite.use_secure_dut {
                harness.spawn_secure_child().await.expect("spawn secure DUT child");
            } else {
                harness.spawn_child().await.expect("spawn DUT child");
            }
            current_dut_is_secure = suite.use_secure_dut;

            // Drain ROI messages from the new DUT.
            loop {
                Timer::after(Duration::from_millis(500)).await;
                if harness.drain_captured() == 0 {
                    break;
                }
            }
        }
        println!("====================================================================");
        println!("Suite: {}", suite.name);
        println!("--------------------------------------------------------------------");
        println!("Variables:");
        for (name, var) in &suite.variables {
            println!("  #{}: {:02X?}", name, var.as_bytes());
        }
        println!();

        // Create a SecurityTestContext for secure suites.
        let mut sec_ctx = if suite.use_secure_dut {
            Some(zweidraehte_conformance::tests::security::variables::create_security_context())
        } else {
            None
        };

        // Run suite preparation steps if any
        if !suite.preparation.is_empty() {
            println!("Preparation:");
            println!("--------------------------------------------------------------------");
            let mut prep_passed = true;
            for (i, step) in suite.preparation.iter().enumerate() {
                let resolved_step = match step.resolve(&suite.variables) {
                    Ok(s) => s,
                    Err(e) => {
                        println!("  [{}] ❌ Template error: {}", i, e);
                        prep_passed = false;
                        continue;
                    }
                };
                if !execute_step(&mut harness, &resolved_step, i, sec_ctx.as_mut(), &suite.variables).await {
                    prep_passed = false;
                }
                total_steps += 1;
            }

            if prep_passed {
                println!("✅ Preparation completed successfully\n");
            } else {
                println!("❌ Preparation failed - skipping suite tests\n");
                continue; // Skip all tests in this suite if preparation failed
            }
        }

        for test in &suite.cases {
            // Skip test if we have case-level filters and this test doesn't match
            if has_test_case_filter && !filters.iter().any(|f| matches_filter(test.name, f)) {
                continue;
            }

            total_tests += 1;

            // Drain any leftover captured messages from previous tests.
            // Wait for in-flight messages to arrive, then drain.
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
                if !execute_step(&mut harness, &resolved_step, i, sec_ctx.as_mut(), &suite.variables).await {
                    test_passed = false;
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

        // Run suite teardown steps if any
        if !suite.teardown.is_empty() {
            println!("Teardown:");
            println!("--------------------------------------------------------------------");
            for (i, step) in suite.teardown.iter().enumerate() {
                let resolved_step = match step.resolve(&suite.variables) {
                    Ok(s) => s,
                    Err(e) => {
                        println!("  [{}] ❌ Template error: {}", i, e);
                        continue;
                    }
                };
                execute_step(&mut harness, &resolved_step, i, sec_ctx.as_mut(), &suite.variables).await;
                total_steps += 1;
            }
            println!("✅ Teardown completed\n");
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
