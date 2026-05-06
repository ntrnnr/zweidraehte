//! Transport Layer Conformance Tests - Timing Requirements
//!
//! Tests based on KNX 3.0.0, Volume 08_03_04 Transport Layer Tests v01.06.07 AS
//! Reference: AN179 v04, AN182 v03, AN181 rev3, AN210 v02
//!
//! Test Collection: TL-Testing of Timing Requirements of Transport Layer State Machine (Section 4)
//!
//! These tests verify correct timing behavior of:
//! - Connection timeout timer
//! - Acknowledgement timeout timer
//! - Message repetition behavior

use std::collections::BTreeMap;

use super::helpers::{comment, expect, inject, inject_delay};
use crate::{TestCase, TestSuite, TestVariable};

/// Create test variables for transport layer timing tests
///
/// Based on the EITT specification:
/// - IFACE_A_ADDR: Physical Address for USB A (10.15.254 = AF FE)
/// - BDUT_ADDR: Basic Device Under Test (1.0.1 = 10 01)
pub fn create_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    vars.insert("IFACE_A_ADDR".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("BDUT_ADDR".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    vars
}

/// Create transport layer timing test suite from EITT specification
///
/// Test Collection: TL-Testing of Timing Requirements of Transport Layer State Machine
pub fn create_transport_layer_timing_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // Test Suite 4: Testing of Timing Requirements of Transport Layer State Machine
        // ====================================================================

        // --------------------------------------------------------------------
        // Test 4.1: Testing of the connection-time-out-timer
        // --------------------------------------------------------------------
        TestCase {
            name: "4.1 Testing of the connection-time-out-timer",
            steps: vec![
                comment("Testcase 4.1 Testing of the connection-time-out-timer"),
                comment("This is implicitly tested in clause 5.2.10.1 and 6.2.5.1."),
                comment("================================================================================"),
            ],
            ..Default::default()
        },
        // --------------------------------------------------------------------
        // Test 4.2: Testing of the acknowledgement-time-out timer
        // --------------------------------------------------------------------
        TestCase {
            name: "4.2 Testing of the acknowledgement-time-out timer",
            steps: vec![
                comment("Testcase 4.2 Testing of the acknowledgement-time-out timer"),
                comment("Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead to BDUT."),
                // DeviceDescriptorRead
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 500),
                comment("BDUT repeats sent response every 3 seconds."),
                // First repetition after ~3 seconds (wait 2.8s + 0.4s tolerance)
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3200),
                // Second repetition
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3200),
                // Third repetition
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3200),
                comment("BDUT breaks down connection because of maximum repetitions reached."),
                // T_Disconnect after max repetitions
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 81", 3200),
                comment("================================================================================"),
            ],
            ..Default::default()
        },
    ];

    TestSuite::new("Transport Layer Timing Tests", vars).with_cases(cases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variables_created() {
        let vars = create_test_variables();
        assert!(vars.contains_key("IFACE_A_ADDR"));
        assert!(vars.contains_key("BDUT_ADDR"));

        // Verify addresses
        assert_eq!(vars["IFACE_A_ADDR"].as_bytes(), &[0xAF, 0xFE]);
        assert_eq!(vars["BDUT_ADDR"].as_bytes(), &[0x10, 0x01]);
    }

    #[test]
    fn test_cases_created() {
        let suite = create_transport_layer_timing_suite();
        let tests = &suite.cases;
        assert_eq!(tests.len(), 2);

        // Verify test names
        assert_eq!(tests[0].name, "4.1 Testing of the connection-time-out-timer");
        assert_eq!(tests[1].name, "4.2 Testing of the acknowledgement-time-out timer");
    }
}
