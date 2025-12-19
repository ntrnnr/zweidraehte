//! Network Layer Conformance Tests
//!
//! Tests based on KNX v2.1.1, Volume 08_03_03 System Conformance Testing - NL Tests
//! Reference: AN189 AS v03
//!
//! These tests verify correct handling of:
//! - Inbound message passthrough (Link Layer → Transport Layer)
//! - Outbound routing count setting (Transport Layer → Link Layer)
//! - Service type conversion
//!
//! NOTE: The EITT tests (3.1-3.4) are end-to-end device tests expecting responses.
//! For NetworkLayer-only testing, we verify:
//! 1. Inbound: Messages correctly passed to transport layer with service type conversion
//! 2. Outbound: Messages get correct hop count from default config
//!
//! The NetworkLayer does NOT generate responses - that's the Application layer's job.

use std::collections::BTreeMap;

use crate::{TestCase, TestStep, TestSuite, TestVariable};

/// Create test variables for network layer tests
///
/// Based on the EITT specification:
/// - EDI: External Device Interface (10.15.254 = AF FE)
/// - BDUT: Basic Device Under Test (1.0.1 = 10 01)
/// - GO_ADDR: Group Object Address (1/0/1 = 10 01)
pub fn create_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    vars.insert("EDI".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("BDUT".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    vars.insert("GO_ADDR".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    vars
}

/// Helper to create an inject step from a template string
fn inject(template: &str) -> TestStep {
    TestStep::InjectTemplate { template: template.to_string(), delay_before_ms: 0 }
}

/// Helper to create an inject step with delay
#[allow(dead_code)]
fn inject_delay(template: &str, delay_ms: u32) -> TestStep {
    TestStep::InjectTemplate { template: template.to_string(), delay_before_ms: delay_ms }
}

/// Helper to create an expect step from a template string
fn expect(template: &str, timeout_ms: u32) -> TestStep {
    TestStep::ExpectTemplate { template: template.to_string(), timeout_ms }
}

/// Helper to create a comment step
fn comment(text: &str) -> TestStep {
    TestStep::Comment(text.to_string())
}

/// Helper to set programming mode
fn set_programming_mode(enabled: bool) -> TestStep {
    TestStep::SetProgrammingMode(enabled)
}

/// Create network layer test suite from EITT specification
pub fn create_network_layer_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // Test Suite 3.1: Group oriented communication
        // ====================================================================
        TestCase {
            name: "3.1 Group oriented communication",
            steps: vec![
                comment("Testcase 3.1 Group oriented communication"),
                comment("A Group Object (GO) shall be present in the BDUT that is read- and transmit-enabled."),
                comment("Send telegrams with Routing Count 6, 5, 4, 3, 2, 1, 0 to the BDUT."),
                // Routing Count 0 (NPDU byte 81 = 1000 0001, rc=0)
                inject("BC #EDI #GO_ADDR 81 00 00"),
                comment("Acceptance: The BDUT shall answer with Routing Count 6."),
                // Response: RC=6, length=2
                expect("BC #BDUT #GO_ADDR E2 00 40 00", 200),
                // Routing Count 1 (NPDU byte 91 = 1001 0001, rc=1)
                inject("BC #EDI #GO_ADDR 91 00 00"),
                expect("BC #BDUT #GO_ADDR E2 00 40 00", 200),
                // Routing Count 2 (NPDU byte A1)
                inject("BC #EDI #GO_ADDR A1 00 00"),
                expect("BC #BDUT #GO_ADDR E2 00 40 00", 200),
                // Routing Count 3 (NPDU byte B1)
                inject("BC #EDI #GO_ADDR B1 00 00"),
                expect("BC #BDUT #GO_ADDR E2 00 40 00", 200),
                // Routing Count 4 (NPDU byte C1)
                inject("BC #EDI #GO_ADDR C1 00 00"),
                expect("BC #BDUT #GO_ADDR E2 00 40 00", 200),
                // Routing Count 5 (NPDU byte D1)
                inject("BC #EDI #GO_ADDR D1 00 00"),
                expect("BC #BDUT #GO_ADDR E2 00 40 00", 200),
                // Routing Count 6 (NPDU byte E1)
                inject("BC #EDI #GO_ADDR E1 00 00"),
                expect("BC #BDUT #GO_ADDR E2 00 40 00", 200),
                comment("Test Group Communication Routing Count 7."),
                // Routing Count 7 (NPDU byte F1)
                inject("BC #EDI #GO_ADDR F1 00 00"),
                comment("Acceptance: The BDUT shall answer with Routing Count 6."),
                expect("BC #BDUT #GO_ADDR E2 00 40 00", 200),
            ],
        },
        // ====================================================================
        // Test Suite 3.2: Device oriented communication - connected
        // Uses T_Connect/T_Disconnect and Memory_Read service
        // ====================================================================
        TestCase {
            name: "3.2 Device oriented communication - connected",
            steps: vec![
                comment("Testcase 3.2 Device oriented communication - connected"),
                comment("Send telegrams with Routing Count 6, 5, 4, 3, 2, 1, 0 to the BDUT."),
                comment("Acceptance: The BDUT shall answer with Routing Count 6 in all cases."),
                // RC=6: T_Connect, Memory_Read, expect T_Ack + Memory_Response, T_Ack, T_Disconnect
                inject_delay("BC #EDI #BDUT 60 80", 200),    // T_Connect
                inject("BC #EDI #BDUT 61 43 00"),            // Memory_Read (seq 0)
                expect("B0 #BDUT #EDI 60 C2", 200),          // T_Ack (seq 0)
                expect("BC #BDUT #EDI 63 43 40 ?? ??", 500), // Memory_Response with wildcards
                inject_delay("B0 #EDI #BDUT 60 C2", 200),    // T_Ack (seq 0)
                inject_delay("BC #EDI #BDUT 60 81", 200),    // T_Disconnect
                // RC=5
                inject_delay("BC #EDI #BDUT 60 80", 200),
                inject("BC #EDI #BDUT 51 43 00"),
                expect("B0 #BDUT #EDI 60 C2", 200),
                expect("BC #BDUT #EDI 63 43 40 ?? ??", 500),
                inject_delay("B0 #EDI #BDUT 50 C2", 200),
                inject_delay("BC #EDI #BDUT 60 81", 200),
                // RC=4
                inject_delay("BC #EDI #BDUT 60 80", 200),
                inject("BC #EDI #BDUT 41 43 00"),
                expect("B0 #BDUT #EDI 60 C2", 200),
                expect("BC #BDUT #EDI 63 43 40 ?? ??", 500),
                inject_delay("B0 #EDI #BDUT 40 C2", 200),
                inject_delay("BC #EDI #BDUT 60 81", 200),
                // RC=3
                inject_delay("BC #EDI #BDUT 60 80", 200),
                inject("BC #EDI #BDUT 31 43 00"),
                expect("B0 #BDUT #EDI 60 C2", 200),
                expect("BC #BDUT #EDI 63 43 40 ?? ??", 500),
                inject_delay("B0 #EDI #BDUT 30 C2", 200),
                inject_delay("BC #EDI #BDUT 60 81", 200),
                // RC=2
                inject_delay("BC #EDI #BDUT 60 80", 200),
                inject("BC #EDI #BDUT 21 43 00"),
                expect("B0 #BDUT #EDI 60 C2", 200),
                expect("BC #BDUT #EDI 63 43 40 ?? ??", 500),
                inject_delay("B0 #EDI #BDUT 20 C2", 200),
                inject_delay("BC #EDI #BDUT 60 81", 200),
                // RC=1
                inject_delay("BC #EDI #BDUT 60 80", 200),
                inject("BC #EDI #BDUT 11 43 00"),
                expect("B0 #BDUT #EDI 60 C2", 200),
                expect("BC #BDUT #EDI 63 43 40 ?? ??", 500),
                inject_delay("B0 #EDI #BDUT 10 C2", 200),
                inject_delay("BC #EDI #BDUT 60 81", 200),
                // RC=0
                inject_delay("BC #EDI #BDUT 60 80", 200),
                inject("BC #EDI #BDUT 01 43 00"),
                expect("B0 #BDUT #EDI 60 C2", 200),
                expect("BC #BDUT #EDI 63 43 40 ?? ??", 500),
                inject_delay("B0 #EDI #BDUT 00 C2", 200),
                inject_delay("BC #EDI #BDUT 60 81", 200),
                comment("Routing count 7"),
                inject_delay("BC #EDI #BDUT 70 80", 200),
                inject("BC #EDI #BDUT 71 43 00"),
                comment("Acceptance: The BDUT shall answer with Routing Count 6."),
                expect("B0 #BDUT #EDI 60 C2", 200),
                expect("BC #BDUT #EDI 63 43 40 ?? ??", 500),
                inject_delay("B0 #EDI #BDUT 70 C2", 200),
                inject_delay("BC #EDI #BDUT 70 81", 200),
            ],
        },
        // ====================================================================
        // Test Suite 3.3: Device oriented communication - connectionless
        // Using PropertyRead service
        // ====================================================================
        TestCase {
            name: "3.3 Device oriented communication - connectionless",
            steps: vec![
                comment("Testcase 3.3 Device oriented communication - connectionless"),
                comment("Note: Uses PropertyRead service. Send telegrams with Routing Count 6, 5, 4, 3, 2, 1, 0."),
                comment("Acceptance: The BDUT shall answer with Routing Count 6 in all cases."),
                // PropertyRead with RC=6: destination is #BDUT, source is #EDI
                inject("BC #EDI #BDUT 65 03 D5 00 01 10 01"),
                expect("BC #BDUT #EDI 67 03 D6 00 01 10 01 00 00", 200),
                // RC=5
                inject("BC #EDI #BDUT 55 03 D5 00 01 10 01"),
                expect("BC #BDUT #EDI 67 03 D6 00 01 10 01 00 00", 200),
                // RC=4
                inject("BC #EDI #BDUT 45 03 D5 00 01 10 01"),
                expect("BC #BDUT #EDI 67 03 D6 00 01 10 01 00 00", 200),
                // RC=3
                inject("BC #EDI #BDUT 35 03 D5 00 01 10 01"),
                expect("BC #BDUT #EDI 67 03 D6 00 01 10 01 00 00", 200),
                // RC=2
                inject("BC #EDI #BDUT 25 03 D5 00 01 10 01"),
                expect("BC #BDUT #EDI 67 03 D6 00 01 10 01 00 00", 200),
                // RC=1
                inject("BC #EDI #BDUT 15 03 D5 00 01 10 01"),
                expect("BC #BDUT #EDI 67 03 D6 00 01 10 01 00 00", 200),
                // RC=0
                inject("BC #EDI #BDUT 05 03 D5 00 01 10 01"),
                expect("BC #BDUT #EDI 67 03 D6 00 01 10 01 00 00", 200),
                comment("Routing count 7"),
                inject("BC #EDI #BDUT 75 03 D5 00 01 10 01"),
                comment("Acceptance: The BDUT shall answer with Routing Count 6."),
                expect("BC #BDUT #EDI 67 03 D6 00 01 10 01 00 00", 200),
            ],
        },
        // ====================================================================
        // Test Suite 3.4: Broadcast communication
        // ====================================================================
        TestCase {
            name: "3.4 Broadcast communication",
            steps: vec![
                comment("Testcase 3.4 Broadcast communication"),
                comment("Preparation: Activate ProgMode"),
                set_programming_mode(true),
                comment("Send telegrams with Routing Count 6, 5, 4, 3, 2, 1, 0 to the BDUT."),
                comment("Acceptance: The BDUT shall answer with Routing Count 6 in all cases."),
                // Broadcast: destination 00 00, IndividualRead (01 00)
                inject("BC #EDI 00 00 E1 01 00"),
                expect("BC #BDUT 00 00 E1 01 40", 200),
                // RC=5
                inject("BC #EDI 00 00 D1 01 00"),
                expect("BC #BDUT 00 00 E1 01 40", 200),
                // RC=4
                inject("BC #EDI 00 00 C1 01 00"),
                expect("BC #BDUT 00 00 E1 01 40", 200),
                // RC=3
                inject("BC #EDI 00 00 B1 01 00"),
                expect("BC #BDUT 00 00 E1 01 40", 200),
                // RC=2
                inject("BC #EDI 00 00 A1 01 00"),
                expect("BC #BDUT 00 00 E1 01 40", 200),
                // RC=1
                inject("BC #EDI 00 00 91 01 00"),
                expect("BC #BDUT 00 00 E1 01 40", 200),
                // RC=0
                inject("BC #EDI 00 00 81 01 00"),
                expect("BC #BDUT 00 00 E1 01 40", 200),
                comment("Routing count 7"),
                inject("BC #EDI 00 00 F1 01 00"),
                comment("Acceptance: The BDUT shall answer with Routing Count 6."),
                expect("BC #BDUT 00 00 E1 01 40", 200),
            ],
        },
    ];

    TestSuite::new("Network Layer Tests", vars).with_cases(cases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variables_created() {
        let vars = create_test_variables();
        assert!(vars.contains_key("EDI"));
        assert!(vars.contains_key("BDUT"));
        assert!(vars.contains_key("GO_ADDR"));

        // Verify addresses
        assert_eq!(vars["EDI"].as_bytes(), &[0xAF, 0xFE]);
        assert_eq!(vars["BDUT"].as_bytes(), &[0x10, 0x01]);
    }

    #[test]
    fn test_cases_created() {
        let suite = create_network_layer_suite();
        let tests = &suite.cases;
        assert_eq!(tests.len(), 4);

        // Verify test names
        assert_eq!(tests[0].name, "3.1 Group oriented communication");
        assert_eq!(tests[1].name, "3.2 Device oriented communication - connected");
        assert_eq!(tests[2].name, "3.3 Device oriented communication - connectionless");
        assert_eq!(tests[3].name, "3.4 Broadcast communication");
    }
}
