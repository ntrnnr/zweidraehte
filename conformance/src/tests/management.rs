//! Management Layer Conformance Tests
//!
//! Tests based on KNX v2.1.1, Volume 08_03_07 System Conformance Testing - AIL & Management Tests
//! Reference: v01.07.10 AS
//!
//! These tests verify correct handling of:
//! - Individual Address Read/Write/Serial Number services
//! - Device Descriptor services
//! - Memory/Property access services
//! - Restart services
//! - And other management layer functionality

use std::collections::BTreeMap;

use super::helpers::{comment, expect, expect_none, inject, inject_delay, set_programming_mode};
use crate::{TestCase, TestSuite, TestVariable};

/// Create test variables for management tests
///
/// Based on the EITT specification:
/// - EDI: External Device Interface (10.15.254 = AF FE)
/// - BDUT: Basic Device Under Test (1.0.1 = 10 01)
/// - BDUT_SERIAL_NUMBER: Serial number of the BDUT (default: 30 30 30 30 30 30)
pub fn create_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    vars.insert("EDI".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("BDUT".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    vars.insert("BDUT_SERIAL_NUMBER".to_string(), TestVariable::Bytes(vec![0x30, 0x30, 0x30, 0x30, 0x30, 0x30]));
    vars
}

// ============================================================================
// M-2.3 IndividualAddress_Read Tests
// ============================================================================

/// Create IndividualAddress_Read test suite
///
/// Prior to starting the test, set individual address of the BDUT to a fix value (e.g. 1001H)
pub fn create_individual_address_read_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // M-2.3.1 Read Address with programming LED off
        // ====================================================================
        TestCase::new("M-2.3.1 Read Address with programming LED off").with_steps(vec![
            comment("Testcase 2.3.1 Read Address with programming LED off"),
            // Send IndividualAddress_Read broadcast
            inject("BC #EDI 00 00 E1 01 00"),
            expect_none(200),
            comment("Acceptance: No response may be sent."),
        ]),
        // ====================================================================
        // M-2.3.2 Send Response to BDUT with programming LED off
        // ====================================================================
        TestCase::new("M-2.3.2 Send Response to BDUT with programming LED off").with_steps(vec![
            comment("Testcase 2.3.2 Send Response to BDUT with programming LED off"),
            // Send IndividualAddress_Response broadcast
            inject("BC #EDI 00 00 E1 01 40"),
            expect_none(200),
            comment("Acceptance: No response may be sent."),
        ]),
        // ====================================================================
        // M-2.3.3 Read Address with programming LED on
        // ====================================================================
        TestCase::new("M-2.3.3 Read Address with programming LED on").with_steps(vec![
            comment("Testcase 2.3.3 Read Address with programming LED on"),
            comment("Activate Programming Mode via PropertyWrite"),
            // PropertyWrite to PID_PROG_MODE (Object 0, Property 54 = 0x36)
            inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 01"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 01", 500),
            // Send IndividualAddress_Read broadcast
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC #BDUT 00 00 E1 01 40", 200),
            comment("Acceptance: The BDUT sends an A_IndividualAddress_Response-PDU."),
            comment("Deactivate Programming Mode"),
            inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 00"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 500),
        ]),
        // ====================================================================
        // M-2.3.4 Send Response to BDUT with programming LED on
        // ====================================================================
        TestCase::new("M-2.3.4 Send Response to BDUT with programming LED on").with_steps(vec![
            comment("Testcase 2.3.4 Send Response to BDUT with programming LED on"),
            comment("Activate Programming Mode via PropertyWrite"),
            inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 01"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 01", 500),
            // Send IndividualAddress_Response broadcast - device should ignore it
            inject("BC #EDI 00 00 E1 01 40"),
            expect_none(200),
            comment("Acceptance: No response may be sent."),
            comment("Deactivate Programming Mode"),
            inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 00"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 500),
        ]),
    ];

    TestSuite::new("M-2.3 IndividualAddress_Read", vars).with_cases(cases)
}

// ============================================================================
// M-2.4 IndividualAddress_Write Tests
// ============================================================================

/// Create IndividualAddress_Write test suite
pub fn create_individual_address_write_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // M-2.4.1 Set Address with programming LED off
        // ====================================================================
        TestCase::new("M-2.4.1 Set Address with programming LED off").with_steps(vec![
            comment("Testcase 2.4.1 Set Address with programming LED off"),
            // Send IndividualAddress_Write broadcast (try to set address to 12 03)
            inject("BC #EDI 00 00 E3 00 C0 12 03"),
            expect_none(200),
            comment("Acceptance: No reaction of the BDUT - BDUT keeps individual address as downloaded prior to starting the test."),
            comment("Activate Programming Mode"),
            inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 01"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 01", 500),
            // Verify address unchanged via IndividualAddress_Read
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC #BDUT 00 00 E1 01 40", 200),
            comment("Deactivate Programming Mode"),
            inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 00"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 500),
        ]),
        // ====================================================================
        // M-2.4.2 Set Address with programming LED on
        // ====================================================================
        TestCase::new("M-2.4.2 Set Address with programming LED on").with_steps(vec![
            comment("Testcase 2.4.2 Set Address with programming LED on"),
            comment("Activate Programming Mode"),
            inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 01"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 01", 500),
            // Send IndividualAddress_Write broadcast (set address to 12 03)
            inject("BC #EDI 00 00 E3 00 C0 12 03"),
            expect_none(200),
            comment("Acceptance: The BDUT now has the individual address 1203H."),
            // Verify new address via IndividualAddress_Read
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC 12 03 00 00 E1 01 40", 200),
            comment("Clean up - restore original address"),
            inject("BC #EDI 00 00 E3 00 C0 #BDUT"),
            // Verify address restored
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC #BDUT 00 00 E1 01 40", 200),
            comment("Deactivate Programming Mode"),
            inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 00"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 500),
        ]),
    ];

    TestSuite::new("M-2.4 IndividualAddress_Write", vars).with_cases(cases)
}

// ============================================================================
// M-2.5 DeviceDescriptor_Read Tests
// ============================================================================

/// Create DeviceDescriptor_Read Type 0 test suite
///
/// Prior to starting the test, set the individual address of the BDUT to a fix value (e.g. 1001H).
pub fn create_device_descriptor_type0_suite() -> TestSuite {
    let mut vars = create_test_variables();
    // DD0_RESPONSE: Device Descriptor Type 0 response (2 bytes, wildcard by default)
    vars.insert("DD0_RESPONSE".to_string(), TestVariable::Bytes(vec![0x57, 0xB0]));

    let cases = vec![
        // ====================================================================
        // M-2.5.1 Read Device Descriptor Type 0, connection-oriented
        // ====================================================================
        TestCase::new("M-2.5.1 Read Device Descriptor Type 0, connection-oriented").with_steps(vec![
            comment("Testcase 2.5.1 Read Device Descriptor Type 0, connection-oriented"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // DeviceDescriptor_Read Type 0 (seq 0)
            inject("BC #EDI #BDUT 61 43 00"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 0),
            // Expect DeviceDescriptor_Response
            expect("BC #BDUT #EDI 63 43 40 #DD0_RESPONSE.0 #DD0_RESPONSE.1", 400),
            // T_Ack
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("Acceptance: The BDUT sends a telegram with an A_DeviceDescriptor_Response-PDU, containing the type and version or answers with the lowest Device Descriptor it supports."),
        ]),
        // ====================================================================
        // M-2.5.2 Read Device Descriptor Type 0, connectionless
        // ====================================================================
        TestCase::new("M-2.5.2 Read Device Descriptor Type 0, connectionless").with_steps(vec![
            comment("Testcase 2.5.2 Read Device Descriptor Type 0, connectionless"),
            // DeviceDescriptor_Read Type 0 (connectionless)
            inject("BC #EDI #BDUT 61 03 00"),
            // Expect DeviceDescriptor_Response
            expect("BC #BDUT #EDI 63 03 40 #DD0_RESPONSE.0 #DD0_RESPONSE.1", 200),
            comment("Acceptance: The BDUT sends a telegram with an A_DeviceDescriptor_Response-PDU, containing the type and version or the lowest Device Descriptor it supports."),
        ]),
    ];

    TestSuite::new("M-2.5 DeviceDescriptor_Read Type 0", vars).with_cases(cases)
}

/// Create DeviceDescriptor_Read Type 2 test suite
///
/// Note: Type 2 is optional. Devices that don't support it should return error code 0x7F.
pub fn create_device_descriptor_type2_suite() -> TestSuite {
    let mut vars = create_test_variables();
    // DD2_RESPONSE: Device Descriptor Type 2 response (14 bytes)
    vars.insert(
        "DD2_RESPONSE".to_string(),
        TestVariable::Bytes(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E]),
    );

    let cases = vec![
        // ====================================================================
        // M-2.5.3 Read Device Descriptor Type 2, connection-oriented
        // ====================================================================
        TestCase::new("M-2.5.3 Read Device Descriptor Type 2, connection-oriented").with_steps(vec![
            comment("Testcase 2.5.3 Read Device Descriptor Type 2, connection-oriented"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // DeviceDescriptor_Read Type 2 (seq 0)
            inject("BC #EDI #BDUT 61 43 02"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 0),
            // Expect DeviceDescriptor_Response Type 2 (14 bytes)
            expect("BC #BDUT #EDI 6F 43 42 #DD2_RESPONSE.0 #DD2_RESPONSE.1 #DD2_RESPONSE.2 #DD2_RESPONSE.3 #DD2_RESPONSE.4 #DD2_RESPONSE.5 #DD2_RESPONSE.6 #DD2_RESPONSE.7 #DD2_RESPONSE.8 #DD2_RESPONSE.9 #DD2_RESPONSE.10 #DD2_RESPONSE.11 #DD2_RESPONSE.12 #DD2_RESPONSE.13", 400),
            comment("Error code in case Device Descriptor Type 2 not supported."),
            // T_Ack
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("Acceptance: when The BDUT supports DD2, it shall send a telegram with an A_DeviceDescriptor_Response-PDU, containing the correct DD2 information. When the BDUT does not support DD2, it shall answer with the error code."),
        ]),
        // ====================================================================
        // M-2.5.4 Read Device Descriptor Type 2, connectionless
        // ====================================================================
        TestCase::new("M-2.5.4 Read Device Descriptor Type 2, connectionless").with_steps(vec![
            comment("Testcase 2.5.4 Read Device Descriptor Type 2, connectionless"),
            // DeviceDescriptor_Read Type 2 (connectionless)
            inject("BC #EDI #BDUT 61 03 02"),
            // Expect DeviceDescriptor_Response Type 2 (14 bytes)
            expect("BC #BDUT #EDI 6F 03 42 #DD2_RESPONSE.0 #DD2_RESPONSE.1 #DD2_RESPONSE.2 #DD2_RESPONSE.3 #DD2_RESPONSE.4 #DD2_RESPONSE.5 #DD2_RESPONSE.6 #DD2_RESPONSE.7 #DD2_RESPONSE.8 #DD2_RESPONSE.9 #DD2_RESPONSE.10 #DD2_RESPONSE.11 #DD2_RESPONSE.12 #DD2_RESPONSE.13", 200),
            comment("Error code in case Device Descriptor Type 2 not supported."),
            comment("Acceptance: when The BDUT supports DD2, it shall send a telegram with an A_DeviceDescriptor_Response-PDU. When not supported, it shall answer with error code."),
        ]),
    ];

    TestSuite::new("M-2.5 DeviceDescriptor_Read Type 2", vars).with_cases(cases)
}

/// Create DeviceDescriptor_Read Illegal Types test suite
///
/// Tests all Device Descriptor types 0x01 through 0x3F (except 0x00 and 0x02 which are valid).
/// Each type should return error code 0x7F.
///
/// M-2.5.5: Connection-oriented (skips types 0x00 and 0x02)
/// M-2.5.6: Connectionless (tests all types 0x01-0x3F)
pub fn create_device_descriptor_illegal_types_suite() -> TestSuite {
    use super::helpers::inject_delay;

    let vars = create_test_variables();

    // ========================================================================
    // M-2.5.5: Connection-oriented illegal DD types
    // ========================================================================
    let mut steps_co = vec![
        comment("Testcase M-2.5.5 Read illegal Device Descriptor Types, connection-oriented"),
        // T_Connect
        inject_delay("B0 #EDI #BDUT 60 80", 200),
    ];

    // Test illegal DD types: 0x01, 0x03-0x3F (skip 0x00 and 0x02 which are valid)
    // The sequence number cycles 0-15 (0x0-0xF in TPCI bits)
    let illegal_types_co: Vec<u8> = (0x01..=0x3F).filter(|&t| t != 0x00 && t != 0x02).collect();

    for (i, dd_type) in illegal_types_co.iter().enumerate() {
        let seq = (i % 16) as u8;
        // TPCI byte: 0x43 base + (seq << 2) for sequence number
        // This is 0x40 | (seq << 2) | 0x03
        let tpci_req = 0x43 | (seq << 2);
        // T_Ack TPCI: C2, C6, CA, CE, D2, D6, DA, DE, E2, E6, EA, EE, F2, F6, FA, FE, then C2...
        let tpci_ack = 0xC2 | (seq << 2);

        // DeviceDescriptor_Read with illegal type
        steps_co.push(inject(&format!("BC #EDI #BDUT 61 {:02X} {:02X}", tpci_req, dd_type)));
        // Expect T_Ack
        steps_co.push(expect(&format!("B0 #BDUT #EDI 60 {:02X}", tpci_ack), 200));
        // Expect error response 0x7F
        steps_co.push(expect(&format!("BC #BDUT #EDI 61 {:02X} 7F", tpci_req), 500));
        // Send T_Ack
        steps_co.push(inject_delay(&format!("B0 #EDI #BDUT 60 {:02X}", tpci_ack), 200));
    }

    // T_Disconnect
    steps_co.push(inject_delay("B0 #EDI #BDUT 60 81", 200));
    steps_co.push(comment("Acceptance: BDUT returns error code 0x7F for all illegal DD types."));

    // ========================================================================
    // M-2.5.6: Connectionless illegal DD types
    // ========================================================================
    let mut steps_cl = vec![comment("Testcase M-2.5.6 Read illegal Device Descriptor Types, connectionless")];

    // Test illegal DD types: 0x01, 0x03-0x3F (skip 0x00 and 0x02 which are valid)
    let illegal_types_cl: Vec<u8> = (0x01..=0x3F).filter(|&t| t != 0x00 && t != 0x02).collect();
    for dd_type in illegal_types_cl {
        // DeviceDescriptor_Read with illegal type (connectionless: TPCI = 0x03)
        steps_cl.push(inject(&format!("BC #EDI #BDUT 61 03 {:02X}", dd_type)));
        // Expect error response 0x7F
        steps_cl.push(expect(&format!("BC #BDUT #EDI 61 03 7F",), 500));
    }

    steps_cl.push(comment("Acceptance: The BDUT sends a telegram with a negative A_DeviceDescriptor_Response-PDU."));

    let cases = vec![
        TestCase::new("M-2.5.5 Read Illegal Device Descriptor Types, connection-oriented").with_steps(steps_co),
        TestCase::new("M-2.5.6 Read Illegal Device Descriptor Types, connectionless").with_steps(steps_cl),
    ];

    TestSuite::new("M-2.5 DeviceDescriptor_Read Illegal Types", vars).with_cases(cases)
}

// ============================================================================
// M-2.6 Memory_Read Tests
// ============================================================================

/// Create variables for Memory Access tests
///
/// Based on the EITT specification:
/// - MEMPOS: First accessible memory position (0x0200 = 512)
/// - MEMPOS_LASTACCESS: Last accessible memory position (0x02FF = 767)
/// - MEMPOS_PROTECTED: Protected (unmapped) memory position (0x1000 = 4096)
/// - MEM: Memory values from first position (01 02 03 ... 3F, 63 bytes)
fn create_memory_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = create_test_variables();

    // Memory positions (16-bit, big-endian)
    vars.insert("MEMPOS".to_string(), TestVariable::Bytes(vec![0x02, 0x00])); // 0x0200
    vars.insert("MEMPOS_LASTACCESS".to_string(), TestVariable::Bytes(vec![0x02, 0xFF])); // 0x02FF
    vars.insert("MEMPOS_PROTECTED".to_string(), TestVariable::Bytes(vec![0x10, 0x00])); // 0x1000 - unmapped region

    // MEM: 63 bytes of test data (01 02 03 ... 3F)
    let mem: Vec<u8> = (0x01..=0x3F).collect();
    vars.insert("MEM".to_string(), TestVariable::Bytes(mem));

    vars
}

/// Create Memory_Read test suite
///
/// Tests for A_Memory_Read service (2.6.x tests)
///
/// Memory model assumed:
/// - 0x0200-0x02FF: accessible memory area (linear_memory)
/// - 0x1000+: protected/unmapped memory area
///
/// Test setup loads memory with values 01 02 03 ... at 0x0200, and FF at 0x02FF
pub fn create_memory_read_suite() -> TestSuite {
    use super::helpers::inject_delay;

    let vars = create_memory_test_variables();

    // ====================================================================
    // Suite Preparation - loads memory with test data (2.6.1 Preparation)
    // ====================================================================
    let preparation = vec![
        comment("2.6.1 Preparation"),
        comment("Load memory area with default value (by means of A_Memory_Write-service)"),
        comment("Memory Model: 0200h to 02FFh accessible, 1000h+ unmapped/protected"),
        // T_Connect
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        // Memory_Write: 12 bytes at MEMPOS (0x0200) - accessible memory (seq 0)
        inject("BC #EDI #BDUT 6F 42 8C #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11"),
        expect("B0 #BDUT #EDI 60 C2", 500),
        // Memory_Write: 12 bytes at MEMPOS+12 (seq 1)
        inject("BC #EDI #BDUT 6F 46 8C #MEMPOS+12 #MEM.12 #MEM.13 #MEM.14 #MEM.15 #MEM.16 #MEM.17 #MEM.18 #MEM.19 #MEM.20 #MEM.21 #MEM.22 #MEM.23"),
        expect("B0 #BDUT #EDI 60 C6", 500),
        // Memory_Write: 12 bytes at MEMPOS+24 (seq 2)
        inject("BC #EDI #BDUT 6F 4A 8C #MEMPOS+24 #MEM.24 #MEM.25 #MEM.26 #MEM.27 #MEM.28 #MEM.29 #MEM.30 #MEM.31 #MEM.32 #MEM.33 #MEM.34 #MEM.35"),
        expect("B0 #BDUT #EDI 60 CA", 500),
        // Memory_Write: 12 bytes at MEMPOS+36 (seq 3)
        inject("BC #EDI #BDUT 6F 4E 8C #MEMPOS+36 #MEM.36 #MEM.37 #MEM.38 #MEM.39 #MEM.40 #MEM.41 #MEM.42 #MEM.43 #MEM.44 #MEM.45 #MEM.46 #MEM.47"),
        expect("B0 #BDUT #EDI 60 CE", 500),
        // Memory_Write: 12 bytes at MEMPOS+48 (seq 4)
        inject("BC #EDI #BDUT 6F 52 8C #MEMPOS+48 #MEM.48 #MEM.49 #MEM.50 #MEM.51 #MEM.52 #MEM.53 #MEM.54 #MEM.55 #MEM.56 #MEM.57 #MEM.58 #MEM.59"),
        expect("B0 #BDUT #EDI 60 D2", 500),
        // Memory_Write: 3 bytes at MEMPOS+60 (seq 5)
        inject("BC #EDI #BDUT 66 56 83 #MEMPOS+60 #MEM.60 #MEM.61 #MEM.62"),
        expect("B0 #BDUT #EDI 60 D6", 500),
        // Memory_Write: 1 byte (0xFF) at MEMPOS_LASTACCESS (0x02FF) (seq 6)
        inject("BC #EDI #BDUT 64 5A 81 #MEMPOS_LASTACCESS FF"),
        expect("B0 #BDUT #EDI 60 DA", 500),
        // T_Disconnect
        inject_delay("B0 #EDI #BDUT 60 81", 500),
    ];

    let cases = vec![
        // ====================================================================
        // M-2.6.2 Accessible Memory Area
        // ====================================================================
        TestCase::new("M-2.6.2 Accessible Memory Area").with_steps(vec![
            comment("Testcase 2.6.2 Accessible Memory Area"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Memory_Read: 10 bytes at MEMPOS (seq 0)
            inject("BC #EDI #BDUT 63 42 0A #MEMPOS"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance: the BDUT sends an A_Memory_Response-PDU with the required data."),
            // Expect Memory_Response with 10 bytes
            expect("BC #BDUT #EDI 6D 42 4A #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9", 400),
            // Send T_Ack
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.6.3 Protected Memory Area
        // ====================================================================
        TestCase::new("M-2.6.3 Protected Memory Area").with_steps(vec![
            comment("Testcase 2.6.3 Protected Memory Area"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Memory_Read: 10 bytes at MEMPOS_PROTECTED (seq 0)
            inject("BC #EDI #BDUT 63 42 0A #MEMPOS_PROTECTED"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance: the BDUT sends an A_Memory_Response-PDU with length byte set to 0 and no data."),
            // Expect Memory_Response with length 0 (error)
            expect("BC #BDUT #EDI 63 42 40 #MEMPOS_PROTECTED", 400),
            // Send T_Ack
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // // ====================================================================
        // // M-2.6.4 Partly protected Memory Area - for devices not supporting EFF
        // // ====================================================================
        // TestCase::new("M-2.6.4 Partly protected Memory Area - for devices not supporting EFF").with_steps(vec![
        //     comment("Testcase 2.6.4 Partly protected Memory Area - for devices not supporting EFF"),
        //     // T_Connect
        //     inject_delay("B0 #EDI #BDUT 60 80", 200),
        //     // Memory_Read: 2 bytes at MEMPOS_LASTACCESS (spans into protected area)
        //     inject("BC #EDI #BDUT 63 42 02 #MEMPOS_LASTACCESS"),
        //     // Expect T_Ack
        //     expect("B0 #BDUT #EDI 60 C2", 0),
        //     comment("Acceptance: the BDUT sends an A_Memory_Response-PDU with length byte set to 0 and no data."),
        //     // Expect Memory_Response with length 0 (error - partly protected)
        //     expect("BC #BDUT #EDI 63 42 40 #MEMPOS_LASTACCESS", 400),
        //     // Send T_Ack
        //     inject_delay("B0 #EDI #BDUT 60 C2", 200),
        //     // T_Disconnect
        //     inject_delay("B0 #EDI #BDUT 60 81", 200),
        // ]),
        // // ====================================================================
        // // M-2.6.5 Illegal Length - accessible Memory Area - for devices not supporting EFF
        // // ====================================================================
        // TestCase::new("M-2.6.5 Illegal Length - accessible Memory Area - for devices not supporting EFF").with_steps(vec![
        //     comment("Testcase 2.6.5 Illegal Length - accessible Memory Area  - for devices not supporting EFF"),
        //     // T_Connect
        //     inject_delay("B0 #EDI #BDUT 60 80", 200),
        //     // Memory_Read: 13 bytes at MEMPOS (> 12 bytes max for SFF)
        //     inject("BC #EDI #BDUT 63 42 0D #MEMPOS"),
        //     // Expect T_Ack
        //     expect("B0 #BDUT #EDI 60 C2", 0),
        //     comment("Acceptance: the BDUT sends an A_Memory_Response-PDU with length byte set to 0 and no data."),
        //     // Expect Memory_Response with length 0 (error - illegal length)
        //     expect("BC #BDUT #EDI 63 42 40 #MEMPOS", 400),
        //     // Send T_Ack
        //     inject_delay("B0 #EDI #BDUT 60 C2", 200),
        //     // T_Disconnect
        //     inject_delay("B0 #EDI #BDUT 60 81", 200),
        // ]),
        // ====================================================================
        // M-2.6.6 Accessible Memory Area – for devices supporting EFF
        // ====================================================================
        TestCase::new("M-2.6.6 Accessible Memory Area - for devices supporting EFF").with_steps(vec![
            comment("Testcase 2.6.6 Accessible Memory Area - for devices supporting EFF"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Memory_Read: 13 bytes at MEMPOS (SFF request, but response requires EFF)
            inject("BC #EDI #BDUT 63 42 0D #MEMPOS"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance: the BDUT sends an A_Memory_Response-PDU with the required data in EFF."),
            // Expect Memory_Response in EFF format (3C 60 = EFF control bytes)
            // EFF: 3C 60 SRC DST LEN TPCI APCI_HI ADDR DATA...
            // LEN = 0x10 (16 bytes: TPCI + APCI + ADDR(2) + DATA(13) - 1 = 16)
            expect("3C 60 #BDUT #EDI 10 42 4D #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12", 400),
            // Send T_Ack
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // // ====================================================================
        // // M-2.6.7 Accessible Memory Area - conditional for devices supporting MAX_APDU_LENGTH < 66
        // // ====================================================================
        // TestCase::new("M-2.6.7 Accessible Memory Area - for devices with MAX_APDU_LENGTH < 66").with_steps(vec![
        //     comment("Testcase 2.6.7 Accessible Memory Area - conditional for devices supporting MAX_APDU_LENGTH &lt; 66"),
        //     // T_Connect
        //     inject_delay("B0 #EDI #BDUT 60 80", 200),
        //     // Memory_Read: 63 bytes at MEMPOS (0x3F)
        //     inject("BC #EDI #BDUT 63 42 3F #MEMPOS"),
        //     // Expect T_Ack
        //     expect("B0 #BDUT #EDI 60 C2", 0),
        //     comment("Acceptance: The BDUT sends an A_Memory_Response with the length set to 0 and no data."),
        //     // Expect Memory_Response in EFF with length 0 (error - too large)
        //     expect("3C 60 #BDUT #EDI 03 42 40 #MEMPOS", 400),
        //     // Send T_Ack
        //     inject_delay("B0 #EDI #BDUT 60 C2", 200),
        //     // T_Disconnect
        //     inject_delay("B0 #EDI #BDUT 60 81", 200),
        // ]),
        // ====================================================================
        // M-2.6.8 Accessible Memory Area - EFF - response fits in SFF
        // ====================================================================
        TestCase::new("M-2.6.8 Accessible Memory Area - EFF - response fits in SFF").with_steps(vec![
            comment("Testcase 2.6.8 Accessible Memory Area - EFF - response fits in SFF"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Memory_Read via EFF: 12 bytes at MEMPOS (0x0C)
            // EFF request: 3C 60 SRC DST LEN TPCI APCI ADDR
            inject("3C 60 #EDI #BDUT 03 42 0C #MEMPOS"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance: the BDUT sends an A_Memory_Response-PDU with the required data in SFF."),
            // Expect Memory_Response in SFF (response fits in standard frame)
            expect("BC #BDUT #EDI 6F 42 4C #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11", 400),
            // Send T_Ack
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.6.9 Accessible Memory Area - EFF - response fits in EFF
        // ====================================================================
        TestCase::new("M-2.6.9 Accessible Memory Area - EFF - response fits in EFF").with_steps(vec![
            comment("Testcase 2.6.9 Accessible Memory Area - EFF - response fits in EFF"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Memory_Read via EFF: 13 bytes at MEMPOS (0x0D)
            inject("3C 60 #EDI #BDUT 03 42 0D #MEMPOS"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance: the BDUT sends an A_Memory_Response-PDU with the required data in EFF."),
            // Expect Memory_Response in EFF
            expect("3C 60 #BDUT #EDI 10 42 4D #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12", 400),
            // Send T_Ack
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.6.10 Accessible Memory Area - supporting MAX_APDU_LENGTH >= 66
        // ====================================================================
        TestCase::new("M-2.6.10 Accessible Memory Area - supporting MAX_APDU_LENGTH >= 66").with_steps(vec![
            comment("Testcase 2.6.10 Accessible Memory Area - supporting MAX_APDU_LENGTH >= 66"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Memory_Read: 63 bytes at MEMPOS (0x3F)
            inject("BC #EDI #BDUT 63 42 3F #MEMPOS"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance: The BDUT sends an A_Memory_Response with the stored data."),
            // Expect Memory_Response in EFF with 63 bytes of data
            // LEN = 0x42 (66 bytes: TPCI + APCI + ADDR(2) + DATA(63) - 1 = 66)
            // Note: MEM only has 63 bytes (0x01-0x3F), so we use #MEM.0-#MEM.19 and literal bytes for rest
            expect("3C 60 #BDUT #EDI 42 42 7F #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12 #MEM.13 #MEM.14 #MEM.15 #MEM.16 #MEM.17 #MEM.18 #MEM.19 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F", 400),
            // Send T_Ack
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
    ];

    TestSuite::new("M-2.6 Memory_Read", vars).with_preparation(preparation).with_cases(cases)
}

// ============================================================================
// M-2.7 Memory_Write Tests
// ============================================================================

/// Create Memory_Write test suite
///
/// Tests for A_Memory_Write service (2.7.x tests)
///
/// Memory model assumed:
/// - 0x0200-0x02FF: accessible memory area (linear_memory)
/// - 0x1000+: protected/unmapped memory area
///
/// Test setup loads memory with values 01 02 03 ... at 0x0200, and FF at 0x02FF
pub fn create_memory_write_suite() -> TestSuite {
    use super::helpers::inject_delay;

    let vars = create_memory_test_variables();

    // ====================================================================
    // Suite Preparation - same as M-2.6 (loads memory with test data)
    // ====================================================================
    let preparation = vec![
        comment("M-2.7 Preparation (same as M-2.6)"),
        comment("Load memory area with default value (by means of A_Memory_Write-service)"),
        comment("Memory Model: 0200h to 02FFh accessible, 1000h+ unmapped/protected"),
        // T_Connect
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        // Memory_Write: 12 bytes at MEMPOS (0x0200) - accessible memory (seq 0)
        inject("BC #EDI #BDUT 6F 42 8C #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11"),
        expect("B0 #BDUT #EDI 60 C2", 500),
        // Memory_Write: 12 bytes at MEMPOS+12 (seq 1)
        inject("BC #EDI #BDUT 6F 46 8C #MEMPOS+12 #MEM.12 #MEM.13 #MEM.14 #MEM.15 #MEM.16 #MEM.17 #MEM.18 #MEM.19 #MEM.20 #MEM.21 #MEM.22 #MEM.23"),
        expect("B0 #BDUT #EDI 60 C6", 500),
        // Memory_Write: 12 bytes at MEMPOS+24 (seq 2)
        inject("BC #EDI #BDUT 6F 4A 8C #MEMPOS+24 #MEM.24 #MEM.25 #MEM.26 #MEM.27 #MEM.28 #MEM.29 #MEM.30 #MEM.31 #MEM.32 #MEM.33 #MEM.34 #MEM.35"),
        expect("B0 #BDUT #EDI 60 CA", 500),
        // Memory_Write: 12 bytes at MEMPOS+36 (seq 3)
        inject("BC #EDI #BDUT 6F 4E 8C #MEMPOS+36 #MEM.36 #MEM.37 #MEM.38 #MEM.39 #MEM.40 #MEM.41 #MEM.42 #MEM.43 #MEM.44 #MEM.45 #MEM.46 #MEM.47"),
        expect("B0 #BDUT #EDI 60 CE", 500),
        // Memory_Write: 12 bytes at MEMPOS+48 (seq 4)
        inject("BC #EDI #BDUT 6F 52 8C #MEMPOS+48 #MEM.48 #MEM.49 #MEM.50 #MEM.51 #MEM.52 #MEM.53 #MEM.54 #MEM.55 #MEM.56 #MEM.57 #MEM.58 #MEM.59"),
        expect("B0 #BDUT #EDI 60 D2", 500),
        // Memory_Write: 3 bytes at MEMPOS+60 (seq 5)
        inject("BC #EDI #BDUT 66 56 83 #MEMPOS+60 #MEM.60 #MEM.61 #MEM.62"),
        expect("B0 #BDUT #EDI 60 D6", 500),
        // Memory_Write: 1 byte (0xFF) at MEMPOS_LASTACCESS (0x02FF) (seq 6)
        inject("BC #EDI #BDUT 64 5A 81 #MEMPOS_LASTACCESS FF"),
        expect("B0 #BDUT #EDI 60 DA", 500),
        // T_Disconnect
        inject_delay("B0 #EDI #BDUT 60 81", 500),
    ];

    let cases = vec![
        // ====================================================================
        // M-2.7.1 Accessible Memory - no Verify
        // ====================================================================
        TestCase::new("M-2.7.1 Accessible Memory - no Verify").with_steps(vec![
            comment("Testcase 2.7.1 Accessible Memory - no Verify"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Memory_Write: 10 bytes at MEMPOS (seq 0)
            inject("BC #EDI #BDUT 6D 42 8A #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 200),
            comment("Acceptance: After reading the written memory, the same data is returned by the BDUT as written."),
            // Memory_Read: 10 bytes at MEMPOS (seq 1)
            inject("BC #EDI #BDUT 63 46 0A #MEMPOS"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 6D 42 4A #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.7.2 Partly protected Memory - no Verify
        // ====================================================================
        TestCase::new("M-2.7.2 Partly protected Memory - no Verify").with_steps(vec![
            comment("Testcase 2.7.2 Partly protected Memory - no Verify"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Setup: Write 0xFF to MEMPOS_LASTACCESS first (seq 0)"),
            inject("BC #EDI #BDUT 64 42 81 #MEMPOS_LASTACCESS FF"),
            expect("B0 #BDUT #EDI 60 C2", 200),
            // Memory_Write: 2 bytes at MEMPOS_LASTACCESS (spans into protected area, seq 1)
            inject("BC #EDI #BDUT 65 46 82 #MEMPOS_LASTACCESS 12 34"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C6", 200),
            comment("Acceptance: After reading the affected accessible memory area, a response shall be generated showing that data has not been modified."),
            // Memory_Read: 1 byte at MEMPOS_LASTACCESS (seq 2)
            inject("BC #EDI #BDUT 63 4A 01 #MEMPOS_LASTACCESS"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            // Device's first response is seq=0 (its own counter, not remote's)
            expect("BC #BDUT #EDI 64 42 41 #MEMPOS_LASTACCESS FF", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.7.3 Length inconsistency - accessible Memory - no Verify
        // ====================================================================
        TestCase::new("M-2.7.3 Length inconsistency - accessible Memory - no Verify").with_steps(vec![
            comment("Testcase 2.7.3 Length inconsistency - accessible Memory - no Verify"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Number is greater than data"),
            // Memory_Write: length=13 (0x8D) but only 12 bytes of data
            inject("BC #EDI #BDUT 6F 42 8D #MEMPOS FF FF FF FF FF FF FF FF FF FF FF FF"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 200),
            comment("Number is less than data"),
            // Memory_Write: length=11 (0x8B) but 12 bytes of data (seq 1)
            inject("BC #EDI #BDUT 6F 46 8B #MEMPOS FF FF FF FF FF FF FF FF FF FF FF FF"),
            expect("B0 #BDUT #EDI 60 C6", 200),
            comment("Acceptance: After reading the affected accessible memory area, a response shall be generated showing that data has not been modified."),
            // Memory_Read: 10 bytes at MEMPOS (seq 2)
            inject("BC #EDI #BDUT 63 4A 0A #MEMPOS"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 6D 42 4A #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 ", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.7.4 Accessible Memory – Verify on
        // ====================================================================
        TestCase::new("M-2.7.4 Accessible Memory - Verify on").with_steps(vec![
            comment("Testcase 2.7.4 Accessible Memory – Verify on"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Enable verify via PropertyWrite (Object 0, Property 0x0E, value 0x04)
            inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 04"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 04", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // Memory_Write: 10 bytes at MEMPOS (seq 1 - after previous PropertyWrite/Response exchange)
            inject("BC #EDI #BDUT 6D 46 8A #MEMPOS 99 88 77 66 55 44 33 22 11 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_Memory_Response-PDU with the data written."),
            expect("BC #BDUT #EDI 6D 46 4A #MEMPOS 99 88 77 66 55 44 33 22 11 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.7.5 Protected Memory – Verify on
        // ====================================================================
        TestCase::new("M-2.7.5 Protected Memory - Verify on").with_steps(vec![
            comment("Testcase 2.7.5 Protected Memory – Verify"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Enable verify"),
            inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 04"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 04", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // Memory_Write: 10 bytes at MEMPOS_PROTECTED (seq 1 - after PropertyWrite/Response)
            inject("BC #EDI #BDUT 6D 46 8A #MEMPOS_PROTECTED #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_Memory_Response with the length set to 0 and no data."),
            expect("BC #BDUT #EDI 63 46 40 #MEMPOS_PROTECTED", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.7.6 Partly protected Memory – Verify on
        // ====================================================================
        TestCase::new("M-2.7.6 Partly protected Memory - Verify on").with_steps(vec![
            comment("Testcase 2.7.6 Partly protected Memory – Verify"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Enable verify"),
            inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 04"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 04", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // Memory_Write: 2 bytes at MEMPOS_LASTACCESS (spans into protected, seq 1)
            inject("BC #EDI #BDUT 65 46 82 #MEMPOS_LASTACCESS 12 34"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_Memory_Response with the length set to 0 and no data."),
            expect("BC #BDUT #EDI 63 46 40 #MEMPOS_LASTACCESS", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.7.7 Length inconsistency – Verify on
        // ====================================================================
        // NOTE: The XML specification shows PropertyValueWrite using seqno=0, then
        // Memory_Write also using seqno=0. This is WRONG. The transport layer
        // increments recv_seq after any successfully received T_Data frame, regardless
        // of application layer semantics. After PropertyValueWrite with seqno=0,
        // the next frame must use seqno=1. This matches test 2.7.3 which correctly
        // uses incrementing sequence numbers. We follow the sane interpretation here.
        TestCase::new("M-2.7.7 Length inconsistency - Verify on").with_steps(vec![
            comment("Testcase 2.7.7 Length inconsistency - accessible Memory - Verify"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Enable verify"),
            // PropertyValueWrite with seq 0 to enable verify mode
            inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 04"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 04", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Number is greater than data"),
            // Memory_Write: length=3 (0x83) but only 2 bytes of data (seq 1)
            inject("BC #EDI #BDUT 65 46 83 #MEMPOS 12 34"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_Memory_Response with the length set to 0 and no data."),
            expect("BC #BDUT #EDI 63 46 40 #MEMPOS", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Number is less than data"),
            // Memory_Write: length=2 (0x82) but 3 bytes of data (seq 2)
            inject("BC #EDI #BDUT 66 4A 82 #MEMPOS AA BB CC"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 63 4A 40 #MEMPOS", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Acceptance: The BDUT sends an A_Memory_Response with the length set to 0 and no data. The memory has not been altered."),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.7.8 Accessible Memory - EFF - Verify
        // ====================================================================
        TestCase::new("M-2.7.8 Accessible Memory - EFF - Verify").with_steps(vec![
            comment("Testcase 2.7.8 Accessible Memory - EFF - Verify"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Enable verify"),
            inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 04"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 04", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // Memory_Write via EFF: 13 bytes at MEMPOS (seq 1)
            inject("3C 60 #EDI #BDUT 10 46 8D #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT replies with a Response in EFF containing the same data as written."),
            expect("3C 60 #BDUT #EDI 10 46 4D #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.7.9 Accessible Memory - EFF - respond SFF - Verify
        // ====================================================================
        TestCase::new("M-2.7.9 Accessible Memory - EFF - respond SFF - Verify").with_steps(vec![
            comment("Testcase 2.7.9 Accessible Memory - EFF - respond SFF - Verify"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Enable verify"),
            inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 04"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 04", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // Memory_Write via EFF: 4 bytes (fits in SFF response, seq 1)
            inject("3C 60 #EDI #BDUT 07 46 84 #MEMPOS AA BB CC DD"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT replies with a Response in SFF containing the same data as written."),
            expect("BC #BDUT #EDI 67 46 44 #MEMPOS AA BB CC DD", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // // ====================================================================
        // // M-2.7.10 Accessible Memory - EFF - exceeds MAX_APDU_LENGTH - Verify
        // // (Conditional: not applicable if MAX_APDU_LENGTH >= 66)
        // // ====================================================================
        // TestCase::new("M-2.7.10 Accessible Memory - EFF - exceeds MAX_APDU_LENGTH - Verify").with_steps(vec![
        //     comment("Testcase 2.7.10 Accessible Memory - EFF - exceeds MAX_APDU_LENGTH - Verify"),
        //     comment("This test case is CONDITIONAL and not applicable if the MAX_APDU_LENGTH is equal or greater than 66."),
        //     // T_Connect
        //     inject_delay("B0 #EDI #BDUT 60 80", 200),
        //     comment("Enable verify"),
        //     inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 04"),
        //     expect("B0 #BDUT #EDI 60 C2", 0),
        //     expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 04", 400),
        //     inject_delay("B0 #EDI #BDUT 60 C2", 200),
        //     // Memory_Write via EFF: 63 bytes (exceeds MAX_APDU_LENGTH for small devices, seq 1)
        //     inject("3C 60 #EDI #BDUT 42 46 BF #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12 #MEM.13 #MEM.14 #MEM.15 #MEM.16 #MEM.17 #MEM.18 #MEM.19 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F"),
        //     expect("B0 #BDUT #EDI 60 C6", 0),
        //     comment("The frame might be dropped and there would be no answer, even if Verify Mode is switched on"),
        //     comment("If the frame is not dropped, the next two telegrams shall be enabled"),
        //     expect("BC #BDUT #EDI 63 46 40 #MEMPOS", 400),
        //     inject_delay("B0 #EDI #BDUT 60 C6", 200),
        //     comment("Acceptance: The frames may be ignored. Reading memory from the device shows the data has not been changed."),
        //     inject("BC #EDI #BDUT 63 4A 04 #MEMPOS"),
        //     expect("B0 #BDUT #EDI 60 CA", 0),
        //     expect("BC #BDUT #EDI 67 4A 44 #MEMPOS AA BB CC DD", 400),
        //     inject_delay("B0 #EDI #BDUT 60 CA", 200),
        //     // T_Disconnect
        //     inject_delay("B0 #EDI #BDUT 60 81", 200),
        // ]),
        // ====================================================================
        // M-2.7.11 Length inconsistency - accessible Memory - EFF - Verify
        // ====================================================================
        TestCase::new("M-2.7.11 Length inconsistency - accessible Memory - EFF - Verify").with_steps(vec![
            comment("Testcase 2.7.11 Length inconsistency - accessible Memory - EFF - Verify"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Enable verify"),
            inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 04"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 04", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Number is greater than data (seq 1)"),
            inject("3C 60 #EDI #BDUT 16 46 94 #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12 #MEM.13 #MEM.14 #MEM.15 #MEM.16 #MEM.17 #MEM.18"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 63 46 40 #MEMPOS", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Number is less than data (seq 2)"),
            inject("3C 60 #EDI #BDUT 18 4A 94 #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12 #MEM.13 #MEM.14 #MEM.15 #MEM.16 #MEM.17 #MEM.18 #MEM.19 15"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 63 4A 40 #MEMPOS", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Acceptance: The BDUT sends an A_Memory_Response with the length set to 0 and no data."),
            comment("Disable verify before disconnect (incoming seq 3, device response seq 3)"),
            inject("BC #EDI #BDUT 66 4F D7 00 0E 10 01 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 00 0E 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.7.13 Accessible Memory - EFF - no Verify
        // ====================================================================
        TestCase::new("M-2.7.13 Accessible Memory - EFF - no Verify").with_steps(vec![
            comment("Testcase 2.7.13 Accessible Memory - EFF - no Verify"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Ensure verify is disabled (DEVICE_CONTROL = 0x00) - seq 0"),
            inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // Memory_Write via EFF: 13 bytes at MEMPOS (no verify, seq 1)
            inject("3C 60 #EDI #BDUT 10 46 8D #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12"),
            expect("B0 #BDUT #EDI 60 C6", 200),
            comment("Acceptance: After reading the written memory, the same data is returned by the BDUT as written."),
            // Read back to verify - incoming seq 2, device response seq 1
            inject("BC #EDI #BDUT 63 4A 0D #MEMPOS"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("3C 60 #BDUT #EDI 10 46 4D #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.7.14 Accessible Memory - EFF but fits SFF - no Verify
        // ====================================================================
        TestCase::new("M-2.7.14 Accessible Memory - EFF but fits SFF - no Verify").with_steps(vec![
            comment("Testcase 2.7.14 Accessible Memory - EFF but fits SFF - no Verify"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Memory_Write via EFF: 4 bytes (fits in SFF)
            inject("3C 60 #EDI #BDUT 07 42 84 #MEMPOS AA BB CC DD"),
            expect("B0 #BDUT #EDI 60 C2", 200),
            comment("Acceptance: After reading the written memory, the same data is returned by the BDUT as written."),
            // Read back to verify - incoming seq 1, but response is device's first data frame so seq 0
            inject("BC #EDI #BDUT 63 46 04 #MEMPOS"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 67 42 44 #MEMPOS AA BB CC DD", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // // ====================================================================
        // // M-2.7.15 Accessible Memory - EFF - exceeds MAX_APDU_LENGTH - no Verify
        // // (Conditional: not applicable if MAX_APDU_LENGTH >= 66)
        // // ====================================================================
        // TestCase::new("M-2.7.15 Accessible Memory - EFF - exceeds MAX_APDU_LENGTH - no Verify").with_steps(vec![
        //     comment("Testcase 2.7.15 Accessible Memory - EFF - exceeds MAX_APDU_LENGTH - no Verify"),
        //     comment("This test case is CONDITIONAL and not applicable if the MAX_APDU_LENGTH is equal or greater than 66."),
        //     // T_Connect
        //     inject_delay("B0 #EDI #BDUT 60 80", 200),
        //     // Memory_Write via EFF: 63 bytes (exceeds MAX_APDU_LENGTH for small devices)
        //     inject("3C 60 #EDI #BDUT 42 42 BF #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12 #MEM.13 #MEM.14 #MEM.15 #MEM.16 #MEM.17 #MEM.18 #MEM.19 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F"),
        //     expect("B0 #BDUT #EDI 60 C2", 200),
        //     comment("Acceptance: The frame shall be ignored. Reading memory from the device shows the data has not been changed."),
        //     // Read back - should show previous data (AA BB CC DD from M-2.7.14)
        //     // Incoming seq 1, response is device's first data frame so seq 0
        //     inject("BC #EDI #BDUT 63 46 04 #MEMPOS"),
        //     expect("B0 #BDUT #EDI 60 C6", 0),
        //     expect("BC #BDUT #EDI 67 42 44 #MEMPOS AA BB CC DD", 400),
        //     inject_delay("B0 #EDI #BDUT 60 C2", 200),
        //     // T_Disconnect
        //     inject_delay("B0 #EDI #BDUT 60 81", 200),
        // ]),
        // ====================================================================
        // M-2.7.16 Length inconsistency - accessible Memory - EFF - no Verify
        // ====================================================================
        TestCase::new("M-2.7.16 Length inconsistency - accessible Memory - EFF - no Verify").with_steps(vec![
            comment("Testcase 2.7.16 Length inconsistency - accessible Memory - EFF - no Verify"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Number is greater than data (seq 0)"),
            inject("3C 60 #EDI #BDUT 16 42 94 #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12 #MEM.13 #MEM.14 #MEM.15 #MEM.16 #MEM.17 #MEM.18"),
            expect("B0 #BDUT #EDI 60 C2", 200),
            comment("Number is less than data (seq 1)"),
            inject("3C 60 #EDI #BDUT 18 46 94 #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12 #MEM.13 #MEM.14 #MEM.15 #MEM.16 #MEM.17 #MEM.18 #MEM.19 15"),
            expect("B0 #BDUT #EDI 60 C6", 200),
            comment("Acceptance: The frame shall be ignored. Reading memory from the device shows the data has not been changed."),
            // Memory_Read (seq 2), response is device's first data frame so seq 0
            inject("BC #EDI #BDUT 63 4A 04 #MEMPOS"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 67 42 44 #MEMPOS AA BB CC DD", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.7.18 Accessible Memory - EFF - data matches maximum service length - Verify
        // (Conditional: MAX_APDU_LENGTH >= 66)
        // ====================================================================
        TestCase::new("M-2.7.18 Accessible Memory - EFF - max service length - Verify").with_steps(vec![
            comment("Testcase 2.7.18 Accessible Memory - EFF - data matches maximum service length - Verify"),
            comment("MAX_APDU_LENGTH is equal or greater than 66."),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Enable verify"),
            inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 04"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 04", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // Memory_Write via EFF: 63 bytes at MEMPOS (seq 1 - after PropertyWrite/Response)
            inject("3C 60 #EDI #BDUT 42 46 BF #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12 #MEM.13 #MEM.14 #MEM.15 #MEM.16 #MEM.17 #MEM.18 #MEM.19 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Memory_Response with the data written"),
            expect("3C 60 #BDUT #EDI 42 46 7F #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12 #MEM.13 #MEM.14 #MEM.15 #MEM.16 #MEM.17 #MEM.18 #MEM.19 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.7.19 Accessible Memory - EFF - matches maximum service length - no Verify
        // (Conditional: MAX_APDU_LENGTH >= 66)
        // ====================================================================
        TestCase::new("M-2.7.19 Accessible Memory - EFF - max service length - no Verify").with_steps(vec![
            comment("Testcase 2.7.19 Accessible Memory - EFF - matches maximum service length - no Verify"),
            comment("MAX_APDU_LENGTH is equal or greater 66."),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Ensure verify is disabled (DEVICE_CONTROL = 0x00) - seq 0"),
            inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // Memory_Write via EFF: 63 bytes at MEMPOS (seq 1)
            inject("3C 60 #EDI #BDUT 42 46 BF #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12 #MEM.13 #MEM.14 #MEM.15 #MEM.16 #MEM.17 #MEM.18 #MEM.19 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F"),
            expect("B0 #BDUT #EDI 60 C6", 200),
            comment("Acceptance: Reading memory from the device shows the data has been changed."),
            // Read back to verify - incoming seq 2, device response seq 1
            inject("BC #EDI #BDUT 63 4A 3F #MEMPOS"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("3C 60 #BDUT #EDI 42 46 7F #MEMPOS #MEM.0 #MEM.1 #MEM.2 #MEM.3 #MEM.4 #MEM.5 #MEM.6 #MEM.7 #MEM.8 #MEM.9 #MEM.10 #MEM.11 #MEM.12 #MEM.13 #MEM.14 #MEM.15 #MEM.16 #MEM.17 #MEM.18 #MEM.19 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // Note: M-2.7.12 and M-2.7.17 are complex conditional tests that require
        // more sophisticated handling and are not yet implemented
    ];

    TestSuite::new("M-2.7 Memory_Write", vars).with_preparation(preparation).with_cases(cases)
}

// ============================================================================
// M-2.8 ADC_Read Tests
// ============================================================================

/// Create variables for ADC tests
fn create_adc_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = create_test_variables();
    // Unsupported channel number (default 7 per EITT)
    vars.insert("UNSUPPORTED_CHANNEL_NUMBER".to_string(), TestVariable::Bytes(vec![0x07]));
    vars
}

/// Create the ADC_Read test suite (M-2.8.x)
///
/// Tests the A_ADC_Read service for reading analog-to-digital converter channels.
///
/// APCI format:
/// - A_ADC_Read: 8n (where n = channel in bits 5-0) + count byte
/// - A_ADC_Response: Cn (where n = channel in bits 5-0) + count byte + sum (2 bytes)
///
/// The response contains:
/// - Channel number (same as request)
/// - Read count (0 if channel not supported, otherwise same as request)
/// - Sum of A/D converter values (2 bytes, only meaningful if count > 0)
pub fn create_adc_read_suite() -> TestSuite {
    use super::helpers::inject_delay;
    let vars = create_adc_test_variables();

    let cases = vec![
        // ====================================================================
        // M-2.8.1 Correct Channel Number (Channel 1 and 1 count)
        // ====================================================================
        TestCase::new("M-2.8.1 Correct Channel Number (Channel 1 and 1 count)").with_steps(vec![
            comment("Testcase 2.8.1 Correct Channel Number (Channel 1 and 1 count)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_ADC_Read: APCI 81 (channel 1), count 01
            inject("BC #EDI #BDUT 62 41 81 01"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance: The BDUT sends an A_ADC_Response-PDU with the correct data."),
            // A_ADC_Response: APCI C1 (channel 1), count 01, sum ?? ??
            expect("BC #BDUT #EDI 64 41 C1 01 ?? ??", 400),
            // Send T_Ack
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.8.2 Correct Channel Number (Channel 4 and 1 count)
        // ====================================================================
        TestCase::new("M-2.8.2 Correct Channel Number (Channel 4 and 1 count)").with_steps(vec![
            comment("Testcase 2.8.2 Correct Channel Number (Channel 4 and 1 count)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_ADC_Read: APCI 84 (channel 4), count 01
            inject("BC #EDI #BDUT 62 41 84 01"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance: The BDUT sends an A_ADC_Response-PDU with the correct data."),
            // A_ADC_Response: APCI C4 (channel 4), count 01, sum ?? ??
            expect("BC #BDUT #EDI 64 41 C4 01 ?? ??", 400),
            // Send T_Ack
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.8.3 Unsupported Channel Number
        // ====================================================================
        TestCase::new("M-2.8.3 Unsupported Channel Number").with_steps(vec![
            comment("Testcase 2.8.3 Unsupported Channel Number (e.g. Channel 7 and 1 count)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_ADC_Read: APCI 87 (channel 7 from #UNSUPPORTED_CHANNEL_NUMBER+128), count 01
            inject("BC #EDI #BDUT 62 41 #UNSUPPORTED_CHANNEL_NUMBER+128 01"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance: The BDUT sends an A_ADC_Response-PDU with the count set to zero."),
            // A_ADC_Response: APCI C7 (channel 7), count 00 (unsupported), sum 00 00
            expect("BC #BDUT #EDI 64 41 C7 00 00 00", 400),
            comment("Alternatively the BDUT - as it supports all possible channel numbers - sends an A_ADC_Response PDU with the correct data."),
            // Send T_Ack
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
    ];

    TestSuite::new("M-2.8 ADC_Read", vars).with_cases(cases)
}

// ============================================================================
// M-2.9 Restart Tests
// ============================================================================

/// Create variables for Restart tests
fn create_restart_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = create_test_variables();
    // Factory default address (FF FF = 15.15.255)
    vars.insert("BDUT_DEFAULT_ADDR".to_string(), TestVariable::Bytes(vec![0xFF, 0xFF]));
    // Authorization key for access level where BDUT prevents master reset
    vars.insert("AUTHORIZATION_KEY".to_string(), TestVariable::Bytes(vec![0x12, 0x34, 0x56, 0x78]));
    // Access level where BDUT prevents master reset
    vars.insert("ACCESS_LEVEL".to_string(), TestVariable::Bytes(vec![0x01]));
    vars
}

/// Create the Restart test suite (M-2.9.x)
///
/// Tests the A_Restart service for device restart and master reset operations.
///
/// APCI format:
/// - A_Restart (Basic): 03 80
/// - A_Restart (Master Reset): 03 81 <erase_code> <channel>
/// - A_Restart_Response: 03 A1 <error_code> <process_time (2 bytes)>
///
/// Erase codes:
/// - 0x01: Confirmed restart (basic restart with response)
/// - 0x02: Factory reset (reset all settings including IA)
/// - 0x03: Reset IA only
/// - 0x04: Reset Application Program
/// - 0x05: Reset Parameters
/// - 0x06: Reset Links
/// - 0x07: Factory reset without IA
///
/// Error codes in response:
/// - 0x00: No error
/// - 0x01: Access denied
/// - 0x02: Unsupported erase code
/// - 0x03: Invalid channel number
pub fn create_restart_suite() -> TestSuite {
    use super::helpers::inject_delay;
    let vars = create_restart_test_variables();

    let cases = vec![
        // ====================================================================
        // M-2.9 Restart preparation
        // ====================================================================
        TestCase::new("M-2.9 Restart preparation").with_steps(vec![
            comment("Testcase 2.9 Restart preparation"),
            comment("Activate Programming Mode and setting IA"),
            inject("BC #EDI #BDUT_DEFAULT_ADDR 66 03 D7 00 36 10 01 01"),
            expect("BC #BDUT_DEFAULT_ADDR #EDI 66 03 D6 00 36 10 01 01", 500),
            inject_delay("BC #EDI 00 00 E3 00 C0 #BDUT", 200),
        ]),
        // ====================================================================
        // M-2.9.1 Send Basic Restart (connection oriented)
        // ====================================================================
        TestCase::new("M-2.9.1 Send Basic Restart (connection oriented)").with_steps(vec![
            comment("Testcase 2.9.1 Send Basic Restart (connection oriented)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Restart (basic): APCI 03 80
            inject("BC #EDI #BDUT 61 43 80"),
            // Expect T_Ack
            expect("B0 #BDUT #EDI 60 C2", 200),
            // T_Disconnect (use #WAIT variable for restart delay)
            inject_delay("B0 #EDI #BDUT 60 81", 5000),
            // Drain ROI GroupValue_Read messages triggered by simulated restart.
            comment("Acceptance: Compare BDUT's reaction to what the manufacturer has declared in the supplied PIXIT forms for Management (e.g. previously active programming mode deactivated)."),
            // Verify programming mode is off by reading PID_PROG_MODE
            inject("BC #EDI #BDUT 65 03 D5 00 36 10 01"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 500),
        ]),
        // ====================================================================
        // M-2.9.2 Send Basic Restart (connectionless)- optional (if supported)
        // ====================================================================
        TestCase::new("M-2.9.2 Send Basic Restart (connectionless)- optional (if supported)").with_steps(vec![
            comment("Testcase 2.9.2 Send Basic Restart (connectionless)- optional (if supported)"),
            comment("Activate Programming Mode and setting IA"),
            inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 01"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 01", 500),
            comment("Send Basic restart"),
            inject_delay("BC #EDI #BDUT 61 03 80", 5000),
            comment("Acceptance: Compare BDUT's reaction to what the manufacturer has declared in the supplied PIXIT forms for Management  - verify that previously active programming mode deactivated"),
            inject("BC #EDI #BDUT 65 03 D5 00 36 10 01"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 500),
        ]),
        // ====================================================================
        // M-2.9.3 Send Master Reset – confirmed Restart (connectionless)optional (if supported)
        // ====================================================================
        TestCase::new("M-2.9.3 Send Master Reset - confirmed Restart (connectionless)optional (if supported)").with_steps(vec![
            comment("Testcase 2.9.3 Send Master Reset – confirmed Restart (connectionless)optional (if supported)"),
            comment("Activate Programming Mode and setting IA"),
            inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 01"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 01", 500),
            comment("Send Confirmed restart"),
            inject("BC #EDI #BDUT 63 03 81 01 00"),
            expect("BC #BDUT #EDI 64 03 A1 00 ?? ??", 5000),
            comment("Acceptance: Compare BDUT's reaction to what the manufacturer has declared in the supplied PIXIT forms for Management: is a confirmed alternative to the unconfirmed basis restart."),
            comment("Alternatively if the system profile does not require support of this erase code"),
            comment("Programming mode is swithed off"),
            inject("BC #EDI #BDUT 65 03 D5 00 36 10 01"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 500),
        ]),
        // ====================================================================
        // M-2.9.3a Send Master Reset – confirmed Restart (connection oriented)
        // ====================================================================
        TestCase::new("M-2.9.3a Send Master Reset - confirmed Restart (connection oriented)").with_steps(vec![
            comment("Testcase 2.9.3a Send Master Reset – confirmed Restart (connection oriented)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Enable programming mode
            inject("BC #EDI #BDUT 66 43 D7 00 36 10 01 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 36 10 01 01", 500),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // Send Master Reset with erase code 0x01 (confirmed restart)
            inject("B0 #EDI #BDUT 63 43 81 01 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("B0 #BDUT #EDI 64 43 A1 00 ?? ??", 200),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 5000),
            comment("Acceptance: Compare BDUT's reaction to what the manufacturer has declared in the supplied PIXIT forms for Management: is a confirmed alternative to the unconfirmed basis restart."),
            // Verify programming mode is off after restart
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 65 43 D5 00 36 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 00 36 10 01 00", 500),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.9.4 Send Master Reset - Factory Reset (connectionless)
        // ====================================================================
        TestCase::new("M-2.9.4 Send Master Reset - Factory Reset (connectionless)").with_steps(vec![
            comment("Testcase 2.9.4 Send Master Reset - Factory Reset (connectionless)"),
            // Send Factory Reset (erase code 0x02)
            inject("BC #EDI #BDUT 63 03 81 02 00"),
            comment("Expect A_Restart_Response with no error"),
            expect("BC #BDUT #EDI 64 03 A1 00 ?? ??", 2000),
            comment("Acceptance: IA, Domain Address, IP settings should all be reset"),
            comment("Clean up: Restore BDUT address"),
            // Activate programming mode on default address
            inject_delay("BC #EDI #BDUT_DEFAULT_ADDR 66 03 D7 00 36 10 01 01", 2000),
            expect("BC #BDUT_DEFAULT_ADDR #EDI 66 03 D6 00 36 10 01 01", 500),
            // Write IA back to BDUT
            inject("BC #EDI 00 00 E3 00 C0 #BDUT"),
            // Deactivate programming mode
            inject_delay("BC #EDI #BDUT 66 03 D7 00 36 10 01 00", 200),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 500),
        ]),
        // ====================================================================
        // M-2.9.4a Send Master Reset - Factory Reset (connection oriented)
        // ====================================================================
        TestCase::new("M-2.9.4a Send Master Reset - Factory Reset (connection oriented)").with_steps(vec![
            comment("Testcase 2.9.4a Send Master Reset - Factory Reset (connection oriented)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Send Factory Reset (erase code 0x02)
            inject("B0 #EDI #BDUT 63 43 81 02 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("B0 #BDUT #EDI 64 43 A1 00 ?? ??", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("Acceptance: IA, Domain Address, IP settings should all be reset"),
            comment("Clean up: Restore BDUT address"),
            inject_delay("BC #EDI #BDUT_DEFAULT_ADDR 66 03 D7 00 36 10 01 01", 2000),
            expect("BC #BDUT_DEFAULT_ADDR #EDI 66 03 D6 00 36 10 01 01", 500),
            inject("BC #EDI 00 00 E3 00 C0 #BDUT"),
            inject_delay("BC #EDI #BDUT 66 03 D7 00 36 10 01 00", 200),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 500),
        ]),
        // ====================================================================
        // M-2.9.5 Send Master Reset - ResetIA (connectionless)
        // ====================================================================
        TestCase::new("M-2.9.5 Send Master Reset - ResetIA (connectionless)").with_steps(vec![
            comment("Testcase 2.9.5 Send Master Reset - ResetIA (connectionless)"),
            // Send ResetIA (erase code 0x03)
            inject("BC #EDI #BDUT 63 03 81 03 00"),
            expect("BC #BDUT #EDI 64 03 A1 00 ?? ??", 2000),
            comment("Acceptance: IA shall be reset to medium specific default"),
            comment("Clean up: Restore BDUT address"),
            inject_delay("BC #EDI #BDUT_DEFAULT_ADDR 66 03 D7 00 36 10 01 01", 2000),
            expect("BC #BDUT_DEFAULT_ADDR #EDI 66 03 D6 00 36 10 01 01", 500),
            inject("BC #EDI 00 00 E3 00 C0 #BDUT"),
            inject_delay("BC #EDI #BDUT 66 03 D7 00 36 10 01 00", 200),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 500),
        ]),
        // ====================================================================
        // M-2.9.5a Send Master Reset - ResetIA (connection oriented)
        // ====================================================================
        TestCase::new("M-2.9.5a Send Master Reset - ResetIA (connection oriented)").with_steps(vec![
            comment("Testcase 2.9.5a Send Master Reset - ResetIA (connection oriented)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Send ResetIA (erase code 0x03)
            inject("B0 #EDI #BDUT 63 43 81 03 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("B0 #BDUT #EDI 64 43 A1 00 ?? ??", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("Acceptance: IA shall be reset to medium specific default"),
            comment("Clean up"),
            inject_delay("BC #EDI #BDUT_DEFAULT_ADDR 66 03 D7 00 36 10 01 01", 2000),
            expect("BC #BDUT_DEFAULT_ADDR #EDI 66 03 D6 00 36 10 01 01", 500),
            inject("BC #EDI 00 00 E3 00 C0 #BDUT"),
            inject_delay("BC #EDI #BDUT 66 03 D7 00 36 10 01 00", 200),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 500),
        ]),
        // ====================================================================
        // M-2.9.6 Send Master Reset - ResetAP (connectionless)
        // ====================================================================
        TestCase::new("M-2.9.6 Send Master Reset - ResetAP (connectionless)").with_steps(vec![
            comment("Testcase 2.9.6 Send Master Reset - ResetAP (connectionless)"),
            // Send ResetAP (erase code 0x04)
            inject("BC #EDI #BDUT 63 03 81 04 00"),
            expect("BC #BDUT #EDI 64 03 A1 00 ?? ??", 2000),
            comment("Acceptance: Application Program Memory shall be reset to default"),
        ]),
        // ====================================================================
        // M-2.9.6a Send Master Reset - ResetAP (connection oriented)
        // ====================================================================
        TestCase::new("M-2.9.6a Send Master Reset - ResetAP (connection oriented)").with_steps(vec![
            comment("Testcase 2.9.6a Send Master Reset - ResetAP (connection oriented)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Send ResetAP (erase code 0x04)
            inject("B0 #EDI #BDUT 63 43 81 04 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("B0 #BDUT #EDI 64 43 A1 00 ?? ??", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("Acceptance: Application Program Memory shall be reset to default"),
        ]),
        // ====================================================================
        // M-2.9.7 Send Master Reset - ResetParam (connectionless)
        // ====================================================================
        TestCase::new("M-2.9.7 Send Master Reset - ResetParam (connectionless)").with_steps(vec![
            comment("Testcase 2.9.7 Send Master Reset - ResetParam (connectionless)"),
            // Send ResetParam (erase code 0x05)
            inject("BC #EDI #BDUT 63 03 81 05 00"),
            expect("BC #BDUT #EDI 64 03 A1 00 ?? ??", 2000),
            comment("Acceptance: Parameters shall be reset to default"),
        ]),
        // ====================================================================
        // M-2.9.7a Send Master Reset - ResetParam (connection oriented)
        // ====================================================================
        TestCase::new("M-2.9.7a Send Master Reset - ResetParam (connection oriented)").with_steps(vec![
            comment("Testcase 2.9.7a Send Master Reset - ResetParam (connection oriented)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Send ResetParam (erase code 0x05)
            inject("B0 #EDI #BDUT 63 43 81 05 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("B0 #BDUT #EDI 64 43 A1 00 ?? ??", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("Acceptance: Parameters shall be reset to default"),
        ]),
        // ====================================================================
        // M-2.9.8 Send Master Reset - ResetLinks (connectionless)
        // ====================================================================
        TestCase::new("M-2.9.8 Send Master Reset - ResetLinks (connectionless)").with_steps(vec![
            comment("Testcase 2.9.8 Send Master Reset - ResetLinks (connectionless)"),
            // Send ResetLinks (erase code 0x06)
            inject("BC #EDI #BDUT 63 03 81 06 00"),
            expect("BC #BDUT #EDI 64 03 A1 00 ?? ??", 2000),
            comment("Acceptance: Link information for group objects shall be reset"),
        ]),
        // ====================================================================
        // M-2.9.8a Send Master Reset - ResetLinks (connection oriented)
        // ====================================================================
        TestCase::new("M-2.9.8a Send Master Reset - ResetLinks (connection oriented)").with_steps(vec![
            comment("Testcase 2.9.8a Send Master Reset - ResetLinks (connection oriented)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Send ResetLinks (erase code 0x06)
            inject("B0 #EDI #BDUT 63 43 81 06 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("B0 #BDUT #EDI 64 43 A1 00 ?? ??", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("Acceptance: Link information for group objects shall be reset"),
        ]),
        // ====================================================================
        // M-2.9.9 Factory Reset without IA (connectionless)
        // ====================================================================
        TestCase::new("M-2.9.9 Factory Reset without IA (connectionless)").with_steps(vec![
            comment("Testcase 2.9.9 Factory Reset without IA (connectionless)"),
            // Send Factory Reset without IA (erase code 0x07)
            inject("BC #EDI #BDUT 63 03 81 07 00"),
            expect("BC #BDUT #EDI 64 03 A1 00 ?? ??", 2000),
            comment("Acceptance: All resources reset as in 2.9.4, except IA remains unchanged"),
        ]),
        // ====================================================================
        // M-2.9.9a Factory Reset without IA (connection oriented)
        // ====================================================================
        TestCase::new("M-2.9.9a Factory Reset without IA (connection oriented)").with_steps(vec![
            comment("Testcase 2.9.9a Factory Reset without IA (connection oriented)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Send Factory Reset without IA (erase code 0x07)
            inject("B0 #EDI #BDUT 63 43 81 07 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("B0 #BDUT #EDI 64 43 A1 00 ?? ??", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("Acceptance: All resources reset as in 2.9.4, except IA remains unchanged"),
        ]),
        // ====================================================================
        // M-2.9.10 Unsupported EraseCode (connectionless)
        // ====================================================================
        TestCase::new("M-2.9.10 Unsupported EraseCode (connectionless)").with_steps(vec![
            comment("Testcase 2.9.10 Unsupported EraseCode (connectionless)"),
            // Send unsupported erase code 0x22
            inject("BC #EDI #BDUT 63 03 81 22 00"),
            comment("Expect error code 0x02 (unsupported erase code)"),
            expect("BC #BDUT #EDI 64 03 A1 02 00 00", 2000),
        ]),
        // ====================================================================
        // M-2.9.10a Unsupported EraseCode (connection oriented)
        // ====================================================================
        TestCase::new("M-2.9.10a Unsupported EraseCode (connection oriented)").with_steps(vec![
            comment("Testcase 2.9.10a Unsupported EraseCode (connection oriented)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Send unsupported erase code 0x22
            inject("B0 #EDI #BDUT 63 43 81 22 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Expect error code 0x02 (unsupported erase code)"),
            expect("B0 #BDUT #EDI 64 43 A1 02 00 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.9.11 Access denied (connection-oriented)
        // ====================================================================
        TestCase::new("M-2.9.11 Access denied (connection-oriented)").with_steps(vec![
            comment("Testcase 2.9.11 Access denied (connection oriented)"),
            comment("Authorize at level where BDUT would not allow to carry out a master reset. The below example shows that this would be e.g. level 1 with the key 12345678h."),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request with key
            inject("BC #EDI #BDUT 66 43 D1 00 #AUTHORIZATION_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 #ACCESS_LEVEL", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Carry out Master reset"),
            inject("B0 #EDI #BDUT 63 47 81 02 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("B0 #BDUT #EDI 64 47 A1 01 00 00", 200),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("BDUT shall respond with error code access denied."),
        ]),
        // ====================================================================
        // M-2.9.12 Incorrect Channel number (connectionless)
        // ====================================================================
        TestCase::new("M-2.9.12 Incorrect Channel number (connectionless)").with_steps(vec![
            comment("Testcase 2.9.12 Incorrect Channel number (connectionless)"),
            comment("NOTE: Make sure the BDUT is not at the proper authorization level to carry out the master reset."),
            // Send Master Reset with invalid channel 0xFF
            inject("BC #EDI #BDUT 63 03 81 02 FF"),
            expect("BC #BDUT #EDI 64 03 A1 03 00 00", 2000),
            comment("BDUT shall respond with error code Invalid Channel Number."),
        ]),
        // ====================================================================
        // M-2.9.12a Incorrect Channel number (connection oriented)
        // ====================================================================
        TestCase::new("M-2.9.12a Incorrect Channel number (connection oriented)").with_steps(vec![
            comment("Testcase 2.9.12a Incorrect Channel number (connection oriented)"),
            comment("NOTE: Make sure the BDUT is not at the proper authorization level to carry out the master reset."),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Send Master Reset with invalid channel 0xFF
            inject("B0 #EDI #BDUT 63 43 81 02 FF"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("B0 #BDUT #EDI 64 43 A1 03 00 00", 200),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("BDUT shall respond with error code Invalid Channel Number."),
        ]),
        // Note: M-2.9 Restart preparation is typically run before the suite
        // to set up the BDUT with programming mode and correct IA
    ];

    TestSuite::new("M-2.9 Restart", vars).with_cases(cases)
}

// ============================================================================
// M-2.10 MemoryBit_Write Tests
// ============================================================================

/// Create variables for MemoryBit tests
///
/// Memory model assumed:
/// - 0x0200 to 0x02FF: accessible memory area, entire memory area filled with 0x0F
/// - 0x0300 to 0x03FF: protected memory area
fn create_memorybit_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = create_test_variables();
    // Memory positions (same as Memory_Read/Write tests)
    vars.insert("MEMPOS".to_string(), TestVariable::Bytes(vec![0x02, 0x00])); // 0x0200
    vars.insert("MEMPOS_LASTACCESS".to_string(), TestVariable::Bytes(vec![0x02, 0xFF])); // 0x02FF
    vars.insert("MEMPOS_PROTECTED".to_string(), TestVariable::Bytes(vec![0x10, 0x00])); // 0x1000 - unmapped/protected
                                                                                        // Memory content: 16 bytes of 0x0F (default value)
    let mem: Vec<u8> = vec![0x0F; 16];
    vars.insert("MEM".to_string(), TestVariable::Bytes(mem));
    vars
}

/// Create the MemoryBit_Write test suite (M-2.10.x)
///
/// Tests the A_MemoryBit_Write service for bit-level memory manipulation.
///
/// APCI format:
/// - A_MemoryBit_Write: 0x1D0 | count (4 bits) | address (2 bytes) | AND-mask | XOR-mask
/// - Response uses A_Memory_Response: 0x140 | count (6 bits) | address (2 bytes) | data
///
/// The service allows atomic bit manipulation:
/// - new_value = (old_value AND and_mask) XOR xor_mask
///
/// For each byte position:
/// - AND mask of 0x33 and XOR mask of 0x55 with original value 0x0F:
///   (0x0F AND 0x33) XOR 0x55 = 0x03 XOR 0x55 = 0x56
///
/// Legal length for MemoryBit_Write is max 5 bytes (count 1-5).
pub fn create_memorybit_write_suite() -> TestSuite {
    use super::helpers::inject_delay;
    let vars = create_memorybit_test_variables();

    // Preparation: Reset memory to 0x0F (previous tests may have modified it)
    // Write 256 bytes of 0x0F to address 0x0200 using EFF (Extended Frame Format)
    // EFF format: 3C ECF SRC DST LEN TPCI APCI ADDR DATA...
    // ECF = 0x60 (AT=0 individual, HC=6, EFF=0)
    // LEN = APDU length (TPCI + APCI + ADDR + DATA bytes)
    // APCI = 0xBF = 0x80 | 0x3F (Memory_Write with count=63)
    let preparation = vec![
        comment("M-2.10 Preparation: Reset linear memory to 0x0F"),
        // Open connection
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        // Block 1: Write 63 bytes starting at 0x0200 (seq 0)
        // LEN = 1(TPCI) + 1(APCI) + 2(ADDR) + 63(DATA) = 67 = 0x43
        inject("3C 60 #EDI #BDUT 43 42 BF 02 00 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F"),
        expect("B0 #BDUT #EDI 60 C2", 1000),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        // Block 2: Write 63 bytes starting at 0x023F (seq 1)
        inject("3C 60 #EDI #BDUT 43 46 BF 02 3F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F"),
        expect("B0 #BDUT #EDI 60 C6", 1000),
        inject_delay("B0 #EDI #BDUT 60 C6", 200),
        // Block 3: Write 63 bytes starting at 0x027E (seq 2)
        inject("3C 60 #EDI #BDUT 43 4A BF 02 7E 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F"),
        expect("B0 #BDUT #EDI 60 CA", 1000),
        inject_delay("B0 #EDI #BDUT 60 CA", 200),
        // Block 4: Write 63 bytes starting at 0x02BD (seq 3)
        // Covers 0x02BD to 0x02FB
        inject("3C 60 #EDI #BDUT 43 4E BF 02 BD 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F"),
        expect("B0 #BDUT #EDI 60 CE", 1000),
        inject_delay("B0 #EDI #BDUT 60 CE", 200),
        // Block 5: Write 4 bytes starting at 0x02FC to cover 0x02FC-0x02FF (seq 4)
        // Using standard frame: BC with NPDU 0x67 (hop 6, len 7: TPCI+APCI+ADDR+DATA = 1+1+2+4 = 8-1=7)
        inject("BC #EDI #BDUT 67 52 84 02 FC 0F 0F 0F 0F"),
        expect("B0 #BDUT #EDI 60 D2", 1000),
        inject_delay("B0 #EDI #BDUT 60 D2", 200),
        // Close connection
        inject_delay("B0 #EDI #BDUT 60 81", 200),
    ];

    let cases = vec![
        // ====================================================================
        // M-2.10.1 Legal Length - accessible Memory - no Verify
        // ====================================================================
        TestCase::new("M-2.10.1 Legal Length - accessible Memory - no Verify").with_steps(vec![
            comment("Testcase 2.10.1 Legal Length - accessible Memory - no Verify (5 bytes from first accessible memory position)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_MemoryBit_Write: count=5, addr=MEMPOS, AND=33x5, XOR=55x5
            inject("BC #EDI #BDUT 6E 43 D0 05 #MEMPOS 33 33 33 33 33 55 55 55 55 55"),
            expect("B0 #BDUT #EDI 60 C2", 200),
            comment("Acceptance: After reading the concerned memory area, the BDUT sends a response showing that the memory has been manipulated."),
            // Read back to verify: A_Memory_Read 5 bytes at MEMPOS
            inject("BC #EDI #BDUT 63 46 05 #MEMPOS"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 68 42 45 #MEMPOS 56 56 56 56 56", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.10.2 Legal Length - partly protected Memory - no Verify
        // ====================================================================
        TestCase::new("M-2.10.2 Legal Length - partly protected Memory - no Verify").with_steps(vec![
            comment("Testcase 2.10.2 Legal Length - partly protected Memory - no Verify ((2 bytes from last accessible memory position)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_MemoryBit_Write: count=2, addr=MEMPOS_LASTACCESS, AND=33x2, XOR=55x2
            inject("BC #EDI #BDUT 68 43 D0 02 #MEMPOS_LASTACCESS 33 33 55 55"),
            expect("B0 #BDUT #EDI 60 C2", 200),
            comment("Acceptance: After reading the last byte of the accessible memory area, the BDUT sends a response showing that the memory has not been manipulated."),
            // Read back last accessible byte - should still be 0x0F
            inject("BC #EDI #BDUT 63 46 01 #MEMPOS_LASTACCESS"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 64 42 41 #MEMPOS_LASTACCESS 0F", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.10.3 Illegal Length - accessible Memory - no Verify
        // ====================================================================
        TestCase::new("M-2.10.3 Illegal Length - accessible Memory - no Verify").with_steps(vec![
            comment("Testcase 2.10.3 Illegal Length - accessible Memory - no Verify (6 bytes from first accessible memory position + 10h)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_MemoryBit_Write: count=6 (illegal), addr=MEMPOS+16
            inject("BC #EDI #BDUT 6F 43 D0 06 #MEMPOS+16 33 33 33 33 33 33 55 55 55 55 55"),
            expect("B0 #BDUT #EDI 60 C2", 200),
            comment("Acceptance: After reading the concerned memory area, the BDUT sends a response showing that the memory has not been manipulated."),
            // Read back - should still be 0x0F
            inject("BC #EDI #BDUT 63 46 06 #MEMPOS+16"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 69 42 46 #MEMPOS+16 0F 0F 0F 0F 0F 0F", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
    ];

    TestSuite::new("M-2.10 MemoryBit_Write", vars).with_preparation(preparation).with_cases(cases)
}

/// Create the MemoryBit_Write Verify test suite (M-2.10 tests 4-7)
///
/// Tests for A_MemoryBit_Write service with Verify flag enabled.
/// The Verify flag is enabled in suite preparation.
pub fn create_memorybit_write_verify_suite() -> TestSuite {
    use super::helpers::inject_delay;
    let vars = create_memorybit_test_variables();

    // ====================================================================
    // Suite Preparation - Reset memory and enable Verify flag
    // ====================================================================
    // Using EFF (Extended Frame Format) for 63-byte writes:
    // EFF format: 3C ECF SRC DST LEN TPCI APCI ADDR DATA...
    // ECF = 0x60 (AT=0 individual, HC=6, EFF=0)
    // LEN = 0x43 (67 = 1 TPCI + 1 APCI + 2 ADDR + 63 DATA)
    // TPCI = 0x42 (T_Data_Connected seq=0, APCI upper 2 bits = 10)
    // APCI = 0xBF = 0x80 | 0x3F (Memory_Write with count=63)
    let preparation = vec![
        comment("M-2.10 Verify Preparation: Reset linear memory to 0x0F"),
        // Block 1: Write 63 bytes starting at 0x0200
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        inject("3C 60 #EDI #BDUT 43 42 BF 02 00 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F"),
        expect("B0 #BDUT #EDI 60 C2", 1000),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        inject_delay("B0 #EDI #BDUT 60 81", 200),
        // Block 2: Write 63 bytes starting at 0x023F
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        inject("3C 60 #EDI #BDUT 43 42 BF 02 3F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F"),
        expect("B0 #BDUT #EDI 60 C2", 1000),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        inject_delay("B0 #EDI #BDUT 60 81", 200),
        // Block 3: Write 63 bytes starting at 0x027E
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        inject("3C 60 #EDI #BDUT 43 42 BF 02 7E 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F"),
        expect("B0 #BDUT #EDI 60 C2", 1000),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        inject_delay("B0 #EDI #BDUT 60 81", 200),
        // Block 4: Write 63 bytes starting at 0x02BD (covers 0x02BD to 0x02FB)
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        inject("3C 60 #EDI #BDUT 43 42 BF 02 BD 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F"),
        expect("B0 #BDUT #EDI 60 C2", 1000),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        // Block 5: Write 4 bytes starting at 0x02FC to cover 0x02FC-0x02FF
        inject("BC #EDI #BDUT 67 47 84 02 FC 0F 0F 0F 0F"),
        expect("B0 #BDUT #EDI 60 C6", 1000),
        inject_delay("B0 #EDI #BDUT 60 C6", 200),
        inject_delay("B0 #EDI #BDUT 60 81", 200),
        comment("M-2.10 Verify Preparation: Enable Verify flag in DEVICE_CONTROL"),
        // T_Connect
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        // Enable Verify mode via PropertyWrite to Device Object (0), PID 14 (DEVICE_CONTROL), value 0x04
        inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 04"),
        expect("B0 #BDUT #EDI 60 C2", 1000),
        expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 04", 1000),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        // T_Disconnect
        inject_delay("B0 #EDI #BDUT 60 81", 200),
    ];

    let cases = vec![
        // ====================================================================
        // M-2.10.4 Legal Length - accessible Memory – Verify
        // ====================================================================
        TestCase::new("M-2.10.4 Legal Length - accessible Memory - Verify").with_steps(vec![
            comment("Testcase 2.10.4 Legal Length - accessible Memory – Verify (5 bytes from first accessible memory position + 20h)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_MemoryBit_Write with verify: count=5, addr=MEMPOS+32
            inject("BC #EDI #BDUT 6E 43 D0 05 #MEMPOS+32 33 33 33 33 33 55 55 55 55 55"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance: The BDUT sends a response showing that the memory has been manipulated."),
            // Expect A_Memory_Response with the modified data
            expect("BC #BDUT #EDI 68 42 45 #MEMPOS+32 56 56 56 56 56", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.10.5 Legal Length - accessible Memory – Verify (protected)
        // ====================================================================
        TestCase::new("M-2.10.5 Legal Length - accessible Memory - Verify").with_steps(vec![
            comment("Testcase 2.10.5 Legal Length - accessible Memory – Verify (5 bytes from first protected memory position)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_MemoryBit_Write: count=5, addr=MEMPOS_PROTECTED
            inject("BC #EDI #BDUT 6E 43 D0 05 #MEMPOS_PROTECTED 33 33 33 33 33 55 55 55 55 55"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance: The BDUT sends a response with the count set to zero and no data."),
            expect("BC #BDUT #EDI 63 42 40 #MEMPOS_PROTECTED", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.10.6 Legal Length - partly protected Memory – Verify
        // ====================================================================
        TestCase::new("M-2.10.6 Legal Length - partly protected Memory - Verify").with_steps(vec![
            comment("Testcase 2.10.6 Legal Length - partly protected Memory – Verify (2 bytes from last accessible memory position)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_MemoryBit_Write: count=2, addr=MEMPOS_LASTACCESS
            inject("BC #EDI #BDUT 68 43 D0 02 #MEMPOS_LASTACCESS 33 33 55 55"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance: The BDUT sends a response with the count set to zero and no data."),
            expect("BC #BDUT #EDI 63 42 40 #MEMPOS_LASTACCESS", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.10.7 Illegal Length - accessible Memory – Verify
        // ====================================================================
        TestCase::new("M-2.10.7 Illegal Length - accessible Memory - Verify").with_steps(vec![
            comment("Testcase 2.10.7 Illegal Length - accessible Memory – Verify (6 bytes from first accessible memory position + 30h)"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_MemoryBit_Write: count=6 (illegal), addr=MEMPOS+48
            inject("BC #EDI #BDUT 6E 43 D0 06 #MEMPOS+48 33 33 33 33 33 55 55 55 55 55"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance: The BDUT sends a response with the count set to zero and no data."),
            expect("BC #BDUT #EDI 63 42 40 #MEMPOS+48", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
    ];

    // Teardown: Disable Verify flag after all tests complete
    let teardown = vec![
        comment("Disable Verify flag in DEVICE_CONTROL to restore normal operation"),
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        // Disable Verify mode via PropertyWrite to Device Object (0), PID 14 (DEVICE_CONTROL), value 0x00
        inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 00"),
        expect("B0 #BDUT #EDI 60 C2", 1000),
        expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 00", 1000),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        inject_delay("B0 #EDI #BDUT 60 81", 200),
    ];

    TestSuite::new("M-2.10 MemoryBit_Write Verify", vars)
        .with_preparation(preparation)
        .with_cases(cases)
        .with_teardown(teardown)
}

// ============================================================================
// Authorization Tests (M-2.11)
// ============================================================================

/// Create test variables for Authorization tests
///
/// The Authorization tests use a key table with specific access levels:
/// - Level 0: Key 00000000h (full access)
/// - Level 1: Key 12345678h - access to level 1 block (0x0400)
/// - Level 2: Key FFFFFFFFh (default) - access to level 2 block (0x0300)
/// - Level 3: No key (minimum access, "access for everyone")
///
/// Key 87654321h is NOT in the key table (used for illegal key tests)
///
/// Data in memory:
/// - Block for level 1 (0x0400): FFh
/// - Block for level 2 (0x0300): AAh
fn create_authorization_test_variables() -> std::collections::BTreeMap<String, TestVariable> {
    let mut vars = create_test_variables();

    // Authorization keys
    vars.insert("LEVEL_0_KEY".into(), TestVariable::Bytes(vec![0x00, 0x00, 0x00, 0x00]));
    vars.insert("LEVEL_1_KEY".into(), TestVariable::Bytes(vec![0x12, 0x34, 0x56, 0x78]));
    vars.insert("LEVEL_2_KEY".into(), TestVariable::Bytes(vec![0xFF, 0xFF, 0xFF, 0xFF]));

    // Memory block start addresses
    // MEM_START_BLOCK_LEVEL_1 = 1024 = 0x0400 (requires access level <= 1)
    vars.insert("MEM_START_BLOCK_LEVEL_1".into(), TestVariable::Bytes(vec![0x04, 0x00]));
    // MEM_START_BLOCK_LEVEL_2 = 768 = 0x0300 (requires access level <= 2)
    vars.insert("MEM_START_BLOCK_LEVEL_2".into(), TestVariable::Bytes(vec![0x03, 0x00]));

    vars
}

/// Create the Authorization test suite (M-2.11)
///
/// Tests the A_Authorize_Request and A_Authorize_Response services (APCI 0x3D1/0x3D2).
/// Also tests A_Key_Write service (APCI 0x3D3) for setting keys.
///
/// Authorization levels control access to protected memory regions.
pub fn create_authorization_suite() -> TestSuite {
    let vars = create_authorization_test_variables();

    // ====================================================================
    // Suite Preparation - sets up the key table and memory blocks (2.11 Preparation)
    // ====================================================================
    let preparation = vec![
        comment("2.11 Test preparation"),
        comment("Load memory area with default value (by means of A_Memory_Write-service)"),
        // T_Connect
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        // Write FFh to level 1 memory block
        inject("BC #EDI #BDUT 64 42 81 #MEM_START_BLOCK_LEVEL_1 FF"),
        expect("B0 #BDUT #EDI 60 C2", 500),
        // Write AAh to level 2 memory block
        inject("BC #EDI #BDUT 64 46 81 #MEM_START_BLOCK_LEVEL_2 AA"),
        expect("B0 #BDUT #EDI 60 C6", 500),
        // T_Disconnect
        inject_delay("B0 #EDI #BDUT 60 81", 500),
        comment("Setting the keys"),
        // T_Connect
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        // A_Authorize_Request with default key (to get level 0 access for key writes)
        inject("BC #EDI #BDUT 66 43 D1 00 FF FF FF FF"),
        expect("B0 #BDUT #EDI 60 C2", 0),
        expect("BC #BDUT #EDI 62 43 D2 00", 1000),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        // A_Key_Write: Set key for level 0
        inject("BC #EDI #BDUT 66 47 D3 00 #LEVEL_0_KEY"),
        expect("B0 #BDUT #EDI 60 C6", 0),
        expect("BC #BDUT #EDI 62 47 D4 00", 1000),
        inject_delay("B0 #EDI #BDUT 60 C6", 200),
        // A_Key_Write: Set key for level 1
        inject("BC #EDI #BDUT 66 4B D3 01 #LEVEL_1_KEY"),
        expect("B0 #BDUT #EDI 60 CA", 0),
        expect("BC #BDUT #EDI 62 4B D4 01", 1000),
        comment("Alternatively for devices always returning access level 0"),
        inject_delay("B0 #EDI #BDUT 60 CA", 200),
        // A_Key_Write: Set key for level 2
        inject("BC #EDI #BDUT 66 4F D3 02 #LEVEL_2_KEY"),
        expect("B0 #BDUT #EDI 60 CE", 0),
        expect("BC #BDUT #EDI 62 4F D4 02", 1000),
        comment("Alternatively for devices always returning access level 0"),
        inject_delay("B0 #EDI #BDUT 60 CE", 200),
        // T_Disconnect
        inject_delay("B0 #EDI #BDUT 60 81", 200),
    ];

    let cases = vec![
        // ====================================================================
        // M-2.11.1 Authorization with Legal Key
        // ====================================================================
        TestCase::new("M-2.11.1 Authorization with Legal Key").with_steps(vec![
            comment("Testcase 2.11.1 Authorization with Legal Key"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request with level 1 key
            inject("BC #EDI #BDUT 66 43 D1 00 #LEVEL_1_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance A: Authorize Response for level 1 is returned."),
            expect("BC #BDUT #EDI 62 43 D2 01", 400),
            comment("Alternatively for devices always returning access level 0"),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Acceptance B: Memory read for level 1 block succeeds."),
            // A_Memory_Read: 1 byte from level 1 block
            inject("BC #EDI #BDUT 63 46 01 #MEM_START_BLOCK_LEVEL_1"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            // A_Memory_Response with data FFh
            expect("BC #BDUT #EDI 64 46 41 #MEM_START_BLOCK_LEVEL_1 FF", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.11.2 Authorization with Illegal Key
        // ====================================================================
        TestCase::new("M-2.11.2 Authorization with Illegal Key").with_steps(vec![
            comment("Testcase 2.11.2 Authorization with Illegal Key"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request with illegal key (87654321h is not in key table)
            inject("BC #EDI #BDUT 66 43 D1 00 87 65 43 21"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance A: no authorization is returned (e.g. 3)."),
            // Level 3 = no authorization (or any level > 2 that isn't configured)
            expect("BC #BDUT #EDI 62 43 D2 03", 400),
            comment("Alternatively for devices always returning access level 0"),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Acceptance B: Memory read for level 1 block fails."),
            // A_Memory_Read: 1 byte from level 1 block
            inject("BC #EDI #BDUT 63 46 01 #MEM_START_BLOCK_LEVEL_1"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            // A_Memory_Response with count=0 and no data (access denied)
            expect("BC #BDUT #EDI 63 46 40 #MEM_START_BLOCK_LEVEL_1", 400),
            comment("Alternatively for devices always returning access level 0"),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.11.3 Reaction to Authorize Response
        // ====================================================================
        TestCase::new("M-2.11.3 Reaction to Authorize Response").with_steps(vec![
            comment("Testcase 2.11.3 Reaction to Authorize Response"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Send A_Authorize_Response (wrong direction - this is a response, not request)
            // BDUT should not react to responses, only to requests
            inject("BC #EDI #BDUT 62 43 D2 00"),
            expect("B0 #BDUT #EDI 60 C2", 200),
            comment("Acceptance: No reaction of the BDUT."),
            // T_Disconnect (no other response expected)
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.11.4 Authorization with default Key
        // ====================================================================
        TestCase::new("M-2.11.4 Authorization with default Key").with_steps(vec![
            comment("Testcase 2.11.4 Authorization with default Key"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request with default key (FFFFFFFFh)
            inject("BC #EDI #BDUT 66 43 D1 00 #LEVEL_2_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            comment("Acceptance A: Authorization to level 2 is given (maximal level for default key)."),
            expect("BC #BDUT #EDI 62 43 D2 02", 400),
            comment("Alternatively for devices always returning access level 0"),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Acceptance B: Memory read for level 2 succeeds."),
            // A_Memory_Read: 1 byte from level 2 block
            inject("BC #EDI #BDUT 63 46 01 #MEM_START_BLOCK_LEVEL_2"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            // A_Memory_Response with data AAh
            expect("BC #BDUT #EDI 64 46 41 #MEM_START_BLOCK_LEVEL_2 AA", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.11.5 Access to the device without Authorization
        // ====================================================================
        TestCase::new("M-2.11.5 Access to the device without Authorization").with_steps(vec![
            comment("Testcase 2.11.5 Access to the device without Authorization"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Acceptance: Memory read for level 2 succeeds (maxium level with default key), same reaction as clause 2.11.4"),
            // A_Memory_Read: 1 byte from level 2 block (should succeed, default key gives level 2)
            inject("BC #EDI #BDUT 63 42 01 #MEM_START_BLOCK_LEVEL_2"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            // A_Memory_Response with data AAh
            expect("BC #BDUT #EDI 64 42 41 #MEM_START_BLOCK_LEVEL_2 AA", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            // New connection to test level 1 block access
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Acceptance: Memory read for level 1 does not succeed."),
            // A_Memory_Read: 1 byte from level 1 block (should fail, no authorization)
            inject("BC #EDI #BDUT 63 42 01 #MEM_START_BLOCK_LEVEL_1"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            // A_Memory_Response with count=0 (access denied)
            expect("BC #BDUT #EDI 63 42 40 #MEM_START_BLOCK_LEVEL_1", 400),
            comment("Alternatively for devices always returning access level 0"),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.11 Test clean up
        // ====================================================================
        TestCase::new("M-2.11 Test clean up").with_steps(vec![
            comment("2.11 Test clean up"),
            comment("Restoring the default key for the 0 level"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request with level 0 key (to get access for key writes)
            inject("BC #EDI #BDUT 66 43 D1 00 #LEVEL_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_Key_Write: Restore default key for level 0
            inject("BC #EDI #BDUT 66 47 D3 00 FF FF FF FF"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 62 47 D4 00", 1000),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
    ];

    TestSuite::new("M-2.11 Authorization", vars).with_preparation(preparation).with_cases(cases)
}

// ============================================================================
// Key Access Tests (M-2.12)
// ============================================================================

/// Create test variables for Key Access tests
///
/// Key table configuration:
/// - Level 0: Key 00000000h
/// - Level 1: Key 11111111h
///
/// No other keys are in the key table.
///
/// Note: Some devices always return access level 0 regardless of keys.
/// These tests have alternative expected responses for such devices.
fn create_key_access_test_variables() -> std::collections::BTreeMap<String, TestVariable> {
    let mut vars = create_test_variables();

    // Key access keys (different from authorization tests)
    vars.insert("LEVEL_0_KEY".into(), TestVariable::Bytes(vec![0x00, 0x00, 0x00, 0x00]));
    vars.insert("LEVEL_1_KEY".into(), TestVariable::Bytes(vec![0x11, 0x11, 0x11, 0x11]));

    vars
}

/// Create the Key Access test suite (M-2.12)
///
/// Tests the A_Key_Write service (APCI 0x3D3) for setting authorization keys.
/// Verifies proper access level restrictions when writing keys.
///
/// Key write rules:
/// - Cannot set key for a level higher than current authorization
/// - Cannot set key for illegal levels (> max configured level)
/// - Can set key for same level or lower levels
pub fn create_key_write_suite() -> TestSuite {
    let vars = create_key_access_test_variables();

    let preparation = vec![
        comment("2.12 Test preparation"),
        comment("Set authorization keys"),
        // T_Connect
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        // A_Authorize_Request with default key (to get level 0 access)
        inject("BC #EDI #BDUT 66 43 D1 00 FF FF FF FF"),
        expect("B0 #BDUT #EDI 60 C2", 0),
        expect("BC #BDUT #EDI 62 43 D2 00", 1000),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        // A_Key_Write: Set key for level 0
        inject("BC #EDI #BDUT 66 47 D3 00 #LEVEL_0_KEY"),
        expect("B0 #BDUT #EDI 60 C6", 0),
        expect("BC #BDUT #EDI 62 47 D4 00", 1000),
        inject_delay("B0 #EDI #BDUT 60 C6", 200),
        // A_Key_Write: Set key for level 1
        inject("BC #EDI #BDUT 66 4B D3 01 #LEVEL_1_KEY"),
        expect("B0 #BDUT #EDI 60 CA", 0),
        expect("BC #BDUT #EDI 62 4B D4 01", 1000),
        comment("Alternatively for devices always returning access level 0"),
        inject_delay("B0 #EDI #BDUT 60 CA", 200),
        // A_Key_Write: Set default key for level 2
        inject("BC #EDI #BDUT 66 4F D3 02 FF FF FF FF"),
        expect("B0 #BDUT #EDI 60 CE", 0),
        expect("BC #BDUT #EDI 62 4F D4 02", 1000),
        comment("Alternatively for devices always returning access level 0"),
        inject_delay("B0 #EDI #BDUT 60 CE", 200),
        // T_Disconnect
        inject_delay("B0 #EDI #BDUT 60 81", 200),
    ];

    let cases = vec![
        // ====================================================================
        // M-2.12.1 Authorize at Level 1 - set Key for Illegal Level
        // ====================================================================
        TestCase::new("M-2.12.1 Authorize at Level 1 - set Key for Illegal Level").with_steps(vec![
            comment("Testcase 2.12.1 Authorize at Level 1 - set Key for Illegal Level"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request with level 1 key
            inject("BC #EDI #BDUT 66 43 D1 00 #LEVEL_1_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 01", 400),
            comment("Alternatively for devices always returning access level 0"),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_Key_Write: Try to set key for level 22 (0x16 = 22, illegal level)
            inject("BC #EDI #BDUT 66 47 D3 16 12 34 56 78"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: Rejection value is returned."),
            // A_Key_Response with level=0xFF (rejection)
            expect("BC #BDUT #EDI 62 47 D4 FF", 400),
            comment("Alternatively for devices always returning access level 0"),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.12.2 Authorize at higher Level - set Key for lower Level
        // ====================================================================
        TestCase::new("M-2.12.2 Authorize at higher Level - set Key for lower Level").with_steps(vec![
            comment("Testcase 2.12.2 Authorize at higher Level - set Key for lower Level"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request with level 1 key
            inject("BC #EDI #BDUT 66 43 D1 00 #LEVEL_1_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 01", 400),
            comment("Alternatively for devices always returning access level 0"),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_Key_Write: Set key for level 2 (lower than current auth level 1)
            inject("BC #EDI #BDUT 66 47 D3 02 22 22 22 22"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance A: Access level 2 is set."),
            expect("BC #BDUT #EDI 62 47 D4 02", 400),
            comment("Alternatively for devices always returning access level 0"),
            comment("Acceptance B: Authorization with new key at new level succeeds."),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // A_Authorize_Request with new key
            inject("BC #EDI #BDUT 66 4B D1 00 22 22 22 22"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 62 4B D2 02", 400),
            comment("Alternatively for devices always returning access level 0"),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.12.3 Authorize and set Key at same Level
        // ====================================================================
        TestCase::new("M-2.12.3 Authorize and set Key at same Level").with_steps(vec![
            comment("Testcase 2.12.3 Authorize and set Key at same Level"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request with key 22222222h (set in previous test for level 2)
            inject("BC #EDI #BDUT 66 43 D1 00 22 22 22 22"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 02", 400),
            comment("Alternatively for devices always returning access level 0"),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_Key_Write: Set new key for level 2 (same as current auth level)
            inject("BC #EDI #BDUT 66 47 D3 02 12 12 12 12"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance A: access level 2 is reset."),
            expect("BC #BDUT #EDI 62 47 D4 02", 400),
            comment("Alternatively for devices always returning access level 0"),
            comment("Acceptance B: authorization with new key at same level succeeds."),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // A_Authorize_Request with new key
            inject("BC #EDI #BDUT 66 4B D1 00 12 12 12 12"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 62 4B D2 02", 400),
            comment("Alternatively for devices always returning access level 0"),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.12.4 Authorize at lower Level - set Key for higher Level
        // ====================================================================
        TestCase::new("M-2.12.4 Authorize at lower Level - set Key for higher Level").with_steps(vec![
            comment("Testcase 2.12.4 Authorize at lower Level - set Key for higher Level"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request with key 12121212h (set in previous test for level 2)
            inject("BC #EDI #BDUT 66 43 D1 00 12 12 12 12"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 02", 400),
            comment("Alternatively for devices always returning access level 0"),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_Key_Write: Try to set key for level 1 (higher than current auth level 2)
            inject("BC #EDI #BDUT 66 47 D3 01 33 33 33 33"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: Rejection value is returned."),
            // A_Key_Response with level=0xFF (rejection - cannot set key for higher level)
            expect("BC #BDUT #EDI 62 47 D4 FF", 400),
            comment("Alternatively for devices always returning access level 0"),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.12 Test clean up
        // ====================================================================
        TestCase::new("M-2.12 Test clean up").with_steps(vec![
            comment("2.12 Test clean up"),
            comment("Restoring the default key for the 0 level"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request with level 0 key
            inject("BC #EDI #BDUT 66 43 D1 00 #LEVEL_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_Key_Write: Restore default key for level 0
            inject("BC #EDI #BDUT 66 47 D3 00 FF FF FF FF"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 62 47 D4 00", 1000),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
    ];

    TestSuite::new("M-2.12 Key_Write", vars).with_preparation(preparation).with_cases(cases)
}

// ============================================================================
// Property Access Tests (M-2.13)
// ============================================================================

/// Create test variables for Property Access tests
///
/// Interface object configuration:
/// - Object 0 (index OBJ_0_ID): Access level 0, key AAAAAAAA
///   - Property 1 (OBJ_0_PROP_1): 7 elements, data 01 02 03 04 05 06 07
///   - Property 2 (OBJ_0_PROP_2): 4 elements, data 11 22 33 44
///   - Property 3 (OBJ_0_PROP_3): 11 elements, data 01-0B
///   - Property E0 (OBJ_0_PROP_E0): PDT_GENERIC_20, 20 elements
/// - Object 1 (index OBJ_0_ID+1): Access level 1, key BBBBBBBB
/// - Object 2 (index OBJ_0_ID+2): Access level 2, key CCCCCCCC, Property 01 write protected
fn create_property_access_test_variables() -> std::collections::BTreeMap<String, TestVariable> {
    let mut vars = create_test_variables();

    // Object indices
    vars.insert("OBJ_0_ID".into(), TestVariable::Bytes(vec![0x02]));
    vars.insert("OBJ_0_ILLEGAL_ID".into(), TestVariable::Bytes(vec![0x0E])); // 14 = illegal object index

    // Property IDs
    vars.insert("OBJ_0_PROP_1".into(), TestVariable::Bytes(vec![0x02]));
    vars.insert("OBJ_0_PROP_2".into(), TestVariable::Bytes(vec![0x03]));
    vars.insert("OBJ_0_PROP_3".into(), TestVariable::Bytes(vec![0x04]));
    vars.insert("OBJ_0_PROP_E0".into(), TestVariable::Bytes(vec![0xE0])); // 224 = PDT_GENERIC_20
    vars.insert("OBJ_0_ILLEGAL_PROP_ID".into(), TestVariable::Bytes(vec![0x05]));
    vars.insert("OBJ_0_ILLEGAL_PROP_INDEX".into(), TestVariable::Bytes(vec![0x04]));

    // Property data
    vars.insert("OBJ_0_PROP_1_DATA".into(), TestVariable::Bytes(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]));
    vars.insert("OBJ_0_PROP_2_DATA".into(), TestVariable::Bytes(vec![0x11, 0x22, 0x33, 0x44]));
    vars.insert(
        "OBJ_0_PROP_3_DATA".into(),
        TestVariable::Bytes(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B]),
    );

    // Access keys for different objects
    vars.insert("OBJ_0_ACCESS_KEY".into(), TestVariable::Bytes(vec![0xAA, 0xAA, 0xAA, 0xAA]));
    vars.insert("OBJ_1_ACCESS_KEY".into(), TestVariable::Bytes(vec![0xBB, 0xBB, 0xBB, 0xBB]));
    vars.insert("OBJ_2_ACCESS_KEY".into(), TestVariable::Bytes(vec![0xCC, 0xCC, 0xCC, 0xCC]));

    vars
}

/// Create the Property Value Read test suite (M-2.13)
///
/// Tests the A_PropertyValue_Read service (APCI 0x3D5) for reading interface object properties.
/// Also tests A_PropertyValue_Write service (APCI 0x3D7).
///
/// # NOTE on test suite 2.13
///
/// The following KNX interface objects are defined in an imaginary application program:
///
/// **Object 0** with ID x: Access level 0 with access key = AAAAAAAA
///
/// - Property 01 (Index 00): Object type
/// - Property 02 (Index 01): type 01 (Character - 1 Byte), WrAcc = 0, RdAcc = 0, 7 elements
/// - Property 03 (Index 02): type 01 (Character - 1 Byte), WrAcc = 0, RdAcc = 0, 4 elements
/// - Property 04 (Index 03): type 01 (Character - 1 Byte), WrAcc = 0, RdAcc = 0, 11 elements, MaxElements = 12
///
/// Property 02 data:
/// ```text
/// Start Addr  Data
/// 001         01
/// 002         02
/// 003         03
/// 004         04
/// 005         05
/// 006         06
/// 007         07
/// ```
///
/// Property 03 data:
/// ```text
/// Start Addr  Data
/// 001         11
/// 002         22
/// 003         33
/// 004         44
/// ```
///
/// Property 04 data:
/// ```text
/// Start Addr  Data
/// 1           01
/// 2           02
/// 3           03
/// 4           04
/// 5           05
/// 6           06
/// 7           07
/// 8           08
/// 9           09
/// A           0A
/// B           0B
/// ```
///
/// **Object 1** with index x+1: identical to Object 0 but set to access level 1 with access key BBBBBBBB
///
/// **Object 2** with index x+2: identical to Object 0 but set to access level 2 with access key CCCCCCCC
/// and Property 01: write protected (rest same)
///
/// **Object with index x+3** - Property ID E0h (Index 01): type 24h (PDT_GENERIC_20),
/// WrAcc = 0, RdAcc = 0, 20 elements, MaxElements = 20, content of the data irrelevant
///
/// Whereby x = first application interface object, in the examples x = 0
///
/// # NOTE on test suite 2.14
///
/// Test preparation: see A_PropertyValue_Read-Service Server Test.
///
/// # NOTE on test suite 2.15
///
/// Test Setup: For test preparation see A_PropertyValue_Read-Service Server test
///
/// Note: For an A_PropertyDescription_Read, the index is not evaluated when the Property
/// Identifier in the message has any other value than 0. The index in the corresponding
/// A_PropertyDescriptionResponse shall in this case be a copy of the index received with
/// A_PropertyDescription_Read-service or, alternatively, the actual index of the responding
/// property.
pub fn create_property_value_read_suite() -> TestSuite {
    let vars = create_property_access_test_variables();

    let cases = vec![
        // ====================================================================
        // M-2.13.1 Property Read with legal Property ID
        // ====================================================================
        TestCase::new("M-2.13.1 Property Read with legal Property ID").with_steps(vec![
            comment("Testcase 2.13.1 Property Read with legal Property ID"),
            comment("Test Preparation"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request with OBJ_0 access key
            inject("BC #EDI #BDUT 66 43 D1 00 #OBJ_0_ACCESS_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_PropertyValue_Write: Write all 7 elements to property 1
            inject("BC #EDI #BDUT 6C 47 D7 #OBJ_0_ID #OBJ_0_PROP_1 70 01 01 02 03 04 05 06 07"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with the correct data."),
            expect("BC #BDUT #EDI 6C 47 D6 #OBJ_0_ID #OBJ_0_PROP_1 70 01 01 02 03 04 05 06 07", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // A_PropertyValue_Write: Write 4 elements to property 2
            inject("BC #EDI #BDUT 69 47 D7 #OBJ_0_ID #OBJ_0_PROP_2 40 01 11 22 33 44"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with the correct data."),
            expect("BC #BDUT #EDI 69 47 D6 #OBJ_0_ID #OBJ_0_PROP_2 40 01 11 22 33 44", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // A_PropertyValue_Write: Write 10 elements to property 3
            inject("BC #EDI #BDUT 6F 47 D7 #OBJ_0_ID #OBJ_0_PROP_3 A0 01 01 02 03 04 05 06 07 08 09 0A"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with the correct data."),
            expect("BC #BDUT #EDI 6F 47 D6 #OBJ_0_ID #OBJ_0_PROP_3 A0 01 01 02 03 04 05 06 07 08 09 0A", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // A_PropertyValue_Write: Write element 11 to property 3
            inject("BC #EDI #BDUT 66 47 D7 #OBJ_0_ID #OBJ_0_PROP_3 10 0B 0B"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with the correct data."),
            expect("BC #BDUT #EDI 66 47 D6 #OBJ_0_ID #OBJ_0_PROP_3 10 0B 0B", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            // Now test A_PropertyValue_Read
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request
            inject("BC #EDI #BDUT 66 43 D1 00 #OBJ_0_ACCESS_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_PropertyValue_Read: Read 1 element from property 1, start index 1
            inject("BC #EDI #BDUT 65 47 D5 #OBJ_0_ID #OBJ_0_PROP_1 10 01"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with the correct data."),
            expect("BC #BDUT #EDI 66 47 D6 #OBJ_0_ID #OBJ_0_PROP_1 10 01 #OBJ_0_PROP_1_DATA.0", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // A_PropertyValue_Read: Read 1 element from property 2, start index 1
            inject("BC #EDI #BDUT 65 4B D5 #OBJ_0_ID #OBJ_0_PROP_2 10 01"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with the correct data."),
            expect("BC #BDUT #EDI 66 4B D6 #OBJ_0_ID #OBJ_0_PROP_2 10 01 #OBJ_0_PROP_2_DATA.0", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            // A_PropertyValue_Read: Read 2 elements from property 1, start index 4
            inject("BC #EDI #BDUT 65 4F D5 #OBJ_0_ID #OBJ_0_PROP_1 20 04"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with the correct data."),
            expect("BC #BDUT #EDI 67 4F D6 #OBJ_0_ID #OBJ_0_PROP_1 20 04 #OBJ_0_PROP_1_DATA.3 #OBJ_0_PROP_1_DATA.4", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.13.2 Property Read with illegal Object index
        // ====================================================================
        TestCase::new("M-2.13.2 Property Read with illegal Object index").with_steps(vec![
            comment("Testcase 2.13.2 Property Read with illegal Object index"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request
            inject("BC #EDI #BDUT 66 43 D1 00 #OBJ_0_ACCESS_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_PropertyValue_Read: Read from illegal object index
            inject("BC #EDI #BDUT 65 47 D5 #OBJ_0_ILLEGAL_ID 01 10 01"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends a A_PropertyValue_Response-PDU with count set to 0 and no data."),
            expect("BC #BDUT #EDI 65 47 D6 #OBJ_0_ILLEGAL_ID 01 00 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.13.3 Property Read with illegal Property ID
        // ====================================================================
        TestCase::new("M-2.13.3 Property Read with illegal Property ID").with_steps(vec![
            comment("Testcase 2.13.3 Property Read with illegal Property ID"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request
            inject("BC #EDI #BDUT 66 43 D1 00 #OBJ_0_ACCESS_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_PropertyValue_Read: Read from illegal property ID
            inject("BC #EDI #BDUT 65 47 D5 #OBJ_0_ID #OBJ_0_ILLEGAL_PROP_ID 10 01"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends a A_PropertyValue_Response-PDU with count set to 0 and no data."),
            expect("BC #BDUT #EDI 65 47 D6 #OBJ_0_ID #OBJ_0_ILLEGAL_PROP_ID 00 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.13.4 Property Read with illegal Start Index
        // ====================================================================
        TestCase::new("M-2.13.4 Property Read with illegal Start Index").with_steps(vec![
            comment("Testcase 2.13.4 Property Read with illegal Start Index"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request
            inject("BC #EDI #BDUT 66 43 D1 00 #OBJ_0_ACCESS_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_PropertyValue_Read: Read from start index 5 (property 2 has only 4 elements)
            inject("BC #EDI #BDUT 65 47 D5 #OBJ_0_ID #OBJ_0_PROP_2 10 05"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with count set to 0 and no data."),
            expect("BC #BDUT #EDI 65 47 D6 #OBJ_0_ID #OBJ_0_PROP_2 00 05", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.13.5 Property Read with illegal Access Level
        // ====================================================================
        TestCase::new("M-2.13.5 Property Read with illegal Access Level").with_steps(vec![
            comment("Testcase 2.13.5 Property Read with illegal Access Level"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request with OBJ_2 key (level 2)
            inject("BC #EDI #BDUT 66 43 D1 00 #OBJ_2_ACCESS_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_PropertyValue_Read: Read from OBJ_0 (requires level 0, we have level 2)
            inject("BC #EDI #BDUT 65 47 D5 #OBJ_0_ID #OBJ_0_PROP_1 10 01"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with count set to 0 and no data."),
            expect("BC #BDUT #EDI 65 47 D6 #OBJ_0_ID #OBJ_0_PROP_1 00 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.13.6 Property Read with illegal Count
        // ====================================================================
        TestCase::new("M-2.13.6 Property Read with illegal Count").with_steps(vec![
            comment("Testcase 2.13.6 Property Read with illegal Count"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request
            inject("BC #EDI #BDUT 66 43 D1 00 #OBJ_0_ACCESS_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_PropertyValue_Read: Read 5 elements from property 2 (only has 4 elements)
            inject("BC #EDI #BDUT 65 47 D5 #OBJ_0_ID #OBJ_0_PROP_2 50 01"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with count set to 0 and no data."),
            expect("BC #BDUT #EDI 65 47 D6 #OBJ_0_ID #OBJ_0_PROP_2 00 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.13.7 Property Read of two objects - access level legal/illegal
        // ====================================================================
        TestCase::new("M-2.13.7 Property Read of two objects - access level legal/illegal").with_steps(vec![
            comment("Testcase 2.13.7 Property Read of two objects, for which access level is legal - access level is illegal"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request with OBJ_1 key (level 1)
            inject("BC #EDI #BDUT 66 43 D1 00 #OBJ_1_ACCESS_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_PropertyValue_Read: Read from OBJ_1 (level 1, should succeed)
            inject("BC #EDI #BDUT 65 47 D5 #OBJ_0_ID+1 #OBJ_0_PROP_1 10 01"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with the correct data."),
            expect("BC #BDUT #EDI 66 47 D6 #OBJ_0_ID+1 #OBJ_0_PROP_1 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // A_PropertyValue_Read: Read from OBJ_0 (level 0, we only have level 1 - should fail)
            inject("BC #EDI #BDUT 65 4B D5 #OBJ_0_ID #OBJ_0_PROP_1 10 01"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with count 0 and no data."),
            expect("BC #BDUT #EDI 65 4B D6 #OBJ_0_ID #OBJ_0_PROP_1 00 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.13.8 Property Read on Start Index 0 - current length of arrays
        // ====================================================================
        TestCase::new("M-2.13.8 Property Read on Start Index 0 - current length of arrays").with_steps(vec![
            comment("Testcase 2.13.8 Property Read on Start Index 0 – current length of arrays"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request
            inject("BC #EDI #BDUT 66 43 D1 00 #OBJ_0_ACCESS_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_PropertyValue_Read: Read 1 element from start index 0 (returns current length)
            inject("BC #EDI #BDUT 65 47 D5 #OBJ_0_ID #OBJ_0_PROP_1 10 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with the correct data."),
            // Property 1 has 7 elements, so response is 00 07
            expect("BC #BDUT #EDI 67 47 D6 #OBJ_0_ID #OBJ_0_PROP_1 10 00 00 07", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
        // ====================================================================
        // M-2.13.9 Property Read with data not fitting in PDU
        // ====================================================================
        TestCase::new("M-2.13.9 Property Read with data not fitting in PDU").with_steps(vec![
            comment("Testcase 2.13.9 Property Read with data not fitting in PDU"),
            comment("NOTE: Property 3 has 11 elements"),
            // T_Connect
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_Authorize_Request
            inject("BC #EDI #BDUT 66 43 D1 00 #OBJ_0_ACCESS_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            // A_PropertyValue_Read: Read 11 elements (0xB0 = count 11) - too many for standard frame
            inject("BC #EDI #BDUT 65 47 D5 #OBJ_0_ID #OBJ_0_PROP_3 B0 01"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            comment("Acceptance: The BDUT sends an A_PropertyValue_Response-PDU with count set to 0 and no data."),
            expect("BC #BDUT #EDI 65 47 D6 #OBJ_0_ID #OBJ_0_PROP_3 00 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            // T_Disconnect
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
    ];

    TestSuite::new("M-2.13 PropertyValue_Read", vars).with_cases(cases)
}

// ============================================================================
// M-2.16 IndividualAddressSerialNumber_Write Tests
// ============================================================================

/// Create the IndividualAddressSerialNumber_Write test suite (M-2.16)
///
/// Tests the A_IndividualAddressSerialNumber_Write service (APCI 0x3DE) for setting
/// the individual address of a device via its serial number.
///
/// This is a broadcast service that allows addressing devices without knowing their
/// current individual address, using the unique serial number instead.
///
/// # APCI Codes
/// - A_IndividualAddressSerialNumber_Write: 0x3DE
pub fn create_individual_address_serial_number_write_suite() -> TestSuite {
    let vars = create_test_variables();

    let cases = vec![
        // ====================================================================
        // M-2.16.1 Set Individual Address via correct Serial Number
        // ====================================================================
        TestCase::new("M-2.16.1 Set Individual Address via correct Serial Number").with_steps(vec![
            comment("Testcase 2.16.1 Set Individual Address via correct Serial Number"),
            // A_IndividualAddressSerialNumber_Write to address 0x1002
            // ED = NPDU length 13, 03 DE = APCI for IndividualAddressSerialNumber_Write
            // Serial number (6 bytes) + new address (2 bytes) + reserved (4 bytes)
            inject_delay("BC #EDI 00 00 ED 03 DE #BDUT_SERIAL_NUMBER 10 02 00 00 00 00", 200),
            comment("Acceptance: The BDUT now has the individual address 1002h. This can be checked via an IndividualAddressRead in programming mode."),
            comment("For verification switch ON programming LED of BDUT."),
            set_programming_mode(true),
            // A_IndividualAddress_Read (broadcast)
            inject("BC #EDI 00 00 E1 01 00"),
            // Expect response from new address 0x1002
            expect("BC 10 02 00 00 E1 01 40", 200),
            comment("Now switch OFF programming LED of BDUT."),
            set_programming_mode(false),
        ]),
        // ====================================================================
        // M-2.16.2 Set Individual Address to other Value via same Serial Number
        // ====================================================================
        TestCase::new("M-2.16.2 Set Individual Address to other Value via same Serial Number").with_steps(vec![
            comment("Testcase 2.16.2 Set Individual Address to other Value via same Serial Number"),
            // A_IndividualAddressSerialNumber_Write to address 0x1001 (restore original)
            inject_delay("BC #EDI 00 00 ED 03 DE #BDUT_SERIAL_NUMBER 10 01 00 00 00 00", 200),
            comment("Acceptance: The BDUT now has the individual address 1001h. This can be checked via a IndividualAddressRead in programming mode."),
            comment("For verification switch ON programming LED of BDUT."),
            set_programming_mode(true),
            // A_IndividualAddress_Read (broadcast)
            inject("BC #EDI 00 00 E1 01 00"),
            // Expect response from address 0x1001
            expect("BC 10 01 00 00 E1 01 40", 200),
            comment("Now switch OFF programming LED of BDUT."),
            set_programming_mode(false),
        ]),
        // ====================================================================
        // M-2.16.3 Set Individual Address to other Value via incorrect Serial Number
        // ====================================================================
        TestCase::new("M-2.16.3 Set Individual Address to other Value via incorrect Serial Number").with_steps(vec![
            comment("Testcase 2.16.3 Set Individual Address to other Value via incorrect Serial Number"),
            // A_IndividualAddressSerialNumber_Write with wrong serial number (CA FE BE EF BA BE)
            inject_delay("BC #EDI 00 00 ED 03 DE CA FE BE EF BA BE 10 03 00 00 00 00", 200),
            comment("Acceptance: The BDUT still has the individual address 1001h. This can be checked via a IndividualAddressRead in programming mode."),
            comment("For verification switch ON programming LED of BDUT."),
            set_programming_mode(true),
            // A_IndividualAddress_Read (broadcast)
            inject("BC #EDI 00 00 E1 01 00"),
            // Expect response from original address 0x1001 (unchanged)
            expect("BC 10 01 00 00 E1 01 40", 200),
            comment("Restore BDUT IA."),
            // A_IndividualAddress_Write (restore original address)
            inject_delay("BC #EDI 00 00 E3 00 C0 #BDUT", 200),
            comment("Now switch OFF programming LED of BDUT."),
            set_programming_mode(false),
        ]),
    ];

    TestSuite::new("M-2.16 IndividualAddressSerialNumber_Write", vars).with_cases(cases)
}

// ============================================================================
// M-2.17 IndividualAddressSerialNumber_Read Tests
// ============================================================================

/// Create the IndividualAddressSerialNumber_Read test suite (M-2.17)
///
/// Tests the A_IndividualAddressSerialNumber_Read service (APCI 0x3DC) for reading
/// the individual address of a device via its serial number.
///
/// This is a broadcast service that allows querying a device's address using its
/// unique serial number.
///
/// # APCI Codes
/// - A_IndividualAddressSerialNumber_Read: 0x3DC
/// - A_IndividualAddressSerialNumber_Response: 0x3DD
pub fn create_individual_address_serial_number_read_suite() -> TestSuite {
    let vars = create_test_variables();

    let cases = vec![
        // ====================================================================
        // M-2.17.1 Read Individual Address via incorrect Serial Number
        // ====================================================================
        TestCase::new("M-2.17.1 Read Individual Address via incorrect Serial Number").with_steps(vec![
            comment("Testcase 2.17.1 Read Individual Address via incorrect Serial Number"),
            // A_IndividualAddressSerialNumber_Read with wrong serial number
            // E7 = NPDU length 7, 03 DC = APCI for IndividualAddressSerialNumber_Read
            inject_delay("BC #EDI 00 00 E7 03 DC CA FE BE EF BA BE", 200),
            comment("Acceptance: No response may be sent."),
            expect_none(500),
        ]),
        // ====================================================================
        // M-2.17.2 Send Response to BDUT via incorrect Serial Number
        // ====================================================================
        TestCase::new("M-2.17.2 Send Response to BDUT via incorrect Serial Number").with_steps(vec![
            comment("Testcase 2.17.2 Send Response to BDUT via incorrect Serial Number"),
            // A_IndividualAddressSerialNumber_Response with wrong serial number
            // EB = NPDU length 11, 03 DD = APCI for IndividualAddressSerialNumber_Response
            inject_delay("BC #EDI 00 00 EB 03 DD CA FE BE EF BA BE 00 00 00 00", 200),
            comment("Acceptance: No response may be sent."),
            expect_none(500),
        ]),
        // ====================================================================
        // M-2.17.3 Read Individual Address via correct Serial Number
        // ====================================================================
        TestCase::new("M-2.17.3 Read Individual Address via correct Serial Number").with_steps(vec![
            comment("Testcase 2.17.3 Read Individual Address via correct Serial Number"),
            // A_IndividualAddressSerialNumber_Read with correct serial number
            inject("BC #EDI 00 00 E7 03 DC #BDUT_SERIAL_NUMBER"),
            // Expect A_IndividualAddressSerialNumber_Response
            // EB = NPDU length 11, 03 DD = APCI for Response
            // Serial number (6 bytes) + reserved (4 bytes)
            expect("BC #BDUT 00 00 EB 03 DD #BDUT_SERIAL_NUMBER 00 00 00 00", 200),
            comment("Acceptance: The BDUT sends an A_IndividualAddressSerialNumber_Response-PDU."),
        ]),
        // ====================================================================
        // M-2.17.4 Send Response to BDUT via correct Serial Number
        // ====================================================================
        TestCase::new("M-2.17.4 Send Response to BDUT via correct Serial Number").with_steps(vec![
            comment("Testcase 2.17.4 Send Response to BDUT via correct Serial Number"),
            // A_IndividualAddressSerialNumber_Response sent TO the BDUT (should be ignored)
            inject_delay("BC #EDI 00 00 EB 03 DD #BDUT_SERIAL_NUMBER 00 00 00 00", 200),
            comment("Acceptance: no response may be sent."),
            expect_none(500),
        ]),
    ];

    TestSuite::new("M-2.17 IndividualAddressSerialNumber_Read", vars).with_cases(cases)
}

// ============================================================================
// M-2.18 NetworkParameter_Read Tests
// ============================================================================

/// Create test variables for network parameter tests
fn create_network_parameter_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = create_test_variables();

    // Network parameter fields
    // NP_OBJ_TYPE: Object type (2 bytes) - using Device Object (0x0000) as default
    vars.insert("NP_OBJ_TYPE".into(), TestVariable::Bytes(vec![0x00, 0x00]));
    // NP_PID: Property ID (1 byte) - using PID_SERIAL_NUMBER (0x0B) as example
    vars.insert("NP_PID".into(), TestVariable::Bytes(vec![0x0B]));
    // NP_TEST_INFO: Test info byte
    vars.insert("NP_TEST_INFO".into(), TestVariable::Bytes(vec![0x00]));
    // NP_VALUE: Network parameter value to write
    vars.insert("NP_VALUE".into(), TestVariable::Bytes(vec![0x00]));

    vars
}

/// Create the NetworkParameter_Read test suite (M-2.18)
///
/// Tests the A_NetworkParameter_Read service (APCI 0x3DA) for reading network parameters.
///
/// NOTE: Manufacturers must declare in the PICS/PIXIT for management server services,
/// which network parameters are supported with A_NetworkParameter_Read-Service.
///
/// # APCI Codes
/// - A_NetworkParameter_Read: 0x3DA
/// - A_NetworkParameter_Response: 0x3DB
pub fn create_network_parameter_read_suite() -> TestSuite {
    let vars = create_network_parameter_test_variables();

    let cases = vec![
        // ====================================================================
        // M-2.18 Check if BDUT sends answer with correct data (point-to-point connectionless)
        // ====================================================================
        TestCase::new("M-2.18 Check if BDUT sends answer with correct data (point-to-point connectionless)").with_steps(vec![
            comment("Testcase 2.18 Check if BDUT sends answer with correct data (point-to-point connectionless)"),
            comment("NOTE: Manufacturers must declare in the PICS/PIXIT for management server services, which network parameters are supported with A_NetworkParameter_Read-Service."),
            // A_NetworkParameter_Read (point-to-point connectionless)
            // 65 = NPDU (length 5), 03 DA = APCI for NetworkParameter_Read
            inject("BC #EDI #BDUT 65 03 DA #NP_OBJ_TYPE #NP_PID #NP_TEST_INFO"),
            // Expect A_NetworkParameter_Response
            // 66 = NPDU (length 6), 03 DB = APCI for NetworkParameter_Response
            expect("BC #BDUT #EDI 66 03 DB #NP_OBJ_TYPE #NP_PID #NP_TEST_INFO ??", 200),
            comment("Response when Object_Type is unknown: BC #BDUT #EDI 64 03 DB FF FF FF"),
            comment("Response when PID is unknown: BC #BDUT #EDI 64 03 DB #NP_OBJ_TYPE FF"),
            comment("Acceptance: BDUT sends A_NetworkParameter_Response with correct data and standard hop count."),
        ]),
        // ====================================================================
        // M-2.18a Check if BDUT sends answer with correct data (broadcast)
        // ====================================================================
        TestCase::new("M-2.18a Check if BDUT sends answer with correct data (broadcast)").with_steps(vec![
            comment("Testcase 2.18a Check if BDUT sends answer with correct data (broadcast)"),
            comment("NOTE: Manufacturers must declare in the PICS/PIXIT for management server services, which network parameters are supported with A_NetworkParameter_Read-Service."),
            comment("NOTE: Please take into account the random wait time. This wait time is specified per parameter_type (object_type/PID)."),
            // A_NetworkParameter_Read (broadcast)
            inject("BC #EDI 00 00 65 03 DA #NP_OBJ_TYPE #NP_PID #NP_TEST_INFO"),
            // Expect A_NetworkParameter_Response (with longer timeout for random wait time)
            expect("BC #BDUT #EDI 66 03 DB #NP_OBJ_TYPE #NP_PID #NP_TEST_INFO ??", 10000),
            comment("Acceptance: BDUT sends A_NetworkParameter_Response with correct data and standard hop count."),
            comment("Acceptance: In case the network parameter is not supported OR the check is negative, no response shall be sent (the service is ignored)."),
        ]),
    ];

    TestSuite::new("M-2.18 NetworkParameter_Read", vars).with_cases(cases)
}

// ============================================================================
// M-2.19 NetworkParameter_Write Tests
// ============================================================================

/// Create the NetworkParameter_Write test suite (M-2.19)
///
/// Tests the A_NetworkParameter_Write service (APCI 0x3E4) for writing network parameters.
///
/// NOTE: Manufacturers must declare in the PICS/PIXIT for management server services,
/// which network parameters are supported with A_NetworkParameter_Write-Service.
///
/// # APCI Codes
/// - A_NetworkParameter_Write: 0x3E4
pub fn create_network_parameter_write_suite() -> TestSuite {
    let vars = create_network_parameter_test_variables();

    let cases = vec![
        // ====================================================================
        // M-2.19.1 Check BDUT's acceptance of network parameter-write frames (point-to-point connectionless)
        // ====================================================================
        TestCase::new("M-2.19.1 Check BDUT's acceptance of network parameter-write frames (point-to-point connectionless)").with_steps(vec![
            comment("Testcase 2.19.1 Check BDUT's acceptance of network parameter-write frames (point-to-point connectionless)"),
            comment("NOTE: Manufacturers must declare in the PICS/PIXIT for management server services, which network parameters are supported with A_NetworkParameter_Write-Service."),
            // A_NetworkParameter_Write (point-to-point connectionless)
            // 65 = NPDU (length 5), 03 E4 = APCI for NetworkParameter_Write
            inject_delay("BC #EDI #BDUT 65 03 E4 #NP_OBJ_TYPE #NP_PID #NP_VALUE", 200),
            comment("Acceptance: BDUT's behaviour according to manufacturer's declaration about implemented features."),
            // NetworkParameter_Write has no response - just verify no error
            expect_none(500),
        ]),
        // ====================================================================
        // M-2.19.1a Check BDUT's acceptance of network parameter-write frames (broadcast)
        // ====================================================================
        TestCase::new("M-2.19.1a Check BDUT's acceptance of network parameter-write frames (broadcast)").with_steps(vec![
            comment("Testcase 2.19.1a Check BDUT's acceptance of network parameter-write frames (broadcast)"),
            comment("NOTE: Manufacturers must declare in the PICS/PIXIT for management server services, which network parameters are supported with A_NetworkParameter_Write-Service."),
            comment("NOTE: Please take into account the random wait time. This wait time is specified per parameter_type (object_type/PID)."),
            // Note: The XML shows 03 DA (Read) but this should be 03 E4 (Write) based on the test name
            // Using the correct APCI for Write
            inject_delay("BC #EDI 00 00 65 03 E4 #NP_OBJ_TYPE #NP_PID #NP_VALUE", 200),
            comment("Acceptance: BDUT's behaviour according to manufacturer's declaration about implemented features."),
            // NetworkParameter_Write has no response
            expect_none(500),
        ]),
    ];

    TestSuite::new("M-2.19 NetworkParameter_Write", vars).with_cases(cases)
}

// ============================================================================
// M-2.20 Illegal APCI Tests
// ============================================================================

/// Create the Illegal APCI test suite (M-2.20)
///
/// Tests that the device correctly ignores telegrams with invalid/reserved APCI codes
/// in point-to-point communication mode.
///
/// The test sends various reserved or undefined APCI values and verifies that
/// the device does not respond. This ensures robustness against malformed telegrams.
///
/// NOTE: In the course of the evolution of the KNX standard, some of the stated APCIs
/// may become valid APCIs. Hence the BDUT then logically may accept the frames,
/// if it supports this new APCI.
pub fn create_illegal_apci_suite() -> TestSuite {
    let vars = create_test_variables();

    // The test injects many faulty telegrams with illegal APCI codes
    // Only telegrams with Activate="yes" are included
    // Format: BC #EDI #BDUT 63 XX YY 00 00
    // where XX YY forms the APCI code being tested
    let cases = vec![
        TestCase::new("M-2.20 Illegal APCI in point to point communication mode").with_steps(vec![
            comment("Testcase 2.20 Illegal APCI in point to point communication mode"),
            // APCI 0x0000
            inject_delay("BC #EDI #BDUT 63 00 00 00 00", 200),
            // APCI 0x0100
            inject_delay("BC #EDI #BDUT 63 01 00 00 00", 200),
            // APCI 0x0001
            inject_delay("BC #EDI #BDUT 63 00 01 00 00", 200),
            // APCI 0x0101
            inject_delay("BC #EDI #BDUT 63 01 01 00 00", 200),
            // APCI 0x0002
            inject_delay("BC #EDI #BDUT 63 00 02 00 00", 200),
            // APCI 0x0102
            inject_delay("BC #EDI #BDUT 63 01 02 00 00", 200),
            // APCI 0x0004
            inject_delay("BC #EDI #BDUT 63 00 04 00 00", 200),
            // APCI 0x0104
            inject_delay("BC #EDI #BDUT 63 01 04 00 00", 200),
            // APCI 0x0008
            inject_delay("BC #EDI #BDUT 63 00 08 00 00", 200),
            // APCI 0x0108
            inject_delay("BC #EDI #BDUT 63 01 08 00 00", 200),
            // APCI 0x0010
            inject_delay("BC #EDI #BDUT 63 00 10 00 00", 200),
            // APCI 0x0110
            inject_delay("BC #EDI #BDUT 63 01 10 00 00", 200),
            // APCI 0x0020
            inject_delay("BC #EDI #BDUT 63 00 20 00 00", 200),
            // APCI 0x0120
            inject_delay("BC #EDI #BDUT 63 01 20 00 00", 200),
            // APCI 0x0040
            inject_delay("BC #EDI #BDUT 63 00 40 00 00", 200),
            // APCI 0x0140
            inject_delay("BC #EDI #BDUT 63 01 40 00 00", 200),
            // APCI 0x0080
            inject_delay("BC #EDI #BDUT 63 00 80 00 00", 200),
            // APCI 0x0180
            inject_delay("BC #EDI #BDUT 63 01 80 00 00", 200),
            // APCI 0x0011
            inject_delay("BC #EDI #BDUT 63 00 11 00 00", 200),
            // APCI 0x0111
            inject_delay("BC #EDI #BDUT 63 01 11 00 00", 200),
            // APCI 0x0022
            inject_delay("BC #EDI #BDUT 63 00 22 00 00", 200),
            // APCI 0x0122
            inject_delay("BC #EDI #BDUT 63 01 22 00 00", 200),
            // APCI 0x0044
            inject_delay("BC #EDI #BDUT 63 00 44 00 00", 200),
            // APCI 0x0144
            inject_delay("BC #EDI #BDUT 63 01 44 00 00", 200),
            // APCI 0x0088
            inject_delay("BC #EDI #BDUT 63 00 88 00 00", 200),
            // APCI 0x0188
            inject_delay("BC #EDI #BDUT 63 01 88 00 00", 200),
            comment("Acceptance: BDUT does not accept the frames (sends no reaction onto the bus)."),
            comment("NOTE: In the course of the evolution of the KNX standard, some of the stated APCIs may become valid APCIs. Hence the BDUT then logically may accept the frames, if it supports this new APCI."),
            // Final check that no responses were sent
            expect_none(500),
        ]),
    ];

    TestSuite::new("M-2.20 Illegal APCI", vars).with_cases(cases)
}

// ============================================================================
// M-2.31 UserMemory_Read
// ============================================================================

/// Creates variables for User Memory Access tests (M-2.31 and M-2.32)
///
/// # Memory Model
///
/// The test assumes the following memory layout:
///
/// | Address Range   | Description                                      |
/// |-----------------|--------------------------------------------------|
/// | 7FF0h - 7FFFh   | Accessible user memory (16 bytes)                |
/// | 8000h - 8FFFh   | Protected memory area (inaccessible)             |
///
/// # Variables
///
/// | Variable            | Value     | Description                           |
/// |---------------------|-----------|---------------------------------------|
/// | MEM_ACCESSIBLE_START| 7FF0h     | Start of accessible user memory       |
/// | MEM_ACCESSIBLE_END  | 7FFFh     | End of accessible user memory         |
/// | MEM_PROTECTED_START | 8000h     | Start of protected memory area        |
/// | MEM_VAL             | 11 22...  | 16 bytes of test data at 7FF0h        |
///
/// # A_UserMemory APCIs
///
/// | APCI Code | Service                   |
/// |-----------|---------------------------|
/// | 0x2C0     | A_UserMemory_Read         |
/// | 0x2C1     | A_UserMemory_Response     |
/// | 0x2C2     | A_UserMemory_Write        |
fn create_user_memory_test_variables() -> std::collections::BTreeMap<String, TestVariable> {
    let mut vars = create_test_variables();

    // Memory addresses (16-bit big-endian)
    vars.insert("MEM_ACCESSIBLE_START".to_string(), TestVariable::Bytes(vec![0x7F, 0xF0]));
    vars.insert("MEM_ACCESSIBLE_END".to_string(), TestVariable::Bytes(vec![0x7F, 0xFF]));
    vars.insert("MEM_PROTECTED_START".to_string(), TestVariable::Bytes(vec![0x80, 0x00]));

    // Test data at 7FF0h (16 bytes: 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00)
    vars.insert(
        "MEM_VAL".to_string(),
        TestVariable::Bytes(vec![
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        ]),
    );

    vars
}

/// Creates the M-2.31 UserMemory_Read test suite
///
/// Tests A_UserMemory_Read service for reading user memory areas.
/// Uses APCI 0x2C0 for request, 0x2C1 for response.
///
/// Frame format for A_UserMemory_Read:
/// - Request:  BC SA DA 6n APCI+addr_ext count addr_hi addr_lo
/// - Response: BC SA DA 6n APCI+addr_ext count addr_hi addr_lo [data...]
///
/// Where addr_ext is the address extension nibble in the APCI byte.
pub fn create_user_memory_read_suite() -> TestSuite {
    let vars = create_user_memory_test_variables();

    let cases = vec![
        // ====================================================================
        // M-2.31.0 Preparation
        // ====================================================================
        TestCase::new("M-2.31.0 Preparation").with_steps(vec![
            comment("Preparation"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 6E 42 C2 0A #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2 #MEM_VAL.3 #MEM_VAL.4 #MEM_VAL.5 #MEM_VAL.6 #MEM_VAL.7 #MEM_VAL.8 #MEM_VAL.9"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            // Note: TPCI 46 = seq 1 (after first T_ACK for seq 0)
            inject("BC #EDI #BDUT 69 46 C2 05 #MEM_ACCESSIBLE_START+10 #MEM_VAL.10 #MEM_VAL.11 #MEM_VAL.12 #MEM_VAL.13 #MEM_VAL.14"),
            expect("B0 #BDUT #EDI 60 C6", 1000),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.31.1 Accessible Memory - SFF
        // ====================================================================
        TestCase::new("M-2.31.1 Accessible Memory - SFF").with_steps(vec![
            comment("Testcase 2.31.1 Accessible Memory - SFF"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 64 42 C0 0A #MEM_ACCESSIBLE_START"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: The BDUT returns the correct data."),
            expect("BC #BDUT #EDI 6E 42 C1 0A #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2 #MEM_VAL.3 #MEM_VAL.4 #MEM_VAL.5 #MEM_VAL.6 #MEM_VAL.7 #MEM_VAL.8 #MEM_VAL.9", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.31.2 Protected Memory - SFF
        // ====================================================================
        TestCase::new("M-2.31.2 Protected Memory - SFF").with_steps(vec![
            comment("Testcase 2.31.2 Protected Memory - SFF"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 64 42 C0 0A #MEM_PROTECTED_START"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: The BDUT answers with an A_UserMemory_Response-PDU with no data and count set to zero."),
            expect("BC #BDUT #EDI 64 42 C1 00 #MEM_PROTECTED_START", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.31.3 Partly protected Memory - SFF
        // ====================================================================
        TestCase::new("M-2.31.3 Partly protected Memory - SFF").with_steps(vec![
            comment("Testcase 2.31.3 Partly protected Memory - SFF"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 64 42 C0 02 #MEM_ACCESSIBLE_END"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: The BDUT answers with an A_UserMemory_Response-PDU with no data and count set to zero."),
            expect("BC #BDUT #EDI 64 42 C1 00 #MEM_ACCESSIBLE_END", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // // ====================================================================
        // // M-2.31.4 Illegal Length - accessible Memory - for devices supporting SFF only
        // // ====================================================================
        // TestCase::new("M-2.31.4 Illegal Length - accessible Memory - for devices supporting SFF only").with_steps(vec![
        //     comment("Testcase 2.31.4 Illegal Length - accessible Memory - for devices supporting SFF only"),
        //     inject_delay("B0 #EDI #BDUT 60 80", 200),
        //     inject("BC #EDI #BDUT 64 42 C0 0D #MEM_ACCESSIBLE_START"),
        //     expect("B0 #BDUT #EDI 60 C2", 1000),
        //     comment("Acceptance: The BDUT answers with an A_UserMemory_Response-PDU with no data and count set to zero."),
        //     expect("BC #BDUT #EDI 64 42 C1 00 #MEM_ACCESSIBLE_START", 1000),
        //     inject_delay("B0 #EDI #BDUT 60 C2", 200),
        //     inject_delay("B0 #EDI #BDUT 60 81", 200),
        // ]),

        // ====================================================================
        // M-2.31.5 Accessible Memory - SFF - response fits in EFF - not exceeding MAX_APDU_LENGTH
        // ====================================================================
        TestCase::new("M-2.31.5 Accessible Memory - SFF - response fits in EFF - not exceeding MAX_APDU_LENGTH").with_steps(vec![
            comment("Testcase 2.31.5 Accessible Memory - SFF - response fits in EFF - not exceeding MAX_APDU_LENGTH"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 64 42 C0 0C #MEM_ACCESSIBLE_START"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: The BDUT returns the correct data in EFF."),
            // EFF response: 3C 60 SA DA len APCI...
            expect("3C 60 #BDUT #EDI 10 42 C1 0C #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2 #MEM_VAL.3 #MEM_VAL.4 #MEM_VAL.5 #MEM_VAL.6 #MEM_VAL.7 #MEM_VAL.8 #MEM_VAL.9 #MEM_VAL.10 #MEM_VAL.11", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // // ====================================================================
        // // M-2.31.6 Accessible Memory - SFF - response would fit in EFF - exceeding MAX_APDU_LENGTH
        // // ====================================================================
        // TestCase::new("M-2.31.6 Accessible Memory - SFF - response would fit in EFF - exceeding MAX_APDU_LENGTH").with_steps(vec![
        //     comment("Testcase 2.31.6 Accessible Memory - SFF - response would fit in EFF - exceeding MAX_APDU_LENGTH"),
        //     comment("This test case is CONDITIONAL and not applicable if the MAX_APDU_LENGTH is equal or greater than 195."),
        //     inject_delay("B0 #EDI #BDUT 60 80", 200),
        //     inject("BC #EDI #BDUT 64 42 C0 0F #MEM_ACCESSIBLE_START"),
        //     expect("B0 #BDUT #EDI 60 C2", 1000),
        //     comment("Acceptance: The BDUT sends an A_UserMemory_Response with the length set to 0 and no data."),
        //     // EFF response with count=0
        //     expect("3C 60 #BDUT #EDI 04 42 C1 00 #MEM_ACCESSIBLE_START", 1000),
        //     inject_delay("B0 #EDI #BDUT 60 C2", 200),
        //     inject_delay("B0 #EDI #BDUT 60 81", 200),
        // ]),

        // ====================================================================
        // M-2.31.7 Accessible Memory - EFF - response fits in SFF
        // ====================================================================
        TestCase::new("M-2.31.7 Accessible Memory - EFF - response fits in SFF").with_steps(vec![
            comment("Testcase 2.31.7 Accessible Memory - EFF - response fits in SFF"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // EFF request
            inject("3C 60 #EDI #BDUT 04 42 C0 0A #MEM_ACCESSIBLE_START"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: The BDUT returns the correct data in SFF."),
            expect("BC #BDUT #EDI 6E 42 C1 0A #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2 #MEM_VAL.3 #MEM_VAL.4 #MEM_VAL.5 #MEM_VAL.6 #MEM_VAL.7 #MEM_VAL.8 #MEM_VAL.9", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.31.8 Accessible Memory - EFF - response fits in EFF
        // ====================================================================
        TestCase::new("M-2.31.8 Accessible Memory - EFF - response fits in EFF").with_steps(vec![
            comment("Testcase 2.31.8 Accessible Memory - EFF - response fits in EFF"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // EFF request
            inject("3C 60 #EDI #BDUT 04 42 C0 0C #MEM_ACCESSIBLE_START"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: The BDUT returns the correct data in EFF."),
            expect("3C 60 #BDUT #EDI 10 42 C1 0C #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2 #MEM_VAL.3 #MEM_VAL.4 #MEM_VAL.5 #MEM_VAL.6 #MEM_VAL.7 #MEM_VAL.8 #MEM_VAL.9 #MEM_VAL.10 #MEM_VAL.11", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
    ];

    TestSuite::new("UserMemory_Read", vars).with_cases(cases)
}

// ============================================================================
// M-2.32 UserMemory_Write
// ============================================================================

/// Creates the M-2.32 UserMemory_Write test suite
///
/// Tests A_UserMemory_Write service for writing user memory areas.
/// Uses APCI 0x2C2 for write request.
///
/// Frame format for A_UserMemory_Write:
/// - Write: BC SA DA 6n APCI+addr_ext count addr_hi addr_lo [data...]
///
/// Verify mode is enabled via PropertyWrite to Device Object property 14
/// (PID_DEVICE_CONTROL), not via an APCI flag.
///
/// Test cases from EITT XML specification:
/// - 2.32.1-2.32.3: SFF format tests (accessible, partly protected, inconsistent length)
/// - 2.32.4-2.32.6: Verify mode tests (accessible, protected, partly protected)
/// - 2.32.7-2.32.11: EFF format tests without verify
/// - 2.32.12: SFF verify with inconsistent length
/// - 2.32.13-2.32.17: EFF format tests with verify
pub fn create_user_memory_write_suite() -> TestSuite {
    let vars = create_user_memory_test_variables();

    let cases = vec![
        // ====================================================================
        // M-2.32.1 Accessible Memory - no Verify (10 bytes from 7FF0)
        // ====================================================================
        // XML: Write MEM_VAL values, read back with seq 46 expecting same values
        TestCase::new("M-2.32.1 Accessible Memory - no Verify").with_steps(vec![
            comment("Testcase 2.32.1 Accessible Memory - no Verify (10 bytes from 7FF0)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_UserMemory_Write to accessible memory, 10 bytes - write MEM_VAL values
            inject("BC #EDI #BDUT 6E 42 C2 0A #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2 #MEM_VAL.3 #MEM_VAL.4 #MEM_VAL.5 #MEM_VAL.6 #MEM_VAL.7 #MEM_VAL.8 #MEM_VAL.9"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: After reading the written memory, the same data is returned by the BDUT as written."),
            // Read back with TPCI sequence 6 (46)
            inject("BC #EDI #BDUT 64 46 C0 0A #MEM_ACCESSIBLE_START"),
            expect("B0 #BDUT #EDI 60 C6", 1000),
            expect("BC #BDUT #EDI 6E 42 C1 0A #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2 #MEM_VAL.3 #MEM_VAL.4 #MEM_VAL.5 #MEM_VAL.6 #MEM_VAL.7 #MEM_VAL.8 #MEM_VAL.9", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.32.2 Partly protected Memory - no Verify (2 bytes from last accessible)
        // ====================================================================
        // XML: Write 12 34 to MEM_ACCESSIBLE_END, expect FF back (unmodified)
        TestCase::new("M-2.32.2 Partly protected Memory - no Verify").with_steps(vec![
            comment("Testcase 2.32.2 Partly protected Memory - no Verify (2 bytes from last accessible memory position)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Write spanning accessible and protected boundary (start at 7FFF, write 2 bytes)
            inject("BC #EDI #BDUT 66 42 C2 02 #MEM_ACCESSIBLE_END 12 34"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: After reading the affected accessible memory area, a response shall be generated showing that data has not been modified."),
            // Read back 1 byte at MEM_ACCESSIBLE_END with TPCI sequence 6 (46)
            inject("BC #EDI #BDUT 64 46 C0 01 #MEM_ACCESSIBLE_END"),
            expect("B0 #BDUT #EDI 60 C6", 1000),
            // Expect FF back - the original value was not modified
            expect("BC #BDUT #EDI 65 42 C1 01 #MEM_ACCESSIBLE_END FF", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.32.3 Inconsistent Length - accessible Memory - no Verify
        // ====================================================================
        // XML: Tests BOTH count>data AND count<data, expects IGNORED
        //
        // NOTE: The XML specification shows BOTH malformed writes using seqno=0, implying
        // that rejected frames don't increment the transport layer sequence counter. This
        // is WRONG. The transport layer has no knowledge of application layer validity -
        // it sees a valid T_Data frame, increments its counter, ACKs it, and delivers the
        // APDU to the upper layer. The application layer then rejects the malformed APDU.
        // This matches the behavior in Memory_Write test 2.7.3 which correctly uses
        // incrementing sequence numbers (0, 1, 2). We follow the sane interpretation here.
        TestCase::new("M-2.32.3 Inconsistent Length - accessible Memory - no Verify").with_steps(vec![
            comment("Testcase 2.32.3 Inconsistent Length - accessible Memory - no Verify"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Number is greater than data"),
            // count=3 but only 2 data bytes (AA BB) - seq 0
            inject("BC #EDI #BDUT 66 42 C2 03 #MEM_ACCESSIBLE_START AA BB"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Number is less than data"),
            // count=2 but 3 data bytes (01 02 03) - seq 1
            inject("BC #EDI #BDUT 67 46 C2 02 #MEM_ACCESSIBLE_START 01 02 03"),
            expect("B0 #BDUT #EDI 60 C6", 1000),
            comment("Acceptance: The frames shall be ignored. Reading memory from the device shows the data has not been changed."),
            // Read back 3 bytes with TPCI sequence 2 (4A)
            inject("BC #EDI #BDUT 64 4A C0 03 #MEM_ACCESSIBLE_START"),
            expect("B0 #BDUT #EDI 60 CA", 1000),
            // Expect original MEM_VAL values unchanged
            // Note: Response TPCI is 42 (seq 0) because DUT's send counter starts at 0
            expect("BC #BDUT #EDI 67 42 C1 03 #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.32.7 Accessible Memory - EFF - no Verify
        // ====================================================================
        // XML: EFF write 13 bytes (0D count), uses MEM_VAL values
        TestCase::new("M-2.32.7 Accessible Memory - EFF - no Verify").with_steps(vec![
            comment("Testcase 2.32.7 Accessible Memory - EFF - no Verify"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // EFF write: 13 bytes to accessible memory
            inject("3C 60 #EDI #BDUT 11 42 C2 0D #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2 #MEM_VAL.3 #MEM_VAL.4 #MEM_VAL.5 #MEM_VAL.6 #MEM_VAL.7 #MEM_VAL.8 #MEM_VAL.9 #MEM_VAL.10 #MEM_VAL.11 #MEM_VAL.12"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: After reading the written memory, the same data is returned by the BDUT as written."),
            // Read back with SFF and TPCI sequence 6 (46)
            inject("BC #EDI #BDUT 64 46 C0 0D #MEM_ACCESSIBLE_START"),
            expect("B0 #BDUT #EDI 60 C6", 1000),
            // Response in EFF
            expect("3C 60 #BDUT #EDI 11 42 C1 0D #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2 #MEM_VAL.3 #MEM_VAL.4 #MEM_VAL.5 #MEM_VAL.6 #MEM_VAL.7 #MEM_VAL.8 #MEM_VAL.9 #MEM_VAL.10 #MEM_VAL.11 #MEM_VAL.12", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.32.8 Accessible Memory - EFF but fits SFF - no Verify
        // ====================================================================
        // XML: EFF with 11 bytes (0B count), uses 01 02 03 04 05 06 07 08 09 0A 0B
        TestCase::new("M-2.32.8 Accessible Memory - EFF but fits SFF - no Verify").with_steps(vec![
            comment("Testcase 2.32.8 Accessible Memory - EFF but fits SFF - no Verify"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // EFF format with 11 bytes
            inject("3C 60 #EDI #BDUT 0F 42 C2 0B #MEM_ACCESSIBLE_START 01 02 03 04 05 06 07 08 09 0A 0B"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: After reading the written memory, the same data is returned by the BDUT as written."),
            // Read back with SFF and TPCI sequence 6 (46)
            inject("BC #EDI #BDUT 64 46 C0 0B #MEM_ACCESSIBLE_START"),
            expect("B0 #BDUT #EDI 60 C6", 1000),
            // Response in SFF (fits in 11+4=15 bytes)
            expect("BC #BDUT #EDI 6F 42 C1 0B #MEM_ACCESSIBLE_START 01 02 03 04 05 06 07 08 09 0A 0B", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.32.9 Accessible Memory - EFF - exceeds MAX_APDU_LENGTH - no Verify
        // ====================================================================
        // XML: CONDITIONAL - not applicable if MAX_APDU_LENGTH >= 19
        // Our device has MAX_APDU_LENGTH = 255, so this test is NOT applicable
        // TestCase::new("M-2.32.9 Accessible Memory - EFF - exceeds MAX_APDU_LENGTH - no Verify").with_steps(vec![
        //     comment("Testcase 2.32.9 Accessible Memory - EFF - exceeds MAX_APDU_LENGTH - no Verify"),
        //     comment("This test case is CONDITIONAL and not applicable if the MAX_APDU_LENGTH is equal or greater than 19."),
        //     inject_delay("B0 #EDI #BDUT 60 80", 200),
        //     // Write 15 bytes (0F count)
        //     inject("3C 60 #EDI #BDUT 13 42 C2 0F #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2 #MEM_VAL.3 #MEM_VAL.4 #MEM_VAL.5 #MEM_VAL.6 #MEM_VAL.7 #MEM_VAL.8 #MEM_VAL.9 #MEM_VAL.10 #MEM_VAL.11 #MEM_VAL.12 #MEM_VAL.13 #MEM_VAL.14"),
        //     expect("B0 #BDUT #EDI 60 C2", 1000),
        //     comment("Acceptance: The frame shall be ignored. Reading memory from the device shows the data has not been changed."),
        //     // Read back 11 bytes (0B) with explicit address 07 FF in SFF with TPCI seq 6 (46)
        //     inject("BC #EDI #BDUT 64 46 C0 0B 07 FF"),
        //     expect("B0 #BDUT #EDI 60 C6", 1000),
        //     // Response shows data from previous test (2.32.8)
        //     expect("BC #BDUT #EDI 6F 42 C1 0B #MEM_ACCESSIBLE_START 01 02 03 04 05 06 07 08 09 0A 0B", 1000),
        //     inject_delay("B0 #EDI #BDUT 60 C2", 200),
        //     inject_delay("B0 #EDI #BDUT 60 81", 200),
        // ]),

        // ====================================================================
        // M-2.32.10 Inconsistent Length - accessible Memory - EFF - no Verify
        // ====================================================================
        // XML: Tests BOTH count>data (EFF) AND count<data (SFF), expects IGNORED
        //
        // NOTE: The XML specification shows BOTH malformed writes using seqno=0, implying
        // that rejected frames don't increment the transport layer sequence counter. This
        // is WRONG. The transport layer has no knowledge of application layer validity -
        // it sees a valid T_Data frame, increments its counter, ACKs it, and delivers the
        // APDU to the upper layer. The application layer then rejects the malformed APDU.
        // This matches the behavior in Memory_Write test 2.7.3 which correctly uses
        // incrementing sequence numbers (0, 1, 2). We follow the sane interpretation here.
        TestCase::new("M-2.32.10 Inconsistent Length - accessible Memory - EFF - no Verify").with_steps(vec![
            comment("Testcase 2.32.10 Inconsistent Length - accessible Memory - EFF - no Verify"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Number is greater than data"),
            // EFF with count=3 but only 2 data bytes (11 22) - seq 0
            inject("3C 60 #EDI #BDUT 06 42 C2 03 #MEM_ACCESSIBLE_START 11 22"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Number is less than data"),
            // SFF with count=2 but 3 data bytes (AA BB CC) - seq 1
            inject("BC #EDI #BDUT 67 46 C2 02 #MEM_ACCESSIBLE_START AA BB CC"),
            expect("B0 #BDUT #EDI 60 C6", 1000),
            comment("Acceptance: The frames shall be ignored. Reading memory from the device shows the data has not been changed."),
            // Read back 11 bytes with TPCI seq 2 (4A)
            inject("BC #EDI #BDUT 64 4A C0 0B #MEM_ACCESSIBLE_START"),
            expect("B0 #BDUT #EDI 60 CA", 1000),
            // Expect data from test 2.32.8 unchanged
            // Note: Response TPCI is 42 (seq 0) because DUT's send counter starts at 0
            expect("BC #BDUT #EDI 6F 42 C1 0B #MEM_ACCESSIBLE_START 01 02 03 04 05 06 07 08 09 0A 0B", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.32.11 Illegal Length - accessible Memory - EFF - exceeds MAX_APDU_LENGTH - no Verify
        // ====================================================================
        // XML: CONDITIONAL - not applicable if MAX_APDU_LENGTH >= 19
        // Our device has MAX_APDU_LENGTH = 255, so this test is NOT applicable
        // TestCase::new("M-2.32.11 Illegal Length - accessible Memory - EFF - exceeds MAX_APDU_LENGTH - no Verify").with_steps(vec![
        //     comment("Testcase 2.32.11 Illegal Length - accessible Memory - EFF - exceeds MAX_APDU_LENGTH - no Verify"),
        //     comment("This test case is CONDITIONAL and not applicable if the MAX_APDU_LENGTH is equal or greater than 19."),
        //     inject_delay("B0 #EDI #BDUT 60 80", 200),
        //     // count=0F (15) but only 14 data bytes in frame (length 12 = 0x12)
        //     inject("3C 60 #EDI #BDUT 12 42 C2 0F #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2 #MEM_VAL.3 #MEM_VAL.4 #MEM_VAL.5 #MEM_VAL.6 #MEM_VAL.7 #MEM_VAL.8 #MEM_VAL.9 #MEM_VAL.10 #MEM_VAL.11 #MEM_VAL.12 #MEM_VAL.13"),
        //     expect("B0 #BDUT #EDI 60 C2", 1000),
        //     comment("Acceptance: The frame shall be ignored. Reading memory from the device shows the data has not been changed."),
        //     // Read back with weird frame format from XML (no APCI high byte?)
        //     inject("BC #EDI #BDUT 63 46 0B 07 FF"),
        //     expect("B0 #BDUT #EDI 60 C6", 1000),
        //     // Expect data from test 2.32.8 unchanged
        //     expect("BC #BDUT #EDI 6F 42 C1 0B #MEM_ACCESSIBLE_START 01 02 03 04 05 06 07 08 09 0A 0B", 1000),
        //     inject_delay("B0 #EDI #BDUT 60 C2", 200),
        //     inject_delay("B0 #EDI #BDUT 60 81", 200),
        // ]),

    ];

    TestSuite::new("M-2.32 UserMemory_Write", vars).with_cases(cases)
}

/// Creates the M-2.32 UserMemory_Write Verify test suite
///
/// Tests A_UserMemory_Write service with Verify mode enabled.
/// Verify mode is enabled in preparation and disabled in teardown.
///
/// Test cases from EITT XML specification (Verify):
/// - 2.32.4-2.32.6: Verify mode tests (accessible, protected, partly protected)
/// - 2.32.12-2.32.16: EFF/SFF format tests with verify
pub fn create_user_memory_write_verify_suite() -> TestSuite {
    let vars = create_user_memory_test_variables();

    // ====================================================================
    // Suite Preparation - Enable Verify flag
    // ====================================================================
    let preparation = vec![
        comment("Enable Verify flag in DEVICE_CONTROL (Object 0, PID 14)"),
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        // PropertyWrite to Device Object (0), property 14 (PID_DEVICE_CONTROL), start=16, count=1, value=04
        inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 04"),
        expect("B0 #BDUT #EDI 60 C2", 1000),
        expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 04", 1000),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        inject_delay("B0 #EDI #BDUT 60 81", 200),
    ];

    let cases = vec![
        // ====================================================================
        // M-2.32.4 Accessible Memory - Verify
        // ====================================================================
        TestCase::new("M-2.32.4 Accessible Memory - Verify").with_steps(vec![
            comment("Testcase 2.32.4 Accessible Memory – Verify"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_UserMemory_Write to accessible memory, 10 bytes
            inject("BC #EDI #BDUT 6E 42 C2 0A #MEM_ACCESSIBLE_START 22 33 44 55 66 77 88 99 AA BB"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: The BDUT replies with a Response containing the same data as written."),
            expect("BC #BDUT #EDI 6E 42 C1 0A #MEM_ACCESSIBLE_START 22 33 44 55 66 77 88 99 AA BB", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.32.5 Protected Memory - Verify
        // ====================================================================
        TestCase::new("M-2.32.5 Protected Memory - Verify").with_steps(vec![
            comment("Testcase 2.32.5 Protected Memory – Verify"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Write to protected memory
            inject("BC #EDI #BDUT 6E 42 C2 0A #MEM_PROTECTED_START 22 33 44 55 66 77 88 99 AA BB"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: The BDUT replies with an A_UserMemory_Response-PDU with count set to zero and no data."),
            expect("BC #BDUT #EDI 64 42 C1 00 #MEM_PROTECTED_START", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.32.6 Partly protected Memory - Verify
        // ====================================================================
        TestCase::new("M-2.32.6 Partly protected Memory - Verify").with_steps(vec![
            comment("Testcase 2.32.6 Partly protected Memory – Verify"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // Write spanning boundary with verify (7FFF, 2 bytes)
            inject("BC #EDI #BDUT 66 42 C2 02 #MEM_ACCESSIBLE_END 12 34"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: The BDUT replies with an A_UserMemory_Response-PDU with count set to zero and no data."),
            expect("BC #BDUT #EDI 64 42 C1 00 #MEM_ACCESSIBLE_END", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.32.12 Inconsistent Length - accessible Memory - Verify
        // ====================================================================
        // NOTE: The XML specification shows BOTH malformed writes using seqno=0, implying
        // that rejected frames don't increment the transport layer sequence counter. This
        // is WRONG. The transport layer has no knowledge of application layer validity -
        // it sees a valid T_Data frame, increments its counter, ACKs it, and delivers the
        // APDU to the upper layer. The application layer then rejects the malformed APDU.
        // This matches the behavior in Memory_Write test 2.7.7 which correctly uses
        // incrementing sequence numbers. We follow the sane interpretation here.
        TestCase::new("M-2.32.12 Inconsistent Length - accessible Memory - Verify").with_steps(vec![
            comment("Testcase 2.32.12 Inconsistent Length - accessible Memory - Verify"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Number is greater than data"),
            // count=3 but only 2 data bytes (11 22) - seq 0
            inject("BC #EDI #BDUT 66 42 C2 03 #MEM_ACCESSIBLE_START 11 22"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: The BDUT replies with an A_UserMemory_Response-PDU with count set to zero and no data."),
            expect("BC #BDUT #EDI 64 42 C1 00 #MEM_ACCESSIBLE_START", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Number is less than data"),
            // count=2 but 3 data bytes (01 02 03) - seq 1
            inject("BC #EDI #BDUT 67 46 C2 02 #MEM_ACCESSIBLE_START 01 02 03"),
            expect("B0 #BDUT #EDI 60 C6", 1000),
            comment("Acceptance: The BDUT replies with an A_UserMemory_Response-PDU with count set to zero and no data."),
            expect("BC #BDUT #EDI 64 46 C1 00 #MEM_ACCESSIBLE_START", 1000),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.32.13 Accessible Memory - EFF - Verify
        // ====================================================================
        TestCase::new("M-2.32.13 Accessible Memory - EFF - Verify").with_steps(vec![
            comment("Testcase 2.32.13 Accessible Memory - EFF - Verify"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // EFF write 15 bytes with verify
            inject("3C 60 #EDI #BDUT 13 42 C2 0F #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2 #MEM_VAL.3 #MEM_VAL.4 #MEM_VAL.5 #MEM_VAL.6 #MEM_VAL.7 #MEM_VAL.8 #MEM_VAL.9 #MEM_VAL.10 #MEM_VAL.11 #MEM_VAL.12 #MEM_VAL.13 #MEM_VAL.14"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: The BDUT replies with a Response in EFF containing the same data as written."),
            expect("3C 60 #BDUT #EDI 13 42 C1 0F #MEM_ACCESSIBLE_START #MEM_VAL.0 #MEM_VAL.1 #MEM_VAL.2 #MEM_VAL.3 #MEM_VAL.4 #MEM_VAL.5 #MEM_VAL.6 #MEM_VAL.7 #MEM_VAL.8 #MEM_VAL.9 #MEM_VAL.10 #MEM_VAL.11 #MEM_VAL.12 #MEM_VAL.13 #MEM_VAL.14", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.32.14 Accessible Memory - EFF - response fits in SFF - Verify
        // ====================================================================
        TestCase::new("M-2.32.14 Accessible Memory - EFF - response fits in SFF - Verify").with_steps(vec![
            comment("Testcase 2.32.14 Accessible Memory - EFF - response fits in SFF - Verify"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // EFF request with 3 bytes (response fits in SFF)
            inject("3C 60 #EDI #BDUT 07 42 C2 03 #MEM_ACCESSIBLE_START 01 02 03"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: The BDUT replies with a Response in SFF containing the same data as written."),
            expect("BC #BDUT #EDI 67 42 C1 03 #MEM_ACCESSIBLE_START 01 02 03", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),

        // ====================================================================
        // M-2.32.16 Inconsistent Length - accessible Memory - EFF - Verify
        // ====================================================================
        // NOTE: The XML specification shows BOTH malformed writes using seqno=0, implying
        // that rejected frames don't increment the transport layer sequence counter. This
        // is WRONG. The transport layer has no knowledge of application layer validity -
        // it sees a valid T_Data frame, increments its counter, ACKs it, and delivers the
        // APDU to the upper layer. The application layer then rejects the malformed APDU.
        // This matches the behavior in Memory_Write test 2.7.7 which correctly uses
        // incrementing sequence numbers. We follow the sane interpretation here.
        TestCase::new("M-2.32.16 Inconsistent Length - accessible Memory - EFF - Verify").with_steps(vec![
            comment("Testcase 2.32.16 Inconsistent Length - accessible Memory - EFF - Verify"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Number is greater than data"),
            // EFF with count=3 but only 2 data bytes (11 22) - seq 0
            inject("3C 60 #EDI #BDUT 06 42 C2 03 #MEM_ACCESSIBLE_START 11 22"),
            expect("B0 #BDUT #EDI 60 C2", 1000),
            expect("BC #BDUT #EDI 64 42 C1 00 #MEM_ACCESSIBLE_START", 1000),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Number is less than data"),
            // SFF with count=2 but 3 data bytes (AA BB CC) - seq 1
            inject("BC #EDI #BDUT 67 46 C2 02 #MEM_ACCESSIBLE_START AA BB CC"),
            expect("B0 #BDUT #EDI 60 C6", 1000),
            expect("BC #BDUT #EDI 64 46 C1 00 #MEM_ACCESSIBLE_START", 1000),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Acceptance: The BDUT sends an A_UserMemory_Response with the length set to 0 and no data."),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
        ]),
    ];

    // ====================================================================
    // Suite Teardown - Disable Verify flag
    // ====================================================================
    let teardown = vec![
        comment("Disable Verify flag in DEVICE_CONTROL (Object 0, PID 14)"),
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        // PropertyWrite to Device Object (0), property 14 (PID_DEVICE_CONTROL), start=16, count=1, value=00
        inject("BC #EDI #BDUT 66 43 D7 00 0E 10 01 00"),
        expect("B0 #BDUT #EDI 60 C2", 1000),
        expect("BC #BDUT #EDI 66 43 D6 00 0E 10 01 00", 1000),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        inject_delay("B0 #EDI #BDUT 60 81", 200),
    ];

    TestSuite::new("M-2.32 UserMemory_Write Verify", vars)
        .with_preparation(preparation)
        .with_cases(cases)
        .with_teardown(teardown)
}

// ============================================================================
// M-2.33 UserManufacturerInfo_Read
// ============================================================================

/// Creates variables for User Manufacturer Info Access tests (M-2.33)
///
/// # Variables
///
/// | Variable              | Value   | Description                              |
/// |-----------------------|---------|------------------------------------------|
/// | MANUFACTURER_DEVICE_ID| 00h     | Manufacturer identification of device    |
/// | MANUFACTURER_SPECIFIC | 00 00h  | Manufacturer specific octets (2 bytes)   |
///
/// # A_UserManufacturerInfo APCIs
///
/// | APCI Code | Service                        |
/// |-----------|--------------------------------|
/// | 0x2C5     | A_UserManufacturerInfo_Read    |
/// | 0x2C6     | A_UserManufacturerInfo_Response|
fn create_user_manufacturer_info_test_variables() -> std::collections::BTreeMap<String, TestVariable> {
    let mut vars = create_test_variables();

    // Manufacturer Device ID (1 byte)
    vars.insert("MANUFACTURER_DEVICE_ID".to_string(), TestVariable::Bytes(vec![0x00]));

    // Manufacturer Specific octets (2 bytes)
    vars.insert("MANUFACTURER_SPECIFIC".to_string(), TestVariable::Bytes(vec![0x00, 0x00]));

    vars
}

/// Creates the M-2.33 UserManufacturerInfo_Read test suite
///
/// Tests A_UserManufacturerInfo_Read service for reading manufacturer info.
/// Uses APCI 0x2C5 for request, 0x2C6 for response.
///
/// Frame format:
/// - Request:  BC SA DA 61 42 C5
/// - Response: BC SA DA 64 42 C6 device_id manufacturer_specific[2]
pub fn create_user_manufacturer_info_read_suite() -> TestSuite {
    let vars = create_user_manufacturer_info_test_variables();

    let cases = vec![
        // ====================================================================
        // M-2.33.1 Read User Manufacturer Information
        // ====================================================================
        TestCase::new("M-2.33.1 Read User Manufacturer Information").with_steps(vec![
            comment("Testcase 2.33.1 Read User Manufacturer Information"),
            // Open T_Connection
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            // A_UserManufacturerInfo_Read: APCI = 02C5
            // Frame: BC SA DA 61 42 C5 (numbered data, seq=0)
            inject("BC #EDI #BDUT 61 42 C5"),
            // Expect T_Ack first
            expect("B0 #BDUT #EDI 60 C2", 1000),
            comment("Acceptance: BDUT sends a response containing manufacturer's code and type number according manufacturer's declarations."),
            // Expect A_UserManufacturerInfo_Response
            // Response: BC DA SA 64 42 C6 device_id manufacturer_specific[2]
            expect("BC #BDUT #EDI 64 42 C6 #MANUFACTURER_DEVICE_ID #MANUFACTURER_SPECIFIC", 1000),
            // Send T_Ack for the response
            inject_delay("BC #EDI #BDUT 60 C2", 200),
            // Close T_Connection
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
    ];

    TestSuite::new("M-2.33 UserManufacturerInfo_Read", vars).with_cases(cases)
}

/// Create the full management test suite (combines all management sub-suites)
pub fn create_management_suite() -> TestSuite {
    // For now, return the IndividualAddress_Read suite
    // More suites will be added as we implement them
    create_individual_address_read_suite()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variables_created() {
        let vars = create_test_variables();
        assert!(vars.contains_key("EDI"));
        assert!(vars.contains_key("BDUT"));
        assert!(vars.contains_key("BDUT_SERIAL_NUMBER"));

        assert_eq!(vars["EDI"].as_bytes(), &[0xAF, 0xFE]);
        assert_eq!(vars["BDUT"].as_bytes(), &[0x10, 0x01]);
        assert_eq!(vars["BDUT_SERIAL_NUMBER"].as_bytes(), &[0x30, 0x30, 0x30, 0x30, 0x30, 0x30]);
    }

    #[test]
    fn test_individual_address_read_suite_created() {
        let suite = create_individual_address_read_suite();
        assert_eq!(suite.cases.len(), 4);
        assert_eq!(suite.cases[0].name, "M-2.3.1 Read Address with programming LED off");
        assert_eq!(suite.cases[1].name, "M-2.3.2 Send Response to BDUT with programming LED off");
        assert_eq!(suite.cases[2].name, "M-2.3.3 Read Address with programming LED on");
        assert_eq!(suite.cases[3].name, "M-2.3.4 Send Response to BDUT with programming LED on");
    }
}
