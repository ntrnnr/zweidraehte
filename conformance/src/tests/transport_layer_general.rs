//! Transport Layer Conformance Tests - General Tests
//!
//! Tests based on KNX 3.0.0, Volume 08_03_04 Transport Layer Tests v01.06.07 AS
//! Reference: AN179 v04, AN182 v03, AN181 rev3, AN210 v02
//!
//! Test Collection: TL-General Transport Layer Tests (Section 2)
//!
//! These tests verify correct handling of:
//! - Transport layer TPCI coding validation
//! - Multicast, broadcast, and point-to-point communication
//! - Malformed message handling
//!
//! NOTE: Some tests use two interfaces (USB A and USB B) with different addresses.
//! For single-interface testing, only IFACE0 tests can be run.

use std::collections::BTreeMap;

use crate::{TestCase, TestStep, TestSuite, TestVariable};

/// Create test variables for transport layer tests
///
/// Based on the EITT specification:
/// - IFACE_A_ADDR: Physical Address for USB A (10.15.254 = AF FE)
/// - IFACE_B_ADDR: Physical Address for USB B (10.15.1 = AF 01)
/// - BDUT_ADDR: Basic Device Under Test (1.0.1 = 10 01)
/// - SER_NUM: Serial number of BDUT
/// - GO_ADDR: Group Object Address (2D 05)
pub fn create_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    vars.insert(
        "IFACE_A_ADDR".to_string(),
        TestVariable::Bytes(vec![0xAF, 0xFE]),
    );
    vars.insert(
        "IFACE_B_ADDR".to_string(),
        TestVariable::Bytes(vec![0xAF, 0x01]),
    );
    vars.insert(
        "BDUT_ADDR".to_string(),
        TestVariable::Bytes(vec![0x10, 0x01]),
    );
    vars.insert(
        "SER_NUM".to_string(),
        TestVariable::Bytes(vec![0xFE, 0xED, 0xBA, 0xBE, 0xCA, 0xFE]),
    );
    vars.insert(
        "GO_ADDR".to_string(),
        TestVariable::Bytes(vec![0x2D, 0x05]),
    );
    vars
}

/// Helper to create an inject step from a template string
fn inject(template: &str) -> TestStep {
    TestStep::InjectTemplate {
        template: template.to_string(),
        delay_before_ms: 0,
    }
}

/// Helper to create an inject step with delay
fn inject_delay(template: &str, delay_ms: u32) -> TestStep {
    TestStep::InjectTemplate {
        template: template.to_string(),
        delay_before_ms: delay_ms,
    }
}

/// Helper to create an expect step from a template string
fn expect(template: &str, timeout_ms: u32) -> TestStep {
    TestStep::ExpectTemplate {
        template: template.to_string(),
        timeout_ms,
    }
}

/// Helper to create a comment step
fn comment(text: &str) -> TestStep {
    TestStep::Comment(text.to_string())
}

/// Create transport layer test suite from EITT specification
///
/// Test Collection: TL-General Transport Layer Tests
pub fn create_transport_layer_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // Test Suite 2: General Transport Layer Tests
        // ====================================================================
        
        // --------------------------------------------------------------------
        // Test 2.1: Transport Layer tests for multicast communication
        // --------------------------------------------------------------------
        TestCase {
            name: "2.1 Transport Layer tests for multicast communication",
            steps: vec![
                comment("Testcase 2.1 Transport Layer tests for multicast communication"),
                comment("Multicast-addressed frames with incorrect TPCI coding for multicast communication."),
                comment("Test purpose: Check whether the DUT does not change the value of a communication object with a Group Value write/response command with the Transport Control field set to the value \"40h\", which indicates the frame as \"T_Data_Connected-PDU\" with SeqNo == 0 in the Transport Control field."),
                comment("Test Precondition: Ensure that GA has been assigned to a 1 bit Group Object of the BDUT – Ensure that the update on response flag is set. Set the current Individual Address of the BDUT to be 1001."),
                comment("Assigning individual address to BDUT."),
                // IndividualAddressWrite to set programming mode
                inject_delay("BC #IFACE_A_ADDR 00 00 8D 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00", 200),
                comment("Send GroupValueWrite first to GO with GA to write value"),
                // GroupValueWrite with value 1 (81 = write value 1)
                inject_delay("BC #IFACE_A_ADDR #GO_ADDR E1 00 81", 200),
                comment("Group Value Write with TPCI of T_Data_Connected."),
                // Faulty: GroupValueWrite with TPCI=40 (T_Data_Connected) - should be ignored
                inject_delay("BC #IFACE_A_ADDR #GO_ADDR E1 40 80", 200),
                comment("Check if value was not written"),
                // GroupValueRead to verify value unchanged
                inject("BC #IFACE_A_ADDR #GO_ADDR E1 00 00"),
                // Expect GroupValueResponse with value 1 (41 = response value 1)
                expect("BC #BDUT_ADDR #GO_ADDR E1 00 41", 200),
                comment("Group Value Response with TPCI of T_Connect."),
                // Faulty: GroupValueResponse with TPCI=80 (T_Connect) - should be ignored
                inject_delay("BC #IFACE_A_ADDR #GO_ADDR E2 80 40 00", 200),
                comment("Check if value was not written"),
                // GroupValueRead to verify value unchanged
                inject("BC #IFACE_A_ADDR #GO_ADDR E1 00 00"),
                // Expect GroupValueResponse with value 1 (41 = response value 1)
                expect("BC #BDUT_ADDR #GO_ADDR E1 00 41", 200),
                comment("Test purpose: Check whether the DUT does not react to the reading of the value of a communication object with a Group Value Read command with an undefined Transport Control field."),
                comment("Group Value Read with undefined TPCI."),
                // Faulty: GroupValueRead with TPCI=C0 (undefined) - should be ignored
                inject_delay("BC #IFACE_A_ADDR #GO_ADDR E1 C0 00", 200),
                comment("BDUT does not react"),
                comment("Acceptance: BDUT does not accept the frames. Check BDUT's behaviour, e.g. by reading back the values respectively checking that the BDUT does not generate any responses to read telegrams."),
                comment("Test purpose: Check whether the DUT does not change the value of a communication object with a Group Value write command with TPCI coding 00xxxxb, where x is different from 0."),
                comment("Group Value Write with Sequence number 4."),
                // Faulty: GroupValueWrite with TPCI=10 (seq num 4) - should be ignored
                inject_delay("BC #IFACE_A_ADDR #GO_ADDR E1 10 80", 200),
                comment("Acceptance: Check if value was not written"),
                // GroupValueRead to verify value unchanged
                inject("BC #IFACE_A_ADDR #GO_ADDR E1 00 00"),
                // Expect GroupValueResponse with value 1
                expect("BC #BDUT_ADDR #GO_ADDR E1 00 41", 200),
                comment("Acceptance: BDUT does not accept the frames. Check BDUT's behaviour, e.g. by reading back the values respectively checking that the BDUT does not generate any responses to read telegrams."),
            ],
        },
        
        // --------------------------------------------------------------------
        // Test 2.2: Transport Layer test for broadcast communication
        // --------------------------------------------------------------------
        TestCase {
            name: "2.2 Transport Layer test for broadcast communication",
            steps: vec![
                comment("Testcase 2.2 Transport Layer test for broadcast communication"),
                comment("Broadcast-addressed frames with incorrect TPCI coding for broadcast communication."),
                comment("Test purpose: Check whether the DUT does not change the value of its individual address with an Individual Address Write command with the Transport Control field set to the value \"40h\", which indicates the frame as \"T_Data_Connected-PDU\" with SeqNo == 0 in the Transport Control field."),
                comment("Test Precondition: Activate Programming Mode and (indirectly) check IA. Other settings same as clause 2.1"),
                // Activate programming mode via PropertyWrite
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 66 03 D7 00 36 10 01 01"),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 66 03 D6 00 36 10 01 01", 200),
                comment("IndAddrWrite(Addr=1234) with TPCI of T_Data_Connected."),
                // Faulty: IndividualAddressWrite with TPCI=40 (T_Data_Connected) - should be ignored
                inject_delay("BC #IFACE_A_ADDR 00 00 E3 40 C0 12 34", 200),
                comment("check if BDUT still has the IA 1001"),
                // IndividualAddressRead to verify address unchanged
                inject("BC #IFACE_A_ADDR 00 00 E1 01 00"),
                // Expect IndividualAddressResponse from BDUT
                expect("BC #BDUT_ADDR 00 00 E1 01 40", 200),
                comment("IndAddrWrite(Addr=1234) with TPCI of T_Connect."),
                // Faulty: IndividualAddressWrite with TPCI=80 (T_Connect) - should be ignored
                inject_delay("BC #IFACE_A_ADDR 00 00 E3 80 C0 12 34", 200),
                comment("check if BDUT still has the IA 1001"),
                // IndividualAddressRead to verify address unchanged
                inject("BC #IFACE_A_ADDR 00 00 E1 01 00"),
                expect("BC #BDUT_ADDR 00 00 E1 01 40", 200),
                comment("IndAddrRead() with undefined TPCI"),
                // Faulty: IndividualAddressRead with TPCI=C1 (undefined) - should be ignored
                inject_delay("BC #IFACE_A_ADDR 00 00 E1 C1 00", 200),
                comment("BDUT shows no reaction"),
                comment("Acceptance: BDUT does not accept the frames. Check BDUT's behaviour, e.g. by reading back the values respectively checking that the BDUT does not generate any responses to read telegrams."),
                comment("Broadcast-addressed frames with TPCI coding 00xxxxb, where x is different from 0."),
                comment("IndAddrWrite(Addr=1234) with Sequence number 4."),
                // Faulty: IndividualAddressWrite with TPCI=10 (seq num 4) - should be ignored
                inject_delay("BC #IFACE_A_ADDR 00 00 E3 10 C0 12 34", 200),
                comment("check if BDUT still has the IA 1001"),
                // IndividualAddressRead to verify address unchanged
                inject("BC #IFACE_A_ADDR 00 00 E1 01 00"),
                expect("BC #BDUT_ADDR 00 00 E1 01 40", 200),
                comment("Deactivate Programming Mode"),
                // Deactivate programming mode via PropertyWrite
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 66 03 D7 00 36 10 01 00"),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 66 03 D6 00 36 10 01 00", 200),
                comment("Acceptance: BDUT does not accept the frames. Check BDUT's behaviour, e.g. by reading back the values respectively checking that the BDUT does not generate any responses to read telegrams."),
            ],
        },
        
        // --------------------------------------------------------------------
        // Test 2.3: Transport Layer tests point-to-point connection oriented communication
        // --------------------------------------------------------------------
        TestCase {
            name: "2.3 Transport Layer tests point-to-point connection oriented communication",
            steps: vec![
                comment("Testcase 2.3 Transport Layer tests point-to-point connection oriented communication"),
                comment("Test purpose: Check whether the DUT does not react to a Mask Version Read with the Transport Control field set to the value '00h' and AT type = 1 which indicates the frame as 'T_Data_Group-PDU'."),
                comment("Test Precondition: Other settings same as clause 2.1."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                // Faulty: MaskVersionRead with AT=1 (group) and TPCI=03 - should be ignored
                inject_delay("BC #IFACE_A_ADDR #BDUT_ADDR E1 03 00", 500),
                // T_Disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("BDUT does not react."),
                
                comment("Test purpose: Check whether the DUT either ignores during a connection a connectionless Mask Version Read (Transport Control field set to the value '00h' and AT type = 0 which indicates the frame as 'T_Data_Individual-PDU') or optionally sends a correct Mask Version response"),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                // Connectionless MaskVersionRead (AT=0, TPCI=03) - may be answered
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 03 00"),
                // Optional: BDUT may send MaskVersionResponse
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 03 40 ?? ??", 400),
                // T_Disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("BDUT does not react or optionally sends a connectionless mask version response."),
                
                comment("Test purpose: Check whether the DUT does not react to a Mask Version Read with the Transport Control field set to the value '10h' and AT type = 0 which indicates the frame as 'T_Connect-PDU'"),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                // Faulty: MaskVersionRead with TPCI=83 (T_Connect bit set) - should be ignored
                inject_delay("BC #IFACE_A_ADDR 10 01 61 83 00", 500),
                // T_Disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("BDUT does not react."),
                
                comment("Test purpose: Check whether the DUT does not react to a Mask Version Read with the Transport Control field set to the value '43h' and AT type = 0 which indicates an undefined TPCI coding"),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                // Faulty: MaskVersionRead with TPCI=04 (undefined) - should be ignored
                inject_delay("BC #IFACE_A_ADDR 10 01 61 04 00", 200),
                // T_Disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("BDUT does not react."),
                comment("Acceptance: BDUT does not accept the frames. Check that the BDUT does not return a T-Ack or a Mask Version response."),
                
                comment("Test purpose: Telegram sequence with connection oriented communication interrupted by broadcast or group telegrams."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                // DeviceDescriptorRead (seq 0)
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 400),
                comment("Value Write command to group address supported by the device."),
                // GroupValueWrite (interrupting telegram)
                inject_delay("BC #IFACE_A_ADDR #GO_ADDR E1 00 81", 200),
                // Broadcast IndividualAddressRead (interrupting telegram)
                inject_delay("BC #IFACE_A_ADDR 00 00 E1 01 00", 200),
                // T_Ack for the DeviceDescriptorResponse
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C2", 200),
                comment("Check whether TL connection is still active."),
                // Another DeviceDescriptorRead (seq 1)
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 47 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C6", 200),
                // Expect DeviceDescriptorResponse
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 47 40 ?? ??", 400),
                // T_Ack
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C6", 200),
                // T_Disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("Acceptance: BDUT does not interrupt the established transport connection (it however may write the relevant addressed group object) and shows that the TL connection remains open."),
            ],
        },
        
        // --------------------------------------------------------------------
        // Test 2.4: Transport Layer tests point-to-point connectionless communication
        // --------------------------------------------------------------------
        TestCase {
            name: "2.4 Transport Layer tests point-to-point connectionless communication",
            steps: vec![
                comment("Testcase 2.4 Transport Layer tests point-to-point connectionless communication"),
                comment("Purpose: Check BDUT's acceptance of connectionless frames with incorrect TPCI-coding."),
                comment("Procedure: Use a telegram generator to send connectionless frames with incorrect TPCI coding for connectionless communication:"),
                comment("PropertyRead(Obj=00, Prop=36, Count=1, Start=001) with TPCI of T_Data_Broadcast/T_Data_Group."),
                // Faulty: PropertyRead with TPCI=03 (group/broadcast) - should be ignored
                inject_delay("BC #IFACE_A_ADDR #BDUT_ADDR E5 03 D5 00 36 10 01", 200),
                comment("PropertyRead(Obj=00, Prop=36, Count=1, Start=001) with TPCI of T_Data_Connected."),
                // Faulty: PropertyRead with TPCI=43 (T_Data_Connected) - should be ignored
                inject_delay("BC #IFACE_A_ADDR #BDUT_ADDR 65 43 D5 00 36 10 01", 200),
                comment("PropertyRead(Obj=00, Prop=36, Count=1, Start=001) with an undefined TPCI value."),
                // Faulty: PropertyRead with TPCI=83 (undefined) - should be ignored
                inject_delay("BC #IFACE_A_ADDR #BDUT_ADDR 65 83 D5 00 36 10 01", 200),
                comment("PropertyRead(Obj=00, Prop=36, Count=1, Start=001) with TPCI of T_(N)Ack."),
                // Faulty: PropertyRead with TPCI=C3 (T_Ack/T_Nack) - should be ignored
                inject_delay("BC #IFACE_A_ADDR #BDUT_ADDR 65 C3 D5 00 36 10 01", 200),
                comment("Acceptance: BDUT does not accept the frames and does not produce any responses."),
            ],
        },
        
        // --------------------------------------------------------------------
        // Test 2.5: Additional negative Transport Layer Tests
        // --------------------------------------------------------------------
        TestCase {
            name: "2.5 Additional negative Transport Layer Tests",
            steps: vec![
                comment("Testcase 2.5 Additional negative Transport Layer Tests"),
                
                // === 2.5.1: Ignoring a malformed T_Connect message ===
                comment("Testcase 2.5.1 Ignoring a malformed T_Connect message"),
                comment("Purpose: Check that the BDUT ignores a malformed T_Connect message (with increasing number of appended bytes) and does not react to a correct DeviceDescriptorRead"),
                comment("Procedure: Send a T-Connect with an appended byte(s), wait 1 second, send correct Device Descriptor Read message"),
                // T_Connect with one appended byte - should be ignored
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 61 80 11", 1000),
                // DeviceDescriptorRead - should be ignored (no connection)
                inject_delay("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00", 1000),
                // T_Connect with two appended bytes
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 62 80 11 22", 1000),
                inject_delay("BC #IFACE_A_ADDR #BDUT_ADDR 61 47 00", 1000),
                // T_Connect with three appended bytes
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 63 80 11 22 33", 1000),
                inject_delay("BC #IFACE_A_ADDR #BDUT_ADDR 61 4B 00", 1000),
                // T_Connect with four appended bytes
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 64 80 11 22 33 44", 1000),
                inject_delay("BC #IFACE_A_ADDR #BDUT_ADDR 61 4F 00", 1000),
                // T_Connect with five appended bytes
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 65 80 11 22 33 44 55", 1000),
                inject_delay("BC #IFACE_A_ADDR #BDUT_ADDR 61 53 00", 1000),
                // Clean disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("Acceptance: BDUT ignores the malformed T-Connect and ignores the Device Description Read (as the transport layer connection is not opened)"),
                
                // === 2.5.2: Ignoring a malformed T_Disconnect message ===
                comment("Testcase 2.5.2 Ignoring a malformed T_Disconnect message"),
                comment("Purpose: Check that the BDUT ignores a malformed T_Disconnect message (with increasing number of appended bytes)"),
                comment("Procedure: Send a T-Connect followed by a malformed T-Disconnect, send DeviceDescriptorRead, check response, send malformed T-Disconnect again, check BDUT stays in OPEN_WAIT"),
                
                // Test with one appended byte
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 61 81 11", 1000),  // Malformed T_Disconnect
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 1000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 61 81 11", 1000),  // Malformed T_Disconnect again
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3000),  // BDUT repeats response
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),  // Clean disconnect
                
                // Test with two appended bytes
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 62 81 11 22", 1000),
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 1000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 62 81 11 22", 1000),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                
                // Test with three appended bytes
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 63 81 11 22 33", 1000),
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 1000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 63 81 11 22 33", 1000),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                
                // Test with four appended bytes
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 64 81 11 22 33 44", 1000),
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 1000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 64 81 11 22 33 44", 1000),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("Acceptance: BDUT ignores the malformed T-Disconnect messages"),
                
                // === 2.5.3: Ignoring a malformed T_Ack message ===
                comment("Testcase 2.5.3 Ignoring a malformed T_Ack message"),
                comment("Purpose: Check that the BDUT ignores a malformed T_Ack message (with increasing number of appended bytes)"),
                
                // Test with one appended byte
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 61 C2 11", 1000),  // Malformed T_Ack
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 1000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 61 C2 11", 1000),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                
                // Test with two appended bytes
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 62 C2 11 22", 1000),
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 1000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 62 C2 11 22", 1000),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                
                // Test with three appended bytes
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 63 C2 11 22 33", 1000),
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 1000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 63 C2 11 22 33", 1000),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                
                // Test with four appended bytes
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 64 C2 11 22 33 44", 1000),
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 1000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 64 C2 11 22 33 44", 1000),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("Acceptance: BDUT ignores the malformed T-Ack messages"),
                
                // === 2.5.4: Ignoring a malformed T_Nack message ===
                comment("Testcase 2.5.4 Ignoring a malformed T_Nack message"),
                comment("Purpose: Check that the BDUT ignores a malformed T_Nack message (with increasing number of appended bytes)"),
                
                // Test with one appended byte
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 61 C3 11", 1000),  // Malformed T_Nack
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 1000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 61 C3 11", 1000),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                
                // Test with two appended bytes
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 62 C3 11 22", 1000),
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 1000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 62 C3 11 22", 1000),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                
                // Test with three appended bytes
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 63 C3 11 22 33", 1000),
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 1000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 63 C3 11 22 33", 1000),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                
                // Test with four appended bytes
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 64 C3 11 22 33 44", 1000),
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 1000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 64 C3 11 22 33 44", 1000),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3000),
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("Acceptance: BDUT ignores the malformed T-Nack messages"),
            ],
        },
    ];

    TestSuite::new("Transport Layer General Tests", vars).with_cases(cases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variables_created() {
        let vars = create_test_variables();
        assert!(vars.contains_key("IFACE_A_ADDR"));
        assert!(vars.contains_key("IFACE_B_ADDR"));
        assert!(vars.contains_key("BDUT_ADDR"));
        assert!(vars.contains_key("SER_NUM"));
        assert!(vars.contains_key("GO_ADDR"));

        // Verify addresses
        assert_eq!(vars["IFACE_A_ADDR"].as_bytes(), &[0xAF, 0xFE]);
        assert_eq!(vars["IFACE_B_ADDR"].as_bytes(), &[0xAF, 0x01]);
        assert_eq!(vars["BDUT_ADDR"].as_bytes(), &[0x10, 0x01]);
        assert_eq!(
            vars["SER_NUM"].as_bytes(),
            &[0xFE, 0xED, 0xBA, 0xBE, 0xCA, 0xFE]
        );
    }

    #[test]
    fn test_cases_created() {
        let suite = create_transport_layer_suite();
        let tests = &suite.cases;
        assert_eq!(tests.len(), 5);

        // Verify test names
        assert_eq!(
            tests[0].name,
            "2.1 Transport Layer tests for multicast communication"
        );
        assert_eq!(
            tests[1].name,
            "2.2 Transport Layer test for broadcast communication"
        );
        assert_eq!(
            tests[2].name,
            "2.3 Transport Layer tests point-to-point connection oriented communication"
        );
        assert_eq!(
            tests[3].name,
            "2.4 Transport Layer tests point-to-point connectionless communication"
        );
        assert_eq!(
            tests[4].name,
            "2.5 Additional negative Transport Layer Tests"
        );
    }
}
