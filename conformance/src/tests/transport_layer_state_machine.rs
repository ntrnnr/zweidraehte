//! Transport Layer Conformance Tests - State Machine (without EMI)
//!
//! Tests based on KNX 3.0.0, Volume 08_03_04 Transport Layer Tests v01.06.07 AS
//! Reference: AN179 v04, AN182 v03, AN181 rev3, AN210 v02
//!
//! Test Collection: TL-Testing of Transport Layer State Machine, without EMI (Section 6)
//!
//! These tests verify correct state machine behavior for:
//! - Connect from a remote device
//! - Connect during an existing connection
//! - Disconnect from a remote device
//! - Disconnect during an existing connection (from different source)
//! - Connection timeout
//! - Acknowledgement timeout
//! - Reception of correct N_Data_Individual
//! - Reception of repeated N_Data_Individual
//! - Reception of N_Data_Individual with wrong sequence number
//! - Reception of N_Data_Individual with wrong source address
//! - Reception of T_ACK_PDU
//! - Reception of T_ACK_PDU with wrong sequence number
//! - Reception of T_ACK_PDU with wrong connection address
//! - Reception of T_NAK_PDU with wrong sequence number
//! - Reception of T_NAK_PDU with correct sequence number
//! - Reception of T_NAK_PDU (max repetitions not reached)
//! - Reception of T_NAK_PDU (max repetitions reached)
//! - Reception of T_NAK_PDU with wrong connection address
//! - Events started in state CLOSED
//!
//! ## Test Status
//!
//! All 32 state machine tests are implemented and passing.

use std::collections::BTreeMap;

use super::helpers::{comment, expect, inject, inject_delay};
use crate::{TestCase, TestSuite, TestVariable};

/// Create test variables for transport layer state machine tests
///
/// Based on the EITT specification:
/// - IFACE_A_ADDR: Physical Address for USB A (10.15.254 = AF FE)
/// - IFACE_B_ADDR: Physical Address for USB B (10.15.1 = AF 01)
/// - BDUT_ADDR: Basic Device Under Test (1.0.1 = 10 01)
pub fn create_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    vars.insert("IFACE_A_ADDR".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("IFACE_B_ADDR".to_string(), TestVariable::Bytes(vec![0xAF, 0x01]));
    vars.insert("BDUT_ADDR".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    vars
}

/// Create transport layer state machine test suite from EITT specification
///
/// Test Collection: TL-Testing of Transport Layer State Machine, without EMI
pub fn create_transport_layer_state_machine_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // Test Suite 6.2.1: Connect from a remote device
        // ====================================================================
        TestCase {
            name: "6.2.1.1 Connect with initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.2.1.1 Sequence 1: Procedure with initial state 'OPEN_IDLE'"),
                comment("Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("The BDUT is in State 'OPEN_IDLE'."),
                comment("Connect again from same USB to BDUT."),
                // Second T_Connect from same source - resets connection timeout
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80"),
                comment("BDUT remains in OPEN_IDLE, BDUT only sends Disconnect on the bus after connection time out."),
                // Wait for connection timeout (6 seconds + tolerance)
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 81", 6400),
                comment("================================================================================"),
            ],
        },
        TestCase {
            name: "6.2.1.2 Connect with initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.2.1.2 Sequence 2: Procedure with initial state 'OPEN_WAIT'"),
                comment("Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("The BDUT is in State 'OPEN_IDLE' – send MaskVersion Read to change to OPEN_WAIT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 500),
                comment("The BDUT is in State 'OPEN_WAIT'."),
                comment("A second connect is sent to BDUT from USB A."),
                // Second T_Connect (wait for it to be processed)
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 1000),
                comment("BDUT remains in OPEN_WAIT. EITT confirms the MaskVersionResponse with T-Ack and actively closes."),
                // T_Ack for the response
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C2", 200),
                // T_Disconnect to close cleanly
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.2.2: Connect from a remote device during an existing connection
        // ====================================================================
        TestCase {
            name: "6.2.2.1 Connect during connection, initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.2.2.1 Sequence 3: Procedure with initial state 'OPEN_IDLE'"),
                comment("Connect from USB A to BDUT."),
                // T_Connect from A
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Connect from USB B to BDUT."),
                // T_Connect from B (different source)
                inject("B0 #IFACE_B_ADDR #BDUT_ADDR 60 80"),
                // BDUT should disconnect the new connection attempt from B
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 60 81", 200),
                comment("Send immediate disconnect from USB A."),
                // Clean disconnect from A
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("================================================================================"),
            ],
        },
        TestCase {
            name: "6.2.2.2 Connect during connection, initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.2.2.2 Sequence 4: Procedure with initial state 'OPEN_WAIT'"),
                comment("Connect from USB B to BDUT."),
                // T_Connect from B
                inject_delay("B0 #IFACE_B_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead from USB B to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_B_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 500),
                comment("Send second connection from USB A to BDUT."),
                // T_Connect from A while B is connected
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80"),
                // BDUT should disconnect the new connection attempt from A
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 81", 200),
                comment("BDUT repeats sent response every 3 seconds."),
                // First repetition
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 3200),
                comment("Send immediate disconnect from USB B."),
                // Clean disconnect from B
                inject_delay("B0 #IFACE_B_ADDR #BDUT_ADDR 60 81", 200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.2.3: Disconnect from a remote device
        // ====================================================================
        TestCase {
            name: "6.2.3.1 Disconnect with initial state CLOSED",
            steps: vec![
                comment("Testcase 6.2.3.1 Sequence 5: Procedure with initial state 'CLOSED'"),
                comment("---> Send Disconnect to BDUT in State CLOSED."),
                // T_Disconnect when already closed - should be ignored
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 6200),
                comment("---> No response shows that BDUT remains CLOSED (wait for 6 seconds)."),
                // No expect - we're just verifying no response comes
                comment("================================================================================"),
            ],
        },
        TestCase {
            name: "6.2.3.2 Disconnect with initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.2.3.2 Sequence 6: Procedure with initial state 'OPEN_IDLE'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send Disconnect from USB A to BDUT."),
                comment("---> No response shows that BDUT switched to CLOSED (wait for 6 seconds)."),
                // T_Disconnect - BDUT should close silently
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 6200),
                // No expect - BDUT closes without response
                comment("================================================================================"),
            ],
        },
        TestCase {
            name: "6.2.3.3 Disconnect with initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.2.3.3 Sequence 7: Procedure with initial state 'OPEN_WAIT'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead from USB A to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 500),
                // T_Ack for the response
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C2", 200),
                comment("BCU is in state OPEN_WAIT."),
                comment("Send Disconnect from USB A to BDUT."),
                // T_Disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 6200),
                comment("---> No response shows that BDUT switched to CLOSED."),
                comment("Now the BDUT is in State 'CLOSED'."),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.2.4: Disconnect from a remote device during an existing connection
        // ====================================================================
        TestCase {
            name: "6.2.4.1 Disconnect during connection, initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.2.4.1 Sequence 8: Procedure with initial state 'OPEN_IDLE'"),
                comment("Connect from USB A to BDUT."),
                // T_Connect from A
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send Disconnect from USB B to BDUT."),
                // T_Disconnect from B (different source) - should be ignored
                inject("B0 #IFACE_B_ADDR #BDUT_ADDR 60 81"),
                comment("---> No response shows that BDUT remains in OPEN_IDLE."),
                comment("BDUT sends disconnect to USB A after connection timeout."),
                // After ~6 seconds, BDUT disconnects from A due to timeout
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 81", 6400),
                comment("================================================================================"),
            ],
        },
        TestCase {
            name: "6.2.4.2 Disconnect during connection, initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.2.4.2 Sequence 9: Procedure with initial state 'OPEN_WAIT'"),
                comment("Connect from USB A to BDUT."),
                // T_Connect from A
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead from USB A to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 500),
                comment("BDUT is in state OPEN_WAIT."),
                comment("Send Disconnect from USB B to BDUT."),
                // T_Disconnect from B (different source) - should be ignored
                inject("B0 #IFACE_B_ADDR #BDUT_ADDR 60 81"),
                comment("---> BDUT sends repetition every 3 seconds after ACK-timeout and shows that BDUT remains in OPEN_WAIT."),
                // BDUT repeats the response
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3200),
                comment("Send immediate disconnect from USB A."),
                // Clean disconnect from A
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.2.5: Connection timeout
        // ====================================================================
        TestCase {
            name: "6.2.5.1 Connection timeout from OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.2.5.1 Sequence 10: Procedure with initial state 'OPEN_IDLE'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80"),
                comment("BDUT sends Disconnect to USB A after connection timeout."),
                // After ~6 seconds, BDUT disconnects due to timeout
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 81", 6200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.2.6: Acknowledgement timeout
        // ====================================================================
        TestCase {
            name: "6.2.6.1 Acknowledgement timeout from OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.2.6.1 Sequence 11: Procedure with initial state 'OPEN_WAIT'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead from USB A to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 500),
                comment("BCU is in state OPEN_WAIT."),
                comment("-------------------------------------------"),
                comment("---> BDUT sends repetition every 3 seconds after ACK-timeout."),
                // First repetition
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3200),
                // Second repetition
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3200),
                // Third repetition
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3200),
                comment("---> BDUT sends Disconnect to USB A after ACK-timeout."),
                // Disconnect after max retries
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 81", 3200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.3.1: Reception of a correct N_Data_Individual
        // ====================================================================
        TestCase {
            name: "6.3.1.1 N_Data_Individual with initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.3.1.1 Sequence 12: Procedure with initial state 'OPEN_IDLE'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DeviceDescriptorRead from USB A to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                comment("---> BDUT sends T-ACK and Mask Version Response to USB A."),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 500),
                comment("Send Disconnect from USB A to BDUT."),
                // T_Disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("================================================================================"),
            ],
        },
        TestCase {
            name: "6.3.1.2 N_Data_Individual with initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.3.1.2 Sequence 13: Procedure with initial state 'OPEN_WAIT'"),
                comment("Purpose: check whether a repetition of an N_DataIndividual with SeqNo_of_PDU = SeqNoRcv is accepted."),
                comment("Initial state: Send T_Connect and MaskVersionRead to BDUT to establish OPEN_WAIT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in State OPEN_IDLE."),
                comment("Now the BDUT receives a MaskVersionRead."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                comment("BDUT is in State OPEN_IDLE."),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 500),
                comment("BDUT is in State OPEN_WAIT."),
                // Send PropertyValueRead (seq 1) while still waiting for ack
                inject("BC #IFACE_A_ADDR #BDUT_ADDR 66 47 D7 00 36 10 01 01"),
                // Expect T_Ack for seq 1
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C6", 200),
                comment("BDUT persists in state OPEN_WAIT."),
                // BDUT repeats the DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3400),
                // Send T_Ack for the DeviceDescriptorResponse (seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C2"),
                comment("BDUT is now in OPEN_IDLE and sends the Property-Responses."),
                // PropertyValueResponse (seq 1) - multiple repetitions expected
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 66 47 D6 00 36 10 01 01", 500),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 66 47 D6 00 36 10 01 01", 3200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 66 47 D6 00 36 10 01 01", 3200),
                expect("BC #BDUT_ADDR #IFACE_A_ADDR 66 47 D6 00 36 10 01 01", 3200),
                // Finally disconnect after max retries
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 81", 3200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.3.3: Reception of a repeated N_Data_Individual
        // ====================================================================
        TestCase {
            name: "6.3.3.1 Repeated N_Data_Individual with initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.3.3.1 Sequence 14: Procedure with initial state 'OPEN_IDLE'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("In the following User Data requests are used as the AL of the BDUT will not respond to them."),
                comment("Send UserData from USB A to BDUT."),
                // UserData (seq 0) - APCI 0x02C3 = User Data
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 42 C3"),
                comment("---> BDUT sends T-ACK to USB A."),
                // Expect T_Ack for seq 0
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                comment("Send UserData-repetition from USB A to BDUT to prevent an AL-response."),
                // Same UserData again (seq 0) - repetition
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 61 42 C3", 200),
                comment("--->BDUT sends T-ACK to USB A."),
                // Expect T_Ack for seq 0 again
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                comment("Send Disconnect from USB A to BDUT."),
                // T_Disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("================================================================================"),
            ],
        },
        TestCase {
            name: "6.3.3.2 Repeated N_Data_Individual with initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.3.3.2 Sequence 15: Procedure with initial state 'OPEN_WAIT'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DeviceDescriptorRead from USB A to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 500),
                comment("BCU is in state OPEN_WAIT."),
                comment("Send UserData from USB A to BDUT to prevent an AL-response."),
                // UserData (seq 1) - TPCI 46 = numbered data seq 1
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 46 C3"),
                comment("---> BDUT sends T-ACK to USB A."),
                // Expect T_Ack for seq 1
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C6", 200),
                comment("Send UserData-repetition from USB A to BDUT to prevent an AL-response."),
                // Same UserData again (seq 1) - repetition
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 61 46 C3", 200),
                comment("---> BDUT sends T-ACK to USB A."),
                // Expect T_Ack for seq 1 again
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C6", 200),
                comment("Send Disconnect from USB A to BDUT."),
                // T_Disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.3.4: Reception of N_Data_Individual with wrong sequence number
        // ====================================================================
        TestCase {
            name: "6.3.4.1 Wrong sequence number with initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.3.4.1 Sequence 16: Procedure with initial state 'OPEN_IDLE'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DeviceDescriptorRead from USB A to BDUT with sequence number 5."),
                // DeviceDescriptorRead with seq 5 (wrong - should be 0)
                // TPCI 57 = numbered data seq 5
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 57 00"),
                comment("---> BDUT sends NACK to USB A with sequence number 5."),
                // Expect T_NAck with seq 5 (D7 = 1101 0111 = NAck seq 5)
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 D7", 200),
                comment("-----------------------------------------------------------------"),
                comment("---> BDUT sends Disconnect to USB A after connection-timeout."),
                // Wait for connection timeout
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 81", 6200),
                comment("================================================================================"),
            ],
        },
        TestCase {
            name: "6.3.4.2 Wrong sequence number with initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.3.4.2 Sequence 17: Procedure with initial state 'OPEN_WAIT'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead from USB A to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 500),
                comment("BDUT is in state OPEN_WAIT."),
                comment("--------------------------------------------------------------"),
                comment("Send DeviceDescriptorRead from USB A to BDUT with sequence number 5."),
                // DeviceDescriptorRead with seq 5 (wrong - should be 1)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 57 00"),
                comment("---> BDUT sends NACK to USB A with sequence number 5."),
                // Expect T_NAck with seq 5
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 D7", 200),
                comment("---> BDUT sends repetition of DeviceDescriptorResponse after timeout."),
                // BDUT repeats the response
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3200),
                comment("USB A sends Disconnect to BDUT."),
                // T_Disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.3.5: Reception of N_Data_Individual with wrong source address
        // ====================================================================
        TestCase {
            name: "6.3.5.1 Wrong source address with initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.3.5.1 Sequence 18: Procedure with initial state 'OPEN_IDLE'"),
                comment("Connect from USB B to BDUT."),
                // T_Connect from B
                inject_delay("B0 #IFACE_B_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead from USB A to BDUT."),
                // DeviceDescriptorRead from A (wrong source - connected to B)
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00", 200),
                comment("BDUT sends Disconnect to USB B after connection-timeout."),
                // Wait for connection timeout, BDUT disconnects from B
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 60 81", 6200),
                comment("================================================================================"),
            ],
        },
        TestCase {
            name: "6.3.5.2 Wrong source address with initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.3.5.2 Sequence 19: Procedure with initial state 'OPEN_WAIT'"),
                comment("Connect from USB B to BDUT."),
                // T_Connect from B
                inject_delay("B0 #IFACE_B_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead from USB B to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_B_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 500),
                comment("BDUT is in state OPEN_WAIT."),
                comment("Send DevDescriptorRead from USB A to BDUT."),
                // DeviceDescriptorRead from A (wrong source - connected to B) seq 1
                // TPCI 47 = numbered data seq 1
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 47 00"),
                comment("BDUT sends repetition of DeviceData after ACK-timeout."),
                // BDUT repeats the response to B (ignores A's message)
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 3200),
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 3200),
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 3200),
                comment("BDUT disconnects from USB B."),
                // Disconnect after max retries
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 60 81", 3200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.4.1: Reception of a T_ACK_PDU
        // ====================================================================
        TestCase {
            name: "6.4.1.1 T_ACK_PDU with initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.4.1.1 Sequence 20: Procedure with initial state 'OPEN_IDLE'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send T-ACK from USB A to BDUT."),
                // T_Ack (seq 0) - C2 = 1100 0010 = Ack seq 0
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C2", 200),
                comment("BDUT remains in OPEN_IDLE, BDUT sends no Disconnect on the bus."),
                // Wait 5 seconds to verify no disconnect
                comment("Cleanup: USB A sends Disconnect to BDUT."),
                // T_Disconnect (after waiting)
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 5000),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.4.2: Reception of T_ACK_PDU with wrong sequence number
        // ====================================================================
        TestCase {
            name: "6.4.2.1 T_ACK wrong sequence number with initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.4.2.1 Sequence 21: Procedure with initial state 'OPEN_IDLE'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send T-ACK from USB A to BDUT with wrong sequence number."),
                // T_Ack with seq 5 - D6 = 1101 0110 = wrong ack seq 5
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 D6", 200),
                comment("BDUT remains in OPEN_IDLE, BDUT sends no Disconnect on the bus."),
                // Wait 5 seconds to verify no disconnect
                comment("Cleanup: USB A sends Disconnect to BDUT."),
                // T_Disconnect (after waiting)
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 5000),
                comment("================================================================================"),
            ],
        },
        TestCase {
            name: "6.4.2.2 T_ACK wrong sequence number with initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.4.2.2 Sequence 22: Procedure with initial state 'OPEN_WAIT'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead from USB A to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 500),
                comment("BCU is in state OPEN_WAIT."),
                comment("Send T-ACK from USB A to BDUT with wrong sequence number."),
                // T_Ack with seq 5 (wrong - should be 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 60 D6"),
                comment("---> BDUT remains in OPEN_WAIT, BDUT sends no Disconnect on the bus."),
                // BDUT repeats the response
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3200),
                comment("Cleanup: USB A sends Disconnect to BDUT."),
                // T_Disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.4.3: Reception of T_ACK_PDU with wrong connection address
        // ====================================================================
        TestCase {
            name: "6.4.3.1 T_ACK wrong connection address with initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.4.3.1 Sequence 23: Procedure with initial state 'OPEN_IDLE'"),
                comment("Connect from USB B to BDUT."),
                // T_Connect from B
                inject_delay("B0 #IFACE_B_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send T-ACK from USB A to BDUT."),
                // T_Ack from A (wrong source - connected to B)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C2"),
                comment("---> BDUT sends Disconnect to USB B after connection-timeout."),
                // Wait for connection timeout
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 60 81", 6200),
                comment("================================================================================"),
            ],
        },
        TestCase {
            name: "6.4.3.2 T_ACK wrong connection address with initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.4.3.2 Sequence 24: Procedure with initial state 'OPEN_WAIT'"),
                comment("Connect from USB B to BDUT."),
                // T_Connect from B
                inject_delay("B0 #IFACE_B_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead from USB B to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_B_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 500),
                comment("BDUT is in state OPEN_WAIT."),
                comment("Send T-ACK from USB A to BDUT."),
                // T_Ack from A (wrong source - connected to B)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C2"),
                comment("---> BDUT sends repetition of Device Data after ACK-timeout and disconnects after connection timeout."),
                // BDUT repeats the response to B
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 3200),
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 3200),
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 3200),
                // Disconnect from B after max retries
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 60 81", 12200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.4.4: Reception of T_NAK_PDU with wrong sequence number
        // ====================================================================
        TestCase {
            name: "6.4.4.1 T_NAK wrong sequence number with initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.4.4.1 Sequence 25: Procedure with initial state 'OPEN_IDLE'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send T-NACK from USB A to BDUT with wrong sequence number."),
                // T_NAck with seq 5 (D7 = 1101 0111 = NAck seq 5)
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 D7", 200),
                comment("BDUT remains in OPEN_IDLE, BDUT sends no Disconnect on the bus."),
                // Wait 5 seconds to verify no disconnect
                comment("Cleanup: USB A sends Disconnect to BDUT."),
                // T_Disconnect (after waiting)
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 5000),
                comment("================================================================================"),
            ],
        },
        TestCase {
            name: "6.4.4.2 T_NAK wrong sequence number with initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.4.4.2 Sequence 26: Procedure with initial state 'OPEN_WAIT'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead from USB A to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 500),
                comment("BCU is in state OPEN_WAIT."),
                comment("Send T-NACK from USB A to BDUT with wrong sequence number."),
                // T_NAck with seq 5 (wrong - should be 0)
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 D7", 200),
                comment("---> BDUT remains in OPEN_WAIT, BDUT sends no Disconnect on the bus."),
                // BDUT repeats the response
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3200),
                comment("Cleanup: USB A sends Disconnect to BDUT."),
                // T_Disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.4.5: Reception of T_NAK_PDU with correct sequence number
        // ====================================================================
        TestCase {
            name: "6.4.5.1 T_NAK correct sequence number with initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.4.5.1 Sequence 27: Procedure with initial state 'OPEN_IDLE'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send T-NACK from USB A to BDUT."),
                // T_NAck with seq 0 (C3 = 1100 0011 = NAck seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C3"),
                comment("---> BDUT sends an immediate Disconnect to USB A."),
                // BDUT disconnects immediately
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 81", 200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.4.6: Reception of T_NAK_PDU and maximum number of repetitions is not reached
        // ====================================================================
        TestCase {
            name: "6.4.6.1 T_NAK max repetitions not reached with initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.4.6.1 Sequence 28: Procedure with initial state 'OPEN_WAIT'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead from USB A to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 500),
                comment("BDUT is in state OPEN_WAIT."),
                comment("Send T-NACK from USB A to BDUT."),
                // T_NAck with seq 0 (C3 = NAck seq 0) - triggers immediate repeat
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C3"),
                comment("---> BDUT sends repetition to USB A."),
                // BDUT repeats the response
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3200),
                comment("USB A sends Disconnect to BDUT."),
                // T_Disconnect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 81", 200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.4.7: Reception of T_NAK_PDU and maximum number of repetitions is reached
        // ====================================================================
        TestCase {
            name: "6.4.7.1 T_NAK max repetitions reached with initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.4.7.1 Sequence 29: Procedure with initial state 'OPEN_WAIT'"),
                comment("Send Connect from USB A to BDUT."),
                // T_Connect
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead from USB A to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 500),
                comment("BDUT is in state OPEN_WAIT."),
                comment("BDUT sends repetitions to USB A for 3 times."),
                // BDUT repeats the response 3 times (timeout retries)
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3200),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 3200),
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 63 43 40 ?? ??", 9500),
                comment("Send T-NACK from USB A to BDUT."),
                // T_NAck after max retries - this triggers disconnect
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C3"),
                comment("---> BDUT sends Disconnect to USB A."),
                // BDUT disconnects after receiving NAck at max retries
                expect("B0 #BDUT_ADDR #IFACE_A_ADDR 60 81", 200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.4.8: Reception of T_NAK_PDU with wrong connection address
        // ====================================================================
        TestCase {
            name: "6.4.8.1 T_NAK wrong connection address with initial state OPEN_IDLE",
            steps: vec![
                comment("Testcase 6.4.8.1 Sequence 30: Procedure with initial state 'OPEN_IDLE'"),
                comment("Connect from USB B to BDUT."),
                // T_Connect from B
                inject_delay("B0 #IFACE_B_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send T-NACK from USB A to BDUT."),
                // T_NAck from A (wrong source - connected to B)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C3"),
                comment("BDUT sends no Disconnect on the bus."),
                comment("---> BDUT sends Disconnect to USB B after connection-timeout."),
                // Wait for connection timeout
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 60 81", 6200),
                comment("================================================================================"),
            ],
        },
        TestCase {
            name: "6.4.8.2 T_NAK wrong connection address with initial state OPEN_WAIT",
            steps: vec![
                comment("Testcase 6.4.8.2 Sequence 31: Procedure with initial state 'OPEN_WAIT'"),
                comment("Connect from USB B to BDUT."),
                // T_Connect from B
                inject_delay("B0 #IFACE_B_ADDR #BDUT_ADDR 60 80", 200),
                comment("BDUT is in state OPEN_IDLE."),
                comment("Send DevDescriptorRead from USB B to BDUT."),
                // DeviceDescriptorRead (seq 0)
                inject("B0 #IFACE_B_ADDR #BDUT_ADDR 61 43 00"),
                // Expect T_Ack
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 60 C2", 200),
                // Expect DeviceDescriptorResponse
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 500),
                comment("BDUT is in state OPEN_WAIT."),
                comment("Send T-NACK from USB A to BDUT."),
                // T_NAck from A (wrong source - connected to B)
                inject("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C3"),
                comment("---> BDUT sends repetition of DeviceData after ACK-timeout."),
                // BDUT repeats the response to B
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 3200),
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 3200),
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 63 43 40 ?? ??", 3200),
                comment("BDUT sends disconnect to USB B."),
                // Disconnect from B after max retries
                expect("B0 #BDUT_ADDR #IFACE_B_ADDR 60 81", 12200),
                comment("================================================================================"),
            ],
        },

        // ====================================================================
        // Test Suite 6.5: Events started in state 'CLOSED'
        // ====================================================================
        TestCase {
            name: "6.5.1 Events in state CLOSED",
            steps: vec![
                comment("Testcase 6.5.1 Sequence 32: Procedure with initial state 'CLOSED'"),
                comment("Send DeviceDescriptorRead from USB A to BDUT."),
                // DeviceDescriptorRead without connection - should be ignored
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 61 43 00", 500),
                comment("Send T-ACK from USB A to BDUT."),
                // T_Ack without connection - should be ignored
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C2", 500),
                comment("BDUT sends no Disconnect on the bus."),
                comment("Send T-NACK from USB A to BDUT."),
                // T_NAck without connection - should be ignored
                inject_delay("B0 #IFACE_A_ADDR #BDUT_ADDR 60 C3", 500),
                comment("BDUT sends no Disconnect on the bus."),
                comment("================================================================================"),
            ],
        },
    ];

    TestSuite::new("Transport Layer State Machine Tests", vars).with_cases(cases)
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

        // Verify addresses
        assert_eq!(vars["IFACE_A_ADDR"].as_bytes(), &[0xAF, 0xFE]);
        assert_eq!(vars["IFACE_B_ADDR"].as_bytes(), &[0xAF, 0x01]);
        assert_eq!(vars["BDUT_ADDR"].as_bytes(), &[0x10, 0x01]);
    }

    #[test]
    fn test_cases_created() {
        let suite = create_transport_layer_state_machine_suite();
        let tests = &suite.cases;
        // All 32 tests are currently active
        assert_eq!(tests.len(), 32);

        // Verify test names for active tests
        assert_eq!(tests[0].name, "6.2.1.1 Connect with initial state OPEN_IDLE");
        assert_eq!(tests[1].name, "6.2.1.2 Connect with initial state OPEN_WAIT");
        assert_eq!(tests[2].name, "6.2.2.1 Connect during connection, initial state OPEN_IDLE");
        assert_eq!(tests[3].name, "6.2.2.2 Connect during connection, initial state OPEN_WAIT");
        assert_eq!(tests[4].name, "6.2.3.1 Disconnect with initial state CLOSED");
        assert_eq!(tests[5].name, "6.2.3.2 Disconnect with initial state OPEN_IDLE");
        assert_eq!(tests[6].name, "6.2.3.3 Disconnect with initial state OPEN_WAIT");
        assert_eq!(tests[7].name, "6.2.4.1 Disconnect during connection, initial state OPEN_IDLE");
        assert_eq!(tests[8].name, "6.2.4.2 Disconnect during connection, initial state OPEN_WAIT");
        assert_eq!(tests[9].name, "6.2.5.1 Connection timeout from OPEN_IDLE");
        assert_eq!(tests[10].name, "6.2.6.1 Acknowledgement timeout from OPEN_WAIT");
        assert_eq!(tests[11].name, "6.3.1.1 N_Data_Individual with initial state OPEN_IDLE");
        assert_eq!(tests[12].name, "6.3.1.2 N_Data_Individual with initial state OPEN_WAIT");
        assert_eq!(tests[13].name, "6.3.3.1 Repeated N_Data_Individual with initial state OPEN_IDLE");
        assert_eq!(tests[14].name, "6.3.3.2 Repeated N_Data_Individual with initial state OPEN_WAIT");
        assert_eq!(tests[15].name, "6.3.4.1 Wrong sequence number with initial state OPEN_IDLE");
        assert_eq!(tests[16].name, "6.3.4.2 Wrong sequence number with initial state OPEN_WAIT");
        assert_eq!(tests[17].name, "6.3.5.1 Wrong source address with initial state OPEN_IDLE");
        assert_eq!(tests[18].name, "6.3.5.2 Wrong source address with initial state OPEN_WAIT");
        assert_eq!(tests[19].name, "6.4.1.1 T_ACK_PDU with initial state OPEN_IDLE");
        assert_eq!(tests[20].name, "6.4.2.1 T_ACK wrong sequence number with initial state OPEN_IDLE");
        assert_eq!(tests[21].name, "6.4.2.2 T_ACK wrong sequence number with initial state OPEN_WAIT");
        assert_eq!(tests[22].name, "6.4.3.1 T_ACK wrong connection address with initial state OPEN_IDLE");
        assert_eq!(tests[23].name, "6.4.3.2 T_ACK wrong connection address with initial state OPEN_WAIT");
        assert_eq!(tests[24].name, "6.4.4.1 T_NAK wrong sequence number with initial state OPEN_IDLE");
        assert_eq!(tests[25].name, "6.4.4.2 T_NAK wrong sequence number with initial state OPEN_WAIT");
        assert_eq!(tests[26].name, "6.4.5.1 T_NAK correct sequence number with initial state OPEN_IDLE");
        assert_eq!(tests[27].name, "6.4.6.1 T_NAK max repetitions not reached with initial state OPEN_WAIT");
        assert_eq!(tests[28].name, "6.4.7.1 T_NAK max repetitions reached with initial state OPEN_WAIT");
        assert_eq!(tests[29].name, "6.4.8.1 T_NAK wrong connection address with initial state OPEN_IDLE");
        assert_eq!(tests[30].name, "6.4.8.2 T_NAK wrong connection address with initial state OPEN_WAIT");
        assert_eq!(tests[31].name, "6.5.1 Events in state CLOSED");
    }
}
