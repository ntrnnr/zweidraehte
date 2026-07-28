//! Group Object Conformance Tests
//!
//! Transcribed from the EITT template `KnxConformanceTestTemplate-GroupObjects.xml`,
//! Version 11 (2025-03-18), which realises 08_03_07 "System Conformance Testing -
//! AIL and Management Tests" §1.4.1.
//!
//! Three template revisions matter for reading this file, because earlier
//! transcriptions of these tests looked quite different:
//!
//! - v7 (2023-02-07): the write flag no longer influences the update on a
//!   received `A_GroupValue_Response` — see 1.4.1.5 below.
//! - v8 (2024-07-16): 1.4.1.4a no longer re-types GO0/GO3 to BYTE3.
//! - v9 (2024-12-11): 1.4.1.5's "read response update" clause carries the
//!   BCU2 response value.
//!
//! The tests in this collection are performed on a Group Object with Field Value Type UINT1.
//! This format shall be accessible by GO0, whereas the three additional group objects are
//! implemented as auxiliary objects to access the configuration and communication flags.
//!
//! The test cases (intended to test BCU2 technology) may have to be adapted according to
//! the to-be-tested system implementation as regards the order of the communication and
//! configuration flags.
//!
//! ## Test Setup Requirements
//!
//! The following sample application program with group objects shall be loaded into the BDUT:
//!
//! - **GO0**: object type = 1 bit (UINT1), group address 1000h
//!   - Tests supported AIL format(s) and correct reaction to value read/write/response
//! - **GO1**: object type = 4 bit (UINT4), group address 1001h
//!   - Makes the communication flags of GO0 accessible via the bus
//! - **GO2**: object type = 8 bit (UINT8), group address 1002h
//!   - Makes the configuration flags of GO0 accessible via the bus
//! - **GO3**: object type = 8 bit (UINT8), group address 1003h
//!   - Makes the value of GO0 accessible via the bus, thereby avoiding the modification
//!     of the configuration and communication flags of GO0
//! - **GO4**: object type = 8 bit (UINT8), group address 1005h
//!   - For Read on Init testing
//!
//! ## Special Test Cases
//!
//! - **1.4.1.4a (BDUT receives invalid data length)**: a one-octet payload is
//!   written to the 1-bit GO0. The short encoding carries the value inside the
//!   APCI octet, so the extra octet makes the frame one longer than the object
//!   and the write must be rejected.
//!
//! - **1.4.1.5 (BDUT receives A_GroupValue_Response)**: the update is gated by
//!   Communication Enable and Response Update Enable only. Write Enable does
//!   *not* participate — see the flag discussion in
//!   `zweidraehte_device::layers::application::group_data`.
//!
//! - **1.4.1.6 (Test Read on Init Flag)**: Assuming the BDUT has five group objects
//!   (GO0 to GO4), deactivate the read on init flag of the first 3 (with different settings
//!   of the other available flags) and activate the read on init of the last two. Attribute
//!   the group addresses 1001h to 1005h to Group Object 0 to 4.
//!
//! - **1.4.1.7 (BDUT receives invalid APCI)**: the template carries each
//!   invalid APCI twice, once as a TP frame and once as an RF one
//!   (`Medium="rf"`, changelog v9). Only the TP half applies to a TP1
//!   BDUT. Programming mode is toggled over the bus with an
//!   `A_PropertyValue_Write` to PID_PROGMODE rather than out of band.
//!
//! ## BCU1-Style Test Architecture
//!
//! These tests implement a BCU1-style application program model where:
//!
//! 1. **GO1 exposes GO0's communication flags**:
//!    - Bit 0-1: Transmission state (00=IdleOk, 01=IdleError, 10=Transmitting)
//!    - Bit 2: Read request pending
//!    - Bit 3: Update flag (value was updated)
//!    - Writing with bit 7 set = "set command" (modifies flags)
//!    - Writing with bit 7 clear = "clear command" or read current flags
//!
//! 2. **GO2 exposes GO0's configuration flags**:
//!    - Bits 0-1: Priority (0=System, 1=High, 2=Alarm, 3=Low)
//!    - Bit 2: Communication Enable (CE)
//!    - Bit 3: Read Enable (RE)
//!    - Bit 4: Write Enable (WE)
//!    - Bit 5: Read on Init (ROI)
//!    - Bit 6: Transmission Enable (TE)
//!    - Bit 7: Update Enable (UE) / Read Response Update
//!
//! 3. **GO3 provides direct value access**:
//!    - Reading/writing GO3 accesses GO0's value without modifying flags
//!
//! ## Implementation Notes
//!
//! The shadow object mechanism (GO1/GO2/GO3 accessing GO0's internal state) is
//! implemented via the `handle_write` and `prepare_read` hooks in the conformance
//! harness's `ConformanceComObjects` implementation.
//!
//! ### BCU1/BCU2 Compatibility - Explicit Triggering
//!
//! **Important**: Our stack does NOT automatically send GroupValue_Read/Write when
//! the ReadRequest or WriteRequest flags are set on a communication object. In a
//! real BCU1/BCU2, setting these flags would automatically trigger the bus operation.
//!
//! Our stack architecture separates comm object state from bus operations. Automatic
//! triggering would require either:
//! - Background scanning of all comm objects for status changes
//! - Event-driven status monitoring with async notification
//!
//! Neither approach fits our architecture cleanly. Instead, tests use explicit
//! `trigger_read(asap)` and `trigger_write(asap)` steps after setting the request
//! flags via GO1 to manually initiate the bus operations.
//!
//! ## Tests Implemented
//!
//! - 1.4.1.1: BDUT sends A_GroupValue_Read
//! - 1.4.1.2: BDUT receives A_GroupValue_Read
//! - 1.4.1.3: BDUT sends A_GroupValue_Write
//! - 1.4.1.4: BDUT receives A_GroupValue_Write
//! - 1.4.1.4a: BDUT receives invalid data length (optional)
//! - 1.4.1.5: BDUT receives A_GroupValue_Response
//! - 1.4.1.6: Checking of Read on Init Flag
//! - 1.4.1.7: BDUT receives invalid APCI
//!
//! ## Deliberate Deviations From the Template
//!
//! - `trigger_read` / `trigger_write` steps, as described above.
//! - `expect_none` is inserted wherever the template's acceptance criterion is
//!   "no response generated". EITT leaves that to the operator watching the
//!   trace; our runner needs the assertion spelled out.
//! - The template duplicates all eight cases for a UINT8 GO0. We implement the
//!   UINT1 collection only — the conformance DUT's GO0 is 1-bit.

use std::collections::BTreeMap;

use super::helpers::{
    comment, expect, expect_none, inject, inject_delay, trigger_read, trigger_write, wait_for_restart,
};
use crate::{TestCase, TestSuite, TestVariable};

/// Create test variables for group object tests
///
/// Based on the EITT specification:
/// - EDI: External Device Interface (10.15.254 = AF FE)
/// - BDUT: Basic Device Under Test (1.0.1 = 10 01)
/// - GO_0_ADDR through GO_4_ADDR: Group Object addresses
pub fn create_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    vars.insert("EDI".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("BDUT".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    // Group Object addresses (2/0/0 through 2/0/5)
    vars.insert("GO_0_ADDR".to_string(), TestVariable::Bytes(vec![0x10, 0x00]));
    vars.insert("GO_1_ADDR".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    vars.insert("GO_2_ADDR".to_string(), TestVariable::Bytes(vec![0x10, 0x02]));
    vars.insert("GO_3_ADDR".to_string(), TestVariable::Bytes(vec![0x10, 0x03]));
    vars.insert("GO_4_ADDR".to_string(), TestVariable::Bytes(vec![0x10, 0x05]));
    // Additional variables for test 1.4.1.7 (invalid APCI tests)
    // Memory addresses - these are device-specific placeholders
    vars.insert("MEM_ACCESSIBLE_START_CC".to_string(), TestVariable::Bytes(vec![0x01, 0x00]));
    vars.insert("MEM_ACCESSIBLE_START_AC".to_string(), TestVariable::Bytes(vec![0x01, 0x00]));
    // Interface object IDs and properties
    vars.insert("OBJ_0_ID".to_string(), TestVariable::Bytes(vec![0x00]));
    vars.insert("OBJ_0_PROP_1".to_string(), TestVariable::Bytes(vec![0x01]));
    // Network parameter test values
    vars.insert("NP_OBJ_TYPE".to_string(), TestVariable::Bytes(vec![0x00, 0x00]));
    vars.insert("NP_PID".to_string(), TestVariable::Bytes(vec![0x01]));
    vars.insert("NP_TEST_INFO".to_string(), TestVariable::Bytes(vec![0x00]));
    vars.insert("NP_VALUE".to_string(), TestVariable::Bytes(vec![0x00]));
    // Device serial number (6 bytes) - device-specific placeholder
    vars.insert("BDUT_SERIAL_NUMBER".to_string(), TestVariable::Bytes(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x01]));
    vars
}

/// Create Group Objects UINT1 test suite from EITT specification
pub fn create_group_objects_uint1_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // Test 1.4.1.1: BDUT sends A_GroupValue_Read (UINT1)
        // ====================================================================
        TestCase {
            name: "1.4.1.1 BDUT sends A_GroupValue_Read (UINT1)".into(),
            steps: vec![
                comment("Testcase 1.4.1.1 BDUT sends A_GroupValue_Read (UINT1)"),
                comment("Preparation: Reset object data and flags."),
                // Clear communication flags
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),
                // Set configuration flags (all enabled)
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DF", 200),
                // Clear data
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 00", 200),
                // Set object to value other than default
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 01", 200),
                comment("Generate read request with different priorities."),
                comment("Note: Priority tests are not applicable for KNX RF implementations."),
                // --------------------------------------------------------
                comment("Low priority"),
                // Set read request in communication flags
                inject("BC #EDI #GO_1_ADDR E1 00 87"),
                // NOTE: Explicit trigger required - our stack doesn't auto-send on flag change
                trigger_read(1), // GO0 = ASAP 1
                comment(
                    "Acceptance: BDUT sends A_GroupValue_Read with low priority and Comm. flags are set accordingly.",
                ),
                // BDUT sends Value Read request (low priority = BC)
                expect("BC #BDUT #GO_0_ADDR E1 00 00", 200),
                // Read communication flags
                inject("BC #EDI #GO_1_ADDR E1 00 00"),
                // Comm flags = idle/OK, read (0x44)
                expect("BC #BDUT #GO_1_ADDR E1 00 44", 200),
                // --------------------------------------------------------
                comment("Normal priority"),
                // Clear data
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 00", 200),
                // Set priority to normal in config flags
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DD", 200),
                // Clear communication flags
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),
                // Set read request
                inject("BC #EDI #GO_1_ADDR E1 00 87"),
                trigger_read(1),
                comment("Acceptance: BDUT sends A_GroupValue_Read with normal priority."),
                // BDUT sends Value Read request (normal priority = B4)
                expect("B4 #BDUT #GO_0_ADDR E1 00 00", 200),
                // --------------------------------------------------------
                comment("Urgent priority"),
                // Set priority to urgent in config flags
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DE", 200),
                // Set read request
                inject("BC #EDI #GO_1_ADDR E1 00 87"),
                trigger_read(1),
                comment("Acceptance: BDUT sends A_GroupValue_Read with urgent priority."),
                // BDUT sends Value Read request (urgent priority = B8)
                expect("B8 #BDUT #GO_0_ADDR E1 00 00", 200),
                // --------------------------------------------------------
                comment("System priority"),
                // Set priority to system in config flags
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DC", 200),
                // Set read request
                inject("BC #EDI #GO_1_ADDR E1 00 87"),
                trigger_read(1),
                comment("Acceptance: BDUT sends A_GroupValue_Read with system priority."),
                // BDUT sends Value Read request (system priority = B0)
                expect("B0 #BDUT #GO_0_ADDR E1 00 00", 200),
                // --------------------------------------------------------
                comment("Check function of Configuration flags."),
                comment("Disable 'communication'"),
                // Disable communication in configuration flags
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DB", 200),
                // Clear communication flags
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),
                // Set read request in communication flags
                inject_delay("BC #EDI #GO_1_ADDR E1 00 87", 200),
                trigger_read(1), // Should fail due to disabled comm flag
                comment("Acceptance: BDUT does not send A_GroupValue_Read."),
                comment("Error flag not necessarily set due to disabled communication flag."),
                // Read communication flags
                inject("BC #EDI #GO_1_ADDR E1 00 00"),
                // Comm flags = idle/error, read (0x45); the template accepts
                // any low nibble here because a device may leave the error
                // flag clear when communication itself is disabled.
                expect("BC #BDUT #GO_1_ADDR E1 00 4?", 200),
                // --------------------------------------------------------
                comment("Disable 'read'"),
                // Disable read in configuration flags
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 D7", 200),
                // Clear communication flags
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),
                // Set read request
                inject("BC #EDI #GO_1_ADDR E1 00 87"),
                trigger_read(1),
                comment("Acceptance: BDUT sends A_GroupValue_Read and Comm. flags are set accordingly."),
                // BDUT sends Value Read request
                expect("BC #BDUT #GO_0_ADDR E1 00 00", 200),
                // Read communication flags
                inject("BC #EDI #GO_1_ADDR E1 00 00"),
                // Comm flags = idle/OK, read (0x44)
                expect("BC #BDUT #GO_1_ADDR E1 00 44", 200),
                // --------------------------------------------------------
                comment("Disable 'write'"),
                // Disable write in configuration flags
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 CF", 200),
                // Clear communication flags
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),
                // Set read request in communication flags
                inject("BC #EDI #GO_1_ADDR E1 00 87"),
                trigger_read(1),
                comment("Acceptance: BDUT sends A_GroupValue_Read and Comm. flags are set accordingly."),
                // BDUT sends Value Read request
                expect("BC #BDUT #GO_0_ADDR E1 00 00", 200),
                // Read communication flags
                inject("BC #EDI #GO_1_ADDR E1 00 00"),
                // Comm flags = idle/OK, read (0x44)
                expect("BC #BDUT #GO_1_ADDR E1 00 44", 200),
                // --------------------------------------------------------
                comment("Disable 'transmission'"),
                // Disable transmission in configuration flags
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 9F", 200),
                // Clear communication flags
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),
                // Set read request
                inject_delay("BC #EDI #GO_1_ADDR E1 00 87", 200),
                trigger_read(1), // Should fail due to disabled transmission flag
                comment("Acceptance: BDUT does not send A_GroupValue_Read."),
                // Read communication flags
                inject("BC #EDI #GO_1_ADDR E1 00 00"),
                // Comm flags = idle/error, read (0x45)
                expect("BC #BDUT #GO_1_ADDR E1 00 45", 200),
                // --------------------------------------------------------
                comment("Disable 'read response update'"),
                // NOTE: Deactivation of read response update flag does not have repercussions in BCU1 model
                // Disable read response update in configuration flags
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 5F", 200),
                // Set read request
                inject("BC #EDI #GO_1_ADDR E1 00 87"),
                trigger_read(1),
                comment("Acceptance: BDUT sends A_GroupValue_Read and Comm. flags are set accordingly."),
                // BDUT sends Value Read request
                expect("BC #BDUT #GO_0_ADDR E1 00 00", 200),
                // Read communication flags
                inject("BC #EDI #GO_1_ADDR E1 00 00"),
                // Comm flags = idle/OK, read (0x44)
                expect("BC #BDUT #GO_1_ADDR E1 00 44", 200),
            ],
            ..Default::default()
        },
        // ====================================================================
        // Test 1.4.1.2: BDUT receives A_GroupValue_Read (UINT1)
        // ====================================================================
        TestCase {
            name: "1.4.1.2 BDUT receives A_GroupValue_Read (UINT1)".into(),
            steps: vec![
                comment("Testcase 1.4.1.2 BDUT receives A_GroupValue_Read (UINT1)"),
                comment("Preparation: Reset object data and flags."),
                // Clear communication flags
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),
                // Set configuration flags (all enabled)
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DF", 200),
                // Clear data
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 00", 200),
                // Set object to value other than default
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 01", 200),
                comment("BDUT receives read requests with different priorities."),
                comment("Note: Priority tests are not applicable for KNX RF implementations."),
                // --------------------------------------------------------
                comment("Low priority"),
                // Read object value (low priority = BC)
                inject("BC #EDI #GO_0_ADDR E1 00 00"),
                comment("Acceptance: BDUT sends A_GroupValue_Response with correct data."),
                // BDUT responds with value 1
                expect("BC #BDUT #GO_0_ADDR E1 00 41", 200),
                // --------------------------------------------------------
                comment("Normal priority"),
                inject("B4 #EDI #GO_0_ADDR E1 00 00"),
                expect("B4 #BDUT #GO_0_ADDR E1 00 41", 200),
                // Urgent priority (no comment in XML)
                inject("B8 #EDI #GO_0_ADDR E1 00 00"),
                expect("B8 #BDUT #GO_0_ADDR E1 00 41", 200),
                // --------------------------------------------------------
                comment("System priority"),
                inject("B0 #EDI #GO_0_ADDR E1 00 00"),
                expect("B0 #BDUT #GO_0_ADDR E1 00 41", 200),
                // --------------------------------------------------------
                comment("BDUT receives read requests with different routing counters."),
                comment("Acceptance: Generate response with correct routing counter setting."),
                // RC=7 (E1) -> response with RC=6
                inject("BC #EDI #GO_0_ADDR E1 00 00"),
                expect("BC #BDUT #GO_0_ADDR E1 00 41", 200),
                // RC=0 (81) -> response with RC=6
                inject("BC #EDI #GO_0_ADDR 81 00 00"),
                expect("BC #BDUT #GO_0_ADDR E1 00 41", 200),
                // RC=7 (F1) -> response with RC=6
                inject("BC #EDI #GO_0_ADDR F1 00 00"),
                expect("BC #BDUT #GO_0_ADDR E1 00 41", 200),
                // --------------------------------------------------------
                comment("Check function of Configuration flags."),
                comment("Disable 'communication'"),
                comment("Acceptance: No response generated."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DB", 200),
                inject_delay("BC #EDI #GO_0_ADDR E1 00 00", 200),
                expect_none(200),
                // --------------------------------------------------------
                comment("Disable 'read'"),
                comment("Acceptance: No response generated."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 D7", 200),
                inject_delay("BC #EDI #GO_0_ADDR E1 00 00", 200),
                expect_none(200),
                // --------------------------------------------------------
                comment("Disable 'write'"),
                comment("Acceptance: Response generated."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 CF", 200),
                inject("BC #EDI #GO_0_ADDR E1 00 00"),
                expect("BC #BDUT #GO_0_ADDR E1 00 41", 200),
                // --------------------------------------------------------
                comment("Disable 'transmission'"),
                comment("Acceptance: Response generated."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 9F", 200),
                inject("BC #EDI #GO_0_ADDR E1 00 00"),
                expect("BC #BDUT #GO_0_ADDR E1 00 41", 200),
                // --------------------------------------------------------
                comment("Disable 'read response update'"),
                comment("Acceptance: Response generated."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 5F", 200),
                inject("BC #EDI #GO_0_ADDR E1 00 00"),
                expect("BC #BDUT #GO_0_ADDR E1 00 41", 200),
            ],
            ..Default::default()
        },
        // ====================================================================
        // Test 1.4.1.3: BDUT sends A_GroupValue_Write (UINT1)
        // ====================================================================
        TestCase {
            name: "1.4.1.3 BDUT sends A_GroupValue_Write (UINT1)".into(),
            steps: vec![
                comment("Testcase 1.4.1.3 BDUT sends A_GroupValue_Write (UINT1)"),
                comment("Preparation: reset object data and flags."),
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200), // clear Comm. flags
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DF", 200), // set Configuration flags
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 00", 200), // clear data
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 01", 200), // set object to value other than default
                comment("Stimulate BDUT to send A_GroupValue_Write with different priorities."),
                comment("Note: Priority tests are not applicable for KNX RF implementations."),
                // --------------------------------------------------------
                comment("Low priority"),
                inject("BC #EDI #GO_1_ADDR E1 00 83"), // set transmit request in communication flags
                // NOTE: Explicit trigger required - our stack doesn't auto-send on flag change
                trigger_write(1), // GO0 = ASAP 1
                comment("Acceptance: BDUT sends message with correct data and Comm. flags are set accordingly."),
                expect("BC #BDUT #GO_0_ADDR E1 00 81", 200), // generated valueWrite
                inject("BC #EDI #GO_1_ADDR E1 00 00"),       // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 40", 200), // Comm.-flags = idle/OK
                // --------------------------------------------------------
                comment("Normal priority"),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DD", 200), // set priority to normal
                inject("BC #EDI #GO_1_ADDR E1 00 83"),               // set transmit request
                trigger_write(1),
                expect("B4 #BDUT #GO_0_ADDR E1 00 81", 200), // generated valueWrite
                // --------------------------------------------------------
                comment("Urgent priority"),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DE", 200), // set priority to urgent
                inject("BC #EDI #GO_1_ADDR E1 00 83"),               // set transmit request
                trigger_write(1),
                expect("B8 #BDUT #GO_0_ADDR E1 00 81", 200), // generated valueWrite
                // --------------------------------------------------------
                comment("System priority"),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DC", 200), // set priority to system
                inject("BC #EDI #GO_1_ADDR E1 00 83"),               // set transmit request
                trigger_write(1),
                expect("B0 #BDUT #GO_0_ADDR E1 00 81", 200), // generated valueWrite
                // --------------------------------------------------------
                comment("Check function of Configuration flags"),
                comment("Disable 'communication'"),
                comment("Acceptance: No telegram generated, check Communication flags."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DB", 200), // disable communication
                inject_delay("BC #EDI #GO_1_ADDR E1 00 83", 200),    // set transmit request
                trigger_write(1),                                    // Should fail due to disabled comm flag
                comment("Error flag not necessarily set due to disabled communication flag."),
                inject("BC #EDI #GO_1_ADDR E1 00 00"), // read communication-flags
                // Comm.-flags = idle/error (BCU 2), transmit request (BCU1);
                // low nibble left open per the template.
                expect("BC #BDUT #GO_1_ADDR E1 00 4?", 200),
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200), // reset Comm. flags
                // --------------------------------------------------------
                comment("Disable 'read'"),
                comment("Acceptance: generate telegram, check Comm. flags."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 D7", 200), // disable read
                inject("BC #EDI #GO_1_ADDR E1 00 83"),               // set transmit request
                trigger_write(1),
                expect("BC #BDUT #GO_0_ADDR E1 00 81", 200), // generated valueWrite
                inject("BC #EDI #GO_1_ADDR E1 00 00"),       // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 40", 200), // Comm.-flags = idle/OK
                // --------------------------------------------------------
                comment("Disable 'write'"),
                comment("Acceptance: generate telegram, check Comm. flags."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 CF", 200), // disable write
                inject("BC #EDI #GO_1_ADDR E1 00 83"),               // set transmit request
                trigger_write(1),
                expect("BC #BDUT #GO_0_ADDR E1 00 81", 200), // generated valueWrite
                inject("BC #EDI #GO_1_ADDR E1 00 00"),       // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 40", 200), // Comm.-flags = idle/OK
                // --------------------------------------------------------
                comment("Disable 'transmission'"),
                comment("Acceptance: no telegram generated, check Comm. flags."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 9F", 200), // disable transmission
                inject_delay("BC #EDI #GO_1_ADDR E1 00 83", 200),    // set transmit request
                trigger_write(1),                                    // Should fail due to disabled transmission flag
                inject("BC #EDI #GO_1_ADDR E1 00 00"),               // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 41", 200),         // Comm.-flags = idle/error
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),    // reset Comm. flags
                // --------------------------------------------------------
                comment("Disable 'read response update'"),
                comment("Acceptance: generate telegram, check Comm. flags."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 5F", 200), // disable read response update
                inject("BC #EDI #GO_1_ADDR E1 00 83"),               // set transmit request
                trigger_write(1),
                expect("BC #BDUT #GO_0_ADDR E1 00 81", 200), // generated valueWrite
                inject("BC #EDI #GO_1_ADDR E1 00 00"),       // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 40", 200), // Comm.-flags = idle/OK
            ],
            ..Default::default()
        },
        // ====================================================================
        // Test 1.4.1.4: BDUT receives A_GroupValue_Write (UINT1)
        // ====================================================================
        TestCase {
            name: "1.4.1.4 BDUT receives A_GroupValue_Write (UINT1)".into(),
            steps: vec![
                comment("Testcase 1.4.1.4 BDUT receives A_GroupValue_Write (UINT1)"),
                comment("Preparation: Reset object data and flags"),
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200), // clear Comm. flags
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DF", 200), // set Configuration flags
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 00", 200), // clear data
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 01", 200), // set object to value other than default
                // --------------------------------------------------------
                comment("BDUT receives telegram"),
                inject_delay("BC #EDI #GO_0_ADDR E1 00 80", 200), // Value Write sent by EITT to BDUT
                comment("Acceptance: Communication flags are set accordingly."),
                inject("BC #EDI #GO_1_ADDR E1 00 00"), // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 48", 200), // Comm.-flags = update flag
                inject("BC #EDI #GO_3_ADDR E1 00 00"), // Value read of object value
                expect("BC #BDUT #GO_3_ADDR E2 00 40 00", 200), // Value Response of BDUT
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200), // clear Comm. flags
                // --------------------------------------------------------
                comment("Check function of Configuration flags."),
                comment("Disable 'communication'"),
                comment("Acceptance: Update flag not set."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DB", 200), // disable comm
                inject_delay("BC #EDI #GO_0_ADDR E1 00 81", 200),    // Value Write sent by EITT
                inject("BC #EDI #GO_1_ADDR E1 00 00"),               // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 40", 200),         // Comm.-flags = update flag not set
                inject("BC #EDI #GO_3_ADDR E1 00 00"),               // Value read of object value
                expect("BC #BDUT #GO_3_ADDR E2 00 40 00", 200),      // Value Response of BDUT
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),    // clear Comm. flags
                // --------------------------------------------------------
                comment("Disable 'read'"),
                comment("Acceptance: Update flag set."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 D7", 200), // disable read
                inject_delay("BC #EDI #GO_0_ADDR E1 00 81", 200),    // Value Write sent by EITT
                inject("BC #EDI #GO_1_ADDR E1 00 00"),               // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 48", 200),         // Comm.-flags = update flag
                inject("BC #EDI #GO_3_ADDR E1 00 00"),               // Value read of object value
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 200),      // Value Response of BDUT
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),    // clear Comm. flags
                // --------------------------------------------------------
                comment("Disable 'write'"),
                comment("Acceptance: Update flag not set."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 CF", 200), // disable write
                inject_delay("BC #EDI #GO_0_ADDR E1 00 80", 200),    // Value Write sent by EITT
                inject("BC #EDI #GO_1_ADDR E1 00 00"),               // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 40", 200),         // Comm.-flags = update flag not set
                inject("BC #EDI #GO_3_ADDR E1 00 00"),               // Value read of object value
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 200),      // Value Response of BDUT
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),    // clear Comm. flags
                // --------------------------------------------------------
                comment("Disable 'transmission'"),
                comment("Acceptance: Update flag set."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 9F", 200), // disable transmission
                inject_delay("BC #EDI #GO_0_ADDR E1 00 80", 200),    // Value Write from EITT
                inject("BC #EDI #GO_1_ADDR E1 00 00"),               // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 48", 200),         // Comm.-flags = update flag
                inject("BC #EDI #GO_3_ADDR E1 00 00"),               // Value read of object value
                expect("BC #BDUT #GO_3_ADDR E2 00 40 00", 200),      // Value Response of BDUT
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),    // clear Comm. flags
                // --------------------------------------------------------
                comment("Disable 'read response update'"),
                comment("Acceptance: Update flag set."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 5F", 200), // disable read response update
                inject_delay("BC #EDI #GO_0_ADDR E1 00 81", 200),    // Value Write sent by EITT
                inject("BC #EDI #GO_1_ADDR E1 00 00"),               // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 48", 200),         // Comm.-flags = update flag
                inject("BC #EDI #GO_3_ADDR E1 00 00"),               // Value read of object value
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 200),      // Value Response of BDUT
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),    // clear Comm. Flags
            ],
            ..Default::default()
        },
        // ====================================================================
        // Test 1.4.1.4a: BDUT receives an invalid data length (UINT1, optional)
        // ====================================================================
        TestCase {
            name: "1.4.1.4a BDUT receives an invalid data length (UINT1, optional)".into(),
            steps: vec![
                comment("Testcase 1.4.1.4a BDUT receives invalid data length (UINT1, optional)"),
                comment(
                    "Purpose of the test is to check whether the group objects implemented in BDUT reject a value write/response addressed to them,",
                ),
                comment("of which the indicated info length does not match their own supported field types."),
                comment("Preparation"),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DF", 200), // set Configuration flags
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 00", 200), // clear object data
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 01", 200), // set object to value other than default value
                // --------------------------------------------------------
                comment("Test"),
                // One octet of payload addressed to the 1-bit GO0: the short
                // encoding carries the value inside the APCI octet, so the
                // extra octet makes the frame one longer than the object.
                inject_delay("BC #EDI #GO_0_ADDR E2 00 80 00", 200), // set object to value larger than size of group object
                comment("Acceptance: The object value is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"), // send Value Read to group object
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 200), // value of group object not updated
            ],
            ..Default::default()
        },
        // ====================================================================
        // Test 1.4.1.5: BDUT receives A_GroupValue_Response (UINT1)
        // ====================================================================
        TestCase {
            name: "1.4.1.5 BDUT receives A_GroupValue_Response (UINT1)".into(),
            steps: vec![
                comment("Testcase 1.4.1.5 BDUT receives A_GroupValue_Response (UINT1)"),
                comment("Preparation: Reset object data and flags."),
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200), // clear Comm. flags
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DF", 200), // set Configuration flags
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 00", 200), // clear data
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 01", 200), // set object to value other than default
                // --------------------------------------------------------
                comment("Disable \"communication\""),
                comment("Acceptance: Update flag not set."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DB", 200), // disable comm in configuration flags
                inject_delay("BC #EDI #GO_0_ADDR E1 00 40", 200),    // ValueResponse by EITT to BDUT
                inject("BC #EDI #GO_1_ADDR E1 00 00"),               // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 40", 200),         // Comm.-flags = update flag not set
                inject("BC #EDI #GO_3_ADDR E1 00 00"),               // Value read of object value
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 200),      // Value Response of BDUT
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),    // clear Comm. flags
                // --------------------------------------------------------
                comment("Disable \"read\""),
                comment("Acceptance: Update flag set."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 D7", 200), // disable read in configuration flags
                inject_delay("BC #EDI #GO_0_ADDR E1 00 40", 200),    // ValueResponse by EITT to BDUT
                inject("BC #EDI #GO_1_ADDR E1 00 00"),               // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 48", 200),         // Comm.-flags = update flag
                inject("BC #EDI #GO_3_ADDR E1 00 00"),               // Value read of object value
                expect("BC #BDUT #GO_3_ADDR E2 00 40 00", 200),      // Value Response of BDUT
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),    // clear Comm. flags
                // --------------------------------------------------------
                comment("Disable \"write\""),
                comment("Acceptance: Update flag set."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 CF", 200), // disable write in configuration flags
                inject_delay("BC #EDI #GO_0_ADDR E1 00 41", 200),    // ValueResponse by EITT to BDUT
                inject("BC #EDI #GO_1_ADDR E1 00 00"),               // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 48", 200),         // Comm.-flags = update flag set
                inject("BC #EDI #GO_3_ADDR E1 00 00"),               // Value read of object value
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 200),      // Value Response of BDUT
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),    // clear Comm. flags
                // --------------------------------------------------------
                comment("Disable \"transmission\""),
                comment("Acceptance: Update flag set."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 9F", 200), // disable transmission in configuration flags
                inject_delay("BC #EDI #GO_0_ADDR E1 00 41", 200),    // ValueResponse by EITT to BDUT
                inject("BC #EDI #GO_1_ADDR E1 00 00"),               // read communication-flags
                expect("BC #BDUT #GO_1_ADDR E1 00 48", 200),         // Comm.-flags = update flag
                inject("BC #EDI #GO_3_ADDR E1 00 00"),               // Value read of object value
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 200),      // Value Response of BDUT
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200),    // clear Comm. flags
                // --------------------------------------------------------
                // The BCU2 branch of the template's alternative: we support
                // deactivation of the update flag, so neither the flag nor
                // the value changes. (A BCU1 device would set the flag and
                // take the new value.)
                comment("Disable \"read response update\" (if possible)"),
                comment("Acceptance: Update flag not set (BCU2)."),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 5F", 200), // disable read response update
                inject_delay("BC #EDI #GO_0_ADDR E1 00 40", 200),    // ValueResponse by EITT to BDUT
                inject("BC #EDI #GO_1_ADDR E1 00 00"),               // read communication-flags
                comment("Next telegram: Update flag not set (BCU2), update flag set (BCU1)."),
                expect("BC #BDUT #GO_1_ADDR E1 00 40", 200), // Update flag not set
                inject("BC #EDI #GO_3_ADDR E1 00 00"),       // Value read of object value
                comment(
                    "The group object value remains unchanged for devices supporting deactivation of the update flag and vice versa.",
                ),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 200), // Value Response of BDUT (value unchanged)
                inject_delay("BC #EDI #GO_1_ADDR E1 00 80", 200), // clear Comm. Flags
            ],
            ..Default::default()
        },
        // ====================================================================
        // Test 1.4.1.6: Checking of Read on Init Flag (UINT1)
        // ====================================================================
        // Restarts the device via A_Restart and verifies that only
        // ROI-flagged objects send GroupValue_Read automatically.
        //
        // GO3 (ASAP 4) and GO4 (ASAP 9) have the ROI flag set; the rest do not.
        TestCase {
            name: "1.4.1.6 Checking of Read on Init Flag (UINT1)".into(),
            steps: vec![
                comment("Testcase 1.4.1.6 Checking of Read on Init Flag (UINT1)"),
                comment("The purpose of this test is to check whether the BDUT correctly sends out"),
                comment("a Group Value Read request for group objects with the read-on-init flag set."),
                comment("GO3 (ASAP 4, addr 2/0/3) and GO4 (ASAP 9, addr 2/0/5) have ROI enabled."),
                comment("GO0-GO2 do not have ROI."),
                // Restore ASAP 1's COT flags, which tests 1.4.1.1-1.4.1.5
                // rewrite through GO2, so the ROI scan after restart only
                // fires for the intended objects.
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DF", 200),
                // Send a basic A_Restart (connectionless) to trigger a reboot.
                inject("BC #EDI #BDUT 61 03 80"),
                // Wait for the child to exit and respawn without draining ROI
                // messages, so subsequent Expect steps can observe them.
                wait_for_restart(10000),
                // The ROI scan processes one object per ~100ms iteration,
                // starting from ASAP 1. ASAP 4 fires around ~400ms, ASAP 9
                // around ~900ms.
                expect("BC #BDUT #GO_3_ADDR E1 00 00", 5000),
                expect("BC #BDUT #GO_4_ADDR E1 00 00", 5000),
                // Verify no further ROI reads fire (non-ROI objects stay quiet).
                expect_none(2000),
            ],
            ..Default::default()
        },
        // ====================================================================
        // Test 1.4.1.7: BDUT receives invalid APCI (UINT1)
        // ====================================================================
        // The template pairs every invalid APCI with an RF-medium variant;
        // those are for an RF BDUT and are left out here.
        TestCase {
            name: "1.4.1.7 BDUT receives invalid APCI (UINT1)".into(),
            steps: vec![
                comment("Testcase 1.4.1.7 BDUT receives invalid APCI (UINT1)"),
                comment("Preparation"),
                inject_delay("BC #EDI #GO_2_ADDR E2 00 80 DF", 500),
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 00", 500),
                inject_delay("BC #EDI #GO_3_ADDR E2 00 80 01", 500),
                comment("Test 1 (optional) - Checking acceptance of Value Read with values higher than 00."),
                inject_delay("BC #EDI #GO_0_ADDR E1 00 3F", 2000),
                comment("Acceptance: No value response may be sent."),
                expect_none(500),
                comment(
                    "Test 2 - Checking acceptance of frames with unsupported APCI's or APCI's not valid for group communication.",
                ),
                comment("Activate programming mode"),
                inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 01"),
                expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 01", 500),
                comment("Test: APCI - IndividualAddress_Write"),
                inject_delay("BC #EDI #GO_0_ADDR E3 00 C0 FF FF", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - IndividualAddress_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E1 01 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - IndividualAddress_Response"),
                inject_delay("BC #EDI #GO_0_ADDR E1 01 40", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Deactivate programming mode"),
                inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 00"),
                expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 500),
                comment("Test: APCI - ADC_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E2 41 81 01", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - ADC_Response"),
                inject_delay("BC #EDI #GO_0_ADDR E4 41 C1 01 FF FF", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - SystemNetworkParameter_Read"),
                inject_delay("B0 #EDI #GO_0_ADDR E6 01 C8 00 00 00 10 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - SystemNetworkParameter_Response"),
                inject_delay("B0 #EDI #GO_0_ADDR E9 01 C9 00 00 00 10 00 00 00 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - SystemNetworkParameter_Write"),
                inject_delay("B0 #EDI #GO_0_ADDR E6 01 CA 00 00 03 30 06", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - Memory_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E3 42 04 #MEM_ACCESSIBLE_START_CC", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - Memory_Response"),
                inject_delay("BC #EDI #GO_0_ADDR E7 42 44 #MEM_ACCESSIBLE_START_CC CA FE BA BE", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - Memory_Write"),
                inject_delay("BC #EDI #GO_0_ADDR E5 42 82 #MEM_ACCESSIBLE_START_CC CA FE", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - MemoryBit_Write"),
                inject_delay("BC #EDI #GO_0_ADDR E6 43 D0 01 #MEM_ACCESSIBLE_START_CC FF FF", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - UserMemory_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E4 42 C0 02 #MEM_ACCESSIBLE_START_AC", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - UserMemory_Response"),
                inject_delay("BC #EDI #GO_0_ADDR E6 42 C1 02 #MEM_ACCESSIBLE_START_AC CA FE", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - UserMemory_Write"),
                inject_delay("BC #EDI #GO_0_ADDR E6 42 C2 02 #MEM_ACCESSIBLE_START_AC CA FE", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - UserMemoryBit_Write"),
                inject_delay("BC #EDI #GO_0_ADDR E6 42 C4 01 #MEM_ACCESSIBLE_START_AC FF FF", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - UserManufacturer_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E1 42 C5", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - UserManufacturer_Response"),
                inject_delay("BC #EDI #GO_0_ADDR E4 42 C6 01 CA FE", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - FunctionPropertyCommand"),
                inject_delay("BC #EDI #GO_0_ADDR E4 42 C7 00 00 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - FunctionPropertyState_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E4 42 C8 00 00 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - FunctionPropertyState_Response"),
                inject_delay("BC #EDI #GO_0_ADDR E5 42 C9 00 00 00 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - DeviceDescriptor_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E1 43 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - DeviceDescriptor_Response"),
                inject_delay("BC #EDI #GO_0_ADDR E3 43 40 07 B0", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - Restart"),
                inject_delay("BC #EDI #GO_0_ADDR E1 43 80", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - Authorize_Request"),
                inject_delay("BC #EDI #GO_0_ADDR E6 43 D1 00 12 34 56 78", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - Authorize_Response"),
                inject_delay("BC #EDI #GO_0_ADDR E2 43 D2 01", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - Key_Write"),
                inject_delay("BC #EDI #GO_0_ADDR E6 43 D3 00 CA FE BA BE", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - Key_Response"),
                inject_delay("BC #EDI #GO_0_ADDR E2 43 D4 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - PropertyValue_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E5 43 D5 #OBJ_0_ID #OBJ_0_PROP_1 10 01", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - PropertyValue_Response"),
                inject_delay("BC #EDI #GO_0_ADDR E6 43 D6 #OBJ_0_ID #OBJ_0_PROP_1 10 01 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - PropertyValue_Write"),
                inject_delay("BC #EDI #GO_0_ADDR E6 43 D7 #OBJ_0_ID #OBJ_0_PROP_1 10 01 FF", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - PropertyDescription_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E4 43 D8 #OBJ_0_ID #OBJ_0_PROP_1 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - PropertyDescription_Response"),
                inject_delay("BC #EDI #GO_0_ADDR E8 43 D9 #OBJ_0_ID #OBJ_0_PROP_1 01 81 00 07 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - NetworkParameter_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E5 43 DA #NP_OBJ_TYPE #NP_PID #NP_TEST_INFO", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - NetworkParameter_Response"),
                inject_delay("BC #EDI #GO_0_ADDR E6 43 DB #NP_OBJ_TYPE #NP_PID #NP_TEST_INFO #NP_VALUE", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - NetworkParameter_Write"),
                inject_delay("BC #EDI #GO_0_ADDR E6 43 E4 #NP_OBJ_TYPE #NP_PID #NP_TEST_INFO #NP_VALUE", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - IndividualAddressSerialNumber_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E7 43 DC #BDUT_SERIAL_NUMBER", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - IndividualAddressSerialNumber_Response"),
                inject_delay("BC #EDI #GO_0_ADDR EB 43 DD #BDUT_SERIAL_NUMBER 00 00 00 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - IndividualAddressSerialNumber_Write"),
                inject_delay("BC #EDI #GO_0_ADDR ED 43 DE #BDUT_SERIAL_NUMBER CA FE 00 00 00 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Activate programming mode"),
                inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 01"),
                expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 01", 500),
                comment("Test: APCI - DomainAddress_Write (2 octet DoA)"),
                inject_delay("BC #EDI #GO_0_ADDR E3 43 E0 00 01", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - DomainAddress_Write (6 octet DoA)"),
                inject_delay("BC #EDI #GO_0_ADDR E7 43 E0 00 00 00 00 00 01", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - DomainAddress_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E1 43 E1", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Deactivate programming mode"),
                inject("BC #EDI #BDUT 66 03 D7 00 36 10 01 00"),
                expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 500),
                comment("Test: APCI - DomainAddress_Response (2 octet DoA)"),
                inject_delay("BC #EDI #GO_0_ADDR E3 43 E2 00 01", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - DomainAddress_Response (6 octet DoA)"),
                inject_delay("BC #EDI #GO_0_ADDR E7 43 E2 00 00 00 00 00 01", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - Link_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E3 43 E5 01 01", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - Link_Response"),
                inject_delay("BC #EDI #GO_0_ADDR E5 43 E6 01 11 09 01", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - Link_Write"),
                inject_delay("BC #EDI #GO_0_ADDR E5 43 E7 01 00 79 7F", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - DomainAddressSerialNumber_Read"),
                inject_delay("BC #EDI #GO_0_ADDR E7 43 EC #BDUT_SERIAL_NUMBER", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - DomainAddressSerialNumber_Response (2 octet DoA)"),
                inject_delay("BC #EDI #GO_0_ADDR E9 43 ED #BDUT_SERIAL_NUMBER 00 01", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - DomainAddressSerialNumber_Response (6 octet DoA)"),
                inject_delay("BC #EDI #GO_0_ADDR ED 43 ED #BDUT_SERIAL_NUMBER 00 00 00 00 00 01", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - DomainAddressSerialNumber_Write (2 octet DoA)"),
                inject_delay("BC #EDI #GO_0_ADDR E9 43 EE #BDUT_SERIAL_NUMBER 00 01", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - DomainAddressSerialNumber_Write (6 octet DoA)"),
                inject_delay("BC #EDI #GO_0_ADDR ED 43 EE #BDUT_SERIAL_NUMBER 00 00 00 00 00 01", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
                comment("Test: APCI - FileStream_InfoReport"),
                inject_delay("BC #EDI #GO_0_ADDR E3 43 F0 00 00", 2000),
                comment("Acceptance: No value response may be sent and value of object is not updated."),
                inject("BC #EDI #GO_3_ADDR E1 00 00"),
                expect("BC #BDUT #GO_3_ADDR E2 00 40 01", 500),
            ],
            ..Default::default()
        },
    ];

    TestSuite::new("Group Objects UINT1 Tests", vars).with_cases(cases)
}

// ============================================================================
// 5.2 Association Table Structure Tests
// ============================================================================

/// Create test variables for Association Table structure tests
///
/// Based on the EITT specification:
/// - GA_1: Group address for 1-to-1 and 1-to-n testing (09 00)
/// - GA_2: Group address for n-to-1 testing (09 01)
/// - GA_3: Group address for status information (09 02)
fn create_association_table_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    vars.insert("EDI".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("BDUT".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    // Group addresses for association table testing
    vars.insert("GA_1".to_string(), TestVariable::Bytes(vec![0x09, 0x00])); // 1/1/0
    vars.insert("GA_2".to_string(), TestVariable::Bytes(vec![0x09, 0x01])); // 1/1/1
    vars.insert("GA_3".to_string(), TestVariable::Bytes(vec![0x09, 0x02])); // 1/1/2 (status)
    vars
}

/// Creates the 5.2.1 Server Tests - Receiving telegrams suite
///
/// Tests the structure of the Association Table when receiving telegrams.
/// Tests 1-to-1, 1-to-n, n-to-1, and n-to-n relations between group addresses
/// and group objects.
///
/// # Test Setup Requirements
///
/// The BDUT must be configured with:
/// - **Test 1 (1-to-1)**: One group address linked to one 1-bit group object,
///   with a status object linked to GA_3
/// - **Test 2 (1-to-n)**: One group address linked to two 1-bit group objects,
///   both with status objects linked to GA_3
/// - **Test 3 (n-to-1)**: Two group addresses (GA_1, GA_2) each linked to a
///   different 1-bit group object, with status objects linked to GA_3
/// - **Test 4 (n-to-n)**: Multiple group addresses linked to multiple objects,
///   with status objects linked to GA_3
pub fn create_association_table_receiving_suite() -> TestSuite {
    let vars = create_association_table_test_variables();

    let cases = vec![
        // ====================================================================
        // 5.2.1 Test 1 - 1 to 1 relation (1-bit)
        // ====================================================================
        TestCase::new("5.2.1 Test 1 - 1 to 1 relation (1-bit)").with_steps(vec![
            comment("Testcase 5.2.1 Test 1 - 1 to 1 relation (1-bit)"),
            comment("Please configure the BDUT with a Group Address that is linked to a single 1-bit DPT (Group Object)."),
            comment("The tested object shall have a status object that is linked to a Group Address for status information."),
            // Write value 1 to GA_1
            inject("BC #EDI #GA_1 E1 00 81"),
            // Expect status update on GA_3 with value 1
            expect("BC #BDUT #GA_3 E1 00 81", 200),
            // Write value 0 to GA_1
            inject("BC #EDI #GA_1 E1 00 80"),
            // Expect status update on GA_3 with value 0
            expect("BC #BDUT #GA_3 E1 00 80", 200),
            comment("Acceptance: verify if the returned status value has changed according to the written values."),
            comment("================================================================================"),
        ]),

        // ====================================================================
        // 5.2.1 Test 2 - 1 to n relation (1-bit)
        // ====================================================================
        TestCase::new("5.2.1 Test 2 - 1 to n relation (1-bit)").with_steps(vec![
            comment("Testcase 5.2.1 Test 2 - 1 to n relation (1-bit)"),
            comment("Please configure the BDUT with a Group Address is linked to two 1-bit DPTs (Group Objects)."),
            comment("The tested objects shall have status objects that are linked to a single Group Address for status information."),
            // Write value 1 to GA_1
            inject("BC #EDI #GA_1 E1 00 81"),
            // Expect two status updates on GA_3 (one for each linked object)
            expect("BC #BDUT #GA_3 E1 00 81", 200),
            expect("BC #BDUT #GA_3 E1 00 81", 400),
            // Write value 0 to GA_1
            inject("BC #EDI #GA_1 E1 00 80"),
            // Expect two status updates on GA_3
            expect("BC #BDUT #GA_3 E1 00 80", 200),
            expect("BC #BDUT #GA_3 E1 00 80", 400),
            comment("Acceptance: verify if the returned status values have changed according to the written values."),
            comment("================================================================================"),
        ]),

        // ====================================================================
        // 5.2.1 Test 3 - n to 1 relation (1-bit)
        // ====================================================================
        TestCase::new("5.2.1 Test 3 - n to 1 relation (1-bit)").with_steps(vec![
            comment("Testcase 5.2.1 Test 3 - n to 1 relation (1-bit)"),
            comment("Please configure the BDUT with two Group Addresses that each link to a single, but different, 1-bit DPT (Group Object)."),
            comment("The tested objects shall have status objects that are linked to a single Group Address for status information."),
            // Write value 1 to GA_1
            inject("BC #EDI #GA_1 E1 00 81"),
            expect("BC #BDUT #GA_3 E1 00 81", 200),
            // Write value 0 to GA_1
            inject("BC #EDI #GA_1 E1 00 80"),
            expect("BC #BDUT #GA_3 E1 00 80", 200),
            // Write value 1 to GA_2
            inject("BC #EDI #GA_2 E1 00 81"),
            expect("BC #BDUT #GA_3 E1 00 81", 200),
            // Write value 0 to GA_2
            inject("BC #EDI #GA_2 E1 00 80"),
            expect("BC #BDUT #GA_3 E1 00 80", 200),
            comment("Acceptance: verify if the returned status value has changed according to the written values."),
            comment("================================================================================"),
        ]),

        // ====================================================================
        // 5.2.1 Test 4 - n to n relation (1-bit)
        // ====================================================================
        TestCase::new("5.2.1 Test 4 - n to n relation (1-bit)").with_steps(vec![
            comment("Testcase 5.2.1 Test 4 - n to n relation (1-bit)"),
            comment("Please configure the BDUT with a Group Address is linked to at least two 1-bit DPTs (Group Objects)."),
            comment("The tested objects shall have status objects that are linked to a single Group Address for status information."),
            // Write value 1 to GA_1 (linked to multiple objects)
            inject("BC #EDI #GA_1 E1 00 81"),
            expect("BC #BDUT #GA_3 E1 00 81", 200),
            expect("BC #BDUT #GA_3 E1 00 81", 400),
            // Write value 0 to GA_1
            inject("BC #EDI #GA_1 E1 00 80"),
            expect("BC #BDUT #GA_3 E1 00 80", 200),
            expect("BC #BDUT #GA_3 E1 00 80", 400),
            // Write value 1 to GA_2 (also linked to multiple objects)
            inject("BC #EDI #GA_2 E1 00 81"),
            expect("BC #BDUT #GA_3 E1 00 81", 200),
            expect("BC #BDUT #GA_3 E1 00 81", 400),
            // Write value 0 to GA_2
            inject("BC #EDI #GA_2 E1 00 80"),
            expect("BC #BDUT #GA_3 E1 00 80", 200),
            expect("BC #BDUT #GA_3 E1 00 80", 400),
            comment("Acceptance: verify if the returned status values have changed according to the written values."),
            comment("================================================================================"),
        ]),
    ];

    TestSuite::new("5.2.1 Server Tests - Receiving telegrams", vars).with_cases(cases)
}

/// Creates the 5.2.2 Server Tests - Sending telegrams suite
///
/// Tests the structure of the Association Table when sending telegrams.
/// Requires manual stimulation of the BDUT to trigger sends.
///
/// # Test Setup Requirements
///
/// - Tests require manual stimulation of the BDUT (e.g., button press, sensor input)
/// - Each test expects the tester to stimulate the object twice within 20 seconds
/// - Status objects should be linked to GA_3
///
/// Note: These tests have very long timeouts (20 seconds) because they wait
/// for manual stimulation of the device.
pub fn create_association_table_sending_suite() -> TestSuite {
    let vars = create_association_table_test_variables();

    let cases = vec![
        // ====================================================================
        // 5.2.2 Test 1 - 1 to 1 relation (1-bit)
        // ====================================================================
        TestCase::new("5.2.2 Test 1 - 1 to 1 relation (1-bit)").with_steps(vec![
            comment("Testcase 5.2.2 Test 1 - 1 to 1 relation (1-bit)"),
            comment("Please configure the BDUT with a Group Address that is linked to a single 1-bit DPT (Group Object)."),
            comment("Stimulate the object on the server side: twice and within 20 seconds)."),
            // Expect status message with value 1
            expect("BC #BDUT #GA_3 E1 00 81", 20000),
            // Expect status message with value 0
            expect("BC #BDUT #GA_3 E1 00 80", 20000),
            comment("Acceptance: verify if the returned status value has changed according to the stimuli."),
            comment("================================================================================"),
        ]),

        // ====================================================================
        // 5.2.2 Test 2 - 1 to n relation (1-bit)
        // ====================================================================
        TestCase::new("5.2.2 Test 2 - 1 to n relation (1-bit)").with_steps(vec![
            comment("Testcase 5.2.2 Test 2 - 1 to n relation (1-bit)"),
            comment("Please configure the BDUT with a Group Address is linked to two 1-bit DPTs (Group Objects)."),
            comment("Stimulate both objects on the server side: each object once and within 20 seconds."),
            // Expect two status messages with value 1 (one per object)
            expect("BC #BDUT #GA_3 E1 00 81", 20000),
            expect("BC #BDUT #GA_3 E1 00 81", 20000),
            // Expect two status messages with value 0 (one per object)
            expect("BC #BDUT #GA_3 E1 00 80", 20000),
            expect("BC #BDUT #GA_3 E1 00 80", 20000),
            comment("Acceptance: verify if two telegrams have been sent. One telegram for each Group Address with values according to the stimuli."),
            comment("================================================================================"),
        ]),

        // ====================================================================
        // 5.2.2 Test 3 - n to 1 relation (1-bit)
        // ====================================================================
        TestCase::new("5.2.2 Test 3 - n to 1 relation (1-bit)").with_steps(vec![
            comment("Testcase 5.2.2 Test 3 - n to 1 relation (1-bit)"),
            comment("Please configure the BDUT with two Group Addresses that each link to a single 1-bit DPT (Group Object)."),
            comment("Stimulate the object on the server side: twice and within 20 seconds)."),
            // Expect status message with value 1
            expect("BC #BDUT #GA_3 E1 00 81", 20000),
            // Expect status message with value 0
            expect("BC #BDUT #GA_3 E1 00 80", 20000),
            comment("Acceptance: verify if two telegrams have been sent with the same destination Group Address. The values are according to the stimuli AND no telegram shall have been sent to the second Group Address."),
            comment("================================================================================"),
        ]),
    ];

    TestSuite::new("5.2.2 Server Tests - Sending telegrams", vars).with_cases(cases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variables_created() {
        let vars = create_test_variables();
        // Base variables
        assert_eq!(vars["EDI"].as_bytes(), &[0xAF, 0xFE]);
        assert_eq!(vars["BDUT"].as_bytes(), &[0x10, 0x01]);
        // UINT1 object addresses (2/0/x)
        assert_eq!(vars["GO_0_ADDR"].as_bytes(), &[0x10, 0x00]); // 2/0/0
        assert_eq!(vars["GO_1_ADDR"].as_bytes(), &[0x10, 0x01]); // 2/0/1
        assert_eq!(vars["GO_2_ADDR"].as_bytes(), &[0x10, 0x02]); // 2/0/2
        assert_eq!(vars["GO_3_ADDR"].as_bytes(), &[0x10, 0x03]); // 2/0/3
        assert_eq!(vars["GO_4_ADDR"].as_bytes(), &[0x10, 0x05]); // 2/0/5
    }

    #[test]
    fn test_suite_created() {
        let suite = create_group_objects_uint1_suite();
        assert_eq!(suite.name, "Group Objects UINT1 Tests");
        assert_eq!(suite.cases.len(), 8);
        assert_eq!(suite.cases[0].name, "1.4.1.1 BDUT sends A_GroupValue_Read (UINT1)");
        assert_eq!(suite.cases[1].name, "1.4.1.2 BDUT receives A_GroupValue_Read (UINT1)");
        assert_eq!(suite.cases[2].name, "1.4.1.3 BDUT sends A_GroupValue_Write (UINT1)");
        assert_eq!(suite.cases[3].name, "1.4.1.4 BDUT receives A_GroupValue_Write (UINT1)");
        assert_eq!(suite.cases[4].name, "1.4.1.4a BDUT receives an invalid data length (UINT1, optional)");
        assert_eq!(suite.cases[5].name, "1.4.1.5 BDUT receives A_GroupValue_Response (UINT1)");
        assert_eq!(suite.cases[6].name, "1.4.1.6 Checking of Read on Init Flag (UINT1)");
        assert_eq!(suite.cases[7].name, "1.4.1.7 BDUT receives invalid APCI (UINT1)");
    }
}
