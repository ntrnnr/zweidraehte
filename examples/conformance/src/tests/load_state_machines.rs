//! Load State Machines Conformance Tests
//!
//! Tests based on KNX v2.1.1, Volume 08 TSSG System Conformance Testing - Load State Machines Tests
//! Reference: v01.02.01 AS
//!
//! These tests verify correct handling of:
//! - Load state machine transitions (UNLOADED, LOADING, LOADED, ERROR)
//! - Load events (START_LOADING, LOAD_COMPLETED, LOAD_SEGMENT, UNLOAD, etc.)
//! - PropertyValue_Write for load control
//! - Authorization requirements for load operations
//!
//! NOTE: The original XML specification has incorrect sequence numbers in many tests.
//! The transport layer increments recv_seq after ANY valid T_Data frame, regardless
//! of application layer semantics. We use correct incrementing sequence numbers here.
//! Also, we changed the tests to use RelativeData (0x0b) segment type for LOAD_SEGMENT

use std::collections::BTreeMap;

use super::helpers::{comment, expect, inject, inject_delay};
use crate::{TestCase, TestSuite, TestVariable};

/// Create test variables for load state machine tests
///
/// Based on the EITT specification:
/// - EDI: External Device Interface (10.15.254 = AF FE)
/// - BDUT: Basic Device Under Test (1.0.1 = 10 01)
/// - TEST_OBJ_INDEX: Object index under test (default: 02 = Association Table)
/// - LEV_0_KEY: Authorization key for level 0 (default: AA AA AA AA)
pub fn create_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    vars.insert("EDI".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("BDUT".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    vars.insert("TEST_OBJ_INDEX".to_string(), TestVariable::Bytes(vec![0x02]));
    // Default key for level 0 - matches the stack's initial key configuration
    vars.insert("LEV_0_KEY".to_string(), TestVariable::Bytes(vec![0xFF, 0xFF, 0xFF, 0xFF]));
    // Non-default key used by L-2.6 to test access denial
    vars.insert("LEV_0_KEY_NONDEFAULT".to_string(), TestVariable::Bytes(vec![0xAA, 0xAA, 0xAA, 0xAA]));
    vars
}

// ============================================================================
// L-2.1 Test Preparation
// ============================================================================

/// Create test preparation suite
///
/// This prepares the device for load state machine testing by:
/// 1. Connecting to the device
/// 2. Authorizing with level 0 key
/// 3. Unloading the test object
pub fn create_preparation_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        TestCase::new("L-2.1 Test Preparation").with_steps(vec![
            comment("Testcase 2.1 Test Preparation"),
            comment("Test Setup "),
            comment("Assumed Memory Model: Address 0x4000 to 0xBFFF"),
            comment("Will be unloaded / loaded by this test"),
            comment("Settings of keys:"),
            comment("Key for level 0: 0xAA, 0xAA, 0xAA, 0xAA"),
            comment("Preparation: Unload complete device (Address table, association table and application object, PEI program)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send a LOAD_EVENT_UNLOAD to test object"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("BDUT is now ready for test"),
            comment("================================================================================"),
        ]),
    ];

    TestSuite::new("L-2.1 Test Preparation", vars).with_cases(cases)
}

// ============================================================================
// L-2.2 Tests with initial state LOAD_STATE_UNLOADED
// ============================================================================

/// Create tests for LOAD_STATE_UNLOADED initial state
pub fn create_unloaded_state_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // L-2.2.1 Event: NO OPERATION and unknown Load event
        // ====================================================================
        TestCase::new("L-2.2.1 Event: NO OPERATION and unknown Load event").with_steps(vec![
            comment("Testcase 2.2.1 Event: NO OPERATION and unknown Load event"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Now test object is unloaded"),
            comment("Send to association table object a LOAD_EVENT_NO OPERATION"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 00 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to association table object an unknown LOAD_EVENT"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 05 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.2.2 Event: LOAD_EVENT_START LOADING
        // ====================================================================
        TestCase::new("L-2.2.2 Event: LOAD_EVENT_START LOADING").with_steps(vec![
            comment("Testcase 2.2.2 Event: LOAD_EVENT_START LOADING"),
            comment("Preparation"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Now test object is unloaded"),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            // LOAD_STATE_LOADING = 02
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.2.3 Event: LOAD_EVENT_LOAD COMPLETED
        // ====================================================================
        TestCase::new("L-2.2.3 Event: LOAD_EVENT_LOAD COMPLETED").with_steps(vec![
            comment("Testcase 2.2.3 Event: LOAD_EVENT_LOAD COMPLETED"),
            comment("Preparation"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Now test object is unloaded"),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("Acceptance: BDUT remains in load state LOAD_STATE_UNLOADED, alternatively ERROR"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            // Should remain UNLOADED (00) or go to ERROR (03)
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.2.4 Event: LOAD_SEGMENT
        // ====================================================================
        TestCase::new("L-2.2.4 Event: LOAD_SEGMENT").with_steps(vec![
            comment("Testcase 2.2.4 Event: LOAD_SEGMENT"),
            comment("Preparation"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Now test object is unloaded"),
            comment("Send to association table object a LOAD_SEGMENT"),
            comment("Acceptance: BDUT remains in load state LOAD_STATE_UNLOADED, alternatively ERROR"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 03 00 01 1A 00 7A 33 03 80 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            // Should remain UNLOADED (00) or go to ERROR (03)
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.2.5 Event: UNLOAD
        // ====================================================================
        TestCase::new("L-2.2.5 Event: UNLOAD").with_steps(vec![
            comment("Testcase 2.2.5 Event: UNLOAD"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Now test object is unloaded"),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.2.6 Event: DEVICE RESTART
        // ====================================================================
        TestCase::new("L-2.2.6 Event: DEVICE RESTART").with_steps(vec![
            comment("Testcase 2.2.6 Event: DEVICE RESTART"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Now test object is unloaded"),
            comment("Send a device restart to BDUT"),
            // A_Restart - basic restart (seq 2)
            inject("BC #EDI #BDUT 61 4B 80"),
            // Stack ACKs the restart before processing it
            expect("B0 #BDUT #EDI 60 CA", 0),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Acceptance: Connection breaks down, load state remains UNLOADED"),
            comment("Reconnect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read load state of association table"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            // PropertyValue_Read for PID_LOAD_STATE_CONTROL
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_INDEX 05 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
    ];

    TestSuite::new("L-2.2 Tests with initial state LOAD_STATE_UNLOADED", vars).with_cases(cases)
}

// ============================================================================
// L-2.3 Tests with initial state LOAD_STATE_LOADED
// ============================================================================

/// Create tests for LOAD_STATE_LOADED initial state
///
/// These tests require a complete loading sequence first to get the device
/// into the LOADED state.
///
/// We use RelativeData (0x0b) segment type with MCB format:
/// - 4 bytes: requested memory size (big-endian)
/// - 1 byte: mode (bit 0 = fill memory)
/// - 1 byte: fill value
/// - 2 bytes: CRC (ignored during allocation)
///
/// Example: 03 0b 00 00 00 10 01 00 00 00
///   - 03 = LOAD_SEGMENT event
///   - 0b = RelativeData segment type
///   - 00 00 00 10 = 16 bytes requested
///   - 01 = fill mode enabled
///   - 00 = fill value
///   - 00 00 = CRC (ignored)
pub fn create_loaded_state_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // L-2.3.1 Event: NO OPERATION and unknown load event
        // ====================================================================
        TestCase::new("L-2.3.1 Event: NO OPERATION and unknown load event").with_steps(vec![
            comment("Testcase 2.3.1 Event: NO OPERATION and unknown load event"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to association table object a LOAD_SEGMENT (RelativeData allocation)"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 03 0b 00 00 00 10 01 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Now test object is loaded"),
            comment("Send to association table object a LOAD_EVENT_NO OPERATION"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_INDEX 05 10 01 00 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Send to association table object an unknown LOAD_EVENT"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 5B D7 #TEST_OBJ_INDEX 05 10 01 05 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 DA", 0),
            expect("BC #BDUT #EDI 66 5B D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 DA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.3.2 Event: START LOADING
        // ====================================================================
        TestCase::new("L-2.3.2 Event: START LOADING").with_steps(vec![
            comment("Testcase 2.3.2 Event: START LOADING"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to association table object a LOAD_SEGMENT (RelativeData allocation)"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 03 0b 00 00 00 10 01 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Now test object is loaded"),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.3.3 Event: LOAD COMPLETED
        // ====================================================================
        TestCase::new("L-2.3.3 Event: LOAD COMPLETED").with_steps(vec![
            comment("Testcase 2.3.3 Event: LOAD COMPLETED"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to association table object a LOAD_SEGMENT (RelativeData allocation)"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 03 0b 00 00 00 10 01 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Now test object is loaded"),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("Acceptance: BDUT remains in load state LOAD_STATE_LOADED, alternatively ERROR"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.3.4 Event: LOAD SEGMENT
        // ====================================================================
        TestCase::new("L-2.3.4 Event: LOAD SEGMENT").with_steps(vec![
            comment("Testcase 2.3.4 Event: LOAD SEGMENT"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to association table object a LOAD_SEGMENT (RelativeData allocation)"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 03 0b 00 00 00 10 01 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Now test object is loaded"),
            comment("Send to association table object a LOAD_SEGMENT"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_ERROR"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_INDEX 05 10 01 03 0b 00 00 00 10 01 00 00 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_INDEX 05 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.3.5 Event: UNLOAD
        // ====================================================================
        TestCase::new("L-2.3.5 Event: UNLOAD").with_steps(vec![
            comment("Testcase 2.3.5 Event: UNLOAD"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to association table object a LOAD_SEGMENT (RelativeData allocation)"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 03 0b 00 00 00 10 01 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Now test object is loaded"),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.3.6 Event: DEVICE RESTART
        // ====================================================================
        TestCase::new("L-2.3.6 Event: DEVICE RESTART").with_steps(vec![
            comment("Testcase 2.3.6 Event: DEVICE RESTART"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to association table object a LOAD_SEGMENT (RelativeData allocation)"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 03 0b 00 00 00 10 01 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Now test object is loaded"),
            comment("Send a device restart to BDUT"),
            inject("BC #EDI #BDUT 61 57 80"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("T-ACK is optional. It is depending on the device architecture."),
            comment("Acceptance: Connection breaks down, load state remains LOADED"),
            comment("Reconnect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 5000),
            comment("Read load state of association table"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_INDEX 05 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
    ];

    TestSuite::new("L-2.3 Tests with initial state LOAD_STATE_LOADED", vars).with_cases(cases)
}

// ============================================================================
// L-2.4 Tests with initial state LOAD_STATE_LOADING
// ============================================================================

/// Create tests for LOAD_STATE_LOADING initial state
///
/// These tests first put the device into LOADING state (UNLOAD → START_LOADING),
/// then test various events from that state.
pub fn create_loading_state_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // L-2.4.1 Event: NO OPERATION and unknown load event
        // ====================================================================
        TestCase::new("L-2.4.1 Event: NO OPERATION and unknown Load event").with_steps(vec![
            comment("Testcase 2.4.1 Event: NO OPERATION and unknown Load event"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Now test object is loading"),
            comment("Send to association table object a LOAD_EVENT_NO OPERATION"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 00 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to association table object an unknown LOAD_EVENT"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_INDEX 05 10 01 05 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.4.2 Event: START LOADING
        // ====================================================================
        TestCase::new("L-2.4.2 Event: START LOADING").with_steps(vec![
            comment("Testcase 2.4.2 Event: START LOADING"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Now test object is loading"),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.4.3 Event: LOAD COMPLETED
        // ====================================================================
        TestCase::new("L-2.4.3 Event: LOAD COMPLETED").with_steps(vec![
            comment("Testcase 2.4.3 Event: LOAD COMPLETED"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Now test object is loading"),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("Acceptance: BDUT returns theload state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.4.4 Event: LOAD SEGMENT
        // ====================================================================
        TestCase::new("L-2.4.4 Event: LOAD SEGMENT").with_steps(vec![
            comment("Testcase 2.4.4 Event: LOAD SEGMENT"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Now test object is loading"),
            comment("Send to association table object a LOAD_SEGMENT (RelativeData allocation)"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 03 0b 00 00 00 10 01 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.4.5 Event: UNLOAD
        // ====================================================================
        TestCase::new("L-2.4.5 Event: UNLOAD").with_steps(vec![
            comment("Testcase 2.4.5 Event: UNLOAD"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Now test object is loading"),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.4.6 Event: DEVICE RESTART
        // ====================================================================
        TestCase::new("L-2.4.6 Event: DEVICE RESTART").with_steps(vec![
            comment("Testcase 2.4.6 Event: DEVICE RESTART"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Now test object is loading"),
            comment("Send a device restart to BDUT"),
            inject("BC #EDI #BDUT 61 4F 80"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("T-ACK is optional. It is depending on the device architecture."),
            comment("Acceptance: Connection breaks down, load state remains in loading"),
            comment("Reconnect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 5000),
            comment("Read load state of association table"),
            comment("BDUT returns load state LOAD_STATE_LOADING, optional ERROR"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_INDEX 05 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
    ];

    TestSuite::new("L-2.4 Tests with initial state LOAD_STATE_LOADING", vars).with_cases(cases)
}

// ============================================================================
// L-2.5 Tests with initial state LOAD_STATE_ERROR
// ============================================================================

/// Create tests for LOAD_STATE_ERROR initial state
///
/// These tests first put the device into ERROR state by:
/// 1. UNLOAD → UNLOADED
/// 2. START_LOADING → LOADING
/// 3. LOAD_COMPLETED → LOADED
/// 4. LOAD_SEGMENT with invalid segment type (0x02 Segment control record) → ERROR
///
/// Then test various events from the ERROR state.
pub fn create_error_state_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // L-2.5.1 Event: NO OPERATION and unknown load event
        // ====================================================================
        TestCase::new("L-2.5.1 Event: NO OPERATION and unknown load event").with_steps(vec![
            comment("Testcase 2.5.1 Event: NO OPERATION and unknown load event"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to association table object a LOAD_SEGMENT (Segment control record)"),
            comment("BDUT returns load state LOAD_STATE_ERROR"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_INDEX 05 10 01 03 02 40 30 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_INDEX 05 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Now test object is in state ERROR"),
            comment("Send to association table object a LOAD_EVENT_NO OPERATION"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_ERROR"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_INDEX 05 10 01 00 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_INDEX 05 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Send to association table object an unknown LOAD_EVENT"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_ERROR"),
            inject("BC #EDI #BDUT 6F 5B D7 #TEST_OBJ_INDEX 05 10 01 05 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 DA", 0),
            expect("BC #BDUT #EDI 66 5B D6 #TEST_OBJ_INDEX 05 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 DA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.5.2 Event: START LOADING
        // ====================================================================
        TestCase::new("L-2.5.2 Event: START LOADING").with_steps(vec![
            comment("Testcase 2.5.2 Event: START LOADING"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to association table object a LOAD_SEGMENT (Segment control record)"),
            comment("BDUT returns load state LOAD_STATE_ERROR"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_INDEX 05 10 01 03 02 40 30 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_INDEX 05 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Now test object is in state ERROR"),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_ERROR"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_INDEX 05 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.5.3 Event: LOAD COMPLETED
        // ====================================================================
        TestCase::new("L-2.5.3 Event: LOAD COMPLETED").with_steps(vec![
            comment("Testcase 2.5.3 Event: LOAD COMPLETED"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to association table object a LOAD_SEGMENT (Segment control record)"),
            comment("BDUT returns load state LOAD_STATE_ERROR"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_INDEX 05 10 01 03 02 40 30 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_INDEX 05 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Now test object is in state ERROR"),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("Acceptance: BDUT remains in load state LOAD_STATE_ERROR"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_INDEX 05 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.5.4 Event: LOAD SEGMENT
        // ====================================================================
        TestCase::new("L-2.5.4 Event: LOAD SEGMENT").with_steps(vec![
            comment("Testcase 2.5.4 Event: LOAD SEGMENT"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to association table object a LOAD_SEGMENT (Segment control record)"),
            comment("BDUT returns load state LOAD_STATE_ERROR"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_INDEX 05 10 01 03 02 40 30 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_INDEX 05 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Now test object is in state ERROR"),
            comment("Send to association table object a LOAD_SEGMENT (Segment control record)"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_ERROR"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_INDEX 05 10 01 03 02 40 30 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_INDEX 05 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.5.5 Event: UNLOAD
        // ====================================================================
        TestCase::new("L-2.5.5 Event: UNLOAD").with_steps(vec![
            comment("Testcase 2.5.5 Event: UNLOAD"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to association table object a LOAD_SEGMENT (Segment control record)"),
            comment("BDUT returns load state LOAD_STATE_ERROR"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_INDEX 05 10 01 03 02 40 30 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_INDEX 05 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Now test object is in state ERROR"),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("Acceptance: BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // L-2.5.6 Event: DEVICE RESTART
        // ====================================================================
        TestCase::new("L-2.5.6 Event: DEVICE RESTART").with_steps(vec![
            comment("Testcase 2.5.6 Event: DEVICE RESTART"),
            comment("Preparation: Unload test object (Association table)"),
            comment("Connect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Authorization with highest key to access load state machines"),
            comment("Authorize response for level 0 is returned"),
            inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 62 43 D2 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_INDEX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to association table object a LOAD_EVENT_START LOADING"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_INDEX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_INDEX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to association table object a LOAD_EVENT_LOAD COMPLETED"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_INDEX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_INDEX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to association table object a LOAD_SEGMENT (Segment control record)"),
            comment("BDUT returns load state LOAD_STATE_ERROR"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_INDEX 05 10 01 03 02 40 30 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_INDEX 05 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Now test object is in state ERROR"),
            comment("Send a device restart to BDUT"),
            inject("BC #EDI #BDUT 61 57 80"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("T-ACK is optional. It is depending on the device architecture."),
            comment("Acceptance: Connection breaks down, load state changes to ERROR"),
            comment("Reconnect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 5000),
            comment("Read load state of association table"),
            comment("BDUT returns load state LOAD_STATE_ERROR"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_INDEX 05 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_INDEX 05 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
    ];

    TestSuite::new("L-2.5 Tests with initial state LOAD_STATE_ERROR", vars).with_cases(cases)
}

// ============================================================================
// L-2.6 Test without access rights
// ============================================================================

/// Create test for access rights verification
///
/// This test verifies that the device denies access to the load state machine
/// when no authorization has been performed. The device should return an error
/// response with count=0 (no elements) indicating access denied.
///
/// The test sets up a non-default key for level 0 (0xAAAAAAAA), then attempts
/// to write without authorization and expects access denied. Finally it restores
/// the default key.
pub fn create_no_access_rights_suite() -> TestSuite {
    let vars = create_test_variables();

    // Preparation: Set level 0 key to non-default value so unauthenticated
    // connections get access level 1 instead of level 0
    let preparation = vec![
        comment("Preparation: Set level 0 key to non-default value"),
        comment("Connect to BDUT"),
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        comment("Authorize with default key (0xFFFFFFFF) to get level 0 access"),
        inject("BC #EDI #BDUT 66 43 D1 00 FF FF FF FF"),
        expect("B0 #BDUT #EDI 60 C2", 0),
        expect("BC #BDUT #EDI 62 43 D2 00", 400),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        comment("A_Key_Write: Set key for level 0 to 0xAAAAAAAA"),
        inject("BC #EDI #BDUT 66 47 D3 00 #LEV_0_KEY_NONDEFAULT"),
        expect("B0 #BDUT #EDI 60 C6", 0),
        expect("BC #BDUT #EDI 62 47 D4 00", 400),
        inject_delay("B0 #EDI #BDUT 60 C6", 200),
        comment("Close connection"),
        inject_delay("B0 #EDI #BDUT 60 81", 200),
    ];

    // Teardown: Restore level 0 key to default (0xFFFFFFFF)
    let teardown = vec![
        comment("Cleanup: Restore level 0 key to default (0xFFFFFFFF)"),
        comment("Connect to BDUT"),
        inject_delay("B0 #EDI #BDUT 60 80", 200),
        comment("Authorize with the key we set (0xAAAAAAAA)"),
        inject("BC #EDI #BDUT 66 43 D1 00 #LEV_0_KEY_NONDEFAULT"),
        expect("B0 #BDUT #EDI 60 C2", 0),
        expect("BC #BDUT #EDI 62 43 D2 00", 400),
        inject_delay("B0 #EDI #BDUT 60 C2", 200),
        comment("A_Key_Write: Restore default key for level 0"),
        inject("BC #EDI #BDUT 66 47 D3 00 FF FF FF FF"),
        expect("B0 #BDUT #EDI 60 C6", 0),
        expect("BC #BDUT #EDI 62 47 D4 00", 400),
        inject_delay("B0 #EDI #BDUT 60 C6", 200),
        comment("Close connection"),
        inject_delay("B0 #EDI #BDUT 60 81", 200),
    ];

    let cases = vec![
        // ====================================================================
        // L-2.6 Test without access rights
        // ====================================================================
        TestCase::new("L-2.6 Test without access rights").with_steps(vec![
            comment("Testcase 2.6 Test without access rights"),
            comment("Connect to BDUT without authorization"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("No authorization! Connection has default access level 3."),
            comment("Send to association table object a LOAD_EVENT_UNLOAD"),
            comment("Acceptance: BDUT denies access to load state machine"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_INDEX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            // Access denied response: count=0, start_idx=1 (no data payload)
            expect("BC #BDUT #EDI 65 43 D6 #TEST_OBJ_INDEX 05 00 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
    ];

    TestSuite::new("L-2.6 Test without access rights", vars)
        .with_preparation(preparation)
        .with_cases(cases)
        .with_teardown(teardown)
}

/// Get all load state machine test suites
pub fn get_all_suites() -> Vec<TestSuite> {
    vec![
        create_preparation_suite(),
        create_unloaded_state_suite(),
        create_loaded_state_suite(),
        create_loading_state_suite(),
        create_error_state_suite(),
        create_no_access_rights_suite(),
    ]
}
