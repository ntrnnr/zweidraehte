//! Run State Machine Conformance Tests
//!
//! Tests based on KNX v2.1.1, Volume 08 TSSG System Conformance Testing - Run State Machines Tests
//! Reference: v01.02.01 AS
//!
//! These tests verify correct handling of:
//! - Run state machine transitions (HALTED, RUNNING, READY, TERMINATED)
//! - Run events (NO_OP, RESTART, STOP, RUN, PROGRAM, etc.)
//! - PropertyValue_Write for run control (PID_RUN_STATE_CONTROL = 0x06)
//! - Authorization requirements for run operations
//!
//! NOTE: Run state machine uses object index 03 (Application object) by default,
//! unlike Load state machine tests which use object index 02 (Association table).
//!
//! TODO: These tests currently FAIL because the stack does not implement a proper
//! run state machine. The ApplicationProgramObject just stores the run_state as a
//! simple property value instead of interpreting run control events (STOP, RESTART, etc.)
//! and transitioning between states (HALTED, RUNNING, READY, TERMINATED).

use std::collections::BTreeMap;

use super::helpers::{comment, expect, inject, inject_delay};
use crate::{TestCase, TestSuite, TestVariable};

/// Create test variables for run state machine tests
///
/// Variables:
/// - EDI: External Device Individual address (default: AF FE = 10.15.254)
/// - BDUT: Basic Device Under Test (1.0.1 = 10 01)
/// - TEST_OBJ_IDX: Object index under test (default: 03 = Application object)
/// - LEV_0_KEY: Authorization key for level 0 (default: FF FF FF FF)
pub fn create_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    vars.insert("EDI".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("BDUT".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    vars.insert("TEST_OBJ_IDX".to_string(), TestVariable::Bytes(vec![0x03]));
    vars.insert("LEV_0_KEY".to_string(), TestVariable::Bytes(vec![0xFF, 0xFF, 0xFF, 0xFF]));
    vars
}

// ============================================================================
// R-2.1 Test Preparation
// ============================================================================

/// Create test preparation suite for run state machine tests
pub fn create_preparation_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![TestCase::new("R-2.1 Test preparation").with_steps(vec![
        comment("Assumed Memory Model: Address 0x4000 to 0xBFFF"),
        comment("================================================================================"),
    ])];

    TestSuite::new("R-2.1 Test preparation", vars).with_cases(cases)
}

// ============================================================================
// R-2.2 Tests with initial state RUNSTATE_HALTED
// ============================================================================

/// Create tests for RUNSTATE_HALTED initial state
///
/// Run states:
/// - HALTED = 00
/// - RUNNING = 01
/// - READY = 02
/// - TERMINATED = 03
///
/// Run control events:
/// - NO_OP = 00
/// - RESTART = 01
/// - STOP = 02
pub fn create_halted_state_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // R-2.2.1 Event: Invalid RUNCONTROL and RUNCONTROL_NO_OPERATION
        // ====================================================================
        TestCase::new("R-2.2.1 Event: Invalid RUNCONTROL and RUNCONTROL_NO_OPERATION").with_steps(vec![
            comment("Testcase 2.2 Tests with initial state RUNSTATE_HALTED"),
            comment("Preparation: Load application object (executable part)"),
            comment("Testcase 2.2.1 Event: Invalid RUNCONTROL and RUNCONTROL_NO_OPERATION"),
            comment("Preparation: Unload test object (Application)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to application program object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_HALTED"),
            inject("BC #EDI #BDUT 65 47 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("First check if BDUT ignores invalid Run state event"),
            comment("Acceptance: BDUT returns run state RUNSTATE_HALTED."),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 06 10 01 FF 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Now send to run state object a RUNCONTROL_NO_OPERATION"),
            comment("Acceptance: BDUT returns run state RUNSTATE_HALTED."),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_IDX 06 10 01 00 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.2.2 Event: RUNCONTROL_RESTART and executable part loaded
        // ====================================================================
        TestCase::new("R-2.2.2 Event: RUNCONTROL_RESTART and executable part loaded").with_steps(vec![
            comment("Testcase 2.2.2 Event: RUNCONTROL_RESTART and executable part loaded"),
            comment("Note: Only applicable for devices complying with System 2/BCU2 profiles or mask versions 0300h and 2300h. For all other system profiles, this test does not apply as the initial state can not be provoked."),
            comment("Set device to state 'halted' with executable part loaded as done in clause 2.3.5."),
            comment("Send to run state object a RUNCONTROL_RESTART"),
            comment("Acceptance: BDUT returns run state RUNSTATE_HALTED."),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.2.3 Event: RUNCONTROL_RESTART and executable part unloaded
        // ====================================================================
        TestCase::new("R-2.2.3 Event: RUNCONTROL_RESTART and executable part unloaded").with_steps(vec![
            comment("Testcase 2.2.3 Event: RUNCONTROL_RESTART and executable part unloaded"),
            comment("Preparation: Unload test object (Application)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_HALTED"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to run state object a RUNCONTROL_RESTART"),
            comment("Acceptance: BDUT returns run state RUNSTATE_HALTED."),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.2.4 Event: RUNCONTROL_STOP
        // ====================================================================
        TestCase::new("R-2.2.4 Event: RUNCONTROL_STOP").with_steps(vec![
            comment("Testcase 2.2.4 Event: RUNCONTROL_STOP"),
            comment("Preparation: Unload test object (Application)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_HALTED"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to run state object a RUNCONTROL_STOP"),
            comment("Acceptance: BDUT returns run state RUNSTATE_TERMINATED."),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.2.5 Event: Unload to corresponding load state
        // ====================================================================
        TestCase::new("R-2.2.5 Event: Unload to corresponding load state").with_steps(vec![
            comment("Testcase 2.2.5 Event: Unload to corresponding load state"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to run state object a RUNCONTROL_RESTART"),
            comment("BDUT returns run state RUNSTATE_HALTED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_HALTED"),
            inject("BC #EDI #BDUT 65 47 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to application program object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Read run state"),
            comment("Acceptance: BDUT returns run state RUNSTATE_HALTED."),
            inject("BC #EDI #BDUT 65 4F D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.2.6 Event: Device restart and executable part loaded (Power Up)
        // ====================================================================
        TestCase::new("R-2.2.6 Event: Device restart and executable part loaded (Power Up)").with_steps(vec![
            comment("Testcase 2.2.6 Event: Device restart and executable part loaded (Power Up)"),
            comment("Not applicable as device is in run state 'halted', which is for a loaded application not possible."),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.2.7 Event: Device restart and executable part not loaded (Power Up)
        // ====================================================================
        TestCase::new("R-2.2.7 Event: Device restart and executable part not loaded (Power Up)").with_steps(vec![
            comment("Testcase 2.2.7 Event: Device restart and executable part not loaded (Power Up)"),
            comment("Preparation: Unload test object (Application)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_HALTED"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send a reset to BDUT"),
            inject_delay("BC #EDI #BDUT 61 47 80", 200),
            comment("Connection breaks down, run state is RUNSTATE_HALTED"),
            comment("Reconnect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("Acceptance: BDUT returns run state RUNSTATE_HALTED."),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
    ];

    TestSuite::new("R-2.2 Tests with initial state RUNSTATE_HALTED", vars).with_cases(cases)
}

// ============================================================================
// R-2.3 Tests with initial state RUNSTATE_RUNNING
// ============================================================================

/// Create tests for RUNSTATE_RUNNING initial state
///
/// These tests require the application object to be loaded and running.
/// The preparation step loads the application using LOAD_EVENT_SEGMENTs.
pub fn create_running_state_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // R-2.3.1 Preparation
        // ====================================================================
        TestCase::new("R-2.3.1 Preparation").with_steps(vec![
            comment("Testcase 2.3 Tests with initial state RUNSTATE_RUNNING"),
            comment("Testcase 2.3.1 Preparation"),
            comment("Note: the underneath test preparation is specific to a certain system profile and might have to be adapted for other system profiles to ensure that at the end of the preparation the load state machine is in state 'loaded' and the run state machine is in the state 'running'."),
            comment("Load application object (executable part)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to application program object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to application program object a LOAD_EVENT_START"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 05 10 01 03 00 07 00 00 F8 F1 02 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_IDX 05 10 01 03 00 40 A4 01 5C F1 03 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_IDX 05 10 01 03 00 42 00 01 00 22 03 80 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_IDX 05 10 01 03 00 43 00 01 00 33 03 80 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 5B D7 #TEST_OBJ_IDX 05 10 01 03 00 44 00 72 00 FF 03 80 00"),
            expect("B0 #BDUT #EDI 60 DA", 0),
            expect("BC #BDUT #EDI 66 5B D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 DA", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 5F D7 #TEST_OBJ_IDX 05 10 01 03 02 41 34 00 00 C5 FF 12 11"),
            expect("B0 #BDUT #EDI 60 DE", 0),
            expect("BC #BDUT #EDI 66 5F D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 DE", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 63 D7 #TEST_OBJ_IDX 05 10 01 03 04 40 B7 03 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 E2", 0),
            expect("BC #BDUT #EDI 66 63 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 E2", 200),
            comment("Send to application program object a LOAD_EVENT_COMPLETE"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 67 D7 #TEST_OBJ_IDX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 E6", 0),
            expect("BC #BDUT #EDI 66 67 D6 #TEST_OBJ_IDX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 E6", 200),
            comment("Send to run state object a RUNCONTROL_RESTART"),
            comment("BDUT returns run state RUNSTATE_RUNNING"),
            inject("BC #EDI #BDUT 6F 6B D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 EA", 0),
            expect("BC #BDUT #EDI 66 6B D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 EA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.3.2 Event: Invalid RUNCONTROL and RUNCONTROL_NO_OPERATION
        // ====================================================================
        TestCase::new("R-2.3.2 Event: Invalid RUNCONTROL and RUNCONTROL_NO_OPERATION").with_steps(vec![
            comment("Testcase 2.3.2 Event: Invalid RUNCONTROL and RUNCONTROL_NO_OPERATION"),
            comment("Precondition: The executable part is already loaded (see clause 2.3.1)"),
            comment("Preparation: Set run state to RUNSTATE_RUNNING"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_RUNNING"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("First check if BDUT ignores invalid Run State event"),
            comment("Acceptance: BDUT returns run state RUNSTATE_RUNNING."),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 FF 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Now send to run state object a RUNCONTROL_NO_OPERATION"),
            comment("Acceptance: BDUT returns run state RUNSTATE_RUNNING."),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 06 10 01 00 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.3.3 Event: RUNCONTROL_RESTART (executable part loaded)
        // ====================================================================
        TestCase::new("R-2.3.3 Event: RUNCONTROL_RESTART (executable part loaded)").with_steps(vec![
            comment("Testcase 2.3.3 Event: RUNCONTROL_RESTART (executable part loaded)"),
            comment("Precondition: The executable part is already loaded (see clause 2.3.1)"),
            comment("Preparation: Set run state to RUNSTATE_RUNNING"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_RUNNING"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to run state object a RUNCONTROL_RESTART"),
            comment("Acceptance: BDUT returns run state RUNSTATE_RUNNING. It may intermediately return RUNSTATE_READY (telegrams are optional)."),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.3.4 Event: RUNCONTROL_RESTART and executable part unloaded
        // ====================================================================
        TestCase::new("R-2.3.4 Event: RUNCONTROL_RESTART and executable part unloaded").with_steps(vec![
            comment("Testcase 2.3.4 Event: RUNCONTROL_RESTART and executable part unloaded"),
            comment("Not applicable, the runstate 'running' is not possible for an unloaded application."),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.3.5 Event: RUNCONTROL_STOP
        // ====================================================================
        TestCase::new("R-2.3.5 Event: RUNCONTROL_STOP").with_steps(vec![
            comment("Testcase 2.3.5 Event: RUNCONTROL_STOP"),
            comment("Precondition: The executable part is already loaded (see clause 2.3.1)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_RUNNING"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to run state object a RUNCONTROL_STOP"),
            comment("Acceptance: BDUT returns run state RUNSTATE_TERMINATED, optional HALTED."),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.3.6 Event: Unload corresponding load state
        // ====================================================================
        TestCase::new("R-2.3.6 Event: Unload corresponding load state").with_steps(vec![
            comment("Testcase 2.3.6 Event: Unload corresponding load state"),
            comment("Precondition: The executable part is already loaded (done in 2.)"),
            comment("Preparation: Set run state to RUNSTATE_RUNNING"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to run state object a RUNCONTROL_RESTART"),
            comment("BDUT returns run state RUNSTATE_RUNNING (it may optionally return the intermediate state 'ready')."),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_RUNNING"),
            inject("BC #EDI #BDUT 65 47 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to application program object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Read run state"),
            comment("Acceptance: BDUT returns run state RUNSTATE_HALTED, alternatively the intermediate step 'Shutting Down (05h)'."),
            inject("BC #EDI #BDUT 65 4F D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.3.7 Event: Device restart and executable part loaded (Power Up)
        // ====================================================================
        TestCase::new("R-2.3.7 Event: Device restart and executable part loaded (Power Up)").with_steps(vec![
            comment("Testcase 2.3.7 Event: Device restart and executable part loaded (Power Up)"),
            comment("Preparation: Load application object (executable part)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to application program object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to application program object a LOAD_EVENT_START"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("-------------------------------------------------------"),
            comment("Note: the underneath test preparation until the next dotted line is specific to a certain system profile and might have to be adapted for other system profiles to ensure that at the end of the preparation the load state machine is in state 'loaded' and the run state machine is in the state 'running'."),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 05 10 01 03 00 07 00 00 F8 F1 02 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_IDX 05 10 01 03 00 40 A4 01 5C F1 03 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_IDX 05 10 01 03 00 42 00 01 00 22 03 80 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_IDX 05 10 01 03 00 43 00 01 00 33 03 80 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 5B D7 #TEST_OBJ_IDX 05 10 01 03 00 44 00 72 00 FF 03 80 00"),
            expect("B0 #BDUT #EDI 60 DA", 0),
            expect("BC #BDUT #EDI 66 5B D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 DA", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 5F D7 #TEST_OBJ_IDX 05 10 01 03 02 41 34 00 00 C5 FF 12 11"),
            expect("B0 #BDUT #EDI 60 DE", 0),
            expect("BC #BDUT #EDI 66 5F D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 DE", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 63 D7 #TEST_OBJ_IDX 05 10 01 03 04 40 B7 03 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 E2", 0),
            expect("BC #BDUT #EDI 66 63 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 E2", 200),
            comment("Send to application program object a LOAD_EVENT_COMPLETE"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 67 D7 #TEST_OBJ_IDX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 E6", 0),
            expect("BC #BDUT #EDI 66 67 D6 #TEST_OBJ_IDX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 E6", 200),
            comment("Send to application program object a RUNSTATE_RESTART"),
            inject_delay("BC #EDI #BDUT 6F 6B D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00", 200),
            inject_delay("B0 #BDUT #EDI 60 EA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("-------------------------------------------------"),
            comment("Actual start of test"),
            comment("Preparation: Do reset of device"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send a reset to BDUT"),
            inject_delay("BC #EDI #BDUT 61 43 80", 200),
            comment("Acceptance: Connection breaks down, run state may intermediately return RUNSTATE_HALTED or RUNSTATE_READY or may immediately return the run state RUNSTATE_RUNNING (telegrams are optional)."),
            comment("Read run state"),
            comment("Acceptance: BDUT returns run state RUNSTATE_RUNNING."),
            inject("BC #EDI #BDUT 65 47 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.3.8 Event: Device restart and executable part unloaded (Power Up)
        // ====================================================================
        TestCase::new("R-2.3.8 Event: Device restart and executable part unloaded (Power Up)").with_steps(vec![
            comment("Testcase 2.3.8 Event: Device restart and executable part unloaded (Power Up)"),
            comment("Not applicable, marked as such in AN080."),
            comment("================================================================================"),
        ]),
    ];

    TestSuite::new("R-2.3 Tests with initial state RUNSTATE_RUNNING", vars).with_cases(cases)
}

// ============================================================================
// R-2.4 Tests with initial state RUNSTATE_READY
// ============================================================================

/// Create tests for RUNSTATE_READY initial state
///
/// RUNSTATE_READY is an intermediate state that occurs when run conditions
/// are not immediately fulfilled. If run-conditions are immediately fulfilled
/// and the executable part is started automatically, the BDUT may never return
/// the intermediate run state 'ready'. In that case these tests can be skipped.
pub fn create_ready_state_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // R-2.4.1 General
        // ====================================================================
        TestCase::new("R-2.4.1 General").with_steps(vec![
            comment("If run-conditions are immediately fulfilled and the executable part is started automatically, it may be possible that the BDUT never returns the intermediate run state 'ready'. In that case the underneath tests can be skipped."),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.4.2 Event: Invalid RUNCONTROL and RUNCONTROL_NO_OPERATION
        // ====================================================================
        TestCase::new("R-2.4.2 Event: Invalid RUNCONTROL and RUNCONTROL_NO_OPERATION").with_steps(vec![
            comment("Testcase 2.4.2 Event: Invalid RUNCONTROL and RUNCONTROL_NO_OPERATION"),
            comment("Precondition: The executable part is already loaded"),
            comment("Preparation: Set run state to RUNSTATE_READY"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send a reset to BDUT"),
            inject_delay("BC #EDI #BDUT 61 43 80", 200),
            comment("Acceptance: Connection breaks down, run state is RUNSTATE_READY."),
            comment("Reconnect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_READY (intermediate state)"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("First check if BDUT ignores invalid run state event"),
            comment("Acceptance: BDUT returns run state RUNSTATE_READY."),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 FF 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Now send to run state object a RUNCONTROL_NO_OPERATION"),
            comment("Acceptance: BDUT returns run state RUNSTATE_READY."),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 06 10 01 00 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 06 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.4.3 Event: Restart and executable part loaded
        // ====================================================================
        TestCase::new("R-2.4.3 Event: Restart and executable part loaded").with_steps(vec![
            comment("Testcase 2.4.3 Event: Restart and executable part loaded"),
            comment("Precondition: The executable part is already loaded (done in 2.)"),
            comment("Preparation: Set run state to RUNSTATE_READY"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send a reset to BDUT"),
            inject_delay("BC #EDI #BDUT 61 43 80", 200),
            comment("Acceptance: Connection breaks down, run state is RUNSTATE_READY."),
            comment("Reconnect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_READY (intermediate state)"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to run state object a RUNCONTROL_RESTART"),
            comment("BDUT returns run state RUNSTATE_READY (intermediate state)"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Here we wait a few seconds to be sure that the application has started."),
            comment("Read run state"),
            comment("Acceptance: BDUT returns run state RUNSTATE_RUNNING."),
            inject("BC #EDI #BDUT 65 4B D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.4.4 Event: Restart and executable part unloaded
        // ====================================================================
        TestCase::new("R-2.4.4 Event: Restart and executable part unloaded").with_steps(vec![
            comment("Testcase 2.4.4 Event: Restart and executable part unloaded"),
            comment("Not applicable (if application is unloaded and a restart is sent to the BDUT, the BDUT can acc. AN 080 never be set to the ready state. The case where the initial state is ready for an unloaded application can never occur)."),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.4.5 Event: Stop run state machine
        // ====================================================================
        TestCase::new("R-2.4.5 Event: Stop run state machine").with_steps(vec![
            comment("Testcase 2.4.5 Event: Stop run state machine"),
            comment("Preparation: Set run state to RUNSTATE_READY"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send a reset to BDUT"),
            inject_delay("BC #EDI #BDUT 61 43 80", 200),
            comment("Acceptance: Connection breaks down, run state is RUNSTATE_READY."),
            comment("Reconnect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_READY (intermediate state)"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to run state object a RUNCONTROL_STOP"),
            comment("Acceptance: BDUT returns run state RUNSTATE_TERMINATED."),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.4.6 Event: Unload to corresponding load state
        // ====================================================================
        TestCase::new("R-2.4.6 Event: Unload to corresponding load state").with_steps(vec![
            comment("Testcase 2.4.6 Event: Unload to corresponding load state"),
            comment("Preparation: Set run state to RUNSTATE_READY"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send a reset to BDUT"),
            inject_delay("BC #EDI #BDUT 61 43 80", 200),
            comment("Acceptance: Connection breaks down, run state is RUNSTATE_READY."),
            comment("Reconnect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_READY (intermediate state)"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to application program object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Read run state"),
            comment("Acceptance: BDUT returns run state RUNSTATE_HALTED."),
            inject("BC #EDI #BDUT 65 4B D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.4.7 Event: Device restart and executable part loaded (Power Up)
        // ====================================================================
        TestCase::new("R-2.4.7 Event: Device restart and executable part loaded (Power Up)").with_steps(vec![
            comment("Testcase 2.4.7 Event: Device restart and executable part loaded (Power Up)"),
            comment("Precondition: The executable part is already loaded"),
            comment("Preparation: Load application object (executable part)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to application program object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to application program object a LOAD_EVENT_START"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 05 10 01 03 00 07 00 00 F8 F1 02 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_IDX 05 10 01 03 00 40 A4 01 5C F1 03 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_IDX 05 10 01 03 00 42 00 01 00 22 03 80 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_IDX 05 10 01 03 00 43 00 01 00 33 03 80 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            inject("BC #EDI #BDUT 6F 5B D7 #TEST_OBJ_IDX 05 10 01 03 00 44 00 72 00 FF 03 80 00"),
            expect("B0 #BDUT #EDI 60 DA", 0),
            expect("BC #BDUT #EDI 66 5B D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 DA", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            inject("BC #EDI #BDUT 6F 5F D7 #TEST_OBJ_IDX 05 10 01 03 02 41 34 00 00 C5 FF 12 11"),
            expect("B0 #BDUT #EDI 60 DE", 0),
            expect("BC #BDUT #EDI 66 5F D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 DE", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            inject("BC #EDI #BDUT 6F 63 D7 #TEST_OBJ_IDX 05 10 01 03 04 40 B7 03 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 E2", 0),
            expect("BC #BDUT #EDI 66 63 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 E2", 200),
            comment("Send to application program object a LOAD_EVENT_COMPLETE"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 67 D7 #TEST_OBJ_IDX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 E6", 0),
            // LOAD_STATE_LOADED = 01
            expect("BC #BDUT #EDI 66 67 D6 #TEST_OBJ_IDX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 E6", 200),
            comment("Send to application program object a RUNSTATE_RESTART"),
            inject_delay("BC #EDI #BDUT 6F 6B D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00", 200),
            inject_delay("B0 #BDUT #EDI 60 EA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("Start of actual test: Set run state to RUNSTATE_READY"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send a reset to BDUT"),
            inject_delay("BC #EDI #BDUT 61 43 80", 200),
            comment("Acceptance: Connection breaks down, run state is RUNSTATE_READY."),
            comment("Reconnect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_READY"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send a reset to BDUT"),
            inject_delay("BC #EDI #BDUT 61 47 80", 200),
            comment("Acceptance: Connection breaks down, run state is RUNSTATE_READY."),
            comment("Reconnect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_READY (intermediate state)"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Observe a short wait time to ensure that the application has started."),
            comment("Read run state"),
            comment("Acceptance: BDUT returns run state RUNSTATE_RUNNING."),
            inject("BC #EDI #BDUT 65 47 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            // RUNSTATE_RUNNING = 01
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.4.8 Event: Device restart and executable part unloaded (Power Up)
        // ====================================================================
        TestCase::new("R-2.4.8 Event: Device restart and executable part unloaded (Power Up)").with_steps(vec![
            comment("Testcase 2.4.8 Event: Device restart and executable part unloaded (Power Up)"),
            comment("Not applicable, marked as such in AN080."),
            comment("================================================================================"),
        ]),
    ];

    TestSuite::new("R-2.4 Tests with initial state RUNSTATE_READY", vars).with_cases(cases)
}

// ============================================================================
// R-2.5 Tests with initial state RUNSTATE_TERMINATED
// ============================================================================

/// Create tests for RUNSTATE_TERMINATED initial state
///
/// RUNSTATE_TERMINATED is reached when the application is stopped while loaded,
/// or when trying to run an unloaded application.
pub fn create_terminated_state_suite() -> TestSuite {
    let vars = create_test_variables();
    let cases = vec![
        // ====================================================================
        // R-2.5.1 Event: Invalid RUNCONTROL and RUNCONTROL_NO_OPERATION
        // ====================================================================
        TestCase::new("R-2.5.1 Event: Invalid RUNCONTROL and RUNCONTROL_NO_OPERATION").with_steps(vec![
            comment("Testcase 2.5 Tests with initial state RUNSTATE_TERMINATED"),
            comment("Preparation: Load application object (executable part)"),
            comment("Testcase 2.5.1 Event: Invalid RUNCONTROL and RUNCONTROL_NO_OPERATION"),
            comment("Precondition: The executable part is already loaded"),
            comment("Preparation: Set run state to RUNSTATE_TERMINATED"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to run state object a RUNCONTROL_STOP"),
            comment("BDUT returns run state RUNSTATE_TERMINATED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 06 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("First check if BDUT ignores invalid run state event"),
            comment("Acceptance: BDUT returns run state RUNSTATE_TERMINATED."),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 FF 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Now send to run state object a RUNCONTROL_NO_OPERATION"),
            comment("Acceptance: BDUT returns run state RUNSTATE_TERMINATED."),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 06 10 01 00 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.5.2 Event: RUNCONTROL_RESTART ( executable part loaded)
        // ====================================================================
        TestCase::new("R-2.5.2 Event: RUNCONTROL_RESTART ( executable part loaded)").with_steps(vec![
            comment("Testcase 2.5.2 Event: RUNCONTROL_RESTART ( executable part loaded)"),
            comment("Precondition: The executable part is already loaded (done)"),
            comment("Preparation: Set run state to RUNSTATE_TERMINATED"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to run state object a RUNCONTROL_STOP"),
            comment("BDUT returns run state RUNSTATE_TERMINATED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 06 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to run state object a RUNCONTROL_RESTART"),
            comment("Acceptance: BDUT returns run state RUNSTATE_RUNNING (it may return the intermediate state 'ready')."),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.5.3 Event: RUNCONTROL_RESTART (executable part unloaded)
        // ====================================================================
        TestCase::new("R-2.5.3 Event: RUNCONTROL_RESTART (executable part unloaded)").with_steps(vec![
            comment("Testcase 2.5.3 Event: RUNCONTROL_RESTART (executable part unloaded)"),
            comment("Preparation: Set run state to RUNSTATE_TERMINATED"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to application program object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to run state object a RUNCONTROL_STOP"),
            comment("BDUT returns run state RUNSTATE_TERMINATED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to run state object a RUNCONTROL_RESTART"),
            comment("Acceptance: BDUT returns run state RUNSTATE_HALTED."),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.5.4 Event: RUNCONTROL_STOP
        // ====================================================================
        TestCase::new("R-2.5.4 Event: RUNCONTROL_STOP").with_steps(vec![
            comment("Testcase 2.5.4 Event: RUNCONTROL_STOP"),
            comment("Preparation: Set run state to RUNSTATE_TERMINATED"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to run state object a RUNCONTROL_STOP"),
            comment("BDUT returns run state RUNSTATE_TERMINATED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 06 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to run state object a RUNCONTROL_STOP"),
            comment("Acceptance: BDUT returns run state RUNSTATE_TERMINATED."),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.5.5 Event: Unload to corresponding load state
        // ====================================================================
        TestCase::new("R-2.5.5 Event: Unload to corresponding load state").with_steps(vec![
            comment("Testcase 2.5.5 Event: Unload to corresponding load state"),
            comment("Preparation: Set run state to RUNSTATE_TERMINATED"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to run state object a RUNCONTROL_STOP"),
            comment("BDUT returns run state RUNSTATE_TERMINATED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 06 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to application program object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Read run state"),
            comment("Acceptance: BDUT returns run state RUNSTATE_HALTED."),
            inject("BC #EDI #BDUT 65 4B D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.5.6 Event: Device restart and executable part loaded (Power Up)
        // ====================================================================
        TestCase::new("R-2.5.6 Event: Device restart and executable part loaded (Power Up)").with_steps(vec![
            comment("Testcase 2.5.6 Event: Device restart and executable part loaded (Power Up)"),
            comment("Preparation: Load application object (executable part)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to application program object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to application program object a LOAD_EVENT_START"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("-----------------------------------------------"),
            comment("Note: the underneath test preparation until the next dotted line is specific to a certain system profile and might have to be adapted for other system profiles to ensure that at the end of the preparation the load state machine is in state 'loaded' and the run state machine is in the state 'loaded'."),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 05 10 01 03 00 07 00 00 F8 F1 02 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_IDX 05 10 01 03 00 40 A4 01 5C F1 03 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_IDX 05 10 01 03 00 42 00 01 00 22 03 80 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_IDX 05 10 01 03 00 43 00 01 00 33 03 80 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 5B D7 #TEST_OBJ_IDX 05 10 01 03 00 44 00 72 00 FF 03 80 00"),
            expect("B0 #BDUT #EDI 60 DA", 0),
            expect("BC #BDUT #EDI 66 5B D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 DA", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 5F D7 #TEST_OBJ_IDX 05 10 01 03 02 41 34 00 00 C5 FF 12 11"),
            expect("B0 #BDUT #EDI 60 DE", 0),
            expect("BC #BDUT #EDI 66 5F D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 DE", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 63 D7 #TEST_OBJ_IDX 05 10 01 03 04 40 B7 03 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 E2", 0),
            expect("BC #BDUT #EDI 66 63 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 E2", 200),
            comment("Send to application program object a LOAD_EVENT_COMPLETE"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 67 D7 #TEST_OBJ_IDX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 E6", 0),
            expect("BC #BDUT #EDI 66 67 D6 #TEST_OBJ_IDX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 E6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("----------------------------------------------------"),
            comment("Start of actual test"),
            comment("Precondition: The executable part is already loaded"),
            comment("Preparation: Set run state to RUNSTATE_TERMINATED"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to run state object a RUNCONTROL_STOP"),
            comment("BDUT returns run state RUNSTATE_TERMINATED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 06 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send a reset to BDUT"),
            inject_delay("BC #EDI #BDUT 61 47 80", 200),
            comment("Acceptance: Connection breaks down, run state may intermediately return RUNSTATE_HALTED and/or RUNSTATE_READY or may immediately return the run state RUNSTATE_RUNNING (telegrams are optional)."),
            comment("Reconnect to BDUT"),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_HALTED and/or RUNSTATE_READY (intermediate state)"),
            comment("And/or"),
            comment("In case of an intermediate RUNSTATE_HALTED and/or RUNSTATE_Ready, observe a wait time to ensure that the application has started."),
            comment("Read run state"),
            comment("Acceptance: BDUT returns run state RUNSTATE_RUNNING."),
            inject("BC #EDI #BDUT 65 47 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
        // ====================================================================
        // R-2.5.7 Event: Device restart and executable part not loaded (Power Up)
        // ====================================================================
        TestCase::new("R-2.5.7 Event: Device restart and executable part not loaded (Power Up)").with_steps(vec![
            comment("Testcase 2.5.7 Event: Device restart and executable part not loaded (Power Up)"),
            comment("Preparation: Unload test object (Application)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to application program object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to run state object a RUNCONTROL_STOP"),
            comment("BDUT returns run state RUNSTATE_TERMINATED"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 03", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send a reset to BDUT"),
            inject("BC #EDI #BDUT 61 4B 80"),
            expect("B0 #BDUT #EDI 60 CA", 200),
            comment("T-ACK is optional. It is depending on the device architecture."),
            comment("Acceptance: Connection breaks down, load state remains UNLOADED."),
            comment("Reconnect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("Acceptance: BDUT returns run state RUNSTATE_HALTED."),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("Restore device (Load application object)"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send to application program object a LOAD_EVENT_UNLOAD"),
            comment("BDUT returns load state LOAD_STATE_UNLOADED"),
            inject("BC #EDI #BDUT 6F 43 D7 #TEST_OBJ_IDX 05 10 01 04 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 05 10 01 00", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to application program object a LOAD_EVENT_START"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 05 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 05 10 01 03 00 07 00 00 F8 F1 02 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_IDX 05 10 01 03 00 40 A4 01 5C F1 03 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 53 D7 #TEST_OBJ_IDX 05 10 01 03 00 42 00 01 00 22 03 80 00"),
            expect("B0 #BDUT #EDI 60 D2", 0),
            expect("BC #BDUT #EDI 66 53 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 D2", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 57 D7 #TEST_OBJ_IDX 05 10 01 03 00 43 00 01 00 33 03 80 00"),
            expect("B0 #BDUT #EDI 60 D6", 0),
            expect("BC #BDUT #EDI 66 57 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 D6", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 5B D7 #TEST_OBJ_IDX 05 10 01 03 00 44 00 72 00 FF 03 80 00"),
            expect("B0 #BDUT #EDI 60 DA", 0),
            expect("BC #BDUT #EDI 66 5B D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 DA", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 5F D7 #TEST_OBJ_IDX 05 10 01 03 02 41 34 00 00 C5 FF 12 11"),
            expect("B0 #BDUT #EDI 60 DE", 0),
            expect("BC #BDUT #EDI 66 5F D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 DE", 200),
            comment("Send to application program object a LOAD_EVENT_SEGMENT"),
            comment("BDUT returns load state LOAD_STATE_LOADING"),
            inject("BC #EDI #BDUT 6F 63 D7 #TEST_OBJ_IDX 05 10 01 03 04 40 B7 03 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 E2", 0),
            expect("BC #BDUT #EDI 66 63 D6 #TEST_OBJ_IDX 05 10 01 02", 400),
            inject_delay("B0 #EDI #BDUT 60 E2", 200),
            comment("Send to application program object a LOAD_EVENT_COMPLETE"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 67 D7 #TEST_OBJ_IDX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 E6", 0),
            expect("BC #BDUT #EDI 66 67 D6 #TEST_OBJ_IDX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 E6", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("================================================================================"),
        ]),
    ];

    TestSuite::new("R-2.5 Tests with initial state RUNSTATE_TERMINATED", vars).with_cases(cases)
}

/// Get all run state machine test suites
pub fn get_all_suites() -> Vec<TestSuite> {
    vec![
        create_preparation_suite(),
        create_halted_state_suite(),
        create_running_state_suite(),
        create_ready_state_suite(),
        create_terminated_state_suite(),
    ]
}
