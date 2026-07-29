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
//! NOTE: Run state machine uses object index 04 (Application Program object) by default,
//! unlike Load state machine tests which use object index 02 (Association table).
//!
//! The transitions under test are 03/05/01 §4.24.2.3.3 Table 97. Two of its
//! properties decide most of the expected responses here and are easy to miss:
//! RESTART and STOP each have separate rows for a loaded and an unloaded
//! executable part (note c), and the run state is volatile (§4.24.2.2), so a
//! device restart always resumes from HALTED and cascades back up.

use std::collections::BTreeMap;

use super::helpers::{comment, drain, expect, inject, inject_delay, wait};
use crate::{TestCase, TestSuite, TestVariable};

/// Create test variables for run state machine tests
///
/// Variables:
/// - EDI: External Device Individual address (default: AF FE = 10.15.254)
/// - BDUT: Basic Device Under Test (1.0.1 = 10 01)
/// - TEST_OBJ_IDX: Object index under test (default: 04 = Application Program object)
/// - LEV_0_KEY: Authorization key for level 0 (default: FF FF FF FF)
pub fn create_test_variables() -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    vars.insert("EDI".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE]));
    vars.insert("BDUT".to_string(), TestVariable::Bytes(vec![0x10, 0x01]));
    vars.insert("TEST_OBJ_IDX".to_string(), TestVariable::Bytes(vec![0x04]));
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
            comment("Not applicable. The template says so itself: \"Only applicable for devices complying with System 2/BCU2 profiles or mask versions 0300h and 2300h. For all other system profiles, this test does not apply as the initial state can not be provoked.\" We are System B, mask 07B0/57B0."),
            comment("The preparation it points at cannot run either: it reaches HALTED-with-executable-part-loaded by sending RUNCONTROL_STOP and expecting RUNSTATE_HALTED, annotated \"(only mask 0300h or 2300h, otherwise RUNSTATE_TERMINATED)\". 03/05/01 Table 97 footnote a says the same. For us STOP against a loaded application is TERMINATED, so HALTED-with-application-loaded is unreachable by construction."),
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
            comment("Acceptance: BDUT returns run state RUNSTATE_HALTED. The application is unloaded here (R-2.2.1 unloaded it and nothing since has reloaded it), and 03/05/01 §4.24.2.3.3 note c) allows STOP to reach TERMINATED only while the Load State Machine is in LOADED. The vendor template's own 2.2.4 expects HALTED for the same reason."),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 00", 400),
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
            comment("The template used to interpose seven LOAD_EVENT_SEGMENT writes here and removed them in v8 (2025-01-07), keeping only a note in v9 that a device needing its executable part loaded explicitly may have to put them back. Ours does not: LOAD_EVENT_START followed by LOAD_EVENT_COMPLETE is a whole load. Their segment selectors were AbsoluteData / AbsoluteTask / TaskCtrl1, none of which we implement, so each answered LOAD_STATE_ERROR."),
            comment("Send to application program object a LOAD_EVENT_COMPLETE"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to run state object a RUNCONTROL_RESTART"),
            comment("BDUT returns run state RUNSTATE_RUNNING"),
            inject("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CE", 0),
            expect("BC #BDUT #EDI 66 4F D6 #TEST_OBJ_IDX 06 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CE", 200),
            comment("Starting the application resets the communication objects, which re-arms our read-on-init object (GO3) and puts an unsolicited A_GroupValue_Read on 2/0/1 on the bus. EITT's reference device has no such object configured."),
            drain(200),
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
            comment("The template interposed seven LOAD_EVENT_SEGMENT writes here and removed them in v8 (2025-01-07), keeping only a note in v9 that a device needing its executable part loaded explicitly may have to put them back. Ours does not: LOAD_EVENT_START followed by LOAD_EVENT_COMPLETE is a whole load. Their segment selectors were AbsoluteData / AbsoluteTask / TaskCtrl1, none of which we implement, so each answered LOAD_STATE_ERROR."),
            comment("Send to application program object a LOAD_EVENT_COMPLETE"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to application program object a RUNSTATE_RESTART"),
            inject_delay("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00", 200),
            inject_delay("B0 #BDUT #EDI 60 CE", 200),
            comment("Close connection with BDUT"),
            inject_delay("B0 #EDI #BDUT 60 81", 200),
            comment("-------------------------------------------------"),
            comment("Actual start of test"),
            comment("Preparation: Do reset of device"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Send a reset to BDUT"),
            inject_delay("BC #EDI #BDUT 61 43 80", 200),
            comment("Acceptance: Connection breaks down, run state may intermediately return RUNSTATE_HALTED or RUNSTATE_READY or may immediately return the run state RUNSTATE_RUNNING (telegrams are optional)."),
            comment("Reconnect to BDUT. The restart tears the connection down, so the read below cannot continue the old one — this transcription used to omit the reconnect and inject the read into a connection that no longer existed."),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT may return the intermediate RUNSTATE_HALTED and/or RUNSTATE_READY here, so any state is accepted"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 ??", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("In case of an intermediate state, observe a waiting period to ensure the application has started"),
            wait(2000),
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
            comment("BDUT returns run state RUNSTATE_READY (intermediate state) or RUNSTATE_RUNNING. The template accepts either with a 0? nibble wildcard: 03/05/01 §4.24.2.3.3 note f) makes the Ready to Running transition automatic once the run conditions hold, and §4.24.2.4 notes the intermediate states may never appear. Ours never do."),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 0?", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("First check if BDUT ignores invalid run state event"),
            comment("Acceptance: BDUT returns run state RUNSTATE_READY or RUNSTATE_RUNNING."),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 FF 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 0?", 400),
            inject_delay("B0 #EDI #BDUT 60 C6", 200),
            comment("Now send to run state object a RUNCONTROL_NO_OPERATION"),
            comment("Acceptance: BDUT returns run state RUNSTATE_READY or RUNSTATE_RUNNING."),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 06 10 01 00 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 06 10 01 0?", 400),
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
            comment("BDUT returns run state RUNSTATE_READY (intermediate state) or RUNSTATE_RUNNING. The template accepts either with a 0? nibble wildcard: 03/05/01 §4.24.2.3.3 note f) makes the Ready to Running transition automatic once the run conditions hold, and §4.24.2.4 notes the intermediate states may never appear. Ours never do."),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 0?", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send to run state object a RUNCONTROL_RESTART"),
            comment("BDUT returns run state RUNSTATE_READY (intermediate state) or RUNSTATE_RUNNING. The template accepts either with a 0? nibble wildcard: 03/05/01 §4.24.2.3.3 note f) makes the Ready to Running transition automatic once the run conditions hold, and §4.24.2.4 notes the intermediate states may never appear. Ours never do."),
            inject("BC #EDI #BDUT 6F 47 D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 C6", 0),
            expect("BC #BDUT #EDI 66 47 D6 #TEST_OBJ_IDX 06 10 01 0?", 400),
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
            comment("BDUT returns run state RUNSTATE_READY (intermediate state) or RUNSTATE_RUNNING. The template accepts either with a 0? nibble wildcard: 03/05/01 §4.24.2.3.3 note f) makes the Ready to Running transition automatic once the run conditions hold, and §4.24.2.4 notes the intermediate states may never appear. Ours never do."),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 0?", 400),
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
            comment("BDUT returns run state RUNSTATE_READY (intermediate state) or RUNSTATE_RUNNING. The template accepts either with a 0? nibble wildcard: 03/05/01 §4.24.2.3.3 note f) makes the Ready to Running transition automatic once the run conditions hold, and §4.24.2.4 notes the intermediate states may never appear. Ours never do."),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 0?", 400),
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
            comment("The template interposed seven LOAD_EVENT_SEGMENT writes here and removed them in v8 (2025-01-07), keeping only a note in v9 that a device needing its executable part loaded explicitly may have to put them back. Ours does not: LOAD_EVENT_START followed by LOAD_EVENT_COMPLETE is a whole load. Their segment selectors were AbsoluteData / AbsoluteTask / TaskCtrl1, none of which we implement, so each answered LOAD_STATE_ERROR."),
            comment("Send to application program object a LOAD_EVENT_COMPLETE"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            // LOAD_STATE_LOADED = 01
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
            comment("Send to application program object a RUNSTATE_RESTART"),
            inject_delay("BC #EDI #BDUT 6F 4F D7 #TEST_OBJ_IDX 06 10 01 01 00 00 00 00 00 00 00 00 00", 200),
            inject_delay("B0 #BDUT #EDI 60 CE", 200),
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
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 0?", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("Send a reset to BDUT"),
            inject_delay("BC #EDI #BDUT 61 47 80", 200),
            comment("Acceptance: Connection breaks down, run state is RUNSTATE_READY."),
            comment("Reconnect to BDUT"),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_READY (intermediate state) or RUNSTATE_RUNNING. The template accepts either with a 0? nibble wildcard: 03/05/01 §4.24.2.3.3 note f) makes the Ready to Running transition automatic once the run conditions hold, and §4.24.2.4 notes the intermediate states may never appear. Ours never do."),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 0?", 400),
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
            comment("Impossible, as RUNSTATE_TERMINATED after RUNCONTROL_STOP would result only if the application were loaded, which is not the case here. 03/05/01 §4.24.2.3.3 note c): \"Even if not shown explicitly, the event Stop shall always lead to the state Terminated; this shall only be possible if the corresponding Load State Machine is in the state Loaded.\""),
            comment("The template reduced this case to that observation and sends no telegrams, which also leaves the application loaded so that 2.5.4 onwards work. The transcription here used to unload it and expect RUNSTATE_TERMINATED anyway, taking the rest of the suite with it."),
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
            comment("The template interposed seven LOAD_EVENT_SEGMENT writes here and removed them in v8 (2025-01-07), keeping only a note in v9 that a device needing its executable part loaded explicitly may have to put them back. Ours does not: LOAD_EVENT_START followed by LOAD_EVENT_COMPLETE is a whole load. Their segment selectors were AbsoluteData / AbsoluteTask / TaskCtrl1, none of which we implement, so each answered LOAD_STATE_ERROR."),
            comment("Send to application program object a LOAD_EVENT_COMPLETE"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
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
            comment("Reconnect to BDUT. The restart tears the connection down, so the reads below cannot continue the old one — this transcription used to leave the reconnect and the first read as prose and inject only the second read, into a connection that no longer existed."),
            inject_delay("B0 #EDI #BDUT 60 80", 200),
            comment("Read run state"),
            comment("BDUT returns run state RUNSTATE_HALTED and/or RUNSTATE_READY (intermediate state), so any state is accepted"),
            inject("BC #EDI #BDUT 65 43 D5 #TEST_OBJ_IDX 06 10 01"),
            expect("B0 #BDUT #EDI 60 C2", 0),
            expect("BC #BDUT #EDI 66 43 D6 #TEST_OBJ_IDX 06 10 01 ??", 400),
            inject_delay("B0 #EDI #BDUT 60 C2", 200),
            comment("In case of an intermediate RUNSTATE_HALTED and/or RUNSTATE_Ready, observe a wait time to ensure that the application has started."),
            wait(2000),
            comment("Read run state"),
            comment("Acceptance: BDUT returns run state RUNSTATE_RUNNING. RUNSTATE_TERMINATED does not survive the reset: 03/05/01 §4.24.2.2 keeps the run state in volatile memory and Table 97 note d) starts every reset in HALTED, from where a loaded executable part cascades back to RUNNING."),
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
            comment("Impossible, as RUNSTATE_TERMINATED after RUNCONTROL_STOP would result only if the application were loaded, which is not the case here. 03/05/01 §4.24.2.3.3 note c): \"Even if not shown explicitly, the event Stop shall always lead to the state Terminated; this shall only be possible if the corresponding Load State Machine is in the state Loaded.\""),
            comment("The template reduced this case to that observation and sends no telegrams. The transcription here used to unload the application first and expect RUNSTATE_TERMINATED anyway. What follows is not part of the case: it reloads the application so the suites after this one start from a loaded device."),
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
            comment("The template interposed seven LOAD_EVENT_SEGMENT writes here and removed them in v8 (2025-01-07), keeping only a note in v9 that a device needing its executable part loaded explicitly may have to put them back. Ours does not: LOAD_EVENT_START followed by LOAD_EVENT_COMPLETE is a whole load. Their segment selectors were AbsoluteData / AbsoluteTask / TaskCtrl1, none of which we implement, so each answered LOAD_STATE_ERROR."),
            comment("Send to application program object a LOAD_EVENT_COMPLETE"),
            comment("BDUT returns load state LOAD_STATE_LOADED"),
            inject("BC #EDI #BDUT 6F 4B D7 #TEST_OBJ_IDX 05 10 01 02 00 00 00 00 00 00 00 00 00"),
            expect("B0 #BDUT #EDI 60 CA", 0),
            expect("BC #BDUT #EDI 66 4B D6 #TEST_OBJ_IDX 05 10 01 01", 400),
            inject_delay("B0 #EDI #BDUT 60 CA", 200),
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
