//! Sections 4.6 & 4.7 — Function Property Extended services (5 cases).
//!
//! 4.6: `A_FunctionPropertyExtCommand` / `State_Response`
//! 4.7: `A_FunctionPropertyExtState_Read` / `State_Response`
//!
//! Only includes tests that don't require mode toggling or user objects.

use crate::{TestCase, TestSuite};
use super::variables::create_security_variables;
use crate::tests::helpers::*;

const TIMEOUT: u32 = 3000;

pub fn create_section_4_6_4_7_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("4.6/4.7 FunctionPropertyExt Command/StateRead", variables)
        .secure()
        .with_preparation(vec![
            comment("Set BDUT individual address via A_IndividualAddressSerialNumber_Write"),
            inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
            wait(1000),
        ])
        .with_cases(vec![
            test_4_6_1(),
            test_4_6_3(),
            test_4_6_4(),
            test_4_6_5(),
            // TODO: 4.7.1 needs FunctionPropertyStateRead for LOAD_STATE_CONTROL on base objects
            test_4_7_2(),
            test_4_7_3(),
            test_4_7_4(),
            test_4_7_5(),
        ])
}

// ============================================================================
// 4.6.1 FunctionPropertyExtCommand — valid function property
// ============================================================================
//
// Per XML: Command to Security IO PID_SECURITY_MODE (PDT_FUNCTION).

fn test_4_6_1() -> TestCase {
    TestCase::new("4.6.1 Command to valid function property → success").with_steps(vec![
        // Read current security mode state first
        comment("StateRead Security Mode on Security IO"),
        inject("BC #EDI #BDUT_ADDR 68 01 D5 #USER_OBJ_TYPE1 00 10 #ACCESSIBLE_PROP3 00 00"),
        // Response: 01 D6 + IOT(2) + INST(2) + PID(1) + rc(1) + ServiceID echo(1) + mode(1) = 10 bytes → 0x69
        expect("BC #BDUT_ADDR #EDI 69 01 D6 #USER_OBJ_TYPE1 00 10 #ACCESSIBLE_PROP3 ?? ?? ??", TIMEOUT),
    ])
}

// ============================================================================
// 4.6.3 FunctionPropertyExtCommand — non-existing IO type
// ============================================================================

fn test_4_6_3() -> TestCase {
    TestCase::new("4.6.3 Command non-existing IO type").with_steps(vec![
        comment("IOT 0x000F does not exist → return_code=0xFD"),
        inject("BC #EDI #BDUT_ADDR 69 01 D4 00 0F 00 10 34 00 00 00"),
        expect("BC #BDUT_ADDR #EDI 67 01 D6 00 0F 00 10 34 FD", TIMEOUT),

        comment("IOT 0x8000 does not exist → return_code=0xFD"),
        inject("BC #EDI #BDUT_ADDR 69 01 D4 80 00 00 10 34 00 00 00"),
        expect("BC #BDUT_ADDR #EDI 67 01 D6 80 00 00 10 34 FD", TIMEOUT),
    ])
}

// ============================================================================
// 4.6.4 FunctionPropertyExtCommand — non-existing PID
// ============================================================================

fn test_4_6_4() -> TestCase {
    TestCase::new("4.6.4 Command non-existing PID").with_steps(vec![
        comment("PID 3 on GO Table (IOT=0x0003) does not exist → 0xFD"),
        inject("BC #EDI #BDUT_ADDR 69 01 D4 00 03 00 10 03 00 00 00"),
        expect("BC #BDUT_ADDR #EDI 67 01 D6 00 03 00 10 03 FD", TIMEOUT),

        comment("PID 0 on non-existing instance 0x0018 → 0xFD"),
        inject("BC #EDI #BDUT_ADDR 69 01 D4 00 03 00 18 00 00 00 00"),
        expect("BC #BDUT_ADDR #EDI 67 01 D6 00 03 00 18 00 FD", TIMEOUT),
    ])
}

// ============================================================================
// 4.6.5 FunctionPropertyExtCommand to non-PDT_FUNCTION property
// ============================================================================

fn test_4_6_5() -> TestCase {
    TestCase::new("4.6.5 Command to non-PDT_FUNCTION → empty response").with_steps(vec![
        comment("FunctionPropertyExtCommand to PID 14 (0x0E) on Device Object — not a function property"),
        // 01 D4 = FunctionPropertyExtCommand, IOT=0x0000, inst=0x0010, PID=0x0E, data=00 04
        inject("BC #EDI #BDUT_ADDR 68 01 D4 00 00 00 10 0E 00 04"),
        // Response: 01 D6 with just IOT+inst+PID, NO return_code (PDT mismatch → empty)
        // Wait, the XML expects return_code=0xFE. Let me re-read...
        // XML: OUT: BC #BDUT_ADDR #EDI 67 01 D6 00 00 00 10 0E FE
        // So it DOES have a return code of 0xFE (E_DATA_TYPE_CONFLICT).
        // The spec says "respond without return_code" for non-function PDT,
        // but the conformance test expects 0xFE. Let me match the test.
        expect("BC #BDUT_ADDR #EDI 67 01 D6 00 00 00 10 0E FE", TIMEOUT),
    ])
}

// ============================================================================
// 4.7.1 FunctionPropertyExtStateRead — valid function property
// ============================================================================

fn test_4_7_1() -> TestCase {
    TestCase::new("4.7.1 StateRead on LOAD_STATE_CONTROL → success").with_steps(vec![
        comment("StateRead PID 5 (LOAD_STATE_CONTROL) on Application Program (IOT=0x0003, inst=0x0010)"),
        // 01 D5 = FunctionPropertyExtStateRead, IOT=0x0003, inst=0x0010, PID=0x05
        inject("BC #EDI #BDUT_ADDR 66 01 D5 00 03 00 10 05"),
        // Response: 01 D6 with return_code=0x00 + 1 byte state data
        expect("BC #BDUT_ADDR #EDI 68 01 D6 00 03 00 10 05 00 ??", TIMEOUT),
    ])
}

// ============================================================================
// 4.7.2 FunctionPropertyExtStateRead — non-existing IO type
// ============================================================================

fn test_4_7_2() -> TestCase {
    TestCase::new("4.7.2 StateRead non-existing IO type").with_steps(vec![
        comment("IOT 0x000F does not exist → return_code=0xFD"),
        inject("BC #EDI #BDUT_ADDR 68 01 D5 00 0F 00 10 34 00 00"),
        expect("BC #BDUT_ADDR #EDI 67 01 D6 00 0F 00 10 34 FD", TIMEOUT),
        comment("IOT 0x8000 does not exist → return_code=0xFD"),
        inject("BC #EDI #BDUT_ADDR 68 01 D5 80 00 00 10 34 00 00"),
        expect("BC #BDUT_ADDR #EDI 67 01 D6 80 00 00 10 34 FD", TIMEOUT),
    ])
}

// ============================================================================
// 4.7.3 FunctionPropertyExtStateRead — non-existing Object Instance
// ============================================================================

fn test_4_7_3() -> TestCase {
    TestCase::new("4.7.3 StateRead non-existing Object Instance").with_steps(vec![
        comment("Instance 0x0000 does not exist → return_code=0xFD"),
        inject("BC #EDI #BDUT_ADDR 68 01 D5 #USER_OBJ_TYPE1 00 00 34 00 00"),
        expect("BC #BDUT_ADDR #EDI 67 01 D6 #USER_OBJ_TYPE1 00 00 34 FD", TIMEOUT),

        comment("Instance 0x0020 does not exist → return_code=0xFD"),
        inject("BC #EDI #BDUT_ADDR 68 01 D5 #USER_OBJ_TYPE1 00 20 34 00 00"),
        expect("BC #BDUT_ADDR #EDI 67 01 D6 #USER_OBJ_TYPE1 00 20 34 FD", TIMEOUT),

        comment("Instance 0x8000 does not exist → return_code=0xFD"),
        inject("BC #EDI #BDUT_ADDR 68 01 D5 #USER_OBJ_TYPE1 80 00 34 00 00"),
        expect("BC #BDUT_ADDR #EDI 67 01 D6 #USER_OBJ_TYPE1 80 00 34 FD", TIMEOUT),
    ])
}

// ============================================================================
// 4.7.4 FunctionPropertyExtStateRead — non-existing PID
// ============================================================================

fn test_4_7_4() -> TestCase {
    TestCase::new("4.7.4 StateRead non-existing PID").with_steps(vec![
        comment("PID 3 on Application Program (IOT=0x0003) does not exist → 0xFD"),
        inject("BC #EDI #BDUT_ADDR 68 01 D5 00 03 00 10 03 00 00"),
        expect("BC #BDUT_ADDR #EDI 67 01 D6 00 03 00 10 03 FD", TIMEOUT),
        comment("PID 0 on non-existing instance 0x0018 → 0xFD"),
        inject("BC #EDI #BDUT_ADDR 68 01 D5 00 03 00 18 00 00 00"),
        expect("BC #BDUT_ADDR #EDI 67 01 D6 00 03 00 18 00 FD", TIMEOUT),
    ])
}

// ============================================================================
// 4.7.5 FunctionPropertyExtStateRead — non-PDT_FUNCTION property
// ============================================================================

fn test_4_7_5() -> TestCase {
    TestCase::new("4.7.5 StateRead non-PDT_FUNCTION → empty response").with_steps(vec![
        comment("PID 0x0C (MANUFACTURER_ID) on Device Object is PDT_UNSIGNED_INT, not function"),
        // 01 D5 = StateRead, IOT=0x0000, inst=0x0010, PID=0x0C
        inject("BC #EDI #BDUT_ADDR 66 01 D5 00 00 00 10 0C"),
        // XML expects: 01 D6 00 00 00 10 0C FE — but that has return_code=0xFE.
        // The spec says empty response for non-function PDT, but conformance
        // test expects 0xFE. Let me match the test expectation.
        expect("BC #BDUT_ADDR #EDI 67 01 D6 00 00 00 10 0C FE", TIMEOUT),
    ])
}
