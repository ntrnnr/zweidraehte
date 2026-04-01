//! Section 6 — PID_OPERATION_MODE and PID_GO_DIAGNOSTICS (partial).
//!
//! Only property description verification tests are implemented.
//! The function property command/state tests require PID_OPERATION_MODE
//! and PID_GO_DIAGNOSTICS implementations which are not yet available.

use crate::{TestCase, TestSuite};
use super::variables::create_security_variables;
use crate::tests::helpers::*;

const TIMEOUT: u32 = 3000;

pub fn create_section_6_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("6.1/6.2 PID_OPERATION_MODE / PID_GO_DIAGNOSTICS", variables)
        .secure()
        .with_preparation(vec![
            comment("Set BDUT individual address"),
            inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
            wait(1000),
        ])
        .with_cases(vec![
            test_6_1_1(),
            test_6_2_1(),
        ])
}

// ============================================================================
// 6.1.1 Property description of PID_OPERATION_MODE
// ============================================================================

fn test_6_1_1() -> TestCase {
    TestCase::new("6.1.1 PropertyDescription of PID_OPERATION_MODE").with_steps(vec![
        comment("Read description of PID 0x34 (OPERATION_MODE) on Application Program (IOT 0x0003)"),
        // 01 D2 = PropertyExtDescriptionRead, IOT=0x0003, inst=0x0010, PID=0x34
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 03 00 10 34 00 00"),
        // Response: property should exist with PDT_FUNCTION (0xBE = PDT_Function in encoded form?)
        // Wildcard most fields, just verify it returns a non-zero descriptor.
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 03 00 10 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 6.2.1 Property description of PID_GO_DIAGNOSTICS
// ============================================================================

fn test_6_2_1() -> TestCase {
    TestCase::new("6.2.1 PropertyDescription of PID_GO_DIAGNOSTICS").with_steps(vec![
        comment("Read description of PID 0x42 (GO_DIAGNOSTICS) on GroupObjectTable (IOT 0x0009)"),
        // 01 D2 = PropertyExtDescriptionRead, IOT=0x0009, inst=0x0010, PID=0x42
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 09 00 10 42 00 00"),
        // Response: should return a valid descriptor.
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 09 00 10 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
            TIMEOUT,
        ),
    ])
}
