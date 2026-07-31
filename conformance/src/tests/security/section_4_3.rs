//! Section 4.3 — `A_PropertyExtValue_WriteUnCon` PDU.
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "4.3 PropertyExtValue_WriteUnCon PDU".
//!
//! WriteUnCon (APCI 0x01D0) produces NO response. Tests verify the effect
//! by reading back the target property afterward.
//!
//! Skipped: 4.3.7 (start_index=0 with >2 octets), 4.3.10 (data type conflict),
//! 4.3.11 (access level), 4.3.12 (PDT_FUNCTION).

use super::variables::create_security_variables;
use crate::tests::helpers::*;
use crate::{TestCase, TestSuite};

/// Default response timeout.
const TIMEOUT: u32 = 3000;

/// How long to wait after a WriteUnCon (no response expected) before
/// reading back to verify.
const SETTLE: u32 = 500;

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_4_3_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("4.3 PropertyExtValue_WriteUnCon PDU", variables)
        .secure()
        .with_preparation(vec![
            comment("Set BDUT individual address via A_IndividualAddressSerialNumber_Write"),
            inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
            wait(1000),
            comment("Reset PID_PROG_MODE to 0x00 (may have been changed by earlier suites)"),
            inject("BC #EDI #BDUT_ADDR 6A 01 D0 00 00 00 10 36 01 00 01 00"),
            wait(500),
        ])
        .with_cases(vec![
            test_4_3_1(),
            test_4_3_2(),
            test_4_3_3(),
            test_4_3_4(),
            test_4_3_5(),
            test_4_3_6(),
            test_4_3_8(),
            test_4_3_9(),
            test_4_3_7(),
            test_4_3_10(),
            test_4_3_11(),
            test_4_3_12(),
        ])
}

fn test_4_3_11() -> TestCase {
    TestCase::new("4.3.11 A_PropertyExtValue_WriteUnCon, to area with higher access level").with_steps(vec![
        comment("Placeholder: requires connection-oriented A_Authorize key sequence; harness does not yet drive access-level authorization."),
    ])
}

// ============================================================================
// 4.3.1 Valid write to PID_PROG_MODE
// ============================================================================

fn test_4_3_1() -> TestCase {
    TestCase::new("4.3.1 valid WriteUnCon to PID_PROG_MODE").with_steps(vec![
        comment("WriteUnCon PID_PROG_MODE = 0x01 (no response expected)"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D0 00 00 00 10 36 01 00 01 01"),
        wait(SETTLE),
        comment("Read back PID_PROG_MODE → should be 0x01"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 01", TIMEOUT),
        comment("WriteUnCon PID_PROG_MODE = 0x00 (no response expected)"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D0 00 00 00 10 36 01 00 01 00"),
        wait(SETTLE),
        comment("Read back PID_PROG_MODE → should be 0x00"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.3.2 Non-existing Interface Object type
// ============================================================================

fn test_4_3_2() -> TestCase {
    TestCase::new("4.3.2 non-existing IO type → ignored").with_steps(vec![
        comment("WriteUnCon to IOT 0x000F (non-existing) → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D0 00 0F 00 10 36 01 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged (still 0x00)"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
        comment("WriteUnCon to IOT 0x8000 (non-existing) → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D0 80 00 00 10 36 01 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE still 0x00"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.3.3 Non-existing Interface Object instance
// ============================================================================

fn test_4_3_3() -> TestCase {
    TestCase::new("4.3.3 non-existing IO instance → ignored").with_steps(vec![
        comment("WriteUnCon to instance 0x0020 (non-existing) → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D0 00 00 00 20 36 01 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged (still 0x00)"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
        comment("WriteUnCon to instance 0x8000 (non-existing) → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D0 00 00 80 00 36 01 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE still 0x00"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.3.4 Non-existing PID
// ============================================================================

fn test_4_3_4() -> TestCase {
    TestCase::new("4.3.4 non-existing PID → ignored").with_steps(vec![
        comment("WriteUnCon PID 3 on Device Object → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D0 00 00 00 10 03 01 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
        comment("WriteUnCon PID 0 on instance 0x0018 → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D0 00 00 00 18 00 01 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
        comment("WriteUnCon PID 0x0C on instance 0x0018 → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D0 00 00 00 18 0C 01 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.3.5 Count = 0
// ============================================================================

fn test_4_3_5() -> TestCase {
    TestCase::new("4.3.5 count=0 → ignored").with_steps(vec![
        comment("WriteUnCon PID_PROG_MODE with count=0 → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D0 00 00 00 10 36 00 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged (still 0x00)"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.3.6 Count too big
// ============================================================================

fn test_4_3_6() -> TestCase {
    TestCase::new("4.3.6 count too big → ignored").with_steps(vec![
        comment("WriteUnCon PID_PROG_MODE with count=2 (only 1 element) → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6B 01 D0 00 00 00 10 36 02 00 01 01 00"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged (still 0x00)"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.3.8 Start index too big
// ============================================================================

fn test_4_3_8() -> TestCase {
    TestCase::new("4.3.8 start_index too big → ignored").with_steps(vec![
        comment("WriteUnCon PID_PROG_MODE at start_index=2 → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D0 00 00 00 10 36 01 00 02 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged (still 0x00)"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.3.9 Write to read-only property (PID_SERIAL_NUMBER)
// ============================================================================

fn test_4_3_9() -> TestCase {
    TestCase::new("4.3.9 write to read-only property → ignored").with_steps(vec![
        comment("WriteUnCon to PID_SERIAL_NUMBER (PID 0x0B, read-only) → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6F 01 D0 00 00 00 10 0B 01 00 01 00 00 00 00 00 00"),
        wait(SETTLE),
        comment("Verify PID_SERIAL_NUMBER unchanged (6 bytes, wildcard)"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 0B 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6F 01 CD 00 00 00 10 0B 01 00 01 ?? ?? ?? ?? ?? ??", TIMEOUT),
    ])
}

// ============================================================================
// 4.3.7 WriteUnCon start_index=0 with >2 octets → ignored
// ============================================================================

fn test_4_3_7() -> TestCase {
    TestCase::new("4.3.7 start_index=0 with >2 octets → ignored").with_steps(vec![
        comment("WriteUnCon 6 bytes at start_index=0 to PID_PROG_MODE → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6C 01 D0 00 00 00 10 36 01 00 00 01 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.3.10 WriteUnCon data type conflict → ignored
// ============================================================================

fn test_4_3_10() -> TestCase {
    TestCase::new("4.3.10 data type conflict → ignored").with_steps(vec![
        comment("WriteUnCon 3 bytes to 1-byte PID_PROG_MODE → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6B 01 D0 00 00 00 10 36 01 00 01 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.3.12 WriteUnCon to PDT_FUNCTION property → ignored
// ============================================================================

fn test_4_3_12() -> TestCase {
    TestCase::new("4.3.12 WriteUnCon to PDT_FUNCTION → ignored").with_steps(vec![
        comment("WriteUnCon to the PDT_FUNCTION property on IO1 → ignored"),
        inject("BC #EDI #BDUT_ADDR 6C 01 D0 #USER_OBJ_TYPE1 00 10 #ACCESSIBLE_PROP3 01 00 01 00 00 01"),
        wait(SETTLE),
        comment("Verify it still answers as a function property"),
        // Four octets after the PID — return code plus three, which is
        // what the reference XML matches with `?? ?? ?? ??`. The three
        // this expected before were the shape of PID_SECURITY_MODE, the
        // stand-in `#ACCESSIBLE_PROP3` named before the Certification
        // Object had a function property of its own.
        inject("BC #EDI #BDUT_ADDR 68 01 D5 #USER_OBJ_TYPE1 00 10 #ACCESSIBLE_PROP3 00 00"),
        expect("BC #BDUT_ADDR #EDI 6A 01 D6 #USER_OBJ_TYPE1 00 10 #ACCESSIBLE_PROP3 ?? ?? ?? ??", TIMEOUT),
    ])
}
