//! Section 4.4 — `A_PropertyExtValue_InfoReport` PDU.
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "4.4 PropertyExtValue_InfoReport PDU".
//!
//! InfoReport (APCI 0x01D1) must be completely IGNORED by the device — no
//! response is sent and no state is changed. Each test injects an InfoReport
//! and then reads back the property to verify nothing changed.
//!
//! Skipped: 4.4.7 (start_index=0 with >2 octets), 4.4.10 (connection-oriented),
//! 4.4.11 (user objects).

use super::variables::create_security_variables;
use crate::tests::helpers::*;
use crate::{TestCase, TestSuite};

/// Default response timeout.
const TIMEOUT: u32 = 3000;

/// How long to wait after an InfoReport (no response expected) before
/// reading back to verify.
const SETTLE: u32 = 500;

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_4_4_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("4.4 PropertyExtValue_InfoReport PDU", variables)
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
            test_4_4_1(),
            test_4_4_2(),
            test_4_4_3(),
            test_4_4_4(),
            test_4_4_5(),
            test_4_4_6(),
            test_4_4_8(),
            test_4_4_9(),
            test_4_4_7(),
            test_4_4_10(),
            // Skipped: 4.4.11 — access level restrictions (needs Authorize sequence)
        ])
}

// ============================================================================
// 4.4.1 InfoReport to valid property → ignored
// ============================================================================

fn test_4_4_1() -> TestCase {
    TestCase::new("4.4.1 InfoReport to valid property → ignored").with_steps(vec![
        comment("InfoReport PID_PROG_MODE = 0x01 → must be ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D1 00 00 00 10 36 01 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged (still 0x00)"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.4.2 InfoReport to non-existing IO type → ignored
// ============================================================================

fn test_4_4_2() -> TestCase {
    TestCase::new("4.4.2 non-existing IO type → ignored").with_steps(vec![
        comment("InfoReport to IOT 0x000F → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D1 00 0F 00 10 36 01 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
        comment("InfoReport to IOT 0x8000 → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D1 80 00 00 10 36 01 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.4.3 InfoReport to non-existing IO instance → ignored
// ============================================================================

fn test_4_4_3() -> TestCase {
    TestCase::new("4.4.3 non-existing IO instance → ignored").with_steps(vec![
        comment("InfoReport to instance 0x0020 → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D1 00 00 00 20 36 01 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
        comment("InfoReport to instance 0x8000 → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D1 00 00 80 00 36 01 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.4.4 InfoReport to non-existing PID → ignored
// ============================================================================

fn test_4_4_4() -> TestCase {
    TestCase::new("4.4.4 non-existing PID → ignored").with_steps(vec![
        comment("InfoReport PID 3 on Device Object → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D1 00 00 00 10 03 01 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.4.5 InfoReport with count=0 → ignored
// ============================================================================

fn test_4_4_5() -> TestCase {
    TestCase::new("4.4.5 count=0 → ignored").with_steps(vec![
        comment("InfoReport PID_PROG_MODE with count=0 → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D1 00 00 00 10 36 00 00 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.4.6 InfoReport with count too big → ignored
// ============================================================================

fn test_4_4_6() -> TestCase {
    TestCase::new("4.4.6 count too big → ignored").with_steps(vec![
        comment("InfoReport PID_PROG_MODE with count=2 (only 1 element) → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6B 01 D1 00 00 00 10 36 02 00 01 01 00"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.4.8 InfoReport with start_index too big → ignored
// ============================================================================

fn test_4_4_8() -> TestCase {
    TestCase::new("4.4.8 start_index too big → ignored").with_steps(vec![
        comment("InfoReport PID_PROG_MODE at start_index=2 → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6A 01 D1 00 00 00 10 36 01 00 02 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.4.9 InfoReport to read-only property → ignored
// ============================================================================

fn test_4_4_9() -> TestCase {
    TestCase::new("4.4.9 InfoReport to read-only property → ignored").with_steps(vec![
        comment("InfoReport to PID_SERIAL_NUMBER (PID 0x0B, read-only) → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6F 01 D1 00 00 00 10 0B 01 00 01 00 00 00 00 00 00"),
        wait(SETTLE),
        comment("Verify PID_SERIAL_NUMBER unchanged (6 bytes, wildcard)"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 0B 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6F 01 CD 00 00 00 10 0B 01 00 01 ?? ?? ?? ?? ?? ??", TIMEOUT),
    ])
}

// ============================================================================
// 4.4.7 InfoReport index=0 with >2 octets → ignored
// ============================================================================

fn test_4_4_7() -> TestCase {
    TestCase::new("4.4.7 InfoReport index=0 with >2 octets → ignored").with_steps(vec![
        comment("InfoReport 6 bytes at start_index=0 to PID_PROG_MODE → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6C 01 D1 00 00 00 10 36 01 00 01 01 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}

// ============================================================================
// 4.4.10 InfoReport data type conflict → ignored
// ============================================================================

fn test_4_4_10() -> TestCase {
    TestCase::new("4.4.10 InfoReport data type conflict → ignored").with_steps(vec![
        comment("InfoReport 3 bytes to 1-byte PID_PROG_MODE → silently ignored"),
        inject("BC #EDI #BDUT_ADDR 6C 01 D1 00 00 00 10 36 01 00 01 01 01 01"),
        wait(SETTLE),
        comment("Verify PID_PROG_MODE unchanged"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 36 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 36 01 00 01 00", TIMEOUT),
    ])
}
