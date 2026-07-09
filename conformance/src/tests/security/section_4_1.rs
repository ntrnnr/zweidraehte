//! Section 4.1 — `A_PropertyExtValue_Read` / Response PDU (11 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "4.1 PropertyExtValue_Read / ValueRes PDU".
//!
//! These tests validate the extended property services extension directly —
//! non-secure reads against various object types, instances, PIDs, and
//! error conditions. Security Mode is OFF; no secure wrapping needed.

use super::variables::create_security_variables;
use crate::tests::helpers::*;
use crate::{TestCase, TestSuite};

/// Default response timeout.
const TIMEOUT: u32 = 3000;

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_4_1_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("4.1 PropertyExtValue_Read / ValueRes PDU", variables)
        .secure()
        .with_preparation(vec![
            // 4.1.1 preparation: write IA via serial number broadcast
            comment("Set BDUT individual address via A_IndividualAddressSerialNumber_Write"),
            inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
            wait(1000),
        ])
        .with_cases(vec![
            test_4_1_1(),
            test_4_1_2(),
            test_4_1_3(),
            test_4_1_4(),
            test_4_1_5(),
            test_4_1_6(),
            test_4_1_7(),
            test_4_1_8(),
            test_4_1_9(),
            test_4_1_10(),
            test_4_1_11(),
        ])
}

fn placeholder(name: &'static str, reason: &'static str) -> TestCase {
    TestCase::new(name).with_steps(vec![comment(reason)])
}

fn test_4_1_7() -> TestCase {
    placeholder(
        "4.1.7 A_PropertyExtValue_Read, data fitting to Max APDU Length",
        "Placeholder: requires #USER_OBJ_TYPE1 / #MAX_APDU_LENGTH variables and a user-defined IO not present on the DUT.",
    )
}

fn test_4_1_8() -> TestCase {
    placeholder(
        "4.1.8 A_PropertyExtValue_Read, data exceeds Max APDU Length",
        "Placeholder: requires #USER_OBJ_TYPE1 / #MAX_APDU_LENGTH variables and a user-defined IO not present on the DUT.",
    )
}

fn test_4_1_10() -> TestCase {
    placeholder(
        "4.1.10 A_PropertyExtValue_Read, to area with higher access level (Conditional)",
        "Placeholder: requires connection-oriented A_Authorize / A_Key_Write authorization-key setup not yet supported by the harness.",
    )
}

// ============================================================================
// 4.1.1 Existing Interface Object type (Device, PID_MANUFACTURER_ID)
// ============================================================================

fn test_4_1_1() -> TestCase {
    TestCase::new("4.1.1 existing IO type").with_steps(vec![
        comment("Read PID_MANUFACTURER_ID from Device Object (type 0, instance 0x0010)"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 0C 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6B 01 CD 00 00 00 10 0C 01 00 01 ?? ??", TIMEOUT),
    ])
}

// ============================================================================
// 4.1.2 Not existing Interface Object type
// ============================================================================

fn test_4_1_2() -> TestCase {
    TestCase::new("4.1.2 non-existing IO type").with_steps(vec![
        comment("IOT 0x000F does not exist → E_ADDRESS_VOID (0xFD)"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 0F 00 10 0C 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 0F 00 10 0C 00 00 01 FD", TIMEOUT),
        comment("IOT 0x8000 does not exist → E_ADDRESS_VOID"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 80 00 00 10 0C 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 80 00 00 10 0C 00 00 01 FD", TIMEOUT),
    ])
}

// ============================================================================
// 4.1.3 Not existing Interface Object instance
// ============================================================================

fn test_4_1_3() -> TestCase {
    TestCase::new("4.1.3 non-existing IO instance").with_steps(vec![
        comment("Instance 0x0000 → E_ADDRESS_VOID"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 00 0C 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 00 0C 00 00 01 FD", TIMEOUT),
        comment("Instance 0x0020 → E_ADDRESS_VOID"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 20 0C 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 20 0C 00 00 01 FD", TIMEOUT),
        comment("Instance 0x8000 → E_ADDRESS_VOID"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 80 00 0C 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 80 00 0C 00 00 01 FD", TIMEOUT),
    ])
}

// ============================================================================
// 4.1.4 Not existing PID
// ============================================================================

fn test_4_1_4() -> TestCase {
    TestCase::new("4.1.4 non-existing PID").with_steps(vec![
        comment("PID 3 on Device Object does not exist → E_ADDRESS_VOID"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 03 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 03 00 00 01 FD", TIMEOUT),
        comment("PID 0 on Device(instance 0x0018) — non-existing instance → E_ADDRESS_VOID"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 18 00 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 18 00 00 00 01 FD", TIMEOUT),
    ])
}

// ============================================================================
// 4.1.5 Number of elements = 0
// ============================================================================

fn test_4_1_5() -> TestCase {
    TestCase::new("4.1.5 nr_of_elem = 0").with_steps(vec![
        comment("Read with count=0 → E_ADDRESS_VOID"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 0C 00 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 0C 00 00 01 FD", TIMEOUT),
    ])
}

// ============================================================================
// 4.1.6 Number of elements too big
// ============================================================================

fn test_4_1_6() -> TestCase {
    TestCase::new("4.1.6 nr_of_elem too big").with_steps(vec![
        comment("Read PID_MANUFACTURER_ID with count=2 (only 1 element) → E_ADDRESS_VOID"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 0C 02 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 0C 00 00 01 FD", TIMEOUT),
    ])
}

// ============================================================================
// 4.1.9 Start index too big
// ============================================================================

fn test_4_1_9() -> TestCase {
    TestCase::new("4.1.9 start_index too big").with_steps(vec![
        comment("Read PID_MANUFACTURER_ID at start_index=2 (only 1 element) → E_ADDRESS_VOID"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 0C 01 00 02"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 0C 00 00 02 FD", TIMEOUT),
    ])
}

// ============================================================================
// 4.1.11 Read of PDT_FUNCTION type → E_DATA_TYPE_CONFLICT
// ============================================================================

fn test_4_1_11() -> TestCase {
    TestCase::new("4.1.11 read PDT_FUNCTION → type conflict").with_steps(vec![
        comment("PID_SECURITY_MODE (51=0x33) is PDT_FUNCTION, cannot be read → E_DATA_TYPE_CONFLICT (0xFE)"),
        inject("BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 33 01 00 01"),
        expect("BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 33 00 00 01 FE", TIMEOUT),
    ])
}
