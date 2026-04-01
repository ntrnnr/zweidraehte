//! Section 4.5 — `A_PropertyExtDescription_Read` / Response PDU (6 cases).
//!
//! Tests the extended property description service which uses IOT+instance
//! addressing. Error cases return all-zero descriptor fields.

use crate::{TestCase, TestSuite};
use super::variables::create_security_variables;
use crate::tests::helpers::*;

const TIMEOUT: u32 = 3000;

pub fn create_section_4_5_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("4.5 PropertyExtDescription_Read / Response PDU", variables)
        .secure()
        .with_preparation(vec![
            comment("Set BDUT individual address"),
            inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
            wait(1000),
        ])
        .with_cases(vec![
            test_4_5_1(),
            test_4_5_2(),
            test_4_5_3(),
            test_4_5_5(),
            test_4_5_6(),
            test_4_5_7(),
            // Skipped: 4.5.4 — needs #INDX_PID_SERIAL_NO / #INDX_PID_DEVICE_CTRL variables
        ])
}

// ============================================================================
// 4.5.1 Existing property — read PID_SERIAL_NUMBER and PID_DEVICE_CONTROL descriptions
// ============================================================================

fn test_4_5_1() -> TestCase {
    TestCase::new("4.5.1 existing property description").with_steps(vec![
        comment("Read description of PID 0x0B (SERIAL_NUMBER) on Device (IOT 0, inst 0x0010)"),
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 00 00 10 0B 00 00"),
        // Response: APCI(2)+IOT(2)+INST(2)+PID(1)+descriptor(10) = 17 bytes APDU
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 00 00 10 0B ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
            TIMEOUT,
        ),
        comment("Read description of PID 0x0E (DEVICE_CONTROL) on Device"),
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 00 00 10 0E 00 00"),
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 00 00 10 0E ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 4.5.2 Non-existing Interface Object Type → all-zero descriptor
// ============================================================================

fn test_4_5_2() -> TestCase {
    TestCase::new("4.5.2 non-existing IO type").with_steps(vec![
        comment("IOT 0x000F → error response (zeros)"),
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 0F 00 10 0B 00 00"),
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 0F 00 10 0B 00 00 00 00 00 00 00 00 00 00",
            TIMEOUT,
        ),
        comment("IOT 0x8000 → error response (zeros)"),
        inject("BC #EDI #BDUT_ADDR 68 01 D2 80 00 00 10 0B 00 00"),
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 80 00 00 10 0B 00 00 00 00 00 00 00 00 00 00",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 4.5.3 Non-existing Object Instance → all-zero descriptor
// ============================================================================

fn test_4_5_3() -> TestCase {
    TestCase::new("4.5.3 non-existing IO instance").with_steps(vec![
        comment("Instance 0x0000 → error"),
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 00 00 00 0B 00 00"),
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 00 00 00 0B 00 00 00 00 00 00 00 00 00 00",
            TIMEOUT,
        ),
        comment("Instance 0x0020 → error"),
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 00 00 20 0B 00 00"),
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 00 00 20 0B 00 00 00 00 00 00 00 00 00 00",
            TIMEOUT,
        ),
        comment("Instance 0x8000 → error"),
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 00 80 00 0B 00 00"),
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 00 80 00 0B 00 00 00 00 00 00 00 00 00 00",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 4.5.5 Non-existing property index → all-zero descriptor
// ============================================================================

fn test_4_5_5() -> TestCase {
    TestCase::new("4.5.5 non-existing property index").with_steps(vec![
        comment("PropIdx 0xFF on Device → error"),
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 00 00 10 00 00 FF"),
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 00 00 10 00 00 FF 00 00 00 00 00 00 00 00",
            TIMEOUT,
        ),
        comment("PropIdx 0x0800 (high byte in desc_type field) → error"),
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 00 00 10 00 08 00"),
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 00 00 10 00 08 00 00 00 00 00 00 00 00 00",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 4.5.6 Non-zero desc_type in request → desc_type=0 in response
// ============================================================================

fn test_4_5_6() -> TestCase {
    TestCase::new("4.5.6 non-zero desc_type → response has desc_type=0").with_steps(vec![
        comment("Request with desc_type=0xF for PID 0x0B → response desc_type=0"),
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 00 00 10 0B F0 00"),
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 00 00 10 0B ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
            TIMEOUT,
        ),
        comment("Request with desc_type=0xF for PID 0x0E"),
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 00 00 10 0E F0 00"),
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 00 00 10 0E ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// 4.5.7 Non-existing PID → all-zero descriptor
// ============================================================================

fn test_4_5_7() -> TestCase {
    TestCase::new("4.5.7 non-existing PID").with_steps(vec![
        comment("PID 0xFF on Device → error"),
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 00 00 10 FF 00 00"),
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 00 00 10 FF 00 00 00 00 00 00 00 00 00 00",
            TIMEOUT,
        ),
        comment("PID 0 on non-existing instance 0x0018 → error"),
        inject("BC #EDI #BDUT_ADDR 68 01 D2 00 00 00 18 00 00 00"),
        expect(
            "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 00 00 18 00 00 00 00 00 00 00 00 00 00 00",
            TIMEOUT,
        ),
    ])
}
