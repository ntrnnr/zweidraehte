//! Section 3.8.4 — `PID_MANUFACTURER_ID` access policy `3FF/0CC` (3 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.4 PID_MANUFACTURER_ID".
//!
//! Tests PID 0x0C (PID_MANUFACTURER_ID) on the Device Object
//! (IOT=0x0000, instance=0x0010). Access policy is `3FF/0CC`: requires A+C
//! when Security Mode is ON. The property is read-only (2 bytes), so all
//! writes return `E_ACCESS_READ_ONLY` (0xFB) regardless of security mode.

use crate::{TestCase, TestSuite};
use super::variables::create_security_variables;
use crate::tests::helpers::*;

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

// ============================================================================
// Security Mode Toggle Templates
// ============================================================================

const ENABLE_SECURITY_MODE: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";

const ENABLE_SECURITY_MODE_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

const DISABLE_SECURITY_MODE: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";

const DISABLE_SECURITY_MODE_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

// ============================================================================
// PropertyExtValueRead / Response templates for PID 0x0C on Device Object
// ============================================================================

// Plain (non-secure) A_PropertyExtValueRead: IOT=0x0000, instance=0x0010,
// PID=0x0C (ManufacturerID), count=1, start=1.
const PLAIN_READ_PID0C: &str =
    "BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 0C 01 00 01";

// Plain error response: count=0, return_code=0xFC (E_ACCESS_DENIED).
const PLAIN_READ_PID0C_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 0C 00 00 01 FC";

// Plain success response: count=1, data=2 bytes (manufacturer ID, wildcard).
const PLAIN_READ_PID0C_OK: &str =
    "BC #BDUT_ADDR #EDI 6B 01 CD 00 00 00 10 0C 01 00 01 ?? ??";

// Secure read template (same inner APDU, carried in extended frame for secure wrapping).
const SECURE_READ_PID0C: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 00 00 10 0C 01 00 01";

// Secure error response: count=0, return_code=0xFC.
const SECURE_READ_PID0C_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 00 00 10 0C 00 00 01 FC";

// Secure success response: count=1, data=2 bytes (manufacturer ID, wildcard).
const SECURE_READ_PID0C_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0B 01 CD 00 00 00 10 0C 01 00 01 ?? ??";

// ============================================================================
// PropertyExtValueWriteCon / Response templates for PID 0x0C on Device Object
// ============================================================================

// Plain WriteCon: write 2 bytes to PID 0x0C (read-only, will fail).
const PLAIN_WRITE_PID0C: &str =
    "BC #EDI #BDUT_ADDR 6B 01 CE 00 00 00 10 0C 01 00 01 11 11";

// Plain write error response: count=0, return_code=0xFB (E_ACCESS_READ_ONLY).
const PLAIN_WRITE_PID0C_RO: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 10 0C 00 00 01 FB";

// Secure WriteCon template.
const SECURE_WRITE_PID0C: &str =
    "3C 60 #EDI #BDUT_ADDR 0B 01 CE 00 00 00 10 0C 01 00 01 11 11";

// Secure write error response: return_code=0xFB.
const SECURE_WRITE_PID0C_RO: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 00 00 10 0C 00 00 01 FB";

// ============================================================================
// PropertyExtDescription_Read / Response templates for PID 0x0C on Device Object
// ============================================================================

// Plain A_PropertyExtDescription_Read (0x01D2): IOT=0x0000, instance=0x0010,
// PID=0x0C (ManufacturerID), description index=0x00, property index=0x00.
const PLAIN_DESC_READ_PID0C: &str =
    "BC #EDI #BDUT_ADDR 68 01 D2 00 00 00 10 0C 00 00";

// Plain error response: all-zero descriptor (access denied, no error code — just zeroed).
const PLAIN_DESC_READ_PID0C_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 00 00 10 0C 00 00 00 00 00 00 00 00 00 00";

// Plain success response: valid descriptor (wildcard data bytes).
const PLAIN_DESC_READ_PID0C_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 00 00 10 0C ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_4_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.4 PID_MANUFACTURER_ID (Device Object, access 3FF/0CC)", variables)
        .secure()
        .with_cases(vec![
            test_3_8_4_1(),
            test_3_8_4_2(),
            test_3_8_4_3(),
        ])
}

// ============================================================================
// 3.8.4.1 PropertyValueRead plain, A or A+C
// ============================================================================

fn test_3_8_4_1() -> TestCase {
    TestCase::new("3.8.4.1 PropertyValueRead plain, A or A+C").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain read → E_ACCESS_DENIED (security mode requires A+C)"),
        inject(PLAIN_READ_PID0C),
        expect(PLAIN_READ_PID0C_DENIED, TIMEOUT),

        comment("Auth-only secure read → E_ACCESS_DENIED (needs A+C, not just A)"),
        inject_secure_ao(SECURE_READ_PID0C, "TK1"),
        expect_secure_ao(SECURE_READ_PID0C_DENIED, "TK1", TIMEOUT),

        comment("A+C secure read → success (manufacturer ID)"),
        inject_secure_ac(SECURE_READ_PID0C, "TK1"),
        expect_secure_ac(SECURE_READ_PID0C_OK, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain read → success"),
        inject(PLAIN_READ_PID0C),
        expect(PLAIN_READ_PID0C_OK, TIMEOUT),

        comment("Auth-only secure read → success"),
        inject_secure_ao(SECURE_READ_PID0C, "TK1"),
        expect_secure_ao(SECURE_READ_PID0C_OK, "TK1", TIMEOUT),

        comment("A+C secure read → success"),
        inject_secure_ac(SECURE_READ_PID0C, "TK1"),
        expect_secure_ac(SECURE_READ_PID0C_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.4.2 PropertyValueWrite plain, A or A+C
// ============================================================================

fn test_3_8_4_2() -> TestCase {
    TestCase::new("3.8.4.2 PropertyValueWrite plain, A or A+C").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain write → E_ACCESS_READ_ONLY (PID_MANUFACTURER_ID is read-only)"),
        inject(PLAIN_WRITE_PID0C),
        expect(PLAIN_WRITE_PID0C_RO, TIMEOUT),

        comment("Auth-only secure write → E_ACCESS_READ_ONLY"),
        inject_secure_ao(SECURE_WRITE_PID0C, "TK1"),
        expect_secure_ao(SECURE_WRITE_PID0C_RO, "TK1", TIMEOUT),

        comment("A+C secure write → E_ACCESS_READ_ONLY"),
        inject_secure_ac(SECURE_WRITE_PID0C, "TK1"),
        expect_secure_ac(SECURE_WRITE_PID0C_RO, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain write → E_ACCESS_READ_ONLY"),
        inject(PLAIN_WRITE_PID0C),
        expect(PLAIN_WRITE_PID0C_RO, TIMEOUT),

        comment("Auth-only secure write → E_ACCESS_READ_ONLY"),
        inject_secure_ao(SECURE_WRITE_PID0C, "TK1"),
        expect_secure_ao(SECURE_WRITE_PID0C_RO, "TK1", TIMEOUT),

        comment("A+C secure write → E_ACCESS_READ_ONLY"),
        inject_secure_ac(SECURE_WRITE_PID0C, "TK1"),
        expect_secure_ac(SECURE_WRITE_PID0C_RO, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.4.3 PropertyDescriptionRead plain
// ============================================================================

fn test_3_8_4_3() -> TestCase {
    TestCase::new("3.8.4.3 PropertyDescriptionRead plain").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain description read → all-zero response (access denied)"),
        inject(PLAIN_DESC_READ_PID0C),
        expect(PLAIN_DESC_READ_PID0C_DENIED, TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain description read → valid descriptor"),
        inject(PLAIN_DESC_READ_PID0C),
        expect(PLAIN_DESC_READ_PID0C_OK, TIMEOUT),
    ])
}
