//! Section 3.8.6 — `PID_IO_LIST` access policy `3FF/0CC` (3 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.6 PID_IO_LIST".
//!
//! Tests PID 0x47 (PID_IO_LIST, i.e. PID 71) on the Device Object
//! (IOT=0x0000, instance=0x0010). Access policy is `3FF/0CC`: requires A+C
//! when Security Mode is ON. The property is read-only (2 bytes per element,
//! variable count). This PID is [optional-recommended].

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
    "3C 60 #BDUT_ADDR #EDI 07 01 D6 00 11 00 10 33 00";

const DISABLE_SECURITY_MODE: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";

const DISABLE_SECURITY_MODE_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 07 01 D6 00 11 00 10 33 00";

// ============================================================================
// PropertyExtValueRead / Response templates for PID 0x47 on Device Object
// ============================================================================

// Plain (non-secure) A_PropertyExtValueRead: IOT=0x0000, instance=0x0010,
// PID=0x47 (IO_LIST), count=0x02, start=0x01.
// APDU: 01 CC + 00 00 + 00 10 + 47 + 02 + 00 01 = 10 bytes → TP1 len = 0x69
const PLAIN_READ_PID47: &str =
    "BC #EDI #BDUT_ADDR 69 01 CC 00 00 00 10 47 02 00 01";

// Plain error response: count=0, return_code=0xFC (E_ACCESS_DENIED).
// APDU: 01 CD + 00 00 + 00 10 + 47 + 00 + 00 01 + FC = 11 bytes → TP1 len = 0x6A
const PLAIN_READ_PID47_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 00 00 10 47 00 00 01 FC";

// Plain success response: count=2, data = 2 entries × 2 bytes = 4 bytes (wildcard).
// First entry is always 0x0000 (Device Object), second is wildcard.
// APDU: 01 CD + 00 00 + 00 10 + 47 + 02 + 00 01 + 00 00 ?? ?? = 14 bytes
// → TP1 len = 0x6D (standard frame: 0x60 | 13)
const PLAIN_READ_PID47_OK: &str =
    "BC #BDUT_ADDR #EDI 6D 01 CD 00 00 00 10 47 02 00 01 00 00 ?? ??";

// Secure read template (same inner APDU, carried in extended frame for secure wrapping).
const SECURE_READ_PID47: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 00 00 10 47 02 00 01";

// Secure error response: count=0, return_code=0xFC.
const SECURE_READ_PID47_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 00 00 10 47 00 00 01 FC";

// Secure success response: count=2, data = 4 bytes (wildcard).
// APDU: 14 bytes → extended frame len = 0x0D
const SECURE_READ_PID47_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0D 01 CD 00 00 00 10 47 02 00 01 00 00 ?? ??";

// ============================================================================
// PropertyExtValueWriteCon / Response templates for PID 0x47 on Device Object
// ============================================================================

// Plain WriteCon: write 4 bytes (0x11 × 4) to PID 0x47 (read-only, will fail).
// count=0x02, start=0x01, data = 11 11 11 11.
// APDU: 01 CE + 00 00 + 00 10 + 47 + 02 + 00 01 + 11 11 11 11 = 14 bytes
// → TP1 len = 0x6D (standard frame: 0x60 | 13)
const PLAIN_WRITE_PID47: &str =
    "BC #EDI #BDUT_ADDR 6D 01 CE 00 00 00 10 47 02 00 01 11 11 11 11";

// Plain write error response: count=0, return_code=0xFB (E_ACCESS_READ_ONLY).
// APDU: 01 CF + 00 00 + 00 10 + 47 + 00 + 00 01 + FB = 11 bytes → TP1 len = 0x6A
const PLAIN_WRITE_PID47_RO: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CF 00 00 00 10 47 00 00 01 FB";

// Secure WriteCon template.
const SECURE_WRITE_PID47: &str =
    "3C 60 #EDI #BDUT_ADDR 0D 01 CE 00 00 00 10 47 02 00 01 11 11 11 11";

// Secure write error response: return_code=0xFB.
const SECURE_WRITE_PID47_RO: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 00 00 10 47 00 00 01 FB";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_6_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.6 PID_IO_LIST (Device Object, access 3FF/0CC) [optional-recommended]", variables)
        .secure()
        .with_cases(vec![
            test_3_8_6_1(),
            test_3_8_6_2(),
            // Skipped: 3.8.6.3 — uses A_PropertyExtDescription_Read (0x01D2),
            //   which is not yet implemented.
        ])
}

// ============================================================================
// 3.8.6.1 PropertyValueRead plain, A or A+C
// ============================================================================

fn test_3_8_6_1() -> TestCase {
    TestCase::new("3.8.6.1 PropertyValueRead plain, A or A+C").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain read → E_ACCESS_DENIED (security mode requires A+C)"),
        inject(PLAIN_READ_PID47),
        expect(PLAIN_READ_PID47_DENIED, TIMEOUT),

        comment("Auth-only secure read → E_ACCESS_DENIED (needs A+C, not just A)"),
        inject_secure_ao(SECURE_READ_PID47, "TK1"),
        expect_secure_ao(SECURE_READ_PID47_DENIED, "TK1", TIMEOUT),

        comment("A+C secure read → success (IO list)"),
        inject_secure_ac(SECURE_READ_PID47, "TK1"),
        expect_secure_ac(SECURE_READ_PID47_OK, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain read → success"),
        inject(PLAIN_READ_PID47),
        expect(PLAIN_READ_PID47_OK, TIMEOUT),

        comment("Auth-only secure read → success"),
        inject_secure_ao(SECURE_READ_PID47, "TK1"),
        expect_secure_ao(SECURE_READ_PID47_OK, "TK1", TIMEOUT),

        comment("A+C secure read → success"),
        inject_secure_ac(SECURE_READ_PID47, "TK1"),
        expect_secure_ac(SECURE_READ_PID47_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.6.2 PropertyValueWrite plain, A or A+C
// ============================================================================

fn test_3_8_6_2() -> TestCase {
    TestCase::new("3.8.6.2 PropertyValueWrite plain, A or A+C").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain write → E_ACCESS_READ_ONLY (PID_IO_LIST is read-only)"),
        inject(PLAIN_WRITE_PID47),
        expect(PLAIN_WRITE_PID47_RO, TIMEOUT),

        comment("Auth-only secure write → E_ACCESS_READ_ONLY"),
        inject_secure_ao(SECURE_WRITE_PID47, "TK1"),
        expect_secure_ao(SECURE_WRITE_PID47_RO, "TK1", TIMEOUT),

        comment("A+C secure write → E_ACCESS_READ_ONLY"),
        inject_secure_ac(SECURE_WRITE_PID47, "TK1"),
        expect_secure_ac(SECURE_WRITE_PID47_RO, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain write → E_ACCESS_READ_ONLY"),
        inject(PLAIN_WRITE_PID47),
        expect(PLAIN_WRITE_PID47_RO, TIMEOUT),

        comment("Auth-only secure write → E_ACCESS_READ_ONLY"),
        inject_secure_ao(SECURE_WRITE_PID47, "TK1"),
        expect_secure_ao(SECURE_WRITE_PID47_RO, "TK1", TIMEOUT),

        comment("A+C secure write → E_ACCESS_READ_ONLY"),
        inject_secure_ac(SECURE_WRITE_PID47, "TK1"),
        expect_secure_ac(SECURE_WRITE_PID47_RO, "TK1", TIMEOUT),
    ])
}
