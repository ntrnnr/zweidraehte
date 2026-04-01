//! Section 3.8.1 — `PID_OBJECT_TYPE` access policy `3FF/0CC` (3 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.1 PID_OBJECT_TYPE".
//!
//! Tests PID 1 (PID_OBJECT_TYPE) on the Security Interface Object
//! (IOT=0x0011, instance=0x0010). Access policy is `3FF/0CC`: requires A+C
//! when Security Mode is ON. Each test case toggles Security Mode ON and OFF
//! via `A_FunctionPropertyExtCommand` (APCI 0x01D4) to verify access under
//! both modes.

use crate::{TestCase, TestSuite};
use super::variables::create_security_variables;
use crate::tests::helpers::*;

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

// ============================================================================
// Security Mode Toggle Templates
// ============================================================================

// A_FunctionPropertyExtCommand (0x01D4) on Security IO (0x0011, instance 0x0010),
// PID_SECURITY_MODE (0x33): reserved=0x00, ServiceID=0x00 (Write Security Mode),
// ServiceInfo=0x01 (Enable).
const ENABLE_SECURITY_MODE: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";

// Expected A_FunctionPropertyExtState_Response (0x01D6): return_code=0x00 (success).
// APDU: 01 D6(APCI) + 00 11(IOT) + 00 10(inst) + 33(PID) + 00(rc) = 8 bytes → TP1 len = 07
const ENABLE_SECURITY_MODE_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 07 01 D6 00 11 00 10 33 00";

// Same as above but ServiceInfo=0x00 (Disable).
const DISABLE_SECURITY_MODE: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";

const DISABLE_SECURITY_MODE_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 07 01 D6 00 11 00 10 33 00";

// ============================================================================
// PropertyExtValueRead / Response templates for PID 1 on Security IO
// ============================================================================

// Plain (non-secure) A_PropertyExtValueRead: IOT=0x0011, instance=0x0010,
// PID=1 (ObjectType), count=1, start=1.
const PLAIN_READ_PID1: &str =
    "BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 01 01 00 01";

// Plain error response: count=0, return_code=0xFC (E_ACCESS_DENIED).
const PLAIN_READ_PID1_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 01 00 00 01 FC";

// Plain success response: count=1, data=0x0011 (Security object type).
const PLAIN_READ_PID1_OK: &str =
    "BC #BDUT_ADDR #EDI 6B 01 CD 00 11 00 10 01 01 00 01 00 11";

// Secure read template (same inner APDU, carried in extended frame for secure wrapping).
const SECURE_READ_PID1: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 01 01 00 01";

// Secure error response: count=0, return_code=0xFC.
const SECURE_READ_PID1_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 01 00 00 01 FC";

// Secure success response: count=1, data=0x0011.
const SECURE_READ_PID1_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0B 01 CD 00 11 00 10 01 01 00 01 00 11";

// ============================================================================
// PropertyExtValueWriteCon / Response templates for PID 1 on Security IO
// ============================================================================

// Plain WriteCon: write value 0x0018 to PID 1 (read-only, will fail).
const PLAIN_WRITE_PID1: &str =
    "BC #EDI #BDUT_ADDR 6A 01 CE 00 11 00 10 01 01 00 01 00 18";

// Plain write error response: count=0, return_code=0xFB (E_ACCESS_READ_ONLY).
const PLAIN_WRITE_PID1_RO: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CF 00 11 00 10 01 00 00 01 FB";

// Secure WriteCon template.
const SECURE_WRITE_PID1: &str =
    "3C 60 #EDI #BDUT_ADDR 0A 01 CE 00 11 00 10 01 01 00 01 00 18";

// Secure write error response: return_code=0xFB.
const SECURE_WRITE_PID1_RO: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 01 00 00 01 FB";

// ============================================================================
// PropertyExtDescription_Read / Response templates for PID 1 on Security IO
// ============================================================================

// Plain A_PropertyExtDescription_Read (0x01D2): IOT=0x0011, instance=0x0010,
// PID=1 (ObjectType), description index=0x00, property index=0x00.
const PLAIN_DESC_READ_PID1: &str =
    "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 01 00 00";

// Plain error response: all-zero descriptor (access denied, no error code — just zeroed).
// APDU: 01 D3 + 00 11 + 00 10 + 01 + 00 00 00 00 00 00 00 00 00 00 = 16 bytes
const PLAIN_DESC_READ_PID1_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 01 00 00 00 00 00 00 00 00 00 00";

// Plain success response: valid descriptor (wildcard data bytes).
const PLAIN_DESC_READ_PID1_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_1_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.1 PID_OBJECT_TYPE (Security IO, access 3FF/0CC)", variables)
        .secure()
        .with_cases(vec![
            test_3_8_1_1(),
            test_3_8_1_2(),
            test_3_8_1_3(),
        ])
}

// ============================================================================
// 3.8.1.1 PropertyValueRead plain, A or A+C
// ============================================================================

fn test_3_8_1_1() -> TestCase {
    TestCase::new("3.8.1.1 PropertyValueRead plain, A or A+C").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain read → E_ACCESS_DENIED (security mode requires A+C)"),
        inject(PLAIN_READ_PID1),
        expect(PLAIN_READ_PID1_DENIED, TIMEOUT),

        comment("Auth-only secure read → E_ACCESS_DENIED (needs A+C, not just A)"),
        inject_secure_ao(SECURE_READ_PID1, "TK1"),
        expect_secure_ao(SECURE_READ_PID1_DENIED, "TK1", TIMEOUT),

        comment("A+C secure read → success (0x0011)"),
        inject_secure_ac(SECURE_READ_PID1, "TK1"),
        expect_secure_ac(SECURE_READ_PID1_OK, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain read → success"),
        inject(PLAIN_READ_PID1),
        expect(PLAIN_READ_PID1_OK, TIMEOUT),

        comment("Auth-only secure read → success"),
        inject_secure_ao(SECURE_READ_PID1, "TK1"),
        expect_secure_ao(SECURE_READ_PID1_OK, "TK1", TIMEOUT),

        comment("A+C secure read → success"),
        inject_secure_ac(SECURE_READ_PID1, "TK1"),
        expect_secure_ac(SECURE_READ_PID1_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.1.2 PropertyValueWrite plain, A or A+C
// ============================================================================

fn test_3_8_1_2() -> TestCase {
    TestCase::new("3.8.1.2 PropertyValueWrite plain, A or A+C").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain write → E_ACCESS_READ_ONLY (PID_OBJECT_TYPE is read-only)"),
        inject(PLAIN_WRITE_PID1),
        expect(PLAIN_WRITE_PID1_RO, TIMEOUT),

        comment("Auth-only secure write → E_ACCESS_READ_ONLY"),
        inject_secure_ao(SECURE_WRITE_PID1, "TK1"),
        expect_secure_ao(SECURE_WRITE_PID1_RO, "TK1", TIMEOUT),

        comment("A+C secure write → E_ACCESS_READ_ONLY"),
        inject_secure_ac(SECURE_WRITE_PID1, "TK1"),
        expect_secure_ac(SECURE_WRITE_PID1_RO, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain write → E_ACCESS_READ_ONLY"),
        inject(PLAIN_WRITE_PID1),
        expect(PLAIN_WRITE_PID1_RO, TIMEOUT),

        comment("Auth-only secure write → E_ACCESS_READ_ONLY"),
        inject_secure_ao(SECURE_WRITE_PID1, "TK1"),
        expect_secure_ao(SECURE_WRITE_PID1_RO, "TK1", TIMEOUT),

        comment("A+C secure write → E_ACCESS_READ_ONLY"),
        inject_secure_ac(SECURE_WRITE_PID1, "TK1"),
        expect_secure_ac(SECURE_WRITE_PID1_RO, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.1.3 PropertyDescriptionRead plain
// ============================================================================

fn test_3_8_1_3() -> TestCase {
    TestCase::new("3.8.1.3 PropertyDescriptionRead plain").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain description read → all-zero response (access denied)"),
        inject(PLAIN_DESC_READ_PID1),
        expect(PLAIN_DESC_READ_PID1_DENIED, TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain description read → valid descriptor"),
        inject(PLAIN_DESC_READ_PID1),
        expect(PLAIN_DESC_READ_PID1_OK, TIMEOUT),
    ])
}
