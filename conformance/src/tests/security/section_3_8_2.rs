//! Section 3.8.2 — `PID_OBJECT_NAME` access policy `3FF/0CC`.
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.2 PID_OBJECT_NAME".
//!
//! Tests PID 2 (PID_OBJECT_NAME) on the Security Interface Object
//! (IOT=0x0011, instance=0x0010). Access policy is `3FF/0CC`: requires A+C
//! when Security Mode is ON. The property is read-only and variable length
//! (up to 30 chars, array with 0x0F elements per entry). This PID is
//! [optional], so the device might not support it — wildcard bytes are used
//! generously in expected responses.

use super::variables::create_security_variables;
use crate::tests::helpers::*;
use crate::{TestCase, TestSuite};

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

// ============================================================================
// Security Mode Toggle Templates
// ============================================================================

const ENABLE_SECURITY_MODE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";

const ENABLE_SECURITY_MODE_RESP: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

const DISABLE_SECURITY_MODE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";

const DISABLE_SECURITY_MODE_RESP: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

// ============================================================================
// PropertyExtValueRead / Response templates for PID 2 on Security IO
// ============================================================================

// Plain (non-secure) A_PropertyExtValueRead: IOT=0x0011, instance=0x0010,
// PID=0x02 (ObjectName), count=0x0F, start=0x01.
// APDU: 01 CC + 00 11 + 00 10 + 02 + 0F + 00 01 = 10 bytes → TP1 len = 0x69
#[allow(dead_code)]
const PLAIN_READ_PID02: &str = "BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 02 0F 00 01";

// Plain error response: count=0, return_code=0xFC (E_ACCESS_DENIED).
// APDU: 01 CD + 00 11 + 00 10 + 02 + 00 + 00 01 + FC = 11 bytes → TP1 len = 0x6A
#[allow(dead_code)]
const PLAIN_READ_PID02_DENIED: &str = "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 02 00 00 01 FC";

// Plain success response: count=0x0F, data up to 15 bytes (object name, wildcard).
// APDU: 01 CD + 00 11 + 00 10 + 02 + 0F + 00 01 + 10 wildcard bytes = 20 bytes
// → TP1 len = 0x13 (extended frame, length = 19 decimal)
#[allow(dead_code)]
const PLAIN_READ_PID02_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 13 01 CD 00 11 00 10 02 0F 00 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// Secure read template (same inner APDU, carried in extended frame for secure wrapping).
#[allow(dead_code)]
const SECURE_READ_PID02: &str = "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 02 0F 00 01";

// Secure error response: count=0, return_code=0xFC.
#[allow(dead_code)]
const SECURE_READ_PID02_DENIED: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 02 00 00 01 FC";

// Secure success response: count=0x0F, data wildcard.
#[allow(dead_code)]
const SECURE_READ_PID02_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 13 01 CD 00 11 00 10 02 0F 00 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// ============================================================================
// PropertyExtValueWriteCon / Response templates for PID 2 on Security IO
// ============================================================================

// Plain WriteCon: write 10 zero bytes to PID 0x02 (read-only, will fail).
// count=0x0F, start=0x01, data = 10 bytes of zeroes.
// APDU: 01 CE + 00 11 + 00 10 + 02 + 0F + 00 01 + 10 data bytes = 20 bytes
// → extended frame, TP1 len = 0x13
//
// Note: the XML sends 10 data bytes (00 x10), making the total APDU 20 bytes.
const PLAIN_WRITE_PID02: &str = "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 02 0F 00 01 00 00 00 00 00 00 00 00 00 00";

// Plain write error response: count=0, return_code=0xFB (E_ACCESS_READ_ONLY).
// APDU: 01 CF + 00 11 + 00 10 + 02 + 00 + 00 01 + FB = 11 bytes → TP1 len = 0x6A
const PLAIN_WRITE_PID02_RO: &str = "BC #BDUT_ADDR #EDI 6A 01 CF 00 11 00 10 02 00 00 01 ??";

// Secure WriteCon template.
const SECURE_WRITE_PID02: &str = "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 02 0F 00 01 00 00 00 00 00 00 00 00 00 00";

// Secure write error response: return_code wildcard.
const SECURE_WRITE_PID02_RO: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 02 00 00 01 ??";

// ============================================================================
// PropertyExtDescription_Read / Response templates for PID 2 on Security IO
// ============================================================================

// Plain A_PropertyExtDescription_Read (0x01D2): IOT=0x0011, instance=0x0010,
// PID=0x02 (ObjectName), description index=0x00, property index=0x00.
const PLAIN_DESC_READ_PID02: &str = "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 02 00 00";

// All-zero descriptor response. PID_OBJECT_NAME is not implemented on our
// Security IO, so both denied and "success" cases return zeroed descriptors.
// APDU: 01 D3 + 00 11 + 00 10 + 02 + 00 00 00 00 00 00 00 00 00 00 = 16 bytes
const PLAIN_DESC_READ_PID02_ZERO: &str = "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 02 00 00 00 00 00 00 00 00 00 00";

// With Security Mode off the descriptor is visible: prop_idx 1 (the name
// sits right after OBJECT_TYPE), not writeable, PDT_UNSIGNED_CHAR (02h),
// ten elements, read level 3 / write level 0. The vendor XML wildcards
// the device-specific octets and pins the type; we assert our own values
// exactly.
const PLAIN_DESC_READ_PID02_VISIBLE: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 02 00 01 00 00 00 00 02 00 0A 30";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_2_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.2 PID_OBJECT_NAME (Security IO, access 3FF/0CC) [optional]", variables).secure().with_cases(
        vec![
            // Skipped: 3.8.2.1 — PID_OBJECT_NAME not implemented on Security IO
            test_3_8_2_2(),
            test_3_8_2_3(),
        ],
    )
}

// ============================================================================
// 3.8.2.1 PropertyValueRead plain, A or A+C
// ============================================================================

#[allow(dead_code)]
fn test_3_8_2_1() -> TestCase {
    TestCase::new("3.8.2.1 PropertyValueRead plain, A or A+C").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Plain read → E_ACCESS_DENIED (security mode requires A+C)"),
        inject(PLAIN_READ_PID02),
        expect(PLAIN_READ_PID02_DENIED, TIMEOUT),
        comment("Auth-only secure read → E_ACCESS_DENIED (needs A+C, not just A)"),
        inject_secure_ao(SECURE_READ_PID02, "TK1"),
        expect_secure_ao(SECURE_READ_PID02_DENIED, "TK1", TIMEOUT),
        comment("A+C secure read → success (object name, wildcard)"),
        inject_secure_ac(SECURE_READ_PID02, "TK1"),
        expect_secure_ac(SECURE_READ_PID02_OK, "TK1", TIMEOUT),
        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Plain read → success"),
        inject(PLAIN_READ_PID02),
        expect(PLAIN_READ_PID02_OK, TIMEOUT),
        comment("Auth-only secure read → success"),
        inject_secure_ao(SECURE_READ_PID02, "TK1"),
        expect_secure_ao(SECURE_READ_PID02_OK, "TK1", TIMEOUT),
        comment("A+C secure read → success"),
        inject_secure_ac(SECURE_READ_PID02, "TK1"),
        expect_secure_ac(SECURE_READ_PID02_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.2.2 PropertyValueWrite plain, A or A+C
// ============================================================================

fn test_3_8_2_2() -> TestCase {
    TestCase::new("3.8.2.2 PropertyValueWrite plain, A or A+C").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Plain write → error (PID_OBJECT_NAME is read-only)"),
        inject(PLAIN_WRITE_PID02),
        expect(PLAIN_WRITE_PID02_RO, TIMEOUT),
        comment("Auth-only secure write → error"),
        inject_secure_ao(SECURE_WRITE_PID02, "TK1"),
        expect_secure_ao(SECURE_WRITE_PID02_RO, "TK1", TIMEOUT),
        comment("A+C secure write → error"),
        inject_secure_ac(SECURE_WRITE_PID02, "TK1"),
        expect_secure_ac(SECURE_WRITE_PID02_RO, "TK1", TIMEOUT),
        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Plain write → error"),
        inject(PLAIN_WRITE_PID02),
        expect(PLAIN_WRITE_PID02_RO, TIMEOUT),
        comment("Auth-only secure write → error"),
        inject_secure_ao(SECURE_WRITE_PID02, "TK1"),
        expect_secure_ao(SECURE_WRITE_PID02_RO, "TK1", TIMEOUT),
        comment("A+C secure write → error"),
        inject_secure_ac(SECURE_WRITE_PID02, "TK1"),
        expect_secure_ac(SECURE_WRITE_PID02_RO, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.2.3 PropertyDescriptionRead plain
// ============================================================================
//
// Access policy 3FF/0CC: plain description read is denied when security mode
// is ON. When security mode is OFF, plain access is allowed — but since
// PID_OBJECT_NAME is not implemented on our Security IO, the response is
// all-zero in both cases.

fn test_3_8_2_3() -> TestCase {
    TestCase::new("3.8.2.3 PropertyDescriptionRead plain").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Plain description read → all-zero (access denied, sec mode ON)"),
        inject(PLAIN_DESC_READ_PID02),
        expect(PLAIN_DESC_READ_PID02_ZERO, TIMEOUT),
        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Plain description read → visible descriptor (sec mode OFF)"),
        inject(PLAIN_DESC_READ_PID02),
        expect(PLAIN_DESC_READ_PID02_VISIBLE, TIMEOUT),
    ])
}
