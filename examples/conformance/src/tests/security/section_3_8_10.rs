//! Section 3.8.10 — `PID_GRP_KEY_TABLE` access policy `00C/00C` (3 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.10 PID_GRP_KEY_TABLE".
//!
//! Tests PID 0x35 (PID_GRP_KEY_TABLE, i.e. PID 53) on the Security Interface
//! Object (IOT=0x0011, instance=0x0010). Access policy is `00C/00C`: requires
//! Tool A+C for both read and write in both security modes — plain and
//! auth-only access is always denied.
//!
//! Each table entry is PDT_GENERIC_18: 2 bytes GA_Index + 16 bytes Key.
//!
//! Skipped test cases:
//! - 3.8.10.4 — uses A_PropertyExtDescription_Read (0x01D2), not yet implemented.
//! - 3.8.10.5 — uses T_Connect (connection-oriented), not yet implemented.

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
// PropertyExtValueWriteCon / Response templates for PID 0x35 on Security IO
// ============================================================================

// Secure WriteCon: IOT=0x0011, instance=0x0010, PID=0x35 (GRP_KEY_TABLE),
// count=1, start=1, data=18 bytes (GA_Index=0x0010 + Key=11 F0..FE).
// APDU: 01 CE + 00 11 + 00 10 + 35 + 01 + 00 01 + 18 data bytes = 28 bytes
// → extended frame len = 0x1B
const SECURE_WRITE_ENTRY_A: &str =
    "3C 60 #EDI #BDUT_ADDR 1B 01 CE 00 11 00 10 35 01 00 01 00 10 11 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE";

// Secure WriteCon success response: count=1, start=1, return_code=0x00 (success).
// APDU: 01 CF + 00 11 + 00 10 + 35 + 01 + 00 01 + 00 = 11 bytes → len = 0x0A
const SECURE_WRITE_ENTRY_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 35 01 00 01 00";

// Secure WriteCon error response: count=0, start=1, return_code=0xFC (E_ACCESS_DENIED).
// APDU: 01 CF + 00 11 + 00 10 + 35 + 00 + 00 01 + FC = 11 bytes → len = 0x0A
const SECURE_WRITE_ENTRY_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 35 00 00 01 FC";

// Second entry variant: last key byte is 0xFF instead of 0xFE (used in sec-mode-off phase).
const SECURE_WRITE_ENTRY_B: &str =
    "3C 60 #EDI #BDUT_ADDR 1B 01 CE 00 11 00 10 35 01 00 01 00 10 11 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FF";

// ============================================================================
// PropertyExtValueRead / Response templates for PID 0x35 on Security IO
// ============================================================================

// Secure A_PropertyExtValueRead: count=1, start=1 (read first entry).
// APDU: 01 CC + 00 11 + 00 10 + 35 + 01 + 00 01 = 10 bytes → len = 0x09
const SECURE_READ_ENTRY: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 35 01 00 01";

// Secure read success response with entry A data (18 bytes).
// APDU: 01 CD + 00 11 + 00 10 + 35 + 01 + 00 01 + 18 data bytes = 28 bytes → len = 0x1B
const SECURE_READ_ENTRY_A_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 1B 01 CD 00 11 00 10 35 01 00 01 00 10 11 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE";

// Secure read success response with entry B data (last byte 0xFF).
const SECURE_READ_ENTRY_B_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 1B 01 CD 00 11 00 10 35 01 00 01 00 10 11 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FF";

// Secure read error response: count=0, return_code=0xFC (E_ACCESS_DENIED).
// APDU: 01 CD + 00 11 + 00 10 + 35 + 00 + 00 01 + FC = 11 bytes → len = 0x0A
const SECURE_READ_ENTRY_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 35 00 00 01 FC";

// ============================================================================
// Plain (non-secure) templates — used in tests 3.8.10.2
// ============================================================================

// Plain WriteCon with extended frame: same APDU as secure but sent in the clear.
// The XML sends the full 18-byte entry even though it will be denied.
// APDU: 01 CE + 00 11 + 00 10 + 35 + 01 + 00 01 + 18 data bytes = 28 bytes
// Extended frame: 3C 60 header + len 0x1B
const PLAIN_WRITE_ENTRY: &str =
    "3C 60 #EDI #BDUT_ADDR 1B 01 CE 00 11 00 10 35 01 00 01 00 10 11 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE";

// Plain write error response: count=0, return_code=0xFC (E_ACCESS_DENIED).
// Response is standard frame: BC header.
const PLAIN_WRITE_ENTRY_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CF 00 11 00 10 35 00 00 01 FC";

// Plain A_PropertyExtValueRead: count=1, start=1.
// APDU: 01 CC + 00 11 + 00 10 + 35 + 01 + 00 01 = 10 bytes → TP1 len = 0x69
const PLAIN_READ_ENTRY: &str =
    "BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 35 01 00 01";

// Plain read error response: count=0, return_code=0xFC (E_ACCESS_DENIED).
const PLAIN_READ_ENTRY_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 35 00 00 01 FC";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_10_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.10 PID_GRP_KEY_TABLE (Security IO, access 00C/00C)", variables)
        .secure()
        .with_cases(vec![
            test_3_8_10_1(),
            test_3_8_10_2(),
            test_3_8_10_3(),
            // Skipped: 3.8.10.4 — uses A_PropertyExtDescription_Read (0x01D2),
            //   not yet implemented.
            // Skipped: 3.8.10.5 — uses T_Connect (connection-oriented),
            //   not yet implemented.
        ])
}

// ============================================================================
// 3.8.10.1 Secure PropertyValueWrite/Read – with A+C
// ============================================================================
//
// Access policy 00C/00C means only Tool A+C has read AND write access
// regardless of security mode. This test writes an entry, reads it back,
// then repeats with security mode toggled to verify both modes work.

fn test_3_8_10_1() -> TestCase {
    TestCase::new("3.8.10.1 Secure PropertyValueWrite/Read – with A+C").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Write entry A (GA_Index=0x0010, Key=11 F0..FE) → success"),
        inject_secure_ac(SECURE_WRITE_ENTRY_A, "TK1"),
        expect_secure_ac(SECURE_WRITE_ENTRY_OK, "TK1", TIMEOUT),

        comment("Read back entry at start=1 → expect entry A data"),
        inject_secure_ac(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ac(SECURE_READ_ENTRY_A_OK, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Write entry B (same GA_Index, Key last byte=0xFF) → success"),
        inject_secure_ac(SECURE_WRITE_ENTRY_B, "TK1"),
        expect_secure_ac(SECURE_WRITE_ENTRY_OK, "TK1", TIMEOUT),

        comment("Read back entry at start=1 → expect entry B data"),
        inject_secure_ac(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ac(SECURE_READ_ENTRY_B_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.10.2 Unsecure PropertyValueWrite and Read
// ============================================================================
//
// Plain (non-secure) write and read are always denied under 00C/00C policy,
// regardless of security mode.

fn test_3_8_10_2() -> TestCase {
    TestCase::new("3.8.10.2 Unsecure PropertyValueWrite and Read").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain write → E_ACCESS_DENIED (00C requires A+C)"),
        inject(PLAIN_WRITE_ENTRY),
        expect(PLAIN_WRITE_ENTRY_DENIED, TIMEOUT),

        comment("Plain read → E_ACCESS_DENIED"),
        inject(PLAIN_READ_ENTRY),
        expect(PLAIN_READ_ENTRY_DENIED, TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain write → E_ACCESS_DENIED (still denied, 00C policy)"),
        inject(PLAIN_WRITE_ENTRY),
        expect(PLAIN_WRITE_ENTRY_DENIED, TIMEOUT),

        comment("Plain read → E_ACCESS_DENIED"),
        inject(PLAIN_READ_ENTRY),
        expect(PLAIN_READ_ENTRY_DENIED, TIMEOUT),
    ])
}

// ============================================================================
// 3.8.10.3 Secured PropertyValueRead only authenticated
// ============================================================================
//
// Auth-only (without confidentiality) is insufficient for 00C/00C policy —
// both write and read are denied in both security modes.

fn test_3_8_10_3() -> TestCase {
    TestCase::new("3.8.10.3 Secured PropertyValueRead only authenticated").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Auth-only write → E_ACCESS_DENIED (00C requires A+C, not just A)"),
        inject_secure_ao(SECURE_WRITE_ENTRY_A, "TK1"),
        expect_secure_ao(SECURE_WRITE_ENTRY_DENIED, "TK1", TIMEOUT),

        comment("Auth-only read → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ao(SECURE_READ_ENTRY_DENIED, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Auth-only write → E_ACCESS_DENIED (still denied)"),
        inject_secure_ao(SECURE_WRITE_ENTRY_A, "TK1"),
        expect_secure_ao(SECURE_WRITE_ENTRY_DENIED, "TK1", TIMEOUT),

        comment("Auth-only read → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ao(SECURE_READ_ENTRY_DENIED, "TK1", TIMEOUT),
    ])
}
