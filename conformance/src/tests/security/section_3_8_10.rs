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
//! All 5 test cases implemented.

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
const SECURE_WRITE_ENTRY_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 35 01 00 01 00";

// Secure WriteCon error response: count=0, start=1, return_code=0xFC (E_ACCESS_DENIED).
// APDU: 01 CF + 00 11 + 00 10 + 35 + 00 + 00 01 + FC = 11 bytes → len = 0x0A
const SECURE_WRITE_ENTRY_DENIED: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 35 00 00 01 FC";

// Second entry variant: last key byte is 0xFF instead of 0xFE (used in sec-mode-off phase).
const SECURE_WRITE_ENTRY_B: &str =
    "3C 60 #EDI #BDUT_ADDR 1B 01 CE 00 11 00 10 35 01 00 01 00 10 11 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FF";

// Restore entry 1 to the initial stack config: {GA_Index=0x0002, key=GK1}.
// Tests 3.8.10.1 / 3.8.10.5 overwrite entry 1 as part of their write/read
// round-trip. Without this cleanup, group traffic that depends on GK1
// (TSAP 2 → 1/1/1) decrypts with garbage in subsequent suites. Matching
// pattern used in section_3_2 / section_3_8_17.
const RESTORE_ENTRY_1_GK1: &str =
    "3C 60 #EDI #BDUT_ADDR 1B 01 CE 00 11 00 10 35 01 00 01 00 02 AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA";

// ============================================================================
// PropertyExtValueRead / Response templates for PID 0x35 on Security IO
// ============================================================================

// Secure A_PropertyExtValueRead: count=1, start=1 (read first entry).
// APDU: 01 CC + 00 11 + 00 10 + 35 + 01 + 00 01 = 10 bytes → len = 0x09
const SECURE_READ_ENTRY: &str = "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 35 01 00 01";

// Secure read success response with entry A data (18 bytes).
// APDU: 01 CD + 00 11 + 00 10 + 35 + 01 + 00 01 + 18 data bytes = 28 bytes → len = 0x1B
const SECURE_READ_ENTRY_A_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 1B 01 CD 00 11 00 10 35 01 00 01 00 10 11 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE";

// Secure read success response with entry B data (last byte 0xFF).
const SECURE_READ_ENTRY_B_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 1B 01 CD 00 11 00 10 35 01 00 01 00 10 11 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FF";

// Secure read error response: count=0, return_code=0xFC (E_ACCESS_DENIED).
// APDU: 01 CD + 00 11 + 00 10 + 35 + 00 + 00 01 + FC = 11 bytes → len = 0x0A
const SECURE_READ_ENTRY_DENIED: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 35 00 00 01 FC";

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
const PLAIN_WRITE_ENTRY_DENIED: &str = "BC #BDUT_ADDR #EDI 6A 01 CF 00 11 00 10 35 00 00 01 FC";

// Plain A_PropertyExtValueRead: count=1, start=1.
// APDU: 01 CC + 00 11 + 00 10 + 35 + 01 + 00 01 = 10 bytes → TP1 len = 0x69
const PLAIN_READ_ENTRY: &str = "BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 35 01 00 01";

// Plain read error response: count=0, return_code=0xFC (E_ACCESS_DENIED).
const PLAIN_READ_ENTRY_DENIED: &str = "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 35 00 00 01 FC";

// ============================================================================
// PropertyExtDescription_Read / Response templates for PID 0x35 on Security IO
// ============================================================================

// Secure A+C A_PropertyExtDescription_Read (0x01D2): IOT=0x0011, instance=0x0010,
// PID=0x35, description index=0x00, property index=0x00.
// APDU: 01 D2 + 00 11 + 00 10 + 35 + 00 + 00 = 8 bytes → len = 0x08
const SECURE_DESC_READ_PID35: &str = "3C 60 #EDI #BDUT_ADDR 08 01 D2 00 11 00 10 35 00 00";

// Secure A+C success response: valid descriptor (wildcard data bytes).
// APDU: 01 D3 + 00 11 + 00 10 + 35 + ?? x10 = 16 bytes → len = 0x10
const SECURE_DESC_READ_PID35_OK: &str = "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// Plain A_PropertyExtDescription_Read for PID 0x35.
const PLAIN_DESC_READ_PID35: &str = "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 35 00 00";

// Plain all-zero descriptor response (access denied for 00C/00C — plain NEVER allowed).
const PLAIN_DESC_READ_PID35_ZERO: &str = "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 35 00 00 00 00 00 00 00 00 00 00";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_10_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.10 PID_GRP_KEY_TABLE (Security IO, access 00C/00C)", variables).secure().with_cases(vec![
        test_3_8_10_1(),
        test_3_8_10_2(),
        test_3_8_10_3(),
        test_3_8_10_4(),
        test_3_8_10_5(),
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
        // Cleanup: restore entry 1 to its initial {GA_Index=0x0002, key=GK1}
        // mapping. Without this, subsequent suites that rely on GK1 for
        // secure group telegrams to 1/1/1 would fail (or silently compensate).
        comment("Restore group key entry 1 (TSAP 2 → GK1) — previously overwrote with test pattern"),
        inject_secure_ac(RESTORE_ENTRY_1_GK1, "TK1"),
        expect_secure_ac(SECURE_WRITE_ENTRY_OK, "TK1", TIMEOUT),
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

// ============================================================================
// 3.8.10.4 PropertyDescriptionRead
// ============================================================================
//
// Access policy 00C/00C: A+C secure description read succeeds (A+C is always
// allowed). Plain description read returns all-zero (plain NEVER allowed for
// 00C/00C, regardless of security mode).

fn test_3_8_10_4() -> TestCase {
    TestCase::new("3.8.10.4 PropertyDescriptionRead").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Secure A+C description read → success (valid descriptor)"),
        inject_secure_ac(SECURE_DESC_READ_PID35, "TK1"),
        expect_secure_ac(SECURE_DESC_READ_PID35_OK, "TK1", TIMEOUT),
        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Plain description read → all-zero (plain never allowed for 00C/00C)"),
        inject(PLAIN_DESC_READ_PID35),
        expect(PLAIN_DESC_READ_PID35_ZERO, TIMEOUT),
    ])
}

// ============================================================================
// 3.8.10.5 Secure PropertyValueRead after power down and master reset
// ============================================================================
//
// Verifies that PID_GRP_KEY_TABLE survives confirmed restart and basic
// restart. The test assumes the table was populated by test 3.8.10.1
// (which writes entry B in the sec-mode-off phase).
//
// Phase A: Confirmed Restart (erase code 0x01) — table unchanged
// Phase B: Basic Restart — table unchanged

fn test_3_8_10_5() -> TestCase {
    const CONNECTED_RESTART_CONFIRMED: &str = "3C 60 #EDI #BDUT_ADDR 03 43 81 01 00";

    const CONNECTED_RESTART_CONFIRMED_RESP: &str = "3C 60 #BDUT_ADDR #EDI 04 43 A1 00 00 ??";

    const CONNECTED_BASIC_RESTART: &str = "BC #EDI #BDUT_ADDR 61 43 80";

    TestCase::new("3.8.10.5 Secure PropertyValueRead after power down and master reset").with_steps(vec![
        // The reference test enables security mode first.
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        // Seed entry 1 with the "B" test pattern so the restart-persistence
        // assertions below have a known value to check against. Previously
        // this test depended on 3.8.10.1 leaving entry B in the table, which
        // makes the suite brittle to test ordering.
        comment("Seed entry 1 = B (self-contained, independent of 3.8.10.1)"),
        inject_secure_ac(SECURE_WRITE_ENTRY_B, "TK1"),
        expect_secure_ac(SECURE_WRITE_ENTRY_OK, "TK1", TIMEOUT),
        // ==== Phase A: Confirmed Restart ====
        comment("A. T_Connect + Confirmed Restart (erase=0x01)"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject_secure_ac(CONNECTED_RESTART_CONFIRMED, "TK1"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        expect_secure_ac(CONNECTED_RESTART_CONFIRMED_RESP, "TK1", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),
        comment("Wait for DUT to restart"),
        wait(500),
        comment("Read GRP key table entry → unchanged after confirmed restart"),
        inject_secure_ac(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ac(SECURE_READ_ENTRY_B_OK, "TK1", TIMEOUT),
        inject_secure_ac(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ac(SECURE_READ_ENTRY_B_OK, "TK1", TIMEOUT),
        // ==== Phase B: Basic Restart ====
        comment("B. T_Connect + Basic Restart"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject_secure_ac(CONNECTED_BASIC_RESTART, "TK1"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        comment("Wait for DUT to restart"),
        wait(500),
        comment("Read GRP key table entry → unchanged after basic restart"),
        inject_secure_ac(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ac(SECURE_READ_ENTRY_B_OK, "TK1", TIMEOUT),
        // Cleanup: restore entry 1 before this test exits. Sec mode is still
        // on here, so the secure write travels as A+C.
        comment("Restore group key entry 1 (TSAP 2 → GK1)"),
        inject_secure_ac(RESTORE_ENTRY_1_GK1, "TK1"),
        expect_secure_ac(SECURE_WRITE_ENTRY_OK, "TK1", TIMEOUT),
        // Restore: disable security mode for next suite.
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
    ])
}
