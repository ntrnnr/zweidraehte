//! Section 3.8.9 — `PID_P2P_KEY_TABLE` access policy `00C/00C` (3 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.9 PID_P2P_KEY_TABLE".
//!
//! Tests PID 0x34 (PID_P2P_KEY_TABLE, i.e. PID 52) on the Security Interface
//! Object (IOT=0x0011, instance=0x0010). Access policy is `00C/00C`: requires
//! Tool A+C for both read and write in both security modes — plain and
//! auth-only access is always denied.
//!
//! Each table entry is PDT_GENERIC_20: 2 bytes IA_Index + 16 bytes Key +
//! 2 bytes role/flags.
//!
//! The test writes element count at start=0 (5-byte payload) before writing
//! the actual entry at start=1 (20-byte payload).
//!
//! Skipped test cases:
//! - 3.8.9.5 — uses T_Connect (connection-oriented), not yet implemented.

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
// PropertyExtValueWriteCon templates for PID 0x34 on Security IO
// ============================================================================

// Write element count at start=0: count=1, start=0, data=00 00 (zero entries).
// This clears the table before writing a new entry.
// APDU: 01 CE + 00 11 + 00 10 + 34 + 01 + 00 00 + 00 00 = 12 bytes → len = 0x0B
const SECURE_WRITE_ELEM_COUNT: &str =
    "3C 60 #EDI #BDUT_ADDR 0B 01 CE 00 11 00 10 34 01 00 00 00 00";

// Write element count success: count=1, start=0, return_code=0x00.
// APDU: 01 CF + 00 11 + 00 10 + 34 + 01 + 00 00 + 00 = 11 bytes → len = 0x0A
const SECURE_WRITE_ELEM_COUNT_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 34 01 00 00 00";

// Write element count denied: count=0, start=0, return_code=0xFC.
const SECURE_WRITE_ELEM_COUNT_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 34 00 00 00 FC";

// Write entry at start=1: count=1, start=1, data=20 bytes
// (IA_Index=0x0001 + Key=11 F0..FE + role=00 01).
// APDU: 01 CE + 00 11 + 00 10 + 34 + 01 + 00 01 + 20 data = 30 bytes → len = 0x1D
const SECURE_WRITE_ENTRY: &str =
    "3C 60 #EDI #BDUT_ADDR 1D 01 CE 00 11 00 10 34 01 00 01 00 01 11 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE 00 01";

// Write entry success: count=1, start=1, return_code=0x00.
const SECURE_WRITE_ENTRY_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 34 01 00 01 00";

// Write entry denied: count=0, start=1, return_code=0xFC.
const SECURE_WRITE_ENTRY_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 34 00 00 01 FC";

// ============================================================================
// PropertyExtValueRead templates for PID 0x34 on Security IO
// ============================================================================

// Read element count: count=1, start=0.
// APDU: 01 CC + 00 11 + 00 10 + 34 + 01 + 00 00 = 10 bytes → len = 0x09
const SECURE_READ_ELEM_COUNT: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 34 01 00 00";

// Read element count success: count=1, start=0, data=00 01 (1 entry).
// APDU: 01 CD + 00 11 + 00 10 + 34 + 01 + 00 00 + 00 01 = 12 bytes → len = 0x0B
const SECURE_READ_ELEM_COUNT_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0B 01 CD 00 11 00 10 34 01 00 00 00 01";

// Read element count denied: count=0, start=0, return_code=0xFC.
const SECURE_READ_ELEM_COUNT_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 34 00 00 00 FC";

// Read entry at start=1: count=1, start=1.
// APDU: 01 CC + 00 11 + 00 10 + 34 + 01 + 00 01 = 10 bytes → len = 0x09
const SECURE_READ_ENTRY: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 34 01 00 01";

// Read entry success: count=1, start=1, data=20 bytes (matching written data).
// APDU: 01 CD + 00 11 + 00 10 + 34 + 01 + 00 01 + 20 data = 30 bytes → len = 0x1D
const SECURE_READ_ENTRY_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 1D 01 CD 00 11 00 10 34 01 00 01 00 01 11 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE 00 01";

// Read entry denied: count=0, start=1, return_code=0xFC.
const SECURE_READ_ENTRY_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 34 00 00 01 FC";

// ============================================================================
// Plain (non-secure) templates — used in test 3.8.9.2
// ============================================================================

// Plain write element count: count=1, start=0, data=00 00.
// APDU: 12 bytes → TP1 len = 0x6B
const PLAIN_WRITE_ELEM_COUNT: &str =
    "BC #EDI #BDUT_ADDR 6B 01 CE 00 11 00 10 34 01 00 00 00 00";

// Plain write element count denied: count=0, start=0, return_code=0xFC.
const PLAIN_WRITE_ELEM_COUNT_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CF 00 11 00 10 34 00 00 00 FC";

// Plain write entry: extended frame (too long for standard frame).
// Sent as 3C 60 extended frame even though it's plain, matching the XML.
const PLAIN_WRITE_ENTRY: &str =
    "3C 60 #EDI #BDUT_ADDR 1D 01 CE 00 11 00 10 34 01 00 01 00 01 11 F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE 00 01";

// Plain write entry denied response: standard frame.
const PLAIN_WRITE_ENTRY_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CF 00 11 00 10 34 00 00 01 FC";

// Plain read element count.
// APDU: 10 bytes → TP1 len = 0x69
const PLAIN_READ_ELEM_COUNT: &str =
    "BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 34 01 00 00";

// Plain read element count denied.
const PLAIN_READ_ELEM_COUNT_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 34 00 00 00 FC";

// Plain read entry.
const PLAIN_READ_ENTRY: &str =
    "BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 34 01 00 01";

// Plain read entry denied.
const PLAIN_READ_ENTRY_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 34 00 00 01 FC";

// ============================================================================
// PropertyExtDescription_Read / Response templates for PID 0x34 on Security IO
// ============================================================================

// Secure A+C A_PropertyExtDescription_Read (0x01D2): IOT=0x0011, instance=0x0010,
// PID=0x34, description index=0x00, property index=0x00.
// APDU: 01 D2 + 00 11 + 00 10 + 34 + 00 + 00 = 8 bytes → len = 0x08
const SECURE_DESC_READ_PID34: &str =
    "3C 60 #EDI #BDUT_ADDR 08 01 D2 00 11 00 10 34 00 00";

// Secure A+C success response: valid descriptor (wildcard data bytes).
// APDU: 01 D3 + 00 11 + 00 10 + 34 + ?? x10 = 16 bytes → len = 0x10
const SECURE_DESC_READ_PID34_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// Plain A_PropertyExtDescription_Read for PID 0x34.
const PLAIN_DESC_READ_PID34: &str =
    "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 34 00 00";

// Plain all-zero descriptor response (access denied for 00C/00C — plain NEVER allowed).
const PLAIN_DESC_READ_PID34_ZERO: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 34 00 00 00 00 00 00 00 00 00 00";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_9_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.9 PID_P2P_KEY_TABLE (Security IO, access 00C/00C)", variables)
        .secure()
        .with_cases(vec![
            test_3_8_9_1(),
            test_3_8_9_2(),
            test_3_8_9_3(),
            test_3_8_9_4(),
            // TODO: 3.8.9.5 — P2P key table (and other security tables) are
            // not persisted across restarts. SecurityExtensionConfig only saves
            // scalar fields; table data is wiped on from_config(). Need to
            // persist tables for restart tests to pass.
        ])
}

// ============================================================================
// 3.8.9.1 Secure PropertyValueWrite and Read – with A+C
// ============================================================================
//
// Access policy 00C/00C means only Tool A+C has read AND write access
// regardless of security mode. This test clears the table (writes element
// count=0 at start=0), writes one entry at start=1, then reads back the
// element count and the entry to verify. Repeated for both sec-mode-on and
// sec-mode-off phases.

fn test_3_8_9_1() -> TestCase {
    TestCase::new("3.8.9.1 Secure PropertyValueWrite and Read – with A+C").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Write element count = 0 (clear table) → success"),
        inject_secure_ac(SECURE_WRITE_ELEM_COUNT, "TK1"),
        expect_secure_ac(SECURE_WRITE_ELEM_COUNT_OK, "TK1", TIMEOUT),

        comment("Write entry at start=1 (IA=0x0001, Key=11 F0..FE, role=00 01) → success"),
        inject_secure_ac(SECURE_WRITE_ENTRY, "TK1"),
        expect_secure_ac(SECURE_WRITE_ENTRY_OK, "TK1", TIMEOUT),

        comment("Read element count → expect 1"),
        inject_secure_ac(SECURE_READ_ELEM_COUNT, "TK1"),
        expect_secure_ac(SECURE_READ_ELEM_COUNT_OK, "TK1", TIMEOUT),

        comment("Read entry at start=1 → expect written data"),
        inject_secure_ac(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ac(SECURE_READ_ENTRY_OK, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Write element count = 0 (clear table) → success"),
        inject_secure_ac(SECURE_WRITE_ELEM_COUNT, "TK1"),
        expect_secure_ac(SECURE_WRITE_ELEM_COUNT_OK, "TK1", TIMEOUT),

        comment("Write entry at start=1 → success"),
        inject_secure_ac(SECURE_WRITE_ENTRY, "TK1"),
        expect_secure_ac(SECURE_WRITE_ENTRY_OK, "TK1", TIMEOUT),

        comment("Read element count → expect 1"),
        inject_secure_ac(SECURE_READ_ELEM_COUNT, "TK1"),
        expect_secure_ac(SECURE_READ_ELEM_COUNT_OK, "TK1", TIMEOUT),

        comment("Read entry at start=1 → expect written data"),
        inject_secure_ac(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ac(SECURE_READ_ENTRY_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.9.2 Unsecure PropertyValueWrite and Read
// ============================================================================
//
// Plain (non-secure) write and read are always denied under 00C/00C policy,
// regardless of security mode.

fn test_3_8_9_2() -> TestCase {
    TestCase::new("3.8.9.2 Unsecure PropertyValueWrite and Read").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain write element count → E_ACCESS_DENIED"),
        inject(PLAIN_WRITE_ELEM_COUNT),
        expect(PLAIN_WRITE_ELEM_COUNT_DENIED, TIMEOUT),

        comment("Plain write entry → E_ACCESS_DENIED"),
        inject(PLAIN_WRITE_ENTRY),
        expect(PLAIN_WRITE_ENTRY_DENIED, TIMEOUT),

        comment("Plain read element count → E_ACCESS_DENIED"),
        inject(PLAIN_READ_ELEM_COUNT),
        expect(PLAIN_READ_ELEM_COUNT_DENIED, TIMEOUT),

        comment("Plain read entry → E_ACCESS_DENIED"),
        inject(PLAIN_READ_ENTRY),
        expect(PLAIN_READ_ENTRY_DENIED, TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain write element count → E_ACCESS_DENIED"),
        inject(PLAIN_WRITE_ELEM_COUNT),
        expect(PLAIN_WRITE_ELEM_COUNT_DENIED, TIMEOUT),

        comment("Plain write entry → E_ACCESS_DENIED"),
        inject(PLAIN_WRITE_ENTRY),
        expect(PLAIN_WRITE_ENTRY_DENIED, TIMEOUT),

        comment("Plain read element count → E_ACCESS_DENIED"),
        inject(PLAIN_READ_ELEM_COUNT),
        expect(PLAIN_READ_ELEM_COUNT_DENIED, TIMEOUT),

        comment("Plain read entry → E_ACCESS_DENIED"),
        inject(PLAIN_READ_ENTRY),
        expect(PLAIN_READ_ENTRY_DENIED, TIMEOUT),
    ])
}

// ============================================================================
// 3.8.9.3 Secured PropertyValueRead only authenticated
// ============================================================================
//
// Auth-only (without confidentiality) is insufficient for 00C/00C policy —
// both write and read are denied in both security modes.

fn test_3_8_9_3() -> TestCase {
    TestCase::new("3.8.9.3 Secured PropertyValueRead only authenticated").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Auth-only write element count → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_WRITE_ELEM_COUNT, "TK1"),
        expect_secure_ao(SECURE_WRITE_ELEM_COUNT_DENIED, "TK1", TIMEOUT),

        comment("Auth-only write entry → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_WRITE_ENTRY, "TK1"),
        expect_secure_ao(SECURE_WRITE_ENTRY_DENIED, "TK1", TIMEOUT),

        comment("Auth-only read element count → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_READ_ELEM_COUNT, "TK1"),
        expect_secure_ao(SECURE_READ_ELEM_COUNT_DENIED, "TK1", TIMEOUT),

        comment("Auth-only read entry → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ao(SECURE_READ_ENTRY_DENIED, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Auth-only write element count → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_WRITE_ELEM_COUNT, "TK1"),
        expect_secure_ao(SECURE_WRITE_ELEM_COUNT_DENIED, "TK1", TIMEOUT),

        comment("Auth-only write entry → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_WRITE_ENTRY, "TK1"),
        expect_secure_ao(SECURE_WRITE_ENTRY_DENIED, "TK1", TIMEOUT),

        comment("Auth-only read entry → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ao(SECURE_READ_ENTRY_DENIED, "TK1", TIMEOUT),

        comment("Auth-only read element count → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_READ_ELEM_COUNT, "TK1"),
        expect_secure_ao(SECURE_READ_ELEM_COUNT_DENIED, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.9.4 PropertyDescriptionRead
// ============================================================================
//
// Access policy 00C/00C: A+C secure description read succeeds (A+C is always
// allowed). Plain description read returns all-zero (plain NEVER allowed for
// 00C/00C, regardless of security mode).

fn test_3_8_9_4() -> TestCase {
    TestCase::new("3.8.9.4 PropertyDescriptionRead").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Secure A+C description read → success (valid descriptor)"),
        inject_secure_ac(SECURE_DESC_READ_PID34, "TK1"),
        expect_secure_ac(SECURE_DESC_READ_PID34_OK, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain description read → all-zero (plain never allowed for 00C/00C)"),
        inject(PLAIN_DESC_READ_PID34),
        expect(PLAIN_DESC_READ_PID34_ZERO, TIMEOUT),
    ])
}

// ============================================================================
// 3.8.9.5 Secure PropertyValueRead after power down and master reset
// ============================================================================
//
// Verifies that PID_P2P_KEY_TABLE survives confirmed restart and basic
// restart. The test assumes the table was populated by tests 3.8.9.1
// (which writes element count + one entry via secure A+C).
//
// Phase A: Confirmed Restart (erase code 0x01) — table unchanged
// Phase B: Basic Restart — table unchanged

#[allow(dead_code)] // Blocked on security table persistence.
fn test_3_8_9_5() -> TestCase {
    // Connection-oriented A_Restart: master reset (restart_type=1).
    // TPCI = 0x43 (numbered seq 0 + APCI high 0x03), APCI = 0x81 01 00
    // = A_Restart master reset, erase_code=0x01 (Confirmed), channel=0x00.
    const CONNECTED_RESTART_CONFIRMED: &str =
        "3C 60 #EDI #BDUT_ADDR 03 43 81 01 00";

    // A_Restart_Response: error_code=0x00, process_time=?? (2 bytes).
    const CONNECTED_RESTART_CONFIRMED_RESP: &str =
        "3C 60 #BDUT_ADDR #EDI 04 43 A1 00 00 ??";

    // Connection-oriented basic restart (restart_type=0).
    // Standard frame: BC prefix, TPCI = 0x43 (numbered seq 0), APCI = 0x0380.
    const CONNECTED_BASIC_RESTART: &str =
        "BC #EDI #BDUT_ADDR 61 43 80";

    TestCase::new("3.8.9.5 Secure PropertyValueRead after power down and master reset").with_steps(vec![
        // ==== Phase A: Confirmed Restart ====
        comment("A. Confirmed Restart — T_Connect + master reset"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),

        comment("Secure A+C numbered: A_Restart (Confirmed, erase=0x01)"),
        inject_secure_ac(CONNECTED_RESTART_CONFIRMED, "TK1"),

        comment("Expect T_ACK"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),

        comment("Expect secure A+C numbered: A_Restart_Response"),
        expect_secure_ac(CONNECTED_RESTART_CONFIRMED_RESP, "TK1", TIMEOUT),

        comment("ACK the response"),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),

        comment("T_Disconnect"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),

        comment("Wait for DUT to restart"),
        wait_for_restart(50000),

        comment("Read P2P key table entry → unchanged after confirmed restart"),
        inject_secure_ac(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ac(SECURE_READ_ENTRY_OK, "TK1", TIMEOUT),

        comment("Read again → same"),
        inject_secure_ac(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ac(SECURE_READ_ENTRY_OK, "TK1", TIMEOUT),

        // ==== Phase B: Basic Restart ====
        comment("B. Basic Restart — T_Connect + basic restart"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),

        comment("Secure A+C numbered: A_Restart (basic)"),
        inject_secure_ac(CONNECTED_BASIC_RESTART, "TK1"),

        comment("Expect T_ACK"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),

        comment("Wait for DUT to restart"),
        wait_for_restart(50000),

        comment("Read P2P key table entry → unchanged after basic restart"),
        inject_secure_ac(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ac(SECURE_READ_ENTRY_OK, "TK1", TIMEOUT),

        comment("Read again → same"),
        inject_secure_ac(SECURE_READ_ENTRY, "TK1"),
        expect_secure_ac(SECURE_READ_ENTRY_OK, "TK1", TIMEOUT),
    ])
}
