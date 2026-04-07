//! Section 3.6 — KNX Secure Access - Roles (12 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.6 KNX Secure Access - Roles".
//!
//! Tests role-based access control via P2P (non-tool) secure communication.
//! The DUT must have a Certification Object (IOT 0xC351) with PID 51 (0x33)
//! that enforces per-role read/write permissions.
//!
//! Setup writes the P2P key table with 8 entries (each with IA, key, and
//! role bitmask), the SIAT with the same 8 IAs, syncs each peer, and
//! activates security mode. Each test then sends PropertyExtValueWriteCon
//! and/or PropertyExtValueRead from different peer IAs with different
//! security levels, verifying that the DUT accepts or denies based on the
//! sender's role.
//!
//! Skipped:
//! - 3.6.1.1 — Introduction/setup only (rolled into the setup test case).

use super::variables::create_security_variables;
use crate::tests::helpers::*;
use crate::{TestCase, TestStep, TestSuite};

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

// ============================================================================
// Peer IA addresses (as hex bytes for telegram templates)
// ============================================================================
//
// IA4 = 1.1.1 = 0x1101    IA5 = 1.1.2 = 0x1102    IA6 = 1.1.3 = 0x1103
// IA7 = 1.1.4 = 0x1104    IA8 = 1.1.5 = 0x1105    IA9 = 1.1.6 = 0x1106
// IA10 = 1.1.7 = 0x1107   IA11 = 1.1.8 = 0x1108
// (not in P2P table) = 1.1.10 = 0x110A

// ============================================================================
// Security Mode control templates (on Security IO 0x0011)
// ============================================================================

const ENABLE_SEC_MODE: &str = "3C 60 #EDI #ALT_BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";

const DISABLE_SEC_MODE: &str = "3C 60 #EDI #ALT_BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";

const SEC_MODE_RESP_OK: &str = "3C 60 #ALT_BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

// ============================================================================
// Security IO Load State Control templates
// ============================================================================

// PropertyExtValueWriteCon on Security IO (0x0011, inst 0x0010),
// PID_LOAD_STATE_CONTROL (0x05): set to unloaded (0x00).
const SEC_LOAD_UNLOADED: &str =
    "3C 60 #EDI #ALT_BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 04 00 00 00 00 00 00 00 00 00";

// set to loading (0x01).
const SEC_LOAD_LOADING: &str =
    "3C 60 #EDI #ALT_BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 01 00 00 00 00 00 00 00 00 00";

// set to loaded (0x02).
const SEC_LOAD_LOADED: &str =
    "3C 60 #EDI #ALT_BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 02 00 00 00 00 00 00 00 00 00";

// Expected response: PropertyExtValueWriteConRes with return code 0x00.
const SEC_LOAD_RESP_OK: &str = "3C 60 #ALT_BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 05 01 00 01 00";

// ============================================================================
// SIAT (PID 0x36) write templates — clear and write entries
// ============================================================================

// Clear SIAT: set count = 0.
const SIAT_CLEAR: &str = "3C 60 #EDI #ALT_BDUT_ADDR 0B 01 CE 00 11 00 10 36 01 00 00 00 00";

const SIAT_RESP_OK: &str = "3C 60 #ALT_BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 36 01 00 ?? 00";

// Write SIAT entry N: IA(2) + SeqNr(6)=000000000000.
// Entry 1: IA 1.1.1 = 11 01
const SIAT_ENTRY_1: &str = "3C 60 #EDI #ALT_BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 01 11 01 00 00 00 00 00 00";
const SIAT_ENTRY_2: &str = "3C 60 #EDI #ALT_BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 02 11 02 00 00 00 00 00 00";
const SIAT_ENTRY_3: &str = "3C 60 #EDI #ALT_BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 03 11 03 00 00 00 00 00 00";
const SIAT_ENTRY_4: &str = "3C 60 #EDI #ALT_BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 04 11 04 00 00 00 00 00 00";
const SIAT_ENTRY_5: &str = "3C 60 #EDI #ALT_BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 05 11 05 00 00 00 00 00 00";
const SIAT_ENTRY_6: &str = "3C 60 #EDI #ALT_BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 06 11 06 00 00 00 00 00 00";
const SIAT_ENTRY_7: &str = "3C 60 #EDI #ALT_BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 07 11 07 00 00 00 00 00 00";
const SIAT_ENTRY_8: &str = "3C 60 #EDI #ALT_BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 08 11 08 00 00 00 00 00 00";

// ============================================================================
// P2P Key Table (PID 0x34) write templates — 20 bytes per entry:
//   IA(2) + Key(16) + Roles(2)
// ============================================================================

// Clear P2P key table.
const P2P_CLEAR: &str = "3C 60 #EDI #ALT_BDUT_ADDR 0B 01 CE 00 11 00 10 34 01 00 00 00 00";

const P2P_RESP_OK: &str = "3C 60 #ALT_BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 34 01 00 ?? 00";

// IA4=1.1.1 (0x1101): P2PK1=[0x22;16], Role 0 → roles=0x0001
const P2P_ENTRY_1: &str = "3C 60 #EDI #ALT_BDUT_ADDR 1D 01 CE 00 11 00 10 34 01 00 01 11 01 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 00 01";
// IA5=1.1.2 (0x1102): P2PK2=[0x33;16], Role 1 → roles=0x0002
const P2P_ENTRY_2: &str = "3C 60 #EDI #ALT_BDUT_ADDR 1D 01 CE 00 11 00 10 34 01 00 02 11 02 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 00 02";
// IA6=1.1.3 (0x1103): P2PK3=[0x44;16], Role 2 → roles=0x0004
const P2P_ENTRY_3: &str = "3C 60 #EDI #ALT_BDUT_ADDR 1D 01 CE 00 11 00 10 34 01 00 03 11 03 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 00 04";
// IA7=1.1.4 (0x1104): P2PK4=[0x55;16], Role 3 → roles=0x0008
const P2P_ENTRY_4: &str = "3C 60 #EDI #ALT_BDUT_ADDR 1D 01 CE 00 11 00 10 34 01 00 04 11 04 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 00 08";
// IA8=1.1.5 (0x1105): P2PK5=[0x66;16], Role 4 → roles=0x0010
const P2P_ENTRY_5: &str = "3C 60 #EDI #ALT_BDUT_ADDR 1D 01 CE 00 11 00 10 34 01 00 05 11 05 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 00 10";
// IA9=1.1.6 (0x1106): P2PK6=[0x77;16], Role 5 → roles=0x0020
const P2P_ENTRY_6: &str = "3C 60 #EDI #ALT_BDUT_ADDR 1D 01 CE 00 11 00 10 34 01 00 06 11 06 77 77 77 77 77 77 77 77 77 77 77 77 77 77 77 77 00 20";
// IA10=1.1.7 (0x1107): P2PK7=[0x88;16], No role → roles=0x0000
const P2P_ENTRY_7: &str = "3C 60 #EDI #ALT_BDUT_ADDR 1D 01 CE 00 11 00 10 34 01 00 07 11 07 88 88 88 88 88 88 88 88 88 88 88 88 88 88 88 88 00 00";
// IA11=1.1.8 (0x1108): P2PK8=[0x99;16], Roles 3+4 → roles=0x0018
const P2P_ENTRY_8: &str = "3C 60 #EDI #ALT_BDUT_ADDR 1D 01 CE 00 11 00 10 34 01 00 08 11 08 99 99 99 99 99 99 99 99 99 99 99 99 99 99 99 99 00 18";

// ============================================================================
// PropertyExtValueWriteCon / PropertyExtValueRead templates for Cert Object
// ============================================================================
//
// PropertyExtValueWriteCon: APCI 0x01CE
// Format: FT=Extended src dst length 01 CE IOT(2) INST(2) PID COUNT START_IDX DATA
//
// PropertyExtValueRead: APCI 0x01CC
// Format: FT=Extended src dst length 01 CC IOT(2) INST(2) PID COUNT START_IDX
//
// PropertyExtValueResponse: APCI 0x01CD
// PropertyExtValueWriteConRes: APCI 0x01CF

/// PropertyExtValueWriteCon: write 0xAA to PID 51 on Cert Object, from a given source IA.
fn p2p_write_template(src_ia: &str) -> String {
    format!("3C 60 {} #ALT_BDUT_ADDR 0A 01 CE C3 51 00 10 33 01 00 01 AA", src_ia)
}

/// PropertyExtValueWriteConRes: success (return code 0x00), from BDUT.
fn p2p_write_ok_response(dst_ia: &str) -> String {
    format!("3C 60 #ALT_BDUT_ADDR {} 0A 01 CF C3 51 00 10 33 01 00 01 00", dst_ia)
}

/// PropertyExtValueWriteConRes: access denied (count=0, return code 0xFC).
fn p2p_write_denied_response(dst_ia: &str) -> String {
    format!("3C 60 #ALT_BDUT_ADDR {} 0A 01 CF C3 51 00 10 33 00 00 01 FC", dst_ia)
}

/// PropertyExtValueRead: read PID 51 from Cert Object, from a given source IA.
fn p2p_read_template(src_ia: &str) -> String {
    format!("3C 60 {} #ALT_BDUT_ADDR 09 01 CC C3 51 00 10 33 01 00 01", src_ia)
}

/// PropertyExtValueResponse: success with data 0xAA.
fn p2p_read_ok_response(dst_ia: &str) -> String {
    format!("3C 60 #ALT_BDUT_ADDR {} 0A 01 CD C3 51 00 10 33 01 00 01 AA", dst_ia)
}

/// PropertyExtValueResponse: access denied (count=0, return code 0xFC).
fn p2p_read_denied_response(dst_ia: &str) -> String {
    format!("3C 60 #ALT_BDUT_ADDR {} 0A 01 CD C3 51 00 10 33 00 00 01 FC", dst_ia)
}

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_6_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.6 KNX Secure Access - Roles", variables)
        .secure()
        .with_preparation(preparation_steps())
        .with_cases(vec![
            test_3_6_1_2(),
            test_3_6_1_3(),
            test_3_6_1_4(),
            test_3_6_1_5(),
            test_3_6_1_6(),
            test_3_6_1_7(),
            test_3_6_1_8(),
            test_3_6_1_9(),
            test_3_6_1_10(),
            test_3_6_1_11(),
            test_3_6_1_12(),
        ])
        .with_teardown(teardown_steps())
}

// ============================================================================
// Setup (3.6.1.1)
// ============================================================================

fn preparation_steps() -> Vec<TestStep> {
    vec![
        // ================================================================
        // Set DUT IA to 2.2.2 (ALT_BDUT_ADDR) to avoid conflict with the
        // P2P peer IAs 1.1.1-1.1.8 used for role testing.
        // ================================================================
        comment("Set DUT IA to ALT_BDUT_ADDR (2.2.2)"),
        inject("BC #EDI 00 00 ED 03 DE #SER_NUM #ALT_BDUT_ADDR 00 00 00 00"),
        wait(500),
        // ================================================================
        // Disable security mode so we can modify security tables.
        // ================================================================
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SEC_MODE, "TK1"),
        expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        // ================================================================
        // Transition security load state: unloaded → loading.
        // ================================================================
        comment("Security IO: unloaded"),
        inject_secure_ac(SEC_LOAD_UNLOADED, "TK1"),
        expect_secure_ac(SEC_LOAD_RESP_OK, "TK1", TIMEOUT),
        comment("Security IO: loading"),
        inject_secure_ac(SEC_LOAD_LOADING, "TK1"),
        expect_secure_ac(SEC_LOAD_RESP_OK, "TK1", TIMEOUT),
        // ================================================================
        // Write SIAT entries (8 peers).
        // ================================================================
        comment("Clear SIAT"),
        inject_secure_ac(SIAT_CLEAR, "TK1"),
        expect_secure_ac(SIAT_RESP_OK, "TK1", TIMEOUT),
        comment("Write SIAT entries 1-8"),
        inject_secure_ac(SIAT_ENTRY_1, "TK1"),
        expect_secure_ac(SIAT_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(SIAT_ENTRY_2, "TK1"),
        expect_secure_ac(SIAT_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(SIAT_ENTRY_3, "TK1"),
        expect_secure_ac(SIAT_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(SIAT_ENTRY_4, "TK1"),
        expect_secure_ac(SIAT_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(SIAT_ENTRY_5, "TK1"),
        expect_secure_ac(SIAT_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(SIAT_ENTRY_6, "TK1"),
        expect_secure_ac(SIAT_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(SIAT_ENTRY_7, "TK1"),
        expect_secure_ac(SIAT_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(SIAT_ENTRY_8, "TK1"),
        expect_secure_ac(SIAT_RESP_OK, "TK1", TIMEOUT),
        // ================================================================
        // Write P2P key table entries (8 keys with roles).
        // ================================================================
        comment("Clear P2P key table"),
        inject_secure_ac(P2P_CLEAR, "TK1"),
        expect_secure_ac(P2P_RESP_OK, "TK1", TIMEOUT),
        comment("Write P2P key entries 1-8"),
        inject_secure_ac(P2P_ENTRY_1, "TK1"),
        expect_secure_ac(P2P_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(P2P_ENTRY_2, "TK1"),
        expect_secure_ac(P2P_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(P2P_ENTRY_3, "TK1"),
        expect_secure_ac(P2P_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(P2P_ENTRY_4, "TK1"),
        expect_secure_ac(P2P_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(P2P_ENTRY_5, "TK1"),
        expect_secure_ac(P2P_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(P2P_ENTRY_6, "TK1"),
        expect_secure_ac(P2P_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(P2P_ENTRY_7, "TK1"),
        expect_secure_ac(P2P_RESP_OK, "TK1", TIMEOUT),
        inject_secure_ac(P2P_ENTRY_8, "TK1"),
        expect_secure_ac(P2P_RESP_OK, "TK1", TIMEOUT),
        // ================================================================
        // Transition to loaded.
        // ================================================================
        comment("Security IO: loaded"),
        inject_secure_ac(SEC_LOAD_LOADED, "TK1"),
        expect_secure_ac(SEC_LOAD_RESP_OK, "TK1", TIMEOUT),
        // ================================================================
        // Synchronize sequence numbers for each P2P key.
        //
        // The DUT rate-limits sync responses to 1 per second, so we need
        // a delay between each sync pair.
        // ================================================================
        // TODO: P2P sync requires non-tool sync request support in the test
        // harness crypto module. For now, these are omitted — the DUT's
        // per-peer receiving sequence counters start at 0, and our first
        // P2P data frame will use seq=1, which will be accepted.

        // ================================================================
        // Activate Security Mode.
        // ================================================================
        comment("Activate Security Mode"),
        inject_secure_ac(ENABLE_SEC_MODE, "TK1"),
        expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
    ]
}

// ============================================================================
// 3.6.1.2 — A required — Role 0 — R+W
// ============================================================================

fn test_3_6_1_2() -> TestCase {
    let src = "11 01"; // IA 1.1.1
    let key = "P2PK1";
    TestCase::new("3.6.1.2 A required - role correct to read and write").with_steps(vec![
        comment("Write OK: Role 0, A, R+W"),
        inject_p2p_ao(&p2p_write_template(src), key),
        expect_p2p_ao(&p2p_write_ok_response(src), key, TIMEOUT),
        comment("Read OK: returns 0xAA"),
        inject_p2p_ao(&p2p_read_template(src), key),
        expect_p2p_ao(&p2p_read_ok_response(src), key, TIMEOUT),
    ])
}

// ============================================================================
// 3.6.1.3 — A required — Role 2 — R only
// ============================================================================

fn test_3_6_1_3() -> TestCase {
    let src = "11 03"; // IA 1.1.3
    let key = "P2PK3";
    TestCase::new("3.6.1.3 A required only - role incorrect to write").with_steps(vec![
        comment("Read OK: Role 2 can read"),
        inject_p2p_ao(&p2p_read_template(src), key),
        expect_p2p_ao(&p2p_read_ok_response(src), key, TIMEOUT),
        comment("Write DENIED: Role 2, A, R only"),
        inject_p2p_ao(&p2p_write_template(src), key),
        expect_p2p_ao(&p2p_write_denied_response(src), key, TIMEOUT),
    ])
}

// ============================================================================
// 3.6.1.4 — Role 5 (A+C, W only) sent with A only → insufficient security
// ============================================================================

fn test_3_6_1_4() -> TestCase {
    let src = "11 06"; // IA 1.1.6
    let key = "P2PK6";
    TestCase::new("3.6.1.4 role only allowed to write with A+C").with_steps(vec![
        comment("Write DENIED: Role 5 needs A+C but got A"),
        inject_p2p_ao(&p2p_write_template(src), key),
        expect_p2p_ao(&p2p_write_denied_response(src), key, TIMEOUT),
        comment("Read DENIED: Role 5 has no read permission"),
        inject_p2p_ao(&p2p_read_template(src), key),
        expect_p2p_ao(&p2p_read_denied_response(src), key, TIMEOUT),
    ])
}

// ============================================================================
// 3.6.1.5 — A+C required — Role 1 — R+W
// ============================================================================

fn test_3_6_1_5() -> TestCase {
    let src = "11 02"; // IA 1.1.2
    let key = "P2PK2";
    TestCase::new("3.6.1.5 A and C required - role correct to read and write").with_steps(vec![
        comment("Write OK: Role 1, A+C, R+W"),
        inject_p2p_ac(&p2p_write_template(src), key),
        expect_p2p_ac(&p2p_write_ok_response(src), key, TIMEOUT),
        comment("Read OK: returns 0xAA"),
        inject_p2p_ac(&p2p_read_template(src), key),
        expect_p2p_ac(&p2p_read_ok_response(src), key, TIMEOUT),
    ])
}

// ============================================================================
// 3.6.1.6 — A+C required — Role 3 — R only
// ============================================================================

fn test_3_6_1_6() -> TestCase {
    let src = "11 04"; // IA 1.1.4
    let key = "P2PK4";
    TestCase::new("3.6.1.6 A and C required - role incorrect to write").with_steps(vec![
        comment("Write DENIED: Role 3, A+C, R only"),
        inject_p2p_ac(&p2p_write_template(src), key),
        expect_p2p_ac(&p2p_write_denied_response(src), key, TIMEOUT),
        comment("Read OK: Role 3 can read"),
        inject_p2p_ac(&p2p_read_template(src), key),
        expect_p2p_ac(&p2p_read_ok_response(src), key, TIMEOUT),
    ])
}

// ============================================================================
// 3.6.1.7 — A+C required — No role — denied
// ============================================================================

fn test_3_6_1_7() -> TestCase {
    let src = "11 07"; // IA 1.1.7
    let key = "P2PK7";
    TestCase::new("3.6.1.7 A and C required - role not allowed to read nor write").with_steps(vec![
        comment("Write DENIED: No role"),
        inject_p2p_ac(&p2p_write_template(src), key),
        expect_p2p_ac(&p2p_write_denied_response(src), key, TIMEOUT),
        comment("Read DENIED: No role"),
        inject_p2p_ac(&p2p_read_template(src), key),
        expect_p2p_ac(&p2p_read_denied_response(src), key, TIMEOUT),
    ])
}

// ============================================================================
// 3.6.1.8 — IA not in P2P key table → dropped (no response)
// ============================================================================

fn test_3_6_1_8() -> TestCase {
    let src = "11 0A"; // IA 1.1.10 — NOT in P2P table or SIAT
    // Use P2PK2 as the encryption key (the DUT won't find a matching
    // key for this IA, so it will drop the frame before MAC verification).
    TestCase::new("3.6.1.8 IA not listed in P2P Key Table").with_steps(vec![
        comment("Write: IA not in P2P table → dropped"),
        inject_p2p_ac(&p2p_write_template(src), "P2PK2"),
        expect_none(TIMEOUT),
        comment("Read: IA not in P2P table → dropped"),
        inject_p2p_ac(&p2p_read_template(src), "P2PK2"),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.6.1.9 — Correct IA but wrong key → MAC failure → dropped
// ============================================================================

fn test_3_6_1_9() -> TestCase {
    let src = "11 02"; // IA 1.1.2 (should use P2PK2)
    // Encrypt with P2PK1 instead of P2PK2 → MAC mismatch at DUT.
    TestCase::new("3.6.1.9 A and C required - Role using incorrect key").with_steps(vec![
        comment("Write: wrong key → dropped"),
        inject_p2p_ac(&p2p_write_template(src), "P2PK1"),
        expect_none(TIMEOUT),
        comment("Read: wrong key → dropped"),
        inject_p2p_ac(&p2p_read_template(src), "P2PK1"),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.6.1.10 — A required — Role 4 — W only
// ============================================================================

fn test_3_6_1_10() -> TestCase {
    let src = "11 05"; // IA 1.1.5
    let key = "P2PK5";
    TestCase::new("3.6.1.10 A required - Write but no read").with_steps(vec![
        comment("Write OK: Role 4, A, W only"),
        inject_p2p_ao(&p2p_write_template(src), key),
        expect_p2p_ao(&p2p_write_ok_response(src), key, TIMEOUT),
        comment("Read DENIED: Role 4 has no read permission"),
        inject_p2p_ao(&p2p_read_template(src), key),
        expect_p2p_ao(&p2p_read_denied_response(src), key, TIMEOUT),
    ])
}

// ============================================================================
// 3.6.1.11 — A+C required — Role 5 — W only
// ============================================================================

fn test_3_6_1_11() -> TestCase {
    let src = "11 06"; // IA 1.1.6
    let key = "P2PK6";
    TestCase::new("3.6.1.11 A+C required - Write but no read").with_steps(vec![
        comment("Write OK: Role 5, A+C, W only"),
        inject_p2p_ac(&p2p_write_template(src), key),
        expect_p2p_ac(&p2p_write_ok_response(src), key, TIMEOUT),
        comment("Read DENIED: Role 5 has no read permission"),
        inject_p2p_ac(&p2p_read_template(src), key),
        expect_p2p_ac(&p2p_read_denied_response(src), key, TIMEOUT),
    ])
}

// ============================================================================
// 3.6.1.12 — A+C required — Roles 3+4 — R+W
// ============================================================================

fn test_3_6_1_12() -> TestCase {
    let src = "11 08"; // IA 1.1.8
    let key = "P2PK8";
    // P2PK8 has roles=0x0018 (Role 3 bit + Role 4 bit).
    // Role 3 = A+C R only, Role 4 = A W only.
    // With A+C: Role 3 grants read, but Role 4's W needs A (not A+C).
    // So with A+C: R from Role 3, no W (Role 4 needs A, Role 3 has no W).
    //
    // Actually re-reading the spec: the role check should look at ALL roles
    // assigned to the sender and find ANY that matches. Role 3 (bit 3, A+C)
    // grants R. Role 4 (bit 4, A) grants W but requires A, not A+C.
    // With A+C security level, Role 4's W is not granted (security mismatch).
    //
    // Wait — looking at the test XML expectation: the test sends with A+C
    // and expects BOTH write and read to succeed. This implies:
    // - Read: Role 3 (A+C, R) matches → granted
    // - Write: Somehow works with A+C despite Role 4 requiring A...
    //
    // The likely interpretation: "two supported roles" means the permission
    // union covers both R and W. Role 3 gives R (A+C), and since the sender
    // has both roles, the combined permission is R+W when either role's
    // security level is met. Role 4 requires A for W — and A+C satisfies A
    // (A+C is a superset of A).
    //
    // This aligns with KNX spec: A+C is "at least as secure as" A.
    // Our CertificationObjectAugment needs to handle this: if A+C is sent
    // and a role requires only A, that should still match.
    //
    // TODO: Update CertificationObjectAugment to accept A+C when role requires A.
    TestCase::new("3.6.1.12 A and C required - two supported roles").with_steps(vec![
        comment("Write OK: Role 3+4 combined, A+C satisfies Role 4's A requirement"),
        inject_p2p_ac(&p2p_write_template(src), key),
        expect_p2p_ac(&p2p_write_ok_response(src), key, TIMEOUT),
        comment("Read OK: Role 3 grants read with A+C"),
        inject_p2p_ac(&p2p_read_template(src), key),
        expect_p2p_ac(&p2p_read_ok_response(src), key, TIMEOUT),
    ])
}

// ============================================================================
// Cleanup (3.6.1.x) — Restore DUT IA to BDUT_ADDR
// ============================================================================

fn teardown_steps() -> Vec<TestStep> {
    vec![
        // Deactivate security mode (using ALT_BDUT_ADDR since that's where the DUT is).
        comment("Deactivate Security Mode"),
        inject_secure_ac(DISABLE_SEC_MODE, "TK1"),
        expect_secure_ac(SEC_MODE_RESP_OK, "TK1", TIMEOUT),
        // Unload security tables.
        comment("Security IO: unloaded"),
        inject_secure_ac(SEC_LOAD_UNLOADED, "TK1"),
        expect_secure_ac(SEC_LOAD_RESP_OK, "TK1", TIMEOUT),
        // Restore DUT IA to the standard BDUT_ADDR (1.1.1).
        comment("Restore DUT IA to BDUT_ADDR (1.1.1)"),
        inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
        wait(500),
    ]
}
