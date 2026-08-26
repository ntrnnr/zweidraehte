//! Section 3.2 — S-A_Data PDU with Group Key (18 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.2 S-A_Data PDU with Group Key".
//!
//! Tests secure group communication using runtime group keys (not tool keys).
//! The DUT has four group objects configured:
//!
//! - GO_SEC_0 (CO 12): GK1/GK2 on GA 1/1/1 (recv) / 2/2/2 (send), A-only (flag=0x01)
//! - GO_SEC_1 (CO 13): GK3/GK4 on GA 3/3/3 (recv) / 4/4/4 (send), A+C (flag=0x03)
//! - GO_SEC_2 (CO 11): No key on GA 5/5/5, Plain (flag=0x00)
//! - GO_SEC_3 (CO 14): GK5 on GA 6/6/6, C-only (flag=0x02)
//!
//! Positive tests send correctly secured group reads and expect secured
//! responses. Negative tests send malformed or mismatched frames and expect
//! no response (DUT silently drops).
//!
//! Skipped test cases:
//! - 3.2.1 — Introduction only (no telegrams).

use super::variables::create_security_variables;
use crate::tests::helpers::*;
use crate::{InvalidSecurityParam, SecureParams, SeqSource, TestCase, TestSuite};

// ============================================================================
// Group Address Constants
// ============================================================================
//
// GA encoding (3-level): ((main & 0x1F) << 11) | ((middle & 0x07) << 8) | sub
//
// 1/1/1 = 0x0901    3/3/3 = 0x1B03    5/5/5 = 0x2D05
// 2/2/2 = 0x1202    4/4/4 = 0x2404    6/6/6 = 0x3606

// ============================================================================
// Plaintext Templates — Group Service APDUs
// ============================================================================

// GroupValue_Read (APCI 0x0000) to GA 1/1/1 from EDI.
const GV_READ_111: &str = "BC #EDI 09 01 E1 00 00";
// GroupValue_Response (APCI 0x0040) from BDUT on GA 2/2/2.
const GV_RESP_222: &str = "BC #BDUT_ADDR 12 02 E1 00 40";

// GroupValue_Read to GA 2/2/2 from EDI (for tool-key-on-group tests).
const GV_READ_222: &str = "BC #EDI 12 02 E1 00 00";
// GroupValue_Read to GA 2/2/2 from ALT_SRC_ADDR.
const GV_READ_222_ALT: &str = "BC #ALT_SRC_ADDR 12 02 E1 00 00";
// GroupValue_Response from BDUT on GA 2/2/2 (same GA, response to alt source).
const GV_RESP_222_ALT: &str = "BC #BDUT_ADDR 12 02 E1 00 40";

// GroupValue_Read to GA 3/3/3 from EDI.
const GV_READ_333: &str = "BC #EDI 1B 03 E1 00 00";
// GroupValue_Response from BDUT on GA 4/4/4.
const GV_RESP_444: &str = "BC #BDUT_ADDR 24 04 E1 00 40";

// GroupValue_Read to GA 3/3/3 from ALT_SRC_ADDR.
const GV_READ_333_ALT: &str = "BC #ALT_SRC_ADDR 1B 03 E1 00 00";
// GroupValue_Response from BDUT on GA 4/4/4 (response to alt source).
const GV_RESP_444_ALT: &str = "BC #BDUT_ADDR 24 04 E1 00 40";

// GroupValue_Read to GA 5/5/5 from EDI (for plain GO tests).
const GV_READ_555: &str = "BC #EDI 2D 05 E1 00 00";

// GroupValue_Read to GA 6/6/6 from EDI (for C-only GO test).
const GV_READ_666: &str = "BC #EDI 36 06 E1 00 00";

// ============================================================================
// Security IO Management Templates (for setup phase)
// ============================================================================

// A_PropertyExtValueWriteCon to Security IO (IOT=0x0011, instance=0x0010):
// PID 5 = LOAD_STATE_CONTROL, count=1, start=1, value = 10-byte load record.
// LoadEvent 0x01 = StartLoading, 0x02 = LoadCompleted.
const LOAD_START_LOADING: &str = "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 01 00 00 00 00 00 00 00 00 00";
const LOAD_START_LOADING_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 05 01 00 01 00";
const LOAD_COMPLETED: &str = "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 02 00 00 00 00 00 00 00 00 00";
const LOAD_COMPLETED_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 05 01 00 01 00";

// Write GO security flags (PID 0x3D, count=4, start=1):
// 4 GO flag bytes: GO_SEC_0=0x01(A), GO_SEC_1=0x03(A+C), GO_SEC_2=0x00(plain), GO_SEC_3=0x02(C-only)
//
// Note: the GO flag table is indexed by communication object number starting
// from the first application CO. In our DUT: CO 11 = GO_SEC_2 (index 0 in the
// security GO range is actually relative). The flags are written in order of
// the GO indices as they appear in the DUT's comm object table.
//
// We need to write flags for all security-relevant GOs. The GO flag table
// covers ALL communication objects (indices 0..N). We write 4 flags starting
// at index 12 (CO 12 = GO_SEC_0) to cover CO 12, 13, 14.
// But CO 11 (5/5/5) also needs flag=0x00. It's at index 11.
//
// Actually, the GO flag table is written as a contiguous block starting at
// start_index=1. We need to write enough entries to cover all GOs.
// Let's write all 15 GO flags (COs 1-14 → indices 1-14, or the table uses
// 0-based GO indices). The simplest approach: write flags for GOs 0-14.
//
// For section 3.2, the relevant GOs and their expected flags:
//   GO_SEC_0 (CO 12, 0-based index 11): flag=0x01 (auth-only)
//   GO_SEC_1 (CO 13, 0-based index 12): flag=0x03 (auth+conf)
//   GO_SEC_2 (CO 11, 0-based index 10): flag=0x00 (plain)
//   GO_SEC_3 (CO 14, 0-based index 13): flag=0x02 (C-only)
//
// We write count=4, start=11 (covers indices 10-13 → COs 11-14):
// Data: 00 01 03 02
// APDU: 01 CE + 00 11 + 00 10 + 3D + 04 + 00 0B + 00 01 03 02 = 14 bytes → len = 0x0D
const WRITE_GO_FLAGS: &str = "30 60 #EDI #BDUT_ADDR 0D 01 CE 00 11 00 10 3D 04 00 0B 00 01 03 02";
const WRITE_GO_FLAGS_OK: &str = "30 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 3D 04 00 0B 00";

// Restore group key entry at index 1 (TSAP 2 → GK1) — previous suites
// (e.g. 3.8.10) may overwrite this entry with test data.
// APDU: 01 CE + 00 11 + 00 10 + 35 + 01 + 00 01 + 18 data bytes = 28 bytes → len = 0x1B
const RESTORE_GRP_KEY_ENTRY_1: &str =
    "3C 60 #EDI #BDUT_ADDR 1B 01 CE 00 11 00 10 35 01 00 01 00 02 AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA";
const RESTORE_GRP_KEY_ENTRY_1_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 35 01 00 01 00";

// Temporarily move table entry 2 from TSAP 12 to the unused TSAP 11. The
// table remains sorted, but a secure spontaneous send on ASAP 12 can no
// longer resolve its required key. Restoring the original entry leaves the
// shared DUT state ready for following suites.
const REMOVE_GRP_KEY_ENTRY_2: &str =
    "3C 60 #EDI #BDUT_ADDR 1B 01 CE 00 11 00 10 35 01 00 02 00 0B BB BB BB BB BB BB BB BB BB BB BB BB BB BB BB BB";
const REMOVE_GRP_KEY_ENTRY_2_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 35 01 00 02 00";
const RESTORE_GRP_KEY_ENTRY_2: &str =
    "3C 60 #EDI #BDUT_ADDR 1B 01 CE 00 11 00 10 35 01 00 02 00 0C BB BB BB BB BB BB BB BB BB BB BB BB BB BB BB BB";
const RESTORE_GRP_KEY_ENTRY_2_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 35 01 00 02 00";

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

// ============================================================================
// SIAT Templates for Test 3.2.13 (Cross-IA Sequence Number Replay)
// ============================================================================

// Write SIAT entry 2: IA=#EDI (0xAFFE), last_valid_seq=1.
// PID 0x36 (PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE), count=1, start=2.
const SIAT_EDI_SEQ1: &str = "3C 60 #EDI #BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 02 #EDI 00 00 00 00 00 01";
const SIAT_EDI_ENTRY_2_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 36 01 00 02 00";

// Write SIAT entry 1: IA=#ALT_SRC_ADDR (0xAFFD), last_valid_seq=3.
const SIAT_ALT_SEQ3: &str = "3C 60 #EDI #BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 01 #ALT_SRC_ADDR 00 00 00 00 00 03";
const SIAT_ALT_ENTRY_1_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 36 01 00 01 00";

// The suite's positive group senders are secure communication partners and
// therefore need SIAT rows before their first S-A_Data frame. Start both replay
// floors at zero; the received non-zero sequence numbers advance them.
const SIAT_EDI_SEQ0: &str = "3C 60 #EDI #BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 02 #EDI 00 00 00 00 00 00";
const SIAT_ALT_SEQ0: &str = "3C 60 #EDI #BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 01 #ALT_SRC_ADDR 00 00 00 00 00 00";

// Clear SIAT: write count=0, start=0.
const CLEAR_SIAT: &str = "3C 60 #EDI #BDUT_ADDR 0B 01 CE 00 11 00 10 36 01 00 00 00 00";
const CLEAR_SIAT_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 36 01 00 00 00";

// A sender absent from the SIAT is discarded without updating the Security
// Failures Log (03/03/07 §5.1.3.5, reception step 1).
const CLEAR_FAILURE_LOG: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 37 00 00 00";
const CLEAR_FAILURE_LOG_OK: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 00 00";

const READ_FAILURE_COUNTERS: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D5 00 11 00 10 37 00 00 00";
const READ_EMPTY_FAILURE_COUNTERS: &str =
    "3C 60 #BDUT_ADDR #EDI 11 01 D6 00 11 00 10 37 00 00 00 00 00 00 00 00 00 00 00";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_2_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.2 S-A_Data PDU with Group Key", variables).secure().with_cases(vec![
        // Setup: load Security IO and write GO flags.
        test_3_2_setup(),
        // Placeholder (introduction — documentation-only, 0 telegrams in XML).
        test_3_2_1(),
        // ================================================================
        // Positive tests: auth-only (GO_SEC_0, GK1/GK2)
        // ================================================================
        test_3_2_2(),
        test_3_2_4(),
        // ================================================================
        // Positive tests: auth+conf (GO_SEC_1, GK3/GK4)
        // ================================================================
        test_3_2_8(),
        test_3_2_10(),
        // ================================================================
        // Negative tests: auth-only
        // ================================================================
        test_3_2_3(),
        test_3_2_5(),
        test_3_2_6(),
        test_3_2_7(),
        // ================================================================
        // Negative tests: auth+conf
        // ================================================================
        test_3_2_9(),
        test_3_2_11(),
        test_3_2_12(),
        test_3_2_13(),
        test_3_2_14(),
        test_3_2_15(),
        test_3_2_16(),
        test_3_2_17(),
        test_3_2_18(),
        test_3_2_19(),
        // ================================================================
        // Spontaneous transmit-side tests (transmit half of §6.3.15.3
        // Table 108). Not in the official conformance XML — added by us
        // to lock down the AL/S-AL layering rework that introduced the
        // `RequiredSecurity` annotation. They follow the receive tests
        // because they consume the DUT's sending sequence counters and
        // shouldn't perturb prior tests' replay-protection assumptions.
        // ================================================================
        test_3_2_tx_1_auth_only(),
        test_3_2_tx_2_auth_conf(),
        test_3_2_tx_3_plain(),
        test_3_2_tx_4_missing_key_fails_closed(),
    ])
}

// ============================================================================
// Setup: Load Security IO and configure GO security flags
// ============================================================================

fn test_3_2_setup() -> TestCase {
    TestCase::new("3.2 Setup: Load Security IO, SIAT, and GO flags").with_steps(vec![
        comment("Security IO: transition to Loading so we can write GO flags"),
        inject_secure_ac(LOAD_START_LOADING, "TK1"),
        expect_secure_ac(LOAD_START_LOADING_OK, "TK1", TIMEOUT),
        // Restore group key entry 1 (TSAP 2 → GK1) in case a previous suite
        // (e.g. 3.8.10) overwrote it with test data.
        comment("Restore group key entry 1 (TSAP 2 → GK1)"),
        inject_secure_ac(RESTORE_GRP_KEY_ENTRY_1, "TK1"),
        expect_secure_ac(RESTORE_GRP_KEY_ENTRY_1_OK, "TK1", TIMEOUT),
        comment("Write GO security flags: GO_SEC_2=plain, GO_SEC_0=A, GO_SEC_1=A+C, GO_SEC_3=C"),
        inject_secure_ac(WRITE_GO_FLAGS, "TK1"),
        expect_secure_ac(WRITE_GO_FLAGS_OK, "TK1", TIMEOUT),
        comment("Provision ALT_SRC and EDI as secure group senders with Last Valid SeqNr zero"),
        inject_secure_ac(SIAT_ALT_SEQ0, "TK1"),
        expect_secure_ac(SIAT_ALT_ENTRY_1_OK, "TK1", TIMEOUT),
        inject_secure_ac(SIAT_EDI_SEQ0, "TK1"),
        expect_secure_ac(SIAT_EDI_ENTRY_2_OK, "TK1", TIMEOUT),
        comment("Transition to Loaded — security tables are now active"),
        inject_secure_ac(LOAD_COMPLETED, "TK1"),
        expect_secure_ac(LOAD_COMPLETED_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.2.2 correct S-A_Data PDU - A only
// ============================================================================
//
// Send GroupValue_Read to 1/1/1 with GK1 (auth-only), expect response
// on 2/2/2 with GK2 (auth-only).

fn test_3_2_2() -> TestCase {
    TestCase::new("3.2.2 correct S-A_Data A only (GK1→GK2)").with_steps(vec![
        comment("GroupValue_Read to 1/1/1 with GK1 (auth-only)"),
        inject_group_ao(GV_READ_111, "GK1"),
        expect_group_ao(GV_RESP_222, "GK2", TIMEOUT),
    ])
}

// ============================================================================
// 3.2.3 correct S-A_Data, A+C encoded, but A only required
// ============================================================================
//
// GO_SEC_0 requires auth-only (flag=0x01), but we send A+C → reject.

fn test_3_2_3() -> TestCase {
    TestCase::new("3.2.3 A+C to A-only GO → reject").with_steps(vec![
        comment("A+C read to 1/1/1 but GO requires auth-only → reject"),
        inject_group_ac(GV_READ_111, "GK1"),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.2.4 correct S-A_Data PDU – A only - second source and destination
// ============================================================================
//
// Read from ALT_SRC_ADDR on 2/2/2 with GK2, expect response on 2/2/2.

fn test_3_2_4() -> TestCase {
    TestCase::new("3.2.4 A only - second source (ALT_SRC, GK2)").with_steps(vec![
        comment("GroupValue_Read from ALT_SRC on 2/2/2 with GK2 (auth-only)"),
        inject_group_ao(GV_READ_222_ALT, "GK2"),
        expect_group_ao(GV_RESP_222_ALT, "GK2", TIMEOUT),
    ])
}

// ============================================================================
// 3.2.5 correct S-A_Data – A only - but encrypted with AT=P2P
// ============================================================================
//
// Auth-only with correct GK1 but wrong address type (P2P instead of group)
// in the CCM context → MAC mismatch → reject.

fn test_3_2_5() -> TestCase {
    TestCase::new("3.2.5 A only with AT=P2P → reject").with_steps(vec![
        comment("Auth-only to 1/1/1 with AT=P2P in CCM → reject"),
        inject_secure_invalid(
            GV_READ_111,
            SecureParams::group_auth_only("GK1"),
            InvalidSecurityParam::WrongAddressType,
        ),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.2.6 correct S-A_Data (A only) - correct SCF with correct tool key access
// ============================================================================
//
// Tool key must not be used for group communication. Send 4 telegrams:
// 1. To 1/1/1 with TK1 + tool flag (SCF has TA=yes, key=TK1)
// 2. To 1/1/1 with TK1 + no tool flag
// 3. To 2/2/2 with TK1 + tool flag
// 4. To 2/2/2 with TK1 + no tool flag
// All should be rejected.

fn test_3_2_6() -> TestCase {
    TestCase::new("3.2.6 tool key on group comms → reject").with_steps(vec![
        comment("TK1 with tool flag to 1/1/1 → reject"),
        inject_secure(GV_READ_111, SecureParams::tool_auth_only("TK1")),
        expect_none(TIMEOUT),
        comment("TK1 without tool flag to 1/1/1 → reject (wrong key)"),
        inject_secure(GV_READ_111, SecureParams::group_auth_only("TK1")),
        expect_none(TIMEOUT),
        comment("TK1 with tool flag to 2/2/2 → reject"),
        inject_secure(GV_READ_222, SecureParams::tool_auth_only("TK1")),
        expect_none(TIMEOUT),
        comment("TK1 without tool flag to 2/2/2 → reject (wrong key)"),
        inject_secure(GV_READ_222, SecureParams::group_auth_only("TK1")),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.2.7 incorrect S-A_Data PDU - wrongly coded MAC for A only
// ============================================================================

fn test_3_2_7() -> TestCase {
    TestCase::new("3.2.7 wrong MAC (A only) → reject").with_steps(vec![
        comment("Auth-only to 1/1/1 with wrong MAC → reject"),
        inject_secure_invalid(
            GV_READ_111,
            SecureParams::group_auth_only("GK1"),
            InvalidSecurityParam::InvalidMac([0xFF, 0x00, 0x00, 0x00]),
        ),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.2.8 correct S-A_Data PDU - A and C required
// ============================================================================
//
// Send GroupValue_Read to 3/3/3 with GK3 (auth+conf), expect response
// on 4/4/4 with GK4 (auth+conf).

fn test_3_2_8() -> TestCase {
    TestCase::new("3.2.8 correct S-A_Data A+C (GK3→GK4)").with_steps(vec![
        comment("GroupValue_Read to 3/3/3 with GK3 (auth+conf)"),
        inject_group_ac(GV_READ_333, "GK3"),
        expect_group_ac(GV_RESP_444, "GK4", TIMEOUT),
    ])
}

// ============================================================================
// 3.2.9 correct S-A_Data PDU – GO security flags no A, no C
// ============================================================================
//
// GO_SEC_2 (5/5/5) has flag=0x00 (plain). Sending a secure frame → reject.

fn test_3_2_9() -> TestCase {
    TestCase::new("3.2.9 secure to plain GO (5/5/5) → reject").with_steps(vec![
        comment("A+C to 5/5/5 but GO requires plain → reject"),
        inject_group_ac(GV_READ_555, "GK3"),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.2.10 correct S-A_Data - A+C - second source and destination
// ============================================================================
//
// Read from ALT_SRC_ADDR on 3/3/3 with GK3, expect response on 4/4/4 with GK4.

fn test_3_2_10() -> TestCase {
    TestCase::new("3.2.10 A+C - second source (ALT_SRC, GK3→GK4)").with_steps(vec![
        comment("GroupValue_Read from ALT_SRC on 3/3/3 with GK3 (auth+conf)"),
        inject_group_ac(GV_READ_333_ALT, "GK3"),
        expect_group_ac(GV_RESP_444_ALT, "GK4", TIMEOUT),
    ])
}

// ============================================================================
// 3.2.11 correct S-A_Data – A+C - but encrypted with AT=P2P
// ============================================================================

fn test_3_2_11() -> TestCase {
    TestCase::new("3.2.11 A+C with AT=P2P → reject").with_steps(vec![
        comment("A+C to 3/3/3 with AT=P2P in CCM → reject"),
        inject_secure_invalid(
            GV_READ_333,
            SecureParams::group_auth_conf("GK3"),
            InvalidSecurityParam::WrongAddressType,
        ),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.2.12 correct S-A_Data - tool key flag set but runtime key used
// ============================================================================
//
// SCF=0x90 (tool flag + conf) but encrypted with GK3 (runtime key).
// The DUT should reject because the tool flag is set but the key is not
// the tool key (MAC won't verify with tool key, and tool key shouldn't
// be used for group comms anyway).

fn test_3_2_12() -> TestCase {
    TestCase::new("3.2.12 tool flag + runtime key → reject").with_steps(vec![
        comment("SCF=0x90 (tool+conf) but GK3 used → reject"),
        inject_secure_invalid(
            GV_READ_333,
            SecureParams::group_auth_conf("GK3"),
            InvalidSecurityParam::InvalidScf(0x90),
        ),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.2.14 incorrect S-A_Data PDU - wrongly encrypted cipher text
// ============================================================================

fn test_3_2_14() -> TestCase {
    TestCase::new("3.2.14 wrong ciphertext (A+C) → reject").with_steps(vec![
        comment("A+C to 3/3/3 with corrupted ciphertext → reject"),
        inject_secure_invalid(GV_READ_333, SecureParams::group_auth_conf("GK3"), InvalidSecurityParam::InvalidCipher),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.2.15 correct S-A_Data PDU - A and C required – A only received
// ============================================================================
//
// GO_SEC_1 (3/3/3) requires A+C (flag=0x03), but we send auth-only → reject.

fn test_3_2_15() -> TestCase {
    TestCase::new("3.2.15 A only to A+C GO → reject").with_steps(vec![
        comment("Auth-only to 3/3/3 but GO requires A+C → reject"),
        inject_group_ao(GV_READ_333, "GK3"),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.2.16 correct S-A_Data PDU - A and C required - Plain received
// ============================================================================
//
// GO_SEC_1 (3/3/3) requires A+C (flag=0x03), but we send plain → reject.

fn test_3_2_16() -> TestCase {
    TestCase::new("3.2.16 plain to A+C GO → reject").with_steps(vec![
        comment("Plain GroupValue_Read to 3/3/3 but GO requires A+C → reject"),
        inject(GV_READ_333),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.2.17 incorrect S-A_Data PDU - wrongly coded MAC for C and A
// ============================================================================

fn test_3_2_17() -> TestCase {
    TestCase::new("3.2.17 wrong MAC (A+C) → reject").with_steps(vec![
        comment("A+C to 3/3/3 with wrong MAC → reject"),
        inject_secure_invalid(
            GV_READ_333,
            SecureParams::group_auth_conf("GK3"),
            InvalidSecurityParam::InvalidMac([0xFF, 0x00, 0x00, 0x00]),
        ),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.2.18 correct S-A_Data PDU – GA linked to GO requiring plain only
// ============================================================================
//
// GO_SEC_2 (5/5/5) has flag=0x00 (plain). Sending a secure frame → reject.
// (Same concept as 3.2.9 but explicitly testing "plain only" semantics.)

fn test_3_2_18() -> TestCase {
    TestCase::new("3.2.18 secure to plain-only GO (5/5/5) → reject").with_steps(vec![
        comment("A+C to 5/5/5 but GO requires plain → reject"),
        inject_group_ac(GV_READ_555, "GK3"),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.2.19 correct S-A_Data PDU - only C set in GO flags – A+C received
// ============================================================================
//
// GO_SEC_3 (6/6/6) has flag=0x02 (C-only). No valid SCF matches this flag,
// so all frames are rejected. We send A+C → reject.

fn test_3_2_19() -> TestCase {
    TestCase::new("3.2.19 A+C to C-only GO (6/6/6) → reject").with_steps(vec![
        comment("A+C to 6/6/6 but GO requires C-only (0x02) → reject"),
        inject_group_ac(GV_READ_666, "GK5"),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.2.13 correct S-A_Data - with a correct sequence number but from a
//        different IA (cross-IA sequence replay)
// ============================================================================
//
// The DUT must maintain per-sender sequence counters for group messages.
// If IA1 (#EDI, 0xAFFE) has last_valid_seq=1 and IA2 (#ALT_SRC_ADDR,
// 0xAFFD) has last_valid_seq=3, then sending a frame FROM IA2 with seq=2
// (which is IA1's expected next) must be rejected — seq=2 is not valid
// for IA2 (needs >3).

fn test_3_2_13() -> TestCase {
    TestCase::new("3.2.13 cross-IA sequence number replay → reject").with_steps(vec![
        comment("Write SIAT entry 2: IA=#EDI (0xAFFE), last_valid_seq=1"),
        inject_secure_ac(SIAT_EDI_SEQ1, "TK1"),
        expect_secure_ac(SIAT_EDI_ENTRY_2_OK, "TK1", TIMEOUT),
        comment("Write SIAT entry 1: IA=#ALT_SRC_ADDR (0xAFFD), last_valid_seq=3"),
        inject_secure_ac(SIAT_ALT_SEQ3, "TK1"),
        expect_secure_ac(SIAT_ALT_ENTRY_1_OK, "TK1", TIMEOUT),
        comment("GroupValue_Read from ALT_SRC_ADDR to 3/3/3 with GK3, seq=2"),
        comment("seq=2 is EDI's expected next (1+1), NOT ALT_SRC_ADDR's (needs >3)"),
        inject_secure(GV_READ_333_ALT, {
            let mut p = SecureParams::group_auth_conf("GK3");
            p.seq_source = SeqSource::Fixed(2);
            p
        }),
        expect_none(TIMEOUT),
        comment("Cleanup: clear SIAT entries"),
        inject_secure_ac(CLEAR_SIAT, "TK1"),
        expect_secure_ac(CLEAR_SIAT_OK, "TK1", TIMEOUT),
        comment("Clear the failure log before checking the missing-SIAT behavior"),
        inject_secure_ac(CLEAR_FAILURE_LOG, "TK1"),
        expect_secure_ac(CLEAR_FAILURE_LOG_OK, "TK1", TIMEOUT),
        comment("A correctly keyed group frame from an IA absent from the SIAT must be rejected"),
        inject_group_ac(GV_READ_333, "GK3"),
        expect_none(TIMEOUT),
        comment("The missing SIAT entry must not increment any security-failure counter"),
        inject_secure_ac(READ_FAILURE_COUNTERS, "TK1"),
        expect_secure_ac(READ_EMPTY_FAILURE_COUNTERS, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.2.tx-* — Spontaneous outbound secure transmission tests
// ============================================================================
//
// These tests cover the **transmit** side of `PID_GO_SECURITY_FLAGS` /
// 03/05/01 §6.3.15.3 Table 108: when the local application initiates a
// `A_GroupValue_Write.req` (or read), the GO's flag bits become this
// primitive's `par_auth` / `par_conf`. The S-AL must encrypt the frame
// before it leaves the bus.
//
// They are not in the official KNX conformance XML (the spec only
// scripts the receive side) — this is our own coverage for the
// transmit-side fix in the AL/S-AL layering rework. Without these, a
// regression that drops the buffer's `RequiredSecurity` annotation or
// reverts the outbox-swap around `handle_app_request` would slip past
// the upstream conformance tests.
//
// Setup phase (test_3_2_setup) writes:
//   GO_SEC_2 (CO 11, GA 5/5/5)        flag=0x00 plain
//   GO_SEC_0 (CO 12, GA 2/2/2 send)   flag=0x01 auth-only
//   GO_SEC_1 (CO 13, GA 4/4/4 send)   flag=0x03 auth+conf
//   GO_SEC_3 (CO 14, GA 6/6/6)        flag=0x02 c-only (reserved/undefined)
//
// We trigger writes from the local app (ASAP 12, 13, 11) and assert the
// outbound encryption matches each GO's flag bits.

// Plaintext template for a spontaneous GroupValue_Write to GA 2/2/2 from
// the DUT carrying value 0 (the default for `go_sec_0`). Short APCI form
// (1-bit DPT_Switch fits in the low 6 bits of the second APCI byte):
// APCI = 0x00 0x80 (GroupValueWrite | value=0).
const GV_WRITE_222_VAL0: &str = "BC #BDUT_ADDR 12 02 E1 00 80";

// Same as above but for GA 4/4/4 (GO_SEC_1's send TSAP).
const GV_WRITE_444_VAL0: &str = "BC #BDUT_ADDR 24 04 E1 00 80";

// Plaintext outbound to GA 5/5/5 (GO_SEC_2, plain).
const GV_WRITE_555_VAL0: &str = "BC #BDUT_ADDR 2D 05 E1 00 80";

// 3.2.tx.1 — GO_SEC_0 (auth-only) spontaneous write must be encrypted A.
//
// `trigger_write(12)` makes the DUT push an A_GroupValue_Write.req for
// ASAP 12 (GO_SEC_0). With `PID_GO_SECURITY_FLAGS[11] = 0x01` the AL
// stamps `RequiredSecurity::Auth`; the S-AL encrypts auth-only with the
// GO's send-side group key (GK2 on 2/2/2).
fn test_3_2_tx_1_auth_only() -> TestCase {
    TestCase::new("3.2.tx.1 spontaneous GO_SEC_0 (auth-only) → A-secured tx").with_steps(vec![
        comment("DUT-initiated GroupValue_Write on ASAP 12 (GO_SEC_0)"),
        comment("PID_GO_SECURITY_FLAGS=0x01 → must be encrypted auth-only with GK2"),
        trigger_write(12),
        expect_group_ao(GV_WRITE_222_VAL0, "GK2", TIMEOUT),
    ])
}

// 3.2.tx.2 — GO_SEC_1 (auth+conf) spontaneous write must be encrypted A+C.
fn test_3_2_tx_2_auth_conf() -> TestCase {
    TestCase::new("3.2.tx.2 spontaneous GO_SEC_1 (auth+conf) → A+C-secured tx").with_steps(vec![
        comment("DUT-initiated GroupValue_Write on ASAP 13 (GO_SEC_1)"),
        comment("PID_GO_SECURITY_FLAGS=0x03 → must be encrypted A+C with GK4"),
        trigger_write(13),
        expect_group_ac(GV_WRITE_444_VAL0, "GK4", TIMEOUT),
    ])
}

// 3.2.tx.3 — GO_SEC_2 (plain) spontaneous write must remain plaintext.
//
// Guards against an over-eager S-AL accidentally encrypting a GO whose
// flags are 0x00 — the receiver would reject the frame as "secure to
// plain-only GO" (cf. test 3.2.18) and the bus would silently lose the
// update.
fn test_3_2_tx_3_plain() -> TestCase {
    TestCase::new("3.2.tx.3 spontaneous GO_SEC_2 (plain) → plain tx").with_steps(vec![
        comment("DUT-initiated GroupValue_Write on ASAP 11 (GO_SEC_2)"),
        comment("PID_GO_SECURITY_FLAGS=0x00 → must be sent in plaintext"),
        trigger_write(11),
        expect(GV_WRITE_555_VAL0, TIMEOUT),
    ])
}

// 3.2.tx.4 — a required-secure send with no matching group key must be
// negatively confirmed inside the device and must not fall back to plaintext.
fn test_3_2_tx_4_missing_key_fails_closed() -> TestCase {
    TestCase::new("3.2.tx.4 missing group key fails closed").with_steps(vec![
        comment("Move GK2 away from TSAP 12 while Security IO is loading"),
        inject_secure_ac(LOAD_START_LOADING, "TK1"),
        expect_secure_ac(LOAD_START_LOADING_OK, "TK1", TIMEOUT),
        inject_secure_ac(REMOVE_GRP_KEY_ENTRY_2, "TK1"),
        expect_secure_ac(REMOVE_GRP_KEY_ENTRY_2_OK, "TK1", TIMEOUT),
        inject_secure_ac(LOAD_COMPLETED, "TK1"),
        expect_secure_ac(LOAD_COMPLETED_OK, "TK1", TIMEOUT),
        comment("Required-auth send without GK2 must emit neither secure nor plaintext traffic"),
        trigger_write(12),
        expect_none(TIMEOUT),
        comment("Restore GK2 for following suites"),
        inject_secure_ac(LOAD_START_LOADING, "TK1"),
        expect_secure_ac(LOAD_START_LOADING_OK, "TK1", TIMEOUT),
        inject_secure_ac(RESTORE_GRP_KEY_ENTRY_2, "TK1"),
        expect_secure_ac(RESTORE_GRP_KEY_ENTRY_2_OK, "TK1", TIMEOUT),
        inject_secure_ac(LOAD_COMPLETED, "TK1"),
        expect_secure_ac(LOAD_COMPLETED_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.2.1 — placeholder (introduction / setup assumptions, 0 telegrams in XML)
// ============================================================================

fn test_3_2_1() -> TestCase {
    TestCase::new("3.2.1 Introduction")
        .with_steps(vec![comment("Placeholder: documents GO/key/GA assumptions for the 3.2 suite.")])
}
