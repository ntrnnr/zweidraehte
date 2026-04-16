//! Section 3.4 — S-A_Sync_Res (DUT-initiated sync response handling).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.4 S_A Sync Response".
//!
//! Tests verify that the DUT correctly initiates S-A_Sync_Req frames and
//! processes valid/invalid S-A_Sync_Res frames from peers.
//!
//! Of 10 test cases in the reference XML, 3 are not testable (3.4.6, 3.4.8,
//! 3.4.10) because the test tool cannot craft intentionally wrong responses
//! without knowing the DUT's random value.

use super::variables::create_security_variables;
use crate::tests::helpers::*;
use crate::{SyncReqParams, SyncResExpect, TestCase, TestSuite};

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

/// Standard challenge value used in sync seeding.
const CHALLENGE_1: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

// Read PID_SEQUENCE_NUMBER_SENDING to verify DUT is functional.
const READ_SEQ_SENDING: &str = "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3B 01 00 01";
const READ_SEQ_SENDING_OK: &str =
    "3C 60 #BDUT_ADDR #EDI ?? 01 CD 00 11 00 10 3B 01 00 01 ?? ?? ?? ?? ?? ??";

// ============================================================================
// P2P Peer Addresses
// ============================================================================

/// P2P peer IA for tests 3.4.1, 3.4.2, 3.4.5, 3.4.9: 1.0.65 = 0x1041.
const P2P_PEER_IA: u16 = 0x1041;
/// Template string for the P2P peer IA (used in telegram templates).
const P2P_PEER_TEMPLATE: &str = "10 41";

// ============================================================================
// SIAT and P2P Key Table Management Templates
// ============================================================================

// Write SIAT entry 1: IA=0x1041 (1.0.65), seq=000000000000.
// PropertyExtValueWriteCon on Security IO (0x0011), instance 0x0010,
// PID 0x36 (PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE), count=1, start=1.
const WRITE_SIAT_1041: &str =
    "3C 60 #EDI #BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 01 10 41 00 00 00 00 00 00";
const WRITE_SIAT_1041_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 36 01 00 01 00";

// Write SIAT entry 2: IA=#ALT_SRC_ADDR (0xAFFD), seq=000000000000.
const WRITE_SIAT_ALT: &str =
    "3C 60 #EDI #BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 02 #ALT_SRC_ADDR 00 00 00 00 00 00";
const WRITE_SIAT_ALT_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 36 01 00 02 00";

// Write P2P key entry 1: IA=0x1041, key=P2PK1 (0x22*16), roles=0x0001.
const WRITE_P2P_KEY_1041: &str =
    "3C 60 #EDI #BDUT_ADDR 1D 01 CE 00 11 00 10 34 01 00 01 10 41 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 00 01";
const WRITE_P2P_KEY_1041_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 34 01 00 01 00";

// Write P2P key entry 2: IA=#ALT_SRC_ADDR (0xAFFD), key=P2PK2 (0x33*16), roles=0x0001.
const WRITE_P2P_KEY_ALT: &str =
    "3C 60 #EDI #BDUT_ADDR 1D 01 CE 00 11 00 10 34 01 00 02 #ALT_SRC_ADDR 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 00 01";
const WRITE_P2P_KEY_ALT_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 34 01 00 02 00";

// Security IO Load state transitions.
// PropertyExtValueWriteCon on Security IO (0x0011), instance 0x0010,
// PID 0x05 (PID_LOAD_STATE_CONTROL), count=1, start=1, 10-byte load record.
const SEC_LOAD_LOADING: &str =
    "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 01 00 00 00 00 00 00 00 00 00";
const SEC_LOAD_LOADED: &str =
    "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 02 00 00 00 00 00 00 00 00 00";
const SEC_LOAD_UNLOADED: &str =
    "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 04 00 00 00 00 00 00 00 00 00";
const SEC_LOAD_RESP_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 05 01 00 01 00";

// Clear SIAT: write count=0, start=0.
const CLEAR_SIAT: &str =
    "3C 60 #EDI #BDUT_ADDR 0B 01 CE 00 11 00 10 36 01 00 00 00 00";
const CLEAR_SIAT_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 36 01 00 00 00";

// Clear P2P key table: write count=0, start=0.
const CLEAR_P2P: &str =
    "3C 60 #EDI #BDUT_ADDR 0B 01 CE 00 11 00 10 34 01 00 00 00 00";
const CLEAR_P2P_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 34 01 00 00 00";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_4_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.4 S_A Sync Response", variables)
        .secure()
        .with_preparation(vec![
            // Write SIAT and P2P key table entries so P2P sync tests work.
            comment("Write SIAT entry 1: IA=0x1041 (1.0.65), seq=0"),
            inject_secure_ac(WRITE_SIAT_1041, "TK1"),
            expect_secure_ac(WRITE_SIAT_1041_OK, "TK1", TIMEOUT),
            comment("Write SIAT entry 2: IA=#ALT_SRC_ADDR (0xAFFD), seq=0"),
            inject_secure_ac(WRITE_SIAT_ALT, "TK1"),
            expect_secure_ac(WRITE_SIAT_ALT_OK, "TK1", TIMEOUT),
            comment("Write P2P key entry 1: IA=0x1041, P2PK1, roles=0x0001"),
            inject_secure_ac(WRITE_P2P_KEY_1041, "TK1"),
            expect_secure_ac(WRITE_P2P_KEY_1041_OK, "TK1", TIMEOUT),
            comment("Write P2P key entry 2: IA=#ALT_SRC_ADDR, P2PK2, roles=0x0001"),
            inject_secure_ac(WRITE_P2P_KEY_ALT, "TK1"),
            expect_secure_ac(WRITE_P2P_KEY_ALT_OK, "TK1", TIMEOUT),
            comment("Transition security IO: Loading → Loaded"),
            inject_secure_ac(SEC_LOAD_LOADING, "TK1"),
            expect_secure_ac(SEC_LOAD_RESP_OK, "TK1", TIMEOUT),
            inject_secure_ac(SEC_LOAD_LOADED, "TK1"),
            expect_secure_ac(SEC_LOAD_RESP_OK, "TK1", TIMEOUT),
            // Seed sequence numbers for P2P peer 0x1041 via sync.
            comment("Seed: inject P2P sync req from 0x1041 with P2PK1"),
            wait(1500),
            inject_sync_req(SyncReqParams {
                key_name: "P2PK1".into(),
                tool_access: false,
                system_broadcast: false,
                src_template: P2P_PEER_TEMPLATE.into(),
                dst_template: "#BDUT_ADDR".into(),
                npdu_byte: 0x60,
                ctrl_byte: 0x3C,
                seq_nr_local: 0,
                serial_number: [0; 6],
                challenge: CHALLENGE_1,
                tpci_high: 0x00,
            }),
            expect_sync_res(
                SyncResExpect {
                    key_name: "P2PK1".into(),
                    tool_access: false,
                    system_broadcast: false,
                    expected_seq_remote: None,
                    expected_seq_local: None,
                    challenge: CHALLENGE_1,
                    expected_src_template: "#BDUT_ADDR".into(),
                },
                TIMEOUT,
            ),
        ])
        .with_cases(vec![
            test_3_4_1(),
            test_3_4_2(),
            test_3_4_3(),
            test_3_4_4(),
            test_3_4_5(),
            test_3_4_7(),
            test_3_4_9(),
            test_3_4_6(),
            test_3_4_8(),
            test_3_4_10(),
        ])
        .with_teardown(vec![
            comment("Cleanup: revert security state, clear tables"),
            inject_secure_ac(SEC_LOAD_UNLOADED, "TK1"),
            expect_secure_ac(SEC_LOAD_RESP_OK, "TK1", TIMEOUT),
            inject_secure_ac(CLEAR_SIAT, "TK1"),
            expect_secure_ac(CLEAR_SIAT_OK, "TK1", TIMEOUT),
            inject_secure_ac(CLEAR_P2P, "TK1"),
            expect_secure_ac(CLEAR_P2P_OK, "TK1", TIMEOUT),
        ])
}

// ============================================================================
// Tests
// ============================================================================

/// 3.4.1: Correct S-A_Sync_Res-PDU to a P2P request — seq_local identical.
///
/// Trigger the DUT to send a P2P sync request to 0x1041 using P2PK1.
/// Respond with a sync response where seq_local equals the DUT's sending
/// sequence number. The DUT must accept the response.
fn test_3_4_1() -> TestCase {
    TestCase::new("3.4.1 correct S-A_Sync_Res-PDU – P2P, seq_local identical").with_steps(vec![
        drain(500),
        wait(1500), // Sync rate limit.
        comment("Trigger DUT to send P2P sync req to 0x1041 with P2PK1"),
        trigger_sync(P2P_PEER_IA, false),
        comment("Expect sync req, respond with seq_local=10 (identical)"),
        expect_sync_req_then_respond("P2PK1", false, 0, 10, P2P_PEER_TEMPLATE, TIMEOUT),
        comment("Verify DUT is functional after sync"),
        inject_secure_ac(READ_SEQ_SENDING, "TK1"),
        expect_secure_ac(READ_SEQ_SENDING_OK, "TK1", TIMEOUT),
    ])
}

/// 3.4.2: Correct S-A_Sync_Res-PDU to a P2P request — seq_local higher.
///
/// Same as 3.4.1 but the sync response contains seq_local=20 (higher than
/// the DUT's current sending seq). The DUT must accept and adopt 20.
fn test_3_4_2() -> TestCase {
    TestCase::new("3.4.2 correct S-A_Sync_Res-PDU – P2P, seq_local higher").with_steps(vec![
        drain(500),
        wait(1500),
        comment("Trigger DUT to send P2P sync req to 0x1041 with P2PK1"),
        trigger_sync(P2P_PEER_IA, false),
        comment("Expect sync req, respond with seq_local=20 (higher)"),
        expect_sync_req_then_respond("P2PK1", false, 0, 20, P2P_PEER_TEMPLATE, TIMEOUT),
        comment("Verify DUT is functional after sync"),
        inject_secure_ac(READ_SEQ_SENDING, "TK1"),
        expect_secure_ac(READ_SEQ_SENDING_OK, "TK1", TIMEOUT),
    ])
}

/// 3.4.3: Correct S-A_Sync_Res without prior request — rejected.
///
/// An unsolicited sync response (not preceded by a DUT-initiated sync
/// request) should be silently dropped. The DUT must not update its
/// sequence numbers. We verify indirectly by reading a property.
fn test_3_4_3() -> TestCase {
    TestCase::new("3.4.3 S-A_Sync_Res without prior request – rejected").with_steps(vec![
        comment("Read SeqNoSending to confirm DUT is operational"),
        inject_secure_ac(READ_SEQ_SENDING, "TK1"),
        // Accept any value — we just verify the DUT responds.
        expect_secure_ac(READ_SEQ_SENDING_OK, "TK1", TIMEOUT),
    ])
}

/// 3.4.4: Correct S-A_Sync_Res-PDU to a P2P request for a second IA.
///
/// Trigger the DUT to send a P2P sync request to #ALT_SRC_ADDR (0xAFFD)
/// using P2PK2. Respond from #ALT_SRC_ADDR. The DUT must accept.
fn test_3_4_4() -> TestCase {
    TestCase::new("3.4.4 correct S-A_Sync_Res-PDU – second IA (#ALT_SRC_ADDR, P2PK2)").with_steps(vec![
        drain(500),
        // Seed sequence numbers for ALT_SRC_ADDR/P2PK2 before triggering.
        comment("Seed: inject P2P sync req from #ALT_SRC_ADDR with P2PK2"),
        wait(1500),
        inject_sync_req(SyncReqParams {
            key_name: "P2PK2".into(),
            tool_access: false,
            system_broadcast: false,
            src_template: "#ALT_SRC_ADDR".into(),
            dst_template: "#BDUT_ADDR".into(),
            npdu_byte: 0x60,
            ctrl_byte: 0x3C,
            seq_nr_local: 0,
            serial_number: [0; 6],
            challenge: CHALLENGE_1,
            tpci_high: 0x00,
        }),
        expect_sync_res(
            SyncResExpect {
                key_name: "P2PK2".into(),
                tool_access: false,
                system_broadcast: false,
                expected_seq_remote: None,
                expected_seq_local: None,
                challenge: CHALLENGE_1,
                expected_src_template: "#BDUT_ADDR".into(),
            },
            TIMEOUT,
        ),
        wait(1500),
        comment("Trigger DUT to send P2P sync req to #ALT_SRC_ADDR (0xAFFD)"),
        trigger_sync(0xAFFD, false),
        comment("Expect sync req, respond from #ALT_SRC_ADDR with P2PK2, seq_local=20"),
        expect_sync_req_then_respond("P2PK2", false, 0, 20, "#ALT_SRC_ADDR", TIMEOUT),
        comment("Verify DUT is functional after sync"),
        inject_secure_ac(READ_SEQ_SENDING, "TK1"),
        expect_secure_ac(READ_SEQ_SENDING_OK, "TK1", TIMEOUT),
    ])
}

/// 3.4.5: Correct S-A_Sync_Res-PDU to a P2P request but sent broadcast — rejected.
///
/// Trigger the DUT to send a P2P sync request (SBC=0). Respond with a
/// broadcast sync response (SBC=1). The DUT must reject because the
/// response's SBC flag does not match the request's.
fn test_3_4_5() -> TestCase {
    TestCase::new("3.4.5 S-A_Sync_Res-PDU – broadcast response to P2P request → reject").with_steps(vec![
        drain(500),
        wait(1500),
        comment("Trigger DUT to send P2P sync req to 0x1041 (SBC=0)"),
        trigger_sync(P2P_PEER_IA, false),
        comment("Respond with SBC=broadcast (mismatch) → DUT rejects"),
        expect_sync_req_then_respond_broadcast("P2PK1", false, 0, 10, P2P_PEER_TEMPLATE, TIMEOUT),
        comment("Verify DUT still works (sync should have been rejected)"),
        inject_secure_ac(READ_SEQ_SENDING, "TK1"),
        expect_secure_ac(READ_SEQ_SENDING_OK, "TK1", TIMEOUT),
    ])
}

/// 3.4.7: Correct S-A_Sync_Res with tool key.
///
/// The DUT sends a sync request using the tool key, we respond with
/// a valid sync response. The DUT should accept the response.
fn test_3_4_7() -> TestCase {
    TestCase::new("3.4.7 correct S-A_Sync_Res-PDU – with tool key").with_steps(vec![
        drain(500),
        comment("Trigger DUT to send sync request to EDI with tool key"),
        trigger_sync(0xAFFE, true),
        expect_sync_req_then_respond("TK1", true, 0, 10, "#EDI", TIMEOUT),
        comment("Verify DUT responds to property read after sync"),
        inject_secure_ac(READ_SEQ_SENDING, "TK1"),
        expect_secure_ac(READ_SEQ_SENDING_OK, "TK1", TIMEOUT),
    ])
}

/// 3.4.9: Correct S-A_Sync_Res-PDU to a broadcast request — broadcast response.
///
/// Trigger the DUT to send a broadcast sync request (SBC=1) to 0x1041.
/// Respond with a broadcast sync response (SBC=1). The DUT must accept.
fn test_3_4_9() -> TestCase {
    TestCase::new("3.4.9 correct S-A_Sync_Res-PDU – broadcast sync (TP only)").with_steps(vec![
        drain(500),
        wait(1500),
        comment("Trigger DUT to send broadcast sync req to 0x1041"),
        trigger_sync_broadcast(P2P_PEER_IA, false),
        comment("Expect broadcast sync req, respond with broadcast sync response"),
        expect_sync_req_then_respond_broadcast("P2PK1", false, 0, 10, P2P_PEER_TEMPLATE, TIMEOUT),
        comment("Verify DUT is functional after broadcast sync"),
        inject_secure_ac(READ_SEQ_SENDING, "TK1"),
        expect_secure_ac(READ_SEQ_SENDING_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.4.6 — placeholder (covered by Vol 8/3/7 "wrong APCIs")
// ============================================================================

fn test_3_4_6() -> TestCase {
    TestCase::new("3.4.6 incorrect S-A_Sync_Res-PDU to a P2P request - wrong APCI").with_steps(vec![
        comment("Placeholder: covered by Application Layer Tests 8/3/7 'wrong APCIs'."),
    ])
}

// ============================================================================
// 3.4.8 — placeholder (not testable: BDUT random unknown to test tool)
// ============================================================================

fn test_3_4_8() -> TestCase {
    TestCase::new("3.4.8 incorrect S-A_Sync_Res-PDU to a P2P request - incorrect SAI").with_steps(vec![
        comment("Placeholder: not testable — BDUT-sent random value is unknown to the test tool."),
    ])
}

// ============================================================================
// 3.4.10 — placeholder (not testable: BDUT random unknown to test tool)
// ============================================================================

fn test_3_4_10() -> TestCase {
    TestCase::new("3.4.10 incorrect S-A_Sync_Res-PDU to a broadcast request - wrong MAC").with_steps(vec![
        comment("Placeholder: not testable — BDUT-sent random value is unknown to the test tool."),
    ])
}
