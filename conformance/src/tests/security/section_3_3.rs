//! Section 3.3 — S-A_Sync_Req (22 test cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.3 S_A Sync Request".
//!
//! Tests verify that the DUT correctly handles incoming S-A_Sync_Req
//! frames and responds with proper S-A_Sync_Res frames (positive tests)
//! or silently rejects invalid requests (negative tests).

use super::variables::create_security_variables;
use crate::tests::helpers::*;
use crate::{InvalidSecurityParam, SeqSource, SyncReqParams, SyncResExpect, TestCase, TestSuite};

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

/// Standard challenge value used in most tests.
const CHALLENGE_1: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

/// DUT serial number matching the test variable #SER_NUM.
const DUT_SERIAL: [u8; 6] = [0xFE, 0xED, 0xBA, 0xBE, 0xCA, 0xFE];

// ============================================================================
// Preparation: provision the P2P partner and seed sequence numbers
// ============================================================================

// Both the non-tool sync in 3.3.4 and the counter-isolation check in 3.3.15
// need this row. Suite preparation also runs when either case is filtered.
const WRITE_SIAT: &str = "3C 60 #EDI #BDUT_ADDR 11 01 CE 00 11 00 10 36 01 00 01 #EDI 00 00 00 00 00 01";
const WRITE_SIAT_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 36 01 00 01 00";

// P2PK1 addresses its partner by SIAT index 1, not by individual address.
const WRITE_P2P_KEY: &str = "3C 60 #EDI #BDUT_ADDR 1D 01 CE 00 11 00 10 34 01 00 01 00 01 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 00 01";
const WRITE_P2P_KEY_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 34 01 00 01 00";

const SEC_LOAD_LOADING: &str = "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 01 00 00 00 00 00 00 00 00 00";
const SEC_LOAD_LOADED: &str = "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 02 00 00 00 00 00 00 00 00 00";
const SEC_LOAD_UNLOADED: &str = "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 04 00 00 00 00 00 00 00 00 00";
const SEC_LOAD_RESP_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 05 01 00 01 00";

/// Write PID_SEQUENCE_NUMBER_SENDING = 2 to the DUT via secure property write.
const WRITE_SEQ_SENDING_2: &str = "3C 60 #EDI #BDUT_ADDR 0F 01 CE 00 11 00 10 3B 01 00 01 00 00 00 00 00 02";
const WRITE_SEQ_SENDING_2_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 3B 01 00 01 00";

// Read PID_SEQUENCE_NUMBER_SENDING to verify.
#[allow(dead_code)]
const READ_SEQ_SENDING: &str = "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3B 01 00 01";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_3_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.3 S_A Sync Request", variables)
        .secure()
        .with_preparation(vec![
            comment("Load the shared non-tool partner: SIAT entry 1 is #EDI with sequence 1 and key P2PK1"),
            inject_secure_ac(SEC_LOAD_LOADING, "TK1"),
            expect_secure_ac(SEC_LOAD_RESP_OK, "TK1", TIMEOUT),
            inject_secure_ac(WRITE_SIAT, "TK1"),
            expect_secure_ac(WRITE_SIAT_OK, "TK1", TIMEOUT),
            inject_secure_ac(WRITE_P2P_KEY, "TK1"),
            expect_secure_ac(WRITE_P2P_KEY_OK, "TK1", TIMEOUT),
            inject_secure_ac(SEC_LOAD_LOADED, "TK1"),
            expect_secure_ac(SEC_LOAD_RESP_OK, "TK1", TIMEOUT),
            comment("Write SeqNoSending=2 in the BDUT"),
            inject_secure_ac(WRITE_SEQ_SENDING_2, "TK1"),
            expect_secure_ac(WRITE_SEQ_SENDING_2_OK, "TK1", TIMEOUT),
            comment("Initial sync to seed EITT sequence numbers"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
            comment("Wait for sync rate limit to expire"),
            wait(1500),
        ])
        .with_cases(vec![
            // Placeholder cases (0 active telegrams in XML).
            test_3_3_0(),
            test_3_3_7(),
            test_3_3_12(),
            // ================================================================
            // Positive tests
            // ================================================================
            test_3_3_1(),
            test_3_3_2(),
            test_3_3_3(),
            test_3_3_4(),
            test_3_3_5(),
            test_3_3_6(),
            test_3_3_13(),
            test_3_3_14(),
            test_3_3_17(),
            test_3_3_22(),
            // 3.3.15 and 3.3.16 permanently raise the DUT's stored tool
            // receiving sequence number to ~5 billion. Keep them after the
            // low-counter cases; sync responses advance the runner to the
            // accepted floor for subsequent secure property reads.
            test_3_3_15(),
            test_3_3_16(),
            // ================================================================
            // Negative tests
            // ================================================================
            test_3_3_8(),
            test_3_3_9(),
            test_3_3_10(),
            test_3_3_11(),
            test_3_3_18(),
            test_3_3_19(),
            test_3_3_20(),
            test_3_3_21(),
        ])
        .with_teardown(vec![
            // Tests 3.3.15/3.3.16 permanently raise the DUT's stored tool
            // receiving sequence number to ~5 billion. The runner's
            // ExpectSyncRes handler updates tool_seq_nr from the DUT's
            // SeqNr_local, so a final sync re-aligns the harness's data
            // counter with what the DUT expects for subsequent suites.
            comment("Re-sync to align harness tool_seq_nr after high-sequence tests"),
            wait(1500),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
            // Unload clears SIAT as well as keys. Defer it until 3.3.15 has
            // checked that tool-key sync leaves the non-tool counter intact.
            comment("Unload Security IO after all shared-table assertions"),
            inject_secure_ac(SEC_LOAD_UNLOADED, "TK1"),
            expect_secure_ac(SEC_LOAD_RESP_OK, "TK1", TIMEOUT),
        ])
}

// ============================================================================
// Positive tests
// ============================================================================

/// 3.3.1: Correct S-A_Sync_Req, A+C, P2P connection-oriented, tool key.
///
/// Sends a sync request inside a connected transport session (T_Connect /
/// T_Disconnect). A malformed secure APDU first advances only the request
/// direction; the sync then uses TPCI=0x47 (numbered data, seq 1), while the
/// DUT must protect its S-A_Sync_Res with its independent outgoing seq 0.
fn test_3_3_1() -> TestCase {
    TestCase::new("3.3.1 correct S-A_Sync_Req-PDU, A+C – P2P – connection-oriented").with_steps(vec![
        wait(1500), // Sync rate limit.
        comment("Open transport connection"),
        inject("BC #EDI #BDUT_ADDR 60 80"),
        comment("Advance only the request-side TL sequence with a malformed secure APDU"),
        inject("BC #EDI #BDUT_ADDR 60 43 F1"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        comment("Send connection-oriented sync req (TPCI=0x47: numbered data seq 1)"),
        inject_sync_req(SyncReqParams {
            key_name: "TK1".into(),
            tool_access: true,
            system_broadcast: false,
            src_template: "#EDI".into(),
            dst_template: "#BDUT_ADDR".into(),
            npdu_byte: 0x60,
            ctrl_byte: 0x3C,
            seq_local: SeqSource::Fixed(0),
            serial_number: [0; 6],
            challenge: CHALLENGE_1,
            tpci_high: 0x47,
        }),
        comment("Expect T_ACK for our numbered data"),
        expect("B0 #BDUT_ADDR #EDI 60 C6", TIMEOUT),
        comment("Expect connection-oriented sync response on the DUT's independent sequence 0"),
        expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
        comment("ACK the DUT's response"),
        inject("BC #EDI #BDUT_ADDR 60 C2"),
        comment("Close transport connection"),
        inject("BC #EDI #BDUT_ADDR 60 81"),
    ])
}

/// 3.3.2: Correct S-A_Sync_Req, A+C, P2P connectionless, tool key.
fn test_3_3_2() -> TestCase {
    TestCase::new("3.3.2 correct S-A_Sync_Req-PDU, A+C – P2P – connectionless").with_steps(vec![
        wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
        comment("Send correct sync req connectionless with TK1"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE_1),
        expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
    ])
}

/// 3.3.3: Correct S-A_Sync_Req from second IA (0xFFFE).
fn test_3_3_3() -> TestCase {
    TestCase::new("3.3.3 correct S-A_Sync_Req-PDU, A+C – P2P connectionless, from second IA").with_steps(vec![
        wait(1500), // Rate limit: need > 1s between sync responses.
        comment("Send sync req from alternate source FF FE with TK1"),
        inject_sync_req(SyncReqParams {
            key_name: "TK1".into(),
            tool_access: true,
            system_broadcast: false,
            src_template: "FF FE".into(),
            dst_template: "#BDUT_ADDR".into(),
            npdu_byte: 0x60,
            ctrl_byte: 0x3C,
            seq_local: SeqSource::Fixed(0),
            serial_number: [0; 6],
            challenge: CHALLENGE_1,
            tpci_high: 0x00,
        }),
        expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
    ])
}

/// 3.3.4: Correct S-A_Sync_Req with P2P key (not tool key), connectionless.
///
/// Optional for devices not supporting PID_P2P_KEY_TABLE. Suite preparation
/// provisions EDI with non-tool sequence 1 and P2PK1 (roles 0x0001). Send a
/// P2P sync request (SCF 0x12: A+C, no tool) and expect a valid response
/// (SCF 0x13) encrypted with P2PK1. Keep the row for 3.3.15's read-back.
fn test_3_3_4() -> TestCase {
    TestCase::new("3.3.4 correct S-A_Sync_Req-PDU, A+C – P2P, connectionless, not with ToolKey (conditional)")
        .with_steps(vec![
            comment("THIS TEST CASE IS OPTIONAL FOR DEVICES NOT SUPPORTING P2P_KEY_TABLE"),
            wait(1500), // Rate limit.
            comment("Send P2P sync req with P2PK1 (SCF=0x12: A+C, no tool)"),
            inject_sync_req(SyncReqParams {
                key_name: "P2PK1".into(),
                tool_access: false,
                system_broadcast: false,
                src_template: "#EDI".into(),
                dst_template: "#BDUT_ADDR".into(),
                npdu_byte: 0x60,
                ctrl_byte: 0x3C,
                seq_local: SeqSource::Fixed(0),
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
}

/// 3.3.5: P2P sync from IA not in SIAT → reject.
///
/// Sends a P2P sync request from IA 0x1117 (not in the SIAT) using P2PK1.
/// The DUT must silently drop the frame because the sender's IA is not
/// authorized in the Security Individual Address Table.
fn test_3_3_5() -> TestCase {
    TestCase::new("3.3.5 correct S-A_Sync_Req-PDU, A+C – P2P, connectionless, not with tool key, from IA not part of the PID_Security_Individual_Address_Table").with_steps(vec![
        wait(1500), // Rate limit.
        comment("Send P2P sync req from IA 0x1117 (not in SIAT) with P2PK1 → reject"),
        inject_sync_req(SyncReqParams {
            key_name: "P2PK1".into(),
            tool_access: false,
            system_broadcast: false,
            src_template: "11 17".into(),
            dst_template: "#BDUT_ADDR".into(),
            npdu_byte: 0x60,
            ctrl_byte: 0x3C,
            seq_local: SeqSource::Fixed(0),
            serial_number: [0; 6],
            challenge: CHALLENGE_1,
            tpci_high: 0x00,
        }),
        expect_none(TIMEOUT),
    ])
}

/// 3.3.6: Correct S-A_Sync_Req via broadcast and system broadcast.
fn test_3_3_6() -> TestCase {
    TestCase::new("3.3.6 correct S-A_Sync_Req-PDU – (system) broadcast").with_steps(vec![
        wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
        comment("Broadcast sync req with matching serial number"),
        inject_sync_req_broadcast("#EDI", "TK1", 0, DUT_SERIAL, CHALLENGE_1, false),
        expect_sync_res(
            SyncResExpect {
                key_name: "TK1".into(),
                tool_access: true,
                system_broadcast: false,
                expected_seq_remote: None,
                expected_seq_local: None,
                challenge: CHALLENGE_1,
                expected_src_template: "#BDUT_ADDR".into(),
            },
            TIMEOUT,
        ),
        wait(1500), // Rate limit: must wait > 1 second between sync responses.
        comment("System broadcast sync req with matching serial number"),
        inject_sync_req_broadcast("#EDI", "TK1", 0, DUT_SERIAL, CHALLENGE_1, true),
        expect_sync_res(
            SyncResExpect {
                key_name: "TK1".into(),
                tool_access: true,
                system_broadcast: true,
                expected_seq_remote: None,
                expected_seq_local: None,
                challenge: CHALLENGE_1,
                expected_src_template: "#BDUT_ADDR".into(),
            },
            TIMEOUT,
        ),
    ])
}

/// 3.3.13: Correct S-A_Sync_Req with a different challenge value.
fn test_3_3_13() -> TestCase {
    let challenge_2: [u8; 6] = [0x11, 0x11, 0x11, 0x11, 0x11, 0x11];
    TestCase::new("3.3.13 correct S-A_Sync_Req-PDU - A+C – P2P - other challenge").with_steps(vec![
        wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
        comment("Send sync req with different challenge value"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, challenge_2),
        expect_sync_res_tool("TK1", challenge_2, None, None, TIMEOUT),
    ])
}

/// 3.3.14: SeqNr_local lower than expected by BDUT — DUT still responds.
fn test_3_3_14() -> TestCase {
    TestCase::new("3.3.14 correct S-A_Sync_Req-PDU – sequence number local lower than expected by BDUT – P2P")
        .with_steps(vec![
            wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
            comment("Send sync req with SeqNr_local=1 (lower than what BDUT expects)"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 1, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
        ])
}

/// 3.3.15: SeqNr_local higher than expected by BDUT — DUT accepts and
/// updates its stored receiving sequence number to the new value.
///
/// The EITT XML sets the tool's outgoing seq to 5,000,000,000 which is
/// far higher than the DUT's stored value (~2 from previous tests). The
/// DUT should accept, update stored to (received - 1), and reflect the
/// received value back as response SeqNr_local. A second sync with
/// seq 5,000,000,001 confirms the DUT retained the update. Finally, we
/// verify that the SIAT entry for #EDI still shows seq=1 (tool seq and
/// non-tool SIAT seq are independent).
fn test_3_3_15() -> TestCase {
    const HIGH_SEQ: u64 = 5_000_000_000;

    // After the two tool syncs, read PID 54 entry 1 and check it still holds
    // #EDI with non-tool LastValidSeqNr = 1 (seeded in preparation). This is the
    // template's read-back: it proves the *non-tool* per-IA seqnr is unaffected
    // by the tool-access sync (the two counters are independent — NOTE 104) and
    // that PID 54 reads return the live value from the store (03/05/01 §6.3.8).
    const READ_SIAT_EDI: &str = "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 36 01 00 01";
    const READ_SIAT_EDI_SEQ1: &str = "3C 60 #BDUT_ADDR #EDI 11 01 CD 00 11 00 10 36 01 00 01 #EDI 00 00 00 00 00 01";

    TestCase::new("3.3.15 correct S-A_Sync_Req-PDU – Sequence number local higher to that expected by BDUT – P2P")
        .with_steps(vec![
            wait(1500), // Sync rate limit.
            comment("Send sync req with SeqNr_local = 5,000,000,000 (far above stored)"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", HIGH_SEQ, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, Some(HIGH_SEQ), TIMEOUT),
            wait(1500), // Rate limit.
            comment("Send sync req with SeqNr_local = 5,000,000,001 (increment)"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", HIGH_SEQ + 1, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, Some(HIGH_SEQ + 1), TIMEOUT),
            comment("Read PID 54 entry 1: #EDI's non-tool seq is still 1 (seeded in preparation)"),
            inject_secure_ac(READ_SIAT_EDI, "TK1"),
            expect_secure_ac(READ_SIAT_EDI_SEQ1, "TK1", TIMEOUT),
        ])
}

/// 3.3.16: SeqNr_local identical to that expected by BDUT.
///
/// Establish the template's next-valid value locally, then read it back with
/// a zero-counter request. This must exercise equality even when filtering
/// omits 3.3.15; merely echoing the fixed value could otherwise test an advance.
fn test_3_3_16() -> TestCase {
    const EXPECTED_SEQ: u64 = 5_000_000_002;

    TestCase::new("3.3.16 correct S-A_Sync_Req-PDU – Sequence number local identical to that expected by BDUT – P2P")
        .with_preparation(vec![
            wait(1500),
            comment("Seed the template's next-valid tool sequence independently of 3.3.15"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", EXPECTED_SEQ, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, Some(EXPECTED_SEQ), TIMEOUT),
            wait(1500),
            comment("Probe with zero: the retained next-valid sequence must already equal 5,000,000,002"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, Some(EXPECTED_SEQ), TIMEOUT),
        ])
        .with_steps(vec![
            wait(1500), // Sync rate limit.
            comment("Send sync req with SeqNr_local = 5,000,000,002 (identical to expected)"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", EXPECTED_SEQ, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, Some(EXPECTED_SEQ), TIMEOUT),
        ])
}

/// 3.3.17: Sync reports the sending counter without consuming it; a data
/// response consumes one number. Follow the template's 100 → 101 → 101 checks.
fn test_3_3_17() -> TestCase {
    // Write SeqNoSending=100 (0x64) to DUT.
    let write_seq_100 = "3C 60 #EDI #BDUT_ADDR 0F 01 D0 00 11 00 10 3B 01 00 01 00 00 00 00 00 64";
    const READ_SEQ: &str = "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3B 01 00 01";
    const READ_SEQ_100: &str = "3C 60 #BDUT_ADDR #EDI 0F 01 CD 00 11 00 10 3B 01 00 01 00 00 00 00 00 64";
    const SECOND_CHALLENGE: [u8; 6] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];

    TestCase::new("3.3.17 correct S-A_Sync_Req-PDU – verification of correct setting of sequence number sending")
        .with_steps(vec![
            wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
            comment("Write SeqNoSending=100"),
            inject_secure_ac(write_seq_100, "TK1"),
            // A_PropertyExtValueWriteUnCon has no response and must not consume
            // a sending sequence number. A drain would hide an erroneous reply.
            expect_none(200),
            comment("Verify SeqNr_remote=100 in sync response"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, Some(100), None, TIMEOUT),
            comment("Read back 100: this data response consumes sequence number 100"),
            inject_secure_ac(READ_SEQ, "TK1"),
            expect_secure_ac(READ_SEQ_100, "TK1", TIMEOUT),
            comment("Sync with a different challenge must report the next sending sequence, 101"),
            wait(1500), // Rate limit.
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, SECOND_CHALLENGE),
            expect_sync_res_tool("TK1", SECOND_CHALLENGE, Some(101), None, TIMEOUT),
            wait(1500),
            comment("Repeating sync must leave the sending counter at 101"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, SECOND_CHALLENGE),
            expect_sync_res_tool("TK1", SECOND_CHALLENGE, Some(101), None, TIMEOUT),
        ])
}

/// 3.3.22: S-A_Sync_Req with SBC flag set for P2P (optional, should accept).
fn test_3_3_22() -> TestCase {
    TestCase::new("3.3.22 S-A_Sync_Req-PDU - A+C – P2P - with tool key – SBC flag set (optional)").with_steps(vec![
        wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
        comment("Send P2P sync req with SBC flag set — DUT should still accept"),
        inject_sync_req(SyncReqParams {
            key_name: "TK1".into(),
            tool_access: true,
            system_broadcast: true,
            src_template: "#EDI".into(),
            dst_template: "#BDUT_ADDR".into(),
            npdu_byte: 0x60,
            ctrl_byte: 0x30, // Extended frame with repeat flag.
            seq_local: SeqSource::Fixed(0),
            serial_number: [0; 6],
            challenge: CHALLENGE_1,
            tpci_high: 0x00,
        }),
        expect_sync_res(
            SyncResExpect {
                key_name: "TK1".into(),
                tool_access: true,
                system_broadcast: true,
                expected_seq_remote: None,
                expected_seq_local: None,
                challenge: CHALLENGE_1,
                expected_src_template: "#BDUT_ADDR".into(),
            },
            TIMEOUT,
        ),
    ])
}

// ============================================================================
// Negative tests — DUT should silently reject
// ============================================================================

/// 3.3.8: Invalid SCF (0x82, reserved SAI=000b) → reject.
fn test_3_3_8() -> TestCase {
    TestCase::new("3.3.8 incorrect S-A_Sync_Req-PDU – reserved SAI case 1").with_steps(vec![
        wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
        comment("Send sync req with invalid SCF 0x82 (reserved SAI) → reject"),
        inject_sync_req_invalid(
            SyncReqParams {
                key_name: "TK1".into(),
                tool_access: true,
                system_broadcast: false,
                src_template: "#EDI".into(),
                dst_template: "#BDUT_ADDR".into(),
                npdu_byte: 0x60,
                ctrl_byte: 0x3C,
                seq_local: SeqSource::Fixed(0),
                serial_number: [0; 6],
                challenge: CHALLENGE_1,
                tpci_high: 0x00,
            },
            InvalidSecurityParam::InvalidScf(0x82),
        ),
        expect_none(TIMEOUT),
    ])
}

/// 3.3.9: Invalid SCF (0xE2, reserved SAI=111b) → reject.
fn test_3_3_9() -> TestCase {
    TestCase::new("3.3.9 incorrect S-A_Sync_Req-PDU – reserved SAI case 2").with_steps(vec![
        wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
        comment("Send sync req with invalid SCF 0xE2 (reserved SAI) → reject"),
        inject_sync_req_invalid(
            SyncReqParams {
                key_name: "TK1".into(),
                tool_access: true,
                system_broadcast: false,
                src_template: "#EDI".into(),
                dst_template: "#BDUT_ADDR".into(),
                npdu_byte: 0x60,
                ctrl_byte: 0x3C,
                seq_local: SeqSource::Fixed(0),
                serial_number: [0; 6],
                challenge: CHALLENGE_1,
                tpci_high: 0x00,
            },
            InvalidSecurityParam::InvalidScf(0xE2),
        ),
        expect_none(TIMEOUT),
    ])
}

/// 3.3.10: Broadcast with serial=0 → reject.
fn test_3_3_10() -> TestCase {
    TestCase::new("3.3.10 S-A_Sync_Req, A+C with KNX Serial number set to 0 for (system) broadcast").with_steps(vec![
        wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
        comment("Broadcast sync req with serial=0 → reject"),
        inject_sync_req_broadcast("#EDI", "TK1", 0, [0; 6], CHALLENGE_1, false),
        expect_none(TIMEOUT),
        comment("System broadcast sync req with serial=0 → reject"),
        inject_sync_req_broadcast("#EDI", "TK1", 0, [0; 6], CHALLENGE_1, true),
        expect_none(TIMEOUT),
    ])
}

/// 3.3.11: Broadcast with wrong serial → reject.
fn test_3_3_11() -> TestCase {
    let wrong_serial: [u8; 6] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBB];
    TestCase::new("3.3.11 S-A_Sync_Req-PDU, A+C with KNX Serial number not corresponding to that of the BDUT – (system) broadcast").with_steps(vec![
        wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
        comment("Broadcast sync req with wrong serial → reject"),
        inject_sync_req_broadcast("#EDI", "TK1", 0, wrong_serial, CHALLENGE_1, false),
        expect_none(TIMEOUT),
        comment("System broadcast sync req with wrong serial → reject"),
        inject_sync_req_broadcast("#EDI", "TK1", 0, wrong_serial, CHALLENGE_1, true),
        expect_none(TIMEOUT),
    ])
}

/// 3.3.18: Incorrect MAC → reject.
fn test_3_3_18() -> TestCase {
    TestCase::new("3.3.18 S-A_Sync_Req-PDU - A+C – P2P - with tool key - incorrectly encrypted MAC").with_steps(vec![
        wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
        comment("Send sync req with invalid MAC → reject"),
        inject_sync_req_invalid(
            SyncReqParams {
                key_name: "TK1".into(),
                tool_access: true,
                system_broadcast: false,
                src_template: "#EDI".into(),
                dst_template: "#BDUT_ADDR".into(),
                npdu_byte: 0x60,
                ctrl_byte: 0x3C,
                seq_local: SeqSource::Fixed(0),
                serial_number: [0; 6],
                challenge: CHALLENGE_1,
                tpci_high: 0x00,
            },
            InvalidSecurityParam::InvalidMac([0x12, 0x34, 0x56, 0x78]),
        ),
        expect_none(TIMEOUT),
    ])
}

/// 3.3.19: Sync req sent as group (wrong address type) → reject.
fn test_3_3_19() -> TestCase {
    TestCase::new("3.3.19 S-A_Sync_Req-PDU - A+C – P2P - with tool key – sent as group").with_steps(vec![
        wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
        comment("Send sync req computed with group address type → reject"),
        inject_sync_req_invalid(
            SyncReqParams {
                key_name: "TK1".into(),
                tool_access: true,
                system_broadcast: false,
                src_template: "#EDI".into(),
                dst_template: "#BDUT_ADDR".into(),
                npdu_byte: 0x60,
                ctrl_byte: 0x3C,
                seq_local: SeqSource::Fixed(0),
                serial_number: [0; 6],
                challenge: CHALLENGE_1,
                tpci_high: 0x00,
            },
            InvalidSecurityParam::WrongAddressType,
        ),
        expect_none(TIMEOUT),
    ])
}

/// 3.3.20: One byte too many → reject.
fn test_3_3_20() -> TestCase {
    TestCase::new("3.3.20 S-A_Sync_Req-PDU - A+C – P2P - with tool key – one byte too many").with_steps(vec![
        wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
        comment("Send sync req with one extra byte appended → reject"),
        inject_sync_req_invalid(
            SyncReqParams {
                key_name: "TK1".into(),
                tool_access: true,
                system_broadcast: false,
                src_template: "#EDI".into(),
                dst_template: "#BDUT_ADDR".into(),
                npdu_byte: 0x60,
                ctrl_byte: 0x3C,
                seq_local: SeqSource::Fixed(0),
                serial_number: [0; 6],
                challenge: CHALLENGE_1,
                tpci_high: 0x00,
            },
            InvalidSecurityParam::AppendBytes(vec![0xFF]),
        ),
        expect_none(TIMEOUT),
    ])
}

/// 3.3.21: One byte too few → reject.
fn test_3_3_21() -> TestCase {
    TestCase::new("3.3.21 S-A_Sync_Req-PDU - A+C – P2P - with tool key – one byte too few").with_steps(vec![
        wait(1500), // Sync rate limit: DUT ignores requests within 1s of last response.
        comment("Send sync req with one byte truncated → reject"),
        inject_sync_req_invalid(
            SyncReqParams {
                key_name: "TK1".into(),
                tool_access: true,
                system_broadcast: false,
                src_template: "#EDI".into(),
                dst_template: "#BDUT_ADDR".into(),
                npdu_byte: 0x60,
                ctrl_byte: 0x3C,
                seq_local: SeqSource::Fixed(0),
                serial_number: [0; 6],
                challenge: CHALLENGE_1,
                tpci_high: 0x00,
            },
            InvalidSecurityParam::TruncateBytes(1),
        ),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.3.0 — placeholder (preparation is performed via suite `.with_preparation`)
// ============================================================================

fn test_3_3_0() -> TestCase {
    TestCase::new("3.3.0 Test preparation")
        .with_steps(vec![comment("Placeholder: preparation is executed as suite-level with_preparation.")])
}

// ============================================================================
// 3.3.7 — placeholder (covered by Vol 8/3/7 "wrong APCIs")
// ============================================================================

fn test_3_3_7() -> TestCase {
    TestCase::new("3.3.7 incorrect S-A_Sync_Req-PDU - incorrect APCI – P2P")
        .with_steps(vec![comment("Placeholder: covered by Application Layer Tests 8/3/7 'wrong APCIs'.")])
}

// ============================================================================
// 3.3.12 — placeholder (EITT cannot inject wrong challenge; see 3.3.18)
// ============================================================================

fn test_3_3_12() -> TestCase {
    TestCase::new("3.3.12 S-A_Sync_Req-PDU, A+C with wrong encrypted data – (system) broadcast").with_steps(vec![
        comment("Placeholder: see 3.3.18; challenge is MAC input and EITT cannot inject wrong challenge."),
    ])
}
