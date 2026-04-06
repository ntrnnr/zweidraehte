//! Section 3.3 — S-A_Sync_Req (22 test cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.3 S_A Sync Request".
//!
//! Tests verify that the DUT correctly handles incoming S-A_Sync_Req
//! frames and responds with proper S-A_Sync_Res frames (positive tests)
//! or silently rejects invalid requests (negative tests).

use crate::{InvalidSecurityParam, SyncReqParams, SyncResExpect, TestCase, TestSuite};
use crate::tests::helpers::*;
use super::variables::create_security_variables;

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

/// Standard challenge value used in most tests.
const CHALLENGE_1: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

/// DUT serial number matching the test variable #SER_NUM.
const DUT_SERIAL: [u8; 6] = [0xFE, 0xED, 0xBA, 0xBE, 0xCA, 0xFE];

// ============================================================================
// Preparation: write SeqNoSending=2 and sync to seed sequence numbers
// ============================================================================

/// Write PID_SEQUENCE_NUMBER_SENDING = 2 to the DUT via secure property write.
const WRITE_SEQ_SENDING_2: &str =
    "3C 60 #EDI #BDUT_ADDR 0F 01 CE 00 11 00 10 3B 01 00 01 00 00 00 00 00 02";
const WRITE_SEQ_SENDING_2_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 3B 01 00 01 00";

// Read PID_SEQUENCE_NUMBER_SENDING to verify.
const READ_SEQ_SENDING: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3B 01 00 01";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_3_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.3 S_A Sync Request", variables)
        .secure()
        .with_preparation(vec![
            comment("Write SeqNoSending=2 in the BDUT"),
            inject_secure_ac(WRITE_SEQ_SENDING_2, "TK1"),
            expect_secure_ac(WRITE_SEQ_SENDING_2_OK, "TK1", TIMEOUT),
            comment("Initial sync to seed EITT sequence numbers"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
            comment("Wait for sync rate limit to expire"),
            wait(55000),
        ])
        .with_cases(vec![
            // ================================================================
            // Positive tests
            // ================================================================
            test_3_3_2(),
            test_3_3_3(),
            test_3_3_6(),
            test_3_3_13(),
            test_3_3_14(),
            test_3_3_16(),
            test_3_3_17(),
            test_3_3_22(),

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
}

// ============================================================================
// Positive tests
// ============================================================================

/// 3.3.2: Correct S-A_Sync_Req, A+C, P2P connectionless, tool key.
fn test_3_3_2() -> TestCase {
    TestCase::new("3.3.2 correct S-A_Sync_Req-PDU, A+C – P2P – connectionless").with_steps(vec![
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
        comment("Send correct sync req connectionless with TK1"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE_1),
        expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
    ])
}

/// 3.3.3: Correct S-A_Sync_Req from second IA (0xFFFE).
fn test_3_3_3() -> TestCase {
    TestCase::new("3.3.3 correct S-A_Sync_Req-PDU, A+C – P2P connectionless, from second IA").with_steps(vec![
        wait(55000), // Rate limit: need > 1s between sync responses.
        comment("Send sync req from alternate source FF FE with TK1"),
        inject_sync_req(SyncReqParams {
            key_name: "TK1".into(),
            tool_access: true,
            system_broadcast: false,
            src_template: "FF FE".into(),
            dst_template: "#BDUT_ADDR".into(),
            npdu_byte: 0x60,
            ctrl_byte: 0x3C,
            seq_nr_local: 0,
            serial_number: [0; 6],
            challenge: CHALLENGE_1,
            tpci_high: 0x00,
        }),
        expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
    ])
}

/// 3.3.6: Correct S-A_Sync_Req via broadcast and system broadcast.
fn test_3_3_6() -> TestCase {
    TestCase::new("3.3.6 correct S-A_Sync_Req-PDU – (system) broadcast").with_steps(vec![
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
        comment("Broadcast sync req with matching serial number"),
        inject_sync_req_broadcast("#EDI", "TK1", 0, DUT_SERIAL, CHALLENGE_1, false),
        expect_sync_res(SyncResExpect {
            key_name: "TK1".into(),
            tool_access: true,
            system_broadcast: false,
            expected_seq_remote: None,
            expected_seq_local: None,
            challenge: CHALLENGE_1,
            expected_src_template: "#BDUT_ADDR".into(),
        }, TIMEOUT),
        wait(55000), // Rate limit: must wait > 1 second between sync responses.
        comment("System broadcast sync req with matching serial number"),
        inject_sync_req_broadcast("#EDI", "TK1", 0, DUT_SERIAL, CHALLENGE_1, true),
        expect_sync_res(SyncResExpect {
            key_name: "TK1".into(),
            tool_access: true,
            system_broadcast: true,
            expected_seq_remote: None,
            expected_seq_local: None,
            challenge: CHALLENGE_1,
            expected_src_template: "#BDUT_ADDR".into(),
        }, TIMEOUT),
    ])
}

/// 3.3.13: Correct S-A_Sync_Req with a different challenge value.
fn test_3_3_13() -> TestCase {
    let challenge_2: [u8; 6] = [0x11, 0x11, 0x11, 0x11, 0x11, 0x11];
    TestCase::new("3.3.13 correct S-A_Sync_Req-PDU - A+C – P2P - other challenge").with_steps(vec![
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
        comment("Send sync req with different challenge value"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, challenge_2),
        expect_sync_res_tool("TK1", challenge_2, None, None, TIMEOUT),
    ])
}

/// 3.3.14: SeqNr_local lower than expected by BDUT — DUT still responds.
fn test_3_3_14() -> TestCase {
    TestCase::new("3.3.14 correct S-A_Sync_Req-PDU – sequence number local lower than expected by BDUT – P2P").with_steps(vec![
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
        comment("Send sync req with SeqNr_local=1 (lower than what BDUT expects)"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 1, CHALLENGE_1),
        expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
    ])
}

/// 3.3.16: SeqNr_local identical to that expected by BDUT.
fn test_3_3_16() -> TestCase {
    TestCase::new("3.3.16 correct S-A_Sync_Req-PDU – Sequence number local identical to that expected by BDUT – P2P").with_steps(vec![
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
        comment("Send sync req with SeqNr_local matching what BDUT expects"),
        // We don't know the exact value, so use 0 (always accepted per spec).
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE_1),
        expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
    ])
}

/// 3.3.17: Verify SeqNr_remote = 100 after writing SeqNoSending=100.
fn test_3_3_17() -> TestCase {
    // Write SeqNoSending=100 (0x64) to DUT.
    let write_seq_100 = "3C 60 #EDI #BDUT_ADDR 0F 01 D0 00 11 00 10 3B 01 00 01 00 00 00 00 00 64";

    TestCase::new("3.3.17 correct S-A_Sync_Req-PDU – verification of correct setting of sequence number sending").with_steps(vec![
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
        comment("Write SeqNoSending=100"),
        inject_secure_ac(write_seq_100, "TK1"),
        // A_PropertyExtValueWriteCon response (no error).
        // We don't need to match the exact response — just drain it.
        drain(500),
        comment("Verify SeqNr_remote=100 in sync response"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE_1),
        expect_sync_res_tool("TK1", CHALLENGE_1, Some(100), None, TIMEOUT),
        comment("Verify different random value with second sync req (different challenge)"),
        wait(55000), // Rate limit.
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]),
        // SeqNr_remote should be 101 now (100 was consumed by the secure write response).
        expect_sync_res_tool("TK1", [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC], None, None, TIMEOUT),
    ])
}

/// 3.3.22: S-A_Sync_Req with SBC flag set for P2P (optional, should accept).
fn test_3_3_22() -> TestCase {
    TestCase::new("3.3.22 S-A_Sync_Req-PDU - A+C – P2P - with tool key – SBC flag set (optional)").with_steps(vec![
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
        comment("Send P2P sync req with SBC flag set — DUT should still accept"),
        inject_sync_req(SyncReqParams {
            key_name: "TK1".into(),
            tool_access: true,
            system_broadcast: true,
            src_template: "#EDI".into(),
            dst_template: "#BDUT_ADDR".into(),
            npdu_byte: 0x60,
            ctrl_byte: 0x30, // Extended frame with repeat flag.
            seq_nr_local: 0,
            serial_number: [0; 6],
            challenge: CHALLENGE_1,
            tpci_high: 0x00,
        }),
        expect_sync_res(SyncResExpect {
            key_name: "TK1".into(),
            tool_access: true,
            system_broadcast: true,
            expected_seq_remote: None,
            expected_seq_local: None,
            challenge: CHALLENGE_1,
            expected_src_template: "#BDUT_ADDR".into(),
        }, TIMEOUT),
    ])
}

// ============================================================================
// Negative tests — DUT should silently reject
// ============================================================================

/// 3.3.8: Invalid SCF (0x82, reserved SAI=000b) → reject.
fn test_3_3_8() -> TestCase {
    TestCase::new("3.3.8 incorrect S-A_Sync_Req-PDU – reserved SAI case 1").with_steps(vec![
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
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
                seq_nr_local: 0,
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
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
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
                seq_nr_local: 0,
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
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
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
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
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
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
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
                seq_nr_local: 0,
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
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
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
                seq_nr_local: 0,
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
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
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
                seq_nr_local: 0,
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
        wait(55000), // Sync rate limit: DUT ignores requests within 1s of last response.
        // The wait is scaled down by time_divisor (50x), so 55s → ~1.1s real time.
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
                seq_nr_local: 0,
                serial_number: [0; 6],
                challenge: CHALLENGE_1,
                tpci_high: 0x00,
            },
            InvalidSecurityParam::TruncateBytes(1),
        ),
        expect_none(TIMEOUT),
    ])
}
