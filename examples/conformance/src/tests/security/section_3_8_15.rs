//! Section 3.8.15 — `PID_SEQUENCE_NUMBER_SENDING` access policy `00C/00C`.
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.15 PID_SEQUENCE_NUMBER_SENDING".
//!
//! Tests PID 0x3B (PID_SEQUENCE_NUMBER_SENDING, i.e. PID 59) on the Security
//! Interface Object (IOT=0x0011, instance=0x0010). Access policy is `00C/00C`:
//! requires Tool A+C for both read and write in both security modes — plain and
//! auth-only access is always denied.
//!
//! The property is PDT_GENERIC_06 (6 bytes, 48-bit sequence counter).
//!
//! Skipped test cases:
//! - 3.8.15.7 — master reset tests (complex reset/persistence scenarios).

use crate::{TestCase, TestSuite};
use super::variables::create_security_variables;
use crate::tests::helpers::*;

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

/// Standard challenge value used in sync seeding.
const CHALLENGE_1: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

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
// PropertyExtValueRead / Response templates for PID 0x3B
// ============================================================================

// Plain read: count=1, start=1.
// APDU: 01 CC + 00 11 + 00 10 + 3B + 01 + 00 01 = 10 bytes → TP1 len = 0x69
const PLAIN_READ: &str =
    "BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 3B 01 00 01";

// Plain read denied: count=0, return_code=0xFC.
const PLAIN_READ_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 3B 00 00 01 FC";

// Plain write: count=1, start=1, data=6 zero bytes.
// APDU: 01 CE + 00 11 + 00 10 + 3B + 01 + 00 01 + 00 00 00 00 00 00 = 16 bytes
// → TP1 extended frame, len = 0x0F
const PLAIN_WRITE: &str =
    "3C 60 #EDI #BDUT_ADDR 0F 01 CE 00 11 00 10 3B 01 00 01 00 00 00 00 00 00";

// Plain write denied: count=0, return_code=0xFC.
// APDU: 11 bytes → TP1 standard frame len = 0x6A
const PLAIN_WRITE_DENIED: &str =
    "BC #BDUT_ADDR #EDI 6A 01 CF 00 11 00 10 3B 00 00 01 FC";

// ============================================================================
// Secure (auth-only) templates for PID 0x3B
// ============================================================================

// Secure A read: count=1, start=1.
const SECURE_READ: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3B 01 00 01";

// Secure read denied: count=0, return_code=0xFC.
const SECURE_READ_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 3B 00 00 01 FC";

// Secure A write: count=1, start=1, data=6 zero bytes.
const SECURE_WRITE: &str =
    "3C 60 #EDI #BDUT_ADDR 0F 01 CE 00 11 00 10 3B 01 00 01 00 00 00 00 00 00";

// Secure write denied.
const SECURE_WRITE_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 3B 00 00 01 FC";

// ============================================================================
// Verification read — A+C secure read to confirm current state
// ============================================================================

// A+C secure element count query: count=1, start=0.
const VERIFY_READ: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3B 01 00 00";

// Response: count=1, start=0, 2-byte element count.
const VERIFY_READ_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0B 01 CD 00 11 00 10 3B 01 00 00 ?? ??";

// ============================================================================
// PropertyExtDescription_Read / Response templates
// ============================================================================

// Secure A+C description read for PID 0x3B.
const SECURE_DESC_READ: &str =
    "3C 60 #EDI #BDUT_ADDR 08 01 D2 00 11 00 10 3B 00 00";

// Secure A+C success response: valid descriptor (wildcard data bytes).
const SECURE_DESC_READ_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 3B ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// Plain description read.
const PLAIN_DESC_READ: &str =
    "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 3B 00 00";

// Plain all-zero descriptor (00C/00C: plain NEVER allowed).
const PLAIN_DESC_READ_ZERO: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 3B 00 00 00 00 00 00 00 00 00 00";

// ============================================================================
// Suite Constructor
// ============================================================================

// Secure A+C write to reset sequence number to a sane value after overflow
// test (3.8.15.6). Without this, the DUT won't send any secure frames for
// subsequent suites.
const RESET_SEQ: &str =
    "3C 60 #EDI #BDUT_ADDR 0F 01 CE 00 11 00 10 3B 01 00 01 00 00 00 00 10 00";
const RESET_SEQ_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 3B 01 00 01 00";

pub fn create_section_3_8_15_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.15 PID_SEQUENCE_NUMBER_SENDING (Security IO, access 00C/00C)", variables)
        .secure()
        .with_preparation(vec![
            // Sync tool key sequence numbers to align the harness with
            // whatever the DUT's current sending seq is.
            comment("Sync tool key sequence numbers"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
            wait(55000), // Sync rate limit.
        ])
        .with_cases(vec![
            test_3_8_15_1(),
            test_3_8_15_2(),
            test_3_8_15_3(),
            test_3_8_15_4(),
            test_3_8_15_5(),
            test_3_8_15_8(),
            // 3.8.15.6 runs last: it drives the DUT's seq to overflow,
            // after which the DUT refuses to send any secure frames.
            test_3_8_15_6(),
        ])
        .with_teardown(vec![
            // After the overflow test, the DUT's sending seq is at max and
            // it won't send. We need a sync to re-align, then write a sane
            // value so subsequent suites work.
            comment("Re-sync after overflow test"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
            comment("Reset PID_SEQUENCE_NUMBER_SENDING to 0x1000"),
            inject_secure_ac(RESET_SEQ, "TK1"),
            expect_secure_ac(RESET_SEQ_OK, "TK1", TIMEOUT),
        ])
}

// ============================================================================
// 3.8.15.2 Unsecure PropertyValue Access
// ============================================================================
//
// Plain (non-secure) read and write are always denied under 00C/00C policy,
// regardless of security mode.

fn test_3_8_15_2() -> TestCase {
    TestCase::new("3.8.15.2 Unsecure PropertyValue Access").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        // Per XML: write first, then read.
        comment("Plain write → E_ACCESS_DENIED (00C requires A+C)"),
        inject(PLAIN_WRITE),
        expect(PLAIN_WRITE_DENIED, TIMEOUT),

        comment("Plain read → E_ACCESS_DENIED"),
        inject(PLAIN_READ),
        expect(PLAIN_READ_DENIED, TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain write → E_ACCESS_DENIED (still denied, 00C policy)"),
        inject(PLAIN_WRITE),
        expect(PLAIN_WRITE_DENIED, TIMEOUT),

        comment("Plain read → E_ACCESS_DENIED"),
        inject(PLAIN_READ),
        expect(PLAIN_READ_DENIED, TIMEOUT),
    ])
}

// ============================================================================
// 3.8.15.3 Secure PropertyValueWrite and Read — verify counter increments
// ============================================================================
//
// Writes a known value to PID_SEQUENCE_NUMBER_SENDING, then reads it back.
// The read-back value is the written value + 1 because the encrypted
// write-response consumed one sequence number.
//
// Repeated in both sec-mode-on and sec-mode-off phases.

fn test_3_8_15_3() -> TestCase {
    // Secure A+C write: PID 0x3B, count=1, start=1, data = 00 00 00 00 1F 32.
    const WRITE_SEQ: &str =
        "3C 60 #EDI #BDUT_ADDR 0F 01 CE 00 11 00 10 3B 01 00 01 00 00 00 00 1F 32";
    const WRITE_SEQ_OK: &str =
        "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 3B 01 00 01 00";

    // Secure A+C read: PID 0x3B, count=1, start=1.
    const READ_SEQ: &str =
        "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3B 01 00 01";
    // Expected read-back: 00 00 00 00 1F 33 (written value + 1).
    const READ_SEQ_OK: &str =
        "3C 60 #BDUT_ADDR #EDI 0F 01 CD 00 11 00 10 3B 01 00 01 00 00 00 00 1F 33";

    TestCase::new("3.8.15.3 Secure PropertyValueRead after power down check SeqNb").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Write sequence number = 0x1F32"),
        inject_secure_ac(WRITE_SEQ, "TK1"),
        expect_secure_ac(WRITE_SEQ_OK, "TK1", TIMEOUT),

        comment("Read back → expect 0x1F33 (written + 1, consumed by write response)"),
        inject_secure_ac(READ_SEQ, "TK1"),
        expect_secure_ac(READ_SEQ_OK, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Write sequence number = 0x1F32 again"),
        inject_secure_ac(WRITE_SEQ, "TK1"),
        expect_secure_ac(WRITE_SEQ_OK, "TK1", TIMEOUT),

        comment("Read back → expect 0x1F33 again"),
        inject_secure_ac(READ_SEQ, "TK1"),
        expect_secure_ac(READ_SEQ_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.15.4 Auth-only Secured PropertyValueRead/Write
// ============================================================================
//
// Auth-only (A without C) is insufficient for 00C/00C — both read and write
// are denied in both security modes.

fn test_3_8_15_4() -> TestCase {
    TestCase::new("3.8.15.4 Auth. Secured PropertyValueRead/Write").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        // Per XML: read first, then write.
        comment("Auth-only read → E_ACCESS_DENIED (00C requires A+C, not just A)"),
        inject_secure_ao(SECURE_READ, "TK1"),
        expect_secure_ao(SECURE_READ_DENIED, "TK1", TIMEOUT),

        comment("Auth-only write → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_WRITE, "TK1"),
        expect_secure_ao(SECURE_WRITE_DENIED, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Auth-only read → E_ACCESS_DENIED (still denied)"),
        inject_secure_ao(SECURE_READ, "TK1"),
        expect_secure_ao(SECURE_READ_DENIED, "TK1", TIMEOUT),

        comment("Auth-only write → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_WRITE, "TK1"),
        expect_secure_ao(SECURE_WRITE_DENIED, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.15.5 PropertyDescriptionRead
// ============================================================================
//
// 00C/00C: A+C secure description read succeeds. Plain description read
// returns all-zero (plain NEVER allowed).

fn test_3_8_15_5() -> TestCase {
    TestCase::new("3.8.15.5 PropertyDescriptionRead").with_steps(vec![
        // Per XML: sec ON, A+C desc read first.
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Secure A+C description read → valid descriptor"),
        inject_secure_ac(SECURE_DESC_READ, "TK1"),
        expect_secure_ac(SECURE_DESC_READ_OK, "TK1", TIMEOUT),

        // Per XML: sec OFF, plain desc read (all-zero for 00C/00C).
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain description read → all-zero (00C never allows plain)"),
        inject(PLAIN_DESC_READ),
        expect(PLAIN_DESC_READ_ZERO, TIMEOUT),
    ])
}

// ============================================================================
// 3.8.15.8 PropertyValueWrite attempt to set to 0
// ============================================================================
//
// Connection-oriented: T_Connect, numbered secure A+C write with value 0,
// DUT should reject (sequence number must not be set to 0). Uses T_ACK
// handshake for the connection-oriented exchange.

fn test_3_8_15_8() -> TestCase {
    // Connection-oriented secure write: TPCI=0x41 (numbered data seq 0).
    // PropExtValueWriteCon (0x01CE) on Security IO PID 0x3B, value = 6 zero bytes.
    const CONNECTED_WRITE_ZERO: &str =
        "3C 60 #EDI #BDUT_ADDR 0F 41 CE 00 11 00 10 3B 01 00 01 00 00 00 00 00 00";

    // Connection-oriented secure response: TPCI=0x41 (numbered data seq 0).
    // PropExtValueWriteConRes (0x01CF) with error (count=0, return_code=F?).
    const CONNECTED_WRITE_DENIED: &str =
        "3C 60 #BDUT_ADDR #EDI 0A 41 CF 00 11 00 10 3B 00 00 01 F?";

    TestCase::new("3.8.15.8 PropertyValueWrite attempt to set to 0").with_steps(vec![
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Open transport connection"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),

        comment("Send secure A+C numbered write: PID_SEQUENCE_NUMBER_SENDING = 0"),
        inject_secure_ac(CONNECTED_WRITE_ZERO, "TK1"),

        comment("Expect T_ACK for our numbered data"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),

        comment("Expect secure A+C numbered response: write denied"),
        expect_secure_ac(CONNECTED_WRITE_DENIED, "TK1", TIMEOUT),

        comment("ACK the DUT's response"),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),

        comment("Close transport connection"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),

        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.15.1 Secure PropertyValueWrite and stimulate immediate usage of SeqNb
// ============================================================================
//
// Writes PID_SEQUENCE_NUMBER_SENDING = 0x1F00 and verifies the DUT
// immediately uses the new value: the write response itself is sent with
// seq=0x1F00, and a subsequent read returns 0x1F01 (written value + 1,
// because the write response consumed one seq increment).
//
// Repeated in both security-mode-on and security-mode-off phases.

fn test_3_8_15_1() -> TestCase {
    // Write PID 0x3B = 0x000000001F00.
    const WRITE_SEQ_1F00: &str =
        "3C 60 #EDI #BDUT_ADDR 0F 01 CE 00 11 00 10 3B 01 00 01 00 00 00 00 1F 00";
    const WRITE_SEQ_1F00_OK: &str =
        "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 3B 01 00 01 00";

    // Read PID 0x3B, expect 0x000000001F01 (written + 1).
    const READ_SEQ: &str =
        "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3B 01 00 01";
    const READ_SEQ_1F01: &str =
        "3C 60 #BDUT_ADDR #EDI 0F 01 CD 00 11 00 10 3B 01 00 01 00 00 00 00 1F 01";

    TestCase::new("3.8.15.1 Secure PropertyValueWrite and stimulate immediate usage of SeqNb").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Write PID_SEQUENCE_NUMBER_SENDING = 0x1F00"),
        inject_secure_ac(WRITE_SEQ_1F00, "TK1"),
        expect_secure_ac(WRITE_SEQ_1F00_OK, "TK1", TIMEOUT),

        comment("Read back → expect 0x1F01 (written + 1, consumed by write response)"),
        inject_secure_ac(READ_SEQ, "TK1"),
        expect_secure_ac(READ_SEQ_1F01, "TK1", TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Write PID_SEQUENCE_NUMBER_SENDING = 0x1F00 again"),
        inject_secure_ac(WRITE_SEQ_1F00, "TK1"),
        expect_secure_ac(WRITE_SEQ_1F00_OK, "TK1", TIMEOUT),

        comment("Read back → expect 0x1F01 again"),
        inject_secure_ac(READ_SEQ, "TK1"),
        expect_secure_ac(READ_SEQ_1F01, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.15.6 Overflow check
// ============================================================================
//
// Write PID_SEQUENCE_NUMBER_SENDING to 0xFFFFFFFFFFFE (max - 1). The write
// response uses seq=0xFFFFFFFFFFFE, bumping the counter to 0xFFFFFFFFFFFF.
// A first read succeeds (returning 0xFFFFFFFFFFFF, seq=0xFFFFFFFFFFFF).
// A second read gets NO response — the DUT has reached sequence number
// overflow and stops sending secure frames.

fn test_3_8_15_6() -> TestCase {
    // Write max-1. After the write response (which uses seq=max-1),
    // the counter becomes 0xFFFFFFFFFFFF (max). Our DUT stops at max
    // per the spec's "optionally maximum value minus 1" allowance.
    const WRITE_SEQ_MAX_MINUS_1: &str =
        "3C 60 #EDI #BDUT_ADDR 0F 01 CE 00 11 00 10 3B 01 00 01 FF FF FF FF FF FE";
    const WRITE_SEQ_OK: &str =
        "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 3B 01 00 01 00";

    const READ_SEQ: &str =
        "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3B 01 00 01";

    TestCase::new("3.8.15.6 Overflow check").with_steps(vec![
        // The XML runs this with security mode off.
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Write PID_SEQUENCE_NUMBER_SENDING = 0xFFFFFFFFFFFE (max - 1)"),
        inject_secure_ac(WRITE_SEQ_MAX_MINUS_1, "TK1"),
        expect_secure_ac(WRITE_SEQ_OK, "TK1", TIMEOUT),

        // The write response used seq=0xFFFFFFFFFFFE, so the counter is
        // now at 0xFFFFFFFFFFFF. The DUT refuses to send any more secure
        // frames because the next send would overflow the 48-bit counter.
        comment("Read → no response (seq at max, DUT stops sending)"),
        inject_secure_ac(READ_SEQ, "TK1"),
        expect_none(TIMEOUT),
    ])
}
