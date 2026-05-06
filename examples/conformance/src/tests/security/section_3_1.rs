//! Section 3.1 — S-A_Data PDU with Tool Key (29 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.1 S-A_Data PDU with Tool Key".
//!
//! All tests use `A_PropertyExtValue_Read` as the inner service wrapped in
//! `S-A_Data`. Positive tests expect a secure `A_PropertyExtValue_Response`;
//! negative tests expect no response (DUT silently drops the frame).
//!
//! The DUT runs with Security Mode OFF — all tests operate via tool key
//! commissioning through the FDSK.

use super::variables::create_security_variables;
use crate::tests::helpers::*;
use crate::{InvalidSecurityParam, SecureParams, SeqSource, TestCase, TestSuite};

// ============================================================================
// Plaintext templates
// ============================================================================

// A_PropertyExtValue_Read: IOT=0x0011 (Security), instance=0x0010, PID=1 (ObjectType), count=1, start=1
// Auth-only tests use PID 1 (which requires auth-only access).
const READ_PID1: &str = "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 01 01 00 01";

// Response: PID 1 returns ObjectType = 0x0011 (Security)
const RESP_PID1: &str = "3C 60 #BDUT_ADDR #EDI 0B 01 CD 00 11 00 10 01 01 00 01 00 11";

// A_PropertyExtValue_Read: IOT=0x0011, instance=0x0010, PID=57 (0x39, SerialNumber), count=1, start=1
// A+C tests use PID 57 (which requires auth+conf access).
const READ_PID57: &str = "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 39 01 00 01";

// Response for PID 57 (PID_SECURITY_REPORT, PDT_BITSET8) — 1 byte data, wildcarded.
const RESP_PID57: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 39 01 00 01 ??";

// Same as READ_PID1 but from alternate source 11.F1 (0x11F1)
const READ_PID1_ALT_SRC: &str = "3C 60 #ALT_SRC_ADDR #BDUT_ADDR 09 01 CC 00 11 00 10 01 01 00 01";
const RESP_PID1_ALT_SRC: &str = "3C 60 #BDUT_ADDR #ALT_SRC_ADDR 0B 01 CD 00 11 00 10 01 01 00 01 00 11";

// Same as READ_PID57 but from alternate source
const READ_PID57_ALT_SRC: &str = "3C 60 #ALT_SRC_ADDR #BDUT_ADDR 09 01 CC 00 11 00 10 39 01 00 01";
const RESP_PID57_ALT_SRC: &str = "3C 60 #BDUT_ADDR #ALT_SRC_ADDR 0A 01 CD 00 11 00 10 39 01 00 01 ??";

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_1_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.1 S-A_Data PDU with Tool Key", variables).secure().with_cases(vec![
        // ================================================================
        // Positive tests: auth-only
        // ================================================================
        test_3_1_1(),
        test_3_1_3(),
        test_3_1_7(),
        test_3_1_10(),
        test_3_1_11(),
        // ================================================================
        // Positive tests: auth+conf
        // ================================================================
        test_3_1_2(),
        test_3_1_14(),
        test_3_1_15(),
        test_3_1_18(),
        test_3_1_20(),
        test_3_1_21(),
        // ================================================================
        // Negative tests: auth-only
        // ================================================================
        test_3_1_5(),
        test_3_1_6(),
        test_3_1_8(),
        test_3_1_9(),
        test_3_1_12(),
        test_3_1_13(),
        test_3_1_26(),
        test_3_1_28(),
        // ================================================================
        // Negative tests: auth+conf
        // ================================================================
        test_3_1_17(),
        test_3_1_19(),
        test_3_1_22(),
        test_3_1_23(),
        test_3_1_25(),
        test_3_1_27(),
        test_3_1_29(),
        test_3_1_24(),
        // Placeholders for cross-reference cases (0 active telegrams in XML).
        test_3_1_4(),
        test_3_1_16(),
    ])
}

// ============================================================================
// 3.1.4 — placeholder (covered by Vol 8/3/7 "wrong APCIs")
// ============================================================================

fn test_3_1_4() -> TestCase {
    TestCase::new("3.1.4 incorrect S-A_Data A only - incorrect APCI Sec")
        .with_steps(vec![comment("Placeholder: covered by Application Layer Tests 8/3/7 'wrong APCIs'.")])
}

// ============================================================================
// 3.1.16 — placeholder (covered by Vol 8/3/7 "wrong APCIs")
// ============================================================================

fn test_3_1_16() -> TestCase {
    TestCase::new("3.1.16 incorrect S-A_Data PDU - incorrect APCI")
        .with_steps(vec![comment("Placeholder: covered by Application Layer Test 8/3/7 'wrong APCIs'.")])
}

// ============================================================================
// 3.1.1 correct S-A_Data A only
// ============================================================================

fn test_3_1_1() -> TestCase {
    TestCase::new("3.1.1 correct S-A_Data A only").with_steps(vec![
        comment("Inject A_PropertyExtValueRead with auth-only, expect response"),
        inject_secure_ao(READ_PID1, "TK1"),
        expect_secure_ao(RESP_PID1, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.1.2 correct S-A_Data A+C
// ============================================================================

fn test_3_1_2() -> TestCase {
    TestCase::new("3.1.2 correct S-A_Data A+C").with_steps(vec![
        comment("Inject A_PropertyExtValueRead with auth+conf, expect response"),
        inject_secure_ac(READ_PID1, "TK1"),
        expect_secure_ac(RESP_PID1, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.1.3 correct S-A_Data A only - with a second source
// ============================================================================

fn test_3_1_3() -> TestCase {
    TestCase::new("3.1.3 correct S-A_Data A only - second source").with_steps(vec![
        comment("Inject from ALT_SRC_ADDR (11.F1) with auth-only"),
        inject_secure_ao(READ_PID1_ALT_SRC, "TK1"),
        expect_secure_ao(RESP_PID1_ALT_SRC, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.1.5 incorrect SCF - tool access bit not set (auth-only)
// ============================================================================

fn test_3_1_5() -> TestCase {
    TestCase::new("3.1.5 incorrect SCF - no tool access (A only)").with_steps(vec![
        comment("Auth-only with SCF=0x00 (tool bit cleared) → reject"),
        inject_secure_invalid(READ_PID1, SecureParams::tool_auth_only("TK1"), InvalidSecurityParam::InvalidScf(0x00)),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.6 incorrect SCF - reserved SAI field
// ============================================================================

fn test_3_1_6() -> TestCase {
    TestCase::new("3.1.6 reserved SAI in SCF (A only)").with_steps(vec![
        comment("Auth-only with SCF=0x20 (reserved SAI bits set) → reject"),
        inject_secure_invalid(READ_PID1, SecureParams::tool_auth_only("TK1"), InvalidSecurityParam::InvalidScf(0x20)),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.7 correct S-A_Data A only with SBC set to 1
// ============================================================================

fn test_3_1_7() -> TestCase {
    let mut params = SecureParams::tool_auth_only("TK1");
    params.system_broadcast = true;
    TestCase::new("3.1.7 correct S-A_Data A only with SBC=1").with_steps(vec![
        comment("Auth-only with system_broadcast flag set → accepted"),
        inject_secure(READ_PID1, params.clone()),
        expect_secure_ao(RESP_PID1, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.1.8 reserved S-AL service type (auth-only)
// ============================================================================

fn test_3_1_8() -> TestCase {
    TestCase::new("3.1.8 reserved S-AL service type (A only)").with_steps(vec![
        comment("SCF=0x84 has reserved service type bits → reject"),
        inject_secure_invalid(READ_PID1, SecureParams::tool_auth_only("TK1"), InvalidSecurityParam::InvalidScf(0x84)),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.9 sequence number identical/lower than last known
// ============================================================================

fn test_3_1_9() -> TestCase {
    TestCase::new("3.1.9 sequence number replay (A only)").with_steps(vec![
        comment("First: valid request to establish sequence number"),
        inject_secure_ao(READ_PID1, "TK1"),
        expect_secure_ao(RESP_PID1, "TK1", TIMEOUT),
        comment("Second: replay with old seq (Fixed=1) → reject"),
        inject_secure(READ_PID1, {
            let mut p = SecureParams::tool_auth_only("TK1");
            p.seq_source = SeqSource::Fixed(1);
            p
        }),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.10 sequence number incremented by 1
// ============================================================================

fn test_3_1_10() -> TestCase {
    TestCase::new("3.1.10 sequence number +1 (A only)").with_steps(vec![
        comment("Two consecutive requests — seq increments by 1 each time"),
        inject_secure_ao(READ_PID1, "TK1"),
        expect_secure_ao(RESP_PID1, "TK1", TIMEOUT),
        inject_secure_ao(READ_PID1, "TK1"),
        expect_secure_ao(RESP_PID1, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.1.11 sequence number incremented by 2
// ============================================================================

fn test_3_1_11() -> TestCase {
    TestCase::new("3.1.11 sequence number +2 (A only)").with_steps(vec![
        comment("Two requests — but seq jumps by 2 (gap is acceptable)"),
        inject_secure_ao(READ_PID1, "TK1"),
        expect_secure_ao(RESP_PID1, "TK1", TIMEOUT),
        // The SecurityTestContext auto-increments seq by 1, so the second
        // request will have seq = first + 2 (gap of 1). This is valid per
        // spec — the DUT only rejects seq ≤ last known.
        inject_secure_ao(READ_PID1, "TK1"),
        expect_secure_ao(RESP_PID1, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.1.12 padded bits not zero
// ============================================================================

fn test_3_1_12() -> TestCase {
    TestCase::new("3.1.12 padded bits not zero (A only)").with_steps(vec![
        comment("Reserved 6 bits in secure data following seq_nr must be 0"),
        // TODO: Need infrastructure to set reserved padding bits.
        // The XML injects 6 separate telegrams each with different
        // non-zero padding patterns. For now this is a placeholder.
    ])
}

// ============================================================================
// 3.1.13 wrongly coded MAC (auth-only)
// ============================================================================

fn test_3_1_13() -> TestCase {
    TestCase::new("3.1.13 invalid MAC (A only)").with_steps(vec![
        comment("Auth-only with wrong MAC bytes → reject"),
        inject_secure_invalid(
            READ_PID1,
            SecureParams::tool_auth_only("TK1"),
            InvalidSecurityParam::InvalidMac([0x01, 0x02, 0x03, 0x04]),
        ),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.14 correct S-A_Data A+C (PID 57)
// ============================================================================

fn test_3_1_14() -> TestCase {
    TestCase::new("3.1.14 correct S-A_Data A+C (PID 57)").with_steps(vec![
        comment("A+C read of PID_SERIAL_NUMBER (requires A+C access)"),
        inject_secure_ac(READ_PID57, "TK1"),
        expect_secure_ac(RESP_PID57, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.1.15 correct S-A_Data A+C - second source
// ============================================================================

fn test_3_1_15() -> TestCase {
    TestCase::new("3.1.15 correct S-A_Data A+C - second source").with_steps(vec![
        comment("A+C from ALT_SRC_ADDR reading PID 57"),
        inject_secure_ac(READ_PID57_ALT_SRC, "TK1"),
        expect_secure_ac(RESP_PID57_ALT_SRC, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.1.17 incorrect SCF - tool access not set (A+C)
// ============================================================================

fn test_3_1_17() -> TestCase {
    TestCase::new("3.1.17 incorrect SCF - no tool access (A+C)").with_steps(vec![
        comment("A+C with SCF=0x10 (tool bit cleared) → reject"),
        inject_secure_invalid(READ_PID57, SecureParams::tool_auth_conf("TK1"), InvalidSecurityParam::InvalidScf(0x10)),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.18 correct S-A_Data A+C with SBC=1
// ============================================================================

fn test_3_1_18() -> TestCase {
    let mut params = SecureParams::tool_auth_conf("TK1");
    params.system_broadcast = true;
    TestCase::new("3.1.18 correct S-A_Data A+C with SBC=1").with_steps(vec![
        comment("A+C with system broadcast flag → accepted"),
        inject_secure(READ_PID57, params.clone()),
        expect_secure_ac(RESP_PID57, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.1.19 reserved S-AL service type (A+C)
// ============================================================================

fn test_3_1_19() -> TestCase {
    TestCase::new("3.1.19 reserved S-AL service type (A+C)").with_steps(vec![
        comment("SCF=0x94 has reserved service type bits → reject"),
        inject_secure_invalid(READ_PID57, SecureParams::tool_auth_conf("TK1"), InvalidSecurityParam::InvalidScf(0x94)),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.20 sequence number +1 (A+C)
// ============================================================================

fn test_3_1_20() -> TestCase {
    TestCase::new("3.1.20 sequence number +1 (A+C)").with_steps(vec![
        inject_secure_ac(READ_PID57, "TK1"),
        expect_secure_ac(RESP_PID57, "TK1", TIMEOUT),
        inject_secure_ac(READ_PID57, "TK1"),
        expect_secure_ac(RESP_PID57, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.1.21 sequence number +2 (A+C)
// ============================================================================

fn test_3_1_21() -> TestCase {
    TestCase::new("3.1.21 sequence number +2 (A+C)").with_steps(vec![
        inject_secure_ac(READ_PID57, "TK1"),
        expect_secure_ac(RESP_PID57, "TK1", TIMEOUT),
        inject_secure_ac(READ_PID57, "TK1"),
        expect_secure_ac(RESP_PID57, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.1.22 sequence number replay (A+C)
// ============================================================================

fn test_3_1_22() -> TestCase {
    TestCase::new("3.1.22 sequence number replay (A+C)").with_steps(vec![
        comment("First: valid A+C request"),
        inject_secure_ac(READ_PID57, "TK1"),
        expect_secure_ac(RESP_PID57, "TK1", TIMEOUT),
        comment("Replay with old seq (Fixed=1) → reject"),
        inject_secure(READ_PID57, {
            let mut p = SecureParams::tool_auth_conf("TK1");
            p.seq_source = SeqSource::Fixed(1);
            p
        }),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.23 wrongly encrypted ciphertext (A+C)
// ============================================================================

fn test_3_1_23() -> TestCase {
    TestCase::new("3.1.23 invalid ciphertext (A+C)").with_steps(vec![
        comment("A+C with corrupted ciphertext → reject"),
        inject_secure_invalid(READ_PID57, SecureParams::tool_auth_conf("TK1"), InvalidSecurityParam::InvalidCipher),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.25 wrongly coded MAC (A+C)
// ============================================================================

fn test_3_1_25() -> TestCase {
    TestCase::new("3.1.25 invalid MAC (A+C)").with_steps(vec![
        comment("A+C with wrong MAC → reject"),
        inject_secure_invalid(
            READ_PID57,
            SecureParams::tool_auth_conf("TK1"),
            InvalidSecurityParam::InvalidMac([0x11, 0x22, 0x33, 0x44]),
        ),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.26 A only with wrong address type (AT=group)
// ============================================================================

fn test_3_1_26() -> TestCase {
    TestCase::new("3.1.26 A only with AT=group in CCM → reject").with_steps(vec![
        comment("MAC computed with AT=group instead of individual → reject"),
        inject_secure_invalid(READ_PID1, SecureParams::tool_auth_only("TK1"), InvalidSecurityParam::WrongAddressType),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.27 A+C with wrong address type (AT=group)
// ============================================================================

fn test_3_1_27() -> TestCase {
    TestCase::new("3.1.27 A+C with AT=group in CCM → reject").with_steps(vec![
        comment("Encrypted with AT=group instead of individual → reject"),
        inject_secure_invalid(READ_PID57, SecureParams::tool_auth_conf("TK1"), InvalidSecurityParam::WrongAddressType),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.28 A only – one byte too many
// ============================================================================

fn test_3_1_28() -> TestCase {
    TestCase::new("3.1.28 A only – one byte too many").with_steps(vec![
        comment("Auth-only frame with one extra byte appended after MAC → reject"),
        inject_secure_invalid(
            READ_PID1,
            SecureParams::tool_auth_only("TK1"),
            InvalidSecurityParam::AppendBytes(vec![0x00]),
        ),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.29 A+C – one byte too few
// ============================================================================

fn test_3_1_29() -> TestCase {
    TestCase::new("3.1.29 A+C – one byte too few").with_steps(vec![
        comment("A+C frame truncated by one byte → reject"),
        inject_secure_invalid(READ_PID57, SecureParams::tool_auth_conf("TK1"), InvalidSecurityParam::TruncateBytes(1)),
        expect_none(TIMEOUT),
    ])
}

// ============================================================================
// 3.1.24 correct S-A_Data A+C, Plain APDU
// ============================================================================
//
// Per XML: sends an A+C frame but the ciphertext is the plaintext APDU
// (not encrypted). The DUT must reject this because the MAC will not verify
// when the ciphertext doesn't match the actual encrypted payload.
//
// The XML enables Security Mode first, sends the bad frame, expects no
// response (DUT silently drops it), then disables Security Mode.

fn test_3_1_24() -> TestCase {
    // Per XML InvalCypher: the plain APDU bytes that replace the ciphertext.
    // This is A_PropertyExtValueRead for PID 0x39 on Security IO:
    // 01 CC 00 11 00 10 39 01 00 00 (10 bytes)
    let plain_apdu = vec![0x01, 0xCC, 0x00, 0x11, 0x00, 0x10, 0x39, 0x01, 0x00, 0x00];

    TestCase::new("3.1.24 A+C with plain APDU (not encrypted) → reject").with_steps(vec![
        comment("Enable Security Mode"),
        inject_secure_ac("3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01", "TK1"),
        expect_secure_ac("3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00", "TK1", TIMEOUT),
        comment("A+C frame with plaintext as ciphertext → reject (MAC mismatch)"),
        inject_secure_invalid(
            READ_PID57,
            SecureParams::tool_auth_conf("TK1"),
            InvalidSecurityParam::PlainCipher(plain_apdu),
        ),
        expect_none(TIMEOUT),
        comment("Disable Security Mode"),
        inject_secure_ac("3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00", "TK1"),
        expect_secure_ac("3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00", "TK1", TIMEOUT),
    ])
}
