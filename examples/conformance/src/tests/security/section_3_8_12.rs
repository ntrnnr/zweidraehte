//! Section 3.8.12 — `PID_SECURITY_FAILURES_LOG` access policy `1FF/0CC`.
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.12 PID_SECURITY_FAILURES_LOG".
//!
//! Tests PID 0x37 (PID_SECURITY_FAILURES_LOG, i.e. PID 55) on the Security
//! Interface Object (IOT=0x0011, instance=0x0010). Access policy is `1FF/0CC`:
//! - Security Mode OFF: read allowed with A, A+C, or plain; write requires A+C.
//! - Security Mode ON: read requires A+C; write requires A+C.
//!
//! This PID is `PDT_FUNCTION` — accessed via FunctionPropertyExtCommand
//! (0x01D4) and FunctionPropertyExtState_Read (0x01D5).
//!
//! Skipped test cases:
//! - 3.8.12.1–6 — power-down, restart, factory reset persistence and overflow
//!   tests. Need restart infrastructure and SyncReq support.
//! - 3.8.12.8 — connection-oriented FunctionPropertyCommand negative cases.
//!   Needs T_Connect transport layer support.

use crate::{TestCase, TestStep, TestSuite};
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
// PID 0x37 (SECURITY_FAILURES_LOG) Templates
// ============================================================================

// FunctionPropertyExtCommand: clear failures log (id=0, info=0, data=0x00).
const CLEAR_LOG: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 37 00 00 00";

// Response to clear: rc=00, data=[id=00].
const CLEAR_LOG_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 00 00";

// FunctionPropertyExtStateRead: read all counters (id=0, info=0).
const READ_COUNTERS: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D5 00 11 00 10 37 00 00 00";

// Response: rc=00, id=00, info=00, then 4×2-byte BE counters.
// After provoking crypto(1), access(1), seq(1):
// counters = [SCF=0, Crypto=1, Seq=1, Access=1] = 00 00 00 01 00 01 00 01.
const READ_COUNTERS_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 11 01 D6 00 11 00 10 37 00 00 00 00 00 00 01 00 01 00 01";

// FunctionPropertyExtStateRead: read last entry (id=1, info=0).
const READ_LAST_ENTRY: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D5 00 11 00 10 37 00 01 00";

// Response: rc=00, id=01, info=00, src_addr(#EDI), fragment(9 wildcards),
// failure_type=02 (SeqNrError — the last provoked error).
const READ_LAST_ENTRY_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 15 01 D6 00 11 00 10 37 00 01 00 #EDI ?? ?? ?? ?? ?? ?? ?? ?? ?? 02";

// ============================================================================
// Error Provocation Templates
// ============================================================================

// Provoke CryptoError: FunctionPropertyExtStateRead on PID_SECURITY_MODE
// (0x33) encrypted with wrong key (ZERO_KEY). DUT can't decrypt → drops.
const PROVOKE_CRYPTO: &str =
    "3C 60 #EDI #BDUT_ADDR 08 01 D5 00 11 00 10 33 00 00";

// Provoke AccessError: PropertyExtValueWriteCon on PID_SEQUENCE_NUMBER_SENDING
// (0x3B) with auth-only. Policy 00C/00C requires A+C → denied.
const PROVOKE_ACCESS: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 3B 01 00 00";

// Response to access provocation: PropertyExtValueWriteConRes with error FC.
const PROVOKE_ACCESS_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 3B 00 00 00 FC";

// Provoke SeqNrError: FunctionPropertyExtStateRead on PID 0x37 with seq=0.
// DUT rejects (seq=0 invalid) → drops, no response.
const PROVOKE_SEQ: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D5 00 11 00 10 37 00 00 00";

// ============================================================================
// 3.8.12.7 Negative Case Templates
// ============================================================================

// StateRead with bad service ID (id=5) → F2 (SERVICE_NOT_SUPPORTED), data=[05].
const NEG_BAD_ID: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D5 00 11 00 10 37 00 05 00";
const NEG_BAD_ID_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 F2 05";

// StateRead with wrong service info (id=0, info=0x11) → F8, data=[00].
const NEG_BAD_INFO: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D5 00 11 00 10 37 00 00 11";
const NEG_BAD_INFO_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 F8 00";

// StateRead with out-of-bounds entry index (id=1, info=8) → F8, data=[01].
const NEG_OOB_ENTRY: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D5 00 11 00 10 37 00 01 08";
const NEG_OOB_ENTRY_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 F8 01";

// StateRead with incorrect length (only id, no info byte) → F8, data=[00].
const NEG_SHORT: &str =
    "3C 60 #EDI #BDUT_ADDR 07 01 D5 00 11 00 10 37 00";
const NEG_SHORT_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 F8 00";

// Unsecured FctPropStateRead on PID 0x37 → FC (denied, SM=ON).
const UNSECURED_STATE_READ: &str =
    "BC #EDI #BDUT_ADDR 69 01 D5 00 11 00 10 37 00 00 00";
const UNSECURED_STATE_READ_RESP: &str =
    "BC #BDUT_ADDR #EDI 68 01 D6 00 11 00 10 37 FC 00";

// Unsecured read of last entry → FC.
const UNSECURED_LAST_ENTRY: &str =
    "BC #EDI #BDUT_ADDR 69 01 D5 00 11 00 10 37 00 01 00";
const UNSECURED_LAST_ENTRY_RESP: &str =
    "BC #BDUT_ADDR #EDI 68 01 D6 00 11 00 10 37 FC 01";

// Auth-only FctPropStateRead on PID 0x37 → FC (SM=ON, 1FF needs A+C).
const AUTH_ONLY_STATE_READ: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D5 00 11 00 10 37 00 00 00";
const AUTH_ONLY_STATE_READ_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 FC 00";

// Auth-only read of last entry → FC.
const AUTH_ONLY_LAST_ENTRY: &str =
    "3C 60 #EDI #BDUT_ADDR 09 01 D5 00 11 00 10 37 00 01 00";
const AUTH_ONLY_LAST_ENTRY_RESP: &str =
    "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 FC 01";

// ============================================================================
// PropertyExtDescription_Read templates for PID 0x37
// ============================================================================

// Per XML 3.8.12.9: plain A_PropertyExtDescription_Read.
const PLAIN_DESC_READ: &str =
    "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 37 00 00";

// Per XML: all-zero descriptor (sec ON, 1FF denies plain desc when sec ON).
const PLAIN_DESC_READ_DENIED: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 37 00 00 00 00 00 00 00 00 00 00";

// Per XML: valid descriptor (sec OFF, 1FF allows plain).
const PLAIN_DESC_READ_OK: &str =
    "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 37 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// ============================================================================
// General Procedure (shared preamble for tests 3.8.12.1–7)
// ============================================================================

/// Generate the general procedure steps that are common to tests 3.8.12.1–7:
/// clear counters, provoke three error types, read and verify counters/entries.
fn general_procedure_steps() -> Vec<TestStep> {
    vec![
        // ---- Clear error counters ----
        comment("Clear failure log"),
        inject_secure_ac(CLEAR_LOG, "TK1"),
        expect_secure_ac(CLEAR_LOG_RESP, "TK1", TIMEOUT),

        // ---- Provoke CryptoError (wrong key) ----
        comment("Provoke CryptoError: encrypt with wrong key → DUT drops"),
        inject_secure_ac(PROVOKE_CRYPTO, "ZERO_KEY"),
        expect_none(TIMEOUT),

        // ---- Provoke AccessError (A-only on 00C property) ----
        comment("Provoke AccessError: auth-only write on 00C PID → FC"),
        inject_secure_ao(PROVOKE_ACCESS, "TK1"),
        expect_secure_ao(PROVOKE_ACCESS_RESP, "TK1", TIMEOUT),

        // ---- Provoke SeqNrError (seq=0) ----
        comment("Provoke SeqNrError: send with seq=0 → DUT drops"),
        inject_secure_ac_seq0(PROVOKE_SEQ, "TK1"),
        expect_none(TIMEOUT),

        // ---- Read all counters (expect [0, 1, 1, 1]) ----
        comment("Read counters: expect SCF=0, Crypto=1, Seq=1, Access=1"),
        inject_secure_ac(READ_COUNTERS, "TK1"),
        expect_secure_ac(READ_COUNTERS_RESP, "TK1", TIMEOUT),

        // ---- Read last error entry (SeqNrError from EDI) ----
        comment("Read last entry: expect SeqNrError (type=02) from #EDI"),
        inject_secure_ac(READ_LAST_ENTRY, "TK1"),
        expect_secure_ac(READ_LAST_ENTRY_RESP, "TK1", TIMEOUT),
    ]
}

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_12_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.8.12 PID_SECURITY_FAILURES_LOG (Security IO, access 1FF/0CC)", variables)
        .secure()
        .with_cases(vec![
            test_3_8_12_7(),
            test_3_8_12_9(),
        ])
}

// ============================================================================
// 3.8.12.7 Secure FunctionPropertyStateRead, negative cases
// ============================================================================
//
// Per XML: Run the general procedure (clear, provoke errors, read counters),
// then perform negative cases for FunctionPropertyStateRead, then re-verify
// that the counters haven't changed. Also test unsecured and auth-only reads.

fn test_3_8_12_7() -> TestCase {
    let mut steps = vec![
        // The test requires Security Mode to be ON.
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("==== General Procedure (clear + provoke + verify) ===="),
    ];
    steps.extend(general_procedure_steps());

    steps.extend(vec![
        // ---- Specific procedure for 3.8.12.7 ----
        comment("==== 3.8.12.7 Negative Cases ===="),

        comment("Incorrect ServiceID for FctPropStateRead (id=5)"),
        inject_secure_ac(NEG_BAD_ID, "TK1"),
        expect_secure_ac(NEG_BAD_ID_RESP, "TK1", TIMEOUT),

        comment("Wrong ServiceInfo for FctPropStateRead (id=0, info=0x11)"),
        inject_secure_ac(NEG_BAD_INFO, "TK1"),
        expect_secure_ac(NEG_BAD_INFO_RESP, "TK1", TIMEOUT),

        comment("Unsupported entry index (id=1, info=8)"),
        inject_secure_ac(NEG_OOB_ENTRY, "TK1"),
        expect_secure_ac(NEG_OOB_ENTRY_RESP, "TK1", TIMEOUT),

        comment("Incorrect length (missing info byte)"),
        inject_secure_ac(NEG_SHORT, "TK1"),
        expect_secure_ac(NEG_SHORT_RESP, "TK1", TIMEOUT),

        // ---- Re-read counters (should be unchanged) ----
        comment("Re-read counters: same as before"),
        inject_secure_ac(READ_COUNTERS, "TK1"),
        expect_secure_ac(READ_COUNTERS_RESP, "TK1", TIMEOUT),

        comment("Re-read last entry: still SeqNrError from #EDI"),
        inject_secure_ac(READ_LAST_ENTRY, "TK1"),
        expect_secure_ac(READ_LAST_ENTRY_RESP, "TK1", TIMEOUT),

        // ---- Unsecured reads (SM=ON, should be denied) ----
        comment("Unsecured FctPropStateRead → FC (SM=ON)"),
        inject(UNSECURED_STATE_READ),
        expect(UNSECURED_STATE_READ_RESP, TIMEOUT),

        comment("Unsecured read last entry → FC"),
        inject(UNSECURED_LAST_ENTRY),
        expect(UNSECURED_LAST_ENTRY_RESP, TIMEOUT),

        // ---- Auth-only reads (SM=ON, 1FF/0CC needs A+C) ----
        comment("Auth-only FctPropStateRead → FC (SM=ON)"),
        inject_secure_ao(AUTH_ONLY_STATE_READ, "TK1"),
        expect_secure_ao(AUTH_ONLY_STATE_READ_RESP, "TK1", TIMEOUT),

        comment("Auth-only read last entry → FC"),
        inject_secure_ao(AUTH_ONLY_LAST_ENTRY, "TK1"),
        expect_secure_ao(AUTH_ONLY_LAST_ENTRY_RESP, "TK1", TIMEOUT),
    ]);

    TestCase::new("3.8.12.7 Secure FunctionPropertyStateRead, negative cases")
        .with_steps(steps)
}

// ============================================================================
// 3.8.12.9 Unsecured PropDescrRead
// ============================================================================
//
// Per XML: sec ON first → plain desc read returns all-zero.
// Then sec OFF → plain desc read returns valid descriptor.

fn test_3_8_12_9() -> TestCase {
    TestCase::new("3.8.12.9 Unsecured PropDescrRead").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain desc read → all-zero (sec ON, 1FF denies plain)"),
        inject(PLAIN_DESC_READ),
        expect(PLAIN_DESC_READ_DENIED, TIMEOUT),

        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Plain desc read → valid descriptor (sec OFF, 1FF allows)"),
        inject(PLAIN_DESC_READ),
        expect(PLAIN_DESC_READ_OK, TIMEOUT),
    ])
}
