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

/// Challenge bytes used in sync_req after the power cycle in 3.8.12.1–6.
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

    // 3.8.12.3/4/5 perform factory resets (A_Restart with erase 0x02
    // / IPC master_reset) that land the DUT on `tool_key == FDSK`.
    // Rebuild the default SHM snapshot via `full_reset` so the next
    // suite starts with tool_key = TK1 (the pre-provisioned baseline).
    TestSuite::new("3.8.12 PID_SECURITY_FAILURES_LOG (Security IO, access 1FF/0CC)", variables)
        .secure()
        .with_cases(vec![
            test_3_8_12_1(),
            test_3_8_12_2(),
            test_3_8_12_3(),
            test_3_8_12_4(),
            test_3_8_12_5(),
            test_3_8_12_6(),
            test_3_8_12_7(),
            test_3_8_12_8(),
            test_3_8_12_9(),
        ])
        .with_teardown(vec![
            comment("Teardown: rebuild default SHM + respawn to restore all DUT tables."),
            full_reset(2000),
            wait(1500),
        ])
}

fn placeholder(name: &'static str, reason: &'static str) -> TestCase {
    TestCase::new(name).with_steps(vec![comment(reason)])
}

fn test_3_8_12_1() -> TestCase {
    let mut steps = vec![
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("==== General Procedure (clear + provoke 3 errors + verify) ===="),
    ];
    steps.extend(general_procedure_steps());

    // ==== Power down / power up the BDUT ====
    //
    // The XML says `@@Power down BDUT and power up again`. We simulate with
    // `power_cycle`, which flushes the live state to the shared-memory region
    // (so the failures log + counters survive) and respawns the child.
    steps.extend(vec![
        comment("==== Specific procedure for 3.8.12.1: Power down + power up ===="),
        power_cycle(2000),

        // After the power cycle the harness's tool-sending seq counter is
        // ahead of the DUT's freshly-reloaded receiving seq. Re-sync so
        // subsequent secure frames are accepted.
        comment("Sync with BDUT after power-up to re-align tool seq numbers"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 1, CHALLENGE_1),
        expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),

        // ---- Verify counters persisted ----
        comment("Read counters after power-up → expect same [0, 1, 1, 1]"),
        inject_secure_ac(READ_COUNTERS, "TK1"),
        expect_secure_ac(READ_COUNTERS_RESP, "TK1", TIMEOUT),

        comment("Read last entry after power-up → expect same SeqNrError"),
        inject_secure_ac(READ_LAST_ENTRY, "TK1"),
        expect_secure_ac(READ_LAST_ENTRY_RESP, "TK1", TIMEOUT),
    ]);

    TestCase::new(
        "3.8.12.1 Secure FunctionProperty, behavior on Power Down",
    )
    .with_steps(steps)
}

fn test_3_8_12_2() -> TestCase {
    // Connection-oriented A_Restart master reset: restart_type=1, erase=0x01
    // (Confirmed). TPCI 0x43 (numbered seq 0 + APCI high 0x03), APCI 0x8101,
    // erase_code=0x01, channel=0x00.
    const CONNECTED_RESTART_CONFIRMED: &str =
        "3C 60 #EDI #BDUT_ADDR 03 43 81 01 00";
    // A_Restart_Response: error_code=0x00, process_time=?? (2 bytes).
    const CONNECTED_RESTART_CONFIRMED_RESP: &str =
        "3C 60 #BDUT_ADDR #EDI 04 43 A1 00 00 ??";

    let mut steps = vec![
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("==== General Procedure (clear + provoke 3 errors + verify) ===="),
    ];
    steps.extend(general_procedure_steps());

    // Confirmed Restart (erase=0x01) preserves all state including the
    // failures log. No sync needed — the DUT keeps its tool sending /
    // receiving sequence counters across this restart variant.
    steps.extend(vec![
        comment("==== Specific procedure for 3.8.12.2: Confirmed Restart ===="),
        comment("Open transport connection"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),

        comment("Secure A+C numbered A_Restart (Confirmed, erase=0x01)"),
        inject_secure_ac(CONNECTED_RESTART_CONFIRMED, "TK1"),
        comment("Expect T_ACK for our numbered request"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        comment("Expect secure A+C A_Restart_Response (error=0)"),
        expect_secure_ac(CONNECTED_RESTART_CONFIRMED_RESP, "TK1", TIMEOUT),
        comment("ACK the response"),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        comment("T_Disconnect"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),

        comment("Wait for the DUT to auto-restart (parent respawns on EOF)"),
        wait(500),

        // ---- Verify counters persisted across Confirmed Restart ----
        comment("Read counters after restart → expect same [0, 1, 1, 1]"),
        inject_secure_ac(READ_COUNTERS, "TK1"),
        expect_secure_ac(READ_COUNTERS_RESP, "TK1", TIMEOUT),

        comment("Read last entry after restart → expect same SeqNrError"),
        inject_secure_ac(READ_LAST_ENTRY, "TK1"),
        expect_secure_ac(READ_LAST_ENTRY_RESP, "TK1", TIMEOUT),
    ]);

    TestCase::new("3.8.12.2 Secure FunctionPropertyCommand, behavior on Confirmed Restart")
        .with_steps(steps)
}

fn test_3_8_12_3() -> TestCase {
    // Connection-oriented secure A+C `A_Restart` master reset, erase
    // code 0x02 (FactoryReset). Same wire shape as 3.8.9.5's
    // `CONNECTED_RESTART_CONFIRMED`, but `81 02 00` instead of
    // `81 01 00`.
    const CONNECTED_RESTART_FACTORY: &str =
        "3C 60 #EDI #BDUT_ADDR 03 43 81 02 00";
    const CONNECTED_RESTART_FACTORY_RESP: &str =
        "3C 60 #BDUT_ADDR #EDI 04 43 A1 00 00 ??";

    // After FactoryReset the counters and ring buffer are empty.
    const READ_COUNTERS_EMPTY: &str =
        "3C 60 #BDUT_ADDR #EDI 11 01 D6 00 11 00 10 37 00 00 00 00 00 00 00 00 00 00 00";
    // F8 = E_BAD_ARGUMENT — no entry at index 1 because the log is empty.
    const READ_LAST_ENTRY_EMPTY: &str =
        "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 F8 01";


    let mut steps = vec![
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("==== General Procedure (clear + provoke 3 errors + verify) ===="),
    ];
    steps.extend(general_procedure_steps());

    steps.extend(vec![
        comment("==== Specific procedure for 3.8.12.3: Master Reset (FactoryReset) ===="),

        // Bus-level connection-oriented A_Restart with erase=0x02. The
        // DUT auto-respawns; persisted state survives in SHM but the
        // factory-reset path inside the security extension wipes the
        // active tool key (restored to FDSK) and the failures log.
        comment("Open transport connection"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        comment("Secure A+C numbered A_Restart (FactoryReset, erase=0x02)"),
        inject_secure_ac(CONNECTED_RESTART_FACTORY, "TK1"),
        comment("Expect T_ACK"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        comment("Expect secure A+C A_Restart_Response (error=0)"),
        expect_secure_ac(CONNECTED_RESTART_FACTORY_RESP, "TK1", TIMEOUT),
        comment("ACK the response (DUT IA may already be 0xFFFF)"),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        comment("T_Disconnect (DUT now answers as 0xFFFF)"),
        inject("B0 #EDI FF FF 60 81"),

        comment("Wait for the DUT to auto-restart"),
        wait_for_restart(2000),
        drain(500),

        // Re-program the DUT individual address via serial number
        // (broadcast). On real BDUTs there'd also be a domain-address
        // write here, but our TP1 conformance DUT has no domain
        // address — `2C E0` system-broadcast `A_DomainAddress_*` is
        // a no-op for it.
        comment("Re-program BDUT IA via A_IndividualAddressSerialNumber_Write"),
        inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
        wait(200),

        // After FactoryReset the active tool key reverts to FDSK
        // (distinct from TK1), so post-reset management traffic must
        // use FDSK until a new tool key is written.
        comment("Sync tool seq number after FactoryReset (FDSK-encrypted)"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "FDSK", 1, CHALLENGE_1),
        expect_sync_res_tool("FDSK", CHALLENGE_1, None, None, TIMEOUT),

        // ---- Verify counters were cleared ----
        comment("Read counters after FactoryReset → expect all zero"),
        inject_secure_ac(READ_COUNTERS, "FDSK"),
        expect_secure_ac(READ_COUNTERS_EMPTY, "FDSK", TIMEOUT),

        comment("Read last entry after FactoryReset → expect F8 (empty log)"),
        inject_secure_ac(READ_LAST_ENTRY, "FDSK"),
        expect_secure_ac(READ_LAST_ENTRY_EMPTY, "FDSK", TIMEOUT),
    ]);

    // This case ends with `tool_key == FDSK` because of the factory
    // reset. Re-provision TK1 in teardown so later cases (which
    // assume TK1 is active) continue to authenticate.
    TestCase::new("3.8.12.3 Secure FunctionPropertyCommand, behavior on Factory Reset")
        .with_steps(steps)
        .with_teardown(provision_tk1_via_fdsk())
}

fn test_3_8_12_4() -> TestCase {
    // Same shape as 3.8.12.3 but with `EraseCode::FactoryResetKeepIA`
    // (0x07): the IA survives the reset, so we don't need to
    // re-program it via `A_IndividualAddressSerialNumber_Write`.
    const CONNECTED_RESTART_FRWITHIA: &str =
        "3C 60 #EDI #BDUT_ADDR 03 43 81 07 00";
    const CONNECTED_RESTART_FRWITHIA_RESP: &str =
        "3C 60 #BDUT_ADDR #EDI 04 43 A1 00 00 ??";

    const READ_COUNTERS_EMPTY: &str =
        "3C 60 #BDUT_ADDR #EDI 11 01 D6 00 11 00 10 37 00 00 00 00 00 00 00 00 00 00 00";
    const READ_LAST_ENTRY_EMPTY: &str =
        "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 F8 01";

    let mut steps = vec![
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("==== General Procedure (clear + provoke 3 errors + verify) ===="),
    ];
    steps.extend(general_procedure_steps());

    steps.extend(vec![
        comment("==== Specific procedure for 3.8.12.4: FactoryResetKeepIA (erase=0x07) ===="),
        comment("Open transport connection"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        comment("Secure A+C numbered A_Restart (FactoryResetKeepIA, erase=0x07)"),
        inject_secure_ac(CONNECTED_RESTART_FRWITHIA, "TK1"),
        comment("Expect T_ACK"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        comment("Expect secure A+C A_Restart_Response (error=0)"),
        expect_secure_ac(CONNECTED_RESTART_FRWITHIA_RESP, "TK1", TIMEOUT),
        comment("ACK the response"),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        comment("T_Disconnect"),
        inject("B0 #EDI #BDUT_ADDR 60 81"),

        comment("Wait for the DUT to auto-restart (IA is preserved)"),
        wait_for_restart(2000),
        drain(500),

        comment("Sync tool seq number after FactoryResetKeepIA (FDSK-encrypted)"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "FDSK", 1, CHALLENGE_1),
        expect_sync_res_tool("FDSK", CHALLENGE_1, None, None, TIMEOUT),

        comment("Read counters → expect all zero"),
        inject_secure_ac(READ_COUNTERS, "FDSK"),
        expect_secure_ac(READ_COUNTERS_EMPTY, "FDSK", TIMEOUT),

        comment("Read last entry → expect F8 (empty log)"),
        inject_secure_ac(READ_LAST_ENTRY, "FDSK"),
        expect_secure_ac(READ_LAST_ENTRY_EMPTY, "FDSK", TIMEOUT),
    ]);

    // Factory reset left `tool_key == FDSK`; restore TK1 in teardown.
    TestCase::new("3.8.12.4 Secure FunctionPropertyCommand, behavior on Factory Reset without IA")
        .with_steps(steps)
        .with_teardown(provision_tk1_via_fdsk())
}

fn test_3_8_12_5() -> TestCase {
    // "Local Factory Reset" is a non-bus reset (typically a service
    // button press on the device). We exercise the same code path
    // via the `master_reset` IPC primitive with `EraseCode::FactoryReset`
    // (0x02). The DUT reapplies its FDSK as the active tool key, just
    // like 3.8.12.3 — but no `A_Restart_Response` is emitted on the
    // bus and the IA is wiped to 0xFFFF, requiring a re-program.
    const READ_COUNTERS_EMPTY: &str =
        "3C 60 #BDUT_ADDR #EDI 11 01 D6 00 11 00 10 37 00 00 00 00 00 00 00 00 00 00 00";
    const READ_LAST_ENTRY_EMPTY: &str =
        "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 F8 01";

    let mut steps = vec![
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("==== General Procedure (clear + provoke 3 errors + verify) ===="),
    ];
    steps.extend(general_procedure_steps());

    steps.extend(vec![
        comment("==== Specific procedure for 3.8.12.5: Local Factory Reset ===="),
        // Erase code 0x02 = FactoryReset, applied via the IPC primitive
        // (no bus restart telegram, no T_Connect required).
        master_reset(0x02, 2000),

        comment("Re-program BDUT IA via A_IndividualAddressSerialNumber_Write"),
        inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
        wait(200),

        comment("Sync tool seq number after Local Factory Reset (FDSK-encrypted)"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "FDSK", 1, CHALLENGE_1),
        expect_sync_res_tool("FDSK", CHALLENGE_1, None, None, TIMEOUT),

        comment("Read counters → expect all zero"),
        inject_secure_ac(READ_COUNTERS, "FDSK"),
        expect_secure_ac(READ_COUNTERS_EMPTY, "FDSK", TIMEOUT),

        comment("Read last entry → expect F8 (empty log)"),
        inject_secure_ac(READ_LAST_ENTRY, "FDSK"),
        expect_secure_ac(READ_LAST_ENTRY_EMPTY, "FDSK", TIMEOUT),
    ]);

    // Local Factory Reset left `tool_key == FDSK`; restore TK1.
    TestCase::new("3.8.12.5 Secure FunctionPropertyCommand, behavior on Local Factory Reset")
        .with_steps(steps)
        .with_teardown(provision_tk1_via_fdsk())
}

fn test_3_8_12_6() -> TestCase {
    // Pre-load all four counters to FFFFh via the manufacturer-specific
    // PID 203 (#OVERFLOW_PROPERTY). PropertyExtValueWriteCon: count=4
    // starting at index 1, data = 8 × 0xFF.
    const PRELOAD_COUNTERS: &str =
        "3C 60 #EDI #BDUT_ADDR 11 01 CE 00 11 00 10 #OVERFLOW_PROPERTY 04 00 01 FF FF FF FF FF FF FF FF";
    const PRELOAD_COUNTERS_OK: &str =
        "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 #OVERFLOW_PROPERTY 04 00 01 00";

    // After provoking three error types, all four counters must remain
    // saturated at FFFFh. `READ_COUNTERS` returns 8 bytes of counter
    // payload after the 3-byte service-info prefix; bytes 0–1 (the
    // `SCF` counter) stay zero per spec because it is incremented by a
    // separate code path that this test does not provoke.
    const READ_COUNTERS_SATURATED: &str =
        "3C 60 #BDUT_ADDR #EDI 11 01 D6 00 11 00 10 37 00 00 00 FF FF FF FF FF FF FF FF";

    let steps = vec![
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),

        comment("Pre-load all four failure counters to FFFFh via PID 203"),
        inject_secure_ac(PRELOAD_COUNTERS, "TK1"),
        expect_secure_ac(PRELOAD_COUNTERS_OK, "TK1", TIMEOUT),

        // Provoke the same three failure types as the general procedure
        // (crypto, access, seq) — but do NOT clear the counters first
        // and do not assert intermediate counter values; we only care
        // that after each provocation the counter saturates at FFFFh
        // rather than wrapping to 0.
        comment("Provoke CryptoError: encrypt with wrong key"),
        inject_secure_ac(PROVOKE_CRYPTO, "ZERO_KEY"),
        expect_none(TIMEOUT),

        comment("Provoke AccessError: auth-only write on 00C PID"),
        inject_secure_ao(PROVOKE_ACCESS, "TK1"),
        expect_secure_ao(PROVOKE_ACCESS_RESP, "TK1", TIMEOUT),

        comment("Provoke SeqNrError: send with seq=0"),
        inject_secure_ac_seq0(PROVOKE_SEQ, "TK1"),
        expect_none(TIMEOUT),

        comment("Read counters → expect all four still at FFFFh (saturating add)"),
        inject_secure_ac(READ_COUNTERS, "TK1"),
        expect_secure_ac(READ_COUNTERS_SATURATED, "TK1", TIMEOUT),
    ];

    TestCase::new("3.8.12.6 Check prevention of Overflow in security counters")
        .with_steps(steps)
}

fn test_3_8_12_8() -> TestCase {
    placeholder(
        "3.8.12.8 Secure FunctionPropertyCommand, negative cases",
        "Placeholder: negative-case stimulation of FunctionPropertyCommand not yet wired up.",
    )
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
