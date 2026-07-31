//! Section 3.8.13 — `PID_TOOL_KEY` access policy `008/008` (4 cases).
//!
//! Converted from `KnxConformanceTestTemplate-DataSecurity.xml` test suite
//! "3.8.13 PID_TOOL_KEY".
//!
//! Tests PID 0x38 (PID_TOOL_KEY, i.e. PID 56) on the Security Interface
//! Object (IOT=0x0011, instance=0x0010). Access policy is `008/008`: requires
//! Tool A+C for writing. The property is **write-only** — all read attempts
//! are denied with E_ACCESS_DENIED (0xFC).
//!
//! The tool key value is PDT_GENERIC_16 (16 bytes).
//!
//! Skipped test cases:
//! - 3.8.13.1 — writes an actual key and uses it for authentication
//!   (complex key-switch scenario with SyncReq).
//! - 3.8.13.2 — unloads/reloads Security IO and switches from TK1 to TK2;
//!   requires LoadStateControl support not exercised elsewhere.
//! - 3.8.13.6 — uses T_Connect (connection-oriented), not yet implemented.
//! - 3.8.13.8 — uses FDSK key setup, not yet implemented.
//!
//! Note: The XML test template uses TK2 for tests 3.8.13.3–5 because it
//! assumes 3.8.13.2 already switched the tool key. Since we skip 3.8.13.2,
//! we use TK1 (the default tool key) instead.

use super::variables::create_security_variables;
use crate::tests::helpers::*;
use crate::{TestCase, TestSuite};

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

/// Fixed challenge used for the tool-key S-A_Sync_Req after a restart /
/// factory reset. Any non-zero value works; pinning it to a constant
/// makes the test wire-deterministic.
const CHALLENGE_1: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

// ============================================================================
// Security Mode Toggle Templates
// ============================================================================

const ENABLE_SECURITY_MODE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";

const ENABLE_SECURITY_MODE_RESP: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

const DISABLE_SECURITY_MODE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";

const DISABLE_SECURITY_MODE_RESP: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

// ============================================================================
// PropertyExtValueWriteCon templates for PID 0x38 on Security IO
// ============================================================================

// Secure write: count=1, start=1, data=16 bytes (all-zero key + 0x01).
// The last byte 0x01 is part of the 16-byte key value.
// APDU: 01 CE + 00 11 + 00 10 + 38 + 01 + 00 01 + 16 data = 26 bytes → len = 0x19
const SECURE_WRITE_TOOL_KEY: &str =
    "3C 60 #EDI #BDUT_ADDR 19 01 CE 00 11 00 10 38 01 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01";

// Write success: count=1, start=1, return_code=0x00.
// APDU: 01 CF + 00 11 + 00 10 + 38 + 01 + 00 01 + 00 = 11 bytes → len = 0x0A
#[allow(dead_code)] // Not used since we skip 3.8.13.1 and 3.8.13.2.
const SECURE_WRITE_TOOL_KEY_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 38 01 00 01 00";

// Write denied: count=0, start=1, return_code=0xFC (E_ACCESS_DENIED).
const SECURE_WRITE_TOOL_KEY_DENIED: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 38 00 00 01 FC";

// Plain write denied response: standard frame.
const PLAIN_WRITE_TOOL_KEY_DENIED: &str = "BC #BDUT_ADDR #EDI 6A 01 CF 00 11 00 10 38 00 00 01 FC";

// ============================================================================
// PropertyExtValueRead templates for PID 0x38 on Security IO (write-only)
// ============================================================================

// Secure A_PropertyExtValueRead: count=1, start=1.
// APDU: 01 CC + 00 11 + 00 10 + 38 + 01 + 00 01 = 10 bytes → len = 0x09
const SECURE_READ_TOOL_KEY: &str = "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 38 01 00 01";

// Secure read denied: count=0, start=1, return_code=0xFC (E_ACCESS_DENIED).
// All reads are denied because PID_TOOL_KEY is write-only.
const SECURE_READ_TOOL_KEY_DENIED: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 38 00 00 01 FC";

// Plain extended read (extended frame for oversize APDU).
const PLAIN_EXT_READ_TOOL_KEY: &str = "BC #EDI #BDUT_ADDR 69 01 CC 00 11 00 10 38 01 00 01";

// Plain extended read denied.
const PLAIN_EXT_READ_TOOL_KEY_DENIED: &str = "BC #BDUT_ADDR #EDI 6A 01 CD 00 11 00 10 38 00 00 01 FC";

// ============================================================================
// Standard PropertyValueRead templates (03 D5/D6) for PID 0x38
// ============================================================================
//
// The XML also tests the old-style A_PropertyValue_Read service to verify
// that reads are denied through both API paths.

// Plain standard read: obj_index=#SEC_INTF_OBJ_INDEX, PID=0x38, count=1, start=1.
// APDU: 03 D5 + OBJ_INDEX(1) + PID(1) + count_start(2) = 6 bytes → TP1 len = 0x65
const PLAIN_STD_READ_TOOL_KEY: &str = "BC #EDI #BDUT_ADDR 65 03 D5 #SEC_INTF_OBJ_INDEX 38 10 01";

// Plain standard read denied: count=0, start=1.
// In standard property read, count=0 indicates an error/denied response.
const PLAIN_STD_READ_TOOL_KEY_DENIED: &str = "BC #BDUT_ADDR #EDI 65 03 D6 #SEC_INTF_OBJ_INDEX 38 00 01";

// Secure standard read (extended frame).
// APDU: 03 D5 + OBJ_INDEX(1) + PID(1) + count_start(2) = 6 bytes → len = 0x05
const SECURE_STD_READ_TOOL_KEY: &str = "3C 60 #EDI #BDUT_ADDR 05 03 D5 #SEC_INTF_OBJ_INDEX 38 10 01";

// Secure standard read denied: count=0, start=1.
const SECURE_STD_READ_TOOL_KEY_DENIED: &str = "3C 60 #BDUT_ADDR #EDI 05 03 D6 #SEC_INTF_OBJ_INDEX 38 00 01";

// ============================================================================
// PropertyExtDescription_Read / Response templates for PID 0x38 on Security IO
// ============================================================================

// Secure A+C A_PropertyExtDescription_Read (0x01D2): IOT=0x0011, instance=0x0010,
// PID=0x38, description index=0x00, property index=0x00.
// APDU: 01 D2 + 00 11 + 00 10 + 38 + 00 + 00 = 8 bytes → len = 0x08
const SECURE_DESC_READ_PID38: &str = "3C 60 #EDI #BDUT_ADDR 08 01 D2 00 11 00 10 38 00 00";

// Secure A+C success response: valid descriptor (wildcard data bytes).
// APDU: 01 D3 + 00 11 + 00 10 + 38 + ?? x10 = 16 bytes → len = 0x10
const SECURE_DESC_READ_PID38_OK: &str = "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 38 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";

// Plain A_PropertyExtDescription_Read for PID 0x38.
const PLAIN_DESC_READ_PID38: &str = "BC #EDI #BDUT_ADDR 68 01 D2 00 11 00 10 38 00 00";

// Plain all-zero descriptor response (access denied for 00C/00C — plain NEVER allowed).
const PLAIN_DESC_READ_PID38_ZERO: &str = "3C 60 #BDUT_ADDR #EDI 10 01 D3 00 11 00 10 38 00 00 00 00 00 00 00 00 00 00";

// ============================================================================
// Suite Constructor
// ============================================================================

pub fn create_section_3_8_13_suite() -> TestSuite {
    let variables = create_security_variables();

    // Teardown rebuilds the DUT from the default SHM snapshot. 3.8.13.6
    // sub-cases (d) and (e) both issue destructive factory resets that
    // wipe address / association / group-key / GO-flag tables. Without
    // a full reset, subsequent suites' preparation (notably 3.8.15's
    // SyncReq) cascades into timeouts.
    TestSuite::new("3.8.13 PID_TOOL_KEY (Security IO, access 008/008, write-only)", variables)
        .secure()
        .with_cases(vec![
            test_3_8_13_1(),
            test_3_8_13_2(),
            test_3_8_13_3(),
            test_3_8_13_4(),
            test_3_8_13_5(),
            test_3_8_13_7(),
            // `.6` and `.8` leave the DUT with `tool_key == FDSK`
            // (destructive factory-reset sub-cases / FDSK-revert
            // test). Run them last so the suite teardown's
            // `full_reset` reverts to the default SHM snapshot before
            // the next suite starts.
            test_3_8_13_6(),
            test_3_8_13_8(),
        ])
        .with_teardown(vec![
            comment("Teardown: rebuild default SHM + respawn to restore all DUT tables."),
            full_reset(2000),
            // Clear the `S-A_Sync_Req` rate-limit window (1 s spec,
            // scaled by `KNX_TIME_DIVISOR` under the conformance
            // harness) so 3.8.15's preparation SyncReq isn't
            // throttled into a timeout.
            wait(1500),
        ])
}

fn test_3_8_13_1() -> TestCase {
    // Per TSSJ §3.8.13.1: the WriteConRes for PID_TOOL_KEY must be
    // authenticated and encrypted with the *newly-set* security tool
    // key, not the key that authenticated the request. Each write
    // below is authenticated with the current key and the response
    // is verified with the new key.
    //
    // We rotate TK1 → TK2 → TK1 both with Security Mode off and on.

    // Write PID_TOOL_KEY = TK2 (request authenticated with TK1;
    // response expected encrypted with TK2 per TSSJ §3.8.13.1).
    const WRITE_TK2: &str = "3C 60 #EDI #BDUT_ADDR 19 01 CE 00 11 00 10 38 01 00 01 \
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02";

    // Write PID_TOOL_KEY = TK1 (restore to default for subsequent tests).
    const WRITE_TK1: &str = "3C 60 #EDI #BDUT_ADDR 19 01 CE 00 11 00 10 38 01 00 01 \
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01";

    const WRITE_TK_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 38 01 00 01 00";

    TestCase::new("3.8.13.1 Secure PropertyValueWrite – A+C").with_steps(vec![
        // ==== Phase A: Security Mode OFF ====
        comment("Sec mode OFF — write Tool Key = TK2 (auth with TK1, response with TK2)"),
        inject_secure_ac(WRITE_TK2, "TK1"),
        expect_secure_ac(WRITE_TK_OK, "TK2", TIMEOUT),
        // Subsequent management traffic authenticates with TK2.
        comment("Enable Security Mode (now auth with TK2)"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK2"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK2", TIMEOUT),
        // ==== Phase B: Security Mode ON ====
        comment("Sec mode ON — write Tool Key = TK1 (auth with TK2, response with TK1)"),
        inject_secure_ac(WRITE_TK1, "TK2"),
        expect_secure_ac(WRITE_TK_OK, "TK1", TIMEOUT),
        comment("Disable Security Mode (back to default, auth with TK1)"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
    ])
}

fn test_3_8_13_2() -> TestCase {
    // PropertyExtValueWriteCon on PID_LOAD_STATE_CONTROL (5) of the
    // Security Object (IOT 0x0011), one element starting at index 1,
    // 9-byte load-control record. First byte selects the load event:
    // 0x04 = Unload, 0x02 = LoadCompleted. The trailing 8 bytes are
    // the load-procedure record; we send all-zero (System B ignores it).
    const SET_UNLOADED: &str = "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 04 00 00 00 00 00 00 00 00 00";
    const SET_UNLOADED_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 05 01 00 01 00";

    const SET_LOADED: &str = "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 02 00 00 00 00 00 00 00 00 00";
    const SET_LOADED_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 05 01 00 01 00";

    // PropertyExtValueWriteCon on PID_TOOL_KEY (56 = 0x38), one element
    // starting at index 1, 16-byte key. The reference XML uses literal
    // bytes that don't correspond to a named key, but for our harness
    // we instead rotate between the two named keys TK1 and TK2 — the
    // test invariant being checked (acceptance of secure frames while
    // the Security Object load state is Unloaded) is independent of
    // the specific key bytes.
    //
    // Write Tool Key = TK2 = 10 11 12 ... 1F.
    const WRITE_TK2: &str = "3C 60 #EDI #BDUT_ADDR 19 01 CE 00 11 00 10 38 01 00 01 \
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02";
    const WRITE_TK_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 38 01 00 01 00";

    // Write Tool Key = TK1 = 00 01 02 ... 0F (used to restore TK1
    // before the test exits so subsequent suites still authenticate).
    const WRITE_TK1: &str = "3C 60 #EDI #BDUT_ADDR 19 01 CE 00 11 00 10 38 01 00 01 \
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01";

    const ENABLE_SM: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";
    const ENABLE_SM_OK: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";
    const DISABLE_SM: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 00";
    const DISABLE_SM_OK: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";

    let steps = vec![
        comment("Set Security IO to Unloaded (still authenticated with TK1)"),
        inject_secure_ac(SET_UNLOADED, "TK1"),
        expect_secure_ac(SET_UNLOADED_OK, "TK1", TIMEOUT),
        // Even though the Security Object is unloaded, secure tool-key
        // management traffic still works — that's the invariant the
        // test exercises. Activate sec mode encrypted with TK1.
        comment("Activate Security Mode while SecIO unloaded"),
        inject_secure_ac(ENABLE_SM, "TK1"),
        expect_secure_ac(ENABLE_SM_OK, "TK1", TIMEOUT),
        // Rotate tool key to TK2 (write authenticated with current
        // key TK1, response encrypted with the new key TK2 per
        // TSSJ §3.8.13.1).
        comment("Write Tool Key = TK2 (auth with TK1, response with TK2)"),
        inject_secure_ac(WRITE_TK2, "TK1"),
        expect_secure_ac(WRITE_TK_OK, "TK2", TIMEOUT),
        // Subsequent management traffic must use the new key TK2.
        comment("Deactivate Security Mode (now authenticated with TK2)"),
        inject_secure_ac(DISABLE_SM, "TK2"),
        expect_secure_ac(DISABLE_SM_OK, "TK2", TIMEOUT),
        // Rotate the tool key back to TK1 to leave a clean state for
        // subsequent test cases / suites. Response uses the new key (TK1).
        comment("Restore Tool Key = TK1 (auth with TK2, response with TK1)"),
        inject_secure_ac(WRITE_TK1, "TK2"),
        expect_secure_ac(WRITE_TK_OK, "TK1", TIMEOUT),
        comment("Reload Security IO (LoadCompleted)"),
        inject_secure_ac(SET_LOADED, "TK1"),
        expect_secure_ac(SET_LOADED_OK, "TK1", TIMEOUT),
    ];

    TestCase::new("3.8.13.2 Check ToolKey usage when Security Interface Object is unloaded").with_steps(steps)
}

fn test_3_8_13_6() -> TestCase {
    // Tool key persistence across different restart types. The
    // reference XML checks five sub-cases:
    //   (a) power cycle               — key survives
    //   (b) bus-level Basic Restart   — key survives
    //   (c) bus-level Confirmed Restart (erase=0x01) — key survives
    //   (d) FactoryResetKeepIA (erase=0x07) — key unchanged
    //   (e) local FactoryReset (erase=0x02) — key replaced with FDSK
    //
    // "Read" here is really "write PID_TOOL_KEY using the current key
    // and observe an ACK" — PID 56 is write-only, so that's the only
    // way to probe which key the BDUT is currently accepting. Each
    // sub-case leaves the device with the expected current key; a
    // successful secure write under that key proves the invariant.
    //
    // Sub-cases (a)-(d) match the original tool key (TK1 in our
    // harness): 03/05/01 §6.3.10's master-reset table leaves the tool
    // key "not influenced" by a Confirmed Restart *and* by "Reset to
    // default without IA" (07h), and only (e), "Reset to default state"
    // (02h), makes it inactive so the FDSK becomes active again
    // (§6.1.4). (e) verifies under SecKey="FDSK", which is a distinct
    // key in our harness, so it also confirms the DUT stops accepting
    // TK1 there.

    // Write PID_TOOL_KEY = TK1 (idempotent: matches the default).
    const WRITE_TK1: &str = "3C 60 #EDI #BDUT_ADDR 19 01 CE 00 11 00 10 38 01 00 01 \
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01";
    // Write PID_TOOL_KEY = FDSK (idempotent when current key is FDSK).
    const WRITE_FDSK: &str = "3C 60 #EDI #BDUT_ADDR 19 01 CE 00 11 00 10 38 01 00 01 \
         11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11";
    const WRITE_TK_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 38 01 00 01 00";

    // Connection-oriented Basic Restart (secure A+C).
    //   TPCI 0x43 = numbered seq 0, APCI high 0x03, APCI low 0x80 (Restart).
    const CONNECTED_BASIC_RESTART: &str = "3C 60 #EDI #BDUT_ADDR 02 43 80";

    // Connection-oriented Confirmed Restart (secure A+C, erase=0x01).
    const CONNECTED_RESTART_CONFIRMED: &str = "3C 60 #EDI #BDUT_ADDR 03 43 81 01 00";
    const CONNECTED_RESTART_CONFIRMED_RESP: &str = "3C 60 #BDUT_ADDR #EDI 04 43 A1 00 00 ??";

    // Connection-oriented FactoryResetKeepIA (secure A+C, erase=0x07).
    const CONNECTED_RESTART_FRWITHIA: &str = "3C 60 #EDI #BDUT_ADDR 03 43 81 07 00";
    const CONNECTED_RESTART_FRWITHIA_RESP: &str = "3C 60 #BDUT_ADDR #EDI 04 43 A1 00 00 ??";

    TestCase::new("3.8.13.6 Tool Key persistence across power-down / master reset")
        .with_steps(vec![
            comment("Enable Security Mode"),
            inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
            expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
            // ==== (a) Power cycle — tool key persists ====
            comment("(a) Power cycle — tool key survives"),
            power_cycle(2000),
            // Tool seq counters reset by power_cycle need re-sync before any
            // subsequent secure traffic.
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 1, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
            comment("Verify: write TK1 with TK1 → ACK"),
            inject_secure_ac(WRITE_TK1, "TK1"),
            expect_secure_ac(WRITE_TK_OK, "TK1", TIMEOUT),
            // ==== (b) Bus-level Basic Restart — tool key persists ====
            comment("(b) Bus-level Basic Restart (secure A+C) — tool key survives"),
            inject("B0 #EDI #BDUT_ADDR 60 80"),
            inject_secure_ac(CONNECTED_BASIC_RESTART, "TK1"),
            expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
            inject("B0 #EDI #BDUT_ADDR 60 81"),
            wait_for_restart(2000),
            drain(500),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 1, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
            comment("Verify: write TK1 with TK1 → ACK"),
            inject_secure_ac(WRITE_TK1, "TK1"),
            expect_secure_ac(WRITE_TK_OK, "TK1", TIMEOUT),
            // ==== (c) Bus-level Confirmed Restart (erase=0x01) ====
            comment("(c) Confirmed Restart (erase=0x01) — tool key survives"),
            inject("B0 #EDI #BDUT_ADDR 60 80"),
            inject_secure_ac(CONNECTED_RESTART_CONFIRMED, "TK1"),
            expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
            expect_secure_ac(CONNECTED_RESTART_CONFIRMED_RESP, "TK1", TIMEOUT),
            inject("B0 #EDI #BDUT_ADDR 60 C2"),
            inject("B0 #EDI #BDUT_ADDR 60 81"),
            wait_for_restart(2000),
            drain(500),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 1, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
            comment("Verify: write TK1 with TK1 → ACK"),
            inject_secure_ac(WRITE_TK1, "TK1"),
            expect_secure_ac(WRITE_TK_OK, "TK1", TIMEOUT),
            // ==== (d) FactoryResetKeepIA (erase=0x07) — tool key survives ====
            // 07h clears the key tables, the SIAT, the GO flags, the
            // failures log and the security report, but 03/05/01 §6.3.10
            // leaves the tool key itself "not influenced" — so TK1 still
            // opens the device afterwards. It does wipe the address /
            // association / group-key / GO-flag tables, so the suite
            // teardown issues a `full_reset` to rebuild the default SHM
            // snapshot before handing off to the next suite.
            comment("(d) FactoryResetKeepIA (erase=0x07) — tool key survives"),
            inject("B0 #EDI #BDUT_ADDR 60 80"),
            inject_secure_ac(CONNECTED_RESTART_FRWITHIA, "TK1"),
            expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
            expect_secure_ac(CONNECTED_RESTART_FRWITHIA_RESP, "TK1", TIMEOUT),
            inject("B0 #EDI #BDUT_ADDR 60 C2"),
            inject("B0 #EDI #BDUT_ADDR 60 81"),
            wait_for_restart(2000),
            drain(500),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 1, CHALLENGE_1),
            expect_sync_res_tool("TK1", CHALLENGE_1, None, None, TIMEOUT),
            comment("Verify: write TK1 with TK1 → ACK"),
            inject_secure_ac(WRITE_TK1, "TK1"),
            expect_secure_ac(WRITE_TK_OK, "TK1", TIMEOUT),
            // ==== (e) Local FactoryReset (erase=0x02) — tool key → FDSK ====
            // IA also wiped; re-program via serial-number-keyed
            // `A_IndividualAddressSerialNumber_Write` before the verify.
            comment("(e) Local FactoryReset (erase=0x02) — tool key → FDSK, IA wiped"),
            master_reset(0x02, 2000),
            comment("Re-program BDUT IA via A_IndividualAddressSerialNumber_Write"),
            inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
            wait(200),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "FDSK", 1, CHALLENGE_1),
            expect_sync_res_tool("FDSK", CHALLENGE_1, None, None, TIMEOUT),
            comment("Verify: write PID_TOOL_KEY (value = FDSK) with FDSK → ACK"),
            inject_secure_ac(WRITE_FDSK, "FDSK"),
            expect_secure_ac(WRITE_TK_OK, "FDSK", TIMEOUT),
        ])
        // Case left `tool_key == FDSK` across phases (d) and (e); restore
        // TK1 so 3.8.13.8 (and anything else the suite orders after us)
        // starts from the same TK1 baseline every other case expects.
        .with_teardown(provision_tk1_via_fdsk())
}

fn test_3_8_13_8() -> TestCase {
    // Check usage of the FDSK — direct port of TSS J §3.8.13.8.
    //
    // Procedure:
    //   1. Factory reset (erase 0x02) → tool_key reverts to FDSK.
    //   2. Restore IA + sync tool seq using FDSK.
    //   3. Write PID_TOOL_KEY = TK1, encrypted with FDSK → ACK.
    //   4. Write PID_TOOL_KEY = TK1, encrypted with TK1 → ACK.
    //   5. Try to write PID_TOOL_KEY (to the P2PK2 value), encrypted
    //      with FDSK → DUT must silently drop it (MAC verifies against
    //      the current key, which is now TK1).
    //   6. Verify tool_key is still TK1 by writing PID_TOOL_KEY = TK1
    //      encrypted with TK1 → ACK.
    //
    // `SECURE_FDSK` is distinct from `TK1` in our harness
    // (`harness::secure_stack::SECURE_FDSK`), so step 5's rejection
    // is observable on the wire.

    const CONNECTED_RESTART_FACTORY: &str = "3C 60 #EDI #BDUT_ADDR 03 43 81 02 00";
    const CONNECTED_RESTART_FACTORY_RESP: &str = "3C 60 #BDUT_ADDR #EDI 04 43 A1 00 00 ??";

    // PID_TOOL_KEY writes. Value = TK1 (`00 01 02 ... 0F`).
    const WRITE_TK1: &str = "3C 60 #EDI #BDUT_ADDR 19 01 CE 00 11 00 10 38 01 00 01 \
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01";
    // Attempt to write value = P2PK2 (0x33*16). The particular value
    // doesn't matter — this step expects no response.
    const WRITE_P2PK2: &str = "3C 60 #EDI #BDUT_ADDR 19 01 CE 00 11 00 10 38 01 00 01 \
         33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33";
    const WRITE_TK_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 38 01 00 01 00";

    TestCase::new("3.8.13.8 Check usage of the FDSK").with_steps(vec![
        comment("Factory reset (erase 0x02) → tool key reverts to FDSK"),
        inject("B0 #EDI #BDUT_ADDR 60 80"),
        inject_secure_ac(CONNECTED_RESTART_FACTORY, "TK1"),
        expect("B0 #BDUT_ADDR #EDI 60 C2", TIMEOUT),
        expect_secure_ac(CONNECTED_RESTART_FACTORY_RESP, "TK1", TIMEOUT),
        inject("B0 #EDI #BDUT_ADDR 60 C2"),
        inject("B0 #EDI FF FF 60 81"),
        wait_for_restart(2000),
        drain(500),
        comment("Restore BDUT IA via A_IndividualAddressSerialNumber_Write"),
        inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
        wait(200),
        comment("Sync tool seq using FDSK (the post-reset active tool key)"),
        inject_sync_req_tool("#EDI", "#BDUT_ADDR", "FDSK", 1, CHALLENGE_1),
        expect_sync_res_tool("FDSK", CHALLENGE_1, None, None, TIMEOUT),
        comment("Write PID_TOOL_KEY = TK1 authenticated with FDSK → ACK (response encrypted with TK1)"),
        inject_secure_ac(WRITE_TK1, "FDSK"),
        expect_secure_ac(WRITE_TK_OK, "TK1", TIMEOUT),
        comment("Write PID_TOOL_KEY = TK1 authenticated with TK1 → ACK"),
        inject_secure_ac(WRITE_TK1, "TK1"),
        expect_secure_ac(WRITE_TK_OK, "TK1", TIMEOUT),
        comment(
            "Try to write PID_TOOL_KEY authenticated with FDSK now that \
                 the tool key has been set to TK1 → DUT must reject (no resp)",
        ),
        inject_secure_ac(WRITE_P2PK2, "FDSK"),
        expect_none(1000),
        comment("Verify tool_key is still TK1 (write TK1 with TK1 → ACK)"),
        inject_secure_ac(WRITE_TK1, "TK1"),
        expect_secure_ac(WRITE_TK_OK, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.13.3 Secured PropertyValueWrite sent only authenticated
// ============================================================================
//
// Auth-only write is insufficient for 008/008 policy — it requires A+C.
// Write is denied in both security modes.

fn test_3_8_13_3() -> TestCase {
    TestCase::new("3.8.13.3 Secured PropertyValueWrite sent only authenticated").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Auth-only write tool key → E_ACCESS_DENIED (008 requires A+C)"),
        inject_secure_ao(SECURE_WRITE_TOOL_KEY, "TK1"),
        expect_secure_ao(SECURE_WRITE_TOOL_KEY_DENIED, "TK1", TIMEOUT),
        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Auth-only write tool key → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_WRITE_TOOL_KEY, "TK1"),
        expect_secure_ao(SECURE_WRITE_TOOL_KEY_DENIED, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.13.4 Unsecure PropertyValueWrite
// ============================================================================
//
// Plain (non-secure) write is always denied under 008/008 policy.

fn test_3_8_13_4() -> TestCase {
    TestCase::new("3.8.13.4 Unsecure PropertyValueWrite").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Plain write tool key → E_ACCESS_DENIED"),
        inject(SECURE_WRITE_TOOL_KEY),
        expect(PLAIN_WRITE_TOOL_KEY_DENIED, TIMEOUT),
        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Plain write tool key → E_ACCESS_DENIED"),
        inject(SECURE_WRITE_TOOL_KEY),
        expect(PLAIN_WRITE_TOOL_KEY_DENIED, TIMEOUT),
    ])
}

// ============================================================================
// 3.8.13.5 Secure Property(Ext)ValueRead
// ============================================================================
//
// PID_TOOL_KEY is write-only: all reads are denied with E_ACCESS_DENIED (0xFC)
// regardless of access mode (plain, auth-only, A+C) and regardless of which
// property read service is used (standard 03 D5 or extended 01 CC).
//
// Tests both security mode ON and OFF phases.

fn test_3_8_13_5() -> TestCase {
    TestCase::new("3.8.13.5 Secure Property(Ext)ValueRead").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        // -- Standard property read (03 D5) --
        comment("Plain standard read → denied (write-only)"),
        inject(PLAIN_STD_READ_TOOL_KEY),
        expect(PLAIN_STD_READ_TOOL_KEY_DENIED, TIMEOUT),
        comment("Auth-only standard read → denied"),
        inject_secure_ao(SECURE_STD_READ_TOOL_KEY, "TK1"),
        expect_secure_ao(SECURE_STD_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),
        comment("A+C standard read → denied"),
        inject_secure_ac(SECURE_STD_READ_TOOL_KEY, "TK1"),
        expect_secure_ac(SECURE_STD_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),
        // -- Extended property read (01 CC) --
        comment("Plain extended read → E_ACCESS_DENIED"),
        inject(PLAIN_EXT_READ_TOOL_KEY),
        expect(PLAIN_EXT_READ_TOOL_KEY_DENIED, TIMEOUT),
        comment("Auth-only extended read → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_READ_TOOL_KEY, "TK1"),
        expect_secure_ao(SECURE_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),
        comment("A+C extended read → E_ACCESS_DENIED"),
        inject_secure_ac(SECURE_READ_TOOL_KEY, "TK1"),
        expect_secure_ac(SECURE_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),
        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        // -- Standard property read (03 D5) --
        comment("Plain standard read → denied"),
        inject(PLAIN_STD_READ_TOOL_KEY),
        expect(PLAIN_STD_READ_TOOL_KEY_DENIED, TIMEOUT),
        comment("Auth-only standard read → denied"),
        inject_secure_ao(SECURE_STD_READ_TOOL_KEY, "TK1"),
        expect_secure_ao(SECURE_STD_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),
        comment("A+C standard read → denied"),
        inject_secure_ac(SECURE_STD_READ_TOOL_KEY, "TK1"),
        expect_secure_ac(SECURE_STD_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),
        // -- Extended property read (01 CC) --
        comment("Plain extended read → E_ACCESS_DENIED"),
        inject(PLAIN_EXT_READ_TOOL_KEY),
        expect(PLAIN_EXT_READ_TOOL_KEY_DENIED, TIMEOUT),
        comment("Auth-only extended read → E_ACCESS_DENIED"),
        inject_secure_ao(SECURE_READ_TOOL_KEY, "TK1"),
        expect_secure_ao(SECURE_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),
        comment("A+C extended read → E_ACCESS_DENIED"),
        inject_secure_ac(SECURE_READ_TOOL_KEY, "TK1"),
        expect_secure_ac(SECURE_READ_TOOL_KEY_DENIED, "TK1", TIMEOUT),
    ])
}

// ============================================================================
// 3.8.13.7 PropertyDescriptionRead
// ============================================================================
//
// Access policy 008/008: A+C secure description read succeeds (A+C is always
// allowed). Plain description read returns all-zero (plain NEVER allowed for
// 008/008, regardless of security mode).

fn test_3_8_13_7() -> TestCase {
    TestCase::new("3.8.13.7 PropertyDescriptionRead").with_steps(vec![
        // ==== Security Mode ON ====
        comment("Enable Security Mode"),
        inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(ENABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Secure A+C description read → success (valid descriptor)"),
        inject_secure_ac(SECURE_DESC_READ_PID38, "TK1"),
        expect_secure_ac(SECURE_DESC_READ_PID38_OK, "TK1", TIMEOUT),
        // ==== Security Mode OFF ====
        comment("Disable Security Mode"),
        inject_secure_ac(DISABLE_SECURITY_MODE, "TK1"),
        expect_secure_ac(DISABLE_SECURITY_MODE_RESP, "TK1", TIMEOUT),
        comment("Plain description read → all-zero (plain never allowed for 008/008)"),
        inject(PLAIN_DESC_READ_PID38),
        expect(PLAIN_DESC_READ_PID38_ZERO, TIMEOUT),
    ])
}
