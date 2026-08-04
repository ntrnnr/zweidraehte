//! System 7 **Data Secure** DUT smoke suite.
//!
//! Not a transcription of a certification template — the TSSJ
//! DataSecurity template runs against this DUT through
//! `conformance-eitt` with the `tp1-system7.toml` profile. This suite
//! drives the crossing itself end-to-end through the real engine and
//! DUT process: the things that are specifically *System 7 + Data
//! Secure*, none of which any other suite exercises on this family:
//!
//! - DD0 answering mask 0705h on the secure DUT
//! - the object roster the profile depends on: Security IO at index 5
//!   (`SEC_INTF_OBJ_INDEX = 05`), Group Object Table at 6,
//!   Certification Object at 7
//! - PID_GO_DIAGNOSTICS answered on Object Type 9 — the object System 7
//!   only has *because* it is secure (06 Profiles v02.02.01
//!   §9.2.1.1.1.1)
//! - tool-key secure property access and `S-A_Sync` over the RT8-table
//!   family
//! - a secure group round-trip over the RT8 tables (GO flags → keys →
//!   response security)
//! - erase codes on a secure device: 03h/04h refused as unsupported
//!   (§9.1.2.5.1 marks them `X`), 02h reverting the tool key to the
//!   FDSK with the IA — which on System 7 lives inside the RT8
//!   address-table blob — wiped and re-programmed
//!
//! Frame vocabulary matches the security suites (`#EDI` = tool at
//! 10.15.254, `#BDUT_ADDR` = 1.0.1, keys from `TSSJ_SCT.csv`).

use std::collections::BTreeMap;

use crate::tests::helpers::*;
use crate::tests::security::variables::create_security_variables;
use crate::{TestCase, TestSuite, TestVariable};

/// Default response timeout in milliseconds.
const TIMEOUT: u32 = 3000;

/// A fixed sync challenge; the value is arbitrary, it only has to match
/// between request and expected response.
const CHALLENGE: [u8; 6] = [0xC0, 0xFF, 0xEE, 0x00, 0x07, 0x05];

fn create_test_variables() -> BTreeMap<String, TestVariable> {
    // The security suites' variable set (keys, EDI, BDUT_ADDR, GO
    // addresses) with the System 7 deltas on top.
    let mut vars = create_security_variables();
    vars.insert("SER_NUM".into(), TestVariable::Bytes(vec![0xFE, 0xED, 0x07, 0x05, 0xCA, 0xFE]));
    vars.insert("DD0_RESPONSE".into(), TestVariable::Bytes(vec![0x07, 0x05]));
    vars.insert("SEC_INTF_OBJ_INDEX".into(), TestVariable::Bytes(vec![0x05]));
    vars
}

// ---- Security IO Load State Control (PID 5) ----
// The group-key and GO-flag tables are only evaluated while the Security
// IO's load state machine is Loaded (03/05/01 §6.3.6-8); the factory
// image ships Unloaded, exactly like the System B secure DUT — the TSSJ
// template's own preparation performs this load, and so does this suite.
const LOAD_START_LOADING: &str = "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 01 00 00 00 00 00 00 00 00 00";
const LOAD_START_LOADING_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 05 01 00 01 00";
const LOAD_COMPLETED: &str = "3C 60 #EDI #BDUT_ADDR 13 01 CE 00 11 00 10 05 01 00 01 02 00 00 00 00 00 00 00 00 00";
const LOAD_COMPLETED_OK: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 05 01 00 01 00";

pub fn create_system7_secure_smoke_suite() -> TestSuite {
    let vars = create_test_variables();

    let cases = vec![
        // ====================================================================
        // S7S-1: DD0 answers the System 7 mask on the secure DUT
        // ====================================================================
        TestCase::new("S7S-1 DD0 reads 0705h").with_steps(vec![
            comment("The secure DUT identifies as System 7 TP1 (mask 0705h)"),
            inject_delay("B0 #EDI #BDUT_ADDR 60 80", 200),
            inject("BC #EDI #BDUT_ADDR 61 43 00"),
            expect("B0 #BDUT_ADDR #EDI 60 C2", 0),
            expect("BC #BDUT_ADDR #EDI 63 43 40 07 05", 400),
            inject_delay("B0 #EDI #BDUT_ADDR 60 C2", 200),
            inject_delay("B0 #EDI #BDUT_ADDR 60 81", 200),
        ]),
        // ====================================================================
        // S7S-2: The object roster the TSSJ profile depends on
        // ====================================================================
        TestCase::new("S7S-2 Security IO at 5, GO Table at 6, Certification Object at 7").with_steps(vec![
            comment("A_PropertyValue_Read of PID_OBJECT_TYPE per index; the"),
            comment("indexes are what SEC_INTF_OBJ_INDEX = 05 pins in the profile"),
            inject_delay("B0 #EDI #BDUT_ADDR 60 80", 200),
            comment("Index 5 = Security Interface Object (OT 0011h)"),
            inject("BC #EDI #BDUT_ADDR 65 43 D5 05 01 10 01"),
            expect("B0 #BDUT_ADDR #EDI 60 C2", 0),
            expect("BC #BDUT_ADDR #EDI 67 43 D6 05 01 10 01 00 11", 400),
            inject_delay("B0 #EDI #BDUT_ADDR 60 C2", 200),
            comment("Index 6 = Group Object Table Object (OT 0009h)"),
            inject("BC #EDI #BDUT_ADDR 65 47 D5 06 01 10 01"),
            expect("B0 #BDUT_ADDR #EDI 60 C6", 0),
            expect("BC #BDUT_ADDR #EDI 67 47 D6 06 01 10 01 00 09", 400),
            inject_delay("B0 #EDI #BDUT_ADDR 60 C6", 200),
            comment("Index 7 = Certification Object (OT C351h)"),
            inject("BC #EDI #BDUT_ADDR 65 4B D5 07 01 10 01"),
            expect("B0 #BDUT_ADDR #EDI 60 CA", 0),
            expect("BC #BDUT_ADDR #EDI 67 4B D6 07 01 10 01 C3 51", 400),
            inject_delay("B0 #EDI #BDUT_ADDR 60 CA", 200),
            inject_delay("B0 #EDI #BDUT_ADDR 60 81", 200),
        ]),
        // ====================================================================
        // S7S-3: PID_GO_DIAGNOSTICS lives on Object Type 9
        // ====================================================================
        TestCase::new("S7S-3 GO diagnostics answered on OT 9").with_steps(vec![
            comment("A_FunctionPropertyExtStateRead, OT 0009h instance 1 PID 66:"),
            comment("read GO0's config (GO index 1). Plain works while SM is off."),
            comment("The response payload (config word, type, flags) is the"),
            comment("device's own business here — what this pins is that OT 9"),
            comment("exists and PID 66 dispatches to the diagnostics augment."),
            inject("BC #EDI #BDUT_ADDR 6A 01 D5 00 09 00 10 42 00 00 00 01"),
            expect("3C 60 #BDUT_ADDR #EDI 11 01 D6 00 09 00 10 42 20 00 00 01 ?? ?? ?? ?? ?? ?? ??", TIMEOUT),
        ]),
        // ====================================================================
        // S7S-4: Tool-key secure property access
        // ====================================================================
        TestCase::new("S7S-4 secure reads under TK1").with_steps(vec![
            comment("S-A_Data auth-only: read Security IO PID 1"),
            inject_secure_ao("3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 01 01 00 01", "TK1"),
            expect_secure_ao("3C 60 #BDUT_ADDR #EDI 0B 01 CD 00 11 00 10 01 01 00 01 00 11", "TK1", TIMEOUT),
            comment("S-A_Data auth+conf: same read"),
            inject_secure_ac("3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 01 01 00 01", "TK1"),
            expect_secure_ac("3C 60 #BDUT_ADDR #EDI 0B 01 CD 00 11 00 10 01 01 00 01 00 11", "TK1", TIMEOUT),
        ]),
        // ====================================================================
        // S7S-5: S-A_Sync over the System 7 family
        // ====================================================================
        TestCase::new("S7S-5 S-A_Sync_Req answered").with_steps(vec![
            wait(1500), // Sync rate limit.
            comment("Connectionless P2P sync request under TK1"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE),
            expect_sync_res_tool("TK1", CHALLENGE, None, None, TIMEOUT),
        ]),
        // ====================================================================
        // S7S-6: Secure group round-trip over the RT8 tables
        // ====================================================================
        TestCase::new("S7S-6 secure group read over RT8 tables").with_steps(vec![
            comment("GO_SEC_0 (flags = A only): GroupValue_Read on 1/1/1 under"),
            comment("GK1; the response transmits on 2/2/2 under GK2. The GA →"),
            comment("TSAP resolution runs over the RT8 address table, the GO"),
            comment("flags over the M112 numbering (FIRST_ASAP = 0)."),
            inject_group_ao("BC #EDI 09 01 E1 00 00", "GK1"),
            expect_group_ao("BC #BDUT_ADDR 12 02 E1 00 4?", "GK2", TIMEOUT),
        ]),
        // ====================================================================
        // S7S-7: Erase codes on a secure System 7 device
        // ====================================================================
        TestCase::new("S7S-7 erase codes 03h/04h unsupported; 02h reverts to FDSK").with_steps(vec![
            comment("§9.1.2.5.1 marks ResetIA (03h) and ResetAP (04h) X for"),
            comment("every Data Secure profile — refused as unsupported, not"),
            comment("as access-denied, and nothing resets."),
            inject_delay("B0 #EDI #BDUT_ADDR 60 80", 200),
            inject("B0 #EDI #BDUT_ADDR 63 43 81 03 00"),
            expect("B0 #BDUT_ADDR #EDI 60 C2", 0),
            expect("B0 #BDUT_ADDR #EDI 64 43 A1 02 ?? ??", 400),
            inject_delay("B0 #EDI #BDUT_ADDR 60 C2", 200),
            inject("B0 #EDI #BDUT_ADDR 63 47 81 04 00"),
            expect("B0 #BDUT_ADDR #EDI 60 C6", 0),
            expect("B0 #BDUT_ADDR #EDI 64 47 A1 02 ?? ??", 400),
            inject_delay("B0 #EDI #BDUT_ADDR 60 C6", 200),
            inject_delay("B0 #EDI #BDUT_ADDR 60 81", 200),
            comment("Erase 02h (local master reset): the tool key reverts to"),
            comment("the FDSK and the IA — which rides inside the RT8"),
            comment("address-table blob — is wiped."),
            master_reset(0x02, 2000),
            comment("Re-program the IA via A_IndividualAddressSerialNumber_Write"),
            inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
            wait(200),
            comment("Sync and read under the FDSK — the active key now"),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "FDSK", 1, CHALLENGE),
            expect_sync_res_tool("FDSK", CHALLENGE, None, None, TIMEOUT),
            inject_secure_ac("3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 01 01 00 01", "FDSK"),
            expect_secure_ac("3C 60 #BDUT_ADDR #EDI 0B 01 CD 00 11 00 10 01 01 00 01 00 11", "FDSK", TIMEOUT),
        ]),
    ];

    // 02h wiped the tables and left the tool key at FDSK; hand the next
    // suite a factory-fresh DUT.
    TestSuite::new("System 7 Secure smoke", vars)
        .system7_secure()
        .with_preparation(vec![
            comment("Security IO: Loading → Loaded (keys evaluated only in Loaded)"),
            inject_secure_ac(LOAD_START_LOADING, "TK1"),
            expect_secure_ac(LOAD_START_LOADING_OK, "TK1", TIMEOUT),
            inject_secure_ac(LOAD_COMPLETED, "TK1"),
            expect_secure_ac(LOAD_COMPLETED_OK, "TK1", TIMEOUT),
        ])
        .with_cases(cases)
        .with_teardown(vec![comment("Teardown: rebuild default SHM + respawn"), full_reset(2000)])
}
