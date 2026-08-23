//! Focused crossing tests for polling System 7 plus Data Secure.
//!
//! The ordinary micro System 7 suite already owns mask-level management,
//! RT8 tables, and TL Style 3. These cases pin only behavior introduced or
//! altered by the secure composition.

use crate::tests::helpers::*;
use crate::tests::security::variables::create_security_variables;
use crate::{SecureParams, SeqSource, TestCase, TestSuite, TestVariable};

const TIMEOUT: u32 = 3000;
const READ_DD0: &str = "BC #EDI #BDUT_ADDR 61 03 00";
const DD0_RESPONSE: &str = "3C 60 #BDUT_ADDR #EDI 03 03 40 07 05";
const READ_SECURITY_IO_TYPE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 01 01 00 01";
const SECURITY_IO_TYPE_RESPONSE: &str = "3C 60 #BDUT_ADDR #EDI 0B 01 CD 00 11 00 10 01 01 00 01 00 11";
const SECURITY_IO_TYPE_DENIED: &str = "3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 01 00 00 01 FC";
const READ_GO_TABLE_TYPE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 09 00 10 01 01 00 01";
const GO_TABLE_TYPE_RESPONSE: &str = "3C 60 #BDUT_ADDR #EDI 0B 01 CD 00 09 00 10 01 01 00 01 00 09";
const ENABLE_SECURITY_MODE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01";
const ENABLE_SECURITY_MODE_RESPONSE: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00";
const GV_READ_111: &str = "BC #EDI 09 01 E1 00 00";
const GV_RESPONSE_222: &str = "BC #BDUT_ADDR 12 02 E1 00 40";
const GV_READ_333: &str = "BC #EDI 1B 03 E1 00 00";
const GV_RESPONSE_444: &str = "BC #BDUT_ADDR 24 04 E1 00 40";
const CHALLENGE: [u8; 6] = [0x00, 0x07, 0x05, 0xBA, 0xBE, 0x01];

pub fn create_micro_system7_secure_smoke_suite() -> TestSuite {
    let mut variables = create_security_variables();
    variables.insert("DD0_RESPONSE".into(), TestVariable::Bytes(vec![0x07, 0x05]));
    variables.insert("SER_NUM".into(), TestVariable::Bytes(vec![0xFE, 0xED, 0x07, 0x05, 0xBE, 0xEF]));
    variables.insert("SEC_INTF_OBJ_INDEX".into(), TestVariable::Bytes(vec![0x05]));

    let cases = vec![
        TestCase::new("MS7S-1 plain DD0 masks and secure DD0 reads 0705h").with_steps(vec![
            inject_delay("B0 #EDI #BDUT_ADDR 60 80", 200),
            inject("BC #EDI #BDUT_ADDR 61 43 00"),
            expect("B0 #BDUT_ADDR #EDI 60 C2", 0),
            expect("BC #BDUT_ADDR #EDI 63 43 40 FF FF", 400),
            inject_delay("B0 #EDI #BDUT_ADDR 60 C2", 200),
            inject_delay("B0 #EDI #BDUT_ADDR 60 81", 200),
            inject_secure_ac(READ_DD0, "TK1"),
            expect_secure_ac(DD0_RESPONSE, "TK1", TIMEOUT),
        ]),
        TestCase::new("MS7S-2 Security IO at 5 and GO Table at 6").with_steps(vec![
            comment("The secure profile appends OT17 then OT9 to System 7's five base objects"),
            inject_secure_ac(READ_SECURITY_IO_TYPE, "TK1"),
            expect_secure_ac(SECURITY_IO_TYPE_RESPONSE, "TK1", TIMEOUT),
            inject_secure_ac(READ_GO_TABLE_TYPE, "TK1"),
            expect_secure_ac(GO_TABLE_TYPE_RESPONSE, "TK1", TIMEOUT),
        ]),
        TestCase::new("MS7S-3 Object Type enforces A+C while Security Mode is on").with_steps(vec![
            inject_secure_ao(READ_SECURITY_IO_TYPE, "TK1"),
            expect_secure_ao(SECURITY_IO_TYPE_DENIED, "TK1", TIMEOUT),
            inject_secure_ac(READ_SECURITY_IO_TYPE, "TK1"),
            expect_secure_ac(SECURITY_IO_TYPE_RESPONSE, "TK1", TIMEOUT),
        ]),
        TestCase::new("MS7S-4 S-A_Sync_Req is answered").with_steps(vec![
            wait(1500),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE),
            expect_sync_res_tool("TK1", CHALLENGE, None, None, TIMEOUT),
        ]),
        TestCase::new("MS7S-5 secure group reads follow RT8 sending associations").with_steps(vec![
            comment("Auth-only read on 1/1/1 answers through GO0's first association on 2/2/2"),
            inject_group_ao(GV_READ_111, "GK1"),
            expect_group_ao(GV_RESPONSE_222, "GK2", TIMEOUT),
            comment("Auth+conf read on 3/3/3 answers through GO1's first association on 4/4/4"),
            inject_group_ac(GV_READ_333, "GK3"),
            expect_group_ac(GV_RESPONSE_444, "GK4", TIMEOUT),
        ]),
        TestCase::new("MS7S-6 wrong key, sequence zero, and replay are dropped").with_steps(vec![
            inject_secure_ac_wrongkey(READ_SECURITY_IO_TYPE),
            expect_none(TIMEOUT),
            inject_secure_ac_seq0(READ_SECURITY_IO_TYPE, "TK1"),
            expect_none(TIMEOUT),
            inject_secure(READ_SECURITY_IO_TYPE, {
                let mut params = SecureParams::tool_auth_conf("TK1");
                params.seq_source = SeqSource::Fixed(100);
                params
            }),
            expect_secure_ac(SECURITY_IO_TYPE_RESPONSE, "TK1", TIMEOUT),
            inject_secure(READ_SECURITY_IO_TYPE, {
                let mut params = SecureParams::tool_auth_conf("TK1");
                params.seq_source = SeqSource::Fixed(100);
                params
            }),
            expect_none(TIMEOUT),
        ]),
    ];

    TestSuite::new("Micro System 7 Secure smoke", variables)
        .micro_system7_secure()
        .with_preparation(vec![
            comment("The EITT-compatible boot image starts with Security Mode off"),
            inject_secure_ac(ENABLE_SECURITY_MODE, "TK1"),
            expect_secure_ac(ENABLE_SECURITY_MODE_RESPONSE, "TK1", TIMEOUT),
        ])
        .with_cases(cases)
        .with_teardown(vec![comment("Restore factory configuration and sequence state"), full_reset(2000)])
}
