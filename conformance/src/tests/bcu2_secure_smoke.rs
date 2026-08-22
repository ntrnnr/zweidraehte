//! BCU2 Data Secure micro-stack smoke suite.
//!
//! The configuration runner owns the commissioning test: it loads the
//! Security IO tables, enables security mode, and verifies secure group
//! traffic through the real client. This suite instead pins the S-AL boundary
//! against the blocking DUT process, including its fail-closed cases.

use crate::tests::helpers::*;
use crate::tests::security::variables::create_security_variables;
use crate::{SecureParams, SeqSource, TestCase, TestSuite, TestVariable};

const TIMEOUT: u32 = 3000;
const READ_SECURITY_IO_TYPE: &str = "3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 01 01 00 01";
const SECURITY_IO_TYPE_RESPONSE: &str = "3C 60 #BDUT_ADDR #EDI 0B 01 CD 00 11 00 10 01 01 00 01 00 11";
const CHALLENGE: [u8; 6] = [0x00, 0x21, 0xBA, 0xBE, 0x00, 0x01];

pub fn create_bcu2_secure_smoke_suite() -> TestSuite {
    let mut variables = create_security_variables();
    variables.insert("DD0_RESPONSE".into(), TestVariable::Bytes(vec![0x00, 0x21]));

    let cases = vec![
        TestCase::new("B2S-1 DD0 reads 0021h").with_steps(vec![
            comment("The secure micro profile identifies as mask 0021h"),
            inject_delay("B0 #EDI #BDUT_ADDR 60 80", 200),
            inject("BC #EDI #BDUT_ADDR 61 43 00"),
            expect("B0 #BDUT_ADDR #EDI 60 C2", 0),
            expect("BC #BDUT_ADDR #EDI 63 43 40 00 21", 400),
            inject_delay("B0 #EDI #BDUT_ADDR 60 C2", 200),
            inject_delay("B0 #EDI #BDUT_ADDR 60 81", 200),
        ]),
        TestCase::new("B2S-2 secure extended-property reads under TK1").with_steps(vec![
            comment("Authentication-only request and response"),
            inject_secure_ao(READ_SECURITY_IO_TYPE, "TK1"),
            expect_secure_ao(SECURITY_IO_TYPE_RESPONSE, "TK1", TIMEOUT),
            comment("Authentication plus confidentiality request and response"),
            inject_secure_ac(READ_SECURITY_IO_TYPE, "TK1"),
            expect_secure_ac(SECURITY_IO_TYPE_RESPONSE, "TK1", TIMEOUT),
        ]),
        TestCase::new("B2S-3 S-A_Sync_Req is answered").with_steps(vec![
            wait(1500),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE),
            expect_sync_res_tool("TK1", CHALLENGE, None, None, TIMEOUT),
        ]),
        TestCase::new("B2S-4 wrong key, sequence zero, and replay are dropped").with_steps(vec![
            comment("A frame protected by an unknown key fails authentication"),
            inject_secure_ac_wrongkey(READ_SECURITY_IO_TYPE),
            expect_none(TIMEOUT),
            comment("Sequence number zero is never valid"),
            inject_secure_ac_seq0(READ_SECURITY_IO_TYPE, "TK1"),
            expect_none(TIMEOUT),
            comment("A valid high sequence advances the durable replay floor"),
            inject_secure(READ_SECURITY_IO_TYPE, {
                let mut params = SecureParams::tool_auth_conf("TK1");
                params.seq_source = SeqSource::Fixed(100);
                params
            }),
            expect_secure_ac(SECURITY_IO_TYPE_RESPONSE, "TK1", TIMEOUT),
            comment("Repeating that sequence is a replay and stays silent"),
            inject_secure(READ_SECURITY_IO_TYPE, {
                let mut params = SecureParams::tool_auth_conf("TK1");
                params.seq_source = SeqSource::Fixed(100);
                params
            }),
            expect_none(TIMEOUT),
        ]),
    ];

    TestSuite::new("BCU2 Secure smoke", variables)
        .bcu2_secure()
        .with_preparation(provision_tk1_via_fdsk())
        .with_cases(cases)
        .with_teardown(vec![comment("Restore the factory image and sequence store"), full_reset(2000)])
}
