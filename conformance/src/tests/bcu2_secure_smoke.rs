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

    let mut cases = vec![
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
        TestCase::new("B2S-4 ETS programming-mode serial scan is answered").with_steps(vec![
            comment("Programming mode off: the system-network-parameter scan stays silent"),
            set_programming_mode(false),
            inject("AC #EDI 00 00 E6 01 C8 00 00 00 B0 01"),
            expect_none(1500),
            comment("Programming mode on: answer with the provisioned serial number"),
            set_programming_mode(true),
            inject("AC #EDI 00 00 E6 01 C8 00 00 00 B0 01"),
            expect("BC #BDUT_ADDR 00 00 EC 01 C9 00 00 00 B0 01 #SER_NUM", 1500),
            set_programming_mode(false),
        ]),
        TestCase::new("B2S-5 wrong key, sequence zero, and replay are dropped").with_steps(vec![
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

    for code in [0x00, 0x01, 0x07] {
        let load_state = if code == 0x07 { "00" } else { "01" };
        cases.push(
            TestCase::new(format!("B2S-6 local reset {code:02X} preserves tool access"))
                .with_preparation(vec![full_reset(2000)])
                .with_steps(vec![
                    inject_secure_ac("3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 33 00 00 01", "TK1"),
                    expect_secure_ac("3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 33 00 00", "TK1", TIMEOUT),
                    master_reset(code, 2000),
                    wait(1500),
                    inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, CHALLENGE),
                    expect_sync_res_tool("TK1", CHALLENGE, None, None, TIMEOUT),
                    inject_secure_ac("3C 60 #EDI #BDUT_ADDR 08 01 D5 00 11 00 10 33 00 00", "TK1"),
                    expect_secure_ac("3C 60 #BDUT_ADDR #EDI 09 01 D6 00 11 00 10 33 00 00 01", "TK1", TIMEOUT),
                    comment("Only 07h unloads Security IO; basic and confirmed reset preserve it"),
                    inject_secure_ac("3C 60 #EDI #BDUT_ADDR 09 01 CC 00 11 00 10 05 01 00 01", "TK1"),
                    expect_secure_ac(
                        &format!("3C 60 #BDUT_ADDR #EDI 0A 01 CD 00 11 00 10 05 01 00 01 {load_state}"),
                        "TK1",
                        TIMEOUT,
                    ),
                ])
                .with_teardown(vec![full_reset(2000)]),
        );
    }

    cases.push(
        TestCase::new("B2S-7 local reset 02 restores FDSK and unloads the application")
            .with_preparation(vec![full_reset(2000)])
            .with_steps(vec![
                master_reset(0x02, 2000),
                inject_delay("B0 #EDI FF FF 60 80", 200),
                inject("BC #EDI FF FF 65 43 D5 03 05 10 01"),
                expect("B0 FF FF #EDI 60 C2", 0),
                expect("BC FF FF #EDI 66 43 D6 03 05 10 01 00", 400),
                inject_delay("B0 #EDI FF FF 60 C2", 200),
                inject_delay("B0 #EDI FF FF 60 81", 200),
                inject("BC #EDI 00 00 ED 03 DE #SER_NUM #BDUT_ADDR 00 00 00 00"),
                wait(1500),
                inject_sync_req_tool("#EDI", "#BDUT_ADDR", "FDSK", 0, CHALLENGE),
                expect_sync_res_tool("FDSK", CHALLENGE, None, None, TIMEOUT),
                inject_secure_ac("3C 60 #EDI #BDUT_ADDR 08 01 D5 00 11 00 10 33 00 00", "FDSK"),
                expect_secure_ac("3C 60 #BDUT_ADDR #EDI 09 01 D6 00 11 00 10 33 00 00 00", "FDSK", TIMEOUT),
            ])
            .with_teardown(vec![full_reset(2000)]),
    );

    TestSuite::new("BCU2 Secure smoke", variables)
        .bcu2_secure()
        .with_cases(cases)
        .with_teardown(vec![comment("Restore the factory image and sequence store"), full_reset(2000)])
}
