//! EITT's network, transport and data-security templates contain no nonzero
//! EFF cases. Exercise reserved and unsupported LTE formats on actual DUTs.
#![cfg(feature = "dut")]

use zweidraehte_conformance::engine::{CaseOrder, EngineOptions, run_suites};
use zweidraehte_conformance::harness::DutMode;
use zweidraehte_conformance::logger;
use zweidraehte_conformance::tests::helpers::{
    expect, expect_none, expect_secure_ac, inject, inject_secure_ac, set_programming_mode,
};
use zweidraehte_conformance::tests::management::create_test_variables;
use zweidraehte_conformance::tests::security::crypto::{wrap_secure, wrap_sync_req};
use zweidraehte_conformance::tests::security::section_3_3::create_section_3_3_suite;
use zweidraehte_conformance::tests::security::variables::{TK1, create_security_context};
use zweidraehte_conformance::{SecureParams, SeqSource, Telegram, TestCase, TestStep, TestSuite};
use zweidraehte_proto::encoding::tp1::knx_to_tp1_message_no_checksum;

#[tokio::test]
async fn unsupported_formats_never_reach_plain_handlers() {
    logger::init(log::LevelFilter::Warn, false);
    for dut_mode in [DutMode::SystemB, DutMode::System7, DutMode::MicroSystem7, DutMode::MicroSystem7Secure] {
        let mut steps = vec![set_programming_mode(true)];
        for eff in 1..16 {
            steps.extend([
                // Individual management and broadcast address discovery both
                // used to interpret these formats as ordinary addressing.
                inject(&format!("3C {:02X} #EDI #BDUT 05 03 D5 00 36 10 01", 0x60 | eff)),
                expect_none(100),
                inject(&format!("3C {:02X} #EDI 00 00 01 01 00", 0xE0 | eff)),
                expect_none(100),
            ]);
        }
        steps.extend([
            inject("BC #EDI #BDUT 65 03 D5 00 36 10 01"),
            expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 01", 1000),
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC #BDUT 00 00 E1 01 40", 1000),
        ]);
        // The plain micro fixture is a standard-frame composition; its
        // secure variant and both full stacks also accept ordinary extended
        // frames. Rejection must depend on EFF, not just the extended flag.
        if dut_mode != DutMode::MicroSystem7 {
            steps.extend([inject("3C E0 #EDI 00 00 01 01 00"), expect("BC #BDUT 00 00 E1 01 40", 1000)]);
        }
        let suite = TestSuite::new("Unsupported frame formats", create_test_variables())
            .with_cases(vec![TestCase::new("plain ingress").with_steps(steps)]);
        let options =
            EngineOptions { divisor: 1, dut_mode, case_filters: Vec::new(), case_order: CaseOrder::Independent };
        let summary = run_suites(&[suite], &options).await;
        assert_eq!(summary.passed, 1, "{dut_mode:?}: {summary:?}");
        assert_eq!(summary.failed + summary.blocked + summary.preparation_failed + summary.teardown_failed, 0);
    }
}

#[tokio::test]
async fn unsupported_formats_are_ignored_even_with_a_valid_mac() {
    logger::init(log::LevelFilter::Warn, false);
    for dut_mode in [DutMode::SystemBSecure, DutMode::System7Secure] {
        let mut suite = create_section_3_3_suite();
        if dut_mode == DutMode::System7Secure {
            suite = suite.system7_secure();
        }
        let mut steps = vec![
            inject_secure_ac("3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 37 00 00 00", "TK1"),
            expect_secure_ac("3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 00 00", "TK1", 3000),
        ];
        let mut params = SecureParams::tool_auth_conf("TK1");
        params.seq_source = SeqSource::Fixed(0x010203040506);
        for eff in 1..16 {
            let sync =
                wrap_sync_req(0x3C, 0xAFFE, 0x1001, 0x60 | eff, 0, &TK1, 0x92, &[1, 2, 3, 4, 5, 6], &[0; 6], &[7; 6]);
            let plain = [0x3C, 0xAF, 0xFE, 0x10, 0x01, 0x60 | eff, 0x01, 0xCC, 0, 0x11, 0, 0x10, 1, 1, 0, 1];
            let data = wrap_secure(&plain, &params, &mut create_security_context());
            for frame in [sync, data] {
                steps.extend([
                    TestStep::Inject {
                        telegram: Telegram::from_bytes(&knx_to_tp1_message_no_checksum(frame)),
                        delay_before_ms: 0,
                    },
                    expect_none(100),
                ]);
            }
        }
        // A normal, lower-sequence request must still work and no security
        // error may have been logged: rejection happens before the S-AL.
        steps.extend([
            inject_secure_ac("3C 60 #EDI #BDUT_ADDR 09 01 D5 00 11 00 10 37 00 00 00", "TK1"),
            expect_secure_ac(
                "3C 60 #BDUT_ADDR #EDI 11 01 D6 00 11 00 10 37 00 00 00 00 00 00 00 00 00 00 00",
                "TK1",
                3000,
            ),
        ]);
        suite.cases = vec![TestCase::new("secure ingress").with_steps(steps)];
        let options =
            EngineOptions { divisor: 1, dut_mode, case_filters: Vec::new(), case_order: CaseOrder::Independent };
        let summary = run_suites(&[suite], &options).await;
        assert_eq!(summary.passed, 1, "{dut_mode:?}: {summary:?}");
        assert_eq!(summary.failed + summary.blocked + summary.preparation_failed + summary.teardown_failed, 0);
    }
}
