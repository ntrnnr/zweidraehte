//! Validate sync injection inputs and rejection of malformed frames by the DUT.
#![cfg(feature = "dut")]

use std::collections::BTreeMap;

use zweidraehte_conformance::engine::{CaseOrder, EngineOptions, run_suites};
use zweidraehte_conformance::harness::DutMode;
use zweidraehte_conformance::logger;
use zweidraehte_conformance::tests::helpers::{expect_none, expect_sync_res_tool, inject_sync_req_tool, wait};
use zweidraehte_conformance::tests::security::crypto::wrap_sync_req;
use zweidraehte_conformance::tests::security::section_3_3::create_section_3_3_suite;
use zweidraehte_conformance::tests::security::variables::TK1;
use zweidraehte_conformance::{
    InvalidSecurityParam, SeqSource, SyncReqParams, SyncResInject, Telegram, TestCase, TestStep, TestSuite,
    TestVariable,
};
use zweidraehte_proto::encoding::tp1::knx_to_tp1_message_no_checksum;

#[tokio::test]
async fn full_stacks_reject_overlong_sync_requests_with_a_valid_mac() {
    logger::init(log::LevelFilter::Warn, false);
    let challenge = [1, 2, 3, 4, 5, 6];
    // These addresses and TK1 belong to the shared security fixture. Repeat
    // the genuine MAC so taking the final four bytes still authenticates;
    // rejection must come from the length check rather than a MAC mismatch.
    let mut frame =
        wrap_sync_req(0x3C, 0xAFFE, 0x1001, 0x60, 0, &TK1, 0x92, &[0, 0, 0, 0, 3, 0xE8], &[0; 6], &challenge);
    frame.extend_from_within(frame.len() - 4..);
    let telegram = Telegram::from_bytes(&knx_to_tp1_message_no_checksum(frame));

    for mode in [DutMode::SystemBSecure, DutMode::System7Secure] {
        let mut suite = create_section_3_3_suite();
        if mode == DutMode::System7Secure {
            suite = suite.system7_secure();
        }
        suite.cases = vec![TestCase::new("overlong authenticated sync request").with_steps(vec![
            // Establish a known counter above the preparation traffic, then
            // prove that the malformed request cannot advance it to 1000.
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 100, challenge),
            expect_sync_res_tool("TK1", challenge, None, Some(100), 3000),
            wait(1500),
            TestStep::Inject { telegram: telegram.clone(), delay_before_ms: 0 },
            expect_none(300),
            wait(1500),
            inject_sync_req_tool("#EDI", "#BDUT_ADDR", "TK1", 0, challenge),
            expect_sync_res_tool("TK1", challenge, None, Some(100), 3000),
        ])];
        let options =
            EngineOptions { divisor: 1, dut_mode: mode, case_filters: Vec::new(), case_order: CaseOrder::Independent };
        let summary = run_suites(&[suite], &options).await;
        assert_eq!(summary.preparation_failed, 0, "{mode:?}");
        assert_eq!(summary.teardown_failed, 0, "{mode:?}");
        assert_eq!(summary.blocked, 0, "{mode:?}");
        assert_eq!(summary.failed, 0, "{mode:?}");
        assert_eq!(summary.passed, 1, "{mode:?}");
    }
}

fn injection_steps(src: &str, dst: &str) -> [TestStep; 3] {
    let request = SyncReqParams {
        key_name: "FDSK".into(),
        tool_access: true,
        system_broadcast: false,
        src_template: src.into(),
        dst_template: dst.into(),
        npdu_byte: 0x60,
        ctrl_byte: 0x3C,
        seq_local: SeqSource::Fixed(1),
        serial_number: [0; 6],
        challenge: [1; 6],
        tpci_high: 0,
    };
    [
        TestStep::InjectSyncReq { sync_params: request.clone(), delay_before_ms: 0 },
        TestStep::InjectSyncReqInvalid {
            sync_params: request,
            invalid: InvalidSecurityParam::InvalidMac([0; 4]),
            delay_before_ms: 0,
        },
        TestStep::InjectSyncRes {
            params: SyncResInject {
                key_name: "FDSK".into(),
                tool_access: true,
                system_broadcast: false,
                src_template: src.into(),
                dst_template: dst.into(),
                seq_nr_remote: 1,
                seq_nr_local: 1,
                challenge: [1; 6],
                ctrl_byte: 0x3C,
                npdu_byte: 0x60,
                tpci_high: 0,
            },
            delay_before_ms: 0,
        },
    ]
}

#[tokio::test]
async fn every_sync_injection_rejects_bad_addresses_but_accepts_explicit_zero() {
    logger::init(log::LevelFilter::Warn, false);
    let variables = BTreeMap::from([
        ("PEER".into(), TestVariable::Bytes(vec![0xAF, 0xFE])),
        ("DUT".into(), TestVariable::Bytes(vec![0x10, 0x01])),
        ("SHORT".into(), TestVariable::Bytes(vec![0x10])),
        ("LONG".into(), TestVariable::Bytes(vec![0x10, 0, 1])),
    ]);
    let mut invalid = Vec::new();
    for address in ["#MISSING", "", "12", "12 34 56", "?? ??", "GG 00", "#SHORT", "#LONG"] {
        for (src, dst) in [(address, "#DUT"), ("#PEER", address)] {
            for (kind, step) in injection_steps(src, dst).into_iter().enumerate() {
                invalid.push(
                    TestCase::new(format!("kind {kind}, source {src:?}, destination {dst:?}")).with_steps(vec![step]),
                );
            }
        }
    }
    let invalid_count = invalid.len();
    let options = EngineOptions {
        divisor: 1,
        dut_mode: DutMode::SystemBSecure,
        case_filters: Vec::new(),
        case_order: CaseOrder::Independent,
    };
    let summary = run_suites(
        &[TestSuite::new("Invalid sync addresses", variables.clone()).secure().with_cases(invalid)],
        &options,
    )
    .await;
    assert_eq!(summary.failed, invalid_count);
    assert_eq!(summary.passed, 0);
    assert_eq!(summary.blocked, 0);
    assert_eq!(summary.preparation_failed, 0);

    // Explicit zero remains legal test input, including for broadcast and
    // protocol negatives. Only unresolved or incorrectly sized values fail.
    let mut valid = Vec::new();
    for (src, dst) in [("#PEER", "#DUT"), ("AF FE", "10 01"), ("00 00", "10 01"), ("AF FE", "00 00")] {
        for (kind, step) in injection_steps(src, dst).into_iter().enumerate() {
            valid.push(TestCase::new(format!("kind {kind}, source {src}, destination {dst}")).with_steps(vec![step]));
        }
    }
    let valid_count = valid.len();
    let summary =
        run_suites(&[TestSuite::new("Valid sync addresses", variables).secure().with_cases(valid)], &options).await;
    assert_eq!(summary.passed, valid_count);
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.blocked, 0);
    assert_eq!(summary.preparation_failed, 0);
}
