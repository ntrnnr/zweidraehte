//! Malformed injection addresses must fail the step before they reach the DUT.
#![cfg(feature = "dut")]

use std::collections::BTreeMap;

use zweidraehte_conformance::engine::{CaseOrder, EngineOptions, run_suites};
use zweidraehte_conformance::harness::DutMode;
use zweidraehte_conformance::logger;
use zweidraehte_conformance::{
    InvalidSecurityParam, SeqSource, SyncReqParams, SyncResInject, TestCase, TestStep, TestSuite, TestVariable,
};

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
