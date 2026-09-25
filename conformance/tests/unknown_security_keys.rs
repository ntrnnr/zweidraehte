//! Invalid key names fail locally while later independent cases still execute.
#![cfg(feature = "dut")]

use std::collections::BTreeMap;
use std::process::ExitCode;

use zweidraehte_conformance::engine::{CaseOrder, EngineOptions, run_suites};
use zweidraehte_conformance::harness::DutMode;
use zweidraehte_conformance::logger;
use zweidraehte_conformance::tests::helpers::{expect_secure_ac, inject_secure_ac};
use zweidraehte_conformance::{TestCase, TestSuite};

#[tokio::test]
async fn unknown_key_failure_does_not_abort_the_suite() {
    logger::init(log::LevelFilter::Warn, false);
    let request = "BC AF FE 10 01 61 03 00";
    let suite = TestSuite::new("Unknown security key", BTreeMap::new()).secure().with_cases(vec![
        TestCase::new("misspelled injection key").with_steps(vec![inject_secure_ac(request, "FDSK-typo")]),
        TestCase::new("misspelled expectation key").with_steps(vec![expect_secure_ac(request, "FDSK-typo", 1000)]),
        // The boot fixture has TK1. Prove that the runner continues with
        // an authenticated request/response, not merely an empty passing case.
        TestCase::new("valid exchange after failures").with_steps(vec![
            inject_secure_ac(request, "TK1"),
            expect_secure_ac("3C 60 10 01 AF FE 03 03 40 07 B0", "TK1", 3000),
        ]),
    ]);
    let options = EngineOptions {
        divisor: 1,
        dut_mode: DutMode::SystemBSecure,
        case_filters: Vec::new(),
        case_order: CaseOrder::Independent,
    };
    let summary = run_suites(&[suite], &options).await;
    assert_eq!(summary.tests, 3);
    assert_eq!(summary.failed, 2);
    assert_eq!(summary.passed, 1);
    assert_eq!(summary.blocked + summary.preparation_failed + summary.teardown_failed, 0);
    assert_eq!(summary.exit_code(), ExitCode::FAILURE);
}
