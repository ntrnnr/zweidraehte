//! Exercise setup and cleanup failure through the real engine and DUT, without vendor XML.
#![cfg(feature = "dut")]

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::Once;

use zweidraehte_conformance::engine::{CaseOrder, EngineOptions, run_suites};
use zweidraehte_conformance::harness::DutMode;
use zweidraehte_conformance::logger;
use zweidraehte_conformance::tests::helpers::{expect, inject, set_programming_mode};
use zweidraehte_conformance::{TestCase, TestSuite};

static LOGGER: Once = Once::new();

#[tokio::test]
async fn failed_setup_blocks_selected_cases_and_still_cleans_up() {
    LOGGER.call_once(|| logger::init(log::LevelFilter::Warn, false));

    let failing = TestSuite::new("Broken setup", BTreeMap::new())
        .with_preparation(vec![
            set_programming_mode(true),
            inject("BC AF FE 10 01 61 03 00"),
            // The plain System B fixture answers 07B0h, so this expect fails.
            expect("BC 10 01 AF FE 63 03 40 FF FF", 500),
        ])
        .with_cases(vec![
            TestCase::new("selected first"),
            TestCase::new("unselected"),
            TestCase::new("selected second"),
        ])
        .with_teardown(vec![set_programming_mode(false)]);

    // This case passes only if the failed suite's teardown actually ran.
    let recovery =
        TestSuite::new("Recovery", BTreeMap::new()).with_cases(vec![TestCase::new("selected recovery").with_steps(
            vec![inject("BC AF FE 10 01 65 03 D5 00 36 10 01"), expect("BC 10 01 AF FE 66 03 D6 00 36 10 01 00", 500)],
        )]);
    let excluded = TestSuite::new("Excluded", BTreeMap::new()).with_preparation(vec![inject("#MISSING")]);
    let opts = EngineOptions {
        divisor: 1,
        dut_mode: DutMode::SystemB,
        case_filters: vec!["selected ".into()],
        case_order: CaseOrder::Independent,
    };

    let summary = run_suites(&[failing, recovery, excluded], &opts).await;

    assert_eq!(summary.suites, 2);
    assert_eq!(summary.tests, 3);
    assert_eq!(summary.passed, 1);
    assert_eq!(summary.failed, 0, "the only failure was suite preparation");
    assert_eq!(summary.blocked, 2, "unselected cases do not count as blocked");
    assert_eq!(summary.preparation_failed, 1);
    assert_eq!(summary.exit_code(), ExitCode::FAILURE);
}

#[tokio::test]
async fn invalid_preparation_fails_even_without_cases() {
    LOGGER.call_once(|| logger::init(log::LevelFilter::Warn, false));

    let invalid = TestSuite::new("Invalid setup", BTreeMap::new()).with_preparation(vec![inject("#MISSING")]);
    let opts = EngineOptions {
        divisor: 1,
        dut_mode: DutMode::SystemB,
        case_filters: Vec::new(),
        case_order: CaseOrder::Independent,
    };

    let summary = run_suites(&[invalid], &opts).await;

    assert_eq!(summary.suites, 1);
    assert_eq!(summary.tests, 0);
    assert_eq!(summary.passed, 0);
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.blocked, 0);
    assert_eq!(summary.preparation_failed, 1);
    assert_eq!(summary.exit_code(), ExitCode::FAILURE);
}

#[tokio::test]
async fn sequential_failures_block_cases_within_and_across_suites() {
    LOGGER.call_once(|| logger::init(log::LevelFilter::Warn, false));
    for failure_in_setup in [false, true] {
        let mut first = TestSuite::new("Provisioning", BTreeMap::new()).with_cases(vec![
            TestCase::new("prerequisite").with_steps(vec![inject("#MISSING")]),
            TestCase::new("depends on prerequisite"),
        ]);
        if failure_in_setup {
            first.preparation = vec![inject("#MISSING")];
        }
        let next = TestSuite::new("Later suite", BTreeMap::new()).with_cases(vec![TestCase::new("target")]);
        let opts = EngineOptions {
            divisor: 1,
            dut_mode: DutMode::SystemB,
            case_filters: vec!["target".into()],
            case_order: CaseOrder::Sequential,
        };

        let summary = run_suites(&[first, next], &opts).await;

        assert_eq!(summary.tests, 3, "the filter retains both prerequisites");
        assert_eq!(summary.passed, 0, "empty dependent cases must not appear to pass");
        assert_eq!(summary.failed, usize::from(!failure_in_setup));
        assert_eq!(summary.preparation_failed, usize::from(failure_in_setup));
        assert_eq!(summary.blocked, if failure_in_setup { 3 } else { 2 });
        assert_eq!(summary.exit_code(), ExitCode::FAILURE);
    }
}

#[tokio::test]
async fn sequential_selection_preserves_setup_state_and_omits_the_tail() {
    LOGGER.call_once(|| logger::init(log::LevelFilter::Warn, false));
    let setup = TestSuite::new("Setup", BTreeMap::new())
        .with_cases(vec![TestCase::new("enable programming").with_steps(vec![set_programming_mode(true)])]);
    let selected = TestSuite::new("Readback", BTreeMap::new()).with_cases(vec![
        TestCase::new("target").with_steps(vec![
            inject("BC AF FE 10 01 65 03 D5 00 36 10 01"),
            expect("BC 10 01 AF FE 66 03 D6 00 36 10 01 01", 500),
        ]),
        TestCase::new("excluded tail").with_steps(vec![inject("#MISSING")]),
    ]);
    let opts = EngineOptions {
        divisor: 1,
        dut_mode: DutMode::SystemB,
        case_filters: vec!["target".into()],
        case_order: CaseOrder::Sequential,
    };

    let summary = run_suites(&[setup, selected], &opts).await;

    assert_eq!(summary.tests, 2);
    assert_eq!(summary.passed, 2);
    assert_eq!(summary.blocked, 0);
    assert_eq!(summary.exit_code(), ExitCode::SUCCESS);
}

#[tokio::test]
async fn teardown_failures_fail_the_run_but_finish_cleanup() {
    LOGGER.call_once(|| logger::init(log::LevelFilter::Warn, false));

    for suite_cleanup in [false, true] {
        for invalid_template in [false, true] {
            let teardown = vec![
                if invalid_template {
                    inject("#MISSING")
                } else {
                    // No request was sent, so this expectation must time out.
                    expect("BC 10 01 AF FE 63 03 40 07 B0", 50)
                },
                set_programming_mode(false),
            ];
            let mut failing =
                TestSuite::new("Failed cleanup", BTreeMap::new()).with_preparation(vec![set_programming_mode(true)]);
            if suite_cleanup {
                // Suite teardown must fail the run even without any cases.
                failing.teardown = teardown;
            } else {
                failing.cases = vec![TestCase::new("case cleanup").with_teardown(teardown)];
            }

            // Read back real DUT state: stopping at the failed cleanup step
            // would leave programming mode enabled and this case would fail.
            let recovery = TestSuite::new("Recovery", BTreeMap::new()).with_cases(vec![
                TestCase::new("cleanup finished").with_steps(vec![
                    inject("BC AF FE 10 01 65 03 D5 00 36 10 01"),
                    expect("BC 10 01 AF FE 66 03 D6 00 36 10 01 00", 500),
                ]),
            ]);
            let opts = EngineOptions {
                divisor: 1,
                dut_mode: DutMode::SystemB,
                case_filters: Vec::new(),
                case_order: CaseOrder::Independent,
            };

            let summary = run_suites(&[failing, recovery], &opts).await;

            assert_eq!(summary.tests, 1 + usize::from(!suite_cleanup));
            assert_eq!(summary.passed, 1, "remaining cleanup steps must restore DUT state");
            assert_eq!(summary.failed, usize::from(!suite_cleanup));
            assert_eq!(summary.preparation_failed, 0);
            assert_eq!(summary.teardown_failed, usize::from(suite_cleanup));
            assert_eq!(summary.blocked, 0);
            assert_eq!(summary.exit_code(), ExitCode::FAILURE);
        }
    }
}

#[tokio::test]
async fn sequential_teardown_failure_blocks_dependent_cases() {
    LOGGER.call_once(|| logger::init(log::LevelFilter::Warn, false));

    for suite_cleanup in [false, true] {
        let mut first = TestSuite::new("Provisioning", BTreeMap::new())
            .with_cases(vec![TestCase::new("prerequisite"), TestCase::new("depends on prerequisite")]);
        if suite_cleanup {
            first.teardown = vec![inject("#MISSING")];
        } else {
            first.cases[0].teardown = vec![inject("#MISSING")];
        }
        let next = TestSuite::new("Later suite", BTreeMap::new()).with_cases(vec![TestCase::new("target")]);
        let opts = EngineOptions {
            divisor: 1,
            dut_mode: DutMode::SystemB,
            case_filters: vec!["target".into()],
            case_order: CaseOrder::Sequential,
        };

        let summary = run_suites(&[first, next], &opts).await;

        assert_eq!(summary.tests, 3);
        assert_eq!(summary.passed, if suite_cleanup { 2 } else { 0 });
        assert_eq!(summary.failed, usize::from(!suite_cleanup));
        assert_eq!(summary.preparation_failed, 0);
        assert_eq!(summary.teardown_failed, usize::from(suite_cleanup));
        assert_eq!(summary.blocked, if suite_cleanup { 1 } else { 2 });
        assert_eq!(summary.exit_code(), ExitCode::FAILURE);
    }
}
