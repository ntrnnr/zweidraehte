//! IPC ingress must follow the device's live address, including changes made
//! through broadcast commissioning telegrams, for both TP1 frame formats.
#![cfg(feature = "dut")]

use zweidraehte_conformance::engine::{CaseOrder, EngineOptions, run_suites};
use zweidraehte_conformance::harness::DutMode;
use zweidraehte_conformance::logger;
use zweidraehte_conformance::tests::helpers::{expect, expect_none, inject, set_programming_mode};
use zweidraehte_conformance::tests::management::create_test_variables;
use zweidraehte_conformance::{TestCase, TestSuite};

#[tokio::test]
async fn filtering_follows_broadcast_address_assignment() {
    logger::init(log::LevelFilter::Warn, false);
    for dut_mode in [DutMode::SystemB, DutMode::System7] {
        let mut steps = Vec::new();
        for (header, length) in [("BC", "65"), ("3C 60", "05")] {
            steps.extend([
                inject(&format!("{header} #EDI #BDUT {length} 03 D5 00 36 10 01")),
                expect("BC #BDUT #EDI 66 03 D6 00 36 10 01 00", 1000),
                inject(&format!("{header} #EDI 12 03 {length} 03 D5 00 36 10 01")),
                expect_none(100),
            ]);
        }

        // A checker built from an address snapshot would keep admitting the old
        // IA and reject the new one after this broadcast write.
        steps.extend([
            set_programming_mode(true),
            inject("BC #EDI 00 00 E3 00 C0 12 03"),
            expect_none(100),
            inject("BC #EDI 00 00 E1 01 00"),
            expect("BC 12 03 00 00 E1 01 40", 1000),
        ]);
        for (header, length) in [("BC", "65"), ("3C 60", "05")] {
            steps.extend([
                inject(&format!("{header} #EDI #BDUT {length} 03 D5 00 36 10 01")),
                expect_none(100),
                inject(&format!("{header} #EDI 12 03 {length} 03 D5 00 36 10 01")),
                expect("BC 12 03 #EDI 66 03 D6 00 36 10 01 01", 1000),
            ]);
        }

        let suite = TestSuite::new("IPC address filtering", create_test_variables())
            .with_cases(vec![TestCase::new("live individual address").with_steps(steps)]);
        let options =
            EngineOptions { divisor: 1, dut_mode, case_filters: Vec::new(), case_order: CaseOrder::Independent };
        let summary = run_suites(&[suite], &options).await;

        assert_eq!(summary.tests, 1, "{dut_mode:?}");
        assert_eq!(summary.passed, 1, "{dut_mode:?}");
        assert_eq!(summary.failed, 0, "{dut_mode:?}");
        assert_eq!(summary.preparation_failed, 0, "{dut_mode:?}");
        assert_eq!(summary.blocked, 0, "{dut_mode:?}");
    }
}
