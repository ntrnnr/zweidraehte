//! The local reset IPC command must persist erased state, not reinstall the
//! commissioned conformance fixture. FullReset is the explicit fixture restore.
#![cfg(feature = "dut")]

use zweidraehte_conformance::engine::{CaseOrder, EngineOptions, run_suites};
use zweidraehte_conformance::harness::DutMode;
use zweidraehte_conformance::logger;
use zweidraehte_conformance::tests::helpers::{
    expect, expect_none, expect_secure_ac, full_reset, inject, inject_secure_ac, master_reset, power_cycle,
    set_programming_mode,
};
use zweidraehte_conformance::tests::security::variables::create_security_variables;
use zweidraehte_conformance::{TestCase, TestSuite};

#[tokio::test]
async fn local_reset_codes_survive_respawn_without_reloading_the_application() {
    logger::init(log::LevelFilter::Warn, false);
    for mode in [DutMode::MicroSystem7, DutMode::MicroSystem7Secure] {
        let mut cases = Vec::new();
        // 00h is a reserved erase code (03/05/02 §3.7.1.2.3 Table 4); the
        // restart that erases nothing is the confirmed restart, 01h.
        for code in [1, 2, 7] {
            let erased = matches!(code, 2 | 7);
            let ia = if code == 2 { "FF FF" } else { "12 34" };
            let key = if code == 2 { "FDSK" } else { "TK1" };
            let mut steps = vec![
                full_reset(3000),
                set_programming_mode(true),
                inject("BC #EDI 00 00 E3 00 C0 12 34"),
                expect_none(100),
                master_reset(code, 3000),
                power_cycle(3000),
            ];
            for object in 1..=3 {
                let state = u8::from(!erased);
                if mode == DutMode::MicroSystem7Secure {
                    // A successful authenticated response also verifies 02h's
                    // FDSK restoration versus 07h's retained commissioned key.
                    let request = format!("3C 60 #EDI {ia} 05 03 D5 {object:02X} 05 10 01");
                    let response = format!("3C 60 {ia} #EDI 06 03 D6 {object:02X} 05 10 01 {state:02X}");
                    steps.extend([inject_secure_ac(&request, key), expect_secure_ac(&response, key, 3000)]);
                } else {
                    steps.extend([
                        inject(&format!("BC #EDI {ia} 65 03 D5 {object:02X} 05 10 01")),
                        expect(&format!("BC {ia} #EDI 66 03 D6 {object:02X} 05 10 01 {state:02X}"), 3000),
                    ]);
                }
            }
            cases.push(TestCase::new(format!("erase code {code:02X}")).with_steps(steps));
        }
        let mut suite = TestSuite::new("Micro local reset", create_security_variables()).with_cases(cases);
        if mode == DutMode::MicroSystem7Secure {
            suite = suite.micro_system7_secure();
        }
        let options =
            EngineOptions { divisor: 1, dut_mode: mode, case_filters: Vec::new(), case_order: CaseOrder::Independent };
        let summary = run_suites(&[suite], &options).await;
        assert_eq!(summary.passed, 3, "{mode:?}: {summary:?}");
        assert_eq!(summary.failed + summary.blocked + summary.preparation_failed + summary.teardown_failed, 0);
    }
}
