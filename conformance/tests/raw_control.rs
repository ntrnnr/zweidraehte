//! Raw injection must not repair a deliberately contradictory wire header.
#![cfg(feature = "dut")]

use std::collections::BTreeMap;

use zweidraehte_conformance::engine::{CaseOrder, EngineOptions, run_suites};
use zweidraehte_conformance::harness::DutMode;
use zweidraehte_conformance::logger;
use zweidraehte_conformance::tests::helpers::{expect_none, expect_sync_res_tool_from, wait};
use zweidraehte_conformance::tests::security::crypto::{unwrap_sync_req, wrap_sync_req};
use zweidraehte_conformance::tests::security::variables::TK1;
use zweidraehte_conformance::{Telegram, TestCase, TestStep, TestSuite};
use zweidraehte_proto::encoding::tp1::{knx_to_tp1_message_no_checksum, tp1_to_knx_message_no_checksum};

#[tokio::test]
async fn raw_sync_control_is_not_repaired_by_the_runner() {
    logger::init(log::LevelFilter::Warn, false);
    let challenge = [1, 2, 3, 4, 5, 6];
    let internal = wrap_sync_req(0x3C, 0xAFFE, 0x1001, 0x60, 0, &TK1, 0x92, &[0, 0, 0, 0, 0, 100], &[0; 6], &challenge);
    let wire = knx_to_tp1_message_no_checksum(internal);
    assert_eq!(wire[0], 0x3C);

    // Deliberately claim standard format over an extended layout. Its address
    // positions then name a foreign destination. If injection repairs FT,
    // the valid sync underneath will elicit a response and fail ExpectNone.
    let mut wrong_format = wire.clone();
    wrong_format[0] = 0xBC;

    // The repeat flag is another field the ordinary encoder normalizes.
    // Patch AFTER encoding; no other byte (including the MAC) should change.
    let mut repeated = wire.clone();
    repeated[0] = 0x1C;
    assert_eq!(&repeated[1..], &wire[1..]);
    let decoded = unwrap_sync_req(&tp1_to_knx_message_no_checksum(repeated.clone()), &TK1)
        .expect("changing repetition preserves sync authentication");
    assert_eq!(decoded.challenge, challenge);

    for dut_mode in [DutMode::SystemBSecure, DutMode::System7Secure] {
        let suite = TestSuite::new("Raw TP1 control", BTreeMap::new()).secure().with_cases(vec![
            TestCase::new("mismatched format is not silently repaired").with_steps(vec![
                TestStep::Inject { telegram: Telegram::from_bytes(&wrong_format), delay_before_ms: 0 },
                expect_none(200),
                // A valid frame with the same key/challenge must still work.
                // This distinguishes rejection of the wrong layout from a
                // broken fixture or failed authentication.
                TestStep::Inject { telegram: Telegram::from_bytes(&repeated), delay_before_ms: 0 },
                expect_sync_res_tool_from("10 01", "TK1", challenge, None, Some(100), 3000),
                wait(1500),
                TestStep::Inject { telegram: Telegram::from_bytes(&wire), delay_before_ms: 0 },
                expect_sync_res_tool_from("10 01", "TK1", challenge, None, Some(100), 3000),
            ]),
        ]);
        let options =
            EngineOptions { divisor: 1, dut_mode, case_filters: Vec::new(), case_order: CaseOrder::Independent };
        let summary = run_suites(&[suite], &options).await;
        assert_eq!(summary.passed, 1, "{dut_mode:?}: {summary:?}");
        assert_eq!(summary.failed + summary.blocked + summary.preparation_failed + summary.teardown_failed, 0);
    }
}
