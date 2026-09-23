//! A successful injection is insufficient: exercise counter read-back against
//! the real DUT, including deliberately wrong expectations and a dropped reply.
#![cfg(feature = "dut")]

use zweidraehte_conformance::engine::{CaseOrder, EngineOptions, run_suites};
use zweidraehte_conformance::harness::DutMode;
use zweidraehte_conformance::logger;
use zweidraehte_conformance::tests::helpers::wait;
use zweidraehte_conformance::tests::security::section_3_4::create_section_3_4_suite;
use zweidraehte_conformance::{
    SyncRequestFrameExpect, SyncResInject, SyncResponseFrame, SyncResponseLocalSequence, SyncResponseParams,
    SyncResponseVerify, TestCase, TestStep,
};

#[tokio::test]
async fn counter_checks_distinguish_acceptance_rejection_and_bad_expectations() {
    logger::init(log::LevelFilter::Warn, false);
    let baseline = SyncResponseParams {
        request_key_name: "P2PK1".into(),
        request_tool_access: false,
        request_frame: Some(SyncRequestFrameExpect {
            src_template: "#BDUT_ADDR".into(),
            dst_template: "10 41".into(),
            system_broadcast: false,
        }),
        key_name: "P2PK1".into(),
        tool_access: false,
        seq_nr_remote: 10,
        seq_nr_local: SyncResponseLocalSequence::Request,
        system_broadcast: false,
        src_template: "10 41".into(),
        response_frame: None,
        verify: Some(SyncResponseVerify { sending: SyncResponseLocalSequence::Request, peer_next: 10 }),
    };
    let mut scenarios = vec![("identical local counter", baseline.clone(), false, true)];

    let explicit =
        SyncResponseFrame { dst_template: "#BDUT_ADDR".into(), ctrl_byte: 0x34, npdu_byte: 0x30, tpci_high: 0 };
    for (name, destination, tpci, should_pass) in [
        ("explicit response framing accepted", "#BDUT_ADDR", 0, true),
        ("unresolved response destination fails", "#MISSING", 0, false),
        ("wildcard response destination fails", "?? ??", 0, false),
        ("connected response cannot be rewritten connectionlessly", "#BDUT_ADDR", 0x40, false),
    ] {
        let mut params = baseline.clone();
        params.response_frame =
            Some(SyncResponseFrame { dst_template: destination.into(), tpci_high: tpci, ..explicit.clone() });
        scenarios.push((name, params, false, should_pass));
    }

    let mut higher = baseline.clone();
    higher.seq_nr_local = SyncResponseLocalSequence::RequestOffset(10);
    higher.verify.as_mut().expect("baseline verifies state").sending = higher.seq_nr_local;
    scenarios.push(("higher local counter", higher, false, true));

    let mut broadcast = baseline.clone();
    broadcast.system_broadcast = true;
    let request = broadcast.request_frame.as_mut().expect("baseline checks routing");
    request.system_broadcast = true;
    request.dst_template = "00 00".into();
    scenarios.push(("broadcast accepted", broadcast, true, true));

    let mut explicit_broadcast = baseline.clone();
    explicit_broadcast.system_broadcast = true;
    let request = explicit_broadcast.request_frame.as_mut().expect("baseline checks routing");
    request.system_broadcast = true;
    request.dst_template = "00 00".into();
    explicit_broadcast.response_frame =
        Some(SyncResponseFrame { dst_template: "00 00".into(), npdu_byte: 0xB0, ..explicit });
    scenarios.push(("explicit broadcast accepted", explicit_broadcast, true, true));

    let mut rejected = baseline.clone();
    rejected.system_broadcast = true;
    rejected.verify.as_mut().expect("baseline verifies state").peer_next = 1;
    scenarios.push(("broadcast mismatch rejected", rejected, false, true));

    let mut wrong_key = baseline.clone();
    wrong_key.key_name = "P2PK2".into();
    scenarios.push(("injection succeeds but response is dropped", wrong_key, false, false));

    let mut wrong_peer_counter = baseline.clone();
    wrong_peer_counter.verify.as_mut().expect("baseline verifies state").peer_next = 11;
    scenarios.push(("wrong peer-counter assertion fails", wrong_peer_counter, false, false));

    let mut wrong_sending = baseline.clone();
    wrong_sending.verify.as_mut().expect("baseline verifies state").sending =
        SyncResponseLocalSequence::RequestOffset(1);
    scenarios.push(("wrong sending-counter assertion fails", wrong_sending, false, false));

    let mut wrong_destination = baseline.clone();
    wrong_destination.request_frame.as_mut().expect("baseline checks routing").dst_template = "10 42".into();
    scenarios.push(("wrong request address fails", wrong_destination, false, false));

    let mut wrong_broadcast = baseline;
    wrong_broadcast.request_frame.as_mut().expect("baseline checks routing").system_broadcast = true;
    scenarios.push(("wrong request SBC fails", wrong_broadcast, false, false));

    let mut scenarios: Vec<_> = scenarios
        .into_iter()
        .map(|(name, params, broadcast, should_pass)| {
            (
                name,
                vec![
                    wait(1500),
                    TestStep::TriggerSync { peer_ia: 0x1041, tool_access: false, is_broadcast: broadcast },
                    TestStep::ExpectSyncReqThenRespond { params, timeout_ms: 3000 },
                ],
                should_pass,
            )
        })
        .collect();
    let unsolicited = SyncResInject {
        key_name: "P2PK1".into(),
        tool_access: false,
        system_broadcast: false,
        src_template: "10 41".into(),
        dst_template: "#BDUT_ADDR".into(),
        // The compound check replaces these stale XML example counters.
        seq_nr_remote: 0,
        seq_nr_local: 30,
        challenge: [0, 0, 0, 0, 0, 1],
        ctrl_byte: 0x3C,
        npdu_byte: 0x60,
        tpci_high: 0,
    };
    for (name, peer, key, should_pass) in [
        ("unsolicited forward counters rejected", "10 41", "P2PK1", true),
        ("wrong key cannot masquerade as rejection", "10 41", "P2PK2", false),
        ("unknown peer cannot masquerade as rejection", "11 F0", "P2PK1", false),
        ("invalid peer cannot masquerade as rejection", "?? ??", "P2PK1", false),
    ] {
        let params = SyncResInject { src_template: peer.into(), key_name: key.into(), ..unsolicited.clone() };
        scenarios.push((name, vec![TestStep::VerifyUnsolicitedSyncRes { params, timeout_ms: 1000 }], should_pass));
    }

    for (name, steps, should_pass) in scenarios {
        // Reuse the handwritten suite's loaded Security IO and peer tables.
        // Its reset makes every assertion independent of prior scenarios.
        let mut suite = create_section_3_4_suite();
        suite.cases = vec![TestCase::new(name).with_steps(steps)];
        let options = EngineOptions {
            divisor: 1,
            dut_mode: DutMode::SystemBSecure,
            case_filters: Vec::new(),
            case_order: CaseOrder::Independent,
        };

        let summary = run_suites(&[suite], &options).await;

        assert_eq!(summary.tests, 1, "{name}");
        assert_eq!(summary.preparation_failed, 0, "{name}");
        assert_eq!(summary.blocked, 0, "{name}");
        assert_eq!(summary.passed, usize::from(should_pass), "{name}");
        assert_eq!(summary.failed, usize::from(!should_pass), "{name}");
    }
}
