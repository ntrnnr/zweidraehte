//! Read the actual Security IO after malformed traffic. The vendor template
//! wildcards the latest failure's sequence and does not isolate silent drops
//! from the cryptographic-error counter.
#![cfg(feature = "dut")]

use zweidraehte_conformance::engine::{CaseOrder, EngineOptions, run_suites};
use zweidraehte_conformance::harness::DutMode;
use zweidraehte_conformance::logger;
use zweidraehte_conformance::tests::helpers::{expect_none, expect_secure_ac, inject_secure_ac};
use zweidraehte_conformance::tests::security::crypto::{wrap_secure, wrap_sync_req};
use zweidraehte_conformance::tests::security::section_3_3::create_section_3_3_suite;
use zweidraehte_conformance::tests::security::variables::{TK1, create_security_context};
use zweidraehte_conformance::{SecureParams, SeqSource, Telegram, TestCase, TestStep};
use zweidraehte_proto::encoding::tp1::knx_to_tp1_message_no_checksum;

const CLEAR: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D4 00 11 00 10 37 00 00 00";
const CLEARED: &str = "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 00 00";
const COUNTERS: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D5 00 11 00 10 37 00 00 00";
const LATEST: &str = "3C 60 #EDI #BDUT_ADDR 09 01 D5 00 11 00 10 37 00 01 00";

#[tokio::test]
async fn failure_records_distinguish_crypto_errors_from_silent_drops() {
    logger::init(log::LevelFilter::Warn, false);

    // Deliberately different bytes in each sequence octet expose misplaced
    // headers and partial copies. Rejected frames must not consume this value.
    let sequence = [1, 2, 3, 4, 5, 6];
    let request = wrap_sync_req(0x3C, 0xAFFE, 0x1001, 0x60, 0, &TK1, 0x92, &sequence, &[0; 6], &[7; 6]);
    let mut overlong = request.clone();
    overlong.push(0);
    let mut bad_mac = request.clone();
    *bad_mac.last_mut().expect("request MAC") ^= 1;
    let mut invalid_scf = request.clone();
    invalid_scf[8] |= 0x40;

    let mut params = SecureParams::p2p_auth_conf("P2PK1");
    params.seq_source = SeqSource::Fixed(0x010203040506);
    let missing_key = wrap_secure(
        &[0x3C, 0xAF, 0xFE, 0x10, 0x01, 0x60, 0x01, 0xCC, 0, 0x11, 0, 0x10, 1, 1, 0, 1],
        &params,
        &mut create_security_context(),
    );
    let mut group_plain = [0x3C, 0xAF, 0xFE, 0x09, 0x01, 0xE0, 0x00, 0x81];
    let mut tool = SecureParams::tool_auth_conf("TK1");
    tool.seq_source = params.seq_source.clone();
    let tool_group = wrap_secure(&group_plain, &tool, &mut create_security_context());
    group_plain[4] = 2; // Known GA, but deliberately absent from the key table.
    let tool_unconfigured_group = wrap_secure(&group_plain, &tool, &mut create_security_context());
    let mut group = SecureParams::group_auth_conf("GK1");
    group.seq_source = params.seq_source.clone();
    let missing_group_key = wrap_secure(&group_plain, &group, &mut create_security_context());

    for mode in [DutMode::SystemBSecure, DutMode::System7Secure] {
        let mut suite = create_section_3_3_suite();
        if mode == DutMode::System7Secure {
            suite = suite.system7_secure();
        }
        // Leave the sender in SIAT but remove its P2P key. This distinguishes
        // a missing key from the already-correct unlisted-sender rejection.
        suite.preparation.extend([
            inject_secure_ac("3C 60 #EDI #BDUT_ADDR 0B 01 CE 00 11 00 10 34 01 00 00 00 00", "TK1"),
            expect_secure_ac("3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 34 01 00 00 00", "TK1", 3000),
            inject_secure_ac("3C 60 #EDI #BDUT_ADDR 0B 01 CE 00 11 00 10 35 01 00 00 00 00", "TK1"),
            expect_secure_ac("3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 35 01 00 00 00", "TK1", 3000),
            inject_secure_ac("3C 60 #EDI #BDUT_ADDR 1B 01 CE 00 11 00 10 35 01 00 01 00 02 AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA", "TK1"),
            expect_secure_ac("3C 60 #BDUT_ADDR #EDI 0A 01 CF 00 11 00 10 35 01 00 01 00", "TK1", 3000),
        ]);
        suite.cases = [
            ("short secure envelope", request[..15].to_vec(), 3),
            ("short sync request", request[..30].to_vec(), 3),
            ("overlong sync request", overlong.clone(), 3),
            ("incorrect sync MAC", bad_mac.clone(), 3),
            ("invalid SCF is silent", invalid_scf.clone(), 0),
            ("missing peer key is silent", missing_key.clone(), 0),
            ("tool group access is an access error", tool_group.clone(), 4),
            ("missing group key is silent", missing_group_key.clone(), 0),
            ("tool access to an unconfigured group is silent", tool_unconfigured_group.clone(), 0),
        ]
        .into_iter()
        .map(|(name, frame, error_type)| {
            let crypto = u8::from(error_type == 3);
            let access = u8::from(error_type == 4);
            let counter_response = format!(
                "3C 60 #BDUT_ADDR #EDI 11 01 D6 00 11 00 10 37 00 00 00 00 00 00 00 00 {crypto:02X} 00 {access:02X}"
            );
            let latest_response = match error_type {
                3 => "3C 60 #BDUT_ADDR #EDI 15 01 D6 00 11 00 10 37 00 01 00 #EDI ?? ?? ?? 01 02 03 04 05 06 03",
                4 => "3C 60 #BDUT_ADDR #EDI 15 01 D6 00 11 00 10 37 00 01 00 #EDI ?? ?? ?? ?? ?? ?? ?? ?? ?? 04",
                _ => "3C 60 #BDUT_ADDR #EDI 08 01 D6 00 11 00 10 37 F8 01",
            };
            TestCase::new(name).with_steps(vec![
                inject_secure_ac(CLEAR, "TK1"),
                expect_secure_ac(CLEARED, "TK1", 3000),
                TestStep::Inject {
                    telegram: Telegram::from_bytes(&knx_to_tp1_message_no_checksum(frame)),
                    delay_before_ms: 0,
                },
                expect_none(100),
                inject_secure_ac(COUNTERS, "TK1"),
                expect_secure_ac(&counter_response, "TK1", 3000),
                inject_secure_ac(LATEST, "TK1"),
                expect_secure_ac(latest_response, "TK1", 3000),
            ])
        })
        .collect();
        let options =
            EngineOptions { divisor: 1, dut_mode: mode, case_filters: Vec::new(), case_order: CaseOrder::Independent };
        let summary = run_suites(&[suite], &options).await;
        assert_eq!(summary.preparation_failed, 0, "{mode:?}");
        assert_eq!(summary.teardown_failed, 0, "{mode:?}");
        assert_eq!(summary.blocked, 0, "{mode:?}");
        assert_eq!(summary.failed, 0, "{mode:?}");
        assert_eq!(summary.passed, 9, "{mode:?}");
    }
}
