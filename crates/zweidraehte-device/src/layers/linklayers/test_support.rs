//! Authenticated frames for medium-specific reception tests.

use zweidraehte_proto::crypto::{
    ccm,
    scf::{SecureServiceType, SecurityControlField},
};
use zweidraehte_proto::messages::{
    apdu::secure::{self, SecureApduRef},
    knx::{DestinationAddress, KnxMessageBuffer},
};

#[test]
fn sbc_mismatch_does_not_require_a_complete_secure_payload() {
    let mut frame = secure_frame(DestinationAddress::SystemBroadcast, SecurityControlField {
        service: SecureServiceType::Data,
        system_broadcast: false,
        confidentiality: true,
        tool_access: true,
    });
    frame.truncate(secure::SCF + 1);
    assert!(super::is_secure_data_without_sbc(&frame));
    for len in 0..=secure::SCF {
        assert!(!super::is_secure_data_without_sbc(&frame[..len]));
    }
}

/// Build and independently verify the MAC before testing communication-mode
/// rejection: a bad MAC must not be the reason these negative cases disappear.
pub(super) fn secure_frame(destination: DestinationAddress, scf: SecurityControlField) -> Vec<u8> {
    let key = [0x55; 16];
    let mut plain = [0xBC, 0x12, 0x03, 0, 0, 0xE0, 0x01, 0x00];
    KnxMessageBuffer::from_buffer(plain.as_mut_slice()).set_dest_addr(destination);
    let mut frame = plain.to_vec();
    match scf.service {
        SecureServiceType::Data => {
            frame.resize(plain.len() + secure::OVERHEAD, 0);
            let layout = secure::wrap_plaintext(&mut frame, plain.len(), scf.encode(), &[0, 0, 0, 0, 0, 1])
                .expect("buffer includes secure overhead");
            let context = SecureApduRef::parse(&frame).expect("secure data frame").ccm_context(0x1203);
            let payload = &mut frame[layout.payload_start..layout.payload_end];
            let mac = if scf.confidentiality {
                ccm::encrypt_and_mac(&key, &context, scf.encode(), payload)
            } else {
                ccm::compute_mac_auth_only(&key, &context, scf.encode(), payload)
            };
            frame[layout.mac_start..].copy_from_slice(&mac);

            let parsed = SecureApduRef::parse(&frame).expect("complete secure frame");
            let mut payload = parsed.payload().to_vec();
            if scf.confidentiality {
                ccm::verify_and_decrypt(&key, &context, scf.encode(), &mut payload, &parsed.mac())
                    .expect("negative case has a valid MAC");
            } else {
                ccm::verify_mac_auth_only(&key, &context, scf.encode(), &payload, &parsed.mac())
                    .expect("negative case has a valid MAC");
            }
        }
        SecureServiceType::SyncRequest => {
            frame.resize(secure::sync::FRAME_LEN, 0);
            let mac_start = secure::build_sync_request(
                &mut frame,
                plain[0],
                0x1203,
                0,
                plain[5],
                0,
                scf.encode(),
                &[0, 0, 0, 0, 0, 1],
                &[0; 6],
                &[0x33; 6],
            );
            let context = secure::SyncReqRef::parse(&frame).expect("sync request").ccm_context();
            let mut challenge = [0x33; 6];
            let mac = ccm::encrypt_and_mac_sync_req(&key, &context, scf.encode(), &[0; 6], &mut challenge);
            frame[secure::sync::CHALLENGE..mac_start].copy_from_slice(&challenge);
            frame[mac_start..].copy_from_slice(&mac);
        }
        SecureServiceType::SyncResponse => {
            frame.resize(secure::sync::FRAME_LEN, 0);
            let mac_start = secure::build_sync_response(
                &mut frame,
                plain[0],
                0x1203,
                0,
                plain[5],
                0,
                scf.encode(),
                &[0x33; 6],
                &[0, 0, 0, 0, 0, 1],
                &[0, 0, 0, 0, 0, 2],
            );
            let response = secure::SyncResRef::parse(&frame).expect("sync response");
            let mut payload = response.payload_enc();
            let mac = ccm::encrypt_and_mac_sync_res(
                &key,
                &[0x33; 6],
                response.src(),
                response.dst(),
                response.ctrl2_field().ccm_at(),
                response.tpci_apci(),
                scf.encode(),
                &mut payload,
            );
            frame[secure::sync::SEQ_NR_REMOTE..mac_start].copy_from_slice(&payload);
            frame[mac_start..].copy_from_slice(&mac);
        }
    }
    frame
}
