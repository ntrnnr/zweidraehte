//! Per-connection Data Secure state: sequence counters and CCM calls.
//!
//! The tool side of a secure exchange keeps two counters per device
//! (03/03/07 §5.1.3, mirrored from the conformance harness's
//! tool-side implementation in `conformance/src/tests/security/`):
//!
//! - `tool_seq` — our own sending Sequence Number for Tool Access. Each
//!   wrapped frame consumes one; the value must never repeat under the
//!   same key, which is why it is persisted.
//! - `table_seq` — the next sequence number we accept from the device
//!   (its "Last Valid Sequence Number" + 1 in spec terms). Anything
//!   below is a replay, an equal-or-higher value is accepted and
//!   advances the counter.

use zweidraehte_proto::crypto::ccm::{self, CcmContext};
use zweidraehte_proto::crypto::scf::{SecureServiceType, SecurityControlField};
use zweidraehte_proto::messages::apdu::secure;
use zweidraehte_proto::messages::knx::offsets;

use super::SecureError;

/// Convert a 48-bit sequence number to its 6-byte wire form.
pub fn seq_to_bytes(val: u64) -> [u8; 6] {
    let b = val.to_be_bytes();
    [b[2], b[3], b[4], b[5], b[6], b[7]]
}

/// Convert a 6-byte wire sequence number to a u64.
pub fn seq_from_bytes(bytes: &[u8; 6]) -> u64 {
    let mut b = [0u8; 8];
    b[2..8].copy_from_slice(bytes);
    u64::from_be_bytes(b)
}

/// Per-TL-connection security state for the tool (client) side.
///
/// Time-free and I/O-free; the bus task persists the counter values it
/// returns.
pub struct SecureChannel {
    key: [u8; 16],
    serial: [u8; 6],
    /// Next sequence number we will send with.
    tool_seq: u64,
    /// Next sequence number we accept from the device.
    table_seq: u64,
}

impl SecureChannel {
    pub fn new(key: [u8; 16], serial: [u8; 6], tool_seq: u64, table_seq: u64) -> Self {
        Self { key, serial, tool_seq, table_seq }
    }

    /// The device serial this channel's counters are stored under.
    pub fn serial(&self) -> &[u8; 6] {
        &self.serial
    }

    /// The active key (for the sync handshake's own CCM calls).
    pub fn key(&self) -> &[u8; 16] {
        &self.key
    }

    /// Current `tool_seq` without consuming it — the value an
    /// S-A_Sync_Req advertises as SeqNr_local (the sync service carries
    /// "next valid SeqNr", 03/03/07 §5.3.2).
    pub fn peek_tool_seq(&self) -> u64 {
        self.tool_seq
    }

    /// [`Self::peek_tool_seq`] in 6-byte wire form.
    pub fn peek_tool_seq_bytes(&self) -> [u8; 6] {
        seq_to_bytes(self.tool_seq)
    }

    /// Wrap a plaintext internal-format frame (CTRL + SRC + DST + NPDU +
    /// TPCI/APCI + data) into a Secure APDU frame, consuming one
    /// `tool_seq`.
    ///
    /// `src` is the client's bus address; it is written into the output
    /// header and into the CCM nonce, so it must match what actually
    /// goes on the wire — the receiver recomputes the MAC from the
    /// received header.
    ///
    /// All tool-access management traffic is sent A+C (SCF 0x90); the
    /// TPCI bits of the plaintext are preserved on the secure envelope
    /// so the transport layer sequence numbering is unaffected.
    ///
    /// Returns the secure frame and the *new* `tool_seq` for
    /// persistence.
    pub fn wrap(&mut self, src: u16, frame: &[u8]) -> (Vec<u8>, u64) {
        assert!(frame.len() > offsets::MSG_TPCI, "frame too short for wrapping");

        let seq_nr = seq_to_bytes(self.tool_seq);
        self.tool_seq += 1;

        let scf = SecurityControlField {
            service: SecureServiceType::Data,
            system_broadcast: false,
            confidentiality: true,
            tool_access: true,
        };
        let scf_byte = scf.encode();

        let dst = u16::from_be_bytes([frame[offsets::MSG_DEST_ADDR], frame[offsets::MSG_DEST_ADDR + 1]]);
        let addr_type = frame[offsets::MSG_ADDR_TYPE] & 0x80;

        // The protected payload is the whole plaintext APDU including
        // its TPCI/APCI; the secure envelope repeats the TPCI bits with
        // the Secure Service APCI (03F1h) in the escape position.
        let plain_apdu = &frame[offsets::MSG_TPCI..];
        let tpci_high = plain_apdu[0] & 0xFC;
        let secure_tpci_apci = u16::from_be_bytes([tpci_high | 0x03, 0xF1]);

        let ccm_ctx = CcmContext { seq_nr, src, dst, addr_type, tpci_apci: secure_tpci_apci };

        let mut payload = plain_apdu.to_vec();
        let mac = ccm::encrypt_and_mac(&self.key, &ccm_ctx, scf_byte, &mut payload);

        let mut out = Vec::with_capacity(frame.len() + secure::OVERHEAD);
        out.extend_from_slice(&frame[..offsets::MSG_TPCI]);
        out[offsets::MSG_SOURCE_ADDR..offsets::MSG_SOURCE_ADDR + 2].copy_from_slice(&src.to_be_bytes());
        out.push(tpci_high | 0x03);
        out.push(0xF1);
        out.push(scf_byte);
        out.extend_from_slice(&seq_nr);
        out.extend_from_slice(&payload);
        out.extend_from_slice(&mac);

        (out, self.tool_seq)
    }

    /// Unwrap an incoming Secure APDU frame from the device.
    ///
    /// Verifies the sequence number against `table_seq` (replay
    /// protection, checked before the MAC as the device does), then
    /// verifies the MAC and decrypts. Accepts both A+C and auth-only
    /// frames.
    ///
    /// Returns the plaintext internal-format frame (original header +
    /// decrypted APDU) and the *new* `table_seq` for persistence.
    pub fn unwrap(&mut self, frame: &[u8]) -> Result<(Vec<u8>, u64), SecureError> {
        if frame.len() < secure::MIN_FRAME_LEN {
            return Err(SecureError::TooShort);
        }

        let scf = SecurityControlField::parse(frame[secure::SCF]).map_err(|_| SecureError::InvalidScf)?;
        if scf.service != SecureServiceType::Data {
            return Err(SecureError::UnexpectedService);
        }

        let mut seq_nr = [0u8; 6];
        seq_nr.copy_from_slice(&frame[secure::SEQ_NR..secure::SEQ_NR + 6]);
        let received = seq_from_bytes(&seq_nr);
        if received < self.table_seq {
            return Err(SecureError::Replay { received, expected: self.table_seq });
        }

        let src = u16::from_be_bytes([frame[offsets::MSG_SOURCE_ADDR], frame[offsets::MSG_SOURCE_ADDR + 1]]);
        let dst = u16::from_be_bytes([frame[offsets::MSG_DEST_ADDR], frame[offsets::MSG_DEST_ADDR + 1]]);
        let addr_type = frame[offsets::MSG_ADDR_TYPE] & 0x80;
        let tpci_apci = u16::from_be_bytes([frame[offsets::MSG_TPCI], frame[offsets::MSG_TPCI + 1]]);

        let ccm_ctx = CcmContext { seq_nr, src, dst, addr_type, tpci_apci };

        let scf_byte = frame[secure::SCF];
        let mac_start = frame.len() - secure::MAC_LEN;
        let mut received_mac = [0u8; 4];
        received_mac.copy_from_slice(&frame[mac_start..]);

        let mut payload = frame[secure::PAYLOAD..mac_start].to_vec();
        if scf.confidentiality {
            ccm::verify_and_decrypt(&self.key, &ccm_ctx, scf_byte, &mut payload, &received_mac)
                .map_err(|_| SecureError::MacMismatch)?;
        } else {
            ccm::verify_mac_auth_only(&self.key, &ccm_ctx, scf_byte, &payload, &received_mac)
                .map_err(|_| SecureError::MacMismatch)?;
        }

        // Only advance the counter after the MAC verified — an attacker
        // must not be able to move it with an unauthenticated frame.
        self.table_seq = received + 1;

        // Plaintext frame = original header + decrypted APDU (which
        // starts with the plain TPCI/APCI).
        let mut out = Vec::with_capacity(offsets::MSG_TPCI + payload.len());
        out.extend_from_slice(&frame[..offsets::MSG_TPCI]);
        out.extend_from_slice(&payload);

        Ok((out, self.table_seq))
    }

    /// Apply the counters from a verified S-A_Sync_Res.
    ///
    /// Both values are "next valid SeqNr" (03/03/07 §5.3.2):
    /// `seq_nr_remote` is the device's next sending number (so it
    /// becomes `table_seq` as-is, not +1), `seq_nr_local` is what the
    /// device expects us to send next. A zero `seq_nr_local` is ignored
    /// — adopting it would rewind our counter (the device applies the
    /// same guard).
    ///
    /// Counters only move forward. Returns the new
    /// `(tool_seq, table_seq)` for persistence.
    pub fn apply_sync_response(&mut self, seq_nr_remote: u64, seq_nr_local: u64) -> (u64, u64) {
        self.table_seq = self.table_seq.max(seq_nr_remote);
        if seq_nr_local > 0 {
            self.tool_seq = self.tool_seq.max(seq_nr_local);
        }
        (self.tool_seq, self.table_seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Spec Annex C.1.1: A+C S-A_Data under the spec tool key,
    // SA = FF67h, DA = FF00h, SeqNr = 4, plain APDU
    // 03 D7 05 35 10 01 20..2F, secure TPCI/APCI = 03F1h.
    const TOOL_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    const SERIAL: [u8; 6] = [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78];

    const C1_1_PLAIN_APDU: [u8; 22] = [
        0x03, 0xD7, 0x05, 0x35, 0x10, 0x01, 0x20, 0x21, 0x22, 0x23, 0x24, //
        0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    ];
    const C1_1_CIPHERTEXT: [u8; 22] = [
        0x67, 0x67, 0x24, 0x2a, 0x23, 0x08, 0xca, 0x76, 0xa1, 0x17, 0x74, //
        0x21, 0x4e, 0xe4, 0xcf, 0x5d, 0x94, 0x90, 0x9f, 0x74, 0x3d, 0x05,
    ];
    const C1_1_MAC: [u8; 4] = [0x0d, 0x8f, 0xc1, 0x68];

    /// Plaintext internal frame matching the C.1.1 parameters
    /// (src FF67 stamped by wrap, dst FF00, individual address).
    fn c1_1_plain_frame() -> Vec<u8> {
        let mut frame = vec![0xB0, 0x00, 0x00, 0xFF, 0x00, 0x60];
        frame.extend_from_slice(&C1_1_PLAIN_APDU);
        frame
    }

    /// The secure frame as the wire carries it for C.1.1.
    fn c1_1_secure_frame() -> Vec<u8> {
        let mut frame = vec![0xB0, 0xFF, 0x67, 0xFF, 0x00, 0x60, 0x03, 0xF1, 0x90];
        frame.extend_from_slice(&seq_to_bytes(4));
        frame.extend_from_slice(&C1_1_CIPHERTEXT);
        frame.extend_from_slice(&C1_1_MAC);
        frame
    }

    #[test]
    fn wrap_annex_c1_1_matches_spec() {
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 4, 1);
        let (secure, new_tool_seq) = ch.wrap(0xFF67, &c1_1_plain_frame());

        assert_eq!(secure, c1_1_secure_frame());
        assert_eq!(new_tool_seq, 5);
        assert_eq!(ch.peek_tool_seq(), 5);
    }

    #[test]
    fn unwrap_annex_c1_1_decrypts_correctly() {
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 1, 1);
        let (plain, new_table_seq) = ch.unwrap(&c1_1_secure_frame()).expect("C.1.1 frame verifies");

        assert_eq!(&plain[..6], &c1_1_secure_frame()[..6], "header preserved");
        assert_eq!(&plain[6..], &C1_1_PLAIN_APDU, "plain APDU recovered");
        assert_eq!(new_table_seq, 5, "table_seq = received + 1");
    }

    #[test]
    fn seq_replay_rejected() {
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 1, 1);
        ch.unwrap(&c1_1_secure_frame()).expect("first delivery accepted");

        // The identical frame again: seq 4 < table_seq 5.
        assert_eq!(ch.unwrap(&c1_1_secure_frame()), Err(SecureError::Replay { received: 4, expected: 5 }));
    }

    #[test]
    fn replay_threshold_from_construction_rejected() {
        // A channel restored with table_seq above the frame's seq must
        // reject it without ever having seen it — that is the point of
        // persisting the counter.
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 1, 5);
        assert_eq!(ch.unwrap(&c1_1_secure_frame()), Err(SecureError::Replay { received: 4, expected: 5 }));
    }

    #[test]
    fn tampered_mac_rejected_and_counter_unmoved() {
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 1, 1);
        let mut frame = c1_1_secure_frame();
        let last = frame.len() - 1;
        frame[last] ^= 0x01;

        assert_eq!(ch.unwrap(&frame), Err(SecureError::MacMismatch));

        // The unauthenticated frame must not have advanced table_seq.
        ch.unwrap(&c1_1_secure_frame()).expect("genuine frame still accepted");
    }

    #[test]
    fn sync_counters_update_from_response() {
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 4, 1);

        // remote = 17 (device's next sending seq), local = 42 (device's
        // expectation of us).
        let (tool, table) = ch.apply_sync_response(17, 42);
        assert_eq!((tool, table), (42, 17));
        assert_eq!(ch.peek_tool_seq(), 42);

        // Forward-only: lower values change nothing.
        let (tool, table) = ch.apply_sync_response(3, 7);
        assert_eq!((tool, table), (42, 17));

        // seq_nr_local == 0 is ignored (would rewind on adoption).
        let (tool, _) = ch.apply_sync_response(20, 0);
        assert_eq!(tool, 42);
    }

    #[test]
    fn non_data_service_rejected() {
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 1, 1);
        let mut frame = c1_1_secure_frame();
        // SCF 0x92 = SyncRequest — not S-A_Data.
        frame[secure::SCF] = 0x92;
        assert_eq!(ch.unwrap(&frame), Err(SecureError::UnexpectedService));
    }
}
