//! Per-connection Data Secure state: receive floor and CCM calls.
//!
//! Outgoing values must be durably reserved by the bus-level store.
//! `table_seq` is the next sequence number we accept from the device
//!   (its "Last Valid Sequence Number" + 1 in spec terms). Anything
//!   below is a replay, an equal-or-higher value is accepted and
//!   advances the counter.

use zweidraehte_proto::crypto::ccm;
#[cfg(test)]
use zweidraehte_proto::crypto::ccm::CcmContext;
use zweidraehte_proto::crypto::scf::{SecureServiceType, SecurityControlField};
use zweidraehte_proto::messages::apdu::secure;
use zweidraehte_proto::messages::knx::{DestinationAddress, FrameType, KnxMessageBuffer, offsets};
use zweidraehte_util::secret::SecretBytes;

use super::SecureError;

/// Convert a 48-bit sequence number to its 6-byte wire form.
pub(crate) fn seq_to_bytes(val: u64) -> [u8; 6] {
    let b = val.to_be_bytes();
    [b[2], b[3], b[4], b[5], b[6], b[7]]
}

/// Convert a 6-byte wire sequence number to a u64.
pub(crate) fn seq_from_bytes(bytes: &[u8; 6]) -> u64 {
    let mut b = [0u8; 8];
    b[2..8].copy_from_slice(bytes);
    u64::from_be_bytes(b)
}

/// Per-TL-connection security state for the tool (client) side.
///
/// Time-free and I/O-free; the bus task persists the counter values it
/// returns.
pub(crate) struct SecureChannel {
    key: SecretBytes,
    /// `None` for devices whose keyring entry carries no serial —
    /// their counters cannot be persisted (no stable key to store
    /// them under) and live only as long as the connection; the
    /// S-A_Sync handshake recovers them on the next connect.
    serial: Option<[u8; 6]>,
    /// Next sequence number we accept from the device.
    table_seq: u64,
}

impl SecureChannel {
    pub fn new(key: [u8; 16], serial: [u8; 6], table_seq: u64) -> Self {
        Self { key: key.into(), serial: Some(serial), table_seq }
    }

    /// A channel without counter persistence (device serial unknown).
    pub fn new_unpersisted(key: [u8; 16], table_seq: u64) -> Self {
        Self { key: key.into(), serial: None, table_seq }
    }

    /// The device serial this channel's counters are stored under,
    /// if known.
    pub fn serial(&self) -> Option<&[u8; 6]> {
        self.serial.as_ref()
    }

    /// The active key (for the sync handshake's own CCM calls).
    pub fn key(&self) -> &[u8; 16] {
        self.key.key16_ref().expect("secure-channel keys have fixed width")
    }

    /// Change the key without disturbing either sequence counter.
    ///
    /// This exists solely for `PID_TOOL_KEY`: a device authenticates the
    /// write with its old key but encrypts the confirmed response with the
    /// newly written key. The bus task invokes this after sending that one
    /// request and before receiving its response.
    pub(crate) fn rotate_key(&mut self, key: [u8; 16]) {
        self.key = key.into();
    }

    /// Wrap with a value already durably reserved by the station-wide sequence store.
    pub fn wrap_at(&self, sequence: u64, src: u16, frame: &[u8]) -> Vec<u8> {
        wrap_with_scf(
            self.key(),
            SecurityControlField {
                service: SecureServiceType::Data,
                system_broadcast: false,
                confidentiality: true,
                tool_access: true,
            },
            seq_to_bytes(sequence),
            src,
            frame,
        )
    }

    /// Adopt only the remote device's authenticated sending floor. The
    /// client half belongs to the bus-wide store, not this channel.
    pub fn apply_remote_sync(&mut self, seq_nr_remote: u64) -> u64 {
        self.table_seq = self.table_seq.max(seq_nr_remote);
        self.table_seq
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
        let (plain, received) = unwrap_with_floor(self.key(), frame, self.table_seq)?;

        // Only advance the counter after the MAC verified — an attacker
        // must not be able to move it with an unauthenticated frame.
        self.table_seq = received + 1;

        Ok((plain, self.table_seq))
    }
}

/// Wrap a plaintext internal-format frame into a Secure APDU frame
/// under `scf` with the given sequence number.
///
/// `src` is written into the output header and into the CCM nonce, so
/// it must match what actually goes on the wire — the receiver
/// recomputes the MAC from the received header. The TPCI bits of the
/// plaintext are preserved on the secure envelope.
fn wrap_with_scf(key: &[u8; 16], scf: SecurityControlField, seq_nr: [u8; 6], src: u16, frame: &[u8]) -> Vec<u8> {
    let mut out = frame.to_vec();
    out.resize(frame.len() + secure::OVERHEAD, 0);
    KnxMessageBuffer::from_buffer(out.as_mut_slice()).set_source_addr(src.to_be_bytes().into());
    let layout =
        secure::wrap_plaintext(&mut out, frame.len(), scf.encode(), &seq_nr).expect("buffer includes secure overhead");
    let envelope = secure::SecureApduRef::parse(&out).expect("wrapped frame has an APDU");
    let context = envelope.ccm_context(src);
    let mac = ccm::encrypt_and_mac(key, &context, scf.encode(), &mut out[layout.payload_start..layout.payload_end]);
    out[layout.mac_start..].copy_from_slice(&mac);

    // Security adds sequence, SCF, and MAC octets after the plaintext frame
    // was built. Frame form therefore has to be selected again from the
    // actual outer payload; preserving the inner Standard bit can create an
    // impossible TP frame once the envelope crosses the 15-octet boundary.
    let data_length = out.len().checked_sub(offsets::MSG_TPCI + 1).expect("secure frame contains a TPCI octet");
    let frame_type =
        if crate::bus::frames::uses_standard_frame(data_length) { FrameType::Standard } else { FrameType::Extended };
    let mut message = KnxMessageBuffer::from_buffer(out);
    message.ctrl_field_mut().set_ft(frame_type);

    message.into_inner()
}

/// Verify and decrypt a Secure APDU frame against a replay floor
/// (`floor` = lowest sequence number still accepted).
///
/// The replay check runs before the MAC — same order as the device —
/// but the caller must only move its floor on `Ok`, since the sequence
/// number is unauthenticated until the MAC verifies. Accepts both A+C
/// and auth-only frames. Returns the plaintext internal-format frame
/// and the *received* sequence number.
fn unwrap_with_floor(key: &[u8; 16], frame: &[u8], floor: u64) -> Result<(Vec<u8>, u64), SecureError> {
    let envelope = secure::SecureApduRef::parse(frame).map_err(|_| SecureError::TooShort)?;
    let scf = envelope.scf().map_err(|_| SecureError::InvalidScf)?;
    if scf.service != SecureServiceType::Data {
        return Err(SecureError::UnexpectedService);
    }

    let received = seq_from_bytes(&envelope.seq_nr());
    if received < floor {
        return Err(SecureError::Replay { received, expected: floor });
    }

    let source = KnxMessageBuffer::from_buffer(frame).get_source_addr();
    let context = envelope.ccm_context(u16::from_be_bytes(source.0));
    let mac = envelope.mac();
    let mut out = frame.to_vec();
    let mut plaintext = secure::SecureApduMut::parse(&mut out).expect("validated secure frame");
    if scf.confidentiality {
        ccm::verify_and_decrypt(key, &context, envelope.scf_byte(), plaintext.payload_mut(), &mac)
            .map_err(|_| SecureError::MacMismatch)?;
    } else {
        ccm::verify_mac_auth_only(key, &context, envelope.scf_byte(), plaintext.payload_mut(), &mac)
            .map_err(|_| SecureError::MacMismatch)?;
    }
    let plain_len = plaintext.unwrap_to_plaintext();
    out.truncate(plain_len);

    Ok((out, received))
}

/// Wrap a plaintext group frame (A_GroupValue_*) into a Secure APDU
/// under a group key.
///
/// Group traffic is always sent A+C without tool access (SCF 0x10) —
/// ETS programs S-mode secured group objects as auth+conf only, and a
/// tool-access flag on a group frame is rejected by every receiver
/// (TSSJ §3.2.6). `seq` is the client-wide secure sending sequence
/// number; the caller consumes it from [`super::SecurityStore`] before
/// calling.
pub(crate) fn group_wrap(key: &[u8; 16], seq: u64, src: u16, frame: &[u8]) -> Vec<u8> {
    debug_assert!(
        KnxMessageBuffer::from_buffer(frame).ctrl2_field().is_group_addressed(),
        "group_wrap needs a group-addressed frame"
    );

    let scf = SecurityControlField {
        service: SecureServiceType::Data,
        system_broadcast: false,
        confidentiality: true,
        tool_access: false,
    };

    wrap_with_scf(key, scf, seq_to_bytes(seq), src, frame)
}

/// Protect tool-access data sent as a system broadcast during initial
/// commissioning. Unlike secured group traffic this sets both the system-
/// broadcast and tool-access bits; the inner serial-number service selects
/// the one factory device which owns the FDSK.
pub(crate) fn system_broadcast_wrap(key: &[u8; 16], seq: u64, src: u16, frame: &[u8]) -> Vec<u8> {
    debug_assert_eq!(
        KnxMessageBuffer::from_buffer(frame).get_dest_addr(),
        DestinationAddress::SystemBroadcast,
        "system_broadcast_wrap needs a system-broadcast frame"
    );
    let scf = SecurityControlField {
        service: SecureServiceType::Data,
        system_broadcast: true,
        confidentiality: true,
        tool_access: true,
    };
    wrap_with_scf(key, scf, seq_to_bytes(seq), src, frame)
}

/// Unwrap an incoming secure group frame under a group key.
///
/// `floor` is the next sequence number accepted from this *sender IA*
/// (replay protection is per sender, not per group address — the same
/// slot a device keeps in its SIAT). A retransmission carries the
/// sender's last valid number, i.e. `floor - 1`, and lands in the
/// `Replay` arm like any older number. Sequence number 0 is always
/// rejected, and a tool-access flag on group traffic is refused
/// outright (TSSJ §3.2.6). Accepts A+C (SCF 0x10) and auth-only
/// (SCF 0x00) frames.
///
/// Returns the plaintext frame and the new floor (`received + 1`) for
/// the caller to store — only on `Ok`, so an unauthenticated frame
/// can never move the floor.
pub(crate) fn group_unwrap(key: &[u8; 16], frame: &[u8], floor: u64) -> Result<(Vec<u8>, u64), SecureError> {
    if frame.len() < secure::MIN_FRAME_LEN {
        return Err(SecureError::TooShort);
    }
    let scf = SecurityControlField::parse(frame[secure::SCF]).map_err(|_| SecureError::InvalidScf)?;
    if scf.tool_access {
        return Err(SecureError::ToolAccessOnGroup);
    }

    // Sequence number 0 is invalid on any S-A_Data frame; enforce it
    // even if a caller passed a zero floor.
    let (plain, received) = unwrap_with_floor(key, frame, floor.max(1))?;

    Ok((plain, received + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_proto::messages::knx::offsets;

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
        // Annex C fixes the cryptographic inputs, but its compact header does
        // not override TP's frame-capacity rule. The resulting 35-octet
        // internal frame must use the extended form on the actual bus.
        let mut frame = vec![0x30, 0xFF, 0x67, 0xFF, 0x00, 0x60, 0x03, 0xF1, 0x90];
        frame.extend_from_slice(&seq_to_bytes(4));
        frame.extend_from_slice(&C1_1_CIPHERTEXT);
        frame.extend_from_slice(&C1_1_MAC);
        frame
    }

    #[test]
    fn authentication_covers_eff_but_not_hop_count() {
        for eff in 0..16 {
            let mut plain = c1_1_plain_frame();
            plain[0] = 0x30;
            plain[offsets::MSG_ADDR_TYPE] |= eff;
            let channel = SecureChannel::new(TOOL_KEY, SERIAL, 1);
            let frame = channel.wrap_at(4, 0xFF67, &plain);
            for changed_bits in [0, 0x10, 0x70, 1, 2, 4, 8] {
                let mut changed = frame.clone();
                changed[offsets::MSG_ADDR_TYPE] ^= changed_bits;
                assert_eq!(unwrap_with_floor(&TOOL_KEY, &changed, 1).is_ok(), changed_bits & 0x0F == 0);
            }
        }
    }

    #[test]
    fn system_broadcast_data_sets_the_commissioning_security_flags() {
        let source = zweidraehte_proto::address::IndividualAddress::new(1, 0, 2);
        let plain = crate::bus::frames::build_system_broadcast_frame(
            source,
            zweidraehte_proto::messages::knx::ApciCode::IndividualAddressSerialNumberWrite,
            offsets::MSG_APCI + 10,
            |_| {},
        );
        let secure = system_broadcast_wrap(&TOOL_KEY, 5, u16::from_be_bytes(source.0), &plain);
        let scf = SecurityControlField::parse(secure[secure::SCF]).expect("SCF parses");

        assert!(scf.system_broadcast);
        assert!(scf.confidentiality);
        assert!(scf.tool_access);
        assert_eq!(KnxMessageBuffer::from_buffer(secure.as_slice()).ctrl_field().ft(), FrameType::Extended);
        let (recovered, sequence) = unwrap_with_floor(&TOOL_KEY, &secure, 1).expect("frame verifies");
        assert_eq!(&recovered[1..], &plain[1..]);
        assert_eq!(sequence, 5);
    }

    #[test]
    fn wrap_annex_c1_1_matches_spec() {
        let ch = SecureChannel::new(TOOL_KEY, SERIAL, 1);
        let secure = ch.wrap_at(4, 0xFF67, &c1_1_plain_frame());

        assert_eq!(secure, c1_1_secure_frame());
    }

    #[test]
    fn connected_descriptor_wrap_matches_ets_trace() {
        use zweidraehte_proto::address::IndividualAddress;
        use zweidraehte_proto::messages::apdu::device::DeviceDescriptorRead;
        use zweidraehte_proto::messages::knx::{ApciCode, Tpci};

        // Captured from ETS 6 programming a Weinzierl 420.1. The first six
        // expected bytes are our compact standard-frame header; the encrypted
        // APDU and MAC are the ETS wire bytes. This catches mistakes in
        // connected TPCI handling, nonce addresses, and the short
        // DeviceDescriptor APCI which the connectionless Annex C vector
        // cannot exercise.
        let key = [
            0xC9, 0xFA, 0x59, 0xE4, 0x9A, 0x8D, 0xB2, 0xCB, //
            0x13, 0x30, 0x97, 0xC8, 0x70, 0x93, 0x31, 0x47,
        ];
        let plain = crate::bus::frames::build_individual_frame(
            IndividualAddress::new(0, 0, 0),
            IndividualAddress::new(1, 0, 11),
            Tpci::DataConnected(3),
            ApciCode::DeviceDescriptorRead,
            DeviceDescriptorRead::MIN_MSG_LEN,
            |buf| DeviceDescriptorRead::write(buf, 0),
        );
        let secure = SecureChannel::new(key, [0; 6], 1).wrap_at(0x003F_71E2_D7A4, 0x1002, &plain);

        assert_eq!(secure, [
            0xB0, 0x10, 0x02, 0x10, 0x0B, 0x60, 0x4F, 0xF1, 0x90, 0x00, 0x3F, 0x71, 0xE2, 0xD7, 0xA4, 0x75, 0xD9, 0x77,
            0xE5, 0x55, 0xD3,
        ]);
    }

    #[test]
    fn key_rotation_preserves_sequence_state() {
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 9);
        ch.rotate_key([0x55; 16]);
        assert_eq!(ch.key(), &[0x55; 16]);
    }

    #[test]
    fn unwrap_annex_c1_1_decrypts_correctly() {
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 1);
        let (plain, new_table_seq) = ch.unwrap(&c1_1_secure_frame()).expect("C.1.1 frame verifies");

        assert_eq!(&plain[..6], &c1_1_secure_frame()[..6], "header preserved");
        assert_eq!(&plain[6..], &C1_1_PLAIN_APDU, "plain APDU recovered");
        assert_eq!(new_table_seq, 5, "table_seq = received + 1");
    }

    #[test]
    fn seq_replay_rejected() {
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 1);
        ch.unwrap(&c1_1_secure_frame()).expect("first delivery accepted");

        // The identical frame again: seq 4 < table_seq 5.
        assert_eq!(ch.unwrap(&c1_1_secure_frame()), Err(SecureError::Replay { received: 4, expected: 5 }));
    }

    #[test]
    fn replay_threshold_from_construction_rejected() {
        // A channel restored with table_seq above the frame's seq must
        // reject it without ever having seen it — that is the point of
        // persisting the counter.
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 5);
        assert_eq!(ch.unwrap(&c1_1_secure_frame()), Err(SecureError::Replay { received: 4, expected: 5 }));
    }

    #[test]
    fn tampered_mac_rejected_and_counter_unmoved() {
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 1);
        let mut frame = c1_1_secure_frame();
        let last = frame.len() - 1;
        frame[last] ^= 0x01;

        assert_eq!(ch.unwrap(&frame), Err(SecureError::MacMismatch));

        // The unauthenticated frame must not have advanced table_seq.
        ch.unwrap(&c1_1_secure_frame()).expect("genuine frame still accepted");
    }

    #[test]
    fn sync_counters_update_from_response() {
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 1);

        assert_eq!(ch.apply_remote_sync(17), 17);
        assert_eq!(ch.apply_remote_sync(3), 17, "receive floor never rewinds");
        assert_eq!(ch.apply_remote_sync(0), 17);
        assert_eq!(ch.apply_remote_sync(20), 20);
    }

    #[test]
    fn non_data_service_rejected() {
        let mut ch = SecureChannel::new(TOOL_KEY, SERIAL, 1);
        let mut frame = c1_1_secure_frame();
        // SCF 0x92 = SyncRequest — not S-A_Data.
        frame[secure::SCF] = 0x92;
        assert_eq!(ch.unwrap(&frame), Err(SecureError::UnexpectedService));
    }

    // ---- group traffic ----
    //
    // The spec Annex C carries no group-communication vector, so these
    // tests anchor on round-trips through the CCM primitives that the
    // C.1.1 vector above already pins down, plus byte-level checks of
    // the envelope (SCF, APCI, sequence number).

    const GROUP_KEY: [u8; 16] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, //
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    ];

    /// A plain A_GroupValue_Write to GA 2/3/4 (1304h), value 1 (6-bit).
    fn group_plain_frame() -> Vec<u8> {
        // CTRL, SRC (stamped by wrap), DST = 1304h, NPDU: group-addressed
        // (bit 7), hop count 6, EFF zero; TPCI/APCI 0080h | value.
        vec![0xBC, 0x00, 0x00, 0x13, 0x04, 0xE0, 0x00, 0x81]
    }

    #[test]
    fn group_wrap_envelope_bytes() {
        let secure = group_wrap(&GROUP_KEY, 5, 0x110A, &group_plain_frame());

        assert_eq!(&secure[..6], &[0xBC, 0x11, 0x0A, 0x13, 0x04, 0xE0], "header with src stamped");
        assert_eq!(&secure[6..8], &[0x03, 0xF1], "SecureService APCI");
        assert_eq!(secure[secure::SCF], 0x10, "group data SCF: A+C, no tool access");
        assert_eq!(&secure[secure::SEQ_NR..secure::SEQ_NR + 6], &seq_to_bytes(5));
        assert_eq!(secure.len(), group_plain_frame().len() + secure::OVERHEAD);
    }

    #[test]
    fn group_wrap_unwrap_roundtrip() {
        let plain = group_plain_frame();
        let secure = group_wrap(&GROUP_KEY, 5, 0x110A, &plain);

        let (recovered, new_floor) = group_unwrap(&GROUP_KEY, &secure, 1).expect("own frame verifies");
        assert_eq!(&recovered[6..], &plain[6..], "plain APDU recovered");
        assert_eq!(&recovered[..6], &secure[..6], "header preserved");
        assert_eq!(new_floor, 6, "floor = received + 1");
    }

    #[test]
    fn group_unwrap_replay_rejected() {
        let secure = group_wrap(&GROUP_KEY, 5, 0x110A, &group_plain_frame());

        // A retransmission carries the last valid number: floor - 1.
        assert_eq!(group_unwrap(&GROUP_KEY, &secure, 6), Err(SecureError::Replay { received: 5, expected: 6 }));
        // Anything older is equally dead.
        assert_eq!(group_unwrap(&GROUP_KEY, &secure, 100), Err(SecureError::Replay { received: 5, expected: 100 }));
        // At the floor it is fresh.
        group_unwrap(&GROUP_KEY, &secure, 5).expect("seq == floor is accepted");
    }

    #[test]
    fn group_unwrap_seq_zero_rejected_even_with_zero_floor() {
        let secure = group_wrap(&GROUP_KEY, 0, 0x110A, &group_plain_frame());
        assert_eq!(group_unwrap(&GROUP_KEY, &secure, 0), Err(SecureError::Replay { received: 0, expected: 1 }));
    }

    #[test]
    fn group_unwrap_tool_access_rejected() {
        // The same frame wrapped with the tool SCF (0x90) — a receiver
        // must refuse tool access on group traffic (TSSJ §3.2.6),
        // before any MAC work.
        let ch = SecureChannel::new(GROUP_KEY, SERIAL, 1);
        let tool_wrapped = ch.wrap_at(5, 0x110A, &group_plain_frame());

        assert_eq!(group_unwrap(&GROUP_KEY, &tool_wrapped, 1), Err(SecureError::ToolAccessOnGroup));
    }

    #[test]
    fn group_unwrap_auth_only_accepted() {
        // Hand-build an auth-only (SCF 0x00) frame: payload rides in
        // clear, MAC covers SCF + payload.
        use zweidraehte_proto::crypto::ccm;

        let plain = group_plain_frame();
        let seq_nr = seq_to_bytes(9);
        let src = 0x110Au16;
        let ctx = CcmContext { seq_nr, src, dst: 0x1304, addr_type: 0x80, tpci_apci: 0x03F1 };
        let payload = plain[offsets::MSG_TPCI..].to_vec();
        let mac = ccm::compute_mac_auth_only(&GROUP_KEY, &ctx, 0x00, &payload);

        let mut frame = vec![0xBC, 0x11, 0x0A, 0x13, 0x04, 0xE0, 0x03, 0xF1, 0x00];
        frame.extend_from_slice(&seq_nr);
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&mac);

        let (recovered, new_floor) = group_unwrap(&GROUP_KEY, &frame, 1).expect("auth-only frame verifies");
        assert_eq!(&recovered[6..], &plain[6..]);
        assert_eq!(new_floor, 10);
    }

    #[test]
    fn group_unwrap_tampered_mac_rejected() {
        let mut secure = group_wrap(&GROUP_KEY, 5, 0x110A, &group_plain_frame());
        let last = secure.len() - 1;
        secure[last] ^= 0x01;
        assert_eq!(group_unwrap(&GROUP_KEY, &secure, 1), Err(SecureError::MacMismatch));
    }

    #[test]
    fn group_unwrap_wrong_key_rejected() {
        let secure = group_wrap(&GROUP_KEY, 5, 0x110A, &group_plain_frame());
        assert_eq!(group_unwrap(&TOOL_KEY, &secure, 1), Err(SecureError::MacMismatch));
    }
}
