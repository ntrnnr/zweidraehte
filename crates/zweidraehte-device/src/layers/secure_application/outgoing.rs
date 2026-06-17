//! Outgoing KNX Data Secure frame construction.
//!
//! The CCM wrap step — expanding a plaintext `T_Data_*` / `T_GroupData_Req`
//! buffer into an SCF/SeqNr/payload/MAC secure frame — is needed both by
//! [`SecureApplicationLayer::try_encrypt_outgoing`](super::SecureApplicationLayer)
//! (responding to an incoming secure request) and by unsolicited secure
//! emissions (e.g. `PID_GO_DIAGNOSTICS` WriteServiceID `0x01` / `0x03`,
//! where the triggering management frame arrived plaintext).
//!
//! Factored out as a free function so neither caller has to know about
//! the other's state — all inputs are passed explicitly.

use core::cell::RefCell;

use zweidraehte_proto::crypto::{
    ccm,
    scf::{InvalidScf, SecurityControlField},
};
use zweidraehte_proto::messages::{
    apdu::secure::{self, SecureApduRef},
    buffers::{Buffer, MessageBuffer},
    knx::{KnxMessageBuffer, ServiceType, offsets},
};

use crate::logging::warn;
use crate::objects::tables::AddressTable;
use crate::storage::SequenceNumberStorage;

// ============================================================================
// Sending sequence number reservation
// ============================================================================

/// Default initial Sequence Number Sending on fresh storage (spec §5.3.1: any
/// value 1..255, must be non-zero — SeqNr 0 is ignored by the remote S-AL).
pub(crate) const INITIAL_SENDING_SEQ: [u8; 6] = [0, 0, 0, 0, 0, 1];

// The 6-octet ⇄ u64 sequence-number conversions live with the store
// ([`crate::kvstore`]) — the SIAT is the single source of truth for sequence
// state, so its codec is the one canonical copy.
use crate::kvstore::{seq6_to_u64, u64_to_seq6};

/// Reserve and persist the next sending sequence number.
///
/// Returns the *current* value of the device's single Sequence Number Sending
/// (to place in the outgoing frame) and persists the incremented value. The
/// `tool_access` distinction does **not** apply to the sending counter (spec
/// §5.x: one counter for all outgoing communication); it is kept in the
/// signature only for call-site clarity. Returns `None` on 48-bit overflow —
/// per spec the device must stop sending secure frames once the counter saturates.
pub(crate) fn reserve_next_seq_nr<SEQ: SequenceNumberStorage>(
    seq_storage: &RefCell<SEQ>,
    _tool_access: bool,
) -> Option<[u8; 6]> {
    let mut storage = seq_storage.borrow_mut();
    let seq = storage.load_sending_seq().unwrap_or(INITIAL_SENDING_SEQ);
    let val = seq6_to_u64(&seq);

    // 48-bit overflow guard.
    if val >= 0xFFFF_FFFF_FFFF {
        return None;
    }

    // Increment the single counter and persist it.  A save failure here is
    // unexpected (storage corruption or a full flash sector) — warn and abort
    // the send rather than emitting a frame whose sequence number has not been
    // durably stored. The caller treats `None` as an abort and suppresses the
    // outgoing frame.
    if let Err(_e) = storage.save_sending_seq(&u64_to_seq6(val + 1)) {
        warn!("S-AL: failed to persist sending SeqNr; aborting secure frame");
        return None;
    }

    Some(seq)
}

/// Inputs for [`wrap_outgoing`].
pub(crate) struct WrapInputs<'a, ADT: AddressTable> {
    /// SCF byte to embed in the secure frame. Must be a valid SCF —
    /// [`wrap_outgoing`] returns `Err` otherwise.
    pub scf_byte: u8,
    /// 16-byte AES key selected by the caller (tool key, group key, or
    /// P2P key depending on the frame type).
    pub key: [u8; 16],
    /// Device's own individual address (source of the outgoing frame).
    pub src: u16,
    /// Fresh sending sequence number (6 bytes, must not be zero; the
    /// caller is responsible for incrementing persistent storage).
    pub seq_nr: [u8; 6],
    /// For connection-oriented responses: the TL outgoing sequence
    /// number. When `Some`, the TPCI bits are pre-set to
    /// `DataConnected(seq)` before the MAC is computed so that the
    /// MAC matches the TPCI the TL will later emit on the wire.
    pub outgoing_tl_seq: Option<u8>,
    /// Address table — consulted for `T_GroupData_Req` to reverse-resolve
    /// the TSAP (currently in `MSG_DEST_ADDR`) into the real GA for the
    /// CCM B0 block.
    pub adt: &'a ADT,
}

/// Errors that can happen while wrapping an outgoing frame.
#[derive(Debug)]
pub(crate) enum WrapError {
    /// Buffer doesn't have room for the secure overhead (13 bytes).
    BufferTooSmall,
    /// SCF byte is syntactically invalid.
    InvalidScf,
}

/// Expand a plaintext `T_*_Req` buffer in place into a KNX Data Secure
/// frame (SCF + SeqNr + encrypted/authenticated payload + MAC).
///
/// The message service type must already be one of the secure-wrappable
/// downward indications (`T_Data_Req`, `T_DataUnack_Req`,
/// `T_GroupData_Req`, `T_Broadcast_Req`, `T_SystemBroadcast_Req`);
/// callers are expected to have filtered non-wrappable messages before
/// calling in.
pub(crate) fn wrap_outgoing<ADT: AddressTable>(
    msg: &mut KnxMessageBuffer<Buffer<'static>>,
    inputs: WrapInputs<'_, ADT>,
) -> Result<(), WrapError> {
    // Validate SCF up front so we don't half-build a frame on bad input.
    let scf: SecurityControlField =
        SecurityControlField::parse(inputs.scf_byte).map_err(|InvalidScf| WrapError::InvalidScf)?;

    let st = msg.service_type();
    let buf = msg.buf_mut();

    // For connection-oriented responses, pre-set the TPCI sequence
    // number bits on the plaintext before encrypting. The CCM B0
    // block must include the correct TPCI with TL sequence bits
    // (spec 03/03/07 §5.1.3.2 Figure 101). Without this, the MAC
    // would be computed with the plain TPCI (0x00) but the TL later
    // sets the numbered-data TPCI on the already-encrypted frame,
    // causing a mismatch at the receiver.
    if let Some(seq) = inputs.outgoing_tl_seq {
        // DataConnected TPCI: DC=0 (bit 7, Data), N=1 (bit 6, Numbered),
        // seq in bits 5-2. Preserve the lower 2 bits (APCI high).
        let tpci_bits = 0x40 | ((seq & 0x0F) << 2);
        let apci_high = buf[offsets::MSG_TPCI] & 0x03;
        buf[offsets::MSG_TPCI] = tpci_bits | apci_high;
    }

    let plain_content_len = buf.len();
    let needed_len = plain_content_len + secure::OVERHEAD;

    if needed_len > buf.capacity() {
        warn!("S-AL: buffer too small for secure frame ({} > {})", needed_len, buf.capacity());
        return Err(WrapError::BufferTooSmall);
    }

    // Expand buffer so wrap_plaintext has room to shift the payload.
    buf.set_len(needed_len);

    let layout = secure::wrap_plaintext(buf, plain_content_len, inputs.scf_byte, &inputs.seq_nr)
        .expect("buffer capacity already verified");

    // Build the CCM context from the now-shaped secure frame.
    let secure_ref = SecureApduRef::parse(buf).expect("just built a valid secure frame");
    let mut ccm_ctx = secure_ref.ccm_context(inputs.src);

    // For outgoing group frames, MSG_DEST_ADDR still contains the TSAP
    // (ConnectionNr) — the TL hasn't resolved it to the actual GA yet.
    // Reverse-lookup the real GA for the CCM context so the receiver can
    // verify the MAC. Also set the group address type bit in the CCM context.
    if matches!(st, ServiceType::T_GroupData_Req) {
        let tsap = ccm_ctx.dst;
        if let Some(ga) = inputs.adt.get_address(tsap) {
            ccm_ctx.dst = u16::from_be_bytes(ga.0);
            ccm_ctx.addr_type = 0x80; // Group addressed
        }
    }
    drop(secure_ref);

    // Encrypt payload and compute MAC.
    let mac = if scf.confidentiality {
        ccm::encrypt_and_mac(&inputs.key, &ccm_ctx, inputs.scf_byte, &mut buf[layout.payload_start..layout.payload_end])
    } else {
        ccm::compute_mac_auth_only(
            &inputs.key,
            &ccm_ctx,
            inputs.scf_byte,
            &buf[layout.payload_start..layout.payload_end],
        )
    };

    buf[layout.mac_start..layout.mac_start + secure::MAC_LEN].copy_from_slice(&mac);

    Ok(())
}
