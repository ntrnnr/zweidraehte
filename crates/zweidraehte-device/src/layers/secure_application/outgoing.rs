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

use zweidraehte_proto::security::{self, SequenceNumberStorage};

use crate::logging::warn;
use crate::objects::tables::AddressTable;

// ============================================================================
// Sending sequence number reservation
// ============================================================================

/// Reserve and persist the next sending sequence number.
///
/// The rule itself — persist the increment before handing the current value
/// out, refuse once the 48-bit counter saturates — is
/// [`zweidraehte_proto::security::reserve_next_seq_nr`]. This wrapper only
/// takes the `RefCell` borrow the S-AL holds its store behind.
///
/// The `tool_access` distinction does **not** apply to the sending counter
/// (03/03/07 §5.3: one counter for all outgoing communication); it is kept in
/// the signature for call-site clarity.
pub(crate) fn reserve_next_seq_nr<SEQ: SequenceNumberStorage>(
    seq_storage: &RefCell<SEQ>,
    _tool_access: bool,
) -> Option<[u8; 6]> {
    security::reserve_next_seq_nr(&mut *seq_storage.borrow_mut())
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

    // For connection-oriented responses, pre-set the TPCI sequence number
    // before shaping the secure envelope. `wrap_plaintext` copies these bits
    // into the outer SecureService TPDU and strips them from the protected
    // Plain APDU, as required by Application Layer §2 and §5.1.3.3.
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
        if let Some(ga) = inputs.adt.address(tsap) {
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
