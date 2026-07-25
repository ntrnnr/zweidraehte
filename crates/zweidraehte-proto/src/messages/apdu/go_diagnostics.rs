//! Response writers for the diagnostics function properties carried via
//! `A_FunctionPropertyExtState_Read` / `A_FunctionPropertyExtCommand`.
//!
//! Covers two closely-related properties:
//!
//! - **`PID_OPERATION_MODE`** (PID 52) on the Application Program Object
//!   — carries the current operation-mode byte and a countdown.
//! - **`PID_GO_DIAGNOSTICS`** (PID 66) on the Group Object Table Object
//!   — the single function property used for all GO diagnostic
//!   subcommands (read/write local value, direct GA read/write,
//!   transmit, etc.). Response layouts vary per service-ID; this module
//!   provides one writer per distinct response shape.
//!
//! The wire layout follows KNX spec 03/05/01 §4.8.1. Unlike the
//! `group_value` module, the caller does not supply a `MessageBuilder`
//! buffer here — function-property service data lives inside the
//! [`PropertyBuf`](crate::PropertyBuf) payload of a
//! [`FunctionPropertyResult`](crate::messages::apdu::function_property),
//! so the writers return the populated byte slice directly.
//!
//! All writers are `no_std` / alloc-free: they fill a caller-supplied
//! fixed-size array and return a `&[u8]` of the actual on-wire length.

// ============================================================================
// Return codes
// ============================================================================

crate::create_protocol_enum!(
    /// Return codes for `PID_OPERATION_MODE` and `PID_GO_DIAGNOSTICS`
    /// responses (spec 03/05/01 §4.3.8 and §4.8.1).
    ///
    /// These two properties answer from their own code space, **disjoint
    /// from** the generic property-service table modelled by
    /// [`PropertyReturnCode`](crate::messages::apdu::property_ext::PropertyReturnCode).
    /// The two overlap numerically — `0x20` is a *success* here but has no
    /// meaning in the generic table, and `0xF8` means `E_DATA_VOID` there
    /// while being unassigned here — so the enums are deliberately kept
    /// separate rather than merged into one type over the shared `u8`
    /// field.
    ///
    /// The two success codes are property-specific:
    /// - [`Config`](Self::Config) (`0x20`) doubles as
    ///   `E_OM_CURRENT_OPERATION_MODE` for `PID_OPERATION_MODE` and as
    ///   `E_GD_CONFIG` for GO diagnostics ReadServiceID 0x00.
    /// - [`GoStatusValue`](Self::GoStatusValue) (`0x21`) carries a GO
    ///   status/value payload.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum GoDiagReturnCode: u8 {
        Config, 0x20, "E_GD_CONFIG / E_OM_CURRENT_OPERATION_MODE";
        GoStatusValue, 0x21, "E_GD_GO_STATUS_VALUE";
        OperationModeError, 0xA0, "E_OM_ERROR";
        GoVoid, 0xA1, "E_GD_GO_VOID";
        ConfigFlags, 0xA2, "E_GD_CONFIG_FLAGS";
        GoSizeMismatch, 0xA3, "E_GD_GO_SIZE_MISMATCH";
        _, "Unknown GO diagnostics return code 0x{:x}";
    }
);

// ============================================================================
// PID_OPERATION_MODE
// ============================================================================

/// Response body for `PID_OPERATION_MODE` — both `E_OM_CURRENT_OPERATION_MODE`
/// (return code 0x20) success paths and the `0xA0` negative acknowledgement
/// use the identical three-byte body.
///
/// Wire: `[service_id, operation_mode, time_left]`.
///
/// Per spec 03/05/01 §4.3.8 the `time_left` byte is 0xFF when no timeout
/// is running (i.e. normal mode), otherwise the remaining seconds clamped
/// to 0..=254.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationModeResponse {
    pub service_id: u8,
    pub operation_mode: u8,
    pub time_left: u8,
}

impl OperationModeResponse {
    /// On-wire length of the response body, in bytes.
    pub const LEN: usize = 3;

    /// Write the body into `buf` and return the populated prefix.
    pub fn write(self, buf: &mut [u8; Self::LEN]) -> &[u8] {
        buf[0] = self.service_id;
        buf[1] = self.operation_mode;
        buf[2] = self.time_left;
        &buf[..Self::LEN]
    }
}

// ============================================================================
// PID_GO_DIAGNOSTICS — ReadServiceID 0x00 (Get GO Config)
// ============================================================================

/// Response body for `PID_GO_DIAGNOSTICS` ReadServiceID 0x00 ("Get GO
/// configuration") success (return code 0x20 = `E_GD_CONFIG`).
///
/// Per spec 03/05/01 §4.8.1.1.6 Figure 22 + Figure 23, the wire layout is
///
/// ```text
/// [service_id, GO_number(2), GO_config(2), Size(1), DPT_ID(4)]
/// ```
///
/// `GO_config` packs `Linked`, `conf`/`auth`, and the Group Object
/// Descriptor high octet into a single 16-bit big-endian word:
///
/// ```text
/// bit  15..11 : reserved (0)
/// bit      10 : L (linked — 1 iff ≥1 GA is linked to this GO)
/// bit       9 : conf
/// bit       8 : auth
/// bits   7..0 : GO-descriptor high octet — `[U T I W R C Prio(2)]`
/// ```
///
/// `Size` is a 1-octet Value Field Type code per Realisation Type 7
/// Table 87 (same `u8` as `ComObjectType` — e.g. `0` = Uint1, `7` = Byte1,
/// `9` = Byte3); **not** a raw byte count.
///
/// `DPT_ID` is the concatenation of the Datapoint Type main number (2
/// octets, big-endian) and sub number (2 octets, big-endian). The spec
/// explicitly allows emitting `00 00 00 00` when the device does not
/// track DPT identifiers for its GOs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoConfigResponse {
    /// ReadServiceID echoed back — always 0x00 for this response.
    pub service_id: u8,
    /// Group Object number (ASAP) being queried.
    pub go_idx: u16,
    /// Packed 16-bit GO_config word per Figure 23. Callers compose this
    /// from `linked`, `conf`, `auth`, and the GO descriptor high octet
    /// — see [`GoConfigResponse::pack_config`].
    pub go_config: u16,
    /// Value Field Type code (1 octet) per Realisation Type 7 Table 87
    /// — the `ComObjectType` enum's numeric value, not a raw byte count.
    pub size: u8,
    /// Datapoint Type main number (2 octets, big-endian).
    pub dpt_main: u16,
    /// Datapoint Type sub number (2 octets, big-endian).
    pub dpt_sub: u16,
}

impl GoConfigResponse {
    /// On-wire length of the response body, in bytes.
    ///
    /// Layout: `svc(1) + GO(2) + cfg(2) + size(1) + dpt(4) = 10`.
    pub const LEN: usize = 10;

    /// Pack the GO_config 16-bit word from its components (Figure 23).
    pub const fn pack_config(linked: bool, conf: bool, auth: bool, descriptor_hi: u8) -> u16 {
        let l = if linked { 1u16 << 10 } else { 0 };
        let c = if conf { 1u16 << 9 } else { 0 };
        let a = if auth { 1u16 << 8 } else { 0 };
        l | c | a | descriptor_hi as u16
    }

    /// Write the body into `buf` and return the populated prefix.
    pub fn write(self, buf: &mut [u8; Self::LEN]) -> &[u8] {
        buf[0] = self.service_id;
        buf[1..3].copy_from_slice(&self.go_idx.to_be_bytes());
        buf[3..5].copy_from_slice(&self.go_config.to_be_bytes());
        buf[5] = self.size;
        buf[6..8].copy_from_slice(&self.dpt_main.to_be_bytes());
        buf[8..10].copy_from_slice(&self.dpt_sub.to_be_bytes());
        &buf[..Self::LEN]
    }
}

// ============================================================================
// PID_GO_DIAGNOSTICS — status-plus-value success envelope
// ============================================================================

/// Response body for the `E_GD_GO_STATUS_VALUE` success path (return code
/// 0x21) used by:
///
/// - `WriteServiceID 0x00` (Set local GO value) — echoes the stored value
/// - `WriteServiceID 0x02` (Transmit current GO value) — echoes the sent value
/// - `ReadServiceID  0x01` (Get local GO value)
///
/// Wire: `[service_id, GO_hi, GO_lo, status, value...]` — the value
/// length is carried implicitly by the total response length.
///
/// The caller supplies a backing buffer large enough to hold the
/// envelope plus `value.len()` bytes. The writer copies up to
/// `buf.len() - HEADER_LEN` payload bytes; anything beyond is silently
/// truncated to match the buffer capacity.
#[derive(Debug, Clone, Copy)]
pub struct GoStatusValueResponse<'a> {
    pub service_id: u8,
    pub go_idx: u16,
    pub status: u8,
    pub value: &'a [u8],
}

impl<'a> GoStatusValueResponse<'a> {
    /// Length of the header before the value payload.
    pub const HEADER_LEN: usize = 4;

    /// Total response length for a given value length.
    pub const fn len(value_len: usize) -> usize {
        Self::HEADER_LEN + value_len
    }

    /// Write the body into `buf` and return the populated prefix.
    ///
    /// Clamps the value copy to the buffer's capacity so a short buffer
    /// does not panic — excess value bytes are dropped. Returns the
    /// slice actually written, including the truncated payload length.
    pub fn write<'b>(self, buf: &'b mut [u8]) -> &'b [u8] {
        debug_assert!(
            buf.len() >= Self::HEADER_LEN,
            "GoStatusValueResponse: buffer too small to hold the 4-byte header",
        );
        buf[0] = self.service_id;
        buf[1..3].copy_from_slice(&self.go_idx.to_be_bytes());
        buf[3] = self.status;
        let value_capacity = buf.len() - Self::HEADER_LEN;
        let value_len = self.value.len().min(value_capacity);
        buf[Self::HEADER_LEN..Self::HEADER_LEN + value_len].copy_from_slice(&self.value[..value_len]);
        &buf[..Self::HEADER_LEN + value_len]
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_mode_response_layout() {
        let resp = OperationModeResponse { service_id: 0x00, operation_mode: 0x01, time_left: 0x1E };
        let mut buf = [0u8; OperationModeResponse::LEN];
        assert_eq!(resp.write(&mut buf), &[0x00, 0x01, 0x1E]);
    }

    #[test]
    fn go_config_pack_spec_example() {
        // Spec §4.8.1.1.6 Figure 23 — worked example matching the conformance
        // reference 6.2.24 response for a GO that is linked, A+C secured,
        // and has descriptor hi octet 0x5F (U=0 T=1 I=0 W=1 R=1 C=1 Prio=3).
        // Expected packed word: L=1 conf=1 auth=1 | 0x5F = 0x075F.
        assert_eq!(GoConfigResponse::pack_config(true, true, true, 0x5F), 0x075F);
        // Plain (no security), linked, descriptor 0xDB → 0x04DB.
        assert_eq!(GoConfigResponse::pack_config(true, false, false, 0xDB), 0x04DB);
        // Unlinked, plain, descriptor 0x00 → 0x0000.
        assert_eq!(GoConfigResponse::pack_config(false, false, false, 0x00), 0x0000);
    }

    #[test]
    fn go_config_response_layout() {
        // Conformance 6.2.24 response for GO #1 (linked, A+C, descriptor 0x5F):
        // body = svcID 00 | GO 00 01 | cfg 07 5F | size 00 | dpt 00 00 00 00.
        let resp = GoConfigResponse {
            service_id: 0x00,
            go_idx: 0x0001,
            go_config: 0x075F,
            size: 0x00,
            dpt_main: 0x0000,
            dpt_sub: 0x0000,
        };
        let mut buf = [0u8; GoConfigResponse::LEN];
        assert_eq!(resp.write(&mut buf), &[0x00, 0x00, 0x01, 0x07, 0x5F, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn go_status_value_response_writes_header_and_payload() {
        let value = [0xDE, 0xAD, 0xBE, 0xEF];
        let resp = GoStatusValueResponse { service_id: 0x01, go_idx: 0x0007, status: 0x00, value: &value };
        let mut buf = [0u8; 16];
        let out = resp.write(&mut buf);
        assert_eq!(out, &[0x01, 0x00, 0x07, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn go_status_value_response_empty_value() {
        let resp = GoStatusValueResponse { service_id: 0x00, go_idx: 0x0000, status: 0x00, value: &[] };
        let mut buf = [0u8; 4];
        assert_eq!(resp.write(&mut buf), &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn go_status_value_response_truncates_to_capacity() {
        let value = [1u8; 100];
        let resp = GoStatusValueResponse { service_id: 0x02, go_idx: 0x0001, status: 0x00, value: &value };
        // Buffer only fits 4 header + 8 payload = 12 bytes.
        let mut buf = [0u8; 12];
        let out = resp.write(&mut buf);
        assert_eq!(out.len(), 12);
        assert_eq!(&out[..4], &[0x02, 0x00, 0x01, 0x00]);
        assert!(out[4..].iter().all(|&b| b == 1));
    }
}
