//! KNX IP Secure Messages (03/08/09 §2.2)
//!
//! Frame codecs for the secure service family `09xxh`:
//!
//! - `SessionRequest` / `SessionResponse` / `SessionAuthenticate` /
//!   `SessionStatus` — the TCP-only unicast session handshake
//! - `SecureWrapper` — encrypted encapsulation of an inner KNXnet/IP
//!   frame (unicast sessions and, later, multicast routing)
//! - `TimerNotify` — multicast timer synchronisation (codec only; the
//!   timer state machine is not implemented yet)
//!
//! Codecs are crypto-free by design: the CCM wrap/unwrap and the
//! handshake MACs live in `crate::crypto::ip_secure_ccm`, keyed by
//! material these structs merely transport. `SecureWrapper::parse`
//! therefore leaves `encrypted payload | MAC(16)` in the caller's
//! buffer view — decryption happens in place on the receive buffer.

use core::mem;

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, SplitByteSlice, SplitByteSliceMut, Unaligned, big_endian::U16,
};

use crate::{messages::knxip::error::*, util::packets::*};

use super::{super::substructs::*, KNXnetIPServiceType, KNXnetIPVersion, raw::KNXnetIPHeader};

create_protocol_enum!(
    #[allow(missing_docs)]
    #[derive(Eq, PartialEq, Copy, Clone)]
    /// SESSION_STATUS status codes (03/08/09 §2.2.3.9.2)
    pub enum SessionStatusCode: u8 {
        AuthenticationSuccess, 0x00, "Authentication Success";
        AuthenticationFailed, 0x01, "Authentication Failed";
        Unauthenticated, 0x02, "Unauthenticated";
        Timeout, 0x03, "Timeout";
        Keepalive, 0x04, "Keepalive";
        Close, 0x05, "Close";
        _, "Unknown Session Status 0x{:x}";
    }
);

// ============================================================================
// INTERNAL WIRE FORMAT - ZEROCOPY TYPES
// ============================================================================

mod raw {
    use super::*;

    /// SESSION_RESPONSE body (50 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct SessionResponseBody {
        pub session_id: U16,
        pub public_key: [u8; 32],
        pub mac: [u8; 16],
    }

    /// SESSION_AUTHENTICATE body (18 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct SessionAuthenticateBody {
        pub reserved: u8,
        pub user_id: u8,
        pub mac: [u8; 16],
    }

    /// SESSION_STATUS body (2 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct SessionStatusBody {
        pub status: u8,
        pub reserved: u8,
    }

    /// SECURE_WRAPPER security information block (16 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct SecureWrapperInfo {
        pub session_id: U16,
        pub seq_info: [u8; 6],
        pub serial_number: [u8; 6],
        pub message_tag: [u8; 2],
    }

    /// TIMER_NOTIFY body (30 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct TimerNotifyBody {
        pub timer_value: [u8; 6],
        pub serial_number: [u8; 6],
        pub message_tag: [u8; 2],
        pub mac: [u8; 16],
    }
}

// ============================================================================
// SESSION_REQUEST
// ============================================================================

/// KNXnet/IP SESSION_REQUEST (§2.2.3.6)
///
/// Opens a secure unicast session. TCP-only: the control endpoint HPAI
/// must be a route-back HPAI (TCP, address and port all zero).
#[derive(Debug, Clone)]
pub struct SessionRequest {
    pub control_endpoint: HPAI,
    /// Diffie-Hellman client public value X (Curve25519).
    pub public_key: [u8; 32],
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for SessionRequest {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::from(header.service_type.get()) != KNXnetIPServiceType::SessionRequest {
            return Err(ParseError::Format);
        }

        let control_endpoint = HPAI::parse(buffer, ())?;

        let key_bytes = buffer.take_front(32).ok_or(ParseError::Format)?;
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(key_bytes.as_ref());

        Ok(SessionRequest { control_endpoint, public_key })
    }
}

/// Builder for SessionRequest message
pub struct SessionRequestBuilder {
    pub control_endpoint: HPAI,
    pub public_key: [u8; 32],
}

impl SessionRequestBuilder {
    pub fn new(control_endpoint: HPAI, public_key: [u8; 32]) -> Self {
        Self { control_endpoint, public_key }
    }
}

impl SerializablePacket for SessionRequestBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + self.control_endpoint.bytes_len() + 32
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::SessionRequest)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        self.control_endpoint.serialize(bv);

        let mut key_buf = bv.take_front(32).expect("too few bytes for public key");
        key_buf.as_mut().copy_from_slice(&self.public_key);
    }
}

// ============================================================================
// SESSION_RESPONSE
// ============================================================================

/// KNXnet/IP SESSION_RESPONSE (§2.2.3.7)
///
/// Server's answer to a SESSION_REQUEST: the assigned session
/// identifier, the server's public value Y, and the MAC keyed with the
/// device authentication code (see
/// `crypto::ip_secure_ccm::session_response_mac`).
#[derive(Debug, Clone)]
pub struct SessionResponse {
    pub session_id: u16,
    /// Diffie-Hellman server public value Y (Curve25519).
    pub public_key: [u8; 32],
    pub mac: [u8; 16],
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for SessionResponse {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::from(header.service_type.get()) != KNXnetIPServiceType::SessionResponse {
            return Err(ParseError::Format);
        }

        let body = buffer.take_obj_front::<raw::SessionResponseBody>().ok_or(ParseError::Format)?;

        Ok(SessionResponse { session_id: body.session_id.get(), public_key: body.public_key, mac: body.mac })
    }
}

/// Builder for SessionResponse message
pub struct SessionResponseBuilder {
    pub session_id: u16,
    pub public_key: [u8; 32],
    pub mac: [u8; 16],
}

impl SessionResponseBuilder {
    pub fn new(session_id: u16, public_key: [u8; 32], mac: [u8; 16]) -> Self {
        Self { session_id, public_key, mac }
    }
}

impl SerializablePacket for SessionResponseBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::SessionResponseBody>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::SessionResponse)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let body =
            raw::SessionResponseBody { session_id: self.session_id.into(), public_key: self.public_key, mac: self.mac };
        bv.write_obj_front(&body).expect("too few bytes for session response body");
    }
}

// ============================================================================
// SESSION_AUTHENTICATE
// ============================================================================

/// KNXnet/IP SESSION_AUTHENTICATE (§2.2.3.8)
///
/// Always arrives inside a SECURE_WRAPPER. The MAC is keyed with the
/// password hash of `user_id` (see
/// `crypto::ip_secure_ccm::session_authenticate_mac`).
#[derive(Debug, Clone, Copy)]
pub struct SessionAuthenticate {
    /// Reserved octet — `00h` per spec; exposed so the session handler
    /// can reject non-zero values explicitly.
    pub reserved: u8,
    pub user_id: u8,
    pub mac: [u8; 16],
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for SessionAuthenticate {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::from(header.service_type.get()) != KNXnetIPServiceType::SessionAuthenticate {
            return Err(ParseError::Format);
        }

        let body = buffer.take_obj_front::<raw::SessionAuthenticateBody>().ok_or(ParseError::Format)?;

        Ok(SessionAuthenticate { reserved: body.reserved, user_id: body.user_id, mac: body.mac })
    }
}

/// Builder for SessionAuthenticate message
pub struct SessionAuthenticateBuilder {
    pub user_id: u8,
    pub mac: [u8; 16],
}

impl SessionAuthenticateBuilder {
    pub fn new(user_id: u8, mac: [u8; 16]) -> Self {
        Self { user_id, mac }
    }
}

impl SerializablePacket for SessionAuthenticateBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::SessionAuthenticateBody>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::SessionAuthenticate)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let body = raw::SessionAuthenticateBody { reserved: 0, user_id: self.user_id, mac: self.mac };
        bv.write_obj_front(&body).expect("too few bytes for session authenticate body");
    }
}

// ============================================================================
// SESSION_STATUS
// ============================================================================

/// KNXnet/IP SESSION_STATUS (§2.2.3.9)
///
/// Carries handshake results (AuthenticationSuccess/Failed), keepalives,
/// and session teardown notifications. Sent wrapped once a session key
/// is agreed, plain only before (e.g. on a failed SESSION_REQUEST).
#[derive(Debug, Clone, Copy)]
pub struct SessionStatus {
    pub status: SessionStatusCode,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for SessionStatus {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::from(header.service_type.get()) != KNXnetIPServiceType::SessionStatus {
            return Err(ParseError::Format);
        }

        let body = buffer.take_obj_front::<raw::SessionStatusBody>().ok_or(ParseError::Format)?;

        Ok(SessionStatus { status: body.status.into() })
    }
}

/// Builder for SessionStatus message
pub struct SessionStatusBuilder {
    pub status: SessionStatusCode,
}

impl SessionStatusBuilder {
    pub fn new(status: SessionStatusCode) -> Self {
        Self { status }
    }
}

impl SerializablePacket for SessionStatusBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::SessionStatusBody>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::SessionStatus)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let body = raw::SessionStatusBody { status: self.status.into(), reserved: 0 };
        bv.write_obj_front(&body).expect("too few bytes for session status body");
    }
}

// ============================================================================
// SECURE_WRAPPER
// ============================================================================

/// Bytes a SECURE_WRAPPER adds around the encapsulated frame:
/// 6 B header + 16 B security information + 16 B MAC (§2.2.1.3.3).
pub const SECURE_WRAPPER_OVERHEAD: usize = 38;

/// KNXnet/IP SECURE_WRAPPER (§2.2.1.3) — security information only.
///
/// `parse` consumes the KNXnet/IP header and the 16-byte security
/// information block, validates that exactly
/// `encrypted payload | MAC(16)` remains per the header's total length,
/// and **leaves those bytes in the caller's buffer view** — the caller
/// runs `crypto::ip_secure_ccm::unwrap_secure` in place on its receive
/// buffer and re-dispatches the decrypted inner frame.
#[derive(Debug, Clone, Copy)]
pub struct SecureWrapper {
    pub session_id: u16,
    /// 6-byte sequence information (unicast: session sequence number).
    pub seq_info: [u8; 6],
    /// 6-byte KNX serial number of the sender.
    pub serial_number: [u8; 6],
    /// 2-byte message tag (`0000h` on unicast sessions).
    pub message_tag: [u8; 2],
    /// Length of the encrypted encapsulated frame (excluding the MAC).
    pub payload_len: usize,
}

impl SecureWrapper {
    /// The 8 bytes of associated data the CCM MAC covers: the wrapper's
    /// KNXnet/IP header followed by the session identifier.
    pub fn associated_data(session_id: u16, payload_len: usize) -> [u8; 8] {
        let total = (payload_len + SECURE_WRAPPER_OVERHEAD) as u16;
        let mut assoc = [0u8; 8];
        assoc[0] = mem::size_of::<KNXnetIPHeader>() as u8;
        assoc[1] = KNXnetIPVersion::Version10.into();
        assoc[2..4].copy_from_slice(&u16::from(KNXnetIPServiceType::SecureWrapper).to_be_bytes());
        assoc[4..6].copy_from_slice(&total.to_be_bytes());
        assoc[6..8].copy_from_slice(&session_id.to_be_bytes());
        assoc
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for SecureWrapper {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::from(header.service_type.get()) != KNXnetIPServiceType::SecureWrapper {
            return Err(ParseError::Format);
        }

        let info = buffer.take_obj_front::<raw::SecureWrapperInfo>().ok_or(ParseError::Format)?;

        // The remainder is `encrypted payload | MAC(16)`. The payload must
        // contain at least an inner KNXnet/IP header (6 bytes), giving the
        // 44-byte minimum total frame size from §2.2.1.3.3.
        let payload_len =
            (header.total_length.get() as usize).checked_sub(SECURE_WRAPPER_OVERHEAD).ok_or(ParseError::Format)?;
        if payload_len < mem::size_of::<KNXnetIPHeader>() || buffer.len() < payload_len + 16 {
            return Err(ParseError::Format);
        }

        Ok(SecureWrapper {
            session_id: info.session_id.get(),
            seq_info: info.seq_info,
            serial_number: info.serial_number,
            message_tag: info.message_tag,
            payload_len,
        })
    }
}

/// Builder for SecureWrapper message.
///
/// `encrypted_payload` and `mac` come out of
/// `crypto::ip_secure_ccm::wrap_secure`, called with
/// [`SecureWrapper::associated_data`] of the same session id and
/// payload length.
pub struct SecureWrapperBuilder<'a> {
    pub session_id: u16,
    pub seq_info: [u8; 6],
    pub serial_number: [u8; 6],
    pub message_tag: [u8; 2],
    pub encrypted_payload: &'a [u8],
    pub mac: [u8; 16],
}

impl<'a> SecureWrapperBuilder<'a> {
    pub fn new(
        session_id: u16,
        seq_info: [u8; 6],
        serial_number: [u8; 6],
        message_tag: [u8; 2],
        encrypted_payload: &'a [u8],
        mac: [u8; 16],
    ) -> Self {
        Self { session_id, seq_info, serial_number, message_tag, encrypted_payload, mac }
    }
}

impl SerializablePacket for SecureWrapperBuilder<'_> {
    fn bytes_len(&self) -> usize {
        self.encrypted_payload.len() + SECURE_WRAPPER_OVERHEAD
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::SecureWrapper)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let info = raw::SecureWrapperInfo {
            session_id: self.session_id.into(),
            seq_info: self.seq_info,
            serial_number: self.serial_number,
            message_tag: self.message_tag,
        };
        bv.write_obj_front(&info).expect("too few bytes for security information");

        let mut payload_buf = bv.take_front(self.encrypted_payload.len()).expect("too few bytes for payload");
        payload_buf.as_mut().copy_from_slice(self.encrypted_payload);

        let mut mac_buf = bv.take_front(16).expect("too few bytes for MAC");
        mac_buf.as_mut().copy_from_slice(&self.mac);
    }
}

// ============================================================================
// TIMER_NOTIFY
// ============================================================================

/// KNXnet/IP TIMER_NOTIFY (§2.2.2.4)
///
/// Multicast timer synchronisation. Codec only for now — the timer
/// state machine ships with secure routing support.
#[derive(Debug, Clone, Copy)]
pub struct TimerNotify {
    pub timer_value: [u8; 6],
    pub serial_number: [u8; 6],
    pub message_tag: [u8; 2],
    pub mac: [u8; 16],
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for TimerNotify {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::from(header.service_type.get()) != KNXnetIPServiceType::TimerNotify {
            return Err(ParseError::Format);
        }

        let body = buffer.take_obj_front::<raw::TimerNotifyBody>().ok_or(ParseError::Format)?;

        Ok(TimerNotify {
            timer_value: body.timer_value,
            serial_number: body.serial_number,
            message_tag: body.message_tag,
            mac: body.mac,
        })
    }
}

/// Builder for TimerNotify message
pub struct TimerNotifyBuilder {
    pub timer_value: [u8; 6],
    pub serial_number: [u8; 6],
    pub message_tag: [u8; 2],
    pub mac: [u8; 16],
}

impl SerializablePacket for TimerNotifyBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::TimerNotifyBody>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::TimerNotify)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let body = raw::TimerNotifyBody {
            timer_value: self.timer_value,
            serial_number: self.serial_number,
            message_tag: self.message_tag,
            mac: self.mac,
        };
        bv.write_obj_front(&body).expect("too few bytes for timer notify body");
    }
}

// ============================================================================
// Tests using spec Appendix A binary examples
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::packets::{ParseBuffer, SerializeBuffer};
    use core::net::Ipv4Addr;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|h| u8::from_str_radix(h, 16).expect("valid hex")).collect()
    }

    fn serialize_to_vec<P: SerializablePacket>(packet: &P) -> Vec<u8> {
        let mut storage = vec![0u8; packet.bytes_len()];
        let mut buf = storage.as_mut_slice();
        let (written, _) = SerializeBuffer::serialize(&mut buf, packet);
        written.to_vec()
    }

    // ----------------------------------------------------------------
    // A.1.2 — SESSION_REQUEST
    // ----------------------------------------------------------------
    const SESSION_REQUEST_FRAME: &str = "06 10 09 51 00 2e 08 02 00 00 00 00 00 00 \
         0a a2 27 b4 fd 7a 32 31 9b a9 96 0a c0 36 ce 0e \
         5c 45 07 b5 ae 55 16 1f 10 78 b1 dc fb 3c b6 31";

    #[test]
    fn appendix_a1_session_request_roundtrip() {
        let frame = hex(SESSION_REQUEST_FRAME);

        let mut bv = frame.as_slice();
        let parsed: SessionRequest = bv.parse().expect("parse Appendix A.1.2 frame");
        assert_eq!(parsed.control_endpoint, HPAI::ipv4_tcp(Ipv4Addr::UNSPECIFIED, 0));
        assert_eq!(parsed.public_key[0], 0x0a);
        assert_eq!(parsed.public_key[31], 0x31);

        let builder = SessionRequestBuilder::new(parsed.control_endpoint, parsed.public_key);
        assert_eq!(serialize_to_vec(&builder), frame);
    }

    // ----------------------------------------------------------------
    // A.2.3 — SESSION_RESPONSE
    // ----------------------------------------------------------------
    const SESSION_RESPONSE_FRAME: &str = "06 10 09 52 00 38 00 01 \
         bd f0 99 90 99 23 14 3e f0 a5 de 0b 3b e3 68 7b \
         c5 bd 3c f5 f9 e6 f9 01 69 9c d8 70 ec 1f f8 24 \
         a9 22 50 5a aa 43 61 63 57 0b d5 49 4c 2d f2 a3";

    #[test]
    fn appendix_a2_session_response_roundtrip() {
        let frame = hex(SESSION_RESPONSE_FRAME);

        let mut bv = frame.as_slice();
        let parsed: SessionResponse = bv.parse().expect("parse Appendix A.2.3 frame");
        assert_eq!(parsed.session_id, 0x0001);
        assert_eq!(parsed.public_key[0], 0xbd);
        assert_eq!(parsed.mac[0], 0xa9);

        let builder = SessionResponseBuilder::new(parsed.session_id, parsed.public_key, parsed.mac);
        assert_eq!(serialize_to_vec(&builder), frame);
    }

    // ----------------------------------------------------------------
    // A.3.2 — SESSION_AUTHENTICATE
    // ----------------------------------------------------------------
    const SESSION_AUTHENTICATE_FRAME: &str = "06 10 09 53 00 18 00 01 1f 1d 59 ea 9f 12 a1 52 e5 d9 72 7f 08 46 2c de";

    #[test]
    fn appendix_a3_session_authenticate_roundtrip() {
        let frame = hex(SESSION_AUTHENTICATE_FRAME);

        let mut bv = frame.as_slice();
        let parsed: SessionAuthenticate = bv.parse().expect("parse Appendix A.3.2 frame");
        assert_eq!(parsed.reserved, 0x00);
        assert_eq!(parsed.user_id, 0x01);
        assert_eq!(parsed.mac[0], 0x1f);

        let builder = SessionAuthenticateBuilder::new(parsed.user_id, parsed.mac);
        assert_eq!(serialize_to_vec(&builder), frame);
    }

    // ----------------------------------------------------------------
    // A.4.1 — SESSION_STATUS
    // ----------------------------------------------------------------
    #[test]
    fn appendix_a4_session_status_roundtrip() {
        let frame = hex("06 10 09 54 00 08 00 00");

        let mut bv = frame.as_slice();
        let parsed: SessionStatus = bv.parse().expect("parse Appendix A.4.1 frame");
        assert_eq!(parsed.status, SessionStatusCode::AuthenticationSuccess);

        let builder = SessionStatusBuilder::new(parsed.status);
        assert_eq!(serialize_to_vec(&builder), frame);
    }

    // ----------------------------------------------------------------
    // A.3.4 — SECURE_WRAPPER around SESSION_AUTHENTICATE
    // ----------------------------------------------------------------
    const WRAPPED_AUTHENTICATE_FRAME: &str = "06 10 09 50 00 3e 00 01 \
         00 00 00 00 00 00 00 fa 12 34 56 78 af fe \
         79 15 a4 f3 6e 6e 42 08 d2 8b 4a 20 7d 8f 35 c0 \
         d1 38 c2 6a 7b 5e 71 69 \
         52 db a8 e7 e4 bd 80 bd 7d 86 8a 3a e7 87 49 de";

    #[test]
    fn appendix_a3_secure_wrapper_roundtrip() {
        let frame = hex(WRAPPED_AUTHENTICATE_FRAME);

        let mut bv = frame.as_slice();
        let parsed: SecureWrapper = bv.parse().expect("parse Appendix A.3.4 frame");
        assert_eq!(parsed.session_id, 0x0001);
        assert_eq!(parsed.seq_info, [0; 6]);
        assert_eq!(parsed.serial_number, [0x00, 0xfa, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(parsed.message_tag, [0xaf, 0xfe]);
        assert_eq!(parsed.payload_len, 24);

        // Encrypted payload and MAC remain in the buffer view.
        assert_eq!(bv.len(), 24 + 16);
        let (ciphertext, mac) = bv.split_at(24);
        assert_eq!(
            ciphertext,
            hex("79 15 a4 f3 6e 6e 42 08 d2 8b 4a 20 7d 8f 35 c0 d1 38 c2 6a 7b 5e 71 69").as_slice()
        );

        // Associated data helper reproduces the wrapper header bytes.
        assert_eq!(SecureWrapper::associated_data(parsed.session_id, parsed.payload_len), [
            0x06, 0x10, 0x09, 0x50, 0x00, 0x3e, 0x00, 0x01
        ]);

        let builder = SecureWrapperBuilder::new(
            parsed.session_id,
            parsed.seq_info,
            parsed.serial_number,
            parsed.message_tag,
            ciphertext,
            mac.try_into().expect("16-byte MAC"),
        );
        assert_eq!(serialize_to_vec(&builder), frame);
    }

    #[test]
    fn secure_wrapper_too_short_rejected() {
        // Total length 43 < the 44-byte minimum (overhead + inner header).
        let mut frame = hex(WRAPPED_AUTHENTICATE_FRAME);
        frame[4..6].copy_from_slice(&43u16.to_be_bytes());
        frame.truncate(43);

        let mut bv = frame.as_slice();
        assert!(bv.parse::<SecureWrapper>().is_err());
    }

    // ----------------------------------------------------------------
    // A.6.2 — TIMER_NOTIFY
    // ----------------------------------------------------------------
    const TIMER_NOTIFY_FRAME: &str = "06 10 09 55 00 24 c0 c1 c2 c3 c4 c5 00 fa 12 34 56 78 af fe \
         ee 7b 9b 30 83 de b1 57 0e b3 8d 07 3a da d9 85";

    #[test]
    fn appendix_a6_timer_notify_roundtrip() {
        let frame = hex(TIMER_NOTIFY_FRAME);

        let mut bv = frame.as_slice();
        let parsed: TimerNotify = bv.parse().expect("parse Appendix A.6.2 frame");
        assert_eq!(parsed.timer_value, [0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5]);
        assert_eq!(parsed.serial_number, [0x00, 0xfa, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(parsed.message_tag, [0xaf, 0xfe]);

        let builder = TimerNotifyBuilder {
            timer_value: parsed.timer_value,
            serial_number: parsed.serial_number,
            message_tag: parsed.message_tag,
            mac: parsed.mac,
        };
        assert_eq!(serialize_to_vec(&builder), frame);
    }
}
