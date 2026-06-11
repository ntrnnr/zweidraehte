//! KNX IP Secure session state machine (03/08/09 §2.2.3.5.2).
//!
//! Implements the server side of the secure unicast session protocol:
//!
//! ```text
//! Client                          Server (this module)
//!   SESSION_REQUEST(X)        ──▶  E00: allocate, ECDH, respond
//!   ◀── SESSION_RESPONSE(Y ‖ CCM_DAC(X⊕Y))
//!   WRAP(SESSION_AUTHENTICATE) ──▶ E01/E02: verify password MAC
//!   ◀── WRAP(SESSION_STATUS Success/Failed)
//!   WRAP(any KNXnet/IP frame)  ──▶ E05: decrypt, re-dispatch inner
//!   WRAP(STATUS Keepalive)     ──▶ E04: re-arm session timer
//!   WRAP(STATUS Close)         ──▶ E03: confirm close, deallocate
//! ```
//!
//! Event/action labels in comments refer to the transition table in
//! §2.2.3.5.2.5 (E00–E06) and the action list in §2.2.3.5.2.4 (A0–A6).
//! Frames that fail validation are discarded without response, per the
//! error-handling rules in §2.2.3.3 — only state-machine actions emit
//! SESSION_STATUS frames.
//!
//! Only compiled with the `ip-secure` cargo feature; reached through
//! the [`WithIpSecure`](super::secure::WithIpSecure) hooks.

use embassy_time::Instant;
use heapless::Vec;

use zweidraehte_proto::crypto::ip_secure_ccm::{self, IpSecureNonce};
use zweidraehte_proto::crypto::session_key;
use zweidraehte_proto::messages::knxip::{
    KNXnetIPServiceType, SecureWrapper, SecureWrapperBuilder, SessionAuthenticate, SessionRequest,
    SessionResponseBuilder, SessionStatus, SessionStatusBuilder, SessionStatusCode, peek_service_type,
    substructs::HPAI,
};
use zweidraehte_proto::util::packets::{ParseBuffer, SerializablePacket, SerializeBuffer};

use super::secure::{
    ExpiredSession, IpSecureSessionSlot, SECURE_RESPONSE_MAX, SECURE_WRAPPER_OVERHEAD, SecureEnv, SecureFrameOutcome,
    SecureResponses, SecureSessionState, SessionPool, session_timeouts, user_id,
};

type Pool<const N: usize> = SessionPool<IpSecureSessionSlot, N>;
type ResponseBytes = Vec<u8, SECURE_RESPONSE_MAX>;

/// Lower 48 bits of a sequence counter as the big-endian wire format.
fn seq48(seq: u64) -> [u8; 6] {
    let bytes = seq.to_be_bytes();
    [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
}

/// 48-bit big-endian sequence information as a counter value.
fn seq_to_u64(seq_info: &[u8; 6]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes[2..8].copy_from_slice(seq_info);
    u64::from_be_bytes(bytes)
}

/// Serialize a packet into a fixed-capacity byte vector.
fn serialize_to_vec<P: SerializablePacket>(packet: &P) -> ResponseBytes {
    let mut out = ResponseBytes::new();
    out.resize(packet.bytes_len(), 0).expect("secure handshake frames fit SECURE_RESPONSE_MAX");
    let mut buf = out.as_mut_slice();
    SerializeBuffer::serialize(&mut buf, packet);
    out
}

/// Build a SESSION_STATUS wrapped for `slot`'s session, consuming one
/// send sequence number. Status frames are only ever sent inside a
/// SECURE_WRAPPER (§2.2.3.9.1).
fn build_wrapped_status(
    slot: &mut IpSecureSessionSlot,
    serial_number: &[u8; 6],
    status: SessionStatusCode,
) -> ResponseBytes {
    let mut plain = [0u8; 8];
    {
        let mut buf = &mut plain[..];
        SerializeBuffer::serialize(&mut buf, &SessionStatusBuilder::new(status));
    }

    let seq_info = seq48(slot.next_send_seq());
    // The message tag is meaningless on unicast sessions (the receiver
    // reconstructs the nonce from the frame fields); we always send 0.
    let message_tag = [0u8; 2];
    let assoc = SecureWrapper::associated_data(slot.session_id, plain.len());
    let nonce = IpSecureNonce { seq_info, serial_number: *serial_number, message_tag };
    let mac = ip_secure_ccm::wrap_secure(&slot.session_key, &nonce, &assoc, &mut plain);

    serialize_to_vec(&SecureWrapperBuilder::new(slot.session_id, seq_info, *serial_number, message_tag, &plain, mac))
}

// ============================================================================
// Top-level dispatch
// ============================================================================

pub(super) fn handle_secure_frame<const N: usize>(
    pool: &mut Pool<N>,
    frame: &[u8],
    tcp_idx: Option<usize>,
    env: &SecureEnv<'_>,
    scratch: &mut [u8],
    responses: &mut SecureResponses,
) -> SecureFrameOutcome {
    const HANDLED: SecureFrameOutcome = SecureFrameOutcome::Handled { closed_session: None };

    let Ok(service_type) = peek_service_type(frame) else {
        return HANDLED;
    };

    if env.config.is_none() {
        // Feature enabled but the device state carries no IP Secure
        // storage — refuse rather than answer with garbage keys.
        warn!("IP Secure frame {:?} dropped: device has no IP Secure configuration", service_type);
        return HANDLED;
    }

    match service_type {
        KNXnetIPServiceType::SessionRequest => {
            handle_session_request(pool, frame, tcp_idx, env, responses);
            HANDLED
        }
        KNXnetIPServiceType::SecureWrapper => handle_wrapper(pool, frame, tcp_idx, env, scratch, responses),
        // TIMER_NOTIFY belongs to secure multicast (routing) — not
        // implemented yet. SESSION_RESPONSE is client-side only;
        // SESSION_AUTHENTICATE / SESSION_STATUS must arrive wrapped
        // (§2.2.3.8.1 / §2.2.3.9.1) — plain arrivals are discarded.
        _ => {
            debug!("Dropping top-level secure frame {:?}", service_type);
            HANDLED
        }
    }
}

// ============================================================================
// E00: SESSION_REQUEST
// ============================================================================

fn handle_session_request<const N: usize>(
    pool: &mut Pool<N>,
    frame: &[u8],
    tcp_idx: Option<usize>,
    env: &SecureEnv<'_>,
    responses: &mut SecureResponses,
) {
    // Secure unicast sessions are TCP-only; SESSION_REQUEST received
    // via UDP shall be discarded (§2.2.3.3).
    let Some(tcp_idx) = tcp_idx else {
        debug!("SESSION_REQUEST over UDP discarded");
        return;
    };

    let mut buf = frame;
    let Ok(request) = buf.parse::<SessionRequest>() else {
        debug!("Malformed SESSION_REQUEST discarded");
        return;
    };

    // The control endpoint must be a TCP route-back HPAI (§2.2.3.6.2).
    if !matches!(request.control_endpoint, HPAI::Ipv4Tcp { .. }) {
        debug!("SESSION_REQUEST with non-TCP control HPAI discarded");
        return;
    }

    let config = env.config.expect("checked by caller");

    let Some(slot_idx) = pool.slots.iter().position(|s| s.session_state == SecureSessionState::Idle) else {
        // TODO: spec behavior when the session pool is exhausted is not
        // explicit for the unicast case — we silently drop, the client
        // runs into its 10 s response timeout.
        warn!("SESSION_REQUEST dropped: no free secure session slot");
        return;
    };

    // A0: allocate session, ECDH, send SESSION_RESPONSE, arm
    // timeoutAuthentication.
    let mut entropy = [0u8; 32];
    (env.rng_fill)(&mut entropy);
    let (server_private, server_public) = session_key::generate_keypair(&entropy);
    let shared_secret = session_key::x25519_dh(&server_private, &request.public_key);
    let derived_key = session_key::derive_session_key(&shared_secret);

    // Non-zero session identifier, skipping IDs still in use.
    let session_id = loop {
        let candidate = pool.next_session_id;
        pool.next_session_id = pool.next_session_id.wrapping_add(1).max(1);
        if !pool.slots.iter().any(|s| s.session_state != SecureSessionState::Idle && s.session_id == candidate) {
            break candidate;
        }
    };

    let xor_xy = ip_secure_ccm::xor_public_keys(&request.public_key, &server_public);
    let mac = ip_secure_ccm::session_response_mac(&config.device_authentication_code(), session_id, &xor_xy);

    let slot = &mut pool.slots[slot_idx];
    slot.reset();
    slot.session_id = session_id;
    slot.session_key = derived_key;
    slot.session_state = SecureSessionState::Unauthenticated;
    slot.session_timer_deadline = Some(env.now + session_timeouts().0);
    slot.tcp_stream_index = tcp_idx as u8;
    slot.ecdh_ephemeral.client_public_key = request.public_key;
    slot.ecdh_ephemeral.server_public_key = server_public;

    debug!("Secure session {} allocated on TCP stream {}", session_id, tcp_idx);
    let _ = responses.push(serialize_to_vec(&SessionResponseBuilder::new(session_id, server_public, mac)));
}

// ============================================================================
// SECURE_WRAPPER: decrypt, then E01–E05
// ============================================================================

fn handle_wrapper<const N: usize>(
    pool: &mut Pool<N>,
    frame: &[u8],
    tcp_idx: Option<usize>,
    env: &SecureEnv<'_>,
    scratch: &mut [u8],
    responses: &mut SecureResponses,
) -> SecureFrameOutcome {
    const HANDLED: SecureFrameOutcome = SecureFrameOutcome::Handled { closed_session: None };

    // Unicast wrappers ride the session's TCP stream; multicast
    // wrappers (backbone key) belong to deferred secure routing.
    let Some(tcp_idx) = tcp_idx else {
        debug!("SECURE_WRAPPER over UDP discarded (secure multicast not implemented)");
        return HANDLED;
    };

    let mut buf = frame;
    let Ok(wrapper) = buf.parse::<SecureWrapper>() else {
        debug!("Malformed SECURE_WRAPPER discarded");
        return HANDLED;
    };
    let ciphertext = &buf[..wrapper.payload_len];
    let Ok(received_mac): Result<[u8; 16], _> = buf[wrapper.payload_len..wrapper.payload_len + 16].try_into() else {
        return HANDLED;
    };

    // Disconnected session identifier → discard (§2.2.3.3).
    let Some(slot_idx) = pool
        .slots
        .iter()
        .position(|s| s.session_state != SecureSessionState::Idle && s.session_id == wrapper.session_id)
    else {
        debug!("SECURE_WRAPPER for unknown session {} discarded", wrapper.session_id);
        return HANDLED;
    };
    let slot = &mut pool.slots[slot_idx];

    // Sessions are bound to the TCP stream they were opened on.
    if slot.tcp_stream_index as usize != tcp_idx {
        debug!("SECURE_WRAPPER for session {} from wrong TCP stream discarded", wrapper.session_id);
        return HANDLED;
    }

    // Replay check against the receive counter, MAC check before the
    // counter advances.
    let seq = seq_to_u64(&wrapper.seq_info);
    if seq < slot.recv_next_seq {
        debug!("SECURE_WRAPPER replay (seq {} < {}) discarded", seq, slot.recv_next_seq);
        return HANDLED;
    }

    if scratch.len() < wrapper.payload_len {
        warn!("SECURE_WRAPPER payload exceeds scratch buffer, discarded");
        return HANDLED;
    }
    let inner = &mut scratch[..wrapper.payload_len];
    inner.copy_from_slice(ciphertext);

    let assoc = SecureWrapper::associated_data(wrapper.session_id, wrapper.payload_len);
    let nonce = IpSecureNonce {
        seq_info: wrapper.seq_info,
        serial_number: wrapper.serial_number,
        message_tag: wrapper.message_tag,
    };
    if ip_secure_ccm::unwrap_secure(&slot.session_key, &nonce, &assoc, inner, &received_mac).is_err() {
        debug!("SECURE_WRAPPER for session {} failed authentication, discarded", wrapper.session_id);
        return HANDLED;
    }
    slot.accept_recv_seq(seq);

    let serial = env.serial_number;
    match peek_service_type(inner) {
        Ok(KNXnetIPServiceType::SessionAuthenticate) => handle_authenticate(slot, inner, env, &serial, responses),
        Ok(KNXnetIPServiceType::SessionStatus) => handle_status(slot, inner, env, &serial, responses),
        Ok(_) => {
            match slot.session_state {
                // E05 authenticated: re-arm the session timer (A4) and
                // hand the plaintext inner frame back for dispatch.
                SecureSessionState::Authenticated => {
                    slot.session_timer_deadline = Some(env.now + session_timeouts().1);
                    SecureFrameOutcome::Inner {
                        len: wrapper.payload_len,
                        session_id: slot.session_id,
                        user_id: slot.authenticated_user_id.unwrap_or(0),
                    }
                }
                // E05 unauthenticated: A6 — STATUS_UNAUTHENTICATED,
                // close contained connections, deallocate.
                _ => {
                    let closed = slot.session_id;
                    let _ = responses.push(build_wrapped_status(slot, &serial, SessionStatusCode::Unauthenticated));
                    slot.reset();
                    SecureFrameOutcome::Handled { closed_session: Some(closed) }
                }
            }
        }
        Err(_) => HANDLED,
    }
}

/// E01/E02: SESSION_AUTHENTICATE inside a valid wrapper.
fn handle_authenticate(
    slot: &mut IpSecureSessionSlot,
    inner: &[u8],
    env: &SecureEnv<'_>,
    serial: &[u8; 6],
    responses: &mut SecureResponses,
) -> SecureFrameOutcome {
    let config = env.config.expect("checked by caller");

    // In AUTHENTICATED, both E01 and E02 take action A2 — a repeated
    // authenticate always fails the session.
    let auth_ok = slot.session_state == SecureSessionState::Unauthenticated && {
        let mut buf = inner;
        match buf.parse::<SessionAuthenticate>() {
            Ok(auth) if auth.reserved == 0 && (user_id::MANAGEMENT..=user_id::USER_MAX).contains(&auth.user_id) => {
                match config.password_hash(auth.user_id) {
                    Some(hash) => {
                        let xor_xy = ip_secure_ccm::xor_public_keys(
                            &slot.ecdh_ephemeral.client_public_key,
                            &slot.ecdh_ephemeral.server_public_key,
                        );
                        let verified =
                            ip_secure_ccm::verify_session_authenticate_mac(&hash, auth.user_id, &xor_xy, &auth.mac)
                                .is_ok();
                        if verified {
                            slot.authenticated_user_id = Some(auth.user_id);
                        }
                        verified
                    }
                    None => false,
                }
            }
            _ => false,
        }
    };

    if auth_ok {
        // E01: A1 — STATUS_AUTHENTICATION_SUCCESS, session timer to
        // timeoutSession, handshake key material no longer needed.
        slot.session_state = SecureSessionState::Authenticated;
        slot.session_timer_deadline = Some(env.now + session_timeouts().1);
        slot.ecdh_ephemeral = Default::default();
        info!("Secure session {} authenticated as user {}", slot.session_id, slot.authenticated_user_id.unwrap_or(0));
        let _ = responses.push(build_wrapped_status(slot, serial, SessionStatusCode::AuthenticationSuccess));
        SecureFrameOutcome::Handled { closed_session: None }
    } else {
        // E02 (or E01 in AUTHENTICATED): A2 — STATUS_AUTHENTICATION_FAILED,
        // deallocate.
        let closed = slot.session_id;
        warn!("Secure session {} authentication failed", closed);
        let _ = responses.push(build_wrapped_status(slot, serial, SessionStatusCode::AuthenticationFailed));
        slot.reset();
        SecureFrameOutcome::Handled { closed_session: Some(closed) }
    }
}

/// E03/E04: SESSION_STATUS inside a valid wrapper.
fn handle_status(
    slot: &mut IpSecureSessionSlot,
    inner: &[u8],
    env: &SecureEnv<'_>,
    serial: &[u8; 6],
    responses: &mut SecureResponses,
) -> SecureFrameOutcome {
    let mut buf = inner;
    let Ok(status) = buf.parse::<SessionStatus>() else {
        return SecureFrameOutcome::Handled { closed_session: None };
    };

    match (status.status, slot.session_state) {
        // E03: A3 — confirm with STATUS_CLOSE, close contained
        // connections, deallocate.
        (SessionStatusCode::Close, _) => {
            let closed = slot.session_id;
            debug!("Secure session {} closed by client", closed);
            let _ = responses.push(build_wrapped_status(slot, serial, SessionStatusCode::Close));
            slot.reset();
            SecureFrameOutcome::Handled { closed_session: Some(closed) }
        }
        // E04 authenticated: A4 — re-arm the session timer; the spec
        // defines no response to a keepalive.
        (SessionStatusCode::Keepalive, SecureSessionState::Authenticated) => {
            slot.session_timer_deadline = Some(env.now + session_timeouts().1);
            SecureFrameOutcome::Handled { closed_session: None }
        }
        // E04 unauthenticated: A6 — STATUS_UNAUTHENTICATED, deallocate.
        (SessionStatusCode::Keepalive, _) => {
            let closed = slot.session_id;
            let _ = responses.push(build_wrapped_status(slot, serial, SessionStatusCode::Unauthenticated));
            slot.reset();
            SecureFrameOutcome::Handled { closed_session: Some(closed) }
        }
        // Client-side status codes (Success/Failed/Timeout/...) carry
        // no server-side action.
        _ => SecureFrameOutcome::Handled { closed_session: None },
    }
}

// ============================================================================
// Outgoing wrap, tick, teardown
// ============================================================================

/// Wrap an outgoing plaintext frame for the authenticated session on
/// `tcp_idx`. Writes header + security info + ciphertext + MAC into
/// `out` and returns the total length.
pub(super) fn wrap_outgoing<const N: usize>(
    pool: &mut Pool<N>,
    tcp_idx: usize,
    plain: &[u8],
    serial_number: &[u8; 6],
    out: &mut [u8],
) -> Option<usize> {
    let slot = pool
        .slots
        .iter_mut()
        .find(|s| s.session_state == SecureSessionState::Authenticated && s.tcp_stream_index as usize == tcp_idx)?;

    let total = plain.len() + SECURE_WRAPPER_OVERHEAD;
    if out.len() < total {
        error!("SECURE_WRAPPER output buffer too small ({} < {})", out.len(), total);
        return None;
    }

    let seq_info = seq48(slot.next_send_seq());
    let message_tag = [0u8; 2];

    // Encrypt the payload in place inside `out`, then frame it.
    let payload_range = 22..22 + plain.len();
    out[payload_range.clone()].copy_from_slice(plain);
    let assoc = SecureWrapper::associated_data(slot.session_id, plain.len());
    let nonce = IpSecureNonce { seq_info, serial_number: *serial_number, message_tag };
    let mac = ip_secure_ccm::wrap_secure(&slot.session_key, &nonce, &assoc, &mut out[payload_range.clone()]);

    // `assoc` is exactly the first 8 wire bytes (header + session id).
    out[0..8].copy_from_slice(&assoc);
    out[8..14].copy_from_slice(&seq_info);
    out[14..20].copy_from_slice(serial_number);
    out[20..22].copy_from_slice(&message_tag);
    out[payload_range.end..total].copy_from_slice(&mac);

    Some(total)
}

/// The authenticated session bound to `tcp_idx`.
pub(super) fn session_for_tcp<const N: usize>(pool: &Pool<N>, tcp_idx: usize) -> Option<(u16, u8)> {
    pool.slots
        .iter()
        .find(|s| s.session_state == SecureSessionState::Authenticated && s.tcp_stream_index as usize == tcp_idx)
        .map(|s| (s.session_id, s.authenticated_user_id.unwrap_or(0)))
}

/// E06: expire sessions whose timer ran out — A5: STATUS_TIMEOUT,
/// close contained connections, deallocate.
pub(super) fn tick<const N: usize>(
    pool: &mut Pool<N>,
    now: Instant,
    serial_number: &[u8; 6],
) -> Vec<ExpiredSession, 8> {
    let mut expired = Vec::new();
    for slot in pool.slots.iter_mut() {
        if slot.session_state != SecureSessionState::Idle
            && slot.session_timer_deadline.is_some_and(|deadline| deadline <= now)
        {
            warn!("Secure session {} timed out", slot.session_id);
            let entry = ExpiredSession {
                tcp_idx: slot.tcp_stream_index as usize,
                session_id: slot.session_id,
                status_frame: build_wrapped_status(slot, serial_number, SessionStatusCode::Timeout),
            };
            slot.reset();
            if expired.push(entry).is_err() {
                break;
            }
        }
    }
    expired
}

/// §2.4.2: closing a TCP connection implicitly closes every session
/// opened on it, without further notification.
pub(super) fn on_tcp_closed<const N: usize>(pool: &mut Pool<N>, tcp_idx: usize) -> Vec<u16, 8> {
    let mut closed = Vec::new();
    for slot in pool.slots.iter_mut() {
        if slot.session_state != SecureSessionState::Idle && slot.tcp_stream_index as usize == tcp_idx {
            debug!("Secure session {} released (TCP stream {} closed)", slot.session_id, tcp_idx);
            let _ = closed.push(slot.session_id);
            slot.reset();
        }
    }
    closed
}
