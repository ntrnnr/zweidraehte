//! `DataSecure<S, GRP, GO>` — the KNX Data Secure profile module.

use heapless::Vec;

use zweidraehte_proto::access::{AccessContext, AccessPolicy, ClientRole, SecurityMode};
use zweidraehte_proto::crypto::{
    ccm,
    scf::{SecureServiceType, SecurityControlField},
};
use zweidraehte_proto::dpt::{
    PDT_BinaryInformation, PDT_Control, PDT_Function, PDT_Generic01, PDT_Generic06, PDT_Generic08, PDT_Generic16,
    PDT_Generic18, PDT_UnsignedChar, PDT_UnsignedInt, PropertyDataDefinition,
};
use zweidraehte_proto::messages::apdu::load_control::{LoadAction, LoadState, load_control_transition};
use zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode;
use zweidraehte_proto::messages::apdu::restart::EraseCode;
use zweidraehte_proto::messages::apdu::secure::{self, SecureApduMut, SecureApduRef, SyncReqRef};
use zweidraehte_proto::pid;
use zweidraehte_proto::properties::{PropertyAccess, PropertyDescriptor};
use zweidraehte_proto::security::{
    FunctionPropertyAnswer, SecurityConfig, SecurityFailureType, SecurityState, SecurityTable,
};

use crate::frame::FrameBuf;
use crate::sal::{ReplyKey, ReplySecurity, RequestContext};

use super::{FunctionResult, MicroSecurityResources, SalResult, ScheduledRestart, SecurityModule};

pub const SECURITY_IO_TYPE: u16 = 0x0011;

/// `PID_OBJECT_NAME` for the Security Interface Object.
const OBJECT_NAME: &[u8] = b"SecurityIO";

/// KNX Data Secure as a profile module.
///
/// `GRP` is the group-key table capacity and `GO` the group-object security
/// flag count. There is deliberately **no P2P parameter**: this device is
/// tool-access-only, so 06 Profiles §9.1.2.6.4 leaves PID 52 and PID 62
/// (`Cc` — mandatory only when non-tool point-to-point is supported)
/// unimplemented rather than present-but-empty. The bench MV-0021 exposes
/// neither, and its product file declares no P2P capacity.
pub struct DataSecure<S, const GRP: usize, const GO: usize>(core::marker::PhantomData<S>);

/// Runtime state of the Security Interface Object.
///
/// The tables, the mode, the failure log and the key lookups are
/// [`zweidraehte_proto::security`] — the same types the full stack runs on,
/// which is what keeps one implementation of Data Secure rather than two.
pub struct DataSecureState<S, const GRP: usize, const GO: usize> {
    pub security: SecurityState<GRP, 0, GO>,
    /// The Security Individual Address Table and the two singleton sequence
    /// counters. One store serves both, because a SIAT element *is* a sender
    /// address and its Last Valid SeqNr (03/05/01 §6.3.8) — keeping them
    /// apart would mean two copies of the same number.
    pub seq: S,
    /// The Factory Default Setup Key.
    ///
    /// Device identity, not persisted state: the tool key reverts to it on a
    /// factory reset (§6.1.4), and until ETS writes one it *is* the tool key.
    pub fdsk: [u8; 16],
    /// Timestamp of the last sync response. This exists only in a secure
    /// profile; plain devices pay no RAM for the rate limiter.
    pub(crate) last_sync_ms: Option<u32>,
    /// Master-reset handoff consumed by the dispatch that produced it.
    /// Transient by design: snapshots must never replay a reset request.
    pending_restart: Option<ScheduledRestart>,
}

impl<S, const GRP: usize, const GO: usize> DataSecureState<S, GRP, GO> {
    /// A factory-state Security Interface Object: unloaded, security mode
    /// off, no tables, and the FDSK standing in as the tool key.
    pub fn new(fdsk: [u8; 16], seq: S) -> Self {
        // §6.1.4: on a device that has never been commissioned the FDSK is
        // the tool key. Leaving it zero would make the device unreachable
        // until something wrote one, which is the wrong way round.
        let config = SecurityConfig { tool_key: fdsk, ..SecurityConfig::default() };
        Self { security: SecurityState::from_config(config), seq, fdsk, last_sync_ms: None, pending_restart: None }
    }

    /// Restore persisted Security IO state over the device's current FDSK
    /// identity and sequence resource.
    pub fn from_config(fdsk: [u8; 16], seq: S, config: SecurityConfig<GRP, 0, GO>) -> Self {
        Self { security: SecurityState::from_config(config), seq, fdsk, last_sync_ms: None, pending_restart: None }
    }

    /// Snapshot the low-write-frequency Security IO configuration.
    pub fn to_config(&self) -> SecurityConfig<GRP, 0, GO> {
        self.security.to_config()
    }
}

/// The Security Interface Object's spec-ordered property roster.
fn descriptor<const GRP: usize, const GO: usize>(index: u16) -> Option<PropertyDescriptor> {
    let configuration = 2;
    let runtime = 3;
    let system = 0;
    let rw = PropertyAccess::ReadWrite;
    let ro = PropertyAccess::ReadOnly;
    let wo = PropertyAccess::WriteOnly;
    Some(match index {
        0 => PropertyDescriptor::new(
            pid::OBJECT_TYPE,
            PDT_UnsignedInt::ID,
            1,
            ro,
            runtime,
            system,
            AccessPolicy::READ_OPEN_WRITE_TOOL,
        ),
        1 => PropertyDescriptor::new(
            pid::OBJECT_NAME,
            PDT_UnsignedChar::ID,
            OBJECT_NAME.len() as u16,
            ro,
            runtime,
            system,
            AccessPolicy::READ_OPEN_WRITE_TOOL,
        ),
        2 => PropertyDescriptor::new(
            pid::LOAD_STATE_CONTROL,
            PDT_Control::ID,
            1,
            rw,
            configuration,
            configuration,
            AccessPolicy::RESTRICTED,
        ),
        3 => PropertyDescriptor::new(
            pid::security::SECURITY_MODE,
            PDT_Function::ID,
            1,
            rw,
            configuration,
            configuration,
            AccessPolicy::RESTRICTED,
        ),
        4 => PropertyDescriptor::new(
            pid::security::GROUP_KEY_TABLE,
            PDT_Generic18::ID,
            GRP as u16,
            rw,
            configuration,
            configuration,
            AccessPolicy::TOOL_ONLY,
        ),
        5 => PropertyDescriptor::new(
            pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
            PDT_Generic08::ID,
            0,
            rw,
            configuration,
            configuration,
            AccessPolicy::TOOL_ONLY,
        ),
        6 => PropertyDescriptor::new(
            pid::security::SECURITY_FAILURES_LOG,
            PDT_Function::ID,
            1,
            rw,
            runtime,
            configuration,
            AccessPolicy::new(0x1FF, 0x0CC),
        ),
        7 => PropertyDescriptor::new(
            pid::security::TOOL_KEY,
            PDT_Generic16::ID,
            1,
            wo,
            system,
            configuration,
            AccessPolicy::TOOL_ONLY_CONFIDENTIAL,
        ),
        8 => PropertyDescriptor::new(
            pid::security::SECURITY_REPORT,
            PDT_Generic01::ID,
            1,
            rw,
            runtime,
            configuration,
            AccessPolicy::new(0x1FF, 0x0CC),
        ),
        9 => PropertyDescriptor::new(
            pid::security::SECURITY_REPORT_CONTROL,
            PDT_BinaryInformation::ID,
            1,
            rw,
            configuration,
            configuration,
            AccessPolicy::TOOL_ONLY,
        ),
        10 => PropertyDescriptor::new(
            pid::security::SEQUENCE_NUMBER_SENDING,
            PDT_Generic06::ID,
            1,
            rw,
            configuration,
            configuration,
            AccessPolicy::TOOL_ONLY,
        ),
        11 => PropertyDescriptor::new(
            pid::security::GO_SECURITY_FLAGS,
            PDT_Generic01::ID,
            GO as u16,
            rw,
            configuration,
            configuration,
            AccessPolicy::TOOL_ONLY,
        ),
        _ => return None,
    })
}

fn log_failure<S, const GRP: usize, const GO: usize>(
    state: &DataSecureState<S, GRP, GO>,
    kind: SecurityFailureType,
    source: u16,
    frame: &[u8],
) {
    state.security.failures_log().borrow_mut().log_failure(kind, source, frame);
}

#[allow(clippy::too_many_arguments)]
fn process_sync_request<S: MicroSecurityResources, const GRP: usize, const GO: usize>(
    state: &mut DataSecureState<S, GRP, GO>,
    buf: &mut [u8],
    len: usize,
    now_ms: u32,
    own_ia: u16,
    own_serial: [u8; 6],
    time_divisor: u32,
    scf: SecurityControlField,
    scf_byte: u8,
    source: u16,
    fragment: &[u8],
    response_tpci: u8,
) -> SalResult<Option<ReplySecurity>> {
    if !scf.tool_access || !scf.confidentiality {
        log_failure(state, SecurityFailureType::AccessError, source, fragment);
        return SalResult::Dropped;
    }

    let rate_limit_ms = (1_000 / time_divisor.max(1)).max(1);
    if state.last_sync_ms.is_some_and(|last| now_ms.wrapping_sub(last) < rate_limit_ms) {
        return SalResult::Dropped;
    }

    let (seq_nr_local_received, serial_number, received_mac, addr_type, ccm_context) = {
        let Ok(sync) = SyncReqRef::parse(&buf[..len]) else {
            return SalResult::Dropped;
        };
        (sync.seq_nr_local(), sync.knx_serial_number(), sync.mac(), sync.addr_type(), sync.ccm_context())
    };
    let is_broadcast = addr_type != 0;

    if is_broadcast && u16::from_be_bytes([buf[3], buf[4]]) != 0 {
        return SalResult::Dropped;
    }

    if (is_broadcast && (serial_number == [0; 6] || serial_number != own_serial))
        || (!is_broadcast && serial_number != [0; 6] && serial_number != own_serial)
    {
        return SalResult::Dropped;
    }

    let key = {
        let tool_key = state.security.tool_key();
        if tool_key == [0; 16] { state.fdsk } else { tool_key }
    };
    let mut challenge = [0u8; 6];
    challenge.copy_from_slice(&buf[secure::sync::CHALLENGE..secure::sync::CHALLENGE + 6]);
    if ccm::verify_and_decrypt_sync_req(&key, &ccm_context, scf_byte, &serial_number, &mut challenge, &received_mac)
        .is_err()
    {
        log_failure(state, SecurityFailureType::CryptoError, source, fragment);
        return SalResult::Dropped;
    }

    // A sync request announces the tool's next sending number. Persist the
    // preceding number before responding, then return the next acceptable
    // value. Any storage failure aborts the exchange: proceeding would make
    // the response promise replay state the device did not durably record.
    let Ok(stored) = state.seq.load_tool_receiving_seq() else {
        return SalResult::Dropped;
    };
    let stored_value = stored.map(|seq| zweidraehte_proto::security::seq6_to_u64(&seq)).unwrap_or(0);
    let received_value = zweidraehte_proto::security::seq6_to_u64(&seq_nr_local_received);
    let received_predecessor = received_value.saturating_sub(1);
    let new_stored = stored_value.max(received_predecessor);
    if new_stored != stored_value
        && state.seq.save_tool_receiving_seq(&zweidraehte_proto::security::u64_to_seq6(new_stored)).is_err()
    {
        return SalResult::Dropped;
    }
    let Some(response_local_value) = new_stored.checked_add(1) else {
        return SalResult::Dropped;
    };
    if response_local_value > zweidraehte_proto::security::SEQ6_MAX {
        return SalResult::Dropped;
    }
    let response_local = zweidraehte_proto::security::u64_to_seq6(response_local_value);
    let Ok(response_remote) = state.seq.load_sending_seq() else {
        return SalResult::Dropped;
    };

    let mut random = [0u8; 6];
    state.seq.fill_random(&mut random);
    let mut challenge_xor_random = [0u8; 6];
    for (out, (challenge, random)) in challenge_xor_random.iter_mut().zip(challenge.into_iter().zip(random)) {
        *out = challenge ^ random;
    }

    let response_scf = SecurityControlField {
        service: SecureServiceType::SyncResponse,
        system_broadcast: scf.system_broadcast,
        confidentiality: true,
        tool_access: true,
    }
    .encode();
    let destination = if is_broadcast { 0 } else { source };
    let control = buf[0];
    let npdu = buf[5];
    let mac_offset = secure::build_sync_response(
        buf,
        control,
        own_ia,
        destination,
        npdu,
        response_tpci,
        response_scf,
        &challenge_xor_random,
        &response_remote,
        &response_local,
    );
    let tpci_apci = u16::from_be_bytes([buf[6], buf[7]]);
    let mac = ccm::encrypt_and_mac_sync_res(
        &key,
        &random,
        own_ia,
        destination,
        addr_type,
        tpci_apci,
        response_scf,
        &mut buf[secure::sync::SEQ_NR_REMOTE..secure::sync::SEQ_NR_REMOTE + 12],
    );
    buf[mac_offset..mac_offset + secure::MAC_LEN].copy_from_slice(&mac);
    state.last_sync_ms = Some(now_ms);
    SalResult::Response { len: secure::sync::FRAME_LEN }
}

/// Copy a table's elements into a reply buffer using the one-based
/// addressing and `start = 0` count probe that array properties use.
fn read_table<const N: usize, const CAP: usize, const ENTRY: usize>(
    table: &SecurityTable<CAP, ENTRY>,
    count: u8,
    start: u16,
) -> Option<Vec<u8, N>> {
    let mut out: Vec<u8, N> = Vec::new();
    out.resize_default(N).ok()?;
    let len = table.read_elements(start, u16::from(count), &mut out).ok()?;
    out.truncate(len);
    Some(out)
}

fn scalar<const N: usize>(bytes: &[u8]) -> Option<Vec<u8, N>> {
    let mut out: Vec<u8, N> = Vec::new();
    out.extend_from_slice(bytes).ok()?;
    Some(out)
}

/// The element-count probe answer for a property with a single element.
fn one_element<const N: usize>() -> Option<Vec<u8, N>> {
    scalar(&1u16.to_be_bytes())
}

impl<S: MicroSecurityResources + 'static, const GRP: usize, const GO: usize> SecurityModule for DataSecure<S, GRP, GO> {
    type State = DataSecureState<S, GRP, GO>;
    type ReplyContext = Option<ReplySecurity>;
    const ENABLED: bool = true;
    const FRAME_OVERHEAD: usize = secure::OVERHEAD;
    const OBJECT_TYPE: Option<u16> = Some(SECURITY_IO_TYPE);

    #[inline(always)]
    fn plain_reply_context() -> Self::ReplyContext {
        None
    }

    fn property_descriptor(prop_id: u16) -> Option<(u16, PropertyDescriptor)> {
        for index in 0..12 {
            let desc = descriptor::<GRP, GO>(index)?;
            if desc.pid == prop_id {
                return Some((index, desc));
            }
        }
        None
    }

    fn property_descriptor_at(index: u16) -> Option<PropertyDescriptor> {
        descriptor::<GRP, GO>(index)
    }

    fn property_read<const N: usize>(state: &Self::State, prop_id: u16, count: u8, start: u16) -> Option<Vec<u8, N>> {
        let sec = &state.security;
        // The array properties carry their own element addressing; the
        // scalars answer the `start = 0` probe with a count of one.
        match prop_id {
            pid::security::GROUP_KEY_TABLE => return read_table(&sec.grp_keys().borrow(), count, start),
            pid::security::GO_SECURITY_FLAGS => return read_table(&sec.go_flags().borrow(), count, start),
            pid::OBJECT_NAME => {
                if start == 0 {
                    return scalar(&(OBJECT_NAME.len() as u16).to_be_bytes());
                }
                let first = usize::from(start.saturating_sub(1));
                if first >= OBJECT_NAME.len() || count == 0 {
                    return None;
                }
                let end = (first + usize::from(count)).min(OBJECT_NAME.len());
                return scalar(&OBJECT_NAME[first..end]);
            }
            // The SIAT is served live out of the sequence store, not from a
            // second copy: an element is a sender address and its Last Valid
            // SeqNr, and the S-AL updates that number on every accepted
            // frame (03/05/01 §6.3.8).
            pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE => {
                if start == 0 {
                    return scalar(&state.seq.siat_count().to_be_bytes());
                }
                let mut out: Vec<u8, N> = Vec::new();
                for element in start..start.saturating_add(u16::from(count)) {
                    let (ia, seq_nr) = state.seq.siat_read_entry(element - 1)?;
                    out.extend_from_slice(&ia.to_be_bytes()).ok()?;
                    out.extend_from_slice(&seq_nr).ok()?;
                }
                return Some(out);
            }
            _ => {}
        }
        if start == 0 {
            return (count != 0).then(one_element).flatten();
        }
        if count != 1 || start != 1 {
            return None;
        }
        match prop_id {
            pid::OBJECT_TYPE => scalar(&SECURITY_IO_TYPE.to_be_bytes()),
            pid::LOAD_STATE_CONTROL => scalar(&[u8::from(sec.load_state())]),
            pid::security::SECURITY_REPORT => scalar(&[sec.security_report()]),
            // One counter for all outgoing secure communication, tool access
            // included (03/03/07 §5.3), which is why the store answers it
            // rather than the security tables.
            pid::security::SEQUENCE_NUMBER_SENDING => scalar(&state.seq.load_sending_seq().ok()?),
            pid::security::SECURITY_REPORT_CONTROL => scalar(&[u8::from(sec.security_report_enabled())]),
            // PID_TOOL_KEY is write-only (§9.1.2.6.4 access `008/008`,
            // levels `X/2`): there is no read level at all, so a read is
            // refused rather than answered with the key.
            pid::security::TOOL_KEY => None,
            _ => None,
        }
    }

    fn process_incoming(
        state: &mut Self::State,
        buf: &mut [u8],
        len: &mut usize,
        now_ms: u32,
        own_ia: u16,
        serial_number: [u8; 6],
        time_divisor: u32,
        group_key_index: Option<u16>,
        response_tpci: u8,
    ) -> SalResult<Self::ReplyContext> {
        if *len < 8 {
            return SalResult::Passthrough;
        }
        let apci10 = (((buf[6] & 0x03) as u16) << 8) | buf[7] as u16;
        if zweidraehte_proto::messages::knx::ApciCode::from_wire10(apci10)
            != zweidraehte_proto::messages::knx::ApciCode::SecureService
        {
            return SalResult::Passthrough;
        }

        let frame = &buf[..*len];
        let src = u16::from_be_bytes([buf[1], buf[2]]);
        let is_group = buf[5] & 0x80 != 0;
        let dst = u16::from_be_bytes([buf[3], buf[4]]);
        let mut fragment = [0u8; 9];
        let fragment_len = frame.len().min(fragment.len());
        fragment[..fragment_len].copy_from_slice(&frame[..fragment_len]);

        let (scf_byte, scf, seq_nr, received_mac, ccm_ctx) = {
            let Ok(secure_ref) = SecureApduRef::parse(frame) else {
                log_failure(state, SecurityFailureType::ScfError, src, &fragment);
                return SalResult::Dropped;
            };
            let scf_byte = secure_ref.scf_byte();
            let Ok(scf) = secure_ref.scf() else {
                log_failure(state, SecurityFailureType::ScfError, src, &fragment);
                return SalResult::Dropped;
            };
            (scf_byte, scf, secure_ref.seq_nr(), secure_ref.mac(), secure_ref.ccm_context(src))
        };

        if scf.service == SecureServiceType::SyncRequest {
            return process_sync_request(
                state,
                buf,
                *len,
                now_ms,
                own_ia,
                serial_number,
                time_divisor,
                scf,
                scf_byte,
                src,
                &fragment,
                response_tpci,
            );
        }
        if scf.service != SecureServiceType::Data {
            return SalResult::Dropped;
        }
        if !scf.tool_access
            && state.security.load_state() != zweidraehte_proto::messages::apdu::load_control::LoadState::Loaded
        {
            return SalResult::Dropped;
        }
        // Tool access may be addressed individually or as system broadcast,
        // but never to an ordinary group address.
        if scf.tool_access && is_group && dst != 0 {
            log_failure(state, SecurityFailureType::AccessError, src, &fragment);
            return SalResult::Dropped;
        }
        if seq_nr == [0u8; 6] {
            log_failure(state, SecurityFailureType::SeqNrError, src, &fragment);
            return SalResult::Dropped;
        }
        if !scf.tool_access && !is_group {
            log_failure(state, SecurityFailureType::RoleError, src, &fragment);
            return SalResult::Dropped;
        }

        let key = if scf.tool_access {
            let tk = state.security.tool_key();
            if tk != [0u8; 16] { tk } else { state.fdsk }
        } else {
            if !state.seq.siat_contains(src) {
                log_failure(state, SecurityFailureType::RoleError, src, &fragment);
                return SalResult::Dropped;
            }
            let Some(index) = group_key_index else {
                log_failure(state, SecurityFailureType::RoleError, src, &fragment);
                return SalResult::Dropped;
            };
            let Some(key) = state.security.group_key_for_index(index) else {
                log_failure(state, SecurityFailureType::RoleError, src, &fragment);
                return SalResult::Dropped;
            };
            key
        };

        let frame_mut = &mut buf[..*len];
        let mut secure_mut = SecureApduMut::parse(frame_mut).expect("validated");
        let ok = if scf.confidentiality {
            ccm::verify_and_decrypt(&key, &ccm_ctx, scf_byte, secure_mut.payload_mut(), &received_mac).is_ok()
        } else {
            ccm::verify_mac_auth_only(&key, &ccm_ctx, scf_byte, secure_mut.payload(), &received_mac).is_ok()
        };
        if !ok {
            log_failure(state, SecurityFailureType::CryptoError, src, &fragment);
            return SalResult::Dropped;
        }

        let stored = if scf.tool_access {
            match state.seq.load_tool_receiving_seq() {
                Ok(stored) => stored,
                Err(_) => return SalResult::Dropped,
            }
        } else {
            match state.seq.load_receiving_seq(src) {
                Ok(stored) => stored,
                Err(_) => return SalResult::Dropped,
            }
        };
        match zweidraehte_proto::security::check_receiving_seq(&seq_nr, stored) {
            zweidraehte_proto::security::SeqVerdict::Accept => {
                let saved = if scf.tool_access {
                    state.seq.save_tool_receiving_seq(&seq_nr)
                } else {
                    state.seq.save_receiving_seq(src, &seq_nr)
                };
                if saved.is_err() {
                    return SalResult::Dropped;
                }
            }
            zweidraehte_proto::security::SeqVerdict::Retransmission => return SalResult::Dropped,
            zweidraehte_proto::security::SeqVerdict::Replay | zweidraehte_proto::security::SeqVerdict::Invalid => {
                log_failure(state, SecurityFailureType::SeqNrError, src, &fragment);
                return SalResult::Dropped;
            }
        }

        let new_len = secure_mut.unwrap_to_plaintext();
        *len = new_len;

        let security = if scf.confidentiality { SecurityMode::AuthConf } else { SecurityMode::AuthOnly };
        let role = if scf.tool_access { ClientRole::Tool } else { ClientRole::Unlisted };
        let mut access = AccessContext::with_security(0, security, role);
        access.source_addr = src;
        SalResult::Decrypted(RequestContext {
            access,
            reply: Some(ReplySecurity {
                security,
                tool_access: scf.tool_access,
                system_broadcast: scf.system_broadcast,
                key: ReplyKey::Live,
            }),
        })
    }

    fn protect_reply<const N: usize>(
        state: &mut Self::State,
        reply: Self::ReplyContext,
        frame: &mut FrameBuf<N>,
    ) -> bool {
        let Some(reply) = reply else { return true };
        // This profile has no P2P key or role table. Refuse the shape before
        // reserving a counter or even resizing the caller's plaintext buffer.
        if !reply.tool_access {
            return false;
        }
        let plain_len = frame.len();
        let needed = plain_len + secure::OVERHEAD;
        if needed > N || frame.resize_default(N).is_err() {
            return false;
        }
        let (key, seq_nr) = match reply.key {
            ReplyKey::Live => {
                let Some(sequence) = zweidraehte_proto::security::reserve_next_seq_nr(&mut state.seq) else {
                    return false;
                };
                let tool_key = state.security.tool_key();
                let key = if tool_key == [0; 16] { state.fdsk } else { tool_key };
                (key, sequence)
            }
            ReplyKey::Prepared { key, sequence } => (key, sequence),
        };
        let scf_byte = SecurityControlField {
            service: SecureServiceType::Data,
            system_broadcast: reply.system_broadcast,
            confidentiality: reply.security == SecurityMode::AuthConf,
            tool_access: reply.tool_access,
        }
        .encode();
        let buf = frame.as_mut_slice();
        let src = u16::from_be_bytes([buf[1], buf[2]]);
        let Some(layout) = secure::wrap_plaintext(buf, plain_len, scf_byte, &seq_nr) else {
            return false;
        };
        let ccm_ctx = SecureApduRef::parse(&buf[..needed]).expect("just built").ccm_context(src);

        let mac = if reply.security == SecurityMode::AuthConf {
            ccm::encrypt_and_mac(&key, &ccm_ctx, scf_byte, &mut buf[layout.payload_start..layout.payload_end])
        } else {
            ccm::compute_mac_auth_only(&key, &ccm_ctx, scf_byte, &buf[layout.payload_start..layout.payload_end])
        };
        buf[layout.mac_start..layout.mac_start + secure::MAC_LEN].copy_from_slice(&mac);
        frame.truncate(needed);
        true
    }

    fn security_mode_enabled(state: &Self::State) -> bool {
        state.security.security_mode_enabled()
    }

    fn group_security_flags(state: &Self::State, go_index: u16) -> Option<u8> {
        state.security.go_security_flags_for(go_index)
    }

    fn wrap_group(
        state: &mut Self::State,
        group_key_index: u16,
        security_flags: u8,
        buf: &mut [u8],
        len: &mut usize,
        capacity: usize,
    ) -> bool {
        let plain_len = *len;
        let needed = plain_len + secure::OVERHEAD;
        if needed > capacity {
            return false;
        }
        let Some(key) = state.security.group_key_for_index(group_key_index) else {
            return false;
        };
        let Some(seq_nr) = zweidraehte_proto::security::reserve_next_seq_nr(&mut state.seq) else {
            return false;
        };
        let scf_byte = SecurityControlField {
            service: SecureServiceType::Data,
            system_broadcast: false,
            confidentiality: security_flags & 0x02 != 0,
            tool_access: false,
        }
        .encode();
        let source = u16::from_be_bytes([buf[1], buf[2]]);
        let Some(layout) = secure::wrap_plaintext(buf, plain_len, scf_byte, &seq_nr) else {
            return false;
        };
        let context = SecureApduRef::parse(&buf[..needed]).expect("just built").ccm_context(source);
        let mac = if security_flags & 0x02 != 0 {
            ccm::encrypt_and_mac(&key, &context, scf_byte, &mut buf[layout.payload_start..layout.payload_end])
        } else {
            ccm::compute_mac_auth_only(&key, &context, scf_byte, &buf[layout.payload_start..layout.payload_end])
        };
        buf[layout.mac_start..layout.mac_start + secure::MAC_LEN].copy_from_slice(&mac);
        *len = needed;
        true
    }

    fn log_access_failure(state: &Self::State, source: u16, frame: &[u8]) {
        log_failure(state, SecurityFailureType::AccessError, source, frame);
    }

    fn factory_reset(state: &mut Self::State, reply: &mut Self::ReplyContext, code: EraseCode) -> bool {
        let Some(reply) = reply.as_mut() else { return false };
        let key = {
            let tool_key = state.security.tool_key();
            if tool_key == [0; 16] { state.fdsk } else { tool_key }
        };
        let Some(sequence) = zweidraehte_proto::security::reserve_next_seq_nr(&mut state.seq) else {
            return false;
        };
        // The response is the last telegram in the old security context.
        // Capture it request-locally before the durable reset replaces the
        // Tool Key and sending counter.
        reply.key = ReplyKey::Prepared { key, sequence };
        if state.seq.siat_clear().is_err()
            || !zweidraehte_proto::security::erase_seq_on_factory_reset(&mut state.seq, code)
        {
            return false;
        }
        state.security.factory_reset();
        state.security.reset_tool_key_to_fdsk(state.fdsk);
        true
    }

    fn schedule_restart(state: &mut Self::State, restart: ScheduledRestart) {
        state.pending_restart = Some(restart);
    }

    fn take_scheduled_restart(state: &mut Self::State) -> Option<ScheduledRestart> {
        state.pending_restart.take()
    }

    fn function_command<const N: usize>(
        state: &mut Self::State,
        prop_id: u16,
        data: &[u8],
    ) -> Option<FunctionResult<N>> {
        Self::handle_function_command(state, prop_id, data)
    }

    fn function_state_read<const N: usize>(
        state: &Self::State,
        prop_id: u16,
        data: &[u8],
    ) -> Option<FunctionResult<N>> {
        Self::handle_function_state_read(state, prop_id, data)
    }

    fn property_write(state: &mut Self::State, prop_id: u16, count: u8, start: u16, data: &[u8]) -> PropertyReturnCode {
        // PDT_CONTROL is reachable through both the legacy data-property
        // path and the preferred extended function-property path. Keep the
        // transition and its unload side effects in one place so the two
        // services cannot publish different Security IO states.
        if prop_id == pid::LOAD_STATE_CONTROL {
            if start != 1 {
                return PropertyReturnCode::AddressVoid;
            }
            return Self::write_load_control(state, data);
        }

        let sec = &state.security;
        match prop_id {
            pid::security::GROUP_KEY_TABLE => {
                if start != 0 && data.len() != usize::from(count) * 18 {
                    return PropertyReturnCode::DataTypeConflict;
                }
                return sec
                    .grp_keys()
                    .borrow_mut()
                    .write_elements(start, data)
                    .map_or_else(|err| err.to_ext_return_code(), |_| PropertyReturnCode::Success);
            }
            pid::security::GO_SECURITY_FLAGS => {
                if start != 0 && data.len() != usize::from(count) {
                    return PropertyReturnCode::DataTypeConflict;
                }
                return sec
                    .go_flags()
                    .borrow_mut()
                    .write_elements(start, data)
                    .map_or_else(|err| err.to_ext_return_code(), |_| PropertyReturnCode::Success);
            }
            pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE => {
                if start == 0 {
                    let Ok(count) = <[u8; 2]>::try_from(data) else {
                        return PropertyReturnCode::DataTypeConflict;
                    };
                    return if state.seq.siat_set_count(u16::from_be_bytes(count)).is_ok() {
                        PropertyReturnCode::Success
                    } else {
                        PropertyReturnCode::MemoryError
                    };
                }
                if data.len() != usize::from(count) * 8 {
                    return PropertyReturnCode::DataTypeConflict;
                }
                // Positional, like every other array property: the element
                // named is the element replaced, because its position is the
                // `IA_Index` the rest of the security model joins on.
                for (i, row) in data.chunks_exact(8).enumerate() {
                    let ia = u16::from_be_bytes([row[0], row[1]]);
                    let seq_nr = <[u8; 6]>::try_from(&row[2..]).expect("an eight-octet row leaves six");
                    let element = start as usize + i;
                    if state.seq.siat_write_entry((element - 1) as u16, ia, seq_nr).is_err() {
                        return PropertyReturnCode::MemoryError;
                    }
                }
                return PropertyReturnCode::Success;
            }
            _ => {}
        }
        if start != 1 {
            return PropertyReturnCode::AddressVoid;
        }
        match prop_id {
            pid::security::TOOL_KEY => {
                let Ok(key) = <[u8; 16]>::try_from(data) else {
                    return PropertyReturnCode::DataTypeConflict;
                };
                sec.set_tool_key(key);
                PropertyReturnCode::Success
            }
            pid::security::SECURITY_REPORT => {
                // §6.3.11: the report field is cleared by writing it, not set.
                // Only the tool clears it, and only the clear is meaningful.
                if data.len() != 1 {
                    return PropertyReturnCode::DataTypeConflict;
                }
                sec.set_security_report(sec.security_report() & !data[0]);
                PropertyReturnCode::Success
            }
            pid::security::SECURITY_REPORT_CONTROL => {
                if data.len() != 1 {
                    return PropertyReturnCode::DataTypeConflict;
                }
                sec.set_security_report_enabled(data[0] != 0);
                PropertyReturnCode::Success
            }
            pid::security::SEQUENCE_NUMBER_SENDING => {
                let Ok(seq_nr) = <[u8; 6]>::try_from(data) else {
                    return PropertyReturnCode::DataTypeConflict;
                };
                // Zero is never a valid sequence number — a remote S-AL
                // ignores it (03/03/07 §5.3.1) — so accepting it would arm
                // the device to send frames nobody will take.
                if seq_nr == [0u8; 6] {
                    return PropertyReturnCode::DataVoid;
                }
                if state.seq.save_sending_seq(&seq_nr).is_ok() {
                    PropertyReturnCode::Success
                } else {
                    PropertyReturnCode::MemoryError
                }
            }
            _ => PropertyReturnCode::AddressVoid,
        }
    }
}

/// Adapt proto's `FunctionPropertyAnswer` into the `Vec`-based result
/// the module trait returns.
fn adapt_answer<const N: usize>(answer: FunctionPropertyAnswer) -> FunctionResult<N> {
    FunctionResult {
        code: PropertyReturnCode::from(answer.return_code),
        data: {
            let mut v = Vec::new();
            v.extend_from_slice(answer.data()).expect("function-property answer fits the extended frame");
            v
        },
    }
}

impl<S: MicroSecurityResources + 'static, const GRP: usize, const GO: usize> DataSecure<S, GRP, GO> {
    pub(crate) fn handle_function_command<const N: usize>(
        state: &mut DataSecureState<S, GRP, GO>,
        prop_id: u16,
        data: &[u8],
    ) -> Option<FunctionResult<N>> {
        if prop_id == pid::LOAD_STATE_CONTROL {
            let code = Self::write_load_control(state, data);
            return Some(Self::load_state_result(code, state.security.load_state()));
        }
        state.security.function_command(prop_id, data).map(adapt_answer)
    }

    pub(crate) fn handle_function_state_read<const N: usize>(
        state: &DataSecureState<S, GRP, GO>,
        prop_id: u16,
        data: &[u8],
    ) -> Option<FunctionResult<N>> {
        if prop_id == pid::LOAD_STATE_CONTROL {
            return Some(Self::load_state_result(PropertyReturnCode::Success, state.security.load_state()));
        }
        state.security.function_state_read(prop_id, data).map(adapt_answer)
    }

    /// Apply one Security IO load-control record.
    ///
    /// The record's first octet is the load event; its remaining nine octets
    /// are event-specific information (03/05/01 §4.2.5). This Security IO
    /// uses no allocation records, so only the event is consumed.
    fn write_load_control(state: &mut DataSecureState<S, GRP, GO>, data: &[u8]) -> PropertyReturnCode {
        let Some(&event) = data.first() else {
            return PropertyReturnCode::DataTypeConflict;
        };
        let sec = &state.security;
        let (next, action) = load_control_transition(sec.load_state(), event.into());
        if action == LoadAction::Unload {
            // Unloading empties the tables the S-AL would otherwise
            // evaluate. Clear the durable SIAT first so a storage failure
            // cannot publish an Unloaded state while leaving a live replay
            // window behind. It deliberately does *not* touch the tool key:
            // the tool that unloaded the object must remain able to reach it.
            if state.seq.siat_clear().is_err() {
                return PropertyReturnCode::MemoryError;
            }
            sec.grp_keys().borrow_mut().clear();
            sec.go_flags().borrow_mut().clear();
        }
        sec.set_load_state(next);
        PropertyReturnCode::Success
    }

    /// PDT_CONTROL responses always carry the current one-octet state, even
    /// when the requested transition failed (03/05/01 §4.2.5).
    fn load_state_result<const N: usize>(code: PropertyReturnCode, state: LoadState) -> FunctionResult<N> {
        let mut data = Vec::new();
        data.push(state.into()).expect("a function response fits one load-state octet");
        FunctionResult { code, data }
    }
}
