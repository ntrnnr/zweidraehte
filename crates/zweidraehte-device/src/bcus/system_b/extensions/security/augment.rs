//! Security Interface Object augment.
//!
//! Provides the Security Interface Object (Object Type 0x11) as an
//! augment-provided object. This adds one additional object to the
//! device's IO list without modifying the base System B objects.

use core::cell::RefCell;

use super::SecurityTable;
use crate::StackDefinition;
use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult, PropertyBuf,
    PropertyError, WriteResponse, interface_object_augment, pid,
};
use crate::objects::tables::{LoadEvent, LoadState};
use crate::service::ServiceCtx;
use crate::storage::SequenceNumberStorage;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{
    InterfaceObjectType, PDT_BinaryInformation, PDT_Control, PDT_Function, PDT_Generic01, PDT_Generic02, PDT_Generic06,
    PDT_Generic08, PDT_Generic16, PDT_Generic18, PDT_Generic20, PDT_UnsignedChar, PDT_UnsignedInt,
};
use zweidraehte_proto::properties::PropertyRead;

use super::SecurityState;

// ============================================================================
// SecurityAugment
// ============================================================================

/// Augment that provides the Security Interface Object.
///
/// This augment reports one additional interface object
/// (`InterfaceObjectType::Security`) and handles property dispatch for
/// all Security IO PIDs.
//
// Access policies per KNX Profiles v02.02.01, page 116. The macro
// generates the descriptor table, `get_property_descriptor`,
// `property_description_read`, `additional_object_*`, and the dispatch
// arms for the simple PIDs declared inline; the imperative handlers for
// state-machine cascades, array tables, and function-property frames
// live in the `handle_extra_pid_*` methods further down.
#[interface_object_augment(
    // `additional_objects` adds the Security IO to the device's IO list
    // and (implicitly) makes it the dispatch target for every PID below.
    additional_objects = [InterfaceObjectType::Security],
)]
pub struct SecurityAugment<
    'a,
    SEQ: SequenceNumberStorage,
    const GRP: usize,
    const P2P: usize,
    const SIAT: usize,
    const GO: usize,
> {
    state: &'a SecurityState<GRP, P2P, SIAT, GO>,
    seq_storage: &'a RefCell<SEQ>,

    // PIDs are listed in spec-prescribed order (Profiles §9.1.2.6.4):
    // OBJECT_TYPE(1), LOAD_STATE_CONTROL(5), SECURITY_MODE(51), key tables
    // (52/53/54), SECURITY_FAILURES_LOG(55), TOOL_KEY(56), report (57/58),
    // SEQUENCE_NUMBER_SENDING(59), GO_SECURITY_FLAGS(61),
    // TEST_FAILURE_COUNTERS(203 — mfr-specific). The macro emits
    // `DESCRIPTORS` and the index-scan path in declaration order, so
    // index-based property-description reads return the spec-defined
    // prop_idx values.

    // PID 1 OBJECT_TYPE — fixed `InterfaceObjectType::Security` (0x0011) read.
    #[io(
        pid = pid::OBJECT_TYPE,
        pdt = PDT_UnsignedInt,
        access = RO,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL, // 3FF/0CC
        rl = 3, wl = 0,
        read = |_this: &Self| -> [u8; 2] {
            let v: u16 = InterfaceObjectType::Security.into();
            v.to_be_bytes()
        },
    )]
    _object_type_io: (),

    // PID 5 LOAD_STATE_CONTROL — write triggers state-machine + seq seeding.
    #[io(
        pid = pid::LOAD_STATE_CONTROL,
        pdt = PDT_Control,
        access = RW,
        policy = AccessPolicy::RESTRICTED, // 15F/04C
        rl = 2, wl = 2,
        manual,
    )]
    _load_state_control_io: (),

    // PID 51 SECURITY_MODE — PDT_Function, dispatched via FunctionPropertyCommand.
    #[io(
        pid = pid::security::SECURITY_MODE,
        pdt = PDT_Function,
        access = RW,
        policy = AccessPolicy::RESTRICTED, // 15F/04C
        rl = 2, wl = 2,
        manual,
    )]
    _security_mode_io: (),

    // PID 52 P2P_KEY_TABLE — PDT_GENERIC_20 array.
    #[io(
        pid = pid::security::P2P_KEY_TABLE,
        pdt = PDT_Generic20,
        access = RW,
        policy = AccessPolicy::TOOL_ONLY, // 00C/00C
        rl = 2, wl = 2,
        array(max = 0),
        manual,
    )]
    _p2p_key_table_io: (),

    // PID 53 GROUP_KEY_TABLE — PDT_GENERIC_18 array.
    #[io(
        pid = pid::security::GROUP_KEY_TABLE,
        pdt = PDT_Generic18,
        access = RW,
        policy = AccessPolicy::TOOL_ONLY,
        rl = 2, wl = 2,
        array(max = 0),
        manual,
    )]
    _group_key_table_io: (),

    // PID 54 SECURITY_INDIVIDUAL_ADDRESS_TABLE — PDT_GENERIC_08 array.
    #[io(
        pid = pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
        pdt = PDT_Generic08,
        access = RW,
        policy = AccessPolicy::TOOL_ONLY,
        rl = 2, wl = 2,
        array(max = 0),
        manual,
    )]
    _siat_io: (),

    // PID 55 SECURITY_FAILURES_LOG — PDT_FUNCTION; clear via
    // FunctionPropertyCommand, read counters/entries via FunctionPropertyStateRead.
    // ReadOnly per descriptor, but FunctionPropertyCommand is allowed
    // (the dispatch layer treats function commands separately from value writes).
    #[io(
        pid = pid::security::SECURITY_FAILURES_LOG,
        pdt = PDT_Function,
        access = RO,
        policy = AccessPolicy::new(0x1FF, 0x0CC),
        rl = 3, wl = 2,
        array(max = 0),
        manual,
    )]
    _security_failures_log_io: (),

    // PID 56 TOOL_KEY — write-only 16-byte key.
    #[io(
        pid = pid::security::TOOL_KEY,
        pdt = PDT_Generic16,
        access = WO,
        policy = AccessPolicy::TOOL_ONLY_CONFIDENTIAL, // 008/008
        rl = 0, wl = 2,
        write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
            if data.len() < 16 {
                return Err(PropertyError::BufferTooSmall);
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&data[..16]);
            this.state.set_tool_key(key);
            Ok(WriteResponse::Echo)
        },
    )]
    _tool_key_io: (),

    // PID 57 SECURITY_REPORT — single-byte report flags
    // (DPT_Security_Report 21.1002, b0 = Security Failure).
    #[io(
        pid = pid::security::SECURITY_REPORT,
        pdt = PDT_Generic01,
        access = RW,
        policy = AccessPolicy::new(0x1FF, 0x0CC),
        rl = 3, wl = 2,
        read = |this: &Self| -> [u8; 1] { [this.state.security_report()] },
        write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
            if data.is_empty() {
                return Err(PropertyError::BufferTooSmall);
            }
            this.state.set_security_report(data[0]);
            Ok(WriteResponse::Echo)
        },
    )]
    _security_report_io: (),

    // PID 58 SECURITY_REPORT_CONTROL — DPT_Enable 1.003 (single bit, 1
    // byte on the wire).
    #[io(
        pid = pid::security::SECURITY_REPORT_CONTROL,
        pdt = PDT_BinaryInformation,
        access = RW,
        policy = AccessPolicy::TOOL_ONLY, // 00C/00C
        rl = 2, wl = 2,
        read = |this: &Self| -> [u8; 1] {
            [if this.state.security_report_enabled() { 0x01 } else { 0x00 }]
        },
        write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
            if data.is_empty() {
                return Err(PropertyError::BufferTooSmall);
            }
            this.state.set_security_report_enabled(data[0] != 0);
            Ok(WriteResponse::Echo)
        },
    )]
    _security_report_control_io: (),

    // PID 59 SEQUENCE_NUMBER_SENDING — 6-byte tool counter behind seq_storage RefCell.
    #[io(
        pid = pid::security::SEQUENCE_NUMBER_SENDING,
        pdt = PDT_Generic06,
        access = RW,
        policy = AccessPolicy::TOOL_ONLY, // 00C/00C
        rl = 2, wl = 2,
        manual,
    )]
    _sequence_number_sending_io: (),

    // PID 61 GO_SECURITY_FLAGS — per-GO security requirements (1 byte/entry).
    #[io(
        pid = pid::security::GO_SECURITY_FLAGS,
        pdt = PDT_UnsignedChar,
        access = RW,
        policy = AccessPolicy::TOOL_ONLY,
        rl = 2, wl = 2,
        array(max = 0),
        manual,
    )]
    _go_security_flags_io: (),

    // PID 203 TEST_FAILURE_COUNTERS — manufacturer-specific direct view of the
    // four 16-bit failure counters. Used only by conformance test 3.8.12.6.
    #[io(
        pid = pid::security::TEST_FAILURE_COUNTERS,
        pdt = PDT_Generic02,
        access = RW,
        policy = AccessPolicy::TOOL_ONLY,
        rl = 2, wl = 2,
        array(max = 4),
        manual,
    )]
    _test_failure_counters_io: (),
}

impl<'a, SEQ: SequenceNumberStorage, const GRP: usize, const P2P: usize, const SIAT: usize, const GO: usize>
    SecurityAugment<'a, SEQ, GRP, P2P, SIAT, GO>
{
    /// Create a new security augment backed by the given state and
    /// sequence number storage.
    pub fn new(state: &'a SecurityState<GRP, P2P, SIAT, GO>, seq_storage: &'a RefCell<SEQ>) -> Self {
        Self { state, seq_storage }
    }
}

// ============================================================================
// Manual fallback methods invoked by the macro-generated dispatch arms.
//
// PIDs marked `manual` in the struct attributes route here. Unhandled PIDs
// must return `None` so the augment chain can fall through.
// ============================================================================

impl<'a, SEQ: SequenceNumberStorage, const GRP: usize, const P2P: usize, const SIAT: usize, const GO: usize>
    SecurityAugment<'a, SEQ, GRP, P2P, SIAT, GO>
{
    /// All Security PIDs are statically known — no runtime-conditional
    /// descriptors. Always falls through to the macro's static lookup.
    pub fn handle_extra_pid_descriptor(
        &self,
        _object_type: InterfaceObjectType,
        _prop_id: u16,
    ) -> Option<zweidraehte_proto::properties::PropertyDescriptor> {
        None
    }

    pub fn handle_extra_pid_read<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        Some(match req.pid {
            // PID 5 LOAD_STATE_CONTROL — single-byte load state.
            pid::LOAD_STATE_CONTROL => {
                let val: u8 = self.state.load_state().into();
                [val].read_property(req.start_idx, req.count, buf)
            }
            // PID 51 SECURITY_MODE — exposed through both regular reads and
            // function-property state reads. The regular read returns the
            // raw mode byte.
            pid::security::SECURITY_MODE => {
                let val: u8 = if self.state.security_mode_enabled() { 1 } else { 0 };
                [val].read_property(req.start_idx, req.count, buf)
            }
            // PID 52 P2P_KEY_TABLE — array (20 bytes/entry).
            pid::security::P2P_KEY_TABLE => read_table_with_count_probe(&self.state.p2p_keys().borrow(), req, buf),
            // PID 53 GROUP_KEY_TABLE — array (18 bytes/entry).
            pid::security::GROUP_KEY_TABLE => read_table_with_count_probe(&self.state.grp_keys().borrow(), req, buf),
            // PID 54 SECURITY_INDIVIDUAL_ADDRESS_TABLE — array (8 bytes/entry).
            pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE => {
                read_table_with_count_probe(&self.state.siat().borrow(), req, buf)
            }
            // PID 55 SECURITY_FAILURES_LOG — read-only at the value level;
            // accessed via FunctionPropertyStateRead.
            pid::security::SECURITY_FAILURES_LOG => Err(PropertyError::InvalidPropertyId),
            // PID 59 SEQUENCE_NUMBER_SENDING — the device's single Sequence Number
            // Sending (KNX 03/03/07 §5.x), shared by group, P2P, broadcast and
            // tool-access sends. ETS reads this to learn what value to expect from
            // the device on every Secure Link.
            pid::security::SEQUENCE_NUMBER_SENDING => {
                if req.start_idx == 0 {
                    buf[0..2].copy_from_slice(&1u16.to_be_bytes());
                    Ok(2)
                } else {
                    if buf.len() < 6 {
                        return Some(Err(PropertyError::BufferTooSmall));
                    }
                    let storage = self.seq_storage.borrow();
                    let Ok(seq) = storage.load_sending_seq() else {
                        return Some(Err(PropertyError::InvalidPropertyId));
                    };
                    buf[..6].copy_from_slice(&seq);
                    Ok(6)
                }
            }
            // PID 61 GO_SECURITY_FLAGS — array (1 byte/entry).
            pid::security::GO_SECURITY_FLAGS => read_table_with_count_probe(&self.state.go_flags().borrow(), req, buf),
            // PID 203 TEST_FAILURE_COUNTERS — manufacturer-specific direct
            // view of the four 16-bit failure counters.
            pid::security::TEST_FAILURE_COUNTERS => {
                let counters = self.state.failures_log().borrow().counters_as_bytes();
                if req.start_idx == 0 {
                    if buf.len() < 2 {
                        return Some(Err(PropertyError::BufferTooSmall));
                    }
                    buf[..2].copy_from_slice(&4u16.to_be_bytes());
                    Ok(2)
                } else {
                    let start = (req.start_idx - 1) as usize * 2;
                    let bytes = req.count as usize * 2;
                    if start + bytes > counters.len() {
                        return Some(Err(PropertyError::ValueOutOfRange));
                    }
                    if buf.len() < bytes {
                        return Some(Err(PropertyError::BufferTooSmall));
                    }
                    buf[..bytes].copy_from_slice(&counters[start..start + bytes]);
                    Ok(bytes)
                }
            }
            _ => return None,
        })
    }

    pub fn handle_extra_pid_write<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        Some(match req.pid {
            // PID 5 LOAD_STATE_CONTROL — Realisation Type 1 state machine
            // (spec 03/05/01 §4.23.2). On Unloaded → Loaded, seed receiving
            // sequence numbers from the SIAT.
            pid::LOAD_STATE_CONTROL => {
                if req.data.is_empty() {
                    return Some(Err(PropertyError::BufferTooSmall));
                }
                let event = LoadEvent::from(req.data[0]);
                let cur = self.state.load_state();
                let new_state = match event {
                    LoadEvent::NoOp => cur,
                    LoadEvent::StartLoading => match cur {
                        LoadState::Err => cur,
                        _ => LoadState::Loading,
                    },
                    LoadEvent::LoadCompleted => match cur {
                        LoadState::Loading => LoadState::Loaded,
                        _ => cur,
                    },
                    LoadEvent::Unload => LoadState::Unloaded,
                    _ => cur,
                };
                self.state.set_load_state(new_state);
                if new_state == LoadState::Loaded && cur != LoadState::Loaded {
                    self.state.seed_receiving_seqs(&mut *self.seq_storage.borrow_mut());
                }
                Ok(WriteResponse::byte(new_state.into()))
            }
            // PID 51 SECURITY_MODE — also writeable via plain value writes
            // (in addition to the FunctionPropertyCommand path).
            pid::security::SECURITY_MODE => {
                if req.data.is_empty() {
                    return Some(Err(PropertyError::BufferTooSmall));
                }
                self.state.set_security_mode_enabled(req.data[0] != 0);
                Ok(WriteResponse::Echo)
            }
            pid::security::P2P_KEY_TABLE => {
                let mut table = self.state.p2p_keys().borrow_mut();
                write_security_table(&mut table, req)
            }
            pid::security::GROUP_KEY_TABLE => {
                let mut table = self.state.grp_keys().borrow_mut();
                write_security_table(&mut table, req)
            }
            pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE => {
                let mut table = self.state.siat().borrow_mut();
                write_security_table(&mut table, req)
            }
            pid::security::GO_SECURITY_FLAGS => {
                let mut table = self.state.go_flags().borrow_mut();
                write_security_table(&mut table, req)
            }
            // PID 59 SEQUENCE_NUMBER_SENDING — the device's single Sequence Number
            // Sending (KNX 03/03/07 §5.x). ETS writes this to advance the counter
            // it expects the device to use for *all* outgoing secure frames (group
            // and tool-access), so we apply it to both storage slots in lockstep.
            pid::security::SEQUENCE_NUMBER_SENDING => {
                if req.start_idx == 0 {
                    Ok(WriteResponse::Echo)
                } else {
                    if req.data.len() < 6 {
                        return Some(Err(PropertyError::BufferTooSmall));
                    }
                    let mut value = [0u8; 6];
                    value.copy_from_slice(&req.data[..6]);
                    if value == [0u8; 6] {
                        return Some(Err(PropertyError::ValueOutOfRange));
                    }
                    let mut storage = self.seq_storage.borrow_mut();
                    let _ = storage.save_sending_seq(&value);
                    Ok(WriteResponse::Echo)
                }
            }
            // PID 203 TEST_FAILURE_COUNTERS — replace counters wholesale.
            pid::security::TEST_FAILURE_COUNTERS => {
                if req.start_idx == 0 {
                    return Some(Ok(WriteResponse::Echo));
                }
                let start = (req.start_idx - 1) as usize;
                let count = req.count as usize;
                if start + count > 4 || req.data.len() < count * 2 {
                    return Some(Err(PropertyError::ValueOutOfRange));
                }
                let mut log = self.state.failures_log().borrow_mut();
                let mut counters = *log.counters();
                for i in 0..count {
                    let off = i * 2;
                    counters[start + i] = u16::from_be_bytes([req.data[off], req.data[off + 1]]);
                }
                log.set_counters(counters);
                Ok(WriteResponse::Echo)
            }
            _ => return None,
        })
    }

    pub fn handle_extra_pid_function_command<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        match req.prop_id {
            pid::security::SECURITY_MODE => return Some(self.handle_security_mode_command(req)),
            pid::security::SECURITY_FAILURES_LOG => {}
            _ => return None,
        }

        // PID_SECURITY_FAILURES_LOG handler: Command format: [id, info, ...].
        // Only id=0, info=0 is defined (clear the log).
        if req.service_data.is_empty() {
            return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[]) });
        }
        let id = req.service_data[0];
        if req.service_data.len() < 2 {
            return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[id]) });
        }
        let info = req.service_data[1];

        match id {
            0 if info == 0 => {
                self.state.failures_log().borrow_mut().clear();
                Some(FunctionPropertyResult::success_with_data(&[id]))
            }
            0 => Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[id]) }),
            _ => Some(FunctionPropertyResult { return_code: 0xF2, data: PropertyBuf::new(&[id]) }),
        }
    }

    pub fn handle_extra_pid_function_state_read<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        if req.prop_id == pid::security::SECURITY_MODE {
            return Some(self.handle_security_mode_state_read(req));
        }

        if req.prop_id != pid::security::SECURITY_FAILURES_LOG {
            return None;
        }

        // Short frame handling: need at least id and info bytes.
        if req.service_data.is_empty() {
            return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[]) });
        }
        // FunctionPropertyExtStateRead service data layout:
        //   service_data[0] = service_id (0 for standard state reads)
        //   service_data[1] = service_info (0=counters, 1=entries)
        //   service_data[2..] = data (entry index for service_info=1)
        let service_id = req.service_data[0];
        if req.service_data.len() < 2 {
            return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[service_id]) });
        }
        let service_info = req.service_data[1];

        if service_id != 0 {
            return Some(FunctionPropertyResult { return_code: 0xF2, data: PropertyBuf::new(&[service_id]) });
        }

        match service_info {
            // service_info=0: 4 × 2-byte BE counters (8 bytes).
            0 => {
                let data_byte = req.service_data.get(2).copied().unwrap_or(0);
                if data_byte != 0 {
                    return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[service_id]) });
                }
                let log = self.state.failures_log().borrow();
                let counter_bytes = log.counters_as_bytes();
                let mut data = [0u8; 10];
                data[0] = service_id;
                data[1] = service_info;
                data[2..10].copy_from_slice(&counter_bytes);
                Some(FunctionPropertyResult::success_with_data(&data))
            }
            // service_info=1: Nth most recent 12-byte failure entry.
            1 => {
                if req.service_data.len() < 3 {
                    return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[service_info]) });
                }
                let entry_index = req.service_data[2];
                let log = self.state.failures_log().borrow();
                if let Some(entry) = log.get_by_index(entry_index) {
                    let src_bytes = entry.source_addr.to_be_bytes();
                    let mut data = [0u8; 14];
                    data[0] = service_info;
                    data[1] = entry_index;
                    data[2..4].copy_from_slice(&src_bytes);
                    data[4..13].copy_from_slice(&entry.frame_fragment);
                    data[13] = entry.failure_type;
                    Some(FunctionPropertyResult::success_with_data(&data))
                } else {
                    Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[service_info]) })
                }
            }
            _ => Some(FunctionPropertyResult { return_code: 0xF2, data: PropertyBuf::new(&[service_info]) }),
        }
    }
}

// ============================================================================
// Private Helpers
// ============================================================================

impl<'a, SEQ: SequenceNumberStorage, const GRP: usize, const P2P: usize, const SIAT: usize, const GO: usize>
    SecurityAugment<'a, SEQ, GRP, P2P, SIAT, GO>
{
    /// Handle PID_SECURITY_MODE FunctionPropertyCommand.
    ///
    /// ServiceID 0x00: Write Security Mode.
    /// ServiceInfo: 0x00 = disable, 0x01 = enable.
    fn handle_security_mode_command(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        // Command format: [reserved, service_id, service_info]
        if req.service_data.len() < 3 {
            return FunctionPropertyResult::not_supported();
        }
        let service_id = req.service_data[1];
        let service_info = req.service_data[2];

        if service_id != 0x00 {
            return FunctionPropertyResult::not_supported();
        }

        match service_info {
            0x00 => {
                self.state.set_security_mode_enabled(false);
                FunctionPropertyResult::success_with_data(&[service_id])
            }
            0x01 => {
                self.state.set_security_mode_enabled(true);
                FunctionPropertyResult::success_with_data(&[service_id])
            }
            _ => {
                // Invalid ServiceInfo → E_DATA_VOID (0xF8)
                FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[service_id]) }
            }
        }
    }

    /// Handle PID_SECURITY_MODE FunctionPropertyStateRead.
    ///
    /// Service format: [reserved, ReadServiceID]
    /// ReadServiceID 0x00: Read Security Mode → returns current mode byte.
    fn handle_security_mode_state_read(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        if req.service_data.len() < 2 {
            // Too few bytes.
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }

        let reserved = req.service_data[0];
        let read_service_id = req.service_data[1];

        // Reserved byte must be 0.
        if reserved != 0x00 {
            return FunctionPropertyResult { return_code: 0xA0, data: PropertyBuf::new(&[reserved, read_service_id]) };
        }

        // Only ReadServiceID 0x00 is supported.
        if read_service_id != 0x00 {
            return FunctionPropertyResult { return_code: 0xF2, data: PropertyBuf::new(&[read_service_id]) };
        }

        let mode = if self.state.security_mode_enabled() { 0x01u8 } else { 0x00u8 };
        // Response echoes the ReadServiceID (0x00) followed by the mode byte.
        FunctionPropertyResult::success_with_data(&[0x00, mode])
    }
}

/// Read from a `SecurityTable` using the standard array-property protocol:
/// `start_idx == 0` returns the current entry count as a 2-byte big-endian
/// value (the "count probe"); `start_idx >= 1` reads `count` entries
/// starting at the 0-based offset `start_idx - 1`.
pub(in crate::bcus::system_b::extensions) fn read_table_with_count_probe<const N: usize, const ES: usize>(
    table: &SecurityTable<N, ES>,
    req: &FullPropertyReadRequest,
    buf: &mut [u8],
) -> Result<usize, PropertyError> {
    if req.start_idx == 0 {
        if buf.len() < 2 {
            return Err(PropertyError::BufferTooSmall);
        }
        buf[..2].copy_from_slice(&table.count().to_be_bytes());
        Ok(2)
    } else {
        let start = (req.start_idx - 1) as u16;
        table.read_entries(start, req.count as u16, buf)
    }
}

/// Write to a SecurityTable, handling element-count writes (start_idx=0)
/// vs data writes (start_idx>0).
///
/// Element-count writes expect exactly 2 bytes (u16 BE new count).
/// Setting count to 0 clears the table.
pub(in crate::bcus::system_b::extensions) fn write_security_table<const N: usize, const ES: usize>(
    table: &mut SecurityTable<N, ES>,
    req: &FullPropertyWriteRequest<'_>,
) -> Result<WriteResponse, PropertyError> {
    if req.start_idx == 0 {
        // Element count write.
        if req.data.len() < 2 {
            return Err(PropertyError::BufferTooSmall);
        }
        let new_count = u16::from_be_bytes([req.data[0], req.data[1]]);
        if new_count == 0 {
            table.clear();
        } else {
            // Pre-allocate: set the count so subsequent entry writes at
            // start_idx > 0 land within the valid range. The actual entry
            // data is written via separate requests with start_idx > 0.
            table.set_count(new_count);
        }
        Ok(WriteResponse::Echo)
    } else {
        let start = req.start_idx.saturating_sub(1);
        match table.write_entries(start, req.data) {
            Ok(()) => Ok(WriteResponse::Echo),
            Err(e) => Err(e),
        }
    }
}
