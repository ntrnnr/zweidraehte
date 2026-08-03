//! Security Interface Object augment.
//!
//! Provides the Security Interface Object (Object Type 0x11) as an
//! augment-provided object. This adds one additional object to the
//! device's IO list without modifying the base System B objects.

use core::cell::RefCell;

use super::SecurityTable;
use crate::StackDefinition;
use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult, PropertyError,
    WriteResponse, interface_object_augment, pid,
};
use crate::objects::tables::{LoadEvent, LoadState};
use crate::service::ServiceCtx;
use crate::storage::SequenceNumberStorage;
use crate::storage::views::SiatAccess;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{
    InterfaceObjectType, PDT_BinaryInformation, PDT_Control, PDT_Function, PDT_Generic01, PDT_Generic02, PDT_Generic06,
    PDT_Generic08, PDT_Generic16, PDT_Generic18, PDT_Generic20, PDT_UnsignedChar, PDT_UnsignedInt,
};
use zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode;
use zweidraehte_proto::properties::PropertyRead;

use super::SecurityState;

/// The Security Interface Object's name (PID_OBJECT_NAME, ten
/// `PDT_UNSIGNED_CHAR` elements). The value itself is free; the length is
/// what the conformance template exercises.
const SECURITY_OBJECT_NAME: [u8; 10] = *b"SecurityIO";

// ============================================================================
// SecurityAugment
// ============================================================================

/// Augment that provides the Security Interface Object.
///
/// This augment reports one additional interface object
/// (`InterfaceObjectType::Security`) and handles property dispatch for
/// all Security IO PIDs.
///
/// Profiles §9.1.2.6.4 writes the Security IO's access levels in the
/// 4-level notation — `3/X` on PID 1, 2, 55 and 57 — but this object is
/// composed onto whichever base profile hosts it, and the number of
/// authorisation levels belongs to that profile (§4.2 row 12: 4 for
/// System B, 16 for System 7). So the levels below name their audience
/// from 03/04/01 Table 1 and the device resolves them: `Runtime`
/// lands on 3 or 15, `Configuration` on 2 either way.
//
// Access policies per KNX Profiles v02.02.01, page 116. The macro
// generates the descriptor table, `property_descriptor`,
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
    SEQ: SequenceNumberStorage + SiatAccess,
    const GRP: usize,
    const P2P: usize,
    const GO: usize,
> {
    state: &'a SecurityState<GRP, P2P, GO>,
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
        rl = Runtime, wl = SystemManufacturer,
        read = |_this: &Self| -> [u8; 2] {
            let v: u16 = InterfaceObjectType::Security.into();
            v.to_be_bytes()
        },
    )]
    _object_type_io: (),

    // PID 2 OBJECT_NAME — optional-recommended per 03/05/01 §4.2.2; the
    // data-security template's 3.8.2 reads it back (fifteen requested
    // elements clamp to the ten stored ones) and expects the write
    // refused. RO with the open-read policy the suite's 3FF/0CC title
    // names.
    #[io(
        pid = pid::OBJECT_NAME,
        pdt = PDT_UnsignedChar,
        access = RO,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL, // 3FF/0CC
        rl = Runtime, wl = SystemManufacturer,
        array(max = 10),
        manual,
    )]
    _object_name_io: (),

    // PID 5 LOAD_STATE_CONTROL — write triggers state-machine + seq seeding.
    #[io(
        pid = pid::LOAD_STATE_CONTROL,
        pdt = PDT_Control,
        access = RW,
        policy = AccessPolicy::RESTRICTED, // 15F/04C
        rl = Configuration, wl = Configuration,
        manual,
    )]
    _load_state_control_io: (),

    // PID 51 SECURITY_MODE — PDT_Function, dispatched via FunctionPropertyCommand.
    #[io(
        pid = pid::security::SECURITY_MODE,
        pdt = PDT_Function,
        access = RW,
        policy = AccessPolicy::RESTRICTED, // 15F/04C
        rl = Configuration, wl = Configuration,
        manual,
    )]
    _security_mode_io: (),

    // PID 52 P2P_KEY_TABLE — PDT_GENERIC_20 array.
    #[io(
        pid = pid::security::P2P_KEY_TABLE,
        pdt = PDT_Generic20,
        access = RW,
        policy = AccessPolicy::TOOL_ONLY, // 00C/00C
        rl = Configuration, wl = Configuration,
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
        rl = Configuration, wl = Configuration,
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
        rl = Configuration, wl = Configuration,
        array(max = 0),
        manual,
    )]
    _siat_io: (),

    // PID 55 SECURITY_FAILURES_LOG — PDT_FUNCTION; clear via
    // FunctionPropertyCommand, read counters/entries via FunctionPropertyStateRead.
    // Declared RW so the descriptor advertises the function-command channel
    // (write_enable set — TSS J 3.8.12.9 pins BEh); value writes stay
    // refused by the PDT_FUNCTION gate in the property services. Max
    // elements is 1: zero "indicates a problem" per 03/03/07 §3.4.3.2.
    #[io(
        pid = pid::security::SECURITY_FAILURES_LOG,
        pdt = PDT_Function,
        access = RW,
        policy = AccessPolicy::new(0x1FF, 0x0CC),
        rl = Runtime, wl = Configuration,
        array(max = 1),
        manual,
    )]
    _security_failures_log_io: (),

    // PID 56 TOOL_KEY — write-only 16-byte key.
    #[io(
        pid = pid::security::TOOL_KEY,
        pdt = PDT_Generic16,
        access = WO,
        policy = AccessPolicy::TOOL_ONLY_CONFIDENTIAL, // 008/008
        rl = SystemManufacturer, wl = Configuration,
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
        rl = Runtime, wl = Configuration,
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
        rl = Configuration, wl = Configuration,
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
        rl = Configuration, wl = Configuration,
        manual,
    )]
    _sequence_number_sending_io: (),

    // PID 61 GO_SECURITY_FLAGS — per-GO security requirements. Each
    // element is PDT_GENERIC_01 (03/05/01 §6.3.15; TSS J 3.8.17.4 pins
    // 91h = write_enable | 11h), not PDT_UNSIGNED_CHAR.
    #[io(
        pid = pid::security::GO_SECURITY_FLAGS,
        pdt = PDT_Generic01,
        access = RW,
        policy = AccessPolicy::TOOL_ONLY,
        rl = Configuration, wl = Configuration,
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
        rl = Configuration, wl = Configuration,
        array(max = 4),
        manual,
    )]
    _test_failure_counters_io: (),
}

impl<'a, SEQ: SequenceNumberStorage + SiatAccess, const GRP: usize, const P2P: usize, const GO: usize>
    SecurityAugment<'a, SEQ, GRP, P2P, GO>
{
    /// Create a new security augment backed by the given state and
    /// sequence number storage.
    pub fn new(state: &'a SecurityState<GRP, P2P, GO>, seq_storage: &'a RefCell<SEQ>) -> Self {
        Self { state, seq_storage }
    }
}

// ============================================================================
// Manual fallback methods invoked by the macro-generated dispatch arms.
//
// PIDs marked `manual` in the struct attributes route here. Unhandled PIDs
// must return `None` so the augment chain can fall through.
// ============================================================================

impl<'a, SEQ: SequenceNumberStorage + SiatAccess, const GRP: usize, const P2P: usize, const GO: usize>
    SecurityAugment<'a, SEQ, GRP, P2P, GO>
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
            // PID 2 OBJECT_NAME — a fixed ten-character name; over-long
            // reads clamp to the stored characters (ArrayPropertyRead).
            pid::OBJECT_NAME => {
                use zweidraehte_proto::properties::ArrayPropertyRead;
                SECURITY_OBJECT_NAME.read_array_property(req.start_idx, req.count, 1, buf)
            }
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
            // Sourced live from the sequence store (the single source of truth
            // for each sender's Last Valid SeqNr, 03/05/01 §6.3.8), so a read
            // reflects the per-frame updates, not a frozen ETS snapshot.
            pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE => {
                read_siat_from_store(&*self.seq_storage.borrow(), req, buf)
            }
            // PID 55 SECURITY_FAILURES_LOG — PDT_Function. Its value is read
            // through FunctionPropertyStateRead, not a plain PropertyValue_Read.
            // The property *exists* (it has a descriptor), so we must not answer
            // a plain read with InvalidPropertyId — that maps to E_ADDRESS_VOID
            // ("property absent") and misrepresents a present property. A plain
            // read of a function property yields an empty value, mirroring the
            // AL's own "not PDT_Function → empty response" handling in
            // `services/function_property.rs`.
            pid::security::SECURITY_FAILURES_LOG => Ok(0),
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
                write_siat_to_store(&mut *self.seq_storage.borrow_mut(), req)
            }
            pid::security::GO_SECURITY_FLAGS => {
                let mut table = self.state.go_flags().borrow_mut();
                write_security_table(&mut table, req)
            }
            // PID 59 SEQUENCE_NUMBER_SENDING — the device's single Sequence Number
            // Sending (KNX 03/03/07 §5.x). ETS writes this to advance the counter
            // it expects the device to use for *all* outgoing secure frames (group
            // and tool-access); the store holds it as one singleton, so a single
            // write through `save_sending_seq` covers every send path.
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
                    // Propagate a persistence failure (matching the SIAT writes):
                    // if the counter isn't durably stored, ETS must not believe
                    // it advanced — a silent drop desyncs ETS from the device.
                    if storage.save_sending_seq(&value).is_err() {
                        return Some(Err(PropertyError::InvalidPropertyId));
                    }
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

        // PID_SECURITY_FAILURES_LOG command, 03/05/01 §6.3.9.3.2: the data
        // is `[Reserved(00h), WriteServiceID, ServiceInfo]` — the same
        // reserved-first layout as PID_SECURITY_MODE above, and the layout
        // TSS J 3.8.12.8 probes: its "incorrect ServiceID" telegram is
        // `00 05 00`, with the 05h in the *second* octet. Only
        // WriteServiceID 0 with ServiceInfo 0 is defined (clear the log).
        if req.service_data.len() < 2 {
            // Truncated before the WriteServiceID — nothing to echo.
            return Some(FunctionPropertyResult::with_code(PropertyReturnCode::Error, &[0]));
        }
        let id = req.service_data[1];
        let info = req.service_data.get(2).copied();

        match id {
            0 if info == Some(0) => {
                self.state.failures_log().borrow_mut().clear();
                Some(FunctionPropertyResult::success_with_data(&[id]))
            }
            // WriteServiceID 0 with a ServiceInfo that is missing or not
            // an implemented selector: void request data (Table 104
            // defines only 00h).
            0 => Some(FunctionPropertyResult::with_code(PropertyReturnCode::DataVoid, &[id])),
            _ => Some(FunctionPropertyResult::with_code(PropertyReturnCode::CommandInvalid, &[id])),
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

        // State-read data layout per 03/05/01 §6.3.9.3.3:
        // `[Reserved(00h), ReadServiceID, ...]` — reserved-first, like the
        // command above. ReadServiceID 00h reads the counters (its
        // ServiceInfo octet must be 00h), 01h reads the Nth latest
        // failure entry (the next octet is the entry index).
        if req.service_data.len() < 2 {
            // Truncated before the ReadServiceID. TSS J 3.8.12.7's
            // "incorrect Length" case pins F8h with a zero echo (its FFh
            // alternative ships deactivated), so void data it is.
            return Some(FunctionPropertyResult::with_code(PropertyReturnCode::DataVoid, &[0]));
        }
        let service_info = req.service_data[1];

        match service_info {
            // ReadServiceID 00h: 4 × 2-byte BE counters (8 bytes).
            0 => {
                let service_id = 0u8;
                let data_byte = req.service_data.get(2).copied().unwrap_or(0);
                if data_byte != 0 {
                    return Some(FunctionPropertyResult::with_code(PropertyReturnCode::DataVoid, &[service_id]));
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
                    return Some(FunctionPropertyResult::with_code(PropertyReturnCode::DataVoid, &[service_info]));
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
                    Some(FunctionPropertyResult::with_code(PropertyReturnCode::DataVoid, &[service_info]))
                }
            }
            _ => Some(FunctionPropertyResult::with_code(PropertyReturnCode::CommandInvalid, &[service_info])),
        }
    }
}

// ============================================================================
// Private Helpers
// ============================================================================

/// Build a negative `PID_SECURITY_MODE` response per 03/05/01 §6.3.5.3.
///
/// That clause fixes both halves of the answer. The payload is *only* the
/// echoed ServiceID ("repeating the ServiceID – ReadServiceID or
/// WriteServiceID – as appropriate"), never the request data that caused
/// the rejection. The code must be > 7Fh and is restricted to the basic
/// negative (FFh), the two generic negatives the clause admits (FEh, F8h),
/// and the single property-specific code in Table 102 (F2h
/// `E_COMMAND_INVALID`, for an invalid ServiceID).
///
/// Notably, Table 102 defines **no** entry in the specific-negative range
/// A0h–DFh (03/03/07 §3.4.5.5), so this property must never answer from
/// there. This helper exists to make that impossible: taking a
/// [`PropertyReturnCode`] keeps the response inside the generic table and
/// out of the disjoint `GoDiagReturnCode` space that `PID_OPERATION_MODE`
/// uses — the two overlap numerically, and A0h is `E_OM_ERROR` there.
fn security_mode_reject(code: PropertyReturnCode, service_id: u8) -> FunctionPropertyResult {
    FunctionPropertyResult::with_code(code, &[service_id])
}

impl<'a, SEQ: SequenceNumberStorage + SiatAccess, const GRP: usize, const P2P: usize, const GO: usize>
    SecurityAugment<'a, SEQ, GRP, P2P, GO>
{
    /// Handle PID_SECURITY_MODE `A_FunctionPropertyCommand` (03/05/01
    /// §6.3.5.1).
    ///
    /// Request: `[Reserved(00h), WriteServiceID, ServiceInfo]`.
    /// WriteServiceID 00h ("Write the Security Mode") is the only one
    /// defined; ServiceInfo 00h disables, 01h enables.
    ///
    /// Errors follow §6.3.5.3 — see [`security_mode_reject`] for the code
    /// space this property may answer from.
    fn handle_security_mode_command(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        if req.service_data.len() < 3 {
            // Truncated before the WriteServiceID, so there is nothing to
            // echo: only the basic negative code is left.
            return FunctionPropertyResult::with_code(PropertyReturnCode::Error, &[]);
        }
        let reserved = req.service_data[0];
        let service_id = req.service_data[1];
        let service_info = req.service_data[2];

        if reserved != 0x00 {
            return security_mode_reject(PropertyReturnCode::DataVoid, service_id);
        }

        if service_id != 0x00 {
            return security_mode_reject(PropertyReturnCode::CommandInvalid, service_id);
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
            // ServiceInfo is an enumeration; an unsupported value is void
            // request data (03/03/07 §3.4.5.5, E_DATA_VOID).
            _ => security_mode_reject(PropertyReturnCode::DataVoid, service_id),
        }
    }

    /// Handle PID_SECURITY_MODE `A_FunctionPropertyState_Read` (03/05/01
    /// §6.3.5.2).
    ///
    /// Request: `[Reserved(00h), ReadServiceID]`. ReadServiceID 00h ("Read
    /// the current Security Mode") is the only one defined and answers with
    /// `[ReadServiceID, Security Mode]` after the return code (Figure 71).
    ///
    /// Errors follow §6.3.5.3 — see [`security_mode_reject`].
    fn handle_security_mode_state_read(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        if req.service_data.len() < 2 {
            // Truncated before the ReadServiceID — nothing to echo.
            return FunctionPropertyResult::with_code(PropertyReturnCode::Error, &[]);
        }

        let reserved = req.service_data[0];
        let read_service_id = req.service_data[1];

        if reserved != 0x00 {
            return security_mode_reject(PropertyReturnCode::DataVoid, read_service_id);
        }

        // Only ReadServiceID 0x00 is supported.
        if read_service_id != 0x00 {
            return security_mode_reject(PropertyReturnCode::CommandInvalid, read_service_id);
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
pub(crate) fn read_table_with_count_probe<const N: usize, const ES: usize>(
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
pub(crate) fn write_security_table<const N: usize, const ES: usize>(
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

/// PID 54 read against the live SIAT in the sequence store, using the same
/// array-property protocol as [`read_table_with_count_probe`]: `start_idx == 0`
/// returns the 2-byte entry count; `start_idx >= 1` returns `count` entries of
/// 8 bytes (IA(2) + SeqNr(6)) starting at the 0-based offset `start_idx - 1`,
/// in the store's IA-sorted order.
fn read_siat_from_store<S: SiatAccess>(
    store: &S,
    req: &FullPropertyReadRequest,
    buf: &mut [u8],
) -> Result<usize, PropertyError> {
    if req.start_idx == 0 {
        if buf.len() < 2 {
            return Err(PropertyError::BufferTooSmall);
        }
        buf[..2].copy_from_slice(&store.siat_count().to_be_bytes());
        return Ok(2);
    }
    let start = req.start_idx - 1;
    let total = store.siat_count();
    if start >= total {
        return Err(PropertyError::InvalidStartIndex);
    }
    let avail = total - start;
    let to_read = req.count.min(avail);
    let byte_count = to_read as usize * 8;
    if buf.len() < byte_count {
        return Err(PropertyError::BufferTooSmall);
    }
    for i in 0..to_read {
        let (ia, seq) = store.siat_read_entry(start + i).expect("index < count");
        let off = i as usize * 8;
        buf[off..off + 2].copy_from_slice(&ia.to_be_bytes());
        buf[off + 2..off + 8].copy_from_slice(&seq);
    }
    Ok(byte_count)
}

/// PID 54 write against the live SIAT in the sequence store. `start_idx == 0`
/// is an element-count write (0 clears); `start_idx >= 1` writes 8-byte entries
/// (IA(2) + SeqNr(6)) at the 0-based offset `start_idx - 1`. Mirrors
/// [`write_security_table`]'s protocol, but the SIAT is the store's, not a
/// `SecurityTable`. A store error maps to `InvalidPropertyId` (the property
/// service has no flash-error code).
fn write_siat_to_store<S: SiatAccess>(
    store: &mut S,
    req: &FullPropertyWriteRequest<'_>,
) -> Result<WriteResponse, PropertyError> {
    if req.start_idx == 0 {
        if req.data.len() < 2 {
            return Err(PropertyError::BufferTooSmall);
        }
        let new_count = u16::from_be_bytes([req.data[0], req.data[1]]);
        store.siat_set_count(new_count).map_err(|_| PropertyError::InvalidPropertyId)?;
        return Ok(WriteResponse::Echo);
    }
    // Entry write(s): one or more contiguous 8-byte entries landing at the
    // 1-based `req.start_idx`. The position is part of the payload's meaning:
    // it is the `IA_Index` the P2P key table joins on (03/05/01 §6.3.6.2), so
    // each entry replaces exactly the element the writer named.
    if req.data.is_empty() || req.data.len() % 8 != 0 {
        return Err(PropertyError::TypeMismatch);
    }
    for (i, chunk) in req.data.chunks_exact(8).enumerate() {
        let idx = req.start_idx - 1 + i as u16;
        let ia = u16::from_be_bytes([chunk[0], chunk[1]]);
        let mut seq = [0u8; 6];
        seq.copy_from_slice(&chunk[2..8]);
        store.siat_write_entry(idx, ia, seq).map_err(|_| PropertyError::InvalidPropertyId)?;
    }
    Ok(WriteResponse::Echo)
}
