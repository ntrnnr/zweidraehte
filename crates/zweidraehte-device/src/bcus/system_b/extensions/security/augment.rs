//! Security Interface Object augment.
//!
//! Provides the Security Interface Object (Object Type 0x11) as an
//! augment-provided object. This adds one additional object to the
//! device's IO list without modifying the base System B objects.

use core::cell::RefCell;

use super::SecurityTable;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{
    InterfaceObjectType, PDT_BinaryInformation, PDT_Control, PDT_Function, PDT_Generic01, PDT_Generic02, PDT_Generic06,
    PDT_Generic08, PDT_Generic18, PDT_UnsignedChar, PDT_UnsignedInt, PropertyDataDefinition,
};
use crate::objects::interface::{
    AugmentContext, FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult,
    InterfaceObjectAugment, PropertyAccess, PropertyBuf, PropertyDescriptionResponse, PropertyDescriptor,
    PropertyError, PropertyLookup, WriteResponse, pid,
};
use crate::objects::tables::LoadState;
use zweidraehte_proto::properties::PropertyRead;
use crate::storage::SequenceNumberStorage;
use crate::StackDefinition;

use super::SecurityState;

// ============================================================================
// SecurityAugment
// ============================================================================

/// Augment that provides the Security Interface Object.
///
/// This augment reports one additional interface object
/// (`InterfaceObjectType::Security`) and handles property dispatch for
/// all Security IO PIDs. In Phase 1, only PIDs 1 (OBJECT_TYPE),
/// 5 (LOAD_STATE_CONTROL), and 51 (SECURITY_MODE) are functional.
/// Remaining PIDs return `InvalidPropertyId` until Phase 2+.
pub struct SecurityAugment<'a, SEQ: SequenceNumberStorage, const GRP: usize, const P2P: usize, const GO: usize> {
    state: &'a SecurityState<GRP, P2P, GO>,
    seq_storage: &'a RefCell<SEQ>,
}

impl<'a, SEQ: SequenceNumberStorage, const GRP: usize, const P2P: usize, const GO: usize>
    SecurityAugment<'a, SEQ, GRP, P2P, GO>
{
    /// Create a new security augment backed by the given state and
    /// sequence number storage.
    pub fn new(state: &'a SecurityState<GRP, P2P, GO>, seq_storage: &'a RefCell<SEQ>) -> Self {
        Self { state, seq_storage }
    }

    /// Property descriptor table for the Security Interface Object.
    ///
    /// Access policies are per KNX Profiles v02.02.01, page 116.
    const DESCRIPTORS: &'static [PropertyDescriptor] = &[
        // PID_OBJECT_TYPE (1): always readable
        PropertyDescriptor::with_policy(
            pid::OBJECT_TYPE,
            PDT_UnsignedInt::ID,
            1,
            PropertyAccess::ReadOnly,
            3,
            0,
            AccessPolicy::READ_OPEN_WRITE_TOOL, // 3FF/0CC
        ),
        // PID_LOAD_STATE_CONTROL (5): security config loading
        PropertyDescriptor::with_policy(
            pid::LOAD_STATE_CONTROL,
            PDT_Control::ID,
            1,
            PropertyAccess::ReadWrite,
            2,
            2,
            AccessPolicy::RESTRICTED, // 15F/04C
        ),
        // PID_SECURITY_MODE (51): enables/disables Data Secure — PDT_FUNCTION
        // Accessed via A_FunctionPropertyCommand, not regular property read/write.
        PropertyDescriptor::with_policy(
            pid::SECURITY_MODE,
            PDT_Function::ID,
            1,
            PropertyAccess::ReadWrite,
            2,
            2,
            AccessPolicy::RESTRICTED, // 15F/04C
        ),
        // PID_P2P_KEY_TABLE (52): point-to-point encryption keys — PDT_GENERIC_20
        PropertyDescriptor::with_policy(
            pid::P2P_KEY_TABLE,
            0x24, // PDT_GENERIC_20 = 0x10 + 20
            0,
            PropertyAccess::ReadWrite,
            2,
            2,
            AccessPolicy::TOOL_ONLY, // 00C/00C
        ),
        // PID_GROUP_KEY_TABLE (53): group communication encryption keys — PDT_GENERIC_18
        PropertyDescriptor::with_policy(
            pid::GROUP_KEY_TABLE,
            PDT_Generic18::ID,
            0,
            PropertyAccess::ReadWrite,
            2,
            2,
            AccessPolicy::TOOL_ONLY, // 00C/00C
        ),
        // PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE (54): IA→SeqNr mapping — PDT_GENERIC_08
        PropertyDescriptor::with_policy(
            pid::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
            PDT_Generic08::ID,
            0,
            PropertyAccess::ReadWrite,
            2,
            2,
            AccessPolicy::TOOL_ONLY, // 00C/00C
        ),
        // PID_SECURITY_FAILURES_LOG (55): ring buffer of security events — PDT_FUNCTION
        PropertyDescriptor::with_policy(
            pid::SECURITY_FAILURES_LOG,
            PDT_Function::ID,
            0,
            PropertyAccess::ReadOnly,
            3,
            2,
            // 1FF/0CC per Profiles spec (not 15F/04C as in earlier skeleton)
            AccessPolicy::new(0x1FF, 0x0CC),
        ),
        // PID_TOOL_KEY (56): write-only 16-byte key — PDT_GENERIC_16
        PropertyDescriptor::with_policy(
            pid::TOOL_KEY,
            0x20, // PDT_GENERIC_16
            1,
            PropertyAccess::WriteOnly,
            // X/2: no read access, write at level 2
            // Using read_level 0 since WriteOnly prevents reads regardless
            0,
            2,
            AccessPolicy::TOOL_ONLY_CONFIDENTIAL, // 008/008
        ),
        // PID_SECURITY_REPORT (57): security status report — PDT_GENERIC_01 (1 byte).
        // ReadWrite: the report flags can be cleared by writing 0x00.
        PropertyDescriptor::with_policy(
            pid::SECURITY_REPORT,
            PDT_Generic01::ID,
            1,
            PropertyAccess::ReadWrite,
            3,
            2,
            // 1FF/0CC
            AccessPolicy::new(0x1FF, 0x0CC),
        ),
        // PID_SECURITY_REPORT_CONTROL (58): report control — PDT_BINARY_INFORMATION
        // (03/05/01 §6.3.12: DPT_Enable 1.003, single bit, 1 byte on the wire).
        PropertyDescriptor::with_policy(
            pid::SECURITY_REPORT_CONTROL,
            PDT_BinaryInformation::ID,
            1,
            PropertyAccess::ReadWrite,
            2,
            2,
            AccessPolicy::TOOL_ONLY, // 00C/00C
        ),
        // PID_SEQUENCE_NUMBER_SENDING (59): 48-bit anti-replay counter
        PropertyDescriptor::with_policy(
            pid::SEQUENCE_NUMBER_SENDING,
            PDT_Generic06::ID,
            1,
            PropertyAccess::ReadWrite,
            2,
            2,
            // 00C/00C per Profiles spec (not 00C/008 as in earlier skeleton)
            AccessPolicy::TOOL_ONLY,
        ),
        // PID_GO_SECURITY_FLAGS (61): per-GO security requirements
        PropertyDescriptor::with_policy(
            pid::GO_SECURITY_FLAGS,
            PDT_UnsignedChar::ID,
            0, // 0 elements until loaded
            PropertyAccess::ReadWrite,
            2,
            2,
            AccessPolicy::TOOL_ONLY, // 00C/00C
        ),
        // PID_TEST_FAILURE_COUNTERS (203): manufacturer-specific
        // direct view of `PID_SECURITY_FAILURES_LOG`'s four 16-bit
        // counters. Read returns the live counter array; write replaces
        // it. Used only by conformance test 3.8.12.6 to seed FFFFh
        // before provoking errors and observing that the saturating
        // increment in `SecurityFailuresLog::log_failure` holds.
        PropertyDescriptor::with_policy(
            pid::TEST_FAILURE_COUNTERS,
            PDT_Generic02::ID,
            4,
            PropertyAccess::ReadWrite,
            2,
            2,
            AccessPolicy::TOOL_ONLY, // 00C/00C
        ),
    ];

    /// Find a descriptor by PID.
    fn descriptor_by_pid(pid_val: u8) -> Option<(u16, &'static PropertyDescriptor)> {
        Self::DESCRIPTORS.iter().enumerate().find(|(_, d)| d.pid == pid_val).map(|(i, d)| (i as u16, d))
    }

    /// Find a descriptor by augment-local index.
    fn descriptor_by_index(index: u16) -> Option<&'static PropertyDescriptor> {
        Self::DESCRIPTORS.get(index as usize)
    }
}

impl<'a, D: StackDefinition, SEQ: SequenceNumberStorage, const GRP: usize, const P2P: usize, const GO: usize>
    InterfaceObjectAugment<D> for SecurityAugment<'a, SEQ, GRP, P2P, GO>
{
    fn get_property_descriptor(&self, object_type: InterfaceObjectType, prop_id: u8) -> Option<PropertyDescriptor> {
        if object_type != InterfaceObjectType::Security {
            return None;
        }
        Self::DESCRIPTORS.iter().find(|d| d.pid == prop_id).copied()
    }

    fn additional_object_count(&self) -> u16 {
        1
    }

    fn additional_object_type_at(&self, index: u16) -> Option<InterfaceObjectType> {
        if index == 0 { Some(InterfaceObjectType::Security) } else { None }
    }

    fn property_description_read(
        &self,
        _ctx: &AugmentContext<'_, D>,
        object_type: InterfaceObjectType,
        object_idx: u16,
        lookup: PropertyLookup,
    ) -> Option<Result<PropertyDescriptionResponse, PropertyError>> {
        if object_type != InterfaceObjectType::Security {
            return None;
        }

        let (prop_idx, desc) = match lookup {
            PropertyLookup::ByPid(pid_val) => Self::descriptor_by_pid(pid_val)?,
            PropertyLookup::ByIndex(idx) => {
                let desc = Self::descriptor_by_index(idx)?;
                (idx, desc)
            }
        };

        Some(Ok(PropertyDescriptionResponse::from_descriptor(object_idx, prop_idx, desc)))
    }

    fn property_value_read(
        &self,
        _ctx: &AugmentContext<'_, D>,
        object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        if object_type != InterfaceObjectType::Security {
            return None;
        }

        Some(match req.pid {
            pid::OBJECT_TYPE => {
                let obj_type: u16 = InterfaceObjectType::Security.into();
                obj_type.to_be_bytes().read_property(req.start_idx, req.count, buf)
            }
            pid::LOAD_STATE_CONTROL => {
                let val: u8 = self.state.load_state().into();
                [val].read_property(req.start_idx, req.count, buf)
            }
            pid::SECURITY_MODE => {
                let val: u8 = if self.state.security_mode_enabled() { 1 } else { 0 };
                [val].read_property(req.start_idx, req.count, buf)
            }
            // ---- Array property: P2P Key Table (20 bytes/entry) ----
            pid::P2P_KEY_TABLE => {
                let table = self.state.p2p_keys().borrow();
                if req.start_idx == 0 {
                    if buf.len() < 2 {
                        return Some(Err(PropertyError::BufferTooSmall));
                    }
                    buf[..2].copy_from_slice(&table.count().to_be_bytes());
                    Ok(2)
                } else {
                    let start = (req.start_idx - 1) as u16;
                    table.read_entries(start, req.count as u16, buf)
                }
            }
            // ---- Array property: Group Key Table (18 bytes/entry) ----
            pid::GROUP_KEY_TABLE => {
                let table = self.state.grp_keys().borrow();
                if req.start_idx == 0 {
                    // Element count query.
                    if buf.len() < 2 {
                        return Some(Err(PropertyError::BufferTooSmall));
                    }
                    buf[..2].copy_from_slice(&table.count().to_be_bytes());
                    Ok(2)
                } else {
                    let start = (req.start_idx - 1) as u16;
                    table.read_entries(start, req.count as u16, buf)
                }
            }
            // ---- Array property: Security Individual Address Table (8 bytes/entry) ----
            pid::SECURITY_INDIVIDUAL_ADDRESS_TABLE => {
                let table = self.state.siat().borrow();
                if req.start_idx == 0 {
                    if buf.len() < 2 {
                        return Some(Err(PropertyError::BufferTooSmall));
                    }
                    buf[..2].copy_from_slice(&table.count().to_be_bytes());
                    Ok(2)
                } else {
                    let start = (req.start_idx - 1) as u16;
                    table.read_entries(start, req.count as u16, buf)
                }
            }
            // ---- Array property: GO Security Flags (1 byte/entry) ----
            pid::GO_SECURITY_FLAGS => {
                let table = self.state.go_flags().borrow();
                if req.start_idx == 0 {
                    if buf.len() < 2 {
                        return Some(Err(PropertyError::BufferTooSmall));
                    }
                    buf[..2].copy_from_slice(&table.count().to_be_bytes());
                    Ok(2)
                } else {
                    let start = (req.start_idx - 1) as u16;
                    table.read_entries(start, req.count as u16, buf)
                }
            }
            // ---- Write-only: Tool Key (PID 56) ----
            pid::TOOL_KEY => Err(PropertyError::ReadNotAllowed),
            // ---- Sequence Number Sending (PID 59): 6-byte tool counter ----
            pid::SEQUENCE_NUMBER_SENDING => {
                if req.start_idx == 0 {
                    // Element count: always 1 (single-element property).
                    buf[0..2].copy_from_slice(&1u16.to_be_bytes());
                    Ok(2)
                } else {
                    if buf.len() < 6 {
                        return Some(Err(PropertyError::BufferTooSmall));
                    }
                    // PID 59 returns the tool-access sending counter (access
                    // policy 00C/00C means only tool access reads it).
                    let storage = self.seq_storage.borrow();
                    let Ok((_regular, tool)) = storage.load_sending_seqs() else {
                        return Some(Err(PropertyError::InvalidPropertyId));
                    };
                    buf[..6].copy_from_slice(&tool);
                    Ok(6)
                }
            }
            // ---- Security Report (PID 57) — PDT_BITSET8 (1 byte) ----
            // DPT_Security_Report (21.1002): b0 = Security Failure, b1-b7 reserved.
            // b0 is set on any security failure and only cleared by MaC via
            // secure write (spec 03/05/01 section 6.3.11).
            pid::SECURITY_REPORT => {
                if req.start_idx == 0 {
                    // Element count query.
                    buf[0..2].copy_from_slice(&1u16.to_be_bytes());
                    Ok(2)
                } else {
                    buf[0] = self.state.security_report();
                    Ok(1)
                }
            }
            // ---- Security Report Control (PID 58) — 1 byte ----
            pid::SECURITY_REPORT_CONTROL => {
                if req.start_idx == 0 {
                    buf[0..2].copy_from_slice(&1u16.to_be_bytes());
                    Ok(2)
                } else {
                    buf[0] = if self.state.security_report_enabled() { 0x01 } else { 0x00 };
                    Ok(1)
                }
            }
            // ---- Test-only manufacturer-specific PID 203 ----
            // Returns the four 16-bit failure counters as a flat array.
            // start_idx == 0 returns the element count; otherwise returns
            // `count` × 2-byte counters starting at `start_idx`.
            pid::TEST_FAILURE_COUNTERS => {
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
            // ---- Stubs for Phase 6+ ----
            pid::SECURITY_FAILURES_LOG => Err(PropertyError::InvalidPropertyId),
            _ => Err(PropertyError::InvalidPropertyId),
        })
    }

    fn property_value_write(
        &self,
        _ctx: &AugmentContext<'_, D>,
        object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        if object_type != InterfaceObjectType::Security {
            return None;
        }

        Some(match req.pid {
            pid::LOAD_STATE_CONTROL => {
                if req.data.is_empty() {
                    return Some(Err(PropertyError::BufferTooSmall));
                }
                // Interpret byte 0 as a load event and apply the standard
                // Realisation Type 1 state machine (spec 03/05/01 §4.23.2).
                use crate::objects::tables::LoadEvent;
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
                    // AdditionalLoadControls and unknown events: no state change.
                    _ => cur,
                };
                self.state.set_load_state(new_state);
                // On transition into `Loaded`, seed the receiving sequence
                // number storage from the SIAT. After this, the S-AL reads
                // and writes per-peer last-valid seqnrs exclusively via
                // `SequenceNumberStorage`; the SIAT table remains in state
                // for IA-membership checks (`is_in_siat`) and ETS table I/O
                // only — never mutated at runtime. Seeding here (rather
                // than at every incoming frame) keeps the wear profile of
                // the sequence store predictable.
                if new_state == LoadState::Loaded && cur != LoadState::Loaded {
                    self.state.seed_receiving_seqs(&mut *self.seq_storage.borrow_mut());
                }
                // Return the new state in the response (echo format).
                Ok(WriteResponse::byte(new_state.into()))
            }
            pid::SECURITY_MODE => {
                if req.data.is_empty() {
                    return Some(Err(PropertyError::BufferTooSmall));
                }
                self.state.set_security_mode_enabled(req.data[0] != 0);
                Ok(WriteResponse::Echo)
            }
            // ---- Array property: P2P Key Table (20 bytes/entry) ----
            pid::P2P_KEY_TABLE => {
                let mut table = self.state.p2p_keys().borrow_mut();
                write_security_table(&mut table, req)
            }
            // ---- Array property: Group Key Table (18 bytes/entry) ----
            pid::GROUP_KEY_TABLE => {
                let mut table = self.state.grp_keys().borrow_mut();
                write_security_table(&mut table, req)
            }
            // ---- Array property: Security Individual Address Table (8 bytes/entry) ----
            pid::SECURITY_INDIVIDUAL_ADDRESS_TABLE => {
                let mut table = self.state.siat().borrow_mut();
                write_security_table(&mut table, req)
            }
            // ---- Array property: GO Security Flags (1 byte/entry) ----
            pid::GO_SECURITY_FLAGS => {
                let mut table = self.state.go_flags().borrow_mut();
                write_security_table(&mut table, req)
            }
            // ---- Tool Key (PID 56): write-only, 16 bytes ----
            pid::TOOL_KEY => {
                if req.data.len() < 16 {
                    return Some(Err(PropertyError::BufferTooSmall));
                }
                let mut key = [0u8; 16];
                key.copy_from_slice(&req.data[..16]);
                self.state.set_tool_key(key);
                Ok(WriteResponse::Echo)
            }
            // ---- Sequence Number Sending (PID 59): write tool counter ----
            pid::SEQUENCE_NUMBER_SENDING => {
                if req.start_idx == 0 {
                    // Element count write — single-element property, nothing to do.
                    Ok(WriteResponse::Echo)
                } else {
                    if req.data.len() < 6 {
                        return Some(Err(PropertyError::BufferTooSmall));
                    }
                    let mut tool = [0u8; 6];
                    tool.copy_from_slice(&req.data[..6]);
                    // Per KNX spec, the sequence number must not be set to 0.
                    if tool == [0u8; 6] {
                        return Some(Err(PropertyError::ValueOutOfRange));
                    }
                    // Write the new tool counter; preserve the regular counter.
                    let mut storage = self.seq_storage.borrow_mut();
                    let regular = storage.load_sending_seqs().map(|(r, _)| r).unwrap_or([0, 0, 0, 0, 0, 1]);
                    let _ = storage.save_sending_seqs(&regular, &tool);
                    Ok(WriteResponse::Echo)
                }
            }
            // ---- Security Report (PID 57): writable to clear report flags ----
            pid::SECURITY_REPORT => {
                if req.data.is_empty() {
                    return Some(Err(PropertyError::BufferTooSmall));
                }
                self.state.set_security_report(req.data[0]);
                Ok(WriteResponse::Echo)
            }
            // ---- Security Report Control (PID 58) ----
            pid::SECURITY_REPORT_CONTROL => {
                if req.data.is_empty() {
                    return Some(Err(PropertyError::BufferTooSmall));
                }
                self.state.set_security_report_enabled(req.data[0] != 0);
                Ok(WriteResponse::Echo)
            }
            // ---- Test-only manufacturer-specific PID 203 ----
            // Replaces the four 16-bit failure counters wholesale. We
            // accept a write of any prefix of the four counters
            // (`req.count` × 2 bytes starting at `start_idx - 1`) but
            // expect the typical 4-element write from test 3.8.12.6.
            pid::TEST_FAILURE_COUNTERS => {
                if req.start_idx == 0 {
                    // Element count writes are a no-op (fixed at 4).
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
            _ => Err(PropertyError::InvalidPropertyId),
        })
    }

    // ================================================================
    // Function Property handlers
    // ================================================================

    fn function_property_command(
        &self,
        _ctx: &AugmentContext<'_, D>,
        object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        if object_type != InterfaceObjectType::Security {
            return None;
        }

        match req.prop_id {
            pid::SECURITY_MODE => return Some(self.handle_security_mode_command(req)),
            pid::SECURITY_FAILURES_LOG => {}
            _ => return None,
        }

        // PID_SECURITY_FAILURES_LOG handler: Command format: [id, info, ...]
        //
        // Only id=0, info=0 is defined (clear the log). Other combinations
        // return appropriate error codes per the conformance tests.
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
            0 => {
                // id=0 but info != 0 → invalid service info.
                Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[id]) })
            }
            _ => {
                // Unknown service ID.
                Some(FunctionPropertyResult { return_code: 0xF2, data: PropertyBuf::new(&[id]) })
            }
        }
    }

    fn function_property_state_read(
        &self,
        _ctx: &AugmentContext<'_, D>,
        object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        if object_type != InterfaceObjectType::Security {
            return None;
        }

        // PID_SECURITY_MODE state read: returns current security mode.
        if req.prop_id == pid::SECURITY_MODE {
            return Some(self.handle_security_mode_state_read(req));
        }

        if req.prop_id != pid::SECURITY_FAILURES_LOG {
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

        // Only service_id=0 is defined.
        if service_id != 0 {
            return Some(FunctionPropertyResult { return_code: 0xF2, data: PropertyBuf::new(&[service_id]) });
        }

        match service_info {
            // service_info=0: Return 4 × 2-byte BE counters (8 bytes).
            0 => {
                // Validate that the data byte is 0 (the only valid value for
                // the counter read sub-function).
                let data_byte = req.service_data.get(2).copied().unwrap_or(0);
                if data_byte != 0 {
                    return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[service_id]) });
                }

                let log = self.state.failures_log().borrow();
                let counter_bytes = log.counters_as_bytes();
                // Response: service_id(1) + service_info(1) + counters(8)
                let mut data = [0u8; 10];
                data[0] = service_id;
                data[1] = service_info;
                data[2..10].copy_from_slice(&counter_bytes);
                Some(FunctionPropertyResult::success_with_data(&data))
            }
            // service_info=1: Return Nth most recent 12-byte failure entry.
            1 => {
                // Need the entry index from data byte.
                if req.service_data.len() < 3 {
                    return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[service_info]) });
                }
                let entry_index = req.service_data[2];

                let log = self.state.failures_log().borrow();
                if let Some(entry) = log.get_by_index(entry_index) {
                    let src_bytes = entry.source_addr.to_be_bytes();
                    // Response data: service_info(1) + entry_index(1) +
                    //                src_addr(2) + fragment(9) + failure_type(1) = 14 bytes
                    let mut data = [0u8; 14];
                    data[0] = service_info;
                    data[1] = entry_index;
                    data[2..4].copy_from_slice(&src_bytes);
                    data[4..13].copy_from_slice(&entry.frame_fragment);
                    data[13] = entry.failure_type;
                    Some(FunctionPropertyResult::success_with_data(&data))
                } else {
                    // Out of bounds → DataVoid.
                    Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[service_info]) })
                }
            }
            // Unknown service_info → SERVICE_NOT_SUPPORTED.
            _ => Some(FunctionPropertyResult { return_code: 0xF2, data: PropertyBuf::new(&[service_info]) }),
        }
    }
}

// ============================================================================
// Private Helpers
// ============================================================================

impl<'a, SEQ: SequenceNumberStorage, const GRP: usize, const P2P: usize, const GO: usize>
    SecurityAugment<'a, SEQ, GRP, P2P, GO>
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

/// Write to a SecurityTable, handling element-count writes (start_idx=0)
/// vs data writes (start_idx>0).
///
/// Element-count writes expect exactly 2 bytes (u16 BE new count).
/// Setting count to 0 clears the table.
fn write_security_table<const N: usize, const ES: usize>(
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
