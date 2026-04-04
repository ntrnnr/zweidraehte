//! Security Interface Object augment.
//!
//! Provides the Security Interface Object (Object Type 0x11) as an
//! augment-provided object. This adds one additional object to the
//! device's IO list without modifying the base System B objects.

use super::SecurityTable;
use crate::StackState;
use crate::access::AccessPolicy;
use crate::dpt::{
    InterfaceObjectType, PDT_Control, PDT_Function, PDT_Generic01, PDT_Generic06, PDT_Generic08, PDT_Generic18,
    PDT_UnsignedChar, PDT_UnsignedInt, PropertyDataDefinition,
};
use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult,
    InterfaceObjectAugment, PropertyAccess, PropertyBuf, PropertyDescriptionResponse, PropertyDescriptor,
    PropertyError, PropertyLookup, WriteResponse, pid,
};
use crate::objects::tables::LoadState;
use crate::properties::PropertyRead;

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
pub struct SecurityAugment<'a, const GRP: usize, const P2P: usize, const GO: usize> {
    state: &'a SecurityState<GRP, P2P, GO>,
}

impl<'a, const GRP: usize, const P2P: usize, const GO: usize> SecurityAugment<'a, GRP, P2P, GO> {
    /// Create a new security augment backed by the given state.
    pub fn new(state: &'a SecurityState<GRP, P2P, GO>) -> Self {
        Self { state }
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
        // TODO: PDT_BINARY_INFORMATION is not yet defined, using PDT_Generic01 (1 byte)
        PropertyDescriptor::with_policy(
            pid::SECURITY_REPORT_CONTROL,
            PDT_Generic01::ID,
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

impl<'a, S: StackState, const GRP: usize, const P2P: usize, const GO: usize> InterfaceObjectAugment<S>
    for SecurityAugment<'a, GRP, P2P, GO>
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
        _state: &S,
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
        _state: &S,
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
            // ---- Sequence Number Sending (PID 59) ----
            // TODO: delegate to SequenceNumberStorage in Phase 4
            pid::SEQUENCE_NUMBER_SENDING => Err(PropertyError::InvalidPropertyId),
            // ---- Security Report (PID 57) — PDT_BITSET8 (1 byte) ----
            // Returns the current security status as a bitfield.
            // TODO: Implement actual security report bits per spec.
            pid::SECURITY_REPORT => {
                if req.start_idx == 0 {
                    // Element count query.
                    buf[0..2].copy_from_slice(&1u16.to_be_bytes());
                    Ok(2)
                } else {
                    buf[0] = 0x00; // All bits clear = no issues reported.
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
            // ---- Stubs for Phase 6+ ----
            pid::SECURITY_FAILURES_LOG => Err(PropertyError::InvalidPropertyId),
            _ => Err(PropertyError::InvalidPropertyId),
        })
    }

    fn property_value_write(
        &self,
        _state: &S,
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
                match LoadState::try_from(req.data[0]) {
                    Ok(load_state) => {
                        self.state.set_load_state(load_state);
                        Ok(WriteResponse::Echo)
                    }
                    Err(_) => Err(PropertyError::InvalidLoadState),
                }
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
            // ---- Sequence Number Sending (PID 59) ----
            // TODO: delegate to SequenceNumberStorage in Phase 4
            pid::SEQUENCE_NUMBER_SENDING => Err(PropertyError::InvalidPropertyId),
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
            _ => Err(PropertyError::InvalidPropertyId),
        })
    }

    // ================================================================
    // Function Property handlers
    // ================================================================

    fn function_property_command(
        &self,
        _state: &S,
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

        // PID_SECURITY_FAILURES_LOG handler: Command format: [id, info]
        if req.service_data.len() < 2 {
            return Some(FunctionPropertyResult::not_supported());
        }

        let id = req.service_data[0];
        let info = req.service_data[1];

        // id=0, info=0: Clear the failure log.
        if id == 0 && info == 0 {
            self.state.failures_log().borrow_mut().clear();
            return Some(FunctionPropertyResult::success_with_data(&[id]));
        }

        Some(FunctionPropertyResult::not_supported())
    }

    fn function_property_state_read(
        &self,
        _state: &S,
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

        if req.service_data.len() < 2 {
            return Some(FunctionPropertyResult::not_supported());
        }

        let id = req.service_data[0];
        let info = req.service_data[1];

        match id {
            // id=0, info=0: Return 8-byte failure counters.
            0 if info == 0 => {
                let log = self.state.failures_log().borrow();
                let counters = log.counters();
                let mut data = [0u8; 10]; // id(1) + info(1) + counters(8)
                data[0] = id;
                data[1] = info;
                data[2..10].copy_from_slice(counters);
                Some(FunctionPropertyResult::success_with_data(&data))
            }
            // id=1, info=N: Return Nth most recent failure entry.
            1 => {
                let log = self.state.failures_log().borrow();
                if let Some(entry) = log.get_by_index(info) {
                    let src_bytes = entry.source_addr.to_be_bytes();
                    let data = [id, info, entry.failure_type, src_bytes[0], src_bytes[1]];
                    Some(FunctionPropertyResult::success_with_data(&data))
                } else {
                    // No entry at this index — DataVoid.
                    Some(FunctionPropertyResult::success_with_data(&[id]))
                }
            }
            _ => Some(FunctionPropertyResult::not_supported()),
        }
    }
}

// ============================================================================
// Private Helpers
// ============================================================================

impl<'a, const GRP: usize, const P2P: usize, const GO: usize> SecurityAugment<'a, GRP, P2P, GO> {
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
        }
        // Non-zero element count writes just set the count (pre-allocate).
        // The actual entries are written via start_idx > 0.
        Ok(WriteResponse::Echo)
    } else {
        let start = req.start_idx.saturating_sub(1);
        match table.write_entries(start, req.data) {
            Ok(()) => Ok(WriteResponse::Echo),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bcus::system_b::ExtensionState;
    use crate::bcus::system_b::extensions::security::SecurityExtensionConfig;

    /// Minimal StackState impl for testing.
    struct MockState;

    impl crate::StackState for MockState {
        fn individual_address(&self) -> crate::address::IndividualAddress {
            crate::address::IndividualAddress::new(1, 0, 1)
        }
        fn set_individual_address(&self, _addr: crate::address::IndividualAddress) {}
        fn serial_number(&self) -> &[u8; 6] {
            &[0; 6]
        }
    }

    fn make_state() -> SecurityState<64, 8, 32> {
        SecurityState::from_config(SecurityExtensionConfig::default())
    }

    #[test]
    fn augment_reports_one_additional_object() {
        let state = make_state();
        let augment = SecurityAugment::<64, 8, 32>::new(&state);
        let mock = MockState;

        assert_eq!(InterfaceObjectAugment::<MockState>::additional_object_count(&augment), 1);
        assert_eq!(
            InterfaceObjectAugment::<MockState>::additional_object_type_at(&augment, 0),
            Some(InterfaceObjectType::Security)
        );
        assert_eq!(InterfaceObjectAugment::<MockState>::additional_object_type_at(&augment, 1), None);
        let _ = mock;
    }

    #[test]
    fn read_object_type_returns_security() {
        let state = make_state();
        let augment = SecurityAugment::<64, 8, 32>::new(&state);
        let mock = MockState;

        let req = FullPropertyReadRequest {
            object_idx: 6, // augment-provided object
            pid: pid::OBJECT_TYPE,
            start_idx: 1,
            count: 1,
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        let mut buf = [0u8; 4];
        let result = augment.property_value_read(&mock, InterfaceObjectType::Security, &req, &mut buf);

        let len = result.expect("should handle Security IO").expect("should succeed");
        assert_eq!(len, 2);
        let obj_type = u16::from_be_bytes([buf[0], buf[1]]);
        assert_eq!(obj_type, u16::from(InterfaceObjectType::Security));
    }

    #[test]
    fn security_mode_defaults_to_off() {
        let state = make_state();
        assert!(!state.security_mode_enabled());
    }

    #[test]
    fn write_security_mode_toggles() {
        let state = make_state();
        let augment = SecurityAugment::<64, 8, 32>::new(&state);
        let mock = MockState;

        // Write security mode = 1 (enabled)
        let req = FullPropertyWriteRequest {
            object_idx: 6,
            pid: pid::SECURITY_MODE,
            count: 1,
            start_idx: 1,
            data: &[1],
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        let result = augment.property_value_write(&mock, InterfaceObjectType::Security, &req);
        assert!(result.expect("should handle").is_ok());
        assert!(state.security_mode_enabled());

        // Write security mode = 0 (disabled)
        let req = FullPropertyWriteRequest {
            object_idx: 6,
            pid: pid::SECURITY_MODE,
            count: 1,
            start_idx: 1,
            data: &[0],
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        let result = augment.property_value_write(&mock, InterfaceObjectType::Security, &req);
        assert!(result.expect("should handle").is_ok());
        assert!(!state.security_mode_enabled());
    }

    #[test]
    fn ignores_non_security_objects() {
        let state = make_state();
        let augment = SecurityAugment::<64, 8, 32>::new(&state);
        let mock = MockState;

        let req = FullPropertyReadRequest {
            object_idx: 0,
            pid: pid::OBJECT_TYPE,
            start_idx: 1,
            count: 1,
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        let mut buf = [0u8; 4];

        // Should return None for Device object type
        let result = augment.property_value_read(&mock, InterfaceObjectType::Device, &req, &mut buf);
        assert!(result.is_none(), "should not handle Device object");
    }

    #[test]
    fn config_round_trip() {
        let state = make_state();
        state.set_security_mode_enabled(true);
        state.set_tool_key([0xAA; 16]);
        state.set_load_state(LoadState::Err);

        let config = state.to_config();
        assert!(config.security_mode_enabled);
        assert_eq!(config.tool_key, [0xAA; 16]);
        assert_eq!(config.load_state, LoadState::Err);

        let restored = SecurityState::<64, 8, 32>::from_config(config);
        assert!(restored.security_mode_enabled());
        assert_eq!(restored.tool_key(), [0xAA; 16]);
        assert_eq!(restored.load_state(), LoadState::Err);
    }

    #[test]
    fn factory_reset_clears_state() {
        let state = make_state();
        state.set_security_mode_enabled(true);
        state.set_tool_key([0xFF; 16]);
        state.set_load_state(LoadState::Loaded);

        state.factory_reset();

        assert!(!state.security_mode_enabled());
        assert_eq!(state.tool_key(), [0u8; 16]);
        assert_eq!(state.load_state(), LoadState::Unloaded);
    }

    // ================================================================
    // Phase 2 tests: table properties
    // ================================================================

    #[test]
    fn grp_key_table_write_and_read() {
        let state = make_state();
        let augment = SecurityAugment::<64, 8, 32>::new(&state);
        let mock = MockState;

        // Write one group key entry (18 bytes: GA_index=0x0001 + 16-byte key)
        let mut entry = [0u8; 18];
        entry[0] = 0x00;
        entry[1] = 0x01; // GA index 1
        entry[2..18].copy_from_slice(&[0xAB; 16]); // key

        let write_req = FullPropertyWriteRequest {
            object_idx: 6,
            pid: pid::GROUP_KEY_TABLE,
            count: 1,
            start_idx: 1,
            data: &entry,
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        let result = augment.property_value_write(&mock, InterfaceObjectType::Security, &write_req);
        assert!(result.expect("should handle").is_ok());

        // Read element count (start_idx=0)
        let read_req = FullPropertyReadRequest {
            object_idx: 6,
            pid: pid::GROUP_KEY_TABLE,
            start_idx: 0,
            count: 1,
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        let mut buf = [0u8; 32];
        let result = augment.property_value_read(&mock, InterfaceObjectType::Security, &read_req, &mut buf);
        let len = result.expect("should handle").expect("should succeed");
        assert_eq!(len, 2);
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 1); // 1 entry

        // Read the entry back (start_idx=1)
        let read_req = FullPropertyReadRequest {
            object_idx: 6,
            pid: pid::GROUP_KEY_TABLE,
            start_idx: 1,
            count: 1,
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        let result = augment.property_value_read(&mock, InterfaceObjectType::Security, &read_req, &mut buf);
        let len = result.expect("should handle").expect("should succeed");
        assert_eq!(len, 18);
        assert_eq!(&buf[0..2], &[0x00, 0x01]); // GA index
        assert_eq!(&buf[2..18], &[0xAB; 16]); // key
    }

    #[test]
    fn group_key_lookup() {
        let state = make_state();

        // Write a group key entry directly to the table.
        let mut entry = [0u8; 18];
        entry[0] = 0x00;
        entry[1] = 0x05; // GA index 5
        entry[2..18].copy_from_slice(&[0xCC; 16]);
        state.grp_keys().borrow_mut().write_entries(0, &entry).expect("write should succeed");

        // Lookup by GA index.
        assert_eq!(state.group_key_for_index(5), Some([0xCC; 16]));
        assert_eq!(state.group_key_for_index(1), None);
    }

    #[test]
    fn go_security_flags_write_and_lookup() {
        let state = make_state();
        let augment = SecurityAugment::<64, 8, 32>::new(&state);
        let mock = MockState;

        // Write 3 GO flags
        let write_req = FullPropertyWriteRequest {
            object_idx: 6,
            pid: pid::GO_SECURITY_FLAGS,
            count: 3,
            start_idx: 1,
            data: &[0x01, 0x03, 0x00], // GO 0: auth, GO 1: auth+conf, GO 2: none
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        let result = augment.property_value_write(&mock, InterfaceObjectType::Security, &write_req);
        assert!(result.expect("should handle").is_ok());

        // Lookup flags
        assert_eq!(state.go_security_flags_for(0), Some(0x01));
        assert_eq!(state.go_security_flags_for(1), Some(0x03));
        assert_eq!(state.go_security_flags_for(2), Some(0x00));
        assert_eq!(state.go_security_flags_for(3), None);
    }

    #[test]
    fn tool_key_is_write_only() {
        let state = make_state();
        let augment = SecurityAugment::<64, 8, 32>::new(&state);
        let mock = MockState;

        // Write tool key
        let write_req = FullPropertyWriteRequest {
            object_idx: 6,
            pid: pid::TOOL_KEY,
            count: 1,
            start_idx: 1,
            data: &[0xDD; 16],
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        let result = augment.property_value_write(&mock, InterfaceObjectType::Security, &write_req);
        assert!(result.expect("should handle").is_ok());
        assert_eq!(state.tool_key(), [0xDD; 16]);

        // Read should fail (write-only)
        let read_req = FullPropertyReadRequest {
            object_idx: 6,
            pid: pid::TOOL_KEY,
            start_idx: 1,
            count: 1,
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        let mut buf = [0u8; 16];
        let result = augment.property_value_read(&mock, InterfaceObjectType::Security, &read_req, &mut buf);
        assert!(result.expect("should handle").is_err());
    }

    #[test]
    fn table_write_beyond_capacity_fails() {
        let state: SecurityState<2, 2, 2> = SecurityState::from_config(SecurityExtensionConfig::default());
        let augment = SecurityAugment::<2, 2, 2>::new(&state);
        let mock = MockState;

        // Write 3 entries to a table with capacity 2 — should fail.
        let write_req = FullPropertyWriteRequest {
            object_idx: 6,
            pid: pid::GO_SECURITY_FLAGS,
            count: 3,
            start_idx: 1,
            data: &[0x01, 0x02, 0x03],
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        let result = augment.property_value_write(&mock, InterfaceObjectType::Security, &write_req);
        assert!(result.expect("should handle").is_err());
    }

    #[test]
    fn read_out_of_range_returns_error() {
        let state = make_state();
        let augment = SecurityAugment::<64, 8, 32>::new(&state);
        let mock = MockState;

        // Table is empty (0 entries). Reading at start_idx=1 should fail.
        let read_req = FullPropertyReadRequest {
            object_idx: 6,
            pid: pid::GROUP_KEY_TABLE,
            start_idx: 1,
            count: 1,
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        let mut buf = [0u8; 32];
        let result = augment.property_value_read(&mock, InterfaceObjectType::Security, &read_req, &mut buf);
        let err = result.expect("should handle").unwrap_err();
        assert_eq!(err, PropertyError::InvalidStartIndex);
    }

    #[test]
    fn read_with_small_buffer_returns_error() {
        let state = make_state();
        let augment = SecurityAugment::<64, 8, 32>::new(&state);
        let mock = MockState;

        // Write one entry (18 bytes).
        let entry = [0u8; 18];
        let write_req = FullPropertyWriteRequest {
            object_idx: 6,
            pid: pid::GROUP_KEY_TABLE,
            start_idx: 1,
            data: &entry,
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        augment.property_value_write(&mock, InterfaceObjectType::Security, &write_req).unwrap().unwrap();

        // Try to read with a buffer too small for 18 bytes.
        let read_req = FullPropertyReadRequest {
            object_idx: 6,
            pid: pid::GROUP_KEY_TABLE,
            start_idx: 1,
            count: 1,
            ctx: crate::AccessContext::MAX_ACCESS,
        };
        let mut buf = [0u8; 4]; // Too small for 18-byte entry.
        let result = augment.property_value_read(&mock, InterfaceObjectType::Security, &read_req, &mut buf);
        let err = result.expect("should handle").unwrap_err();
        assert_eq!(err, PropertyError::BufferTooSmall);
    }

    // ================================================================
    // Security Failures Log tests
    // ================================================================

    #[test]
    fn failures_log_counters_and_entries() {
        use super::super::{SecurityFailureType, SecurityFailuresLog};

        let mut log = SecurityFailuresLog::default();

        // Log some failures.
        log.log_failure(SecurityFailureType::CryptoError, 0x1001);
        log.log_failure(SecurityFailureType::CryptoError, 0x1002);
        log.log_failure(SecurityFailureType::ScfError, 0x2001);

        // Check counters.
        let counters = log.counters();
        assert_eq!(counters[SecurityFailureType::CryptoError as usize], 2);
        assert_eq!(counters[SecurityFailureType::ScfError as usize], 1);
        assert_eq!(counters[SecurityFailureType::SeqNrError as usize], 0);

        // Check entries (most recent first).
        let e0 = log.get_by_index(0).expect("entry 0");
        assert_eq!(e0.failure_type, SecurityFailureType::ScfError as u8);
        assert_eq!(e0.source_addr, 0x2001);

        let e1 = log.get_by_index(1).expect("entry 1");
        assert_eq!(e1.failure_type, SecurityFailureType::CryptoError as u8);
        assert_eq!(e1.source_addr, 0x1002);

        // Clear.
        log.clear();
        assert_eq!(log.counters()[SecurityFailureType::CryptoError as usize], 0);
        assert!(log.get_by_index(0).is_none());
    }

    #[test]
    fn failures_log_ring_buffer_wraps() {
        use super::super::{SecurityFailureType, SecurityFailuresLog};

        let mut log = SecurityFailuresLog::default();

        // Fill beyond capacity (8 entries).
        for i in 0..10u16 {
            log.log_failure(SecurityFailureType::CryptoError, 0x1000 + i);
        }

        // Most recent should be 0x1009 (i=9).
        let e0 = log.get_by_index(0).expect("entry 0");
        assert_eq!(e0.source_addr, 0x1009);

        // Oldest accessible should be 0x1002 (i=2, since 0 and 1 were evicted).
        let e7 = log.get_by_index(7).expect("entry 7");
        assert_eq!(e7.source_addr, 0x1002);

        // Index 8 should be out of range.
        assert!(log.get_by_index(8).is_none());

        // Counter should be 10 (saturating).
        assert_eq!(log.counters()[SecurityFailureType::CryptoError as usize], 10);
    }
}
