//! Security Interface Object augment.
//!
//! Provides the Security Interface Object (Object Type 0x11) as an
//! augment-provided object. This adds one additional object to the
//! device's IO list without modifying the base System B objects.

use crate::StackState;
use crate::access::AccessPolicy;
use crate::dpt::{
    InterfaceObjectType, PDT_Control, PDT_Generic06, PDT_Generic08, PDT_UnsignedChar, PDT_UnsignedInt,
    PropertyDataDefinition,
};
use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, InterfaceObjectAugment, PropertyAccess,
    PropertyDescriptionResponse, PropertyDescriptor, PropertyError, PropertyLookup, WriteResponse, pid,
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
pub struct SecurityAugment<'a, const GRP: usize, const GO: usize> {
    state: &'a SecurityState<GRP, GO>,
}

impl<'a, const GRP: usize, const GO: usize> SecurityAugment<'a, GRP, GO> {
    /// Create a new security augment backed by the given state.
    pub fn new(state: &'a SecurityState<GRP, GO>) -> Self {
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
        // PID_SECURITY_MODE (51): enables/disables Data Secure
        PropertyDescriptor::with_policy(
            pid::SECURITY_MODE,
            PDT_UnsignedChar::ID,
            1,
            PropertyAccess::ReadWrite,
            2,
            2,
            AccessPolicy::RESTRICTED, // 15F/04C
        ),
        // PID_GROUP_KEY_TABLE (53): group communication encryption keys
        PropertyDescriptor::with_policy(
            pid::GROUP_KEY_TABLE,
            PDT_Generic08::ID, // 18 bytes/entry, but PDT is generic
            0,                 // 0 elements until loaded
            PropertyAccess::ReadWrite,
            2,
            2,
            AccessPolicy::TOOL_ONLY, // 00C/00C
        ),
        // PID_SECURITY_FAILURES_LOG (55): ring buffer of security events
        PropertyDescriptor::with_policy(
            pid::SECURITY_FAILURES_LOG,
            PDT_Generic08::ID,
            0,
            PropertyAccess::ReadOnly,
            3,
            2,
            // 1FF/0CC per Profiles spec (not 15F/04C as in earlier skeleton)
            AccessPolicy::new(0x1FF, 0x0CC),
        ),
        // PID_TOOL_KEY (56): write-only 16-byte key
        PropertyDescriptor::with_policy(
            pid::TOOL_KEY,
            PDT_Generic08::ID,
            1,
            PropertyAccess::WriteOnly,
            // X/2: no read access, write at level 2
            // Using read_level 0 since WriteOnly prevents reads regardless
            0,
            2,
            AccessPolicy::TOOL_ONLY_CONFIDENTIAL, // 008/008
        ),
        // PID_SECURITY_REPORT (57): security status report
        PropertyDescriptor::with_policy(
            pid::SECURITY_REPORT,
            PDT_Generic08::ID,
            1,
            PropertyAccess::ReadOnly,
            3,
            2,
            // 1FF/0CC
            AccessPolicy::new(0x1FF, 0x0CC),
        ),
        // PID_SECURITY_REPORT_CONTROL (58): report control
        PropertyDescriptor::with_policy(
            pid::SECURITY_REPORT_CONTROL,
            PDT_Generic08::ID,
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
    fn descriptor_by_pid(pid_val: u8) -> Option<(u8, &'static PropertyDescriptor)> {
        Self::DESCRIPTORS.iter().enumerate().find(|(_, d)| d.pid == pid_val).map(|(i, d)| (i as u8, d))
    }

    /// Find a descriptor by augment-local index.
    fn descriptor_by_index(index: u8) -> Option<&'static PropertyDescriptor> {
        Self::DESCRIPTORS.get(index as usize)
    }
}

impl<'a, S: StackState, const GRP: usize, const GO: usize> InterfaceObjectAugment<S> for SecurityAugment<'a, GRP, GO> {
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
            // Phase 2+: key tables, sequence numbers, etc.
            pid::GROUP_KEY_TABLE
            | pid::SECURITY_FAILURES_LOG
            | pid::TOOL_KEY
            | pid::SECURITY_REPORT
            | pid::SECURITY_REPORT_CONTROL
            | pid::SEQUENCE_NUMBER_SENDING
            | pid::GO_SECURITY_FLAGS => Err(PropertyError::InvalidPropertyId),
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
            // Phase 2+: key tables, sequence numbers, etc.
            pid::GROUP_KEY_TABLE
            | pid::TOOL_KEY
            | pid::SECURITY_REPORT_CONTROL
            | pid::SEQUENCE_NUMBER_SENDING
            | pid::GO_SECURITY_FLAGS => Err(PropertyError::InvalidPropertyId),
            _ => Err(PropertyError::InvalidPropertyId),
        })
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

    fn make_state() -> SecurityState<64, 32> {
        SecurityState::from_config(SecurityExtensionConfig::default())
    }

    #[test]
    fn augment_reports_one_additional_object() {
        let state = make_state();
        let augment = SecurityAugment::<64, 32>::new(&state);
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
        let augment = SecurityAugment::<64, 32>::new(&state);
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
        let augment = SecurityAugment::<64, 32>::new(&state);
        let mock = MockState;

        // Write security mode = 1 (enabled)
        let req = FullPropertyWriteRequest {
            object_idx: 6,
            pid: pid::SECURITY_MODE,
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
        let augment = SecurityAugment::<64, 32>::new(&state);
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

        let restored = SecurityState::<64, 32>::from_config(config);
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
}
