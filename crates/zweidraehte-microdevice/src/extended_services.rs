//! Extended property, memory, and function-property services.
//!
//! These are the management services 06 Profiles §9.1.2.3 makes mandatory
//! for the KNX Data Security profile module. They address an interface
//! object by type plus one-based occurrence instead of by index. Profile
//! modules expose the same object through the classic indexed compatibility
//! surface when a client scans without `PID_IO_LIST`.
//!
//! Split from `management.rs` because the two service surfaces share no
//! dispatch code — the classic path routes by object index and backing
//! enum, this one by type/occurrence and `SecurityModule` — and either is
//! large enough to read on its own.

use heapless::Vec;

use zweidraehte_proto::access::AccessContext;
use zweidraehte_proto::memory::{MemoryError, MemoryOperation, check_memory_access};
use zweidraehte_proto::messages::apdu::function_property::{FunctionPropertyHeader, FunctionPropertyResponse};
use zweidraehte_proto::messages::apdu::memory::{MemoryExtendedAccess, MemoryExtendedResponse};
use zweidraehte_proto::messages::apdu::property_ext::{
    FunctionPropertyExtHeader, FunctionPropertyExtResponse, PropertyExtDescriptionHeader,
    PropertyExtDescriptionResponse, PropertyExtValueHeader, PropertyExtValueResponse, PropertyExtValueWriteConRes,
    PropertyReturnCode,
};
use zweidraehte_proto::messages::knx::offsets;
use zweidraehte_proto::properties::PropertyDescriptionResponse as PropertyDescription;

use crate::device::Microdevice;
use crate::family::MicroDeviceFamily;
use crate::frame::ApciCode;
use crate::management::{Reply, ServiceResult};
use crate::security::{ObjectRoute, SecurityModule};

/// Where an extended-service payload starts in the canonical frame.
const EXT_PAYLOAD_START: usize = offsets::MSG_APCI + 2;

impl<F: MicroDeviceFamily, const FRAME_CAP: usize, SEC: SecurityModule> Microdevice<F, FRAME_CAP, SEC> {
    // ── Extended memory services ────────────────────────────────────
    //
    // Three address octets and a full-octet count, answered with an explicit
    // return code rather than the classic services' zero-count convention.
    // The address space is still this family's 16-bit one, so an address
    // above 0xFFFF cannot exist here and is refused rather than truncated —
    // silently dropping the top octet would write somewhere real.

    pub(crate) fn memory_ext_read(&mut self, frame: &[u8], access: AccessContext) -> ServiceResult<FRAME_CAP> {
        let Some(req) = MemoryExtendedAccess::parse(frame) else {
            return ServiceResult::None;
        };
        let count = usize::from(req.count);
        let Some(addr) = Self::ext_memory_address(req.address) else {
            return Self::memory_ext_reply(
                ApciCode::MemoryExtendedReadResponse,
                PropertyReturnCode::AddressVoid,
                req.address,
                &[],
            );
        };
        if count == 0 {
            return Self::memory_ext_reply(
                ApciCode::MemoryExtendedReadResponse,
                PropertyReturnCode::DataVoid,
                req.address,
                &[],
            );
        }
        let operation = MemoryOperation::Read;
        if !SEC::memory_access_allowed(&self.sec, access, F::memory_access_policy(addr, count), operation) {
            self.record_access_failure(access, frame);
            return Self::memory_ext_reply(
                ApciCode::MemoryExtendedReadResponse,
                PropertyReturnCode::AccessDenied,
                req.address,
                &[],
            );
        }
        if MemoryExtendedResponse::msg_len(count) > Self::max_plaintext_frame_len() {
            return Self::memory_ext_reply(
                ApciCode::MemoryExtendedReadResponse,
                PropertyReturnCode::LengthExceedsMaxApduLength,
                req.address,
                &[],
            );
        }
        if let Some(code) = Self::memory_region_error(addr, count, operation, access) {
            return Self::memory_ext_reply(ApciCode::MemoryExtendedReadResponse, code, req.address, &[]);
        }
        let mut data: Vec<u8, FRAME_CAP> = Vec::new();
        for i in 0..req.count {
            let _ = data.push(self.mem_read_byte(addr.wrapping_add(u16::from(i))));
        }
        Self::memory_ext_reply(ApciCode::MemoryExtendedReadResponse, PropertyReturnCode::Success, req.address, &data)
    }

    pub(crate) fn memory_ext_write(&mut self, frame: &[u8], access: AccessContext) -> ServiceResult<FRAME_CAP> {
        let Some(req) = MemoryExtendedAccess::parse(frame) else {
            return ServiceResult::None;
        };
        let Some(addr) = Self::ext_memory_address(req.address) else {
            return Self::memory_ext_reply(
                ApciCode::MemoryExtendedWriteResponse,
                PropertyReturnCode::AddressVoid,
                req.address,
                &[],
            );
        };
        if req.count == 0 {
            return Self::memory_ext_reply(
                ApciCode::MemoryExtendedWriteResponse,
                PropertyReturnCode::DataVoid,
                req.address,
                &[],
            );
        }
        let operation = MemoryOperation::Write;
        if !SEC::memory_access_allowed(
            &self.sec,
            access,
            F::memory_access_policy(addr, usize::from(req.count)),
            operation,
        ) {
            self.record_access_failure(access, frame);
            return Self::memory_ext_reply(
                ApciCode::MemoryExtendedWriteResponse,
                PropertyReturnCode::AccessDenied,
                req.address,
                &[],
            );
        }
        // A count that disagrees with the octets carried is not a short
        // write — it is a malformed request, and guessing which of the two
        // the sender meant would write the wrong length somewhere real.
        if !req.is_write_length_consistent() {
            return Self::memory_ext_reply(
                ApciCode::MemoryExtendedWriteResponse,
                PropertyReturnCode::DataTypeConflict,
                req.address,
                &[],
            );
        }
        if let Some(code) = Self::memory_region_error(addr, req.data.len(), operation, access) {
            return Self::memory_ext_reply(ApciCode::MemoryExtendedWriteResponse, code, req.address, &[]);
        }
        if !F::memory_write_intercept(addr, req.data, self.eeprom.as_mut(), &mut self.mgmt) {
            for (i, &byte) in req.data.iter().enumerate() {
                self.mem_write_byte(addr.wrapping_add(i as u16), byte);
            }
        }
        Self::memory_ext_reply(ApciCode::MemoryExtendedWriteResponse, PropertyReturnCode::Success, req.address, &[])
    }

    /// Preserve the richer AN177 error vocabulary at the extended-service
    /// boundary. Classic memory services expose only success/no-response and
    /// continue using the smaller boolean region check.
    fn memory_region_error(
        address: u16,
        length: usize,
        operation: MemoryOperation,
        access: AccessContext,
    ) -> Option<PropertyReturnCode> {
        match check_memory_access(F::MEMORY_REGIONS, address, length, operation, access, F::AUTH_LEVELS as u8) {
            Some(Ok(_)) => None,
            Some(Err(MemoryError::WriteProtected)) => Some(match operation {
                MemoryOperation::Read => PropertyReturnCode::AccessWriteOnly,
                MemoryOperation::Write => PropertyReturnCode::AccessReadOnly,
            }),
            Some(Err(MemoryError::AccessDenied)) => Some(PropertyReturnCode::AccessDenied),
            Some(Err(MemoryError::NotAccessible)) | None => Some(PropertyReturnCode::AddressVoid),
        }
    }

    /// Narrow an extended service's 24-bit address to this family's 16-bit
    /// space, refusing anything that does not fit.
    pub(crate) fn ext_memory_address(address: u32) -> Option<u16> {
        u16::try_from(address).ok()
    }

    pub(crate) fn memory_ext_reply(
        apci: ApciCode,
        code: PropertyReturnCode,
        address: u32,
        data: &[u8],
    ) -> ServiceResult<FRAME_CAP> {
        Self::ext_reply(apci, MemoryExtendedResponse::msg_len(data.len()), |buf| {
            MemoryExtendedResponse::write(buf, code, address, data);
        })
    }

    // ── Extended function properties ────────────────────────────────

    /// `A_FunctionPropertyExtCommand` / `_StateRead`.
    ///
    /// Routed to the profile module when the object is its; the family's own
    /// objects serve no function properties. A property the module does not
    /// have — or an object that is not the module's — draws the empty
    /// response 03/03/07 §3.4.4 specifies for an unsupported property,
    /// because a mandatory service that stays silent is worse than one that
    /// says "no such property".
    pub(crate) fn function_property_ext(
        &mut self,
        frame: &[u8],
        command: bool,
        access: AccessContext,
    ) -> ServiceResult<FRAME_CAP> {
        let Some(hdr) = FunctionPropertyExtHeader::parse(frame) else {
            return ServiceResult::None;
        };
        let data = hdr.data(frame);
        let security_on = SEC::security_mode_enabled(&self.sec);
        let result = match Self::resolve_object(hdr.object_type, hdr.object_instance) {
            Some(ObjectRoute::Module(object)) => match SEC::property_descriptor(object, hdr.prop_id) {
                Some((_, desc))
                    if (command && desc.can_function_write_secure(&access, security_on))
                        || (!command && desc.can_function_read_secure(&access, security_on)) =>
                {
                    if command {
                        SEC::function_command::<FRAME_CAP>(&mut self.sec, object, hdr.prop_id, data)
                    } else {
                        SEC::function_state_read::<FRAME_CAP>(&self.sec, object, hdr.prop_id, data)
                    }
                }
                Some(_) => {
                    self.record_access_failure(access, frame);
                    Some(SEC::function_access_denied(object, hdr.prop_id, data))
                }
                None => None,
            },
            _ => None,
        };
        match result {
            Some(result) => Self::ext_reply(
                ApciCode::FunctionPropertyExtStateResponse,
                FunctionPropertyExtResponse::msg_len(result.data.len()),
                |buf| {
                    FunctionPropertyExtResponse::write(
                        buf,
                        hdr.object_type,
                        hdr.object_instance,
                        hdr.prop_id,
                        result.code.into(),
                        &result.data,
                    );
                },
            ),
            None => Self::ext_reply(
                ApciCode::FunctionPropertyExtStateResponse,
                FunctionPropertyExtResponse::EMPTY_MSG_LEN,
                |buf| {
                    FunctionPropertyExtResponse::write_empty(buf, hdr.object_type, hdr.object_instance, hdr.prop_id);
                },
            ),
        }
    }

    /// Classic indexed twin of [`function_property_ext`](Self::function_property_ext).
    ///
    /// Data Secure mandates the extended service, but the Security Interface
    /// Object remains discoverable at a classic object index and the base
    /// Function Property procedure is still part of the device-management
    /// surface. Both forms therefore reach the same module handler and access
    /// policy; only their addressing and response headers differ.
    pub(crate) fn function_property(
        &mut self,
        frame: &[u8],
        command: bool,
        access: AccessContext,
    ) -> ServiceResult<FRAME_CAP> {
        let Some(hdr) = FunctionPropertyHeader::parse(frame) else {
            return ServiceResult::None;
        };
        let data = hdr.data(frame);
        let result = if let Some(object) = Self::module_object(hdr.object_idx) {
            match SEC::property_descriptor(object, hdr.prop_id) {
                Some((_, desc))
                    if (command && desc.can_function_write_secure(&access, SEC::security_mode_enabled(&self.sec)))
                        || (!command
                            && desc.can_function_read_secure(&access, SEC::security_mode_enabled(&self.sec))) =>
                {
                    if command {
                        SEC::function_command::<FRAME_CAP>(&mut self.sec, object, hdr.prop_id, data)
                    } else {
                        SEC::function_state_read::<FRAME_CAP>(&self.sec, object, hdr.prop_id, data)
                    }
                }
                Some(_) => {
                    self.record_access_failure(access, frame);
                    Some(SEC::function_access_denied(object, hdr.prop_id, data))
                }
                None => None,
            }
        } else {
            None
        };

        match result {
            Some(result) => Self::ext_reply(
                ApciCode::FunctionPropertyStateResponse,
                FunctionPropertyResponse::msg_len(result.data.len()),
                |buf| {
                    FunctionPropertyResponse::write(buf, hdr.object_idx, hdr.prop_id, result.code.into(), &result.data);
                },
            ),
            None => Self::ext_reply(
                ApciCode::FunctionPropertyStateResponse,
                FunctionPropertyResponse::EMPTY_MSG_LEN,
                |buf| FunctionPropertyResponse::write_empty(buf, hdr.object_idx, hdr.prop_id),
            ),
        }
    }

    // ── Extended property services ──────────────────────────────────
    //
    // These reach an interface object by type plus one-based occurrence
    // instead of by index (03/03/07 §3.4.5.1). Everything after the
    // resolution is the classic property path — the same roster, the same
    // access checks — so the extended services are an addressing surface
    // rather than a second property model.

    /// Resolve `(object_type, occurrence)` against the family's indexed
    /// roster.
    ///
    /// Occurrences are one-based (03/03/07 §3.4.5.1) and instance 0 is not a
    /// valid one, so it never resolves — the trap here is answering with
    /// object 0 for it.
    pub(crate) fn resolve_object(object_type: u16, object_instance: u16) -> Option<ObjectRoute> {
        if object_instance == 0 {
            return None;
        }
        let mut seen: u16 = 0;
        for idx in 0..F::OBJECT_COUNT {
            if F::object_type(idx) == object_type {
                seen += 1;
                if seen == object_instance {
                    return Some(ObjectRoute::Indexed(idx));
                }
            }
        }
        // Profile-module objects continue the same occurrence count and are
        // exposed at consecutive classic indices after the family roster.
        for index in 0..SEC::OBJECT_COUNT {
            if SEC::object_type(index) == Some(object_type) {
                seen += 1;
                if seen == object_instance {
                    return Some(ObjectRoute::Module(index));
                }
            }
        }
        None
    }

    /// Build one extended-property reply from a writer that fills a frame
    /// buffer from `MSG_APCI` onward.
    ///
    /// The proto writers start at `MSG_APCI + 2`, leaving the TPCI and APCI
    /// octets to the frame builder — which is exactly the split `Reply`
    /// wants, so the payload is the scratch buffer from octet 8 to the
    /// length the writer reports.
    pub(crate) fn ext_reply(apci: ApciCode, msg_len: usize, fill: impl FnOnce(&mut [u8])) -> ServiceResult<FRAME_CAP> {
        let mut scratch: Vec<u8, FRAME_CAP> = Vec::new();
        if scratch.resize_default(msg_len).is_err() {
            // The response does not fit the profile's frame, and there is no
            // shorter thing to say: `A_PropertyExtDescription_Response` is a
            // fixed 23 canonical octets, so a standard-frame profile cannot
            // answer a description read at all. Callers that *can* answer
            // shorter check the length first and send
            // `E_LENGTH_EXCEEDS_MAX_APDU_LENGTH` instead; reaching here means
            // even that did not fit. Silence beats a truncated frame claiming
            // a length it does not have.
            return ServiceResult::None;
        }
        fill(&mut scratch);
        ServiceResult::Reply(Reply::new(apci, 0, &scratch[EXT_PAYLOAD_START..msg_len]))
    }

    pub(crate) fn property_ext_value_read(&mut self, frame: &[u8], access: AccessContext) -> ServiceResult<FRAME_CAP> {
        let Some(hdr) = PropertyExtValueHeader::parse(frame) else {
            return ServiceResult::None;
        };
        let Some(route) = Self::resolve_object(hdr.object_type, hdr.object_instance) else {
            return Self::ext_error(&hdr, PropertyReturnCode::AddressVoid);
        };
        let value = match route {
            ObjectRoute::Module(object) => {
                let security_on = SEC::security_mode_enabled(&self.sec);
                let Some((_, descriptor)) = SEC::property_descriptor(object, hdr.prop_id) else {
                    return Self::ext_error(&hdr, PropertyReturnCode::AddressVoid);
                };
                if !descriptor.can_read_secure(&access, security_on) {
                    self.record_access_failure(access, frame);
                    return Self::ext_error(&hdr, PropertyReturnCode::AccessDenied);
                }
                SEC::property_read::<FRAME_CAP>(&self.sec, object, hdr.prop_id, hdr.count, hdr.start_idx)
            }
            // A 12-bit PID that does not fit the classic roster's 8-bit space
            // cannot name one of a family's properties, so it is an address
            // error rather than a parse failure.
            ObjectRoute::Indexed(obj) => match u8::try_from(hdr.prop_id) {
                Ok(prop_id) => {
                    let Some((_, spec)) = Self::property_spec_by_id(obj, u16::from(prop_id)) else {
                        return Self::ext_error(&hdr, PropertyReturnCode::AddressVoid);
                    };
                    if !spec.descriptor.can_read_secure(&access, SEC::security_mode_enabled(&self.sec)) {
                        self.record_access_failure(access, frame);
                        return Self::ext_error(&hdr, PropertyReturnCode::AccessDenied);
                    }
                    self.property_read(obj, prop_id, hdr.count, hdr.start_idx, access)
                }
                Err(_) => None,
            },
        };
        match value {
            Some(data) if PropertyExtValueResponse::msg_len(data.len()) > Self::max_plaintext_frame_len() => {
                // The value exists but will not fit the frame this profile
                // can send. 03/03/07 §3.4.5.5 has a code for exactly that,
                // and it is a much better answer than a truncated value the
                // client would read as complete.
                Self::ext_error(&hdr, PropertyReturnCode::LengthExceedsMaxApduLength)
            }
            Some(data) => Self::ext_reply(
                ApciCode::PropertyExtValueResponse,
                PropertyExtValueResponse::msg_len(data.len()),
                |buf| {
                    PropertyExtValueResponse::write(
                        buf,
                        hdr.object_type,
                        hdr.object_instance,
                        hdr.prop_id,
                        hdr.count,
                        hdr.start_idx,
                        &data,
                    );
                },
            ),
            None => Self::ext_error(&hdr, PropertyReturnCode::AddressVoid),
        }
    }

    pub(crate) fn ext_error(hdr: &PropertyExtValueHeader, code: PropertyReturnCode) -> ServiceResult<FRAME_CAP> {
        Self::ext_reply(ApciCode::PropertyExtValueResponse, PropertyExtValueResponse::ERROR_MSG_LEN, |buf| {
            PropertyExtValueResponse::write_error(
                buf,
                hdr.object_type,
                hdr.object_instance,
                hdr.prop_id,
                hdr.start_idx,
                code,
            );
        })
    }

    /// `A_PropertyExtValue_WriteCon` / `_WriteUnCon`.
    ///
    /// The unconfirmed form is the same write without the response, which is
    /// why both share a body: 03/03/07 §3.4.5 differs only in whether the
    /// server answers.
    pub(crate) fn property_ext_value_write(
        &mut self,
        frame: &[u8],
        access: AccessContext,
        confirmed: bool,
    ) -> ServiceResult<FRAME_CAP> {
        let Some(hdr) = PropertyExtValueHeader::parse(frame) else {
            return ServiceResult::None;
        };
        let data = hdr.data(frame);
        let policy_denied = match Self::resolve_object(hdr.object_type, hdr.object_instance) {
            Some(ObjectRoute::Module(object)) => SEC::property_descriptor(object, hdr.prop_id)
                .is_some_and(|(_, desc)| !desc.can_write_secure(&access, SEC::security_mode_enabled(&self.sec))),
            Some(ObjectRoute::Indexed(obj)) => u8::try_from(hdr.prop_id)
                .ok()
                .and_then(|pid| Self::property_spec_by_id(obj, u16::from(pid)))
                .is_some_and(|(_, spec)| {
                    !spec.descriptor.can_write_secure(&access, SEC::security_mode_enabled(&self.sec))
                }),
            None => false,
        };
        let accepted = match Self::resolve_object(hdr.object_type, hdr.object_instance) {
            Some(ObjectRoute::Module(object)) => {
                let security_on = SEC::security_mode_enabled(&self.sec);
                SEC::property_descriptor(object, hdr.prop_id).map(|(_, desc)| {
                    if desc.can_write_secure(&access, security_on) {
                        SEC::property_write(&mut self.sec, object, hdr.prop_id, hdr.count, hdr.start_idx, data)
                    } else {
                        PropertyReturnCode::AccessDenied
                    }
                })
            }
            Some(ObjectRoute::Indexed(obj)) => u8::try_from(hdr.prop_id).ok().map(|pid| {
                if self.property_write(obj, pid, hdr.count, hdr.start_idx, data, access) {
                    PropertyReturnCode::Success
                } else {
                    PropertyReturnCode::AccessDenied
                }
            }),
            None => None,
        };
        let code = match accepted {
            Some(code) => code,
            None => PropertyReturnCode::AddressVoid,
        };
        if policy_denied {
            self.record_access_failure(access, frame);
        }
        if !confirmed {
            return ServiceResult::None;
        }
        Self::ext_reply(ApciCode::PropertyExtValueWriteConRes, PropertyExtValueWriteConRes::MSG_LEN, |buf| {
            if code == PropertyReturnCode::Success {
                PropertyExtValueWriteConRes::write_success(
                    buf,
                    hdr.object_type,
                    hdr.object_instance,
                    hdr.prop_id,
                    hdr.count,
                    hdr.start_idx,
                    code,
                );
            } else {
                PropertyExtValueWriteConRes::write_error(
                    buf,
                    hdr.object_type,
                    hdr.object_instance,
                    hdr.prop_id,
                    hdr.start_idx,
                    code,
                );
            }
        })
    }

    pub(crate) fn property_ext_description_read(
        &self,
        frame: &[u8],
        access: AccessContext,
    ) -> ServiceResult<FRAME_CAP> {
        let Some(hdr) = PropertyExtDescriptionHeader::parse(frame) else {
            return ServiceResult::None;
        };
        // Same lookup rule as the classic service: a zero PID means "the
        // property at this index", anything else means "this property".
        let found = Self::resolve_object(hdr.object_type, hdr.object_instance).and_then(|route| match route {
            ObjectRoute::Module(object) if hdr.prop_id == 0 => {
                SEC::property_descriptor_at(object, hdr.prop_idx).map(|desc| (hdr.prop_idx, desc))
            }
            ObjectRoute::Module(object) => SEC::property_descriptor(object, hdr.prop_id),
            ObjectRoute::Indexed(obj) if hdr.prop_id == 0 => {
                let idx = u8::try_from(hdr.prop_idx).ok()?;
                Self::property_spec(obj, idx).map(|spec| (u16::from(idx), spec.descriptor))
            }
            ObjectRoute::Indexed(obj) => u8::try_from(hdr.prop_id)
                .ok()
                .and_then(|pid| Self::property_spec_by_id(obj, u16::from(pid)))
                .map(|(idx, spec)| (u16::from(idx), spec.descriptor)),
        });
        let found = found.filter(|(_, descriptor)| {
            let allowed = descriptor.can_describe_secure(&access, SEC::security_mode_enabled(&self.sec));
            if !allowed {
                self.record_access_failure(access, frame);
            }
            allowed
        });

        Self::ext_reply(ApciCode::PropertyExtDescriptionResponse, PropertyExtDescriptionResponse::MSG_LEN, |buf| {
            match found {
                Some((property_index, descriptor)) => {
                    let desc = PropertyDescription::from_descriptor(hdr.object_type, property_index, &descriptor);
                    PropertyExtDescriptionResponse::write(buf, hdr.object_type, hdr.object_instance, &desc);
                }
                // Unknown object, property or exhausted by-index scan: echo
                // the lookup key with a zeroed descriptor, as the classic
                // service does.
                None => PropertyExtDescriptionResponse::write_error(
                    buf,
                    hdr.object_type,
                    hdr.object_instance,
                    hdr.prop_id,
                    hdr.desc_type,
                    hdr.prop_idx,
                ),
            }
        })
    }
}
