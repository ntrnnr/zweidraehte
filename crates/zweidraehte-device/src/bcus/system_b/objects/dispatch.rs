//! `PropertyServiceHandler` and `HasDeviceObject` implementations for
//! [`SystemBObjects`].
//!
//! This module contains the property dispatch logic: routing property
//! reads, writes, and descriptions to the correct base object or augment
//! based on the object index and PID.

use crate::{
    HasPersistence, StackDefinition, StackState,
    device_model::DeviceModelNotifier,
    objects::interface::{
        FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult,
        HasDeviceObject, InterfaceObject, PropertyAccess, PropertyBuf, PropertyDescriptionResponse, PropertyDescriptor,
        PropertyError, PropertyServiceHandler, WriteResponse, pid,
    },
    objects::tables::{HasLoadStateMachine, HasRunStateMachine},
    service::{AugmentRegistry, ServiceCtx},
};
use zweidraehte_proto::access::AccessContext;
use zweidraehte_proto::dpt::{DeviceControl, ProgrammingMode, RoutingCount};

use super::SystemBObjects;
use crate::objects::interface::HasRoutingCount;

// ============================================================================
// PropertyServiceHandler — property dispatch across base + augment objects
// ============================================================================

impl<'a, D, ADT, AST, COT, APP, PEI, Aug: AugmentRegistry<D>> PropertyServiceHandler
    for SystemBObjects<'a, D, ADT, AST, COT, APP, PEI, Aug>
where
    D: StackDefinition,
    D::State: StackState + HasPersistence + DeviceModelNotifier,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    fn object_count(&self) -> u16 {
        self.total_object_count()
    }

    fn object_type_at(&self, object_idx: u16) -> Option<zweidraehte_proto::dpt::InterfaceObjectType> {
        self.object_type_for(object_idx)
    }

    fn property_description_read(
        &self,
        object_idx: u16,
        prop_id: u16,
        prop_idx: u16,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        use crate::objects::interface::PropertyLookup;

        let obj_type = self.object_type_for(object_idx).ok_or(PropertyError::InvalidObjectIndex)?;

        // ================================================================
        // Direct PID lookup (prop_id != 0)
        // ================================================================
        if prop_id != 0 {
            // PID_IO_LIST on the Device Object is handled at the container
            // level, before the augment or base object.
            if object_idx == 0 && prop_id == pid::IO_LIST {
                return Ok(PropertyDescriptionResponse::from_descriptor(object_idx, 0, &self.io_list_descriptor()));
            }

            // Augment first (can intercept/add PIDs on base objects,
            // and is the sole handler for augment-provided objects).
            if let Some(result) = self.augments.property_description_read(
                &ServiceCtx::new(self.state, self.lctx, AccessContext::default()),
                obj_type,
                object_idx,
                PropertyLookup::ByPid(prop_id),
            ) {
                return result;
            }

            // For augment-provided objects, augment is sole handler.
            if self.is_augment_object(object_idx) {
                return Err(PropertyError::InvalidPropertyId);
            }
        }

        // ================================================================
        // Augment-provided objects: index scan (prop_id == 0)
        // ================================================================
        //
        // For augment-provided objects, all properties come from the augment.
        // There is no base object to scan first.
        if self.is_augment_object(object_idx) {
            if let Some(result) = self.augments.property_description_read(
                &ServiceCtx::new(self.state, self.lctx, AccessContext::default()),
                obj_type,
                object_idx,
                PropertyLookup::ByIndex(prop_idx),
            ) {
                return result.map(|mut resp| {
                    resp.prop_idx = prop_idx;
                    resp
                });
            }
            return Err(PropertyError::InvalidPropertyId);
        }

        // ================================================================
        // Base objects: try base first, then augment for extra properties
        // ================================================================
        let base_result = match object_idx {
            0 => self.device.borrow().property_description(object_idx, prop_id, prop_idx),
            1 => self.address_table.borrow().property_description(object_idx, prop_id, prop_idx),
            2 => self.association_table.borrow().property_description(object_idx, prop_id, prop_idx),
            3 => self.group_object_table.borrow().property_description(object_idx, prop_id, prop_idx),
            4 => self.application_program.borrow().property_description(object_idx, prop_id, prop_idx),
            5 => self.pei_program.borrow().property_description(object_idx, prop_id, prop_idx),
            _ => unreachable!("augment objects handled above"),
        };

        if base_result.is_ok() || prop_id != 0 {
            return base_result;
        }

        // Index scan (prop_id == 0): base ran out of properties.
        // PID_IO_LIST appears as the first extra property on the Device
        // Object, before any augment properties.
        if object_idx == 0 {
            let base_count = self.base_property_count(object_idx);
            if prop_idx == base_count {
                return Ok(PropertyDescriptionResponse::from_descriptor(
                    object_idx,
                    prop_idx,
                    &self.io_list_descriptor(),
                ));
            }

            // Offset for augment: skip both base properties and IO_LIST.
            let augment_idx = prop_idx.saturating_sub(base_count + 1);
            if let Some(result) = self.augments.property_description_read(
                &ServiceCtx::new(self.state, self.lctx, AccessContext::default()),
                obj_type,
                object_idx,
                PropertyLookup::ByIndex(augment_idx),
            ) {
                return result.map(|mut resp| {
                    resp.prop_idx = prop_idx;
                    resp
                });
            }

            return base_result;
        }

        // Non-Device base objects: give the augment a chance to append its own,
        // using a 0-based index offset from the base property count.
        let base_count = self.base_property_count(object_idx);
        let augment_idx = prop_idx.saturating_sub(base_count);
        if let Some(result) = self.augments.property_description_read(
            &ServiceCtx::new(self.state, self.lctx, AccessContext::default()),
            obj_type,
            object_idx,
            PropertyLookup::ByIndex(augment_idx),
        ) {
            return result.map(|mut resp| {
                resp.prop_idx = prop_idx;
                resp
            });
        }

        base_result
    }

    fn property_value_read(&self, req: &FullPropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        let obj_type = self.object_type_for(req.object_idx).ok_or(PropertyError::InvalidObjectIndex)?;

        // Check access before any read dispatch.
        //
        // `AccessPolicy` is evaluated regardless of whether the stack has
        // a secure extension: plain (non-secure) stacks pass
        // `security_on = false`, which makes `can_read_secure` consult the
        // `sec_off` permission columns. The legacy default policy
        // `READ_OPEN_WRITE_TOOL` permits unlisted plain reads, so existing
        // tests that send `AccessContext::MIN_ACCESS` continue to pass.
        // The previous shape silently bypassed the per-property policy
        // entirely on non-secure devices, which made it impossible to
        // audit a property's access policy without also enabling Data
        // Secure (Vol 6 §6.2 / Profiles Annex A.2).
        if !self.check_access(req.object_idx, req.pid, &req.ctx, PropertyDescriptor::can_read_secure) {
            return Err(PropertyError::AccessDenied);
        }

        // Augment first (can intercept specific PIDs on base objects,
        // and is the sole handler for augment-provided objects).
        if let Some(result) =
            self.augments.property_value_read(&ServiceCtx::new(self.state, self.lctx, req.ctx), obj_type, req, buf)
        {
            return result;
        }

        // For augment-provided objects, the augment is the sole handler.
        // If it returned None, the PID is not supported on this object.
        if self.is_augment_object(req.object_idx) {
            return Err(PropertyError::InvalidPropertyId);
        }

        // PID_IO_LIST on the Device Object is handled at the container level
        // because only the container knows all interface object types present
        // in the device (including augment-provided objects).
        if req.object_idx == 0 && req.pid == pid::IO_LIST {
            return self.read_io_list(req.start_idx, req.count, buf);
        }

        // Dispatch to the appropriate base object.
        let prop_req = req.property_request();
        match req.object_idx {
            0 => self.device.borrow().read_property(prop_req, buf),
            1 => self.address_table.borrow().read_property(prop_req, buf),
            2 => self.association_table.borrow().read_property(prop_req, buf),
            3 => self.group_object_table.borrow().read_property(prop_req, buf),
            4 => self.application_program.borrow().read_property(prop_req, buf),
            5 => self.pei_program.borrow().read_property(prop_req, buf),
            _ => unreachable!("augment objects handled above"),
        }
    }

    fn property_value_write(&self, req: &FullPropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        let obj_type = self.object_type_for(req.object_idx).ok_or(PropertyError::InvalidObjectIndex)?;

        // Check access and bounds before any write dispatch (applies to base
        // and augment objects).
        if let Some(desc) = self.get_descriptor(req.object_idx, req.pid) {
            if matches!(desc.access, PropertyAccess::ReadOnly) {
                return Err(PropertyError::WriteNotAllowed);
            }
            // Same rationale as `property_value_read`: always evaluate the
            // per-property `AccessPolicy`, with the policy evaluated against
            // "Security Mode Off" columns on plain stacks.
            if !desc.can_write_secure(&req.ctx, self.enforce_secure_access_policy()) {
                if req.ctx.source_addr != 0 {
                    self.state.log_access_denied(req.ctx.source_addr);
                }
                return Err(PropertyError::AccessDenied);
            }

            // Validate element count and start index bounds.
            if req.start_idx > 0 && desc.max_elements > 0 {
                // start_idx is 1-based; last element written is at
                // start_idx + count - 1 which must be <= max_elements.
                if req.count == 0 {
                    return Err(PropertyError::InvalidStartIndex);
                }
                if req.start_idx + req.count - 1 > desc.max_elements {
                    return Err(PropertyError::InvalidStartIndex);
                }
            }
        }

        // Augment first (can intercept specific PIDs on base objects,
        // and is the sole handler for augment-provided objects).
        if let Some(result) =
            self.augments.property_value_write(&ServiceCtx::new(self.state, self.lctx, req.ctx), obj_type, req)
        {
            if result.is_ok() {
                self.state.mark_dirty();
            }
            return result;
        }

        // For augment-provided objects, the augment is the sole handler.
        if self.is_augment_object(req.object_idx) {
            return Err(PropertyError::InvalidPropertyId);
        }

        // Dispatch to the appropriate base object.
        let prop_req = req.property_request();
        let result = match req.object_idx {
            0 => self.device.borrow_mut().write_property(prop_req),
            1 => self.address_table.borrow_mut().write_property(prop_req),
            2 => self.association_table.borrow_mut().write_property(prop_req),
            3 => self.group_object_table.borrow_mut().write_property(prop_req),
            4 => self.application_program.borrow_mut().write_property(prop_req),
            5 => self.pei_program.borrow_mut().write_property(prop_req),
            _ => unreachable!("augment objects handled above"),
        };

        // Mark state dirty on successful property writes, but skip volatile
        // properties that don't need persistence (runtime control flags,
        // execution state). These are transient and re-derived on boot.
        if result.is_ok() {
            let volatile = matches!(
                (req.object_idx, req.pid),
                (0, pid::DEVICE_CONTROL)
                    | (0, pid::PROGMODE)
                    | (4, pid::RUN_STATE_CONTROL)
                    | (5, pid::RUN_STATE_CONTROL)
            );
            if !volatile {
                self.state.mark_dirty();
            }
        }

        result
    }

    fn function_property_command(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        // Function property command is write-like — enforce access policy.
        // We use can_function_write_secure (not can_write_secure) because
        // PDT_FUNCTION properties may be marked ReadOnly in the descriptor
        // while still being accessible via FunctionPropertyCommand.
        //
        // Always evaluate the function-property write policy. See the
        // comment on `property_value_read` for rationale; the same
        // applies to function-property gates.
        if !self.check_access(req.object_idx, req.prop_id, &req.ctx, PropertyDescriptor::can_function_write_secure) {
            // Echo back the service_info byte (second byte of service_data)
            // in the access-denied response per conformance spec.
            let service_info = req.service_data.get(1).copied().unwrap_or(0);
            return FunctionPropertyResult { return_code: 0xFC, data: PropertyBuf::new(&[service_info]) };
        }

        if let Some(obj_type) = self.object_type_for(req.object_idx) {
            if let Some(result) =
                self.augments.function_property_command(&ServiceCtx::new(self.state, self.lctx, req.ctx), obj_type, req)
            {
                return result;
            }
        }

        // PDT_CONTROL properties: write the service data via the data
        // property path and return the new state. Per KNX spec 03/04/01
        // Table 2 this is the recommended access method for PDT_CONTROL.
        // `property_value_{write,read}` already route through the augment
        // hooks first, so this path works uniformly for base and
        // augment-provided objects (e.g. Security IO PID_LOAD_STATE_CONTROL).
        if let Some(desc) = self.get_descriptor(req.object_idx, req.prop_id) {
            use zweidraehte_proto::dpt::{PDT_Control, PropertyDataDefinition};
            if desc.pdt_id == PDT_Control::ID {
                let write_req = FullPropertyWriteRequest {
                    object_idx: req.object_idx,
                    pid: req.prop_id,
                    count: 1,
                    start_idx: 1,
                    data: req.service_data,
                    ctx: req.ctx,
                };
                if let Err(_) = self.property_value_write(&write_req) {
                    return FunctionPropertyResult::not_supported();
                }
                // Read back the new state after writing.
                let read_req = FullPropertyReadRequest {
                    object_idx: req.object_idx,
                    pid: req.prop_id,
                    start_idx: 1,
                    count: 1,
                    ctx: req.ctx,
                };
                let mut buf = [0u8; 16];
                match self.property_value_read(&read_req, &mut buf) {
                    Ok(len) => return FunctionPropertyResult::success_with_data(&buf[..len]),
                    Err(_) => return FunctionPropertyResult::not_supported(),
                }
            }
        }

        FunctionPropertyResult::not_supported()
    }

    fn function_property_state_read(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        // Function property state read is read-like — enforce access policy.
        // We use can_function_read_secure (not can_read_secure) because
        // PDT_FUNCTION properties may be marked ReadOnly in the descriptor
        // while still needing policy-based access control for state reads.
        if !self.check_access(req.object_idx, req.prop_id, &req.ctx, PropertyDescriptor::can_function_read_secure) {
            // Echo back the service_info byte (second byte of service_data)
            // in the access-denied response per conformance spec.
            let service_info = req.service_data.get(1).copied().unwrap_or(0);
            return FunctionPropertyResult { return_code: 0xFC, data: PropertyBuf::new(&[service_info]) };
        }

        if let Some(obj_type) = self.object_type_for(req.object_idx) {
            if let Some(result) = self.augments.function_property_state_read(
                &ServiceCtx::new(self.state, self.lctx, req.ctx),
                obj_type,
                req,
            ) {
                return result;
            }
        }

        // PDT_CONTROL properties: read the current value via the data
        // property path and return it as function property data. Per KNX
        // spec 03/04/01 Table 2 PDT_CONTROL is mandatory for extended
        // function property services. Routes through augment hooks, so
        // augment-provided objects (e.g. Security IO) are handled too.
        if let Some(desc) = self.get_descriptor(req.object_idx, req.prop_id) {
            use zweidraehte_proto::dpt::{PDT_Control, PropertyDataDefinition};
            if desc.pdt_id == PDT_Control::ID {
                let read_req = FullPropertyReadRequest {
                    object_idx: req.object_idx,
                    pid: req.prop_id,
                    start_idx: 1,
                    count: 1,
                    ctx: req.ctx,
                };
                let mut buf = [0u8; 16];
                match self.property_value_read(&read_req, &mut buf) {
                    Ok(len) => return FunctionPropertyResult::success_with_data(&buf[..len]),
                    Err(_) => return FunctionPropertyResult::not_supported(),
                }
            }
        }

        FunctionPropertyResult::not_supported()
    }
}

// ============================================================================
// HasDeviceObject — typed access to Device Object properties
// ============================================================================

impl<'a, D, ADT, AST, COT, APP, PEI, Aug: AugmentRegistry<D>> HasDeviceObject
    for SystemBObjects<'a, D, ADT, AST, COT, APP, PEI, Aug>
where
    D: StackDefinition,
    D::State: StackState + DeviceModelNotifier + HasRoutingCount,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    fn device_control(&self) -> DeviceControl {
        self.device.borrow().device_control
    }

    fn set_device_control(&self, value: DeviceControl) {
        self.device.borrow_mut().device_control = value;
    }

    fn programming_mode(&self) -> ProgrammingMode {
        ProgrammingMode::from(self.state.is_programming_mode())
    }

    fn set_programming_mode(&self, value: ProgrammingMode) {
        self.state.set_programming_mode(value.enabled());
    }

    fn routing_count(&self) -> RoutingCount {
        self.device.borrow().routing_count
    }

    fn set_routing_count(&self, value: RoutingCount) {
        self.device.borrow_mut().routing_count = value;
        // Sync to state so the network layer (which reads routing count
        // from state via HasRoutingCount) stays in sync with ETS property writes.
        self.state.set_routing_count(value.value());
    }
}
