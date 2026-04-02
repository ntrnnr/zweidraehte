//! `PropertyServiceHandler` and `HasDeviceObject` implementations for
//! [`SystemBObjects`].
//!
//! This module contains the property dispatch logic: routing property
//! reads, writes, and descriptions to the correct base object or augment
//! based on the object index and PID.

use crate::{
    StackState,
    device_model::DeviceModelNotifier,
    dpt::{DeviceControl, ProgrammingMode, RoutingCount},
    objects::interface::{
        FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult,
        HasDeviceObject, InterfaceObject, InterfaceObjectAugment, PropertyAccess, PropertyDescriptionResponse,
        PropertyError, PropertyServiceHandler, WriteResponse, pid,
    },
    objects::tables::{HasLoadStateMachine, HasRunStateMachine},
};

use super::SystemBObjects;
use crate::objects::interface::HasRoutingCount;

// ============================================================================
// PropertyServiceHandler — property dispatch across base + augment objects
// ============================================================================

impl<'a, S, ADT, AST, COT, APP, PEI, A: InterfaceObjectAugment<S>> PropertyServiceHandler
    for SystemBObjects<'a, S, ADT, AST, COT, APP, PEI, A>
where
    S: StackState + DeviceModelNotifier,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    fn object_count(&self) -> u16 {
        self.total_object_count()
    }

    fn object_type_at(&self, object_idx: u16) -> Option<crate::dpt::InterfaceObjectType> {
        self.object_type_for(object_idx)
    }

    /// Extended property service instance resolution.
    ///
    /// Uses 0x0010-based per-type instance numbering: instance 0x0010 is
    /// the first object of the given type, 0x0011 the second, etc. This
    /// matches the convention used by the KNX conformance test templates.
    fn resolve_ext_object_index(&self, object_type: u16, object_instance: u16) -> Option<u16> {
        // Instance base: 0x0010 = first instance of each type.
        if object_instance < 0x0010 {
            return None;
        }
        let per_type_instance = (object_instance - 0x0010 + 1) as u8;
        self.resolve_object_index(object_type, per_type_instance)
    }

    fn property_description_read(
        &self,
        object_idx: u16,
        prop_id: u8,
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
            if let Some(result) =
                self.augment.property_description_read(self.state, obj_type, object_idx, PropertyLookup::ByPid(prop_id))
            {
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
            if let Some(result) = self.augment.property_description_read(
                self.state,
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
            if let Some(result) = self.augment.property_description_read(
                self.state,
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
        if let Some(result) = self.augment.property_description_read(
            self.state,
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
        // On secure devices (with augment objects), enforce both legacy
        // access levels AND Data Secure access policies. On non-secure
        // devices, only enforce legacy access levels.
        if let Some(desc) = self.get_descriptor(req.object_idx, req.pid) {
            if self.has_secure_extension() {
                let security_on = self.state.security_mode_enabled();
                if !desc.can_read_secure(&req.ctx, security_on) {
                    return Err(PropertyError::AccessDenied);
                }
            } else if !desc.can_read(req.ctx) {
                return Err(PropertyError::AccessDenied);
            }
        }

        // Augment first (can intercept specific PIDs on base objects,
        // and is the sole handler for augment-provided objects).
        if let Some(result) = self.augment.property_value_read(self.state, obj_type, req, buf) {
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
            if self.has_secure_extension() {
                let security_on = self.state.security_mode_enabled();
                if !desc.can_write_secure(&req.ctx, security_on) {
                    return Err(PropertyError::AccessDenied);
                }
            } else if !desc.can_write(req.ctx) {
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
        if let Some(result) = self.augment.property_value_write(self.state, obj_type, req) {
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
        if let Some(desc) = self.get_descriptor(req.object_idx, req.prop_id) {
            if self.has_secure_extension() {
                let security_on = self.state.security_mode_enabled();
                if !desc.can_write_secure(&req.ctx, security_on) {
                    return FunctionPropertyResult::access_denied();
                }
            } else if !desc.can_write(req.ctx) {
                return FunctionPropertyResult::access_denied();
            }
        }

        if let Some(obj_type) = self.object_type_for(req.object_idx) {
            if let Some(result) = self.augment.function_property_command(self.state, obj_type, req) {
                return result;
            }
        }

        // PDT_CONTROL properties on base objects: write the service data via the
        // data property path and return the new state. Per KNX spec 03/04/01
        // Table 2, this is the recommended access method for PDT_CONTROL.
        if !self.is_augment_object(req.object_idx) {
            if let Some(desc) = self.get_descriptor(req.object_idx, req.prop_id) {
                use crate::dpt::{PDT_Control, PropertyDataDefinition};
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
        }

        FunctionPropertyResult::not_supported()
    }

    fn function_property_state_read(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        // Function property state read is read-like — enforce access policy.
        if let Some(desc) = self.get_descriptor(req.object_idx, req.prop_id) {
            if self.has_secure_extension() {
                let security_on = self.state.security_mode_enabled();
                if !desc.can_read_secure(&req.ctx, security_on) {
                    return FunctionPropertyResult::access_denied();
                }
            } else if !desc.can_read(req.ctx) {
                return FunctionPropertyResult::access_denied();
            }
        }

        if let Some(obj_type) = self.object_type_for(req.object_idx) {
            if let Some(result) = self.augment.function_property_state_read(self.state, obj_type, req) {
                return result;
            }
        }

        // PDT_CONTROL properties on base objects: read the current value via the
        // data property path and return it as function property data. Per KNX spec
        // 03/04/01 Table 2, PDT_CONTROL is mandatory for extended function property
        // services and this is the recommended access method.
        if !self.is_augment_object(req.object_idx) {
            if let Some(desc) = self.get_descriptor(req.object_idx, req.prop_id) {
                use crate::dpt::{PDT_Control, PropertyDataDefinition};
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
        }

        FunctionPropertyResult::not_supported()
    }
}

// ============================================================================
// HasDeviceObject — typed access to Device Object properties
// ============================================================================

impl<'a, S, ADT, AST, COT, APP, PEI, A: InterfaceObjectAugment<S>> HasDeviceObject
    for SystemBObjects<'a, S, ADT, AST, COT, APP, PEI, A>
where
    S: StackState + DeviceModelNotifier + HasRoutingCount,
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
