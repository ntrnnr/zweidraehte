//! The interface-object dispatcher shared by the BCU families.
//!
//! A device's interface objects fall into two groups. The **base objects**
//! sit at fixed indexes from 0 upward and are defined by the mask: System B
//! has six, System 7 five, and ETS addresses them by index without checking
//! their type (03/05/03 §3.9.3.3). Behind them come the objects that
//! augments contribute — Security, KNXnet/IP Parameter, RF Medium, …
//!
//! [`ObjectDispatcher`] owns the dispatch between the two: property
//! descriptions, value reads and writes, function properties, the
//! dispatcher-served `PID_IO_LIST`, the per-property access checks and the
//! dirty marking. A family supplies only its base objects, through
//! [`BaseObjects`]. The family type is a generic parameter, so each device
//! monomorphizes its own dispatcher; nothing here dispatches dynamically.

use zweidraehte_proto::access::{AccessContext, AccessLevel, AccessPolicy};
use zweidraehte_proto::dpt::{
    DeviceControl, InterfaceObjectType, PDT_Control, PDT_UnsignedInt, PropertyDataDefinition,
};
use zweidraehte_proto::dpt::{ProgrammingMode, RoutingCount};
use zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode;

use super::{
    FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult,
    HasDeviceObject, HasRoutingCount, PropertyAccess, PropertyDescriptionResponse, PropertyDescriptor, PropertyError,
    PropertyLookup, PropertyReadRequest, PropertyServiceHandler, PropertyWriteRequest, WriteResponse, pid,
};
use crate::context::layer::LayerContext;
use crate::service::{Augment, ServiceCtx, debug_assert_no_duplicate_object_types};
use crate::{HasAuthorization, HasPersistence, HasSecurityMode, StackDefinition, StackState};

// ============================================================================
// The family's part: its base objects
// ============================================================================

/// The fixed-index interface objects a mask defines, ahead of the objects
/// augments add. One implementation per BCU family.
///
/// Every `object_idx` handed to these methods is below `TYPES.len()`; the
/// dispatcher routes the rest to the augments.
pub trait BaseObjects {
    /// The object type at each base index, in index order.
    const TYPES: &'static [InterfaceObjectType];

    /// The descriptor of `pid` on the base object at `object_idx`.
    fn descriptor(&self, object_idx: u16, pid: u16) -> Option<PropertyDescriptor>;

    /// How many properties the base object at `object_idx` declares.
    fn property_count(&self, object_idx: u16) -> u16;

    /// A_PropertyDescription_Read against the base object at `object_idx`.
    fn property_description(
        &self,
        object_idx: u16,
        pid: u16,
        prop_idx: u16,
    ) -> Result<PropertyDescriptionResponse, PropertyError>;

    /// Read a property of the base object at `object_idx`.
    fn read_property(&self, object_idx: u16, req: PropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError>;

    /// Write a property of the base object at `object_idx`.
    fn write_property(&self, object_idx: u16, req: PropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError>;

    // Device Object runtime fields, behind the dispatcher's `HasDeviceObject`.

    fn device_control(&self) -> DeviceControl;
    fn set_device_control(&self, value: DeviceControl);
    fn routing_count(&self) -> RoutingCount;
    fn set_routing_count(&self, value: RoutingCount);

    /// The write level a base property is described with, once the device's
    /// profile modules are known. A profile module may tighten a base
    /// profile's access: Data Security makes System 7's Programming Mode
    /// `3/2` (06 Profiles §9.1.2.6.2). The default leaves `level` alone.
    fn write_level(&self, object_idx: u16, pid: u16, level: u8, has_security_object: bool) -> u8 {
        let _ = (object_idx, pid, has_security_object);
        level
    }
}

// ============================================================================
// The dispatcher
// ============================================================================

/// Interface objects of a device: a family's [`BaseObjects`] at indexes
/// `0..B::TYPES.len()`, then the objects contributed by the augment
/// registry `Aug`.
///
/// The dispatcher borrows the registry for the lifetime of the stack; the
/// runner owns it. Augments may also add or override properties on base
/// objects, and are asked first on every path.
pub struct ObjectDispatcher<'a, D: StackDefinition, B: BaseObjects, Aug: Augment<D> = ()> {
    state: &'a D::State,
    lctx: &'a LayerContext<D>,
    base: B,
    augments: &'a Aug,
}

impl<'a, D: StackDefinition, B: BaseObjects, Aug: Augment<D>> ObjectDispatcher<'a, D, B, Aug> {
    /// Number of base interface objects.
    pub const BASE_OBJECT_COUNT: u16 = B::TYPES.len() as u16;

    /// Assemble a dispatcher from a family's base objects and the device's
    /// augment registry.
    pub fn new(state: &'a D::State, lctx: &'a LayerContext<D>, base: B, augments: &'a Aug) -> Self {
        debug_assert_no_duplicate_object_types::<D, _>(B::TYPES, augments);
        Self { state, lctx, base, augments }
    }

    /// Get the borrowed augment registry.
    pub fn augments(&self) -> &'a Aug {
        self.augments
    }

    /// Total number of interface objects (base + augment-provided).
    fn total_object_count(&self) -> u16 {
        Self::BASE_OBJECT_COUNT + self.augments.additional_object_count()
    }

    /// Resolve the object type at `object_idx`.
    fn object_type_for(&self, object_idx: u16) -> Option<InterfaceObjectType> {
        match B::TYPES.get(usize::from(object_idx)) {
            Some(object_type) => Some(*object_type),
            None => self.augments.additional_object_type_at(object_idx - Self::BASE_OBJECT_COUNT),
        }
    }

    /// Whether `object_idx` is an augment-provided object rather than a
    /// base object.
    fn is_augment_object(&self, object_idx: u16) -> bool {
        object_idx >= Self::BASE_OBJECT_COUNT && object_idx < self.total_object_count()
    }

    /// Whether the composition includes a Security Interface Object, which
    /// is what enables the Data Security profile module.
    fn has_security_object(&self) -> bool {
        (0..self.augments.additional_object_count())
            .any(|index| self.augments.additional_object_type_at(index) == Some(InterfaceObjectType::Security))
    }

    /// Property descriptor for PID_IO_LIST.
    ///
    /// PID_IO_LIST policy per AN193 §"Object Type 0" — `3FF/0CC`
    /// (READ_OPEN_WRITE_TOOL). Readable by anyone, which is level 3 on a
    /// 4-level profile and 15 on a 16-level one. The property is read-only
    /// at the dispatch layer regardless of the policy's write bits.
    fn io_list_descriptor(&self) -> PropertyDescriptor {
        PropertyDescriptor::array::<PDT_UnsignedInt>(
            pid::device::IO_LIST,
            self.total_object_count(),
            PropertyAccess::ReadOnly,
            AccessLevel::Runtime.for_levels(<D::State as HasAuthorization>::MAX_ACCESS_LEVELS),
            AccessLevel::SystemManufacturer.for_levels(<D::State as HasAuthorization>::MAX_ACCESS_LEVELS),
            AccessPolicy::READ_OPEN_WRITE_TOOL,
        )
    }

    /// Read PID_IO_LIST as an array property into `buf`: the base types
    /// followed by the augment-provided ones.
    fn read_io_list(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        let total = usize::from(self.total_object_count());

        if start_idx == 0 {
            if buf.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            buf[..2].copy_from_slice(&(total as u16).to_be_bytes());
            return Ok(2);
        }

        let start = usize::from(start_idx - 1);
        if start >= total {
            return Err(PropertyError::InvalidStartIndex);
        }

        let end = (start + usize::from(count)).min(total);
        let needed = (end - start) * 2;
        if buf.len() < needed {
            return Err(PropertyError::BufferTooSmall);
        }

        for i in start..end {
            let object_type = self.object_type_for(i as u16);
            let ot = object_type.expect("IO_LIST count and object types stay consistent");

            let val: u16 = ot.into();
            let offset = (i - start) * 2;
            buf[offset..offset + 2].copy_from_slice(&val.to_be_bytes());
        }

        Ok(needed)
    }

    /// The descriptor that governs `(obj_idx, prop_id)`.
    fn get_descriptor(&self, obj_idx: u16, prop_id: u16) -> Option<PropertyDescriptor> {
        // PID_IO_LIST is served by the dispatcher, not the Device Object.
        if obj_idx == 0 && prop_id == pid::device::IO_LIST {
            return Some(self.io_list_descriptor());
        }

        // An augment may add a PID to a base object or intercept one; it
        // then owns that property's descriptor, just as it goes first in
        // the value and description dispatch. Without this, a write to an
        // augment-added base-object PID found no descriptor and skipped the
        // access, policy and start-index checks altogether.
        let obj_type = self.object_type_for(obj_idx)?;
        if let Some(descriptor) = self.augments.property_descriptor(obj_type, prop_id) {
            return Some(descriptor);
        }

        if obj_idx >= Self::BASE_OBJECT_COUNT {
            return None;
        }
        let mut descriptor = self.base.descriptor(obj_idx, prop_id)?;
        descriptor.write_level =
            self.base.write_level(obj_idx, prop_id, descriptor.write_level, self.has_security_object());
        Some(descriptor)
    }

    /// Whether per-property `AccessPolicy` bitfields apply with their
    /// "Security Mode On" columns rather than the "Security Mode Off"
    /// ones: true only while the device reports Data Secure as enabled.
    fn enforce_secure_access_policy(&self) -> bool {
        self.state.security_mode_enabled()
    }

    /// Run the per-property access policy for `(object_idx, pid)` against
    /// the caller's `AccessContext`, calling `policy` to evaluate the
    /// matrix (`can_read_secure`, `can_write_secure`,
    /// `can_function_read_secure`, `can_function_write_secure`).
    ///
    /// Returns `true` if access is allowed (or no descriptor is registered
    /// for the property — unknown properties fall through to the
    /// per-object handlers, which decide whether they exist). Returns
    /// `false` after logging an access-denied event when the policy
    /// rejects the access.
    fn check_access<F>(&self, object_idx: u16, pid: u16, ctx: &AccessContext, policy: F) -> bool
    where
        F: FnOnce(&PropertyDescriptor, &AccessContext, bool) -> bool,
    {
        let Some(desc) = self.get_descriptor(object_idx, pid) else {
            return true;
        };

        if policy(&desc, ctx, self.enforce_secure_access_policy()) {
            return true;
        }

        if ctx.source_addr != 0 {
            self.state.log_access_denied(ctx.source_addr);
        }

        false
    }
}

// ============================================================================
// PropertyServiceHandler — property dispatch across base + augment objects
// ============================================================================

impl<'a, D: StackDefinition, B: BaseObjects, Aug: Augment<D>> PropertyServiceHandler
    for ObjectDispatcher<'a, D, B, Aug>
{
    fn object_count(&self) -> u16 {
        self.total_object_count()
    }

    fn object_type_at(&self, object_idx: u16) -> Option<InterfaceObjectType> {
        self.object_type_for(object_idx)
    }

    fn property_description_read(
        &self,
        object_idx: u16,
        prop_id: u16,
        prop_idx: u16,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        let obj_type = self.object_type_for(object_idx).ok_or(PropertyError::InvalidObjectIndex)?;

        // ================================================================
        // Direct PID lookup (prop_id != 0)
        // ================================================================
        if prop_id != 0 {
            // PID_IO_LIST on the Device Object is handled by the dispatcher
            // itself, before the augment or base object.
            if object_idx == 0 && prop_id == pid::device::IO_LIST {
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
        let has_security_object = self.has_security_object();
        let base_result = self.base.property_description(object_idx, prop_id, prop_idx).map(|mut response| {
            response.write_level =
                self.base.write_level(object_idx, response.prop_id, response.write_level, has_security_object);
            response
        });

        if base_result.is_ok() || prop_id != 0 {
            return base_result;
        }

        // Index scan (prop_id == 0): base ran out of properties.
        let base_count = self.base.property_count(object_idx);

        // PID_IO_LIST appears as the first extra property on the Device
        // Object, before any augment properties.
        let augment_idx = if object_idx == 0 {
            if prop_idx == base_count {
                return Ok(PropertyDescriptionResponse::from_descriptor(
                    object_idx,
                    prop_idx,
                    &self.io_list_descriptor(),
                ));
            }
            // Offset for augment: skip both base properties and IO_LIST.
            prop_idx.saturating_sub(base_count + 1)
        } else {
            // Other base objects: give the augment a chance to append its
            // own, using a 0-based index offset from the base property count.
            prop_idx.saturating_sub(base_count)
        };

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

    fn property_description_visible(&self, object_idx: u16, pid: u16, ctx: &AccessContext) -> bool {
        // Visible to anyone the policy grants *any* access — read, write,
        // or the function channel. `check_access` returns true for
        // properties without a descriptor, matching the trait default.
        self.check_access(object_idx, pid, ctx, PropertyDescriptor::can_read_secure)
            || self.check_access(object_idx, pid, ctx, PropertyDescriptor::can_write_secure)
            || self.check_access(object_idx, pid, ctx, PropertyDescriptor::can_function_write_secure)
    }

    fn property_value_read(&self, req: &FullPropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        let obj_type = self.object_type_for(req.object_idx).ok_or(PropertyError::InvalidObjectIndex)?;

        // Check access before any read dispatch.
        //
        // `AccessPolicy` is evaluated regardless of whether the stack has
        // a secure extension: plain (non-secure) stacks pass
        // `security_on = false`, which makes `can_read_secure` consult the
        // `sec_off` permission columns. The legacy default policy
        // `READ_OPEN_WRITE_TOOL` permits unlisted plain reads, so a
        // property's access policy can be audited without also enabling
        // Data Secure (Vol 6 §6.2 / Profiles Annex A.2).
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

        // PID_IO_LIST on the Device Object is handled by the dispatcher
        // because only the dispatcher knows all interface object types present
        // in the device (including augment-provided objects).
        if req.object_idx == 0 && req.pid == pid::device::IO_LIST {
            return self.read_io_list(req.start_idx, req.count, buf);
        }

        self.base.read_property(req.object_idx, req.property_request(), buf)
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

            // A single value's element 0 is its fixed count of 1
            // (03/04/01 §4.3.4.2), so only start index 1 addresses it.
            // Arrays keep element-0 writes, which reset them (§4.3.2.3).
            // Checked here, once for base objects, augments and `manual`
            // handlers alike, because a handler that is handed only the
            // payload would store the count octets as the value.
            if desc.is_single_value() && req.start_idx != 1 {
                return Err(PropertyError::InvalidStartIndex);
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

        let result = self.base.write_property(req.object_idx, req.property_request());

        // Mark state dirty on successful property writes, but skip volatile
        // properties that don't need persistence (runtime control flags,
        // execution state). These are transient and re-derived on boot.
        if result.is_ok() {
            let volatile = matches!(
                (obj_type, req.pid),
                (InterfaceObjectType::Device, pid::DEVICE_CONTROL | pid::device::PROGMODE)
                    | (
                        InterfaceObjectType::ApplicationProgram | InterfaceObjectType::InterfaceProgram,
                        pid::RUN_STATE_CONTROL
                    )
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
        if !self.check_access(req.object_idx, req.prop_id, &req.ctx, PropertyDescriptor::can_function_write_secure) {
            // Echo back the service_info byte (second byte of service_data)
            // in the access-denied response per conformance spec.
            let service_info = req.service_data.get(1).copied().unwrap_or(0);
            return FunctionPropertyResult::with_code(PropertyReturnCode::AccessDenied, &[service_info]);
        }

        let object_type = self.object_type_for(req.object_idx);
        let augment_result = object_type.and_then(|obj_type| {
            let context = ServiceCtx::new(self.state, self.lctx, req.ctx);

            self.augments.function_property_command(&context, obj_type, req)
        });

        if let Some(result) = augment_result {
            return result;
        }

        // PDT_CONTROL properties: write the service data via the data
        // property path and return the new state. Per KNX spec 03/04/01
        // Table 2 this is the recommended access method for PDT_CONTROL.
        // `property_value_{write,read}` already route through the augment
        // hooks first, so this path works uniformly for base and
        // augment-provided objects (e.g. Security IO PID_LOAD_STATE_CONTROL).
        if let Some(desc) = self.get_descriptor(req.object_idx, req.prop_id)
            && desc.pdt_id == PDT_Control::ID
        {
            let write_req = FullPropertyWriteRequest {
                object_idx: req.object_idx,
                pid: req.prop_id,
                count: 1,
                start_idx: 1,
                data: req.service_data,
                ctx: req.ctx,
            };
            if self.property_value_write(&write_req).is_err() {
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
            return FunctionPropertyResult::with_code(PropertyReturnCode::AccessDenied, &[service_info]);
        }

        let object_type = self.object_type_for(req.object_idx);
        let augment_result = object_type.and_then(|obj_type| {
            let context = ServiceCtx::new(self.state, self.lctx, req.ctx);

            self.augments.function_property_state_read(&context, obj_type, req)
        });

        if let Some(result) = augment_result {
            return result;
        }

        // PDT_CONTROL properties: read the current value via the data
        // property path and return it as function property data. Per KNX
        // spec 03/04/01 Table 2 PDT_CONTROL is mandatory for extended
        // function property services. Routes through augment hooks, so
        // augment-provided objects (e.g. Security IO) are handled too.
        if let Some(desc) = self.get_descriptor(req.object_idx, req.prop_id)
            && desc.pdt_id == PDT_Control::ID
        {
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

        FunctionPropertyResult::not_supported()
    }
}

// ============================================================================
// HasDeviceObject — typed access to Device Object properties
// ============================================================================

impl<'a, D: StackDefinition, B: BaseObjects, Aug: Augment<D>> HasDeviceObject for ObjectDispatcher<'a, D, B, Aug> {
    fn device_control(&self) -> DeviceControl {
        self.base.device_control()
    }

    fn set_device_control(&self, value: DeviceControl) {
        self.base.set_device_control(value);
    }

    fn programming_mode(&self) -> ProgrammingMode {
        ProgrammingMode::from(self.state.is_programming_mode())
    }

    fn set_programming_mode(&self, value: ProgrammingMode) {
        self.state.set_programming_mode(value.enabled());
    }

    fn routing_count(&self) -> RoutingCount {
        self.base.routing_count()
    }

    fn set_routing_count(&self, value: RoutingCount) {
        self.base.set_routing_count(value);
        // Sync to state so the network layer (which reads routing count
        // from state via HasRoutingCount) stays in sync with ETS property writes.
        self.state.set_routing_count(value.value());
    }
}
