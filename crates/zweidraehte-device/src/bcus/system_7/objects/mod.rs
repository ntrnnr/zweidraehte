//! Interface object container for System 7 devices.
//!
//! Five base objects at fixed indexes (2705h mask doc §6.1; the same
//! layout the ETS master data assumes for `MV-0705`):
//!
//! - Index 0: Device Object (Type 0)
//! - Index 1: Address Table Object (Type 1)
//! - Index 2: Association Table Object (Type 2)
//! - Index 3: Application Program Object (Type 3)
//! - Index 4: Application Program 2 Object (Type 4)
//!
//! No Group Object Table object — System 7 has none — and augments can
//! contribute additional objects at indexes 5+, same as on System B.
//!
//! The dispatch below mirrors `SystemBObjects`' (`bcus/system_b/objects`)
//! semantics: container-served `PID_IO_LIST`, augment interception before
//! the base objects, per-property access-policy checks, and dirty
//! marking for persistent writes. A shared roster-parameterized container
//! would remove the duplication; see SESSION.md.

mod device;
mod program;
mod table_object;

pub use device::System7DeviceObject;
pub use program::{System7ApplicationProgramObject, System7Program2Object};
pub use table_object::System7TableObject;

use core::cell::RefCell;

use crate::{
    HasPersistence, HasSecurityMode, StackDefinition, StackState,
    context::layer::LayerContext,
    device_model::DeviceModelNotifier,
    ets::DeviceDescriptor,
    objects::interface::{
        AddressTableSpec, AssociationTableSpec, FullPropertyReadRequest, FullPropertyWriteRequest,
        FunctionPropertyRequest, FunctionPropertyResult, HasDeviceObject, HasRoutingCount, InterfaceObject,
        PropertyAccess, PropertyDescriptionResponse, PropertyDescriptor, PropertyError, PropertyLookup,
        PropertyServiceHandler, WriteResponse, pid,
    },
    objects::tables::{
        HasAddressTable, HasApplication, HasAssociationTable, HasLoadStateMachine, HasPeiApplication,
        HasRunStateMachine,
    },
    service::{Augment, ServiceCtx},
};
use zweidraehte_proto::access::AccessContext;
use zweidraehte_proto::dpt::{
    DeviceControl, InterfaceObjectType, PDT_Generic05, PDT_UnsignedChar, PDT_UnsignedInt, ProgrammingMode, RoutingCount,
};
use zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode;

/// The 5 base interface object types present in every System 7 device.
static BASE_IO_TYPES: [InterfaceObjectType; 5] = [
    InterfaceObjectType::Device,
    InterfaceObjectType::AddressTable,
    InterfaceObjectType::AssociationTable,
    InterfaceObjectType::ApplicationProgram,
    InterfaceObjectType::InterfaceProgram,
];

/// Interface objects for System 7 devices.
///
/// Type parameters mirror [`SystemBObjects`](crate::bcus::system_b::SystemBObjects):
/// the tables/applications by their concrete types, `Aug` as the borrowed
/// augment registry.
pub struct System7Objects<'a, D, ADT, AST, APP, APP2, Aug: Augment<D> = ()>
where
    D: StackDefinition,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    APP2: HasLoadStateMachine + HasRunStateMachine,
{
    state: &'a D::State,
    lctx: &'a LayerContext<D>,
    device: RefCell<System7DeviceObject<'a, D::State>>,
    address_table: RefCell<System7TableObject<'a, ADT, AddressTableSpec>>,
    association_table: RefCell<System7TableObject<'a, AST, AssociationTableSpec>>,
    application_program: RefCell<System7ApplicationProgramObject<'a, APP>>,
    application_program_2: RefCell<System7Program2Object<'a, APP2>>,
    augments: &'a Aug,
}

impl<'a, D, ADT, AST, APP, APP2, Aug> System7Objects<'a, D, ADT, AST, APP, APP2, Aug>
where
    D: StackDefinition,
    D::State: StackState + DeviceModelNotifier,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    APP2: HasLoadStateMachine + HasRunStateMachine,
    Aug: Augment<D>,
{
    /// Number of base interface objects (Device, ADT, AST, APP, APP2).
    pub const BASE_OBJECT_COUNT: u16 = 5;

    /// Create a new interface objects container.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: &'a D::State,
        lctx: &'a LayerContext<D>,
        device: &DeviceDescriptor,
        adt: &'a RefCell<ADT>,
        ast: &'a RefCell<AST>,
        app: &'a RefCell<APP>,
        app2: &'a RefCell<APP2>,
        program_version: [u8; 5],
        program2_version: [u8; 5],
        pei_type: u8,
        routing_count: u8,
        augments: &'a Aug,
    ) -> Self {
        crate::service::debug_assert_no_duplicate_object_types::<D, _>(&BASE_IO_TYPES, augments);
        let mut device = System7DeviceObject::from_descriptor(state, device);
        device.routing_count = RoutingCount::from(routing_count);
        Self {
            state,
            lctx,
            device: RefCell::new(device),
            address_table: RefCell::new(System7TableObject::new(adt)),
            association_table: RefCell::new(System7TableObject::new(ast)),
            application_program: RefCell::new(System7ApplicationProgramObject::with_info(
                app,
                PDT_Generic05::with_value(program_version),
                PDT_UnsignedChar::with_value(pei_type),
                state,
            )),
            application_program_2: RefCell::new(System7Program2Object::with_info(
                app2,
                PDT_Generic05::with_value(program2_version),
                PDT_UnsignedChar::default(),
                state,
            )),
            augments,
        }
    }

    /// Get the borrowed augment registry.
    pub fn augments(&self) -> &'a Aug {
        self.augments
    }

    fn total_object_count(&self) -> u16 {
        Self::BASE_OBJECT_COUNT + self.augments.additional_object_count()
    }

    fn io_list_len(&self) -> u16 {
        BASE_IO_TYPES.len() as u16 + self.augments.additional_object_count()
    }

    fn io_list_descriptor(&self) -> PropertyDescriptor {
        use zweidraehte_proto::access::AccessPolicy;
        PropertyDescriptor::array::<PDT_UnsignedInt>(
            pid::device::IO_LIST,
            self.io_list_len(),
            PropertyAccess::ReadOnly,
            15,
            0,
            AccessPolicy::READ_OPEN_WRITE_TOOL,
        )
    }

    fn read_io_list(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        let total = self.io_list_len() as usize;

        if start_idx == 0 {
            if buf.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            buf[..2].copy_from_slice(&(total as u16).to_be_bytes());
            return Ok(2);
        }

        let start = (start_idx - 1) as usize;
        if start >= total {
            return Err(PropertyError::InvalidStartIndex);
        }

        let end = (start + count as usize).min(total);
        let needed = (end - start) * 2;
        if buf.len() < needed {
            return Err(PropertyError::BufferTooSmall);
        }

        let base_len = BASE_IO_TYPES.len();
        for i in start..end {
            let ot = if i < base_len {
                BASE_IO_TYPES[i]
            } else {
                self.augments
                    .additional_object_type_at((i - base_len) as u16)
                    .expect("augment additional_object_count/type_at mismatch")
            };
            let val: u16 = ot.into();
            let offset = (i - start) * 2;
            buf[offset..offset + 2].copy_from_slice(&val.to_be_bytes());
        }

        Ok(needed)
    }

    fn get_descriptor(&self, obj_idx: u16, prop_id: u16) -> Option<PropertyDescriptor> {
        if obj_idx == 0 && prop_id == pid::device::IO_LIST {
            return Some(self.io_list_descriptor());
        }

        match obj_idx {
            0 => self.device.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            1 => self.address_table.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            2 => self.association_table.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            3 => self.application_program.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            4 => self.application_program_2.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            _ => {
                let obj_type = self.object_type_for(obj_idx)?;
                self.augments.property_descriptor(obj_type, prop_id)
            }
        }
    }

    fn base_property_count(&self, object_idx: u16) -> u16 {
        match object_idx {
            0 => self.device.borrow().property_count(),
            1 => self.address_table.borrow().property_count(),
            2 => self.association_table.borrow().property_count(),
            3 => self.application_program.borrow().property_count(),
            4 => self.application_program_2.borrow().property_count(),
            _ => 0,
        }
    }

    fn object_type_for(&self, object_idx: u16) -> Option<InterfaceObjectType> {
        match object_idx {
            i if (i as usize) < BASE_IO_TYPES.len() => Some(BASE_IO_TYPES[i as usize]),
            _ => self.augments.additional_object_type_at(object_idx - Self::BASE_OBJECT_COUNT),
        }
    }

    fn is_augment_object(&self, object_idx: u16) -> bool {
        object_idx >= Self::BASE_OBJECT_COUNT && object_idx < self.total_object_count()
    }

    fn enforce_secure_access_policy(&self) -> bool {
        self.state.security_mode_enabled()
    }

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
// PropertyServiceHandler
// ============================================================================

impl<'a, D, ADT, AST, APP, APP2, Aug: Augment<D>> PropertyServiceHandler
    for System7Objects<'a, D, ADT, AST, APP, APP2, Aug>
where
    D: StackDefinition,
    D::State: StackState + HasPersistence + DeviceModelNotifier,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    APP2: HasLoadStateMachine + HasRunStateMachine,
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

        if prop_id != 0 {
            if object_idx == 0 && prop_id == pid::device::IO_LIST {
                return Ok(PropertyDescriptionResponse::from_descriptor(object_idx, 0, &self.io_list_descriptor()));
            }

            if let Some(result) = self.augments.property_description_read(
                &ServiceCtx::new(self.state, self.lctx, AccessContext::default()),
                obj_type,
                object_idx,
                PropertyLookup::ByPid(prop_id),
            ) {
                return result;
            }

            if self.is_augment_object(object_idx) {
                return Err(PropertyError::InvalidPropertyId);
            }
        }

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

        let base_result = match object_idx {
            0 => self.device.borrow().property_description(object_idx, prop_id, prop_idx),
            1 => self.address_table.borrow().property_description(object_idx, prop_id, prop_idx),
            2 => self.association_table.borrow().property_description(object_idx, prop_id, prop_idx),
            3 => self.application_program.borrow().property_description(object_idx, prop_id, prop_idx),
            4 => self.application_program_2.borrow().property_description(object_idx, prop_id, prop_idx),
            _ => unreachable!("augment objects handled above"),
        };

        if base_result.is_ok() || prop_id != 0 {
            return base_result;
        }

        // Index scan (prop_id == 0): base ran out of properties.
        if object_idx == 0 {
            let base_count = self.base_property_count(object_idx);
            if prop_idx == base_count {
                return Ok(PropertyDescriptionResponse::from_descriptor(
                    object_idx,
                    prop_idx,
                    &self.io_list_descriptor(),
                ));
            }

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

    fn property_description_visible(&self, object_idx: u16, pid: u16, ctx: &AccessContext) -> bool {
        self.check_access(object_idx, pid, ctx, PropertyDescriptor::can_read_secure)
            || self.check_access(object_idx, pid, ctx, PropertyDescriptor::can_write_secure)
            || self.check_access(object_idx, pid, ctx, PropertyDescriptor::can_function_write_secure)
    }

    fn property_value_read(&self, req: &FullPropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        let obj_type = self.object_type_for(req.object_idx).ok_or(PropertyError::InvalidObjectIndex)?;

        if !self.check_access(req.object_idx, req.pid, &req.ctx, PropertyDescriptor::can_read_secure) {
            return Err(PropertyError::AccessDenied);
        }

        if let Some(result) =
            self.augments.property_value_read(&ServiceCtx::new(self.state, self.lctx, req.ctx), obj_type, req, buf)
        {
            return result;
        }

        if self.is_augment_object(req.object_idx) {
            return Err(PropertyError::InvalidPropertyId);
        }

        if req.object_idx == 0 && req.pid == pid::device::IO_LIST {
            return self.read_io_list(req.start_idx, req.count, buf);
        }

        let prop_req = req.property_request();
        match req.object_idx {
            0 => self.device.borrow().read_property(prop_req, buf),
            1 => self.address_table.borrow().read_property(prop_req, buf),
            2 => self.association_table.borrow().read_property(prop_req, buf),
            3 => self.application_program.borrow().read_property(prop_req, buf),
            4 => self.application_program_2.borrow().read_property(prop_req, buf),
            _ => unreachable!("augment objects handled above"),
        }
    }

    fn property_value_write(&self, req: &FullPropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        let obj_type = self.object_type_for(req.object_idx).ok_or(PropertyError::InvalidObjectIndex)?;

        if let Some(desc) = self.get_descriptor(req.object_idx, req.pid) {
            if matches!(desc.access, PropertyAccess::ReadOnly) {
                return Err(PropertyError::WriteNotAllowed);
            }
            if !desc.can_write_secure(&req.ctx, self.enforce_secure_access_policy()) {
                if req.ctx.source_addr != 0 {
                    self.state.log_access_denied(req.ctx.source_addr);
                }
                return Err(PropertyError::AccessDenied);
            }

            if req.start_idx > 0 && desc.max_elements > 0 {
                if req.count == 0 {
                    return Err(PropertyError::InvalidStartIndex);
                }
                if req.start_idx + req.count - 1 > desc.max_elements {
                    return Err(PropertyError::InvalidStartIndex);
                }
            }
        }

        if let Some(result) =
            self.augments.property_value_write(&ServiceCtx::new(self.state, self.lctx, req.ctx), obj_type, req)
        {
            if result.is_ok() {
                self.state.mark_dirty();
            }
            return result;
        }

        if self.is_augment_object(req.object_idx) {
            return Err(PropertyError::InvalidPropertyId);
        }

        let prop_req = req.property_request();
        let result = match req.object_idx {
            0 => self.device.borrow_mut().write_property(prop_req),
            1 => self.address_table.borrow_mut().write_property(prop_req),
            2 => self.association_table.borrow_mut().write_property(prop_req),
            3 => self.application_program.borrow_mut().write_property(prop_req),
            4 => self.application_program_2.borrow_mut().write_property(prop_req),
            _ => unreachable!("augment objects handled above"),
        };

        // Skip persistence for volatile runtime-control properties.
        if result.is_ok() {
            let volatile = matches!(
                (req.object_idx, req.pid),
                (0, pid::DEVICE_CONTROL)
                    | (0, pid::device::PROGMODE)
                    | (3, pid::RUN_STATE_CONTROL)
                    | (4, pid::RUN_STATE_CONTROL)
            );
            if !volatile {
                self.state.mark_dirty();
            }
        }

        result
    }

    fn function_property_command(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        if !self.check_access(req.object_idx, req.prop_id, &req.ctx, PropertyDescriptor::can_function_write_secure) {
            let service_info = req.service_data.get(1).copied().unwrap_or(0);
            return FunctionPropertyResult::with_code(PropertyReturnCode::AccessDenied, &[service_info]);
        }

        if let Some(obj_type) = self.object_type_for(req.object_idx) {
            if let Some(result) =
                self.augments.function_property_command(&ServiceCtx::new(self.state, self.lctx, req.ctx), obj_type, req)
            {
                return result;
            }
        }

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
                if self.property_value_write(&write_req).is_err() {
                    return FunctionPropertyResult::not_supported();
                }
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
        if !self.check_access(req.object_idx, req.prop_id, &req.ctx, PropertyDescriptor::can_function_read_secure) {
            let service_info = req.service_data.get(1).copied().unwrap_or(0);
            return FunctionPropertyResult::with_code(PropertyReturnCode::AccessDenied, &[service_info]);
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
// HasDeviceObject
// ============================================================================

impl<'a, D, ADT, AST, APP, APP2, Aug: Augment<D>> HasDeviceObject for System7Objects<'a, D, ADT, AST, APP, APP2, Aug>
where
    D: StackDefinition,
    D::State: StackState + DeviceModelNotifier + HasRoutingCount,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    APP2: HasLoadStateMachine + HasRunStateMachine,
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
        self.state.set_routing_count(value.value());
    }
}

// ============================================================================
// Helpers and aliases
// ============================================================================

/// [`System7Objects`] with its table/application types projected from the
/// device state's accessor traits.
pub type DefaultSystem7InterfaceObjects<'a, D, A = ()> = System7Objects<
    'a,
    D,
    <<D as StackDefinition>::State as HasAddressTable>::ADT,
    <<D as StackDefinition>::State as HasAssociationTable>::AST,
    <<D as StackDefinition>::State as HasApplication>::APP,
    <<D as StackDefinition>::State as HasPeiApplication>::PEI,
    A,
>;

/// [`DefaultSystem7InterfaceObjects`] with the augment type from the
/// stack definition — the shape `StackDefinition::InterfaceObjects`
/// wants.
pub type System7InterfaceObjectsFor<'a, D> =
    DefaultSystem7InterfaceObjects<'a, D, <D as StackDefinition>::Augments<'a>>;

/// Create the standard System 7 interface object container from a
/// [`System7DeviceState`](super::System7DeviceState)-shaped state.
pub fn create_system_7_objects<'a, D, Aug>(
    state: &'a D::State,
    lctx: &'a LayerContext<D>,
    augments: &'a Aug,
) -> DefaultSystem7InterfaceObjects<'a, D, Aug>
where
    D: StackDefinition,
    D::State: StackState
        + DeviceModelNotifier
        + HasAddressTable
        + HasAssociationTable
        + HasApplication
        + HasPeiApplication
        + HasRoutingCount,
    Aug: Augment<D>,
{
    System7Objects::new(
        state,
        lctx,
        D::DEVICE,
        state.adt(),
        state.ast(),
        state.app(),
        state.pei(),
        [0; 5],
        [0; 5],
        D::DEVICE.pei_type,
        state.routing_count(),
        augments,
    )
}
