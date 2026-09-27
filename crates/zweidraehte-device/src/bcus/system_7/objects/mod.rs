//! Interface objects for System 7 devices.
//!
//! Five base objects at fixed indexes (2705h mask doc §6.1; the same
//! layout the ETS master data assumes for `MV-0705`):
//!
//! - Index 0: Device Object (Type 0)
//! - Index 1: Address Table Object (Type 1)
//! - Index 2: Association Table Object (Type 2)
//! - Index 3: Application Program Object (Type 3)
//! - Index 4: optional Interface Program Object (Type 4)
//!
//! This composition omits the optional Group Object Table object. Augments
//! can contribute additional objects at indexes 5+, same as on System B;
//! the dispatch across both lives in the family-neutral
//! [`ObjectDispatcher`], and this module supplies only
//! [`System7BaseObjects`].

mod device;
mod program;
mod table_object;

pub use device::System7DeviceObject;
pub use program::{System7ApplicationProgramObject, System7Program2Object};
pub use table_object::System7TableObject;

use core::cell::{Cell, RefCell};

use crate::{
    StackDefinition, StackState,
    context::layer::LayerContext,
    device_model::DeviceModelNotifier,
    objects::interface::{
        AddressTableSpec, AssociationTableSpec, BaseObjects, HasRoutingCount, InterfaceObject, ObjectDispatcher,
        PropertyDescriptionResponse, PropertyDescriptor, PropertyError, PropertyReadRequest, PropertyWriteRequest,
        WriteResponse, pid,
    },
    objects::tables::{
        HasAddressTable, HasApplication, HasAssociationTable, HasLoadStateMachine, HasPeiApplication,
        HasRunStateMachine,
    },
    service::Augment,
};
use zweidraehte_proto::device::DeviceDescriptor;
use zweidraehte_proto::dpt::{DeviceControl, InterfaceObjectType, RoutingCount};

// ============================================================================
// System7BaseObjects
// ============================================================================

/// The five base interface objects of a System 7 device (indices 0-4).
///
/// Type parameters mirror
/// [`SystemBBaseObjects`](crate::bcus::system_b::SystemBBaseObjects): the
/// tables and applications by their concrete types.
pub struct System7BaseObjects<'a, D, ADT, AST, APP, APP2>
where
    D: StackDefinition,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    APP2: HasLoadStateMachine + HasRunStateMachine,
{
    device: RefCell<System7DeviceObject<'a, D::State>>,
    address_table: RefCell<System7TableObject<'a, ADT, AddressTableSpec>>,
    association_table: RefCell<System7TableObject<'a, AST, AssociationTableSpec>>,
    application_program: RefCell<System7ApplicationProgramObject<'a, APP, D::State>>,
    application_program_2: RefCell<System7Program2Object<'a, APP2, D::State>>,
}

impl<'a, D, ADT, AST, APP, APP2> System7BaseObjects<'a, D, ADT, AST, APP, APP2>
where
    D: StackDefinition,
    D::State: StackState + DeviceModelNotifier,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    APP2: HasLoadStateMachine + HasRunStateMachine,
{
    /// Build the base objects over the device state's tables.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: &'a D::State,
        device: &DeviceDescriptor,
        adt: &'a RefCell<ADT>,
        ast: &'a RefCell<AST>,
        app: &'a RefCell<APP>,
        app2: &'a RefCell<APP2>,
        program_version: &'a RefCell<[u8; 5]>,
        pei_type: &'a Cell<u8>,
        program2_version: &'a RefCell<[u8; 5]>,
        routing_count: u8,
    ) -> Self {
        let mut device = System7DeviceObject::from_descriptor(state, device);
        device.routing_count = RoutingCount::from(routing_count);
        Self {
            device: RefCell::new(device),
            address_table: RefCell::new(System7TableObject::new(adt)),
            association_table: RefCell::new(System7TableObject::new(ast)),
            application_program: RefCell::new(System7ApplicationProgramObject::new(
                app,
                program_version,
                pei_type,
                state,
            )),
            application_program_2: RefCell::new(System7Program2Object::new(app2, program2_version, state)),
        }
    }
}

impl<'a, D, ADT, AST, APP, APP2> BaseObjects for System7BaseObjects<'a, D, ADT, AST, APP, APP2>
where
    D: StackDefinition,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    APP2: HasLoadStateMachine + HasRunStateMachine,
{
    const TYPES: &'static [InterfaceObjectType] = &[
        InterfaceObjectType::Device,
        InterfaceObjectType::AddressTable,
        InterfaceObjectType::AssociationTable,
        InterfaceObjectType::ApplicationProgram,
        InterfaceObjectType::InterfaceProgram,
    ];

    fn descriptor(&self, object_idx: u16, pid: u16) -> Option<PropertyDescriptor> {
        let by_id = match object_idx {
            0 => self.device.borrow().property_descriptor_by_id(pid),
            1 => self.address_table.borrow().property_descriptor_by_id(pid),
            2 => self.association_table.borrow().property_descriptor_by_id(pid),
            3 => self.application_program.borrow().property_descriptor_by_id(pid),
            4 => self.application_program_2.borrow().property_descriptor_by_id(pid),
            _ => None,
        };
        by_id.map(|(_, descriptor)| descriptor)
    }

    fn property_count(&self, object_idx: u16) -> u16 {
        match object_idx {
            0 => self.device.borrow().property_count(),
            1 => self.address_table.borrow().property_count(),
            2 => self.association_table.borrow().property_count(),
            3 => self.application_program.borrow().property_count(),
            4 => self.application_program_2.borrow().property_count(),
            _ => 0,
        }
    }

    fn property_description(
        &self,
        object_idx: u16,
        pid: u16,
        prop_idx: u16,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        match object_idx {
            0 => self.device.borrow().property_description(object_idx, pid, prop_idx),
            1 => self.address_table.borrow().property_description(object_idx, pid, prop_idx),
            2 => self.association_table.borrow().property_description(object_idx, pid, prop_idx),
            3 => self.application_program.borrow().property_description(object_idx, pid, prop_idx),
            4 => self.application_program_2.borrow().property_description(object_idx, pid, prop_idx),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn read_property(&self, object_idx: u16, req: PropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        match object_idx {
            0 => self.device.borrow().read_property(req, buf),
            1 => self.address_table.borrow().read_property(req, buf),
            2 => self.association_table.borrow().read_property(req, buf),
            3 => self.application_program.borrow().read_property(req, buf),
            4 => self.application_program_2.borrow().read_property(req, buf),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn write_property(&self, object_idx: u16, req: PropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        match object_idx {
            0 => self.device.borrow_mut().write_property(req),
            1 => self.address_table.borrow_mut().write_property(req),
            2 => self.association_table.borrow_mut().write_property(req),
            3 => self.application_program.borrow_mut().write_property(req),
            4 => self.application_program_2.borrow_mut().write_property(req),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn device_control(&self) -> DeviceControl {
        self.device.borrow().device_control
    }

    fn set_device_control(&self, value: DeviceControl) {
        self.device.borrow_mut().device_control = value;
    }

    fn routing_count(&self) -> RoutingCount {
        self.device.borrow().routing_count
    }

    fn set_routing_count(&self, value: RoutingCount) {
        self.device.borrow_mut().routing_count = value;
    }

    /// Data Security strengthens the base profile's optional Programming
    /// Mode property from `3/3` to the mandatory `3/2` in Profiles
    /// §9.1.2.6.2. Keyed on the composed Security object, so plain System 7
    /// retains the Annex A.2.3 descriptor.
    fn write_level(&self, object_idx: u16, pid: u16, level: u8, has_security_object: bool) -> u8 {
        if object_idx == 0 && pid == pid::device::PROGMODE && has_security_object { 2 } else { level }
    }
}

// ============================================================================
// Container aliases and constructor
// ============================================================================

/// The System 7 interface-object dispatcher: [`System7BaseObjects`] at
/// indices 0-4, then the objects `Aug` contributes.
pub type System7Objects<'a, D, ADT, AST, APP, APP2, Aug = ()> =
    ObjectDispatcher<'a, D, System7BaseObjects<'a, D, ADT, AST, APP, APP2>, Aug>;

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

/// Create the standard System 7 interface-object dispatcher from a
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
    let base = System7BaseObjects::new(
        state,
        D::DEVICE,
        state.adt(),
        state.ast(),
        state.app(),
        state.pei(),
        state.program_version(),
        state.program_pei_type(),
        state.pei_program_version(),
        state.routing_count(),
    );
    ObjectDispatcher::new(state, lctx, base, augments)
}
