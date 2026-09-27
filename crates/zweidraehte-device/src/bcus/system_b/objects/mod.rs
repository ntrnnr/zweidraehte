//! Interface objects for System B devices.
//!
//! System B's six base objects sit at fixed indexes, which ETS addresses
//! without checking their type (03/05/03 §3.9.3.3):
//!
//! - Index 0: Device Object
//! - Index 1: Address Table Object
//! - Index 2: Association Table Object
//! - Index 3: Group Object Table Object
//! - Index 4: Application Program Object
//! - Index 5: PEI Program Object (Application Program 2)
//!
//! Augments contribute further objects from index 6 — the KNXnet/IP
//! Parameter Object on 57B0h, the RF Medium Object on 27B0h, the Security
//! Interface Object on secure devices. The dispatch across both lives in
//! the family-neutral [`ObjectDispatcher`]; this module supplies only
//! [`SystemBBaseObjects`].

use core::cell::{Cell, RefCell};

use crate::{
    StackState,
    device_model::DeviceModelNotifier,
    objects::interface::{
        AddressTableObject, ApplicationProgramObject, AssociationTableObject, BaseObjects, DeviceObject,
        GroupObjectTableObject, InterfaceObject, ObjectDispatcher, PeiProgramObject, PropertyDescriptionResponse,
        PropertyDescriptor, PropertyError, PropertyReadRequest, PropertyWriteRequest, WriteResponse,
    },
    objects::tables::{HasLoadStateMachine, HasRunStateMachine},
};
use zweidraehte_proto::dpt::{DeviceControl, InterfaceObjectType, RoutingCount};

use crate::StackDefinition;
use crate::context::layer::LayerContext;
use crate::objects::interface::HasRoutingCount;
use crate::objects::tables::{
    HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasPeiApplication,
};
use crate::service::Augment;
use zweidraehte_proto::device::DeviceDescriptor;

// ============================================================================
// SystemBBaseObjects
// ============================================================================

/// The six base interface objects of a System B device (indices 0-5).
///
/// # Type Parameters
///
/// - `D`:   Stack definition (its state backs the Device and program objects)
/// - `ADT`: Address table type
/// - `AST`: Association table type
/// - `COT`: Communication object table type
/// - `APP`: Application type (implementing both HasLoadStateMachine and HasRunStateMachine)
/// - `PEI`: PEI application type (implementing both HasLoadStateMachine and HasRunStateMachine)
pub struct SystemBBaseObjects<'a, D, ADT, AST, COT, APP, PEI>
where
    D: StackDefinition,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    device: RefCell<DeviceObject<'a, D::State>>,
    address_table: RefCell<AddressTableObject<'a, ADT>>,
    association_table: RefCell<AssociationTableObject<'a, AST>>,
    group_object_table: RefCell<GroupObjectTableObject<'a, COT>>,
    application_program: RefCell<ApplicationProgramObject<'a, APP, D::State>>,
    pei_program: RefCell<PeiProgramObject<'a, PEI, D::State>>,
}

impl<'a, D, ADT, AST, COT, APP, PEI> SystemBBaseObjects<'a, D, ADT, AST, COT, APP, PEI>
where
    D: StackDefinition,
    D::State: StackState + DeviceModelNotifier,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    /// Build the base objects over the device state's tables.
    // These are the borrowed base objects and their fixed descriptor fields.
    // A parameter object would merely duplicate this struct.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: &'a D::State,
        device: &DeviceDescriptor,
        layout: &super::memory_map::MemoryLayout,
        adt: &'a RefCell<ADT>,
        ast: &'a RefCell<AST>,
        cot: &'a RefCell<COT>,
        app: &'a RefCell<APP>,
        pei: &'a RefCell<PEI>,
        program_version: &'a RefCell<[u8; 5]>,
        pei_type: &'a Cell<u8>,
        pei_program_version: &'a RefCell<[u8; 5]>,
        routing_count: u8,
    ) -> Self {
        let mut device = DeviceObject::from_descriptor(state, device);
        device.routing_count = RoutingCount::from(routing_count);
        Self {
            device: RefCell::new(device),
            address_table: RefCell::new(AddressTableObject::new(adt, layout.adt_address())),
            association_table: RefCell::new(AssociationTableObject::new(ast, layout.ast_address())),
            group_object_table: RefCell::new(GroupObjectTableObject::new(cot, layout.cot_address())),
            application_program: RefCell::new(ApplicationProgramObject::new(
                app,
                layout.app_address(),
                program_version,
                pei_type,
                state,
            )),
            pei_program: RefCell::new(PeiProgramObject::new(
                pei,
                0, // PEI has no memory-mapped address
                pei_program_version,
                state,
            )),
        }
    }
}

impl<'a, D, ADT, AST, COT, APP, PEI> BaseObjects for SystemBBaseObjects<'a, D, ADT, AST, COT, APP, PEI>
where
    D: StackDefinition,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    const TYPES: &'static [InterfaceObjectType] = &[
        InterfaceObjectType::Device,
        InterfaceObjectType::AddressTable,
        InterfaceObjectType::AssociationTable,
        InterfaceObjectType::GroupObjectTable,
        InterfaceObjectType::ApplicationProgram,
        InterfaceObjectType::InterfaceProgram,
    ];

    fn descriptor(&self, object_idx: u16, pid: u16) -> Option<PropertyDescriptor> {
        let by_id = match object_idx {
            0 => self.device.borrow().property_descriptor_by_id(pid),
            1 => self.address_table.borrow().property_descriptor_by_id(pid),
            2 => self.association_table.borrow().property_descriptor_by_id(pid),
            3 => self.group_object_table.borrow().property_descriptor_by_id(pid),
            4 => self.application_program.borrow().property_descriptor_by_id(pid),
            5 => self.pei_program.borrow().property_descriptor_by_id(pid),
            _ => None,
        };
        by_id.map(|(_, descriptor)| descriptor)
    }

    fn property_count(&self, object_idx: u16) -> u16 {
        match object_idx {
            0 => self.device.borrow().property_count(),
            1 => self.address_table.borrow().property_count(),
            2 => self.association_table.borrow().property_count(),
            3 => self.group_object_table.borrow().property_count(),
            4 => self.application_program.borrow().property_count(),
            5 => self.pei_program.borrow().property_count(),
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
            3 => self.group_object_table.borrow().property_description(object_idx, pid, prop_idx),
            4 => self.application_program.borrow().property_description(object_idx, pid, prop_idx),
            5 => self.pei_program.borrow().property_description(object_idx, pid, prop_idx),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn read_property(&self, object_idx: u16, req: PropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        match object_idx {
            0 => self.device.borrow().read_property(req, buf),
            1 => self.address_table.borrow().read_property(req, buf),
            2 => self.association_table.borrow().read_property(req, buf),
            3 => self.group_object_table.borrow().read_property(req, buf),
            4 => self.application_program.borrow().read_property(req, buf),
            5 => self.pei_program.borrow().read_property(req, buf),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn write_property(&self, object_idx: u16, req: PropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        match object_idx {
            0 => self.device.borrow_mut().write_property(req),
            1 => self.address_table.borrow_mut().write_property(req),
            2 => self.association_table.borrow_mut().write_property(req),
            3 => self.group_object_table.borrow_mut().write_property(req),
            4 => self.application_program.borrow_mut().write_property(req),
            5 => self.pei_program.borrow_mut().write_property(req),
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
}

// ============================================================================
// Container aliases and constructor
// ============================================================================

/// The System B interface-object dispatcher: [`SystemBBaseObjects`] at
/// indices 0-5, then the objects `Aug` contributes.
pub type SystemBObjects<'a, D, ADT, AST, COT, APP, PEI, Aug = ()> =
    ObjectDispatcher<'a, D, SystemBBaseObjects<'a, D, ADT, AST, COT, APP, PEI>, Aug>;

/// Type alias for [`SystemBObjects`] that auto-fills the associated type projections.
pub type DefaultSystemBInterfaceObjects<'a, D, A = ()> = SystemBObjects<
    'a,
    D,
    <<D as StackDefinition>::State as HasAddressTable>::ADT,
    <<D as StackDefinition>::State as HasAssociationTable>::AST,
    <<D as StackDefinition>::State as HasCommunicationObjectTable>::COT,
    <<D as StackDefinition>::State as HasApplication>::APP,
    <<D as StackDefinition>::State as HasPeiApplication>::PEI,
    A,
>;

/// Create System B interface objects.
///
/// Use this function in your `StackDefinition::create_interface_objects`
/// implementation. Pass `&()` as `augments` if no augmentation is needed
/// (note: the runner's `D::create_augments` already returns the
/// device-wide augment registry, so the `augments` parameter is the
/// `&'a Self::Augments<'a>` argument forwarded into the helper).
///
/// The IO list (PID_IO_LIST) will contain the 6 base System B object
/// types plus any additional objects the augment registry contributes
/// via [`Augment::additional_object_count`](crate::service::Augment::additional_object_count).
pub fn create_system_b_objects<'a, D, Aug>(
    state: &'a D::State,
    lctx: &'a LayerContext<D>,
    layout: &super::memory_map::MemoryLayout,
    augments: &'a Aug,
) -> DefaultSystemBInterfaceObjects<'a, D, Aug>
where
    D: StackDefinition,
    D::State: StackState
        + DeviceModelNotifier
        + HasAddressTable
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasApplication
        + HasPeiApplication
        + HasRoutingCount,
    <D::State as HasAddressTable>::ADT: HasLoadStateMachine,
    <D::State as HasAssociationTable>::AST: HasLoadStateMachine,
    <D::State as HasCommunicationObjectTable>::COT: HasLoadStateMachine,
    <D::State as HasApplication>::APP: HasLoadStateMachine + HasRunStateMachine,
    <D::State as HasPeiApplication>::PEI: HasLoadStateMachine + HasRunStateMachine,
    Aug: Augment<D>,
{
    let base = SystemBBaseObjects::new(
        state,
        D::DEVICE,
        layout,
        state.adt(),
        state.ast(),
        state.cot(),
        state.app(),
        state.pei(),
        state.program_version(),
        state.program_pei_type(),
        state.pei_program_version(),
        state.routing_count(),
    );
    ObjectDispatcher::new(state, lctx, base, augments)
}

/// Type alias that resolves [`DefaultSystemBInterfaceObjects`] for a
/// [`StackDefinition`]'s `Augments` GAT.
///
/// # Example
///
/// ```rust,ignore
/// type InterfaceObjects<'a> = SystemBInterfaceObjectsFor<'a, Self>;
/// ```
pub type SystemBInterfaceObjectsFor<'a, D> =
    DefaultSystemBInterfaceObjects<'a, D, <D as StackDefinition>::Augments<'a>>;
