//! Builder implementations for System B devices.
//!
//! This module provides [`InterfaceObjectsBuilder`] implementations that
//! create interface objects containers for System B devices.

use crate::{
    IpStackState, StackState,
    memory::{HasAddressTable, HasAssociationTable, HasCommunicationObjectTable},
    objects::interface::InterfaceObjectsBuilder,
    objects::tables::{LoadableTable, RunnableTable},
};

use super::{
    HasApplication, KnxIpInterfaceObjects, SystemBDevice,
    SystemBInterfaceObjects, device_info_from,
};

/// Interface objects builder for base System B devices.
///
/// Creates the 5 mandatory interface objects when the stack initializes.
///
/// # Type Parameters
///
/// - `D`: Device type implementing [`SystemBDevice`]
pub struct SystemBInterfaceObjectsBuilder<D: SystemBDevice> {
    _device: core::marker::PhantomData<D>,
}

impl<D: SystemBDevice> SystemBInterfaceObjectsBuilder<D> {
    /// Create a new builder.
    pub fn new() -> Self {
        Self { _device: core::marker::PhantomData }
    }
}

impl<D: SystemBDevice> Default for SystemBInterfaceObjectsBuilder<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: SystemBDevice> Clone for SystemBInterfaceObjectsBuilder<D> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<D: SystemBDevice> Copy for SystemBInterfaceObjectsBuilder<D> {}

impl<S, Tables, D> InterfaceObjectsBuilder<S, Tables> for SystemBInterfaceObjectsBuilder<D>
where
    D: SystemBDevice,
    S: StackState,
    Tables: HasAddressTable + HasAssociationTable + HasCommunicationObjectTable + HasApplication,
    Tables::ADT: LoadableTable,
    Tables::AST: LoadableTable,
    Tables::COT: LoadableTable,
    Tables::APP: LoadableTable + RunnableTable,
{
    type Objects<'a>
        = SystemBInterfaceObjects<'a, S, Tables::ADT, Tables::AST, Tables::COT, Tables::APP>
    where
        Tables: 'a,
        S: 'a;

    fn build<'a>(self, tables: &'a Tables, state: &'a S) -> Self::Objects<'a>
    where
        Tables: 'a,
        S: 'a,
    {
        use super::SystemBDeviceExt;
        let device_info = device_info_from::<D>();
        let layout = D::memory_layout();
        SystemBInterfaceObjects::new(
            state,
            &device_info,
            &layout,
            tables.adt(),
            tables.ast(),
            tables.cot(),
            tables.app(),
            D::PROGRAM_VERSION,
            D::PEI_TYPE,
        )
    }
}

/// Interface objects builder for KNX/IP devices (57B0).
///
/// Creates 6 interface objects (base 5 + IP Parameter Object).
///
/// # Type Parameters
///
/// - `D`: Device type implementing [`SystemBDevice`] (must have mask version 57B0)
pub struct KnxIpInterfaceObjectsBuilder<D: SystemBDevice> {
    _device: core::marker::PhantomData<D>,
}

impl<D: SystemBDevice> KnxIpInterfaceObjectsBuilder<D> {
    /// Create a new builder.
    pub fn new() -> Self {
        Self { _device: core::marker::PhantomData }
    }
}

impl<D: SystemBDevice> Default for KnxIpInterfaceObjectsBuilder<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: SystemBDevice> Clone for KnxIpInterfaceObjectsBuilder<D> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<D: SystemBDevice> Copy for KnxIpInterfaceObjectsBuilder<D> {}

impl<S, Tables, D> InterfaceObjectsBuilder<S, Tables> for KnxIpInterfaceObjectsBuilder<D>
where
    D: SystemBDevice,
    S: IpStackState,
    Tables: HasAddressTable + HasAssociationTable + HasCommunicationObjectTable + HasApplication,
    Tables::ADT: LoadableTable,
    Tables::AST: LoadableTable,
    Tables::COT: LoadableTable,
    Tables::APP: LoadableTable + RunnableTable,
{
    type Objects<'a>
        = KnxIpInterfaceObjects<'a, S, Tables::ADT, Tables::AST, Tables::COT, Tables::APP>
    where
        Tables: 'a,
        S: 'a;

    fn build<'a>(self, tables: &'a Tables, state: &'a S) -> Self::Objects<'a>
    where
        Tables: 'a,
        S: 'a,
    {
        use super::SystemBDeviceExt;
        let device_info = device_info_from::<D>();
        let layout = D::memory_layout();
        KnxIpInterfaceObjects::new(
            state,
            &device_info,
            &layout,
            tables.adt(),
            tables.ast(),
            tables.cot(),
            tables.app(),
            D::PROGRAM_VERSION,
            D::PEI_TYPE,
        )
    }
}
