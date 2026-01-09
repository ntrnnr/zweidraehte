//! Memory mapping for A_Memory_Read/Write services.
//!
//! This module provides the [`MemoryMap`] trait for defining how memory addresses
//! map to tables and other data regions in a KNX device.
//!
//! # Design
//!
//! The memory map is part of the [`StackDefinition`](crate::StackDefinition) and stored
//! in [`Inner`](crate::Inner). Users define their own tables struct (`MemoryTables`)
//! that contains whatever tables they need, and implement `MemoryMap` to dispatch
//! reads/writes to the appropriate tables.
//!
//! For group object communication, the stack requires the tables to implement
//! [`HasAddressTable`], [`HasAssociationTable`], and [`HasCommunicationObjectTable`].
//!
//! # Example
//!
//! ```rust,ignore
//! use zweidraehte::memory::{MemoryMap, MemoryError, HasAddressTable, HasAssociationTable, HasCommunicationObjectTable};
//! use zweidraehte::objects::tables::{AddressTable, AssociationTable, CommunicationObjectTable, TableMemory};
//! use core::cell::RefCell;
//!
//! // Define your tables container
//! pub struct MyTables {
//!     pub adt: RefCell<MyAddressTable>,
//!     pub ast: RefCell<MyAssociationTable>,
//!     pub cot: RefCell<MyCommunicationObjectTable>,
//!     pub custom: RefCell<MyCustomTable>,  // Additional custom table
//! }
//!
//! // Implement the accessor traits for group object communication
//! impl HasAddressTable for MyTables {
//!     type ADT = MyAddressTable;
//!     fn adt(&self) -> &RefCell<Self::ADT> { &self.adt }
//! }
//!
//! impl HasAssociationTable for MyTables {
//!     type AST = MyAssociationTable;
//!     fn ast(&self) -> &RefCell<Self::AST> { &self.ast }
//! }
//!
//! impl HasCommunicationObjectTable for MyTables {
//!     type COT = MyCommunicationObjectTable;
//!     fn cot(&self) -> &RefCell<Self::COT> { &self.cot }
//! }
//!
//! // Define your memory map
//! pub struct MyMemoryMap;
//!
//! impl Default for MyMemoryMap {
//!     fn default() -> Self { Self }
//! }
//!
//! impl MemoryMap<MyTables> for MyMemoryMap {
//!     fn read(&self, tables: &MyTables, address: u16, data: &mut [u8]) -> Result<usize, MemoryError> {
//!         // Check ADT region (0x0200 - 0x02FF)
//!         if address >= 0x0200 && address < 0x0300 {
//!             let offset = (address - 0x0200) as usize;
//!             tables.adt.borrow().read(offset, data);
//!             return Ok(data.len());
//!         }
//!
//!         // Check custom table region (0x1000 - 0x1FFF)
//!         if address >= 0x1000 && address < 0x2000 {
//!             let offset = (address - 0x1000) as usize;
//!             tables.custom.borrow().read(offset, data);
//!             return Ok(data.len());
//!         }
//!
//!         Err(MemoryError::NotAccessible)
//!     }
//!
//!     fn write(&self, tables: &MyTables, address: u16, data: &[u8]) -> Result<usize, MemoryError> {
//!         // Similar dispatch logic for writes
//!         Err(MemoryError::NotAccessible)
//!     }
//! }
//! ```

use core::cell::RefCell;

use crate::objects::tables::{AddressTable, AssociationTable, CommunicationObjectTable};

// ============================================================================
// Table Accessor Traits
// ============================================================================

/// Trait for types that contain an Address Table.
///
/// Implement this trait on your `MemoryTables` type to enable group object
/// communication in the stack.
pub trait HasAddressTable {
    /// The concrete address table type
    type ADT: AddressTable;
    /// Get a reference to the address table
    fn adt(&self) -> &RefCell<Self::ADT>;
}

/// Trait for types that contain an Association Table.
///
/// Implement this trait on your `MemoryTables` type to enable group object
/// communication in the stack.
pub trait HasAssociationTable {
    /// The concrete association table type
    type AST: AssociationTable;
    /// Get a reference to the association table
    fn ast(&self) -> &RefCell<Self::AST>;
}

/// Trait for types that contain a Communication Object Table.
///
/// Implement this trait on your `MemoryTables` type to enable group object
/// communication in the stack.
pub trait HasCommunicationObjectTable {
    /// The concrete communication object table type
    type COT: CommunicationObjectTable;
    /// Get a reference to the communication object table
    fn cot(&self) -> &RefCell<Self::COT>;
}

// ============================================================================
// Memory Map
// ============================================================================

/// Memory access error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    /// Address is not mapped / accessible
    NotAccessible,
    /// Address is read-only (for writes)
    WriteProtected,
    /// Access denied due to insufficient authorization level
    AccessDenied,
}

/// Trait for memory maps that dispatch reads/writes to tables.
///
/// Implementations define how memory addresses map to tables and other data regions.
/// The `Tables` type parameter is user-defined and can contain any set of tables
/// the device needs.
///
/// The trait receives a reference to the user's tables container, allowing full
/// flexibility in the dispatch logic.
pub trait MemoryMap<Tables>: Default {
    /// Read from memory at absolute address.
    ///
    /// The `access_level` parameter indicates the current authorization level (0-3 typically).
    /// Level 0 is maximum access, level 3 is minimum access.
    /// Implementations can use this to restrict access to protected memory regions.
    ///
    /// Returns the number of bytes read, or an error if the address is not accessible
    /// or access is denied due to insufficient authorization.
    fn read(
        &self,
        tables: &Tables,
        address: u16,
        data: &mut [u8],
        access_level: u8,
    ) -> Result<usize, MemoryError>;

    /// Write to memory at absolute address.
    ///
    /// The `access_level` parameter indicates the current authorization level (0-3 typically).
    /// Level 0 is maximum access, level 3 is minimum access.
    /// Implementations can use this to restrict access to protected memory regions.
    ///
    /// Returns the number of bytes written, or an error if the address is not
    /// accessible, write-protected, or access is denied due to insufficient authorization.
    fn write(
        &self,
        tables: &Tables,
        address: u16,
        data: &[u8],
        access_level: u8,
    ) -> Result<usize, MemoryError>;
}

// ============================================================================
// No Memory Map
// ============================================================================

/// A memory map with no mapped regions.
///
/// This is the default memory map that rejects all memory access.
/// Use this when you don't need memory services.
///
/// This implementation works with any `Tables` type since it doesn't
/// actually access any tables.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoMemoryMap;

impl<T> MemoryMap<T> for NoMemoryMap {
    fn read(
        &self,
        _tables: &T,
        _address: u16,
        _data: &mut [u8],
        _access_level: u8,
    ) -> Result<usize, MemoryError> {
        Err(MemoryError::NotAccessible)
    }

    fn write(
        &self,
        _tables: &T,
        _address: u16,
        _data: &[u8],
        _access_level: u8,
    ) -> Result<usize, MemoryError> {
        Err(MemoryError::NotAccessible)
    }
}
