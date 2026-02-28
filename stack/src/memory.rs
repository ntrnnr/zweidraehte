//! Memory mapping for A_Memory_Read/Write services.
//!
//! This module provides the [`MemoryMap`] trait for defining how memory addresses
//! map to tables and other data regions in a KNX device.
//!
//! # Design
//!
//! The memory map is part of the [`StackDefinition`](crate::StackDefinition) and stored
//! in `Inner`. Users define their own tables struct (`MemoryTables`)
//! that contains whatever tables they need, and implement `MemoryMap` to dispatch
//! reads/writes to the appropriate tables.
//!
//! For group object communication, the stack requires the tables to implement
//! [`HasAddressTable`](crate::objects::tables::HasAddressTable),
//! [`HasAssociationTable`](crate::objects::tables::HasAssociationTable), and
//! [`HasCommunicationObjectTable`](crate::objects::tables::HasCommunicationObjectTable).

use crate::AccessContext;

// ============================================================================
// Memory Map
// ============================================================================

/// Memory access error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
pub trait MemoryMap<Tables> {
    /// Read from memory at absolute address.
    ///
    /// The `ctx` parameter carries the caller's authorization context.
    /// Implementations can use this to restrict access to protected memory regions.
    ///
    /// Returns the number of bytes read, or an error if the address is not accessible
    /// or access is denied due to insufficient authorization.
    fn read(
        &self,
        tables: &Tables,
        address: u16,
        data: &mut [u8],
        ctx: AccessContext,
    ) -> Result<usize, MemoryError>;

    /// Write to memory at absolute address.
    ///
    /// The `ctx` parameter carries the caller's authorization context.
    /// Implementations can use this to restrict access to protected memory regions.
    ///
    /// Returns the number of bytes written, or an error if the address is not
    /// accessible, write-protected, or access is denied due to insufficient authorization.
    fn write(
        &self,
        tables: &Tables,
        address: u16,
        data: &[u8],
        ctx: AccessContext,
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
        _ctx: AccessContext,
    ) -> Result<usize, MemoryError> {
        Err(MemoryError::NotAccessible)
    }

    fn write(
        &self,
        _tables: &T,
        _address: u16,
        _data: &[u8],
        _ctx: AccessContext,
    ) -> Result<usize, MemoryError> {
        Err(MemoryError::NotAccessible)
    }
}
