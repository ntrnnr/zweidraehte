//! System B stack definition supertrait.
//!
//! [`SystemBStackDefinition`] extends [`StackDefinition`] with memory layout
//! helpers that are common to all System B devices using [`SystemBMemoryMap`].

use crate::StackDefinition;

use super::memory_map::{MemoryLayout, SystemBMemoryMap};

/// Supertrait for System B devices that use [`SystemBMemoryMap`].
///
/// Provides [`memory_layout()`](Self::memory_layout) and
/// [`memory_map()`](Self::memory_map) as provided methods derived from
/// [`DEVICE`](StackDefinition::DEVICE) and `size_of::<P>()`. Implement
/// with an empty body to get the defaults:
///
/// ```rust,ignore
/// impl SystemBStackDefinition for MyDevice {}
/// ```
///
/// Override [`memory_layout()`](Self::memory_layout) if you need a
/// non-standard base address or custom layout calculation.
pub trait SystemBStackDefinition: StackDefinition<Mem = SystemBMemoryMap> {
    /// Compute the memory layout for this device's tables.
    ///
    /// Derives all table offsets and sizes from
    /// [`DEVICE`](StackDefinition::DEVICE) and `size_of::<P>()`.
    fn memory_layout() -> MemoryLayout {
        MemoryLayout::from_descriptor(
            SystemBMemoryMap::DEFAULT_BASE_ADDRESS,
            Self::DEVICE,
            core::mem::size_of::<Self::P>(),
        )
    }

    /// Compute the memory map for this device.
    ///
    /// Pass to [`zweidraehte_device::new()`](crate::new).
    fn memory_map() -> SystemBMemoryMap {
        SystemBMemoryMap::new(Self::memory_layout())
    }
}
