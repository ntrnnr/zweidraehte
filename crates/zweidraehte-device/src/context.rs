//! Context traits for KNX stack layers
//!
//! This module defines trait-based interfaces for accessing stack resources.
//! Layers depend only on the specific context traits they need, making them
//! easier to test and more modular.

use zweidraehte_proto::messages::buffers::DynBufferManager;
use crate::objects::interface::PropertyServiceHandler;

/// Provides access to the buffer manager for allocating and freeing message buffers.
pub trait BufferManagerContext {
    /// Get a reference to the buffer manager.
    fn buffer_manager(&self) -> &DynBufferManager<'static>;
}

/// Provides access to the runtime APDU length limit.
///
/// Only implemented by contexts that bridge to the device state (e.g.,
/// [`StackContext`](crate::inner::StackContext)), since the limit is stored
/// on [`StackState`](crate::StackState). Link layers use this to detect
/// hardware capabilities and update the stack accordingly.
pub trait ApduLengthContext {
    /// Get the maximum APDU length this device can handle.
    ///
    /// This is the runtime limit based on `StackState::max_apdu_length()`,
    /// which may be lower than the compile-time `StackDefinition::MAX_APDU_LENGTH`.
    /// Link layers should use this to filter/reject oversized incoming frames.
    fn max_apdu_length(&self) -> u16;

    /// Set the maximum APDU length this device can handle.
    ///
    /// Called by link layers after detecting hardware capabilities.
    /// For example, a USB link layer may read the interface's MAX_APDU_LENGTH
    /// property and update the stack state accordingly.
    ///
    /// Values exceeding the compile-time `StackDefinition::MAX_APDU_LENGTH`
    /// will be clamped to that limit.
    fn set_max_apdu_length(&self, length: u16);
}

/// Combined context for link layers that need both buffer allocation and APDU
/// length management. Used as a trait object (`&dyn LinkLayerBufferContext`)
/// by link layers like TPUART and USB.
pub trait LinkLayerBufferContext: BufferManagerContext + ApduLengthContext {}
impl<T: BufferManagerContext + ApduLengthContext> LinkLayerBufferContext for T {}

/// Provides access to the device's property service handler.
///
/// This allows link layers that implement connection-oriented management
/// protocols (e.g., KNX/IP Device Management) to read and write interface
/// object properties on behalf of remote clients like ETS.
pub trait PropertyServiceContext {
    /// Get a reference to the property service handler.
    fn property_handler(&self) -> &dyn PropertyServiceHandler;
}

/// Provides the TP1 max retry count for DLL retry configuration.
///
/// Used by the TPUART link layer at init time to configure the chip's
/// retry behavior from PID_MAX_RETRY_COUNT (PID 52).
pub trait MaxRetryCountContext {
    /// Get the max retry count byte (busy_retry bits 6-4, nak_retry bits 2-0).
    fn max_retry_count(&self) -> u8;
}

/// Provides the KNX primary individual address.
pub trait KnxIndividualAddressContext {
    /// The device's primary individual address.
    fn individual_address(&self) -> zweidraehte_proto::address::IndividualAddress;
}

/// Provides access to the device's address table for ACK decisions.
///
/// Used by the TPUART link layer's [`AutoAddressChecker`](crate::layers::linklayers::tpuart::AutoAddressChecker)
/// to construct a [`DeviceAddressChecker`](crate::layers::linklayers::tpuart::DeviceAddressChecker)
/// at link layer build time, when the address table is at a stable memory
/// location inside [`StackResources`](crate::StackResources).
pub trait AddressTableContext {
    /// The concrete address table type.
    type ADT: crate::objects::tables::AddressTable + crate::objects::tables::HasLoadStateMachine;

    /// Get a reference to the address table's RefCell.
    fn address_table(&self) -> &core::cell::RefCell<Self::ADT>;
}

/// Provides access to publish communication object events to user code.
pub trait EventPublisherContext<Index> {
    /// Publish a communication object event.
    fn publish_event(&self, index: Index, event: crate::objects::comm::ComObjectEvent);
}

/// Provides access to send restart requests to user code.
pub trait RestartPublisherContext {
    /// Try sending a restart request. Returns true if sent successfully.
    fn try_send_restart_request(&self, request: crate::restart::RestartRequest) -> bool;
}

/// Provides access to the inter-layer message outbox.
pub trait OutboxContext {
    /// Get a reference to the shared outbox.
    fn outbox(&self) -> &core::cell::RefCell<crate::router::Outbox>;
}
