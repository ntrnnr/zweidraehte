//! Context traits for KNX stack layers
//!
//! This module defines trait-based interfaces for accessing stack resources.
//! Layers depend only on the specific context traits they need, making them
//! easier to test and more modular.
//!
//! The storage capabilities of `D::Storage` are not context traits — they
//! live in [`crate::storage`] as [`HasConfigStore`](crate::storage::HasConfigStore),
//! [`HasSeqStore`](crate::storage::HasSeqStore), and
//! [`StorageHooks`](crate::storage::StorageHooks); consumers bound on them
//! directly.

use crate::objects::interface::PropertyServiceHandler;
use crate::objects::tables::{AddressTable, HasLoadStateMachine};
use zweidraehte_proto::messages::buffers::DynBufferManager;

/// Provides access to the buffer manager for allocating and freeing message buffers.
pub trait BufferManagerContext {
    /// Get a reference to the buffer manager.
    fn buffer_manager(&self) -> &DynBufferManager<'static>;
}

/// Provides access to the runtime APDU length limit.
///
/// Only implemented by contexts that bridge to the device state (e.g.,
/// [`StackContext`](crate::context::StackContext)), since the limit is stored
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
pub trait IndividualAddressContext {
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
    type ADT: AddressTable + HasLoadStateMachine;

    /// Get a reference to the address table's RefCell.
    fn address_table(&self) -> &core::cell::RefCell<Self::ADT>;
}

/// Provides the stored RF Domain Address and KNX Serial Number to the KNX-RF
/// link layer.
///
/// Link layers never reach into interface objects directly; they read stack
/// state through context traits like this one (cf. [`IndividualAddressContext`]).
/// The RF data-link layer needs both fields: the 6-octet RF Domain Address (RF
/// Medium Object PID 56) for inbound Domain-Address acceptance and for the
/// block-1 `SN/DoA` field when transmitting domain-addressed frames (AET=1),
/// and the KNX Serial Number for the block-1 field of serial-addressed frames
/// (AET=0, per KNX 03/02/05 §6.1.5.1).
pub trait RfDomainAddressContext {
    /// The device's stored 6-octet RF Domain Address.
    fn rf_domain_address(&self) -> [u8; 6];

    /// The device's 6-octet KNX Serial Number.
    fn knx_serial_number(&self) -> [u8; 6];
}

/// Provides the KNX-RF retransmitter parameters to the link layer.
///
/// This context trait exists on the stack context **only when the device
/// composes the optional retransmitter extension** (i.e. `D::State:
/// HasRfRetransmitter`). The `RetransmitEnabled` KNX-RF link-layer policy
/// requires this bound, so a device cannot select the repeating link layer
/// without also composing the extension — and a non-retransmitter device never
/// names this trait, so the retransmit code path is monomorphized away.
///
/// Backs the §6.1.7 algorithm: a received frame is repeated only while
/// [`rf_retransmit_enabled`](Self::rf_retransmit_enabled) is set and its RF
/// Repetition Counter is `> 0` and `> rf_repeat_counter_limit`.
pub trait RfRetransmitterContext {
    /// Whether the device should currently repeat qualifying RF frames
    /// (`PID_RF_RETRANSMITTER`).
    fn rf_retransmit_enabled(&self) -> bool;

    /// The RF Repetition Counter limit (`PID_RF_REPEAT_COUNTER`).
    fn rf_repeat_counter_limit(&self) -> u8;
}
