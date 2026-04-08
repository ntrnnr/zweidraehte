//! Application layer service extensions.
//!
//! Each extension handles a group of optional APCI codes that can be
//! composed into a device's [`AlExtension`](crate::StackDefinition::AlExtension)
//! type via tuples. The core AL dispatches unrecognized APCIs to the
//! extension chain.
//!
//! # Available Extensions
//!
//! | Extension | Services | When to use |
//! |-----------|----------|-------------|
//! | [`MemoryServiceExtension`] | `A_Memory_Read/Write`, `A_MemoryBit_Write` | Devices with a memory map |
//! | [`UserMemoryServiceExtension`] | `A_UserMemory_Read/Write` | Devices with DMA on user memory |
//! | [`AuthorizationExtension`] | `A_Authorize_Request`, `A_Key_Write` | Devices with access level key management |
//! | [`IndividualAddressSerialNumberExtension`] | `A_IndividualAddressSerialNumber_Read/Write` | Serial-number-based address assignment |
//! | [`AdcExtension`] | `A_ADC_Read` | Legacy ADC stub (conformance) |
//! | [`UserManufacturerInfoExtension`] | `A_UserManufacturerInfo_Read` | Devices with manufacturer info |
//! | [`DomainAddressExtension`] | `A_DomainAddressSerialNumber_*` | KNX/IP and RF devices |
//! | [`PropertyExtValueExtension`] | `A_PropertyExtValue_*`, `A_MemoryExtended_*`, `A_FunctionPropertyExt_*` | AN163 extended services |
//!
//! # Convenience Aliases
//!
//! [`SystemBAlExtensions`] composes the standard set for System B devices.

pub mod traits;
pub mod adc;
pub mod address_serial;
pub mod authorization;
pub mod domain_addr;
pub mod manufacturer;
pub mod memory;
pub mod property_ext;
pub mod user_memory;

pub use traits::{AlExtensionContext, AlServiceExtension};
pub use adc::AdcExtension;
pub use address_serial::IndividualAddressSerialNumberExtension;
pub use authorization::AuthorizationExtension;
pub use domain_addr::DomainAddressExtension;
pub use manufacturer::UserManufacturerInfoExtension;
pub use memory::MemoryServiceExtension;
pub use property_ext::PropertyExtValueExtension;
pub use user_memory::UserMemoryServiceExtension;

/// Standard AL extensions for System B devices.
///
/// Composes the services that are mandatory for System B (mask 07B0h/27B0h):
/// memory access, user memory, authorization, serial number addressing,
/// and ADC. Use this as `type AlExtension = SystemBAlExtensions;` to match
/// the pre-modularization behavior.
///
/// For devices that also need domain address or extended property services,
/// compose further:
/// ```rust,ignore
/// type AlExtension = (SystemBAlExtensions, DomainAddressExtension);
/// ```
pub type SystemBAlExtensions = (
    MemoryServiceExtension,
    (UserMemoryServiceExtension,
    (AuthorizationExtension,
    (IndividualAddressSerialNumberExtension,
    (AdcExtension,
    UserManufacturerInfoExtension)))),
);
