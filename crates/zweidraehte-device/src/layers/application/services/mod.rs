//! Application layer services.
//!
//! Each service handles a group of APCI codes that can be composed into
//! a device's [`Services`](crate::StackDefinition::Services) tuple. The
//! AL dispatches unrecognized APCIs (those not handled by built-in
//! handlers) through the services tuple.
//!
//! # Available Services
//!
//! | Service | APCIs | When to use |
//! |---------|-------|-------------|
//! | [`MemoryService`] | `A_Memory_Read/Write`, `A_MemoryBit_Write` | Devices with a memory map |
//! | [`UserMemoryService`] | `A_UserMemory_Read/Write` | Devices with DMA on user memory |
//! | [`AuthorizationService`] | `A_Authorize_Request`, `A_Key_Write` | Devices with access level key management |
//! | [`IndividualAddressSerialNumberService`] | `A_IndividualAddressSerialNumber_Read/Write` | Serial-number-based address assignment |
//! | [`AdcService`] | `A_ADC_Read` | Legacy ADC stub (conformance) |
//! | [`UserManufacturerInfoService`] | `A_UserManufacturerInfo_Read` | Devices with manufacturer info |
//! | [`DomainAddressService`] | `A_DomainAddressSerialNumber_*` | KNX/IP and RF devices |
//! | [`PropertyExtValueService`] | `A_PropertyExtValue_*`, `A_MemoryExtended_*`, `A_FunctionPropertyExt_*` | AN163 extended services |
//!
//! # Convenience Aliases
//!
//! [`SystemBAlServices`] composes the standard set for System B devices.

pub mod adc;
pub mod address_serial;
pub mod authorization;
pub mod domain_addr;
pub mod function_property;
pub mod manufacturer;
pub mod memory;
pub mod property_ext;
pub mod service;
pub mod user_memory;

pub use adc::AdcService;
pub use address_serial::IndividualAddressSerialNumberService;
pub use authorization::AuthorizationService;
pub use domain_addr::DomainAddressService;
pub use function_property::FunctionPropertyService;
pub use manufacturer::UserManufacturerInfoService;
pub use memory::MemoryService;
pub use property_ext::PropertyExtValueService;
pub use service::{AlService, AlServiceContext};
pub use user_memory::UserMemoryService;

/// Right-associate a flat list of types into a nested pair structure:
/// `nest!(A, B, C, D)` expands to `(A, (B, (C, D)))`.
///
/// Intended for composing tuple-fold traits like [`AlService`] whose
/// blanket impl for `(A, B)` drives left-to-right dispatch. The base
/// case requires at least two elements — a single-element composition
/// has no meaning in this pattern, so `nest!(A)` is intentionally a
/// compile error rather than silently expanding to a bare `A`.
#[macro_export]
macro_rules! nest {
    ($a:ty, $b:ty $(,)?) => { ($a, $b) };
    ($a:ty, $($rest:ty),+ $(,)?) => { ($a, $crate::nest!($($rest),+)) };
}

/// Standard AL services for System B devices.
///
/// Composes the services commonly used by System B devices (mask
/// 07B0h/27B0h): memory access, user memory, authorization, serial
/// number addressing, ADC, user-manufacturer info, and function
/// properties. Use this as `type Services = SystemBAlServices;` for the
/// pre-modularization behaviour.
///
/// For devices that also need domain address or extended property
/// services, compose further:
///
/// ```rust,ignore
/// type Services = (SystemBAlServices, DomainAddressService);
/// ```
///
/// Per the KNX spec profile matrix (06 Profiles §4.2), only a subset
/// of these are strictly mandatory on every System B profile —
/// `AdcService` in particular is legacy BCU1/BCU2 and harmless on
/// System B, but devices that target the smallest possible footprint
/// can drop it by spelling out a smaller tuple.
pub type SystemBAlServices = nest!(
    MemoryService,
    UserMemoryService,
    AuthorizationService,
    IndividualAddressSerialNumberService,
    AdcService,
    UserManufacturerInfoService,
    FunctionPropertyService,
);
