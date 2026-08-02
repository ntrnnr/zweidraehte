//! Application layer services.
//!
//! Each service handles a group of APCI codes that can be composed into
//! a device's [`AlExtensions`](crate::StackDefinition::AlExtensions) tuple. The
//! AL dispatches unrecognized APCIs (those not handled by built-in
//! handlers) through the services tuple via
//! [`ApciHandler`](crate::service::ApciHandler).
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
//! [`StandardAlServices`] composes the standard management-server set;
//! [`StandardSecureAlServices`] adds the extended-APCI services the
//! Secure profiles require. BCU families re-export them under their own
//! names (e.g. `SystemBAlServices` in
//! [`bcus::system_b`](crate::bcus::system_b)).

pub mod adc;
pub mod address_serial;
pub mod authorization;
pub mod domain_addr;
pub mod function_property;
pub mod manufacturer;
pub mod memory;
pub mod property_ext;
pub mod rf_domain_addr;
pub mod system_network_parameter;
pub mod user_memory;

pub use adc::AdcService;
pub use address_serial::IndividualAddressSerialNumberService;
pub use authorization::AuthorizationService;
pub use domain_addr::DomainAddressService;
pub use function_property::FunctionPropertyService;
pub use manufacturer::UserManufacturerInfoService;
pub use memory::MemoryService;
pub use property_ext::PropertyExtValueService;
pub use rf_domain_addr::RfDomainAddressService;
pub use system_network_parameter::SystemNetworkParameterService;
pub use user_memory::UserMemoryService;

/// Standard AL services for S-Mode management servers.
///
/// Composes the services commonly used by end devices (System B, System
/// 7, …): memory access, user memory, authorization, serial number
/// addressing, ADC, user-manufacturer info, and function properties.
/// Use this as `type AlExtensions = StandardAlServices;` for the
/// standard management-server behaviour.
///
/// For devices that also need domain address or extended property
/// services, extend the tuple directly:
///
/// ```rust,ignore
/// type AlExtensions = (
///     MemoryService, UserMemoryService, /* … standard set */ ,
///     DomainAddressService,
/// );
/// ```
///
/// Per the KNX spec profile matrix (06 Profiles §4.2), only a subset
/// of these are strictly mandatory on every profile — `AdcService` in
/// particular is legacy BCU1/BCU2 and harmless elsewhere, but devices
/// that target the smallest possible footprint can drop it by spelling
/// out a smaller tuple.
pub type StandardAlServices = (
    MemoryService,
    UserMemoryService,
    AuthorizationService,
    IndividualAddressSerialNumberService,
    SystemNetworkParameterService,
    AdcService,
    UserManufacturerInfoService,
    FunctionPropertyService,
);

/// Standard AL services for KNX Secure / KNX Data Security devices.
///
/// Composes [`StandardAlServices`] with [`PropertyExtValueService`] —
/// the latter covers all extended-APCI management services
/// (`A_PropertyExtValue_*`, `A_PropertyExtDescription_Read`,
/// `A_FunctionPropertyExt*`, `A_MemoryExtended_*`) that spec Vol 6
/// Profiles §9.1.2.3 marks Mandatory for every KNX Secure / KNXnet/IP
/// Security / KNX Data Security profile.
///
/// Use this as `type AlExtensions = StandardSecureAlServices;` in any
/// `StackDefinition` paired with
/// [`SecureDeviceBuilder`](crate::composition::SecureDeviceBuilder).
/// For non-Secure devices continue using [`StandardAlServices`] — the
/// extended services are not mandatory for those profiles and carry a
/// code-size cost that memory-constrained plain devices may prefer to
/// avoid.
pub type StandardSecureAlServices = (
    MemoryService,
    UserMemoryService,
    AuthorizationService,
    IndividualAddressSerialNumberService,
    SystemNetworkParameterService,
    AdcService,
    UserManufacturerInfoService,
    FunctionPropertyService,
    PropertyExtValueService,
);
