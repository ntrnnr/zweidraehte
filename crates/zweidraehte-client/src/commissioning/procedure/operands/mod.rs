//! Concrete management operands shared by preparation and execution.
//!
//! Profile names are resolved here once. Runtime keeps only the selected
//! service and any pointer read that must follow an allocation.

use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence, ResolvedProfile, ResourceFlavour};
use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageLocation, ImageSpace};
use crate::commissioning::procedure::{LoadMachineTarget, OperationExtent};
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::apdu::load_control::LsmMachine;
use zweidraehte_proto::pid;

/// Minimum service required by management authentication. Each operand binds
/// its final service from its own address geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardMemoryService {
    Classic,
    Extended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryService {
    Classic,
    Extended,
    /// Plain memory whose service follows the successfully read pointer base.
    /// Inspection reserves the larger header; execution binds the actual range.
    Standard,
    User,
    Filter,
    Router,
}

impl MemoryService {
    pub const fn overhead(self) -> u16 {
        match self {
            Self::Classic => 3,
            Self::Extended | Self::Standard => 5,
            Self::User | Self::Filter | Self::Router => 4,
        }
    }
    pub const fn max_count(self) -> usize {
        match self {
            Self::Classic => 63,
            Self::Extended | Self::Standard => 255,
            Self::User => 15,
            Self::Filter | Self::Router => 254,
        }
    }
    pub const fn max_address(self) -> u32 {
        match self {
            Self::Classic | Self::Filter | Self::Router => 0xFFFF,
            Self::Extended | Self::Standard => 0xFFFFFF,
            Self::User => 0xFFFFF,
        }
    }

    pub(crate) fn at(self, address: u32, length: u32) -> Self {
        if self == Self::Standard { StandardMemoryService::Classic.for_range(address, length) } else { self }
    }
}

impl StandardMemoryService {
    pub(crate) fn for_range(self, address: u32, length: u32) -> MemoryService {
        if self == Self::Extended
            || address.checked_add(length.saturating_sub(1)).is_none_or(|end| end > u32::from(u16::MAX))
        {
            MemoryService::Extended
        } else {
            MemoryService::Classic
        }
    }

    pub(crate) fn for_pointer(self, width: u32, offset: u32, length: u32) -> MemoryService {
        // A wide pointer can still point into a classic-only device's low
        // memory. Select its service only after a successful deferred read.
        match self.for_range(offset, length) {
            MemoryService::Classic if width > 2 => MemoryService::Standard,
            service => service,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerEncoding {
    Absolute,
    PageOne,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryAddress {
    Fixed(u32),
    Pointer {
        read: Box<ServiceRead>,
        /// Canonical destination whose current physical base the read supplies.
        space: ImageSpace,
        offset: u32,
        encoding: PointerEncoding,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationTarget {
    /// Image-backed source operand; preparation replaces it with a bound
    /// service after the desired image determines its transfer extent.
    #[doc(hidden)]
    ImageMemory(ImageLocation),
    Memory {
        service: MemoryService,
        address: MemoryAddress,
    },
    Property {
        address: PropertyAddress,
        start_element: u16,
    },
    Adc {
        channel: u8,
    },
    Constant(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRead {
    pub target: OperationTarget,
    pub extent: OperationExtent,
}

impl ServiceRead {
    pub fn minimum_apdu(&self) -> Result<u16, CompileError> {
        self.target.minimum_apdu(self.extent)
    }
}

impl OperationTarget {
    pub fn minimum_apdu(&self, extent: OperationExtent) -> Result<u16, CompileError> {
        if extent.property_element_width.is_some() && !matches!(self, Self::Property { .. }) {
            return Err(required_apdu_error("a property window requires a property target"));
        }
        match self {
            Self::ImageMemory(_) => {
                Err(required_apdu_error("image memory operand has not been bound during preparation"))
            }
            Self::Memory { service, address } => {
                if extent.property_elements.is_some() || extent.property_element_width.is_some() {
                    return Err(required_apdu_error("memory transfer carries property elements"));
                }
                let pointer = match address {
                    MemoryAddress::Fixed(address) => {
                        validate_range(*address, extent.byte_length, service.max_address())?;
                        0
                    }
                    MemoryAddress::Pointer { read, space, .. } => {
                        if !matches!(space, ImageSpace::RelativeMemory { .. } | ImageSpace::Pointer { .. }) {
                            return Err(required_apdu_error("pointer operand has no relative destination space"));
                        }
                        read.minimum_apdu()?
                    }
                };
                Ok(pointer.max(if extent.byte_length == 0 { 0 } else { service.overhead() + 1 }))
            }
            Self::Property { address, start_element } => {
                let count = extent
                    .property_elements
                    .filter(|count| *count != 0)
                    .ok_or_else(|| required_apdu_error("property transfer has no element count"))?;
                let width = extent.element_width()?;
                let last = u32::from(*start_element) + u32::from(count) - 1;
                if last > u32::from(address.max_start()) {
                    return Err(required_apdu_error("property element range exceeds the service field"));
                }
                let length = u32::from(address.overhead()) + width;
                u16::try_from(length).map_err(|_| required_apdu_error("property element exceeds the APDU length field"))
            }
            Self::Adc { channel } if *channel <= 0x3F && extent == OperationExtent::bytes(2) => Ok(4),
            Self::Adc { .. } => Err(required_apdu_error("ADC transfer requires a six-bit channel and two bytes")),
            Self::Constant(value) if extent == OperationExtent::bytes(value.len() as u32) => Ok(0),
            Self::Constant(_) => Err(required_apdu_error("constant extent differs from its value")),
        }
    }

    /// The smallest APDU the runtime can execute this transfer over.
    ///
    /// A property addressed by object type falls back to the standard
    /// property service at the located object index when the extended frame
    /// does not fit, so its requirement is the smaller of the two headers. A
    /// property ID or start beyond the standard service's fields leaves only
    /// the extended frame.
    pub(crate) fn fitted_minimum_apdu(&self, extent: OperationExtent) -> Result<u16, CompileError> {
        let prepared = self.minimum_apdu(extent)?;
        let Self::Property { address: PropertyAddress::Extended { property_id, .. }, start_element } = self else {
            return Ok(prepared);
        };

        let indexed = u8::try_from(*property_id).ok().and_then(|property_id| {
            Self::Property {
                address: PropertyAddress::Indexed { object_index: 0, property_id },
                start_element: *start_element,
            }
            .minimum_apdu(extent)
            .ok()
        });
        Ok(indexed.map_or(prepared, |indexed| prepared.min(indexed)))
    }
}

pub(crate) fn validate_range(address: u32, length: u32, maximum: u32) -> Result<(), CompileError> {
    if address > maximum
        || length.checked_sub(1).is_some_and(|last| address.checked_add(last).is_none_or(|end| end > maximum))
    {
        return Err(required_apdu_error("memory range exceeds the service address field"));
    }
    Ok(())
}

pub(crate) fn property_target(
    object: &ObjectSelector,
    property_id: u16,
    start_element: u16,
) -> Result<OperationTarget, CompileError> {
    let address = pure_property_address(object, property_id)?;
    if start_element > address.max_start() {
        return Err(required_apdu_error("property start exceeds the service field"));
    }
    Ok(OperationTarget::Property { address, start_element })
}

pub(crate) fn required_apdu_error(message: impl Into<String>) -> CompileError {
    CompileError::invalid(message)
}

pub(crate) fn programming_mode(
    profile: &ResolvedProfile,
    service: StandardMemoryService,
) -> Result<Option<(ServiceRead, bool)>, CompileError> {
    let Some(resource) = profile.resource("ProgrammingMode").map_err(|error| required_apdu_error(error.to_string()))?
    else {
        return Ok(None);
    };
    let legacy = match resource.flavour().map_err(|error| required_apdu_error(error.to_string()))? {
        Some(ResourceFlavour::ProgrammingModeBcu1) => true,
        Some(ResourceFlavour::ProgrammingModeProp) | None => false,
        _ => return Err(required_apdu_error("unsupported programming-mode coding")),
    };
    Ok(Some((resource.read(service).map_err(|error| required_apdu_error(error.to_string()))?, legacy)))
}

mod sizing;
#[cfg(test)]
mod tests;
pub use sizing::required_plaintext_apdu;
mod resolution;
mod wire;
pub(crate) use resolution::load_endpoint;
pub(crate) use wire::FUNCTION_PROPERTY_NOT_SUPPORTED_ERROR;
pub use wire::{PropertyAddress, pure_property_address};
