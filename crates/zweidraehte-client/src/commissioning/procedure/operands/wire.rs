//! Shared wire limits and service address coding.

use super::*;

/// Legacy ETS identity for a function-property service which the target does
/// not implement. Master Data maps this value around optional IP Parameter
/// Object service-family invocations, while the wire response retains the
/// compact `0x02` return code.
pub(crate) const FUNCTION_PROPERTY_NOT_SUPPORTED_ERROR: u32 = 0xC004_2B25;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PropertyAddress {
    Indexed { object_index: u8, property_id: u8 },
    Extended { object_type: InterfaceObjectType, object_instance: u16, property_id: u16 },
}

impl PropertyAddress {
    pub const fn overhead(self) -> u16 {
        match self {
            Self::Indexed { .. } => 5,
            Self::Extended { .. } => 9,
        }
    }
    pub const fn max_count(self) -> usize {
        match self {
            Self::Indexed { .. } => 15,
            Self::Extended { .. } => 255,
        }
    }
    pub const fn max_start(self) -> u16 {
        match self {
            Self::Indexed { .. } => 0xFFF,
            Self::Extended { .. } => u16::MAX,
        }
    }
}

pub fn pure_property_address(object: &ObjectSelector, property_id: u16) -> Result<PropertyAddress, CompileError> {
    match object {
        ObjectSelector::Index { index } => {
            let object_index = u8::try_from(*index).map_err(|_| {
                required_apdu_error(format!("interface-object index {index} exceeds the standard property service"))
            })?;
            let property_id = u8::try_from(property_id).map_err(|_| {
                required_apdu_error(format!("property ID {property_id} exceeds the standard property service"))
            })?;

            Ok(PropertyAddress::Indexed { object_index, property_id })
        }
        ObjectSelector::Type { object_type, occurrence } => {
            let object_instance = wire_object_instance(*occurrence).map_err(required_apdu_error)?;
            if property_id > 0x0FFF {
                return Err(required_apdu_error(format!(
                    "property ID {property_id} exceeds the extended property's 12-bit field"
                )));
            }

            Ok(PropertyAddress::Extended {
                object_type: InterfaceObjectType::from(*object_type),
                object_instance,
                property_id,
            })
        }
    }
}

pub fn wire_object_instance(occurrence: Occurrence) -> Result<u16, String> {
    let zero_based = match occurrence {
        Occurrence::Absent | Occurrence::Zero => 0,
        Occurrence::Positive { value } => value.get(),
    };
    let instance = zero_based
        .checked_add(1)
        .ok_or_else(|| "object occurrence cannot be converted to a one-based instance".to_owned())?;

    if instance > 0x0FFF {
        return Err(format!("object instance {instance} exceeds the extended service's 12-bit field"));
    }

    Ok(instance)
}
