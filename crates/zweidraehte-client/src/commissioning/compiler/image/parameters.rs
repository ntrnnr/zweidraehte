//! Pack parameter bits while transferring the complete bytes they touch.

use super::CompileError;
use super::{ImageDemand, region_patch};
use crate::commissioning::catalog::rules::product_property_object;
use crate::commissioning::image::{ImageLocation, ImageSegment, ImageSpace, NativeImageRegion, SparseDeviceImage};
use crate::configuration::{LoweredDeviceConfiguration, ParameterValue};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::{ParameterByteOrder, ProductData};
use zweidraehte_project::ProgrammingSection;

pub(super) fn apply_parameters(
    product: &ProductData,
    configuration: &LoweredDeviceConfiguration,
    regions: &BTreeMap<String, NativeImageRegion>,
    image: &mut SparseDeviceImage,
    demand: ImageDemand<'_>,
) -> Result<(), CompileError> {
    for value in &configuration.parameters {
        let Some(location) = product.parameters().iter().find(|location| location.id == value.id) else {
            if !demand.is_complete() || product.property_parameters().iter().any(|location| location.id == value.id) {
                continue;
            }
            return Err(CompileError::invalid(format!("project supplies unknown parameter {0:?}", value.id.clone())));
        };
        let Some(region) = regions.get(&location.code_segment) else {
            if !demand.is_complete() {
                continue;
            }
            return Err(CompileError::invalid(format!(
                "{purpose} refers to missing product segment {segment:?}",
                purpose = format!("parameter {}", value.id),
                segment = location.code_segment.clone()
            )));
        };
        let span = parameter_span(value, location.size_bits, location.bit_offset)?;
        let offset = region.location.offset.checked_add(location.offset).ok_or_else(|| {
            CompileError::invalid(format!("parameter {0:?} lies outside its product segment", location.id.clone()))
        })?;
        if !demand.includes(&ImageLocation { space: region.location.space.clone(), offset }, span as u32) {
            continue;
        }
        let (data, mask) = encode_parameter(
            value,
            location.size_bits,
            location.bit_offset,
            location.byte_ordered,
            &product.programming_options().parameter_byte_order().value,
        )?;
        let patch = region_patch(region, location.offset, data, mask)?;
        let seed: Vec<_> = (0..patch.data().len())
            .map(|index| region.seed.get(location.offset as usize + index).copied().unwrap_or(0))
            .collect();
        transfer_parameter_bytes(image, patch, &seed)?;
    }
    Ok(())
}

pub(super) fn apply_property_parameters(
    product: &ProductData,
    configuration: &LoweredDeviceConfiguration,
    image: &mut SparseDeviceImage,
    demand: ImageDemand<'_>,
) -> Result<(), CompileError> {
    let mut buffers: BTreeMap<ImageSpace, u32> = BTreeMap::new();
    // Materialization orders defaults before active union members. Preserve
    // that last-writer precedence just as memory parameters do; declaration
    // order can otherwise overwrite an active member with an inactive one.
    for value in &configuration.parameters {
        let Some(location) = product.property_parameters().iter().find(|location| location.id == value.id) else {
            continue;
        };
        let object = product_property_object(location.object);
        let target = ImageLocation {
            space: ImageSpace::Property { object, property_id: location.property_id },
            offset: location.offset,
        };
        if !demand.includes(&target, parameter_span(value, location.size_bits, location.bit_offset)? as u32) {
            continue;
        }
        let (data, mask) = encode_parameter(
            value,
            location.size_bits,
            location.bit_offset,
            location.byte_ordered,
            &product.programming_options().parameter_byte_order().value,
        )?;
        let seed = vec![0; data.len()];
        let segment = ImageSegment::new(target, data, mask)?;
        buffers
            .entry(segment.location().space.clone())
            .and_modify(|end| *end = (*end).max(segment.end_offset()))
            .or_insert(segment.end_offset());
        transfer_parameter_bytes(image, segment, &seed)?;
    }
    // The reference allocates a property buffer from byte zero through the
    // last parameter, including gaps. Gaps are read back from the device;
    // they are never default zero values or capacity beyond that extent.
    for (space, length) in buffers {
        image.represent_range(&ImageLocation { space, offset: 0 }, length)?;
    }
    Ok(())
}

/// Packing changes only the field's bits; the native transfer owns each byte.
/// Preserve the product seed and earlier parameter overlays in neighbouring bits.
fn transfer_parameter_bytes(
    image: &mut SparseDeviceImage,
    patch: ImageSegment,
    seed: &[u8],
) -> Result<(), CompileError> {
    let mut data = image.overlay(patch.location(), seed)?;
    for ((byte, value), mask) in data.iter_mut().zip(patch.data()).zip(patch.mask()) {
        *byte = (*byte & !mask) | (value & mask);
    }
    image.apply_section(ProgrammingSection::Parameters, &ImageSegment::owned(patch.location().clone(), data)?);
    Ok(())
}

pub(super) fn encode_parameter(
    parameter: &ParameterValue,
    size_bits: u16,
    bit_offset: u8,
    byte_ordered: bool,
    byte_order: &ParameterByteOrder,
) -> Result<(Vec<u8>, Vec<u8>), CompileError> {
    if let ParameterByteOrder::Unknown(value) = byte_order {
        return Err(CompileError::unsupported(format!(
            "parameter {0:?} uses an unsupported byte order",
            value.clone()
        )));
    }
    let span = parameter_span(parameter, size_bits, bit_offset)?;
    let mut value = parameter.value.clone();
    // Only numeric values have a byte order; text, IP addresses, colours
    // and raw data keep their sequence under a little-endian product.
    if byte_ordered && matches!(byte_order, ParameterByteOrder::LittleEndian) {
        value.reverse();
    }
    if bit_offset == 0 && size_bits.is_multiple_of(8) {
        return Ok((value, vec![u8::MAX; span]));
    }

    // Packed fields count from the MSB. Only their declared bits belong to
    // the parameter, even when their value agrees with the firmware seed.
    let raw = value.iter().fold(0u64, |accumulator, byte| (accumulator << 8) | u64::from(*byte));
    let mut data = vec![0; span];
    let mut masks = vec![0; span];
    for bit in 0..size_bits {
        let position = usize::from(bit_offset) + usize::from(bit);
        let mask = 1_u8 << (7 - position % 8);
        if (raw >> (size_bits - 1 - bit)) & 1 != 0 {
            data[position / 8] |= mask;
        }
        masks[position / 8] |= mask;
    }
    Ok((data, masks))
}

fn parameter_span(value: &ParameterValue, size_bits: u16, bit_offset: u8) -> Result<usize, CompileError> {
    if bit_offset == 0 && size_bits.is_multiple_of(8) {
        if size_bits != 0 && value.value.len() > usize::from(size_bits / 8) {
            return Err(CompileError::invalid(format!("parameter {0:?} is wider than its declared type", value.id)));
        }

        Ok(value.value.len())
    } else {
        // Packed fields are encoded through a u64. A short supplied value
        // does not make a wider declared field safe to shift into place.
        if size_bits > 64 || value.value.len() > 8 {
            return Err(CompileError::invalid(format!("parameter {0:?} is wider than its declared type", value.id)));
        }

        Ok((usize::from(bit_offset) + usize::from(size_bits)).div_ceil(8))
    }
}
