//! Resolve properties operands against the image and target metadata.

use super::*;
use crate::commissioning::error::CompileError;

use crate::commissioning::compiler::selection::syntax::{
    authored_property_wire_length, decode_optional_hex, object_selector,
};
use crate::commissioning::procedure::{
    CachePolicy, ComparisonPadding, ControlPath, OperationData, OperationExtent, ProcedureOperation,
};

impl ProcedureLowerer<'_> {
    pub(super) fn lower_property_write(
        &self,
        control: &zweidraehte_ets_files::schema::LdCtrlWriteProp,
        path: &ControlPath,
    ) -> Result<ProcedureOperation, CompileError> {
        if control.trim == Some(true) {
            return Err(CompileError::at(
                path,
                "WriteProp Trim=true has no defined project-20 through project-23 load-control semantics",
            ));
        }

        let object = object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
        let start_element = control.start_element.unwrap_or(1);
        let count = control.count.unwrap_or(1);
        let inline = decode_optional_hex(control.inline_data.as_deref(), path)?;
        let property = self.property_operand(&object, control.prop_id, start_element, count, Some(false), path)?;
        let target = property.target;
        let image_range = property.image_range;
        let write_length = property.wire_length.or_else(|| image_range.as_ref().map(|(_, length)| *length));

        let data = match (image_range, inline) {
            (Some((location, length)), fallback) => OperationData::Buffer { location, length, fallback },
            (None, Some(mut data)) => {
                let expected_length =
                    write_length.unwrap_or(authored_property_wire_length(&data, count, "WriteProp InlineData", path)?);
                if data.len() < expected_length as usize {
                    return Err(CompileError::at(
                        path,
                        format!(
                            "WriteProp InlineData has only {} bytes but {count} elements require {expected_length}",
                            data.len()
                        ),
                    ));
                }
                data.truncate(expected_length as usize);
                OperationData::Inline(data)
            }
            (None, None) => {
                return Err(CompileError::at(
                    path,
                    format!("no image layout is resolved for property {} on {object:?}", control.prop_id),
                ));
            }
        };
        let extent = OperationExtent::property(operation_data_length(&data), count);
        let policy = WriteIntent::Property { verify: control.verify };
        Ok(ProcedureOperation::Write { target, data, extent, policy })
    }

    pub(super) fn lower_property_compare(
        &self,
        control: &zweidraehte_ets_files::schema::LdCtrlCompareProp,
        path: &ControlPath,
    ) -> Result<ProcedureOperation, CompileError> {
        let object = object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
        let start_element = control.start_element.unwrap_or(1);
        let count = control.count.unwrap_or(1);
        let inline = decode_optional_hex(control.inline_data.as_deref(), path)?;
        let property = self.property_operand(&object, control.prop_id, start_element, count, Some(true), path)?;
        let target = property.target;
        let read_length = property.wire_length;
        let (image_location, comparison_length, extent_length) = match inline.as_ref() {
            Some(data) => {
                let range = property.image_range;
                // Vendor properties absent from the catalogue use the exact
                // authored wire buffer. Known PDTs take precedence so fixed
                // XML padding is discarded below.
                let extent_length = read_length
                    .or_else(|| range.as_ref().map(|(_, length)| *length))
                    .unwrap_or(authored_property_wire_length(data, count, "CompareProp InlineData", path)?);

                let expected_length = usize::try_from(extent_length)
                    .map_err(|_| CompileError::at(path, "property comparison length does not fit this host"))?;
                if data.len() < expected_length {
                    return Err(CompileError::at(
                        path,
                        format!(
                            "CompareProp InlineData has {} bytes but {count} elements return {expected_length}",
                            data.len()
                        ),
                    ));
                }
                if data[expected_length..].iter().any(|byte| *byte != 0) {
                    return Err(CompileError::at(
                        path,
                        "CompareProp InlineData has nonzero bytes beyond the property read value",
                    ));
                }

                (range.map(|(location, _)| location), extent_length, extent_length)
            }
            None => {
                let (location, length) = property.image_range.ok_or_else(|| {
                    CompileError::at(
                        path,
                        format!("no image layout is resolved for property {} on {object:?}", control.prop_id),
                    )
                })?;
                (Some(location), length, read_length.unwrap_or(length))
            }
        };

        let mut comparison = self.comparison(
            inline.clone(),
            control.mask.as_deref(),
            control.range.as_deref(),
            image_location.clone(),
            comparison_length,
            ComparisonPadding::ExpectedTrailingZeros,
            path,
        )?;
        // A successful preceding read overrides the XML buffer; an ignored
        // failed read leaves the authored fallback authoritative.
        if let (Some(location), crate::commissioning::procedure::Comparison::Exact { data, .. }) =
            (image_location, &mut comparison)
        {
            *data = OperationData::Buffer { location, length: comparison_length, fallback: inline };
        }

        Ok(ProcedureOperation::Compare {
            target,
            comparison,
            extent: OperationExtent::property(extent_length, count),
            cache: compare_cache_policy(control.allow_cached_value),
            invert: control.invert.unwrap_or(false),
            retry_interval_milliseconds: control.retry_interval,
            timeout_milliseconds: control.time_out,
        })
    }

    pub(super) fn lower_property_image_read(
        &self,
        control: &zweidraehte_ets_files::schema::LdCtrlLoadImageProp,
        path: &ControlPath,
    ) -> Result<ProcedureOperation, CompileError> {
        let object = object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
        let start_element = control.start_element.unwrap_or(1);
        let count = control.count.unwrap_or(1);
        let property = self.property_operand(&object, control.prop_id, start_element, count, None, path)?;
        let target = property.target;
        let (image_location, length) = property.image_range.ok_or_else(|| {
            CompileError::at(
                path,
                format!("no image layout is resolved for property {} on {object:?}", control.prop_id),
            )
        })?;
        let capture_as = property.capture_as;
        let extent = OperationExtent::property(length, count);
        let image_stamp = capture_as.is_some()
            && self.context.profile.management_model()
                == crate::commissioning::catalog::profile::ManagementModel::SystemB
            && self.context.profile.feature("DownloadStamp").map_err(|error| error.with_path(path))? == Some(1);
        Ok(if image_stamp {
            if !matches!(object, crate::commissioning::catalog::profile::ObjectSelector::Index { .. })
                || control.prop_id != 27
                || length != 8
            {
                return Err(CompileError::at(path, "System B stamp requires indexed PID 27 and eight octets"));
            }
            ProcedureOperation::LoadImage { target, image_location, extent, alignment: 8 }
        } else {
            ProcedureOperation::ReadIntoImage {
                target,
                image_location,
                extent,
                cache: CachePolicy::Populate,
                capture_as,
            }
        })
    }
}

#[cfg(test)]
mod tests;
