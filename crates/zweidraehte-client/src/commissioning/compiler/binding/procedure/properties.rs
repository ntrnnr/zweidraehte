//! Resolve properties operands against the image and target metadata.

use super::*;
use crate::commissioning::error::CompileError;

use crate::commissioning::compiler::selection::syntax::{
    authored_property_wire_length, decode_optional_hex, object_selector,
};
use crate::commissioning::procedure::{
    ComparisonPadding, ControlPath, OperationData, OperationExtent, ProcedureOperation,
};

impl ProcedureLowerer<'_> {
    /// Whether an image-backed property write has no image layout at all.
    pub(super) fn property_write_has_no_source(
        &self,
        control: &zweidraehte_ets_files::schema::LdCtrlWriteProp,
        path: &ControlPath,
    ) -> Result<bool, CompileError> {
        let object = object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
        let property = self.property_operand(
            &object,
            control.prop_id,
            control.start_element.unwrap_or(1),
            control.count.unwrap_or(1),
            Some(false),
            path,
        )?;
        Ok(property.image_range.is_none())
    }

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
        let mut inline = decode_optional_hex(control.inline_data.as_deref(), path)?;
        let property = self.property_operand(&object, control.prop_id, start_element, count, Some(false), path)?;
        // A single-element inline write to an identity resource always carries
        // the product identity. Vendors usually author a zero placeholder, but
        // any authored payload, including a stale identity, is replaced the
        // same way. When the image does not own the identity, this patched
        // payload is what the device receives.
        if start_element == 1 && count == 1 && inline.as_ref().is_some_and(|data| !data.is_empty()) {
            for (resource, offset) in
                crate::commissioning::catalog::property_resources(self.context.profile, &object, control.prop_id)?
            {
                let secondary = self.context.secondary_application_identity.filter(|_| resource.name() == "PeiprogId");
                if offset != Some(0)
                    || !matches!(resource.name(), "ApplicationId" | "PeiprogId")
                    || (resource.name() == "PeiprogId"
                        && !self.context.peiprog_identity_reference
                        && secondary.is_none())
                    || inline.as_ref().unwrap().len() != resource.length() as usize
                {
                    continue;
                }
                // The patched payload becomes the write's fallback; it is used
                // whenever the image does not own the complete identity. A
                // bound secondary PEI Program owns `PeiprogId`.
                let identity = secondary.unwrap_or(self.context.application_identity);
                inline = Some(
                    crate::commissioning::compiler::image::application_identity_resource_value(
                        resource.name(),
                        resource.length(),
                        &identity.application_id,
                    )
                    .map_err(|error| error.with_path(path))?
                    .to_vec(),
                );
            }
        }
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
                // authored wire buffer. Known PDTs take precedence; native
                // property compares ignore the reference suffix beyond the
                // read extent, including nonzero suffix bytes.
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

        let mut comparison = if inline.is_none() && control.range.is_none() {
            let mut mask = decode_optional_hex(control.mask.as_deref(), path)?;
            if comparison_length < extent_length
                || mask.as_ref().is_some_and(|mask| mask.len() < extent_length as usize)
            {
                return Err(CompileError::at(
                    path,
                    "short image-only property reference or mask requires a verified mapping",
                ));
            }
            if let Some(mask) = &mut mask {
                mask.truncate(extent_length as usize);
            }
            crate::commissioning::procedure::Comparison::ImageExact {
                location: image_location.clone().expect("image-only comparison has a bound image location"),
                length: extent_length,
                mask,
            }
        } else {
            self.comparison(
                inline.clone(),
                control.mask.as_deref(),
                control.range.as_deref(),
                image_location.clone(),
                comparison_length,
                if inline.is_some() { ComparisonPadding::None } else { ComparisonPadding::ExpectedTrailingZeros },
                path,
            )?
        };
        // Validate the authored mask against its reference before clipping
        // both to the bytes used by the native comparison. The XML remains
        // available in the product; the executable IR contains the used bytes.
        if let crate::commissioning::procedure::Comparison::Exact { data: OperationData::Inline(data), mask, .. } =
            &mut comparison
        {
            data.truncate(extent_length as usize);
            if let Some(mask) = mask {
                mask.truncate(extent_length as usize);
            }
        }
        let fallback = match &comparison {
            crate::commissioning::procedure::Comparison::Exact { data: OperationData::Inline(data), .. } => {
                Some(data.clone())
            }
            _ => None,
        };
        // A successful preceding read overrides the XML buffer; an ignored
        // failed read leaves the authored fallback authoritative.
        if let (Some(location), crate::commissioning::procedure::Comparison::Exact { data, .. }) =
            (image_location, &mut comparison)
        {
            *data = OperationData::Buffer { location, length: comparison_length, fallback };
        }

        Ok(ProcedureOperation::Compare {
            target,
            comparison,
            extent: OperationExtent::property(extent_length, count),
            cache: compare_cache_policy(control.allow_cached_value),
            invert: control.invert.unwrap_or(false),
            retry_interval_milliseconds: control.retry_interval,
            timeout_milliseconds: control.time_out.map(|seconds| u32::from(seconds) * 1_000),
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
        let extent = OperationExtent::property(length, count);
        let image_stamp = property.capture_as.is_some()
            && self.context.profile.management_model()
                == crate::commissioning::catalog::profile::ManagementModel::SystemB
            && self.context.profile.feature("DownloadStamp").map_err(|error| error.with_path(path))? == Some(1);
        if image_stamp
            && (!matches!(object, crate::commissioning::catalog::profile::ObjectSelector::Index { .. })
                || control.prop_id != 27
                || length != 8)
        {
            return Err(CompileError::at(path, "System B stamp requires indexed PID 27 and eight octets"));
        }
        // The reference reads an image property only where the working image
        // does not own it yet, on every management model and whether or not
        // the property holds a stamp. It never snapshots a stamp at this
        // control: download stamps come from the final image. A stamp-flavoured
        // resource therefore changes neither the cache policy nor the capture.
        let alignment = length
            .checked_div(u32::from(count))
            .filter(|width| *width != 0)
            .ok_or_else(|| CompileError::at(path, "property image read requires a positive element width"))?;
        Ok(ProcedureOperation::LoadImage { target, image_location, extent, alignment })
    }
}

#[cfg(test)]
mod tests;
