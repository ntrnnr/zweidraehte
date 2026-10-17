//! Resolve properties operands against the image and target metadata.

use super::*;
use crate::commissioning::error::CompileError;
use crate::commissioning::image::ImageSpace;

use crate::commissioning::catalog::profile::ObjectSelector;
use crate::commissioning::catalog::property_resources;
use crate::commissioning::catalog::rules::product_property_object;
use crate::commissioning::compiler::selection::syntax::{
    authored_property_wire_length, decode_optional_hex, object_selector, parse_range,
};
use crate::commissioning::procedure::{
    ComparisonPadding, ControlPath, DescribedPropertyAction, DescribedPropertyOperation, OperationData,
    OperationExtent, ProcedureOperation,
};

impl ProcedureLowerer<'_> {
    /// Whether a write sends the image segment of an untyped property that
    /// stores a product parameter, sized by the target's description.
    ///
    /// Without a width from the mask roster or a declaration, the reference
    /// lays out such a parameter's segment from the property's start to the
    /// parameter's last byte, rounded to no element boundary. Later start
    /// elements defer their byte offset until the target supplies a width;
    /// a type-addressed object resolves that description through lookup by type.
    fn writes_described_image(
        &self,
        control: &zweidraehte_ets_files::schema::LdCtrlWriteProp,
        object: &ObjectSelector,
    ) -> Result<bool, CompileError> {
        if control.start_element.unwrap_or(1) == 0 || control.count.unwrap_or(1) == 0 {
            return Ok(false);
        }

        let parameter_owned = self.context.property_parameters.iter().any(|parameter| {
            product_property_object(parameter.object) == *object && parameter.property_id == control.prop_id
        });
        if !parameter_owned {
            return Ok(false);
        }

        let profile = self.context.profile;
        let resources = property_resources(profile, object, control.prop_id)?;
        Ok(profile.catalog.property_width(profile, object, control.prop_id, false, Some(&resources))?.is_none())
    }

    /// Whether an image-backed property write has no image layout at all.
    pub(super) fn property_write_has_no_source(
        &self,
        control: &zweidraehte_ets_files::schema::LdCtrlWriteProp,
        path: &ControlPath,
    ) -> Result<bool, CompileError> {
        let object = object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
        if self.writes_described_image(control, &object).map_err(|error| error.with_path(path))? {
            return Ok(false);
        }
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

        // Element zero writes the two-byte array count, regardless of the
        // ordinary element PDT or a declaration for that property. It has no
        // ordinary-image offset and must not allocate a normal value buffer.
        if start_element == 0
            && count == 1
            && let Some(bytes) = inline.as_ref().filter(|bytes| bytes.len() >= 2)
        {
            let target = crate::commissioning::procedure::operands::property_target(&object, control.prop_id, 0)
                .map_err(|error| error.with_path(path))?;
            return Ok(ProcedureOperation::Write {
                target,
                data: OperationData::Inline(bytes[..2].to_vec()),
                extent: OperationExtent::property(2, 1),
                policy: WriteIntent::Property { verify: control.verify },
            });
        }

        // The first-element segment retains its established clipped-image
        // behavior. Later starts need both the original inline source and a
        // target-described image offset; neither is known from parameter sizes.
        if self.writes_described_image(control, &object).map_err(|error| error.with_path(path))? {
            let target =
                crate::commissioning::procedure::operands::property_target(&object, control.prop_id, start_element)
                    .map_err(|error| error.with_path(path))?;
            let location = ImageLocation {
                space: ImageSpace::Property { object: object.clone(), property_id: control.prop_id },
                offset: 0,
            };
            let policy = WriteIntent::Property { verify: control.verify };
            let action = if start_element == 1 {
                DescribedPropertyAction::WriteImage { location, length: 0, policy }
            } else {
                DescribedPropertyAction::WriteImageWindow { location, length: 0, inline, policy }
            };
            return Ok(ProcedureOperation::DescribedProperty(DescribedPropertyOperation {
                target,
                elements: count,
                extended_description: self.context.extended_property_descriptions,
                widths: self.context.profile.property_data_type_widths(false),
                action,
            }));
        }

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
                    || inline.as_ref().expect("nonempty inline payload").len() < resource.length() as usize
                {
                    continue;
                }
                // The patched payload becomes the write's fallback; it is used
                // whenever the image does not own the complete identity. A
                // bound secondary PEI Program owns `PeiprogId`.
                let identity = secondary.unwrap_or(self.context.application_identity);
                let identity_bytes = crate::commissioning::compiler::image::application_identity_resource_value(
                    resource.name(),
                    resource.length(),
                    &identity.application_id,
                )
                .map_err(|error| error.with_path(path))?;
                inline.as_mut().expect("identity placeholder payload")[..identity_bytes.len()]
                    .copy_from_slice(identity_bytes);
            }
        }
        let target = property.target;
        let mut image_range = property.image_range;
        let write_length = property.wire_length.or_else(|| image_range.as_ref().map(|(_, length)| *length));

        // A unique authored write can allocate an unowned property buffer even
        // when its complete inline value supplies every transmitted byte.
        // Retain its image identity until image creation decides whether that
        // geometry allocates; final binding still falls back to the inline value.
        if image_range.is_none()
            && start_element != 0
            && count != 0
            && self
                .context
                .profile
                .catalog
                .procedure_property_buffer_width(self.context.profile, &object, control.prop_id)?
                .is_some()
            && let Some(length) = write_length
        {
            let offset = u32::from(start_element - 1)
                .checked_mul(length / u32::from(count))
                .ok_or_else(|| CompileError::at(path, "property write image offset exceeds 32 bits"))?;
            image_range = Some((
                ImageLocation {
                    space: ImageSpace::Property { object: object.clone(), property_id: control.prop_id },
                    offset,
                },
                length,
            ));
        }

        // WriteBase discards a short inline value before looking for an image
        // segment. Metadata alone cannot establish whether that segment is
        // absent: controls and image contributions may still supply it. Keep
        // a concrete window until final binding can select or omit the write.
        if start_element != 0
            && count != 0
            && let Some(length) = write_length.filter(|length| *length != 0)
            && inline.as_ref().is_none_or(|bytes| bytes.len() < length as usize)
        {
            inline = None;
            if image_range.is_none() {
                let width = length / u32::from(count);
                let offset = u32::from(start_element - 1)
                    .checked_mul(width)
                    .ok_or_else(|| CompileError::at(path, "property write image offset exceeds 32 bits"))?;
                image_range = Some((
                    ImageLocation {
                        space: ImageSpace::Property { object: object.clone(), property_id: control.prop_id },
                        offset,
                    },
                    length,
                ));
            }
        }

        // Neither the profile, Master Data, a declaration nor an observation
        // types this property, and the image holds none of it. The reference
        // then asks the target for the property's description when the
        // control runs, and the authored bytes are a payload to cut to that
        // size, not a statement of it. The write therefore defers its
        // geometry to execution, describing an indexed object directly and a
        // type-addressed one through the lookup by object type.
        if write_length.is_none()
            && image_range.is_none()
            && start_element != 0
            && count != 0
            && let Some(payload) = inline.clone()
        {
            return Ok(ProcedureOperation::DescribedProperty(DescribedPropertyOperation {
                target,
                elements: count,
                extended_description: self.context.extended_property_descriptions,
                widths: self.context.profile.property_data_type_widths(false),
                action: DescribedPropertyAction::Write {
                    payload,
                    policy: WriteIntent::Property { verify: control.verify },
                },
            }));
        }

        let data = match (image_range, inline) {
            (Some((location, length)), fallback) => OperationData::Buffer { location, length, fallback },
            // TODO: A type-addressed write the reference sizes from the
            // target first locates the object and may use the extended
            // description service; until that lookup is modelled, these
            // writes keep the authored width.
            (None, Some(mut data)) => {
                let expected_length = match write_length {
                    Some(length) => length,
                    None => authored_property_wire_length(&data, count, "WriteProp InlineData", path)?,
                };
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
        let mut inline = decode_optional_hex(control.inline_data.as_deref(), path)?;
        if let Some(range) = control.range.as_deref() {
            if count == 0 || (start_element == 0 && count != 1) {
                return Err(CompileError::at(path, "numeric property comparison requires a positive element count"));
            }
            let range = parse_range(range).map_err(|message| CompileError::at(path, message))?;
            let target =
                crate::commissioning::procedure::operands::property_target(&object, control.prop_id, start_element)
                    .map_err(|error| error.with_path(path))?;
            let profile = self.context.profile;
            let lookup = profile
                .catalog
                .property_data_type_lookup(profile, &object, control.prop_id)
                .map_err(|error| error.with_path(path))?;
            let cache = compare_cache_policy(control.allow_cached_value);
            let invert = control.invert.unwrap_or(false);
            let retry_interval_milliseconds = control.retry_interval;
            let timeout_milliseconds = control.time_out.map(|seconds| u32::from(seconds) * 1_000);
            // A range has no image operand. Keep its lookup live: allocation
            // declarations can occur later, and a preceding clear/disconnect
            // can invalidate identification's mask or observed descriptor.
            return Ok(ProcedureOperation::DescribedProperty(DescribedPropertyOperation {
                target,
                elements: count,
                extended_description: self.context.extended_property_descriptions,
                widths: profile.property_data_type_widths(true),
                action: DescribedPropertyAction::CompareRange {
                    range,
                    lookup: Some(lookup),
                    cache,
                    invert,
                    retry_interval_milliseconds,
                    timeout_milliseconds,
                },
            }));
        }
        let property = self.property_operand(&object, control.prop_id, start_element, count, Some(true), path)?;
        let target = property.target;
        let read_length = property.wire_length;
        if control.range.is_none()
            && let (Some(reference), Some(length), Some((_, image_length))) =
                (&inline, read_length, &property.image_range)
            && length != 0
            && reference.len() < length as usize
            && *image_length >= length
        {
            // An incomplete authored reference supplies no fallback bytes.
            // The native comparison instead takes its complete image value;
            // the image-only path below preserves its ownership semantics.
            inline = None;
        }

        // As for a write: with no type and no image value, the reference
        // reads the target's description, then compares that many bytes of
        // the authored reference, or nothing when the reference is shorter.
        // An authored mask applies to the leading compared bytes; the object
        // is described by index or by type like a write.
        if read_length.is_none()
            && property.image_range.is_none()
            && start_element != 0
            && count != 0
            && control.range.is_none()
            && let Some(reference) = inline.clone()
        {
            let mask = decode_optional_hex(control.mask.as_deref(), path)?;
            return Ok(ProcedureOperation::DescribedProperty(DescribedPropertyOperation {
                target,
                elements: count,
                extended_description: self.context.extended_property_descriptions,
                widths: self.context.profile.property_data_type_widths(true),
                action: DescribedPropertyAction::Compare {
                    reference,
                    mask,
                    cache: compare_cache_policy(control.allow_cached_value),
                    invert: control.invert.unwrap_or(false),
                    retry_interval_milliseconds: control.retry_interval,
                    timeout_milliseconds: control.time_out.map(|seconds| u32::from(seconds) * 1_000),
                },
            }));
        }

        let (image_location, comparison_length, extent_length) = match inline.as_ref() {
            Some(data) => {
                let range = property.image_range;
                // Vendor properties absent from the catalogue use the exact
                // authored wire buffer. Known PDTs take precedence; native
                // property compares ignore the reference suffix beyond the
                // read extent, including nonzero suffix bytes.
                let extent_length = match read_length.or_else(|| range.as_ref().map(|(_, length)| *length)) {
                    Some(length) => length,
                    // Only an otherwise untyped operand needs to infer an
                    // element width from its authored buffer. A known PDT may
                    // discard a suffix that is not a complete extra element.
                    None => authored_property_wire_length(data, count, "CompareProp InlineData", path)?,
                };

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
            let mask = decode_optional_hex(control.mask.as_deref(), path)?;
            if comparison_length < extent_length {
                return Err(CompileError::at(path, "short image-only property reference requires a verified mapping"));
            }
            // Whether this reference exists is an image-dependent decision.
            // Binding skips an absent source before validating an active
            // comparison's mask against the final read extent.
            crate::commissioning::procedure::Comparison::ImageExact {
                location: image_location.clone().expect("image-only comparison has a bound image location"),
                length: extent_length,
                mask,
            }
        } else {
            self.comparison(
                inline.clone(),
                if control.range.is_none() { None } else { control.mask.as_deref() },
                control.range.as_deref(),
                image_location.clone(),
                comparison_length,
                if inline.is_some() { ComparisonPadding::None } else { ComparisonPadding::ExpectedTrailingZeros },
                path,
            )?
        };
        // Property comparisons AND only the authored mask's common prefix.
        // A missing suffix leaves those reference bytes fully compared.
        if let crate::commissioning::procedure::Comparison::Exact { data: OperationData::Inline(data), mask, .. } =
            &mut comparison
        {
            data.truncate(extent_length as usize);
            if control.range.is_none() {
                *mask = decode_optional_hex(control.mask.as_deref(), path)?;
            }
            if let Some(mask) = mask {
                mask.resize(extent_length as usize, u8::MAX);
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
