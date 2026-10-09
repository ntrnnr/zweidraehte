//! Bind absolute and relative memory controls through the same transfer rules.

use super::*;
use crate::commissioning::compiler::selection::syntax::{
    declared_write_payload, memory_location, require_exact_length,
};
use crate::commissioning::error::CompileError;
use crate::commissioning::image::ImageSpace;
use crate::commissioning::procedure::ComparisonPadding;

impl ProcedureLowerer<'_> {
    pub(super) fn lower_memory_write(
        &self,
        control: &LoadControl,
        path: &ControlPath,
    ) -> Result<ProcedureOperation, CompileError> {
        let (location, size, inline, verify, name) = match control {
            LoadControl::LdCtrlWriteMem(control) => (
                memory_location(control.address_space.as_deref(), control.address, path)?,
                control.size,
                control.inline_data.as_deref(),
                control.verify,
                "WriteMem",
            ),
            LoadControl::LdCtrlWriteRelMem(control) => (
                ImageLocation {
                    space: ImageSpace::RelativeMemory {
                        object: object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?,
                    },
                    offset: control.offset,
                },
                control.size,
                control.inline_data.as_deref(),
                control.verify,
                "WriteRelMem",
            ),
            _ => unreachable!("memory-write dispatch accepts only memory writes"),
        };
        let inline = decode_optional_hex(inline, path)?;
        let policy = if matches!(&location.space, ImageSpace::RelativeMemory { .. }) {
            WriteIntent::Relative { verify }
        } else {
            WriteIntent::Memory { verify }
        };

        let (target, data) = if let Some(data) = inline {
            let data = declared_write_payload(data, size, &format!("{name} InlineData"), path)?;
            if data.is_empty() {
                return Err(CompileError::at(path, format!("{name} resolves to an empty write")));
            }
            let target =
                memory_target(self.context.profile, self.context.standard_memory_service, &location, size, path)?;
            (target, OperationData::Inline(data))
        } else {
            // Bind only after the desired image establishes a nonempty window.
            // Optional relative windows must not resolve unused pointer resources.
            (OperationTarget::ImageMemory(location.clone()), OperationData::ImageWindow { location, maximum: size })
        };
        Ok(ProcedureOperation::Write { target, data, extent: OperationExtent::bytes(size), policy })
    }

    pub(super) fn lower_memory_compare(
        &self,
        control: &LoadControl,
        path: &ControlPath,
    ) -> Result<ProcedureOperation, CompileError> {
        let (location, size, inline, mask, range, cache, invert, retry_interval, timeout, name) = match control {
            LoadControl::LdCtrlCompareMem(control) => (
                memory_location(control.address_space.as_deref(), control.address, path)?,
                control.size,
                control.inline_data.as_deref(),
                control.mask.as_deref(),
                control.range.as_deref(),
                control.allow_cached_value,
                control.invert,
                control.retry_interval,
                control.time_out,
                "CompareMem",
            ),
            LoadControl::LdCtrlCompareRelMem(control) => (
                ImageLocation {
                    space: ImageSpace::RelativeMemory {
                        object: object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?,
                    },
                    offset: control.offset,
                },
                control.size,
                control.inline_data.as_deref(),
                control.mask.as_deref(),
                control.range.as_deref(),
                control.allow_cached_value,
                control.invert,
                control.retry_interval,
                control.time_out,
                "CompareRelMem",
            ),
            _ => unreachable!("memory-comparison dispatch accepts only memory comparisons"),
        };
        let target = memory_target(self.context.profile, self.context.standard_memory_service, &location, size, path)?;
        let inline = decode_optional_hex(inline, path)?;
        if let Some(data) = &inline {
            require_exact_length(data.len(), size, &format!("{name} InlineData"), path)?;
        }
        let comparison = self.comparison(inline, mask, range, Some(location), size, ComparisonPadding::None, path)?;

        Ok(ProcedureOperation::Compare {
            target,
            comparison,
            extent: OperationExtent::bytes(size),
            cache: compare_cache_policy(cache),
            invert: invert.unwrap_or(false),
            retry_interval_milliseconds: retry_interval,
            timeout_milliseconds: timeout,
        })
    }

    pub(super) fn lower_memory_image_read(
        &self,
        control: &LoadControl,
        path: &ControlPath,
    ) -> Result<ProcedureOperation, CompileError> {
        let (image_location, size) = match control {
            LoadControl::LdCtrlLoadImageMem(control) => {
                (memory_location(control.address_space.as_deref(), control.address, path)?, control.size)
            }
            LoadControl::LdCtrlLoadImageRelMem(control) => (
                ImageLocation {
                    space: ImageSpace::RelativeMemory {
                        object: object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?,
                    },
                    offset: control.offset,
                },
                control.size,
            ),
            _ => unreachable!("memory-image dispatch accepts only memory-image reads"),
        };
        let target =
            memory_target(self.context.profile, self.context.standard_memory_service, &image_location, size, path)?;
        Ok(ProcedureOperation::ReadIntoImage {
            target,
            image_location,
            extent: OperationExtent::bytes(size),
            cache: CachePolicy::Populate,
            capture_as: None,
        })
    }
}

pub(super) fn memory_target(
    profile: &ResolvedProfile,
    service: crate::commissioning::procedure::operands::StandardMemoryService,
    location: &ImageLocation,
    length: u32,
    path: &ControlPath,
) -> Result<OperationTarget, CompileError> {
    use crate::commissioning::procedure::operands::{MemoryAddress, MemoryService};
    let service = match &location.space {
        ImageSpace::StandardMemory => service.for_range(location.offset, length),
        ImageSpace::UserMemory => MemoryService::User,
        ImageSpace::LineCouplerSlave => MemoryService::Router,
        ImageSpace::LineCouplerFilter => MemoryService::Filter,
        ImageSpace::RelativeMemory { object } => {
            return profile
                .relative_memory_target(object, location.offset, length, service)
                .map_err(|error| error.with_path(path));
        }
        _ => return Err(CompileError::at(path, "memory control has no memory image space")),
    };
    Ok(OperationTarget::Memory { service, address: MemoryAddress::Fixed(location.offset) })
}

#[cfg(test)]
mod tests;
