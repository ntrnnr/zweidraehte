//! Derive image demand from the canonical operands, without parsing XML again.

use crate::commissioning::compiler::binding::procedure::ParsedProcedure;
use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageLocation, RequiredImageRange};
use crate::commissioning::procedure::{Comparison, ControlPath, LoadEffect, OperationData, ProcedureOperation};
use std::collections::BTreeSet;
use zweidraehte_ets_files::product::ProductData;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DemandKind {
    DeviceRead,
    Required,
    Window,
    Fallback,
}

struct ProcedureImageDemand<'a> {
    path: &'a ControlPath,
    range: RequiredImageRange,
    kind: DemandKind,
}

pub(super) fn required_image_ranges(
    parsed: &ParsedProcedure,
    product: &ProductData,
) -> Result<Vec<RequiredImageRange>, CompileError> {
    // Probe geometry describes authored maximum windows, never successful device reads.
    let mut probe = Vec::new();
    let mut ordered = Vec::new();
    for step in &parsed.program.steps {
        match &step.operation {
            ProcedureOperation::Compare { comparison: Comparison::ImageExact { location, length, .. }, .. } => {
                let range = RequiredImageRange { location: location.clone(), length: *length };
                probe.push(range.clone());
                ordered.push(ProcedureImageDemand { path: &step.path, range, kind: DemandKind::Required });
            }
            ProcedureOperation::ReadIntoImage { image_location, extent, .. }
            | ProcedureOperation::LoadImage { image_location, extent, .. } => ordered.push(ProcedureImageDemand {
                path: &step.path,
                range: RequiredImageRange { location: image_location.clone(), length: extent.byte_length },
                kind: DemandKind::DeviceRead,
            }),
            ProcedureOperation::Write { data, .. }
            | ProcedureOperation::Compare { comparison: Comparison::Exact { data, .. }, .. } => {
                if let Some(demand) = data_range(&step.path, data) {
                    if demand.kind != DemandKind::Fallback {
                        probe.push(demand.range.clone());
                    }
                    ordered.push(demand);
                }
            }
            ProcedureOperation::AbsoluteSegment { record, .. } | ProcedureOperation::LoadRecord(record) => {
                if let LoadEffect::Invalidate { location, length } | LoadEffect::Fill { location, length, .. } =
                    &record.effect
                {
                    probe.push(RequiredImageRange { location: location.clone(), length: *length });
                }
            }
            _ => {}
        }
    }
    for range in &mut probe {
        range.length = clip_probe_range_to_product(product, range)?;
        if range.location.offset.checked_add(range.length).is_none() {
            return Err(CompileError::invalid("image range exceeds the 32-bit address space"));
        }
    }
    probe.sort();
    let mut merged: Vec<RequiredImageRange> = Vec::new();
    for range in probe.into_iter().filter(|range| range.length != 0) {
        if let Some(previous) = merged.last_mut()
            && previous.location.space == range.location.space
            && previous.location.offset + previous.length >= range.location.offset
        {
            previous.length = previous.length.max(range.location.offset + range.length - previous.location.offset);
        } else {
            merged.push(range);
        }
    }
    let mut working = BTreeSet::new();
    let mut required = BTreeSet::new();
    for ProcedureImageDemand { path, range, kind } in ordered {
        if kind == DemandKind::DeviceRead {
            working.insert(range);
            continue;
        }
        let end = range
            .location
            .offset
            .checked_add(range.length)
            .ok_or_else(|| CompileError::at(path, "image-backed control range exceeds the 32-bit address space"))?;
        let contains = merged.iter().any(|part| {
            part.location.space == range.location.space
                && part.location.offset <= range.location.offset
                && part.location.offset + part.length >= end
        });
        if kind == DemandKind::Fallback && !contains {
            continue;
        }
        if kind == DemandKind::Window {
            for part in merged.iter().filter(|part| part.location.space == range.location.space) {
                let start = range.location.offset.max(part.location.offset);
                let end = end.min(part.location.offset + part.length);
                let part = RequiredImageRange {
                    location: ImageLocation { space: range.location.space.clone(), offset: start },
                    length: end.saturating_sub(start),
                };
                if part.length != 0 && !working.contains(&part) {
                    required.insert(part);
                }
            }
        } else if !working.contains(&range) {
            if !contains {
                return Err(CompileError::at(path, "required image range is outside the selected product"));
            }
            required.insert(range);
        }
    }
    Ok(required.into_iter().collect())
}

fn data_range<'a>(path: &'a ControlPath, data: &OperationData) -> Option<ProcedureImageDemand<'a>> {
    let (location, length, kind) = match data {
        OperationData::Buffer { location, length, fallback: Some(_) } => (location, *length, DemandKind::Fallback),
        OperationData::Buffer { location, length, fallback: None } | OperationData::Image { location, length } => {
            (location, *length, DemandKind::Required)
        }
        OperationData::ImageWindow { location, maximum } => (location, *maximum, DemandKind::Window),
        _ => return None,
    };
    Some(ProcedureImageDemand { path, range: RequiredImageRange { location: location.clone(), length }, kind })
}

pub(crate) fn clip_probe_range_to_product(
    product: &ProductData,
    range: &RequiredImageRange,
) -> Result<u32, CompileError> {
    let mut available = None;

    for segment in product.segments() {
        let location = crate::commissioning::catalog::rules::product_segment(product, segment)?;

        if location.space != range.location.space || location.offset > range.location.offset {
            continue;
        }
        let Some(end) = location.offset.checked_add(segment.size) else {
            continue;
        };
        if range.location.offset >= end {
            continue;
        }

        let length = end - range.location.offset;
        available = Some(available.map_or(length, |current: u32| current.max(length)));
    }

    Ok(available.map_or(range.length, |available| available.min(range.length)))
}
