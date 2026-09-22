//! Finalize only operands whose geometry depends on the desired image.

use super::*;
use crate::commissioning::error::CompileError;
use crate::commissioning::image::ImageSpace;
use zweidraehte_proto::messages::apdu::load_control::{LoadControlRecord, RelSegment};

#[derive(Debug, Clone)]
pub(super) struct RelativeAllocation {
    pub step: usize,
    pub object: crate::commissioning::catalog::profile::ObjectSelector,
    pub segment: RelSegment,
}

/// The canonical program is retained while a few image operands remain pending.
/// Source XML, choices, merge trees and profiles do not survive parsing.
#[derive(Debug, Clone)]
pub(crate) struct ParsedProcedure {
    pub(crate) program: NormalizedProcedure,
    pub(super) allocations: Vec<RelativeAllocation>,
    pub(super) anchors: Vec<LifecycleAnchor>,
    pub(super) secure_only: bool,
    pub(super) service: crate::commissioning::procedure::operands::StandardMemoryService,
    pub(super) root: ControlPath,
    pub(super) error: Option<CompileError>,
    pub(super) authored_connection_open: bool,
}

impl ParsedProcedure {
    #[cfg(test)]
    pub(crate) fn feature_fixture(profile: &ResolvedProfile) -> Self {
        let id = crate::commissioning::procedure::ProcedureSourceId::Generated { name: "feature-fixture".into() };
        let root = ControlPath {
            mask_id: profile.mask().full_id.clone(),
            variant_index: 0,
            procedure: id.clone(),
            contribution: None,
            control_indices: Vec::new(),
        };
        let steps = [ProcedureOperation::Connect, ProcedureOperation::Disconnect]
            .into_iter()
            .map(|operation| ProcedureStep {
                path: root.clone(),
                source_control_code: Some(0),
                sections: BTreeSet::new(),
                operation,
                on_error: Vec::new(),
                secure_only: false,
            })
            .collect();
        Self {
            program: NormalizedProcedure {
                id,
                steps,
                initial_state: ToolState::default(),
                stamp_output: Default::default(),
            },
            allocations: Vec::new(),
            anchors: [
                (ProcedureCompilationPhase::BeforeFirstStartLoading, 1),
                (ProcedureCompilationPhase::AfterLastCompleteLoading, 1),
                (ProcedureCompilationPhase::BeforeSessionClose, 1),
            ]
            .into_iter()
            .map(|(phase, position)| LifecycleAnchor {
                phase,
                position,
                path: root.clone(),
                session: Some(root.clone()),
            })
            .collect(),
            secure_only: false,
            service: crate::commissioning::procedure::operands::StandardMemoryService::Classic,
            root,
            error: None,
            authored_connection_open: false,
        }
    }

    pub(crate) fn insert_builtin(
        &mut self,
        phase: ProcedureCompilationPhase,
        source: &'static str,
        section: ProgrammingSection,
        secure: bool,
        operation: ProcedureOperation,
    ) {
        self.insert_step(phase, ProcedureStep {
            path: ControlPath { contribution: Some(source), ..self.root.clone() },
            source_control_code: None,
            sections: BTreeSet::from([section]),
            operation,
            on_error: Vec::new(),
            secure_only: self.secure_only || secure,
        });
    }

    pub(crate) fn capture_download_stamps(&mut self) {
        use crate::commissioning::procedure::{DownloadStampOutput, ErrorAction, LoadControlCause};
        if !matches!(self.program.stamp_output, DownloadStampOutput::StagedReads(_)) {
            return;
        }
        let output = std::mem::take(&mut self.program.stamp_output);
        let captured: BTreeSet<_> = self
            .program
            .steps
            .iter()
            .filter_map(|step| match &step.operation {
                ProcedureOperation::ReadIntoImage { capture_as: Some(id), .. } => Some(id.clone()),
                _ => None,
            })
            .collect();
        for stamp in output.descriptors().iter().filter(|stamp| !captured.contains(&stamp.id)) {
            self.insert_step(ProcedureCompilationPhase::BeforeSessionClose, ProcedureStep {
                path: ControlPath { contribution: Some("download-stamp-capture"), ..self.root.clone() },
                source_control_code: None,
                sections: BTreeSet::new(),
                operation: ProcedureOperation::ReadIntoImage {
                    target: stamp.read.target.clone(),
                    image_location: ImageLocation {
                        space: ImageSpace::Pointer { resource_id: stamp.id.clone() },
                        offset: 0,
                    },
                    extent: stamp.read.extent,
                    cache: CachePolicy::Bypass,
                    capture_as: Some(stamp.id.clone()),
                },
                // Published System 7 products may omit an advertised stamp;
                // definite property absence must not undo a completed load.
                on_error: vec![ErrorHandler { cause: LoadControlCause::ResourceNotFound, action: ErrorAction::Ignore }],
                secure_only: self.secure_only,
            });
        }
        self.program.stamp_output = output;
    }

    fn insert_step(&mut self, phase: ProcedureCompilationPhase, mut step: ProcedureStep) {
        let Some(anchor) = self.anchors.iter().find(|anchor| anchor.phase == phase) else {
            self.error.get_or_insert_with(|| {
                CompileError::at(
                    &self.root,
                    "builtin feature requires a lifecycle boundary absent from the selected procedure",
                )
            });
            return;
        };
        let mut path = anchor.path.child(usize::MAX).child(self.program.steps.len());
        path.contribution = step.path.contribution;
        if step.operation.requires_management_session() && anchor.session.is_none() {
            self.error.get_or_insert_with(|| {
                CompileError::at(&path, "builtin feature requires an authored management session")
            });
            return;
        }
        let position = anchor.position;
        step.path = path;
        self.program.steps.insert(position, step);
        self.shift_positions_after_insert(position);
    }

    fn shift_positions_after_insert(&mut self, position: usize) {
        // All three anchors move together. Repeated emissions at one boundary
        // retain feature order without sorting a second copy of the program.
        for anchor in &mut self.anchors {
            if anchor.position >= position {
                anchor.position += 1;
            }
        }
        for allocation in &mut self.allocations {
            if allocation.step >= position {
                allocation.step += 1;
            }
        }
    }

    pub(crate) fn finish(
        mut self,
        profile: &ResolvedProfile,
        image: &SparseDeviceImage,
        download: bool,
    ) -> Result<NormalizedProcedure, CompileError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        for allocation in self.allocations {
            let space = ImageSpace::RelativeMemory { object: allocation.object };
            let maximum = image.end_offset(&space).unwrap_or(0);
            let segment = RelSegment {
                requested_memory_size: allocation.segment.requested_memory_size.max(maximum),
                ..allocation.segment
            };
            let ProcedureOperation::LoadRecord(record) = &mut self.program.steps[allocation.step].operation else {
                unreachable!("allocation binding owns its record")
            };
            record.bytes = LoadControlRecord::rel_segment(&segment).to_vec();
            record.effect = crate::commissioning::procedure::LoadEffect::Invalidate {
                location: ImageLocation { space, offset: 0 },
                length: segment.requested_memory_size,
            };
        }
        for mut step in std::mem::take(&mut self.program.steps) {
            if let ProcedureOperation::Write { target, data, extent, .. } = &mut step.operation {
                if let OperationTarget::ImageMemory(location) = target {
                    let OperationData::ImageWindow { maximum, .. } = data else {
                        return Err(CompileError::at(
                            &step.path,
                            "unbound image memory target requires an image window",
                        ));
                    };
                    let Some(length) = image_extent(image, location, *maximum, &step.path)? else { continue };
                    *target = memory::memory_target(profile, self.service, location, length, &step.path)?;
                    *extent = OperationExtent::bytes(length);
                }
                if let OperationData::Buffer { location, length, fallback } = data {
                    if image.require_range(location, *length).is_ok() {
                        *fallback = None;
                    } else if let Some(bytes) = fallback {
                        // An inline property default applies only when the
                        // image cannot supply its complete declared value.
                        if bytes.len() < extent.byte_length as usize {
                            return Err(CompileError::at(
                                &step.path,
                                format!(
                                    "WriteProp InlineData has only {} bytes but {} elements require {}",
                                    bytes.len(),
                                    extent.property_elements.unwrap_or(1),
                                    extent.byte_length
                                ),
                            ));
                        }
                        bytes.truncate(extent.byte_length as usize);
                        *data = OperationData::Inline(std::mem::take(bytes));
                    } else {
                        image
                            .require_range(location, *length)
                            .map_err(|error| CompileError::from(error).with_path(&step.path))?;
                    }
                }
                let range = match data {
                    OperationData::Image { location, length } | OperationData::Buffer { location, length, .. } => {
                        Some((location, *length))
                    }
                    OperationData::ImageWindow { location, maximum } => Some((location, *maximum)),
                    _ => None,
                };
                if let Some((location, length)) = range {
                    // Authored writes derive ownership from the final image.
                    // Builtins retain their declared section as well, even
                    // when an image transfer spans another section's bytes.
                    if step.path.contribution.is_none() {
                        step.sections.clear();
                    }
                    step.sections.extend(image.sections_for_range(location, length));
                }
            }
            self.program.steps.push(step);
        }
        self.program.validate()?;
        // Validate the authored program before adding cleanup: an implicit
        // disconnect must not make an unclosed source procedure acceptable.
        if download && self.authored_connection_open && profile.retain_final_disconnect() {
            self.program.steps.push(ProcedureStep {
                path: ControlPath { contribution: Some("automatic-session-close"), ..self.root },
                source_control_code: None,
                sections: BTreeSet::new(),
                operation: ProcedureOperation::Disconnect,
                on_error: Vec::new(),
                secure_only: false,
            });
        }
        Ok(self.program)
    }
}

pub(super) fn image_extent(
    image: &SparseDeviceImage,
    location: &ImageLocation,
    maximum: u32,
    path: &ControlPath,
) -> Result<Option<u32>, CompileError> {
    if maximum == 0 {
        return Ok(None);
    }
    let end = location
        .offset
        .checked_add(maximum)
        .ok_or_else(|| CompileError::at(path, "image-backed control range exceeds the 32-bit address space"))?;
    Ok(image
        .ranges()
        .filter(|range| {
            range.location.space == location.space
                && range.location.offset < end
                && range.location.offset + range.length > location.offset
        })
        .map(|range| (range.location.offset + range.length).min(end) - location.offset)
        .max())
}

#[cfg(test)]
mod tests;
