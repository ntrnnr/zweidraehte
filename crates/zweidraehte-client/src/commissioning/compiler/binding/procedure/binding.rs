//! Finalize only operands whose geometry depends on the desired image.

use super::*;
use crate::commissioning::error::CompileError;
use crate::commissioning::image::ImageSpace;
use crate::commissioning::procedure::ErrorHandler;
use zweidraehte_proto::messages::apdu::load_control::{LoadControlRecord, RelSegment};

#[derive(Debug, Clone)]
pub(super) struct RelativeAllocation {
    pub step: usize,
    pub object: crate::commissioning::catalog::profile::ObjectSelector,
    pub segment: RelSegment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AutomaticSession {
    Unprepared,
    Deferred,
    Framed,
}

/// The canonical program is retained while a few image operands remain pending.
/// Source XML, choices, merge trees and profiles do not survive parsing.
#[derive(Debug, Clone)]
pub(crate) struct ParsedProcedure {
    pub(crate) program: NormalizedProcedure,
    pub(super) allocations: Vec<RelativeAllocation>,
    pub(super) anchors: Vec<LifecycleAnchor>,
    pub(super) service: crate::commissioning::procedure::operands::StandardMemoryService,
    pub(super) root: ControlPath,
    pub(super) error: Option<CompileError>,
    pub(super) authored_connection_open: bool,
    pub(super) authored_session_controls: bool,
    pub(super) automatic_session_start: Option<usize>,
    pub(super) automatic_session: AutomaticSession,
    pub(super) feature_restart: Option<(crate::commissioning::procedure::RestartKind, ProgrammingSection)>,
    pub(super) security_block_precedes_unload: bool,
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
                (ProcedureCompilationPhase::NativeSecurityUnload, 1),
                (ProcedureCompilationPhase::NativeSecurityLoad, 1),
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
            service: crate::commissioning::procedure::operands::StandardMemoryService::Classic,
            root,
            error: None,
            authored_connection_open: false,
            authored_session_controls: false,
            automatic_session_start: None,
            automatic_session: AutomaticSession::Unprepared,
            feature_restart: None,
            security_block_precedes_unload: false,
        }
    }

    /// Frame selected download sources which supply no session controls.
    /// Selection records activity before automatic partial controls disappear.
    pub(crate) fn add_automatic_download_session(&mut self) {
        if self.authored_session_controls || self.automatic_session != AutomaticSession::Unprepared {
            return;
        }
        let Some(position) = self.automatic_session_start.take() else {
            // A configuration-only source can be empty or passive. Native IP
            // tasks still append controls to it; their eventual activity, not
            // an invented application recipe, establishes the session.
            self.automatic_session = AutomaticSession::Deferred;
            self.anchors.push(LifecycleAnchor {
                phase: ProcedureCompilationPhase::BeforeSessionClose,
                position: self.program.steps.len(),
                path: self.root.clone(),
                session: None,
            });
            return;
        };
        self.frame_automatic_session(position);
    }

    fn frame_automatic_session(&mut self, position: usize) {
        self.automatic_session = AutomaticSession::Framed;
        let path = ControlPath { contribution: Some("automatic-session-open"), ..self.root.clone() };
        self.program.steps.insert(position, ProcedureStep {
            path: path.clone(),
            source_control_code: None,
            sections: BTreeSet::new(),
            operation: ProcedureOperation::Connect,
            on_error: Vec::new(),
            secure_only: false,
        });
        self.shift_positions_after_insert(position);
        for anchor in &mut self.anchors {
            if anchor.position > position {
                anchor.session = Some(path.clone());
            }
        }
        self.anchors.push(LifecycleAnchor {
            phase: ProcedureCompilationPhase::BeforeSessionClose,
            position: self.program.steps.len(),
            path: path.clone(),
            session: Some(path),
        });
        self.program.steps.push(ProcedureStep {
            path: ControlPath { contribution: Some("automatic-session-close"), ..self.root.clone() },
            source_control_code: None,
            sections: BTreeSet::new(),
            operation: ProcedureOperation::Disconnect,
            on_error: Vec::new(),
            secure_only: false,
        });
    }

    /// Image contributors can require a terminal even without authored controls.
    pub(crate) fn require_feature_restart(
        &mut self,
        kind: crate::commissioning::procedure::RestartKind,
        section: ProgrammingSection,
    ) {
        self.feature_restart = Some((kind, section));
    }

    fn finalize_feature_lifecycle(&mut self) {
        if let Some((kind, section)) = self.feature_restart
            && !self.program.steps.iter().any(|step| {
                matches!(
                    step.operation,
                    ProcedureOperation::Restart { .. } | ProcedureOperation::MasterReset { erase_code: 1, .. }
                )
            })
        {
            // Image finalization precedes session correction. A feature's
            // restart precedes the last disconnect, or follows an unframed
            // source. Existing restarts and erase-code-1 resets already meet
            // this requirement and retain their metadata.
            let position = self
                .program
                .steps
                .iter()
                .rposition(|step| matches!(step.operation, ProcedureOperation::Disconnect))
                .unwrap_or(self.program.steps.len());
            self.program.steps.insert(position, ProcedureStep {
                path: ControlPath { contribution: Some("feature-required-restart"), ..self.root.clone() },
                source_control_code: None,
                sections: BTreeSet::from([section]),
                operation: ProcedureOperation::Restart { kind },
                on_error: Vec::new(),
                secure_only: false,
            });
            self.shift_positions_after_insert(position);
        }

        if self.automatic_session == AutomaticSession::Deferred {
            // Leading passive controls remain outside the generated session.
            // With no generated activity, an empty/delay-only plan stays so.
            let position = self.program.steps.iter().position(|step| {
                !matches!(
                    step.operation,
                    ProcedureOperation::Delay { .. }
                        | ProcedureOperation::SetControlVariable { .. }
                        | ProcedureOperation::MapError { .. }
                        | ProcedureOperation::ClearCache
                        | ProcedureOperation::ProgressText(_)
                        | ProcedureOperation::DeclarePropertyDescriptor { .. }
                )
            });
            if let Some(position) = position {
                self.anchors.retain(|anchor| anchor.phase != ProcedureCompilationPhase::BeforeSessionClose);
                self.frame_automatic_session(position);
            }
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
        self.insert_builtin_with_handlers(phase, source, section, secure, operation, Vec::new());
    }

    pub(crate) fn insert_builtin_with_handlers(
        &mut self,
        phase: ProcedureCompilationPhase,
        source: &'static str,
        section: ProgrammingSection,
        secure: bool,
        operation: ProcedureOperation,
        on_error: Vec<ErrorHandler>,
    ) {
        self.insert_step(phase, ProcedureStep {
            path: ControlPath { contribution: Some(source), ..self.root.clone() },
            source_control_code: None,
            sections: BTreeSet::from([section]),
            operation,
            on_error,
            // Feature controls declare their own security requirement. The
            // credential used to open a session does not make every operation
            // in that session intrinsically secure-only.
            secure_only: secure,
        });
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
        if step.operation.requires_management_session()
            && anchor.session.is_none()
            && self.automatic_session != AutomaticSession::Deferred
        {
            self.error.get_or_insert_with(|| {
                CompileError::at(&path, "builtin feature requires an authored management session")
            });
            return;
        }
        let position = anchor.position;
        step.path = path;
        self.program.steps.insert(position, step);
        self.shift_positions_after_insert_at_phase(position, Some(phase));
    }

    fn shift_positions_after_insert(&mut self, position: usize) {
        self.shift_positions_after_insert_at_phase(position, None);
    }

    fn shift_positions_after_insert_at_phase(
        &mut self,
        position: usize,
        inserted_phase: Option<ProcedureCompilationPhase>,
    ) {
        // Repeated emissions preserve order at their boundary. Security cursors
        // additionally retain the native tie order when final omissions map
        // two distinct source boundaries onto the same output position.
        for anchor in &mut self.anchors {
            let security_tie = self.security_block_precedes_unload
                && inserted_phase == Some(ProcedureCompilationPhase::NativeSecurityUnload)
                && anchor.phase == ProcedureCompilationPhase::NativeSecurityLoad
                && anchor.position == position;
            if anchor.position >= position && !security_tie {
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
        self.finalize_feature_lifecycle();
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
        let mut loaded_ranges = Vec::new();
        for mut step in std::mem::take(&mut self.program.steps) {
            if let ProcedureOperation::Compare {
                target: OperationTarget::Property { .. },
                comparison:
                    crate::commissioning::procedure::Comparison::Exact {
                        data: OperationData::Buffer { location, length, fallback: Some(reference) },
                        ..
                    },
                ..
            } = &mut step.operation
            {
                // Property comparisons overlay image-owned bits on the XML
                // reference. Unowned bits keep that reference; unlike a write,
                // preparing this comparison must not read the device value.
                // The buffer still permits a later working-image observation
                // to override this initial reference at execution time.
                for (index, value) in reference.iter_mut().take(*length as usize).enumerate() {
                    let offset = location.offset.checked_add(index as u32).ok_or_else(|| {
                        CompileError::at(&step.path, "property comparison image range exceeds 32 bits")
                    })?;
                    let cell = ImageLocation { space: location.space.clone(), offset };
                    if let Some((data, mask)) = image.byte(&cell) {
                        *value = (*value & !mask) | (data & mask);
                    }
                }
            }
            if let ProcedureOperation::LoadImage { image_location, extent, .. } = &step.operation {
                // A successful read can own bytes absent from the static image.
                // Even a guarded/ignored read can succeed, so retain dependent
                // writes; the executor selects their actual ownership later.
                loaded_ranges.push((image_location.clone(), extent.byte_length));
            }
            if let ProcedureOperation::Write { target, data, extent, .. } = &mut step.operation {
                if let OperationTarget::ImageMemory(location) = target {
                    let OperationData::ImageWindow { maximum, .. } = data else {
                        return Err(CompileError::at(
                            &step.path,
                            "unbound image memory target requires an image window",
                        ));
                    };
                    let mut length = image_extent(image, location, *maximum, &step.path)?;
                    let end = location.offset.checked_add(*maximum).ok_or_else(|| {
                        CompileError::at(&step.path, "image-backed control range exceeds the 32-bit address space")
                    })?;
                    for (loaded, count) in &loaded_ranges {
                        let loaded_end = loaded.offset.checked_add(*count).ok_or_else(|| {
                            CompileError::at(&step.path, "working-image read range exceeds the 32-bit address space")
                        })?;
                        if *count != 0
                            && *maximum != 0
                            && loaded.space == location.space
                            && loaded.offset < end
                            && location.offset < loaded_end
                        {
                            length = Some(length.unwrap_or(0).max(loaded_end.min(end) - location.offset));
                        }
                    }
                    let Some(length) = length else { continue };
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
