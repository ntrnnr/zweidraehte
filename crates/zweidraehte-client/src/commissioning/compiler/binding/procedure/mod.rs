//! Select source choices and merges while binding canonical control operands.
//! The same traversal retains authored paths, handlers, and feature boundaries.

use crate::commissioning::catalog::profile::{DeclaredProperty, ResolvedProfile};
#[cfg(test)]
use crate::commissioning::compiler::features::ModuleProcedureFragment;
use crate::commissioning::compiler::features::ProcedureCompilationPhase;
use crate::commissioning::compiler::selection::syntax::{
    control_metadata, control_variable, decode_optional_hex, load_machine_target, lower_error_handlers, machine_object,
    object_selector, parameter_test_matches,
};
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageLocation, SparseDeviceImage};
use crate::commissioning::input::ProgramSections;
use crate::commissioning::procedure::{AppliesToScope, parse_applies_to_token};
use crate::commissioning::procedure::{
    CachePolicy, ControlPath, ControlVariable, FunctionPropertyOperation, LoadMachineTarget, LoadRecord,
    MemoryTransfer, NormalizedProcedure, OperationData, OperationExtent, OperationTarget, ProcedureOperation,
    ProcedureStep, RestartKind, ToolState, WriteIntent,
};
use std::collections::{BTreeMap, BTreeSet};
use zweidraehte_ets_files::product::{ApplicationIdentity, ProductData};
use zweidraehte_project::ProgrammingSection;

pub(crate) use binding::ParsedProcedure;
use binding::RelativeAllocation;
use zweidraehte_ets_files::schema::{LdCtrlWriteMem, LoadControl, LoadProcedure};

/// Borrowed source and product facts consumed by the single control traversal.
#[derive(Debug)]
pub(in crate::commissioning) struct ProcedureInput<'a> {
    pub profile: &'a ResolvedProfile,
    pub procedure_id: crate::commissioning::procedure::ProcedureSourceId,
    pub composition: ProcedureComposition,
    pub controls: &'a [LoadControl],
    pub product_merge_fragments: Vec<&'a LoadProcedure>,
    /// Fragments of the relation's secondary PEI Program. Each splices after
    /// the primary application's fragment for the same merge point.
    pub secondary_merge_fragments: Vec<&'a LoadProcedure>,
    /// Application program ID of the secondary PEI Program, when bound.
    pub secondary_application_id: Option<&'a str>,
    pub omitted_controls: Vec<usize>,
    pub parameter_values: &'a BTreeMap<String, crate::configuration::ProcedureParameter>,
    pub applicability: ProcedureApplicability,
    pub configuration_anchor: crate::commissioning::catalog::rules::ConfigurationAnchorPolicy,
    pub download_stamps: Vec<crate::commissioning::procedure::StampDescriptor>,
    pub property_parameters: &'a [zweidraehte_ets_files::product::PropertyParameterLocation],
    // A validated legacy control can reference PeiprogId without loading a
    // separate secondary application definition.
    pub peiprog_identity_reference: bool,
    pub application_program_2_present: bool,
    pub progress_messages_by_reference: &'a BTreeMap<String, String>,
    pub progress_messages_by_id: &'a BTreeMap<u32, String>,
    /// Applications whose own messages resolve a `MessageRef` the caller
    /// supplies no text for: the primary, then a bound secondary.
    pub message_sources: Vec<&'a ProductData>,
    pub initial_tool_state: ToolState,
    pub standard_memory_service: crate::commissioning::procedure::operands::StandardMemoryService,
    pub restart_kind: RestartKind,
    pub application_identity: ApplicationIdentity,
    /// Identity of the bound secondary PEI Program, written to `PeiprogId`.
    pub secondary_application_identity: Option<ApplicationIdentity>,
    /// Whether the product admits extended property services, so that a
    /// type-addressed property description can be read by object type
    /// when the connection carries more than 15 octets.
    pub extended_property_descriptions: bool,
}

#[cfg(test)]
pub(in crate::commissioning) fn lower_procedure(
    context: &ProcedureInput<'_>,
    image: &SparseDeviceImage,
    extensions: Vec<ModuleProcedureFragment>,
) -> Result<NormalizedProcedure, CompileError> {
    lower_procedure_with_tables(context, image, extensions, &[])
}

#[cfg(test)]
pub(in crate::commissioning) fn lower_procedure_with_tables(
    context: &ProcedureInput<'_>,
    image: &SparseDeviceImage,
    extensions: Vec<ModuleProcedureFragment>,
    table_spans: &[crate::commissioning::compiler::image::CompiledTableSpan],
) -> Result<NormalizedProcedure, CompileError> {
    let mut parsed = parse(context)?;
    for fragment in extensions {
        parsed.insert_builtin(
            fragment.phase,
            fragment.source,
            fragment.section,
            fragment.secure_only,
            fragment.operation,
        );
    }
    parsed.finish_with_tables(context.profile, image, table_spans, false)
}

/// An insertion boundary and the authored session which makes it usable.
#[derive(Debug, Clone)]
pub(super) struct LifecycleAnchor {
    phase: ProcedureCompilationPhase,
    position: usize,
    path: ControlPath,
    session: Option<ControlPath>,
}

/// Selected native leaf controls still contribute cursor positions even when
/// final partial processing omits their executable operation.
struct SelectedControlBoundary<'a> {
    control: &'a LoadControl,
    position: usize,
    path: ControlPath,
    session: Option<ControlPath>,
}

pub(super) struct ProcedureLowerer<'a> {
    pub(super) context: &'a ProcedureInput<'a>,
    pub(super) parsed: ParsedProcedure,
    fragments: BTreeMap<u8, &'a LoadProcedure>,
    secondary_fragments: BTreeMap<u8, (usize, &'a LoadProcedure)>,
    used_fragments: BTreeSet<u8>,
    used_secondary_fragments: BTreeSet<u8>,
    inside_fragment: bool,
    sessions: Vec<ControlPath>,
    first_start: Option<LifecycleAnchor>,
    last_complete: Option<LifecycleAnchor>,
    close: Option<LifecycleAnchor>,
    router: Option<LifecycleAnchor>,
    auto_segment_write: bool,
    selected_boundaries: Vec<SelectedControlBoundary<'a>>,
}

pub(in crate::commissioning) fn parse(context: &ProcedureInput<'_>) -> Result<ParsedProcedure, CompileError> {
    ProcedureLowerer::new(context)?.parse()
}

/// Property declarations of the procedure as one download selects it, in
/// procedure order.
///
/// A declaration can follow the write whose geometry it defines, so lowering
/// needs all of them first. This walk makes the same choices, applicability
/// decisions and merge splices as lowering, and nothing else: later partial
/// transformations do not remove a declaration from the procedure.
pub(in crate::commissioning) fn property_declarations<'a>(
    context: &'a ProcedureInput<'a>,
) -> Result<Vec<(DeclaredProperty, &'a str)>, CompileError> {
    let lowerer = ProcedureLowerer::new(context)?;
    let mut declarations = Vec::new();
    let root = lowerer.parsed.root.clone();
    lowerer.collect_declarations(context.controls, &root, false, &mut declarations)?;
    Ok(declarations)
}

impl<'a> ProcedureLowerer<'a> {
    fn new(context: &'a ProcedureInput<'a>) -> Result<Self, CompileError> {
        let parsed = ParsedProcedure {
            program: NormalizedProcedure {
                id: context.procedure_id.clone(),
                initial_state: context.initial_tool_state,
                stamp_output: Default::default(),
                steps: Vec::new(),
            },
            allocations: Vec::new(),
            anchors: Vec::new(),
            service: context.standard_memory_service,
            root: ControlPath {
                mask_id: context.profile.mask().full_id.clone(),
                variant_index: context.profile.variant().source_index,
                procedure: context.procedure_id.clone(),
                contribution: None,
                control_indices: Vec::new(),
            },
            error: None,
            authored_connection_open: false,
            authored_session_controls: false,
            automatic_session_start: None,
            automatic_session: binding::AutomaticSession::Unprepared,
            feature_restart: None,
            security_block_precedes_unload: false,
        };
        let mut fragments = BTreeMap::new();
        for fragment in &context.product_merge_fragments {
            let Some(merge_id) = fragment.merge_id else {
                return Err(CompileError::at(&parsed.root, "product merge fragment has no MergeId"));
            };
            if fragments.insert(merge_id, *fragment).is_some() {
                return Err(CompileError::at(
                    &parsed.root,
                    format!("product defines MergeId {merge_id} more than once"),
                ));
            }
        }
        let mut secondary_fragments = BTreeMap::new();
        for (index, fragment) in context.secondary_merge_fragments.iter().enumerate() {
            let Some(merge_id) = fragment.merge_id else {
                return Err(CompileError::at(&parsed.root, "secondary application fragment has no MergeId"));
            };
            if secondary_fragments.insert(merge_id, (index, *fragment)).is_some() {
                return Err(CompileError::at(
                    &parsed.root,
                    format!("secondary application defines MergeId {merge_id} more than once"),
                ));
            }
        }
        if context.composition != ProcedureComposition::Merged
            && !(fragments.is_empty() && secondary_fragments.is_empty())
        {
            return Err(CompileError::at(&parsed.root, "non-merged procedure was given product merge fragments"));
        }
        Ok(Self {
            context,
            parsed,
            fragments,
            secondary_fragments,
            used_fragments: BTreeSet::new(),
            used_secondary_fragments: BTreeSet::new(),
            inside_fragment: false,
            sessions: Vec::new(),
            first_start: None,
            last_complete: None,
            close: None,
            router: None,
            auto_segment_write: true,
            selected_boundaries: Vec::new(),
        })
    }

    fn parse(mut self) -> Result<ParsedProcedure, CompileError> {
        let root = self.parsed.root.clone();
        self.lower_controls(self.context.controls, &root)?;
        let orphaned: Vec<_> = self.fragments.keys().filter(|id| !self.used_fragments.contains(id)).copied().collect();
        if !orphaned.is_empty() {
            return Err(CompileError::at(
                &root,
                format!("product merge fragments {orphaned:?} have no matching splice point"),
            ));
        }
        let orphaned: Vec<_> =
            self.secondary_fragments.keys().filter(|id| !self.used_secondary_fragments.contains(id)).copied().collect();
        if !orphaned.is_empty() {
            return Err(CompileError::at(
                &root,
                format!("secondary application merge fragments {orphaned:?} have no matching splice point"),
            ));
        }
        let (security_anchors, block_precedes_unload) = self.security_cursor_anchors();
        if let Some(router) = self.router {
            // The 5705 configuration follows its contiguous router writes and
            // must precede a terminal in the same authored session.
            self.close = self
                .close
                .filter(|close| {
                    close.position >= router.position && close.session == router.session && router.session.is_some()
                })
                .map(|_| router);
        }
        self.parsed.security_block_precedes_unload = block_precedes_unload;
        self.parsed.anchors =
            self.first_start.into_iter().chain(self.last_complete).chain(self.close).chain(security_anchors).collect();
        Ok(self.parsed)
    }

    fn lower_controls(&mut self, controls: &'a [LoadControl], parent_path: &ControlPath) -> Result<(), CompileError> {
        for (index, control) in controls.iter().enumerate() {
            if parent_path.control_indices.is_empty() && self.context.omitted_controls.contains(&index) {
                continue;
            }
            let path = parent_path.child(index);
            self.lower_control(control, &path)?;
        }

        Ok(())
    }

    fn lower_control(&mut self, control: &'a LoadControl, path: &ControlPath) -> Result<(), CompileError> {
        if let LoadControl::Choose(choice) = control {
            return self.lower_choice(choice, path);
        }

        // Converted product procedures announce their object table with
        // `LdCtrlTaskSegment`/`LdCtrlLoad LsmIdx="5"` on masks that have no
        // fifth load machine (BCU2 and System 7 among them). The reference
        // drops machine-5 `Load` and `TaskSegment` controls while it reads an
        // application program's procedure unless the mask declares a
        // `GroupObjectTableLoadControl`, so they never reach applicability,
        // session correction or the bus, whatever their annotations.
        // Master Data procedures do not pass through that filter.
        let product_control = self.context.composition == ProcedureComposition::ProductOwned || self.inside_fragment;
        let machine_five = match control {
            LoadControl::LdCtrlLoad(control) => control.lsm_idx == Some(5),
            LoadControl::LdCtrlTaskSegment(control) => control.lsm_idx == Some(5),
            _ => false,
        };
        if product_control
            && machine_five
            && self
                .context
                .profile
                .resource("GroupObjectTableLoadControl")
                .map_err(|error| error.with_path(path))?
                .is_none()
        {
            return Ok(());
        }

        let metadata = control_metadata(control).expect("choice handled above");
        if !self.control_applies(metadata.applies_to, path)? {
            return Ok(());
        }

        // Explicit applicability precedes native session correction. Automatic
        // partial transformations run later, so even an omitted active control
        // can require an otherwise empty management session.
        match control {
            LoadControl::LdCtrlConnect(_)
            | LoadControl::LdCtrlDisconnect(_)
            | LoadControl::LdCtrlRestart(_)
            | LoadControl::LdCtrlMasterReset(_) => self.parsed.authored_session_controls = true,
            LoadControl::LdCtrlMerge(_)
            | LoadControl::LdCtrlMapError(_)
            | LoadControl::LdCtrlDeclarePropDesc(_)
            | LoadControl::LdCtrlDelay(_)
            | LoadControl::LdCtrlSetControlVariable(_)
            | LoadControl::LdCtrlClearCachedObjectTypes(_) => {}
            _ => {
                self.parsed.automatic_session_start.get_or_insert(self.parsed.program.steps.len());
            }
        }

        // Choices and merges flatten before reference feature insertion. Keep
        // leaf positions after explicit applicability but before the final
        // secondary-application and automatic-partial transformations below.
        if !matches!(control, LoadControl::LdCtrlMerge(_)) {
            self.selected_boundaries.push(SelectedControlBoundary {
                control,
                position: self.parsed.program.steps.len(),
                path: path.clone(),
                session: self.sessions.last().cloned(),
            });
        }

        // Final native filtering is independent of automatic transformations.
        // Keep session detection above it, while avoiding operand binding and
        // handlers for controls that never enter the executable procedure.
        if self.omit_absent_secondary_application_control(control) {
            return Ok(());
        }

        // Native Master Data procedures enter as legacy controls marked all.
        // Product procedures and merged product fragments retain auto instead.
        let auto = !self.context.applicability.full
            && product_control
            && metadata.applies_to.unwrap_or("auto").trim() == "auto";
        let transformed = if auto { self.partial_auto_control(control, path)? } else { partial::AutoControl::Keep };
        if matches!(transformed, partial::AutoControl::Omit) {
            return Ok(());
        }

        // A property write without InlineData takes its bytes from the image.
        // When neither a parameter, a resource nor a stamp lays out that
        // property, the image can never hold it and the reference sends
        // nothing for the control. Coupler procedures write every optional
        // router property this way and rely on that skip. Never lower it to a
        // zero-length write: a zero element count clears array properties.
        if let LoadControl::LdCtrlWriteProp(write) = control
            && write.inline_data.is_none()
            && self.property_write_has_no_source(write, path)?
        {
            return Ok(());
        }

        let mut handlers = lower_error_handlers(metadata.on_errors, path)?;

        if let LoadControl::LdCtrlMerge(merge) = control {
            if !handlers.is_empty() {
                return Err(CompileError::at(
                    path,
                    "LdCtrlMerge cannot attach OnError to a non-executable splice point",
                ));
            }

            return self.lower_merge(merge.merge_id, path);
        }

        let position = self.parsed.program.steps.len();
        let (source_code, operation) = if let partial::AutoControl::WriteMemory { address, size } = transformed {
            // The native replacement is a fresh verified WriteMem, with no
            // allocation record or inherited local error handlers.
            let write =
                LoadControl::LdCtrlWriteMem(LdCtrlWriteMem { address, size, verify: true, ..Default::default() });
            handlers.clear();
            (9, self.lower_memory_write(&write, path)?)
        } else {
            (metadata.code.map_err(|error| error.with_path(path))?, self.lower_executable_control(control, path)?)
        };
        if auto
            && let ProcedureOperation::SetControlVariable { variable: ControlVariable::EnableSegmentWrite, value } =
                operation
        {
            // Native finalization tracks only setters themselves marked auto.
            // Its scratch execution context starts with segment writes enabled.
            self.auto_segment_write = value;
        }
        let sections = if operation.mutates_device() {
            application_programming_sections(self.context.applicability.sections)
        } else {
            BTreeSet::new()
        };
        self.parsed.program.steps.push(ProcedureStep {
            path: path.clone(),
            source_control_code: Some(source_code),
            sections,
            operation,
            on_error: handlers,
            secure_only: false,
        });
        self.record_boundary(control, path, position);
        Ok(())
    }

    fn collect_declarations(
        &self,
        controls: &'a [LoadControl],
        parent_path: &ControlPath,
        inside_fragment: bool,
        declarations: &mut Vec<(DeclaredProperty, &'a str)>,
    ) -> Result<(), CompileError> {
        for (index, control) in controls.iter().enumerate() {
            if parent_path.control_indices.is_empty() && self.context.omitted_controls.contains(&index) {
                continue;
            }
            let path = parent_path.child(index);

            match control {
                LoadControl::Choose(choice) => {
                    if let Some(selected) = self.selected_branch(choice, &path)? {
                        let branch_path = path.child(selected);
                        self.collect_declarations(
                            &choice.when[selected].controls,
                            &branch_path,
                            inside_fragment,
                            declarations,
                        )?;
                    }
                }

                // Lowering reports malformed merges; this walk only follows
                // the splices lowering would perform.
                LoadControl::LdCtrlMerge(merge) => {
                    let metadata = control_metadata(control).expect("merge is not a choice");
                    let applies = self.control_applies(metadata.applies_to, &path)?;
                    if applies && !inside_fragment && self.context.composition == ProcedureComposition::Merged {
                        let primary = self.fragments.get(&merge.merge_id).copied();
                        let secondary = self.secondary_fragments.get(&merge.merge_id).map(|(_, fragment)| *fragment);
                        for fragment in primary.into_iter().chain(secondary) {
                            self.collect_declarations(&fragment.controls, &path, true, declarations)?;
                        }
                    }
                }

                LoadControl::LdCtrlDeclarePropDesc(declaration) => {
                    let metadata = control_metadata(control).expect("declaration is not a choice");
                    if self.control_applies(metadata.applies_to, &path)? {
                        let object =
                            object_selector(declaration.obj_idx, declaration.obj_type, declaration.occurrence, &path)?;
                        declarations.push((
                            DeclaredProperty::new(&object, declaration.prop_id),
                            declaration.prop_type.as_str(),
                        ));
                    }
                }

                _ => {}
            }
        }

        Ok(())
    }

    fn lower_choice(
        &mut self,
        choice: &'a zweidraehte_ets_files::schema::LdCtrlChoose,
        path: &ControlPath,
    ) -> Result<(), CompileError> {
        let Some(selected) = self.selected_branch(choice, path)? else { return Ok(()) };
        let branch_path = path.child(selected);
        self.lower_controls(&choice.when[selected].controls, &branch_path)
    }

    /// The branch of a static choice that the current parameter values select.
    fn selected_branch(
        &self,
        choice: &zweidraehte_ets_files::schema::LdCtrlChoose,
        path: &ControlPath,
    ) -> Result<Option<usize>, CompileError> {
        let parameter = self.context.parameter_values.get(&choice.param_ref_id).ok_or_else(|| {
            CompileError::at(path, format!("choose references unresolved parameter {}", choice.param_ref_id))
        })?;

        // An inactive selector supplies no value. In load-control terms that
        // suppresses the whole
        // choice, including a default branch.
        if !parameter.active {
            return Ok(None);
        }
        let value = &parameter.value;

        let mut selected = None;
        let mut default = None;

        for (index, branch) in choice.when.iter().enumerate() {
            if branch.is_default == Some(true) {
                if default.replace(index).is_some() {
                    return Err(CompileError::at(path, "choose has more than one default branch"));
                }
            }

            let Some(test) = branch.test.as_deref() else {
                if branch.is_default != Some(true) {
                    return Err(CompileError::at(
                        &path.child(index),
                        "choose branch has neither a test nor default=\"true\"",
                    ));
                }

                continue;
            };

            let matches =
                parameter_test_matches(value, test).map_err(|message| CompileError::at(&path.child(index), message))?;

            if matches && selected.is_none() {
                selected = Some(index);
            }
        }

        // A choice without a matching or default branch is an explicit
        // no-op in the XSD language, not an unsupported control.
        Ok(selected.or(default))
    }

    fn lower_merge(&mut self, merge_id: u8, path: &ControlPath) -> Result<(), CompileError> {
        if self.context.composition != ProcedureComposition::Merged {
            return Err(CompileError::at(path, format!("unresolved MergeId {merge_id} in a non-merged procedure")));
        }
        if self.inside_fragment {
            return Err(CompileError::at(path, format!("product fragment contains a nested merge {merge_id}")));
        }

        // The reference appends every application slot's fragment for this
        // merge point in slot order: the primary's, then the secondary's.
        if let Some(fragment) = self.fragments.get(&merge_id).copied() {
            self.used_fragments.insert(merge_id);
            self.inside_fragment = true;
            self.lower_controls(&fragment.controls, path)?;
            self.inside_fragment = false;
        }
        if let Some((source_index, fragment)) = self.secondary_fragments.get(&merge_id).copied() {
            self.used_secondary_fragments.insert(merge_id);
            // Keep the splice point's indices but name the secondary source,
            // so its controls never share a path with the primary fragment.
            let product_id = self.context.secondary_application_id.expect("secondary fragments have an application");
            let path = ControlPath {
                procedure: crate::commissioning::procedure::ProcedureSourceId::Product {
                    product_id: product_id.to_owned(),
                    source_index,
                    merge_id: Some(merge_id),
                },
                ..path.clone()
            };
            self.inside_fragment = true;
            self.lower_controls(&fragment.controls, &path)?;
            self.inside_fragment = false;
        }
        Ok(())
    }

    fn control_applies(&self, applies_to: Option<&str>, path: &ControlPath) -> Result<bool, CompileError> {
        let applies_to = applies_to.unwrap_or("auto");
        let mut applies = false;

        // `full` is a download-procedure variant, not the union of every
        // partial variant. Products commonly publish distinct `full` and
        // `par` controls for the same allocation; executing both lets the
        // partial declaration overwrite the full declaration's fill mode.
        for token in applies_to.split(',').map(str::trim) {
            applies |= match parse_applies_to_token(token)
                .ok_or_else(|| CompileError::at(path, format!("unknown AppliesTo token {token:?}")))?
            {
                AppliesToScope::Full => self.context.applicability.full,
                AppliesToScope::ApplicationProgram1 => {
                    !self.context.applicability.full
                        && self.context.applicability.sections.contains(ProgramSections::APPLICATION_PROGRAM_1)
                }
                AppliesToScope::ApplicationProgram2 => {
                    !self.context.applicability.full
                        && self.context.applicability.sections.contains(ProgramSections::APPLICATION_PROGRAM_2)
                }
                AppliesToScope::Parameters => {
                    !self.context.applicability.full
                        && self.context.applicability.sections.contains(ProgramSections::PARAMETERS)
                }
                AppliesToScope::GroupCommunication => {
                    !self.context.applicability.full
                        && self.context.applicability.sections.contains(ProgramSections::GROUP_COMMUNICATION)
                }
                AppliesToScope::Configuration => {
                    !self.context.applicability.full
                        && self.context.applicability.sections.contains(ProgramSections::CONFIGURATION)
                }
                AppliesToScope::All => true,
                AppliesToScope::Automatic => self.context.applicability.automatic,
            };
        }

        Ok(applies)
    }

    fn record_boundary(&mut self, control: &LoadControl, path: &ControlPath, position: usize) {
        use ProcedureCompilationPhase::*;
        let anchor = |phase, position| LifecycleAnchor {
            phase,
            position,
            path: path.clone(),
            session: self.sessions.last().cloned(),
        };
        // A router window extends only through adjacent selected PID 52–55
        // writes; choices and merge markers themselves have no wire boundary.
        if let Some(router) = &mut self.router
            && router.position == position
            && matches!(control, LoadControl::LdCtrlWriteProp(property)
                if property.obj_type == Some(6) && property.obj_idx.is_none()
                    && (52..=55).contains(&property.prop_id))
        {
            router.position += 1;
        }
        match control {
            LoadControl::LdCtrlConnect(_) => {
                self.sessions.push(path.clone());
                self.parsed.authored_connection_open = true;
            }
            LoadControl::LdCtrlLoad(load) => {
                self.first_start.get_or_insert_with(|| anchor(BeforeFirstStartLoading, position));
                if self.context.configuration_anchor
                    == crate::commissioning::catalog::rules::ConfigurationAnchorPolicy::AfterRoutingTableLoad
                    && load.obj_type == Some(6)
                    && load.lsm_idx.is_none()
                {
                    self.router = Some(anchor(BeforeSessionClose, position + 1));
                }
            }
            LoadControl::LdCtrlLoadCompleted(_) => {
                self.last_complete = Some(anchor(AfterLastCompleteLoading, position + 1));
            }
            LoadControl::LdCtrlDisconnect(_) | LoadControl::LdCtrlRestart(_) | LoadControl::LdCtrlMasterReset(_) => {
                if !matches!(control, LoadControl::LdCtrlMasterReset(reset) if reset.erase_code != 1)
                    && !self.sessions.is_empty()
                {
                    self.close = Some(anchor(BeforeSessionClose, position));
                }
                self.sessions.pop();
                // Restart closes only on success. Its ignored failure still
                // needs the final cleanup implied by the authored connection.
                if matches!(control, LoadControl::LdCtrlDisconnect(_)) {
                    self.parsed.authored_connection_open = false;
                }
            }
            _ => {}
        }
    }
}

fn application_programming_sections(sections: ProgramSections) -> BTreeSet<ProgrammingSection> {
    [
        (ProgramSections::APPLICATION_PROGRAM_1, ProgrammingSection::ApplicationProgram1),
        (ProgramSections::APPLICATION_PROGRAM_2, ProgrammingSection::ApplicationProgram2),
        (ProgramSections::PARAMETERS, ProgrammingSection::Parameters),
        (ProgramSections::GROUP_COMMUNICATION, ProgrammingSection::GroupCommunication),
    ]
    .into_iter()
    .filter_map(|(flag, section)| sections.contains(flag).then_some(section))
    .collect()
}

mod binding;
mod controls;
mod memory;
mod partial;
mod properties;
mod property_layout;
mod security;
mod values;

#[cfg(test)]
mod tests;

fn compare_cache_policy(allow_cached_value: Option<bool>) -> CachePolicy {
    // A native compare always records the observed value. AllowCachedValue
    // controls lookup of an earlier value, not population after a fresh read.
    if allow_cached_value.unwrap_or(false) { CachePolicy::UseAndPopulate } else { CachePolicy::Populate }
}

fn operation_data_length(data: &OperationData) -> u32 {
    match data {
        OperationData::Inline(data) => data.len() as u32,
        OperationData::Secret(reference) => reference.byte_length(),
        OperationData::Image { length, .. } | OperationData::Buffer { length, .. } => *length,
        OperationData::ImageWindow { maximum, .. } => *maximum,
    }
}

#[cfg(test)]
pub(in crate::commissioning) mod test_support;
