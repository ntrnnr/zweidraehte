//! Compose complete application procedures before binding their operations.

use super::*;

impl<'a> ProcedureLowerer<'a> {
    pub(super) fn complete_product_controls(
        &self,
    ) -> Result<Option<Vec<(&'a LoadControl, ControlPath)>>, CompileError> {
        let Some(secondary) = self.context.secondary_product_procedure else { return Ok(None) };
        if self.context.composition != ProcedureComposition::ProductOwned {
            return Err(CompileError::at(
                &self.parsed.root,
                "a complete secondary procedure requires a product-owned primary",
            ));
        }
        let product_id =
            self.context.secondary_application_id.expect("a complete secondary procedure has an application");
        let secondary_root = ControlPath {
            procedure: crate::commissioning::procedure::ProcedureSourceId::Product {
                product_id: product_id.to_owned(),
                source_index: 0,
                merge_id: None,
            },
            ..self.parsed.root.clone()
        };
        let mut secondary_controls = Vec::new();
        self.select_complete_controls(&secondary.controls, &secondary_root, false, &mut secondary_controls)?;
        let mut primary_controls = Vec::new();
        self.select_complete_controls(self.context.controls, &self.parsed.root, true, &mut primary_controls)?;

        // Native composition starts with the secondary's complete procedure.
        // Primary unloads splice after its last unload (or first connect),
        // while all other primary controls append. Session correction then
        // removes the adjacent secondary disconnect / primary connect pair.
        // Keep original paths: reordering must not rename controls or errors.
        let insertion = secondary_controls
            .iter()
            .rposition(|(control, _)| matches!(control, LoadControl::LdCtrlUnload(_)))
            .or_else(|| {
                secondary_controls.iter().position(|(control, _)| matches!(control, LoadControl::LdCtrlConnect(_)))
            })
            .map_or(0, |index| index + 1);
        let (unloads, remaining): (Vec<_>, Vec<_>) =
            primary_controls.into_iter().partition(|(control, _)| matches!(control, LoadControl::LdCtrlUnload(_)));
        secondary_controls.splice(insertion..insertion, unloads);
        secondary_controls.extend(remaining);
        Ok(Some(secondary_controls))
    }

    fn select_complete_controls(
        &self,
        controls: &'a [LoadControl],
        parent: &ControlPath,
        primary: bool,
        selected: &mut Vec<(&'a LoadControl, ControlPath)>,
    ) -> Result<(), CompileError> {
        for (index, control) in controls.iter().enumerate() {
            if primary && parent.control_indices.is_empty() && self.context.omitted_controls.contains(&index) {
                continue;
            }
            let path = parent.child(index);
            if let LoadControl::Choose(choice) = control {
                if let Some(branch) = self.selected_branch(choice, &path)? {
                    self.select_complete_controls(
                        &choice.when[branch].controls,
                        &path.child(branch),
                        primary,
                        selected,
                    )?;
                }
            } else {
                let metadata = control_metadata(control).expect("a non-choice control has metadata");
                if self.control_applies(metadata.applies_to, &path)? {
                    selected.push((control, path));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::compiler::binding::procedure::test_support::minimal_profile;
    use crate::commissioning::procedure::ProcedureSourceId;
    use crate::commissioning::procedure::operands::StandardMemoryService;
    use zweidraehte_ets_files::schema::{
        LdCtrlConnect, LdCtrlDelay, LdCtrlDisconnect, LdCtrlTaskSegment, LdCtrlUnload,
    };

    #[test]
    fn complete_product_composition_preserves_unload_order_sessions_and_source_paths() {
        let profile = minimal_profile();
        for secondary_unload in [false, true] {
            let primary = vec![
                LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: Some(1), ..Default::default() }),
                LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 11, ..Default::default() }),
                LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
            ];
            let mut secondary =
                LoadProcedure { merge_id: None, controls: vec![LoadControl::LdCtrlConnect(LdCtrlConnect::default())] };
            if secondary_unload {
                secondary
                    .controls
                    .push(LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: Some(4), ..Default::default() }));
            }
            secondary.controls.extend([
                LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 22, ..Default::default() }),
                LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment {
                    lsm_idx: Some(4),
                    address: 0x4000,
                    ..Default::default()
                }),
                LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
            ]);
            let input = ProcedureInput {
                profile: &profile,
                procedure_id: ProcedureSourceId::Product {
                    product_id: "primary".to_owned(),
                    source_index: 0,
                    merge_id: None,
                },
                composition: ProcedureComposition::ProductOwned,
                controls: &primary,
                product_merge_fragments: Vec::new(),
                secondary_merge_fragments: Vec::new(),
                secondary_product_procedure: Some(&secondary),
                secondary_application_id: Some("secondary"),
                module_procedures_are_empty: true,
                module_procedures: Vec::new(),
                omitted_controls: Vec::new(),
                parameter_values: &BTreeMap::new(),
                applicability: ProcedureApplicability::full(),
                configuration_anchor: profile.configuration_anchor(),
                download_stamps: Vec::new(),
                property_parameters: &[],
                peiprog_identity_reference: false,
                application_program_2_present: true,
                progress_messages_by_reference: &BTreeMap::new(),
                progress_messages_by_id: &BTreeMap::new(),
                message_sources: Vec::new(),
                initial_tool_state: ToolState::default(),
                standard_memory_service: StandardMemoryService::Classic,
                restart_kind: RestartKind::Basic,
                application_identity: ApplicationIdentity::default(),
                secondary_application_identity: Some(ApplicationIdentity {
                    application_id: [1, 2, 3, 4, 0xf1],
                    pei_type: 17,
                }),
                extended_property_descriptions: false,
            };
            let mut parsed = parse(&input).expect("complete application procedures compose");
            parsed.correct_session_anomalies();
            let steps = &parsed.program.steps;
            assert_eq!(steps.iter().filter(|s| matches!(s.operation, ProcedureOperation::Connect)).count(), 1);
            assert_eq!(steps.iter().filter(|s| matches!(s.operation, ProcedureOperation::Disconnect)).count(), 1);
            let primary_unload = steps
                .iter()
                .position(|s| s.path.procedure == input.procedure_id && s.path.control_indices == [1])
                .expect("primary unload keeps its source path");
            let delays: Vec<_> = steps
                .iter()
                .enumerate()
                .filter_map(|(i, s)| match s.operation {
                    ProcedureOperation::Delay { .. } => Some((i, &s.path)),
                    _ => None,
                })
                .collect();
            assert_eq!(delays.len(), 2);
            assert!(primary_unload < delays[0].0 && delays[0].0 < delays[1].0);
            assert!(
                matches!(&delays[0].1.procedure, ProcedureSourceId::Product { product_id, .. } if product_id == "secondary")
            );
            assert_eq!(delays[1].1.control_indices, [2]);
            let task = steps
                .iter()
                .find_map(|s| match &s.operation {
                    ProcedureOperation::LoadRecord(record) if record.poll.is_none() => Some(record),
                    _ => None,
                })
                .expect("secondary task announcement");
            assert_eq!(
                task.bytes,
                zweidraehte_proto::messages::apdu::load_control::LoadControlRecord::task_segment(0x4000, 17, [
                    1, 2, 3, 4, 0xf1
                ])
            );
            if secondary_unload {
                assert!(
                    matches!(&steps[1].path.procedure, ProcedureSourceId::Product { product_id, .. } if product_id == "secondary")
                );
                assert_eq!(primary_unload, 2);
            } else {
                assert_eq!(primary_unload, 1);
            }
        }
    }
}
