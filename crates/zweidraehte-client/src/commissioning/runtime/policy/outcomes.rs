//! Translate completed semantic operations into project section outcomes.

use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::image::SparseDeviceImage;
use crate::commissioning::input::{CommissioningIntent, ProgramSections, UnloadMode};
use crate::commissioning::report::CommissioningSectionOutcome;
use std::collections::{BTreeMap, BTreeSet};
use zweidraehte_project::ProgrammingSection;

pub(in crate::commissioning) fn successful_section_outcomes(
    plan: &CompiledProgram,
    programmed_image: &SparseDeviceImage,
    cleared: &BTreeSet<ProgrammingSection>,
) -> BTreeMap<ProgrammingSection, CommissioningSectionOutcome> {
    let intent = plan.intent();
    let mut outcomes = BTreeMap::new();
    if intent.mutates_address() || intent == CommissioningIntent::Unload(UnloadMode::AllConfiguration) {
        outcomes.insert(
            ProgrammingSection::Address,
            if matches!(intent, CommissioningIntent::Unload(_)) {
                if cleared.contains(&ProgrammingSection::Address) {
                    CommissioningSectionOutcome::Cleared
                } else {
                    CommissioningSectionOutcome::Unverified
                }
            } else {
                CommissioningSectionOutcome::Programmed
            },
        );
    }
    let desired = plan.image().manifest();
    let confirmed = programmed_image.manifest();
    let selected = plan.program_sections().unwrap_or_default();
    for (flag, section) in [
        (ProgramSections::APPLICATION_PROGRAM_1, ProgrammingSection::ApplicationProgram1),
        (ProgramSections::APPLICATION_PROGRAM_2, ProgrammingSection::ApplicationProgram2),
        (ProgramSections::PARAMETERS, ProgrammingSection::Parameters),
        (ProgramSections::GROUP_COMMUNICATION, ProgrammingSection::GroupCommunication),
        (ProgramSections::CONFIGURATION, ProgrammingSection::Configuration),
    ] {
        if intent == CommissioningIntent::Unload(UnloadMode::Application)
            && section == ProgrammingSection::Configuration
            && !cleared.contains(&section)
            && !plan
                .procedure()
                .is_some_and(|procedure| procedure.steps.iter().any(|step| step.sections.contains(&section)))
        {
            continue;
        }
        let outcome = if matches!(intent, CommissioningIntent::Unload(_)) {
            if cleared.contains(&section) {
                CommissioningSectionOutcome::Cleared
            } else {
                CommissioningSectionOutcome::Unverified
            }
        } else if !selected.contains(flag) {
            continue;
        } else if desired.sections.get(&section).is_some_and(|digest| confirmed.sections.get(&section) != Some(digest))
        {
            // Compare image-only digests: semantic metadata has no wire bytes,
            // and credential exposure is retained through its separate channel.
            CommissioningSectionOutcome::Unverified
        } else {
            CommissioningSectionOutcome::Programmed
        };
        outcomes.insert(section, outcome);
    }
    outcomes
}
