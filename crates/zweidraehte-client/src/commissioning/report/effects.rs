//! Physical effects belong to execution, independently of progress subscribers.

use crate::commissioning::compiler::credentials::CredentialTransition;
use crate::commissioning::error::MutationStatus;
use crate::commissioning::report::AddressAssignment;
use std::collections::BTreeSet;
use zweidraehte_project::ProgrammingSection;
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::messages::apdu::restart::EraseCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEffects {
    mutation_status: MutationStatus,
    affected_sections: BTreeSet<ProgrammingSection>,
    cleared_sections: BTreeSet<ProgrammingSection>,
    group_keys_erased: bool,
    credential_transitions: Vec<CredentialTransition>,
    group_key_exposures: BTreeSet<GroupAddress>,
    address_assignment: Option<AddressAssignment>,
    network_configuration_performed: bool,
}

impl Default for ExecutionEffects {
    fn default() -> Self {
        Self {
            mutation_status: MutationStatus::NotStarted,
            affected_sections: BTreeSet::new(),
            cleared_sections: BTreeSet::new(),
            group_keys_erased: false,
            credential_transitions: Vec::new(),
            group_key_exposures: BTreeSet::new(),
            address_assignment: None,
            network_configuration_performed: false,
        }
    }
}

impl ExecutionEffects {
    pub fn mutation_status(&self) -> MutationStatus {
        self.mutation_status
    }
    pub fn affected_sections(&self) -> &BTreeSet<ProgrammingSection> {
        &self.affected_sections
    }
    pub fn cleared_sections(&self) -> &BTreeSet<ProgrammingSection> {
        &self.cleared_sections
    }
    pub fn group_keys_erased(&self) -> bool {
        self.group_keys_erased
    }
    pub fn credential_transitions(&self) -> &[CredentialTransition] {
        &self.credential_transitions
    }
    pub fn group_key_exposures(&self) -> &BTreeSet<GroupAddress> {
        &self.group_key_exposures
    }
    pub fn address_assignment(&self) -> Option<AddressAssignment> {
        self.address_assignment
    }
    pub fn network_configuration_performed(&self) -> bool {
        self.network_configuration_performed
    }

    pub fn learned_target(&self) -> Option<crate::commissioning::error::LearnedTarget> {
        self.address_assignment.map(|assignment| crate::commissioning::error::LearnedTarget {
            address: assignment.current,
            serial_number: assignment.serial_number,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_status(status: MutationStatus) -> Self {
        Self { mutation_status: status, ..Self::default() }
    }

    pub(in crate::commissioning) fn begin(&mut self) {
        if self.mutation_status == MutationStatus::NotStarted {
            self.mutation_status = MutationStatus::NoConfirmedMutation;
        }
    }
    pub(in crate::commissioning) fn record_mutation(&mut self) {
        self.cleared_sections.clear();
        self.mutation_status = MutationStatus::PartiallyApplied;
    }
    pub(crate) fn record_sections(&mut self, sections: impl IntoIterator<Item = ProgrammingSection>) {
        self.affected_sections.extend(sections);
    }
    pub(crate) fn confirm_address(&mut self, assignment: AddressAssignment) {
        self.address_assignment = Some(assignment);
        self.affected_sections.insert(ProgrammingSection::Address);
    }
    pub(crate) fn record_credentials(&mut self, transitions: impl IntoIterator<Item = CredentialTransition>) {
        for transition in transitions {
            if !self.credential_transitions.contains(&transition) {
                self.credential_transitions.push(transition);
            }
        }
    }
    pub(in crate::commissioning) fn expose_group_keys(&mut self, groups: impl IntoIterator<Item = GroupAddress>) {
        for group in groups {
            self.group_keys_erased = false;
            self.group_key_exposures.insert(group);
        }
    }
    pub(in crate::commissioning) fn confirm_section_erasure(&mut self, section: ProgrammingSection) {
        self.cleared_sections.insert(section);
    }
    pub(in crate::commissioning) fn record_network_configuration(&mut self, performed: bool) {
        self.network_configuration_performed = performed;
    }
    pub(in crate::commissioning) fn complete(&mut self) {
        self.mutation_status = MutationStatus::Complete;
    }

    /// Record erasure only after the reset acknowledgement and connection close.
    /// Channel-specific resets cannot establish whole-device section erasure.
    pub(crate) fn confirm_reset(&mut self, code: EraseCode, channel: u8) {
        use ProgrammingSection::*;
        if channel != 0 {
            return;
        }
        let sections: &[ProgrammingSection] = match code {
            EraseCode::FactoryReset => {
                &[Address, ApplicationProgram1, ApplicationProgram2, Parameters, GroupCommunication, Configuration]
            }
            EraseCode::FactoryResetKeepIA => {
                &[ApplicationProgram1, ApplicationProgram2, Parameters, GroupCommunication, Configuration]
            }
            EraseCode::ResetIA => &[Address],
            EraseCode::ResetAP => &[ApplicationProgram1, ApplicationProgram2],
            EraseCode::ResetParam => &[Parameters],
            EraseCode::ResetLinks => &[GroupCommunication],
            _ => &[],
        };
        if sections.contains(&Address) {
            self.address_assignment = None;
        }
        self.cleared_sections.extend(sections);
        self.affected_sections.extend(sections);
        if code.is_factory_reset() {
            self.group_keys_erased = true;
            self.group_key_exposures.clear();
        }
    }
}
