//! Evaluated device data, requested operation and supplied observations.

use crate::commissioning::compiler::ProgramCompiler;
use crate::commissioning::input::facts::ProgrammingFacts;
use crate::commissioning::input::security::DesiredDataSecurity;
use crate::commissioning::{CompileError, CompiledProgram, ProfileSelection, ProgramImage};
use crate::configuration::MaterializedDevice;
use std::collections::BTreeMap;
mod intent;
pub use intent::{
    CommissioningIntent, DownloadMode, ProgramSections, ProgrammingModePolling, TargetSelection, UnloadMode,
};

#[derive(Debug, Clone)]
pub struct ProgrammingInput {
    pub(crate) device: MaterializedDevice,
    pub(crate) intent: CommissioningIntent,
    pub(crate) options: CompileOptions,
    pub(crate) facts: ProgrammingFacts,
    pub(crate) desired_data_security: DesiredDataSecurity,
}

impl ProgrammingInput {
    /// Build the desired public image without accessing a device.
    pub fn preview(&self, selection: &ProfileSelection) -> Result<ProgramImage, CompileError> {
        ProgramCompiler::new(self, selection)?.preview()
    }

    /// Compile an inspectable program from supplied facts, without device I/O.
    pub fn compile(&self, selection: &ProfileSelection) -> Result<CompiledProgram, CompileError> {
        ProgramCompiler::new(self, selection)?.compile()
    }

    /// Compile for offline inspection with the exact bytes of prepared writes.
    pub fn compile_with_payloads(
        &self,
        selection: &ProfileSelection,
    ) -> Result<super::inspection::CompiledInspection, CompileError> {
        ProgramCompiler::new(self, selection)?.compile_with_secrets().map(super::inspection::CompiledInspection::new)
    }

    pub fn new(device: MaterializedDevice, intent: CommissioningIntent, options: CompileOptions) -> Self {
        let desired_data_security = {
            let updates_security = intent.updates_group_communication();

            if !updates_security {
                DesiredDataSecurity::Preserve
            } else if device.key_material().application_security().is_some() {
                DesiredDataSecurity::Enabled
            } else {
                DesiredDataSecurity::Disabled
            }
        };

        Self { device, intent, options, facts: ProgrammingFacts::default(), desired_data_security }
    }

    pub fn device(&self) -> &MaterializedDevice {
        &self.device
    }
    pub fn intent(&self) -> CommissioningIntent {
        self.intent
    }
    pub fn options(&self) -> &CompileOptions {
        &self.options
    }
    pub fn observed_facts(&self) -> ProgrammingFacts {
        self.facts
    }
    pub fn desired_data_security(&self) -> DesiredDataSecurity {
        self.desired_data_security
    }

    pub fn data_security(mut self, desired: DesiredDataSecurity) -> Self {
        self.desired_data_security = desired;
        self
    }

    pub fn facts(mut self, facts: ProgrammingFacts) -> Self {
        self.facts = facts;
        self
    }
}

pub(crate) mod facts;
pub(crate) mod security;
/// Inputs that cannot be inferred from product or Master Data without
/// reintroducing policy guesses into offline compilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileOptions {
    pub target: TargetSelection,

    /// Sections selected by stamp comparison for `DownloadMode::Automatic`.
    /// It must be absent for explicit full/partial downloads and unloads.
    pub automatic_sections: Option<ProgramSections>,

    pub progress_messages_by_reference: BTreeMap<String, String>,
    pub progress_messages_by_id: BTreeMap<u32, String>,
}
