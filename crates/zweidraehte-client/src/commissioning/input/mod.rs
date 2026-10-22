//! Evaluated device data, requested operation and supplied observations.

use crate::commissioning::compiler::ProgramCompiler;
use crate::commissioning::input::facts::ProgrammingFacts;
use crate::commissioning::input::security::DesiredDataSecurity;
use crate::commissioning::{CompileError, CompiledProgram, ProgramImage, ResolvedProfile};
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
    ///
    /// `profile` must be resolved for this input's product, for example with
    /// [`MaterializedDevice::resolve_profile`].
    pub fn preview(&self, profile: &ResolvedProfile) -> Result<ProgramImage, CompileError> {
        ProgramCompiler::new(self, profile)?.preview()
    }

    /// Compile an inspectable program from supplied facts, without device I/O.
    ///
    /// `profile` must be resolved for this input's product, for example with
    /// [`MaterializedDevice::resolve_profile`].
    pub fn compile(&self, profile: &ResolvedProfile) -> Result<CompiledProgram, CompileError> {
        ProgramCompiler::new(self, profile)?.compile()
    }

    /// Desired Data Secure has one owner: the device's resolved key material.
    /// Application tables enable it and their absence disables it, for every
    /// intent that replaces group communication; other intents preserve the
    /// device's current mode. Callers express "disabled" by resolving no
    /// application tables, never by overriding a derived mode.
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
    pub fn facts(&self) -> ProgrammingFacts {
        self.facts
    }
    pub fn desired_data_security(&self) -> DesiredDataSecurity {
        self.desired_data_security
    }

    pub fn with_facts(mut self, facts: ProgrammingFacts) -> Self {
        self.facts = facts;
        self
    }
}

pub(crate) mod facts;
pub(crate) mod security;
/// Inputs that cannot be inferred from product or Master Data without
/// reintroducing policy guesses into offline compilation.
///
/// A value bag: start from [`CompileOptions::new`] and assign the fields
/// that differ.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CompileOptions {
    pub target: TargetSelection,

    /// Sections selected by stamp comparison for `DownloadMode::Automatic`.
    /// It must be absent for explicit full/partial downloads and unloads.
    pub automatic_sections: Option<ProgramSections>,

    /// Translated progress texts by `MessageRef`. A reference missing here
    /// falls back to the application's own untranslated message.
    pub progress_messages_by_reference: BTreeMap<String, String>,
    pub progress_messages_by_id: BTreeMap<u32, String>,
}

impl CompileOptions {
    /// Options for `target` with no automatic section set and no translated
    /// progress messages.
    pub fn new(target: TargetSelection) -> Self {
        Self {
            target,
            automatic_sections: None,
            progress_messages_by_reference: BTreeMap::new(),
            progress_messages_by_id: BTreeMap::new(),
        }
    }
}
