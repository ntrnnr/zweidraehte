//! Execution progress and outcomes shared with programming frontends.

use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::evidence::DiscoveredDevice;
use crate::commissioning::evidence::{DeviceStamp, DifferentialFallback};
use crate::commissioning::image::SparseDeviceImage;
use crate::commissioning::report::effects::ExecutionEffects;
use std::collections::BTreeMap;
use zweidraehte_project::ProgrammingSection;
use zweidraehte_proto::address::IndividualAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommissioningStage {
    DiscoveringTarget,
    IdentifyingProfile,
    CompilingPlan,
    ValidatingDifferential,
    AssigningAddress,
    BootstrappingSecurity,
    ConfiguringNetwork,
    Verifying,
    Connecting,
    Executing,
    RestoringDeviceState,
    Disconnecting,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommissioningEvent {
    Stage(CommissioningStage),
    TargetDiscovered {
        address: IndividualAddress,
        serial_number: Option<[u8; 6]>,
    },
    AddressAssigned {
        previous: IndividualAddress,
        current: IndividualAddress,
        serial_number: Option<[u8; 6]>,
    },
    /// A completed or indeterminate physical mutation affected these exact
    /// compiler-owned programming sections.
    ProgrammingSectionsMutated {
        sections: Vec<ProgrammingSection>,
    },
    DifferentialFallback(DifferentialFallback),
    Step {
        index: usize,
        total: usize,
        description: String,
    },
    Data {
        done: u64,
        total: u64,
    },
    ProgressText(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcedureReport {
    pub steps_completed: usize,
    pub mapped_errors: Vec<(u32, u32)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AddressAssignment {
    pub serial_number: Option<[u8; 6]>,
    pub previous: IndividualAddress,
    pub current: IndividualAddress,
    pub changed: bool,
}

/// Outcome of one ETS-style device status section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommissioningSectionOutcome {
    /// The intent did not operate on this section.
    NotRequested,

    /// The project value was programmed and the complete operation succeeded.
    Programmed,

    /// Requested content was not established; some owned bits remain unknown
    /// or differ from the desired image after an ignored control failure.
    Unverified,

    /// The section was removed by a successful unload.
    Cleared,
}

/// Successful result of one complete commissioning intent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecutionReport {
    /// Address bound for the executed procedure, including unloads at a previous address.
    pub execution_address: IndividualAddress,
    /// Differential decision established during preparation and revalidated for execution.
    pub differential: crate::commissioning::evidence::DifferentialDecision,
    /// Exact immutable plan that was executed.
    pub plan: CompiledProgram,

    /// Confirmed public image contents retained by the execution session.
    ///
    /// This may be sparse when selected controls leave bytes unknown. Its
    /// masks include only canonical image ownership, and its values reflect
    /// successful observations and writes; private credential bytes are absent.
    pub programmed_image: SparseDeviceImage,

    /// Read-only identity to which the plan was bound.
    pub discovered: DiscoveredDevice,

    /// Low-level procedure report for download or unload intents.
    pub procedure: Option<ProcedureReport>,

    /// Device-resident stamps captured by the successful load procedure.
    ///
    /// The exact profile selects these resources. They are read before the
    /// procedure's final restart closes the management session, matching ETS
    /// and avoiding a second connection to a device which is still booting.
    /// Profiles without the `DownloadStamp` capability return an empty set.
    pub device_stamps: Vec<DeviceStamp>,

    /// Outcomes for exact requested sections. Absent sections were not requested.
    pub sections: BTreeMap<ProgrammingSection, CommissioningSectionOutcome>,

    pub(crate) effects: ExecutionEffects,
}

impl ExecutionReport {
    pub fn effects(&self) -> &ExecutionEffects {
        &self.effects
    }

    pub fn section(&self, section: ProgrammingSection) -> CommissioningSectionOutcome {
        self.sections.get(&section).copied().unwrap_or(CommissioningSectionOutcome::NotRequested)
    }
}

pub(crate) mod effects;
