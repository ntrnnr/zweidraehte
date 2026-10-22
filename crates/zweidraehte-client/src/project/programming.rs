//! The single frontend path from loaded project inputs to a programmed batch.
//!
//! [`ProjectProgramming`] owns the inputs it was planned from, so a plan can
//! never execute against products, Master Data or keys loaded for another
//! request. Execution opens the project session and the bus itself and always
//! awaits finalization before returning.

use super::inputs::{ProjectOperationInputs, ProjectSetupRequirement};
use super::operation::execute_batch;
use super::{ProgrammingBatchPlan, ProjectBatchReport};
use crate::commissioning::{CommissionerOptions, CommissioningObserver, DifferentialPolicy, TargetSelection};
use crate::project::error::Result;
use crate::security::SecurityStore;
use crate::{BusResult, KnxBus};
use std::future::Future;
use zweidraehte_project::ProjectDeviceId;

/// Access and transfer choices that cannot be inferred from the project.
///
/// A value bag: start from [`ProgrammingPolicy::default`] and assign the
/// fields that differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProgrammingPolicy {
    pub commissioner: CommissionerOptions,
    /// Permit unauthenticated management for devices without secure credentials.
    pub allow_plaintext: bool,
    pub differential: DifferentialPolicy,
    /// Generate and persist a Tool Key for every planned device that needs one,
    /// before the bus is opened.
    pub generate_missing_tool_keys: bool,
}

impl Default for ProgrammingPolicy {
    fn default() -> Self {
        Self {
            commissioner: CommissionerOptions::default(),
            allow_plaintext: true,
            differential: DifferentialPolicy::FallBackToUndifferenced,
            generate_missing_tool_keys: false,
        }
    }
}

/// A planned batch bound to the inputs it was evaluated from.
///
/// Created by [`ProjectOperationInputs::into_programming`]. Inspect the plan,
/// adjust policy and physical targets, authorize initialization, then
/// [`execute`](Self::execute).
pub struct ProjectProgramming {
    inputs: ProjectOperationInputs,
    plan: ProgrammingBatchPlan,
}

impl std::fmt::Debug for ProjectProgramming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectProgramming")
            .field("inputs", &self.inputs)
            .field("device_count", &self.plan.devices().len())
            .field("policy", &self.plan.policy())
            .finish()
    }
}

impl ProjectProgramming {
    pub(super) fn new(inputs: ProjectOperationInputs, plan: ProgrammingBatchPlan) -> Self {
        Self { inputs, plan }
    }

    pub fn inputs(&self) -> &ProjectOperationInputs {
        &self.inputs
    }

    pub fn plan(&self) -> &ProgrammingBatchPlan {
        &self.plan
    }

    /// Replace the access and transfer policy. Per-device targets are derived
    /// again; explicit [`set_target`](Self::set_target) choices survive.
    pub fn set_policy(&mut self, policy: ProgrammingPolicy) {
        self.plan.set_policy(policy);
    }

    /// Override physical target acquisition without changing evaluated scope.
    pub fn set_target(&mut self, device: &ProjectDeviceId, target: TargetSelection) -> Result<()> {
        self.plan.set_target(device, target)
    }

    /// Setup still needed before [`execute`](Self::execute), including explicit
    /// target overrides.
    pub fn requirements(&self) -> Vec<ProjectSetupRequirement> {
        self.inputs.requirements(&self.plan)
    }

    /// Explicitly authorize empty-project initialization. Never performed by
    /// loading, planning, or execution.
    pub fn initialize(&mut self) -> Result<()> {
        self.inputs.initialize()
    }

    /// Open the project session and the bus, program the queue, and finalize.
    ///
    /// The connector factory keeps transport and executor choices with the
    /// caller. The observer sees every device's events, may veto each prepared
    /// device before its first write, and is polled for cancellation. Every
    /// physical effect and cleanup failure is retained in the result.
    pub async fn execute<Connect, Connecting>(
        self,
        connect: Connect,
        observer: &mut impl CommissioningObserver<ProjectDeviceId>,
    ) -> Result<ProjectBatchReport>
    where
        Connect: FnOnce(SecurityStore) -> Connecting,
        Connecting: Future<Output = BusResult<KnxBus>>,
    {
        let Self { inputs, plan } = self;
        let session = inputs.begin_session()?;

        execute_batch(session, plan, connect, inputs.programming_inputs(), observer).await
    }
}
