//! Revalidate target, module and installed-state evidence before mutation.

use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::error::DiagnosticResult as Result;
use crate::commissioning::runtime::ExecutionSession;
use crate::commissioning::runtime::commissioner::CommissioningCancellation;
use crate::commissioning::runtime::prepare::revalidate::read_bound_evidence;
use crate::commissioning::runtime::prepared::PreparedEvidence;

impl ExecutionSession<'_> {
    pub(super) async fn revalidate_execution(
        &mut self,
        plan: &CompiledProgram,
        evidence: &mut PreparedEvidence,
        cancellation: &CommissioningCancellation,
    ) -> Result<()> {
        let target = plan.observed_target();
        self.revalidate_binding(target.previous_address, plan, evidence, true).await?;

        // Open-medium network configuration is ordered before IA assignment.
        // Once the domain changes, the old path may no longer reach the
        // target, so the serial/programming-mode verification is part of this
        // indivisible phase rather than an application-procedure operation.
        let address_change_requested = plan.network().assign_address;

        // 03/05/02 section 2.9 requires the IA collision check before the
        // open-medium domain write. Preparation checked the same fact, but a
        // second read here closes the race between prepare and execute.
        if address_change_requested
            && self
                .bus
                .network_management()
                .is_device_present(plan.individual_address(), self.config.scan_window)
                .await
                .map_err(|error| Diagnostic::from(error).context("checking the desired individual address"))?
        {
            return Err(Diagnostic::new(format!(
                "individual address {} is already occupied",
                plan.individual_address()
            )));
        }

        read_bound_evidence(self, &mut evidence.reads, cancellation).await?;

        Ok(())
    }
}
