//! Run the compiled application procedure and final reset verification.

use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::error::DiagnosticResult as Result;
use crate::commissioning::input::{CommissioningIntent, UnloadMode};
use crate::commissioning::report::{CommissioningEvent, CommissioningStage, ProcedureReport};
use crate::commissioning::runtime::commissioner::{CommissioningObserver, DeviceObservation};
use crate::commissioning::runtime::{ExecutionSession, ProcedureRunner};

impl<'a> ExecutionSession<'a> {
    pub(super) async fn execute_application(
        &mut self,
        plan: &'a CompiledProgram,
        observer: &mut impl CommissioningObserver,
    ) -> Result<Option<ProcedureReport>> {
        let report = if let Some(procedure) = plan.procedure() {
            observer.checkpoint()?;
            let report = ProcedureRunner::new(self)
                .unloading(matches!(plan.intent(), CommissioningIntent::Unload(_)))
                .with_verification_reads(plan.verification_reads())
                .execute(plan.image(), plan.native_regions(), procedure, &mut *observer)
                .await
                .map_err(|mut error| {
                    error.advise_full_download(
                        plan.program_sections().is_some() && !plan.is_full_program_scope() && self.mutated(),
                    );
                    error
                })?;
            Some(report)
        } else {
            None
        };

        if matches!(plan.intent(), CommissioningIntent::Unload(UnloadMode::AllConfiguration)) {
            observer.emit(CommissioningEvent::Stage(CommissioningStage::Verifying));
            self.finish_complete_unload(plan, &mut *observer).await?;
            observer.checkpoint()?;
        }

        Ok(report)
    }
}
