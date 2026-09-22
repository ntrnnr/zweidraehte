//! Execute one immutable binding with one owner for every live phase.

use super::ExecutionSession;
use crate::commissioning::error::CommissioningError;
use crate::commissioning::error::DiagnosticResult as Result;
use crate::commissioning::image::SparseDeviceImage;
use crate::commissioning::report::effects::ExecutionEffects;
use crate::commissioning::report::{CommissioningEvent, CommissioningStage, ExecutionReport};
use crate::commissioning::runtime::commissioner::{Commissioner, CommissioningCancellation};
use crate::commissioning::runtime::policy::successful_section_outcomes;
use crate::commissioning::runtime::prepared::PreparedProgram;

impl Commissioner<'_> {
    /// Execute the prepared controls after revalidating their device evidence.
    /// Changed evidence, cancellation, or failed services return an error;
    /// device errors retain mutation status and mandatory cleanup failures.
    pub async fn execute<F: FnMut(CommissioningEvent)>(
        &self,
        prepared: PreparedProgram,
        cancellation: &CommissioningCancellation,
        mut event: F,
    ) -> crate::commissioning::Result<ExecutionReport> {
        PreparedProgram::check_bus(prepared.bus_instance_id(), self.bus.instance_id())
            .map_err(CommissioningError::before_execution)?;
        cancellation.check().map_err(CommissioningError::before_execution)?;
        let PreparedProgram { plan, mut evidence, access, authorization, replacement_tool_key, secret_payload, .. } =
            prepared;
        let config = self.management_config(evidence.target_max_apdu, plan.verify_mode(), authorization);
        let mut session = ExecutionSession::new(self.bus, plan.observed_target().previous_address, config, access)
            .map_err(CommissioningError::before_execution)?;
        session.serial_number = plan.observed_target().serial_number;
        session.secret_payload = secret_payload;
        session.replacement_tool_key = replacement_tool_key;
        session.images = super::image_state::ImageState::with_baseline(evidence.baseline_known.take());

        let completion: Result<_> = async {
            session.revalidate_execution(&plan, &mut evidence, cancellation).await?;
            session.begin_execution();
            session.execute_network(&plan, &evidence, cancellation, &mut event).await?;
            let procedure = session.execute_application(&plan, cancellation, &mut event).await?;
            let device_stamps = if plan.intent().download_mode().is_some() {
                cancellation.check()?;
                let stamps = session.images.completed_stamps()?;
                evidence.validate_captured_stamps(&plan, &stamps)?;
                stamps
            } else {
                Vec::new()
            };
            Ok((procedure, device_stamps))
        }
        .await;

        let ((procedure, device_stamps), programmed_image, effects) = session.finalize(completion).await?;
        let sections = successful_section_outcomes(&plan, &programmed_image, effects.cleared_sections());
        let discovered = evidence.discovery(&plan);
        event(CommissioningEvent::Stage(CommissioningStage::Complete));
        Ok(ExecutionReport {
            execution_address: evidence.execution_address,
            differential: evidence.differential,
            plan,
            programmed_image,
            discovered,
            procedure,
            device_stamps,
            sections,
            effects,
        })
    }
}

impl ExecutionSession<'_> {
    /// Mandatory cleanup runs before the only publication of accumulated effects.
    pub(super) async fn finalize<T>(
        mut self,
        result: Result<T>,
    ) -> crate::commissioning::Result<(T, SparseDeviceImage, ExecutionEffects)> {
        let value = match self.finish(result).await {
            Ok(value) => value,
            Err(error) => return Err(CommissioningError::after_execution(error, self.effects)),
        };
        self.effects.complete();
        let image = self.images.take_programmed_image();
        Ok((value, image, self.effects))
    }
}
