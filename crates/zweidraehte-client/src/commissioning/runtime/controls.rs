//! Ordered controls have one handler boundary, including implicit transfers.
use super::{ExecutionSession, PropertyDescriptor};
use crate::commissioning::compiler::secrets::validate_secret_bindings;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::image::{ImageLocation, SparseDeviceImage};
use crate::commissioning::procedure::operands::{MemoryAddress, OperationTarget, PropertyAddress, ServiceRead};
use crate::commissioning::procedure::{
    Comparison, DescribedPropertyAction, ErrorAction, ErrorHandler, LoadControlCause, NormalizedProcedure,
    OperationExtent, ProcedureOperation, ProcedureStep,
};
use crate::commissioning::report::{CommissioningEvent, CommissioningStage, ProcedureReport};
use crate::commissioning::runtime::TransferContext;
use std::time::Duration;
use zweidraehte_proto::pid;

pub(in crate::commissioning) struct ProcedureRunner<'session, 'image> {
    pub(super) session: &'session mut ExecutionSession<'image>,
    pub(super) tool_state: crate::commissioning::procedure::ToolState,
    error_mappings: Vec<ErrorMapping>,
    mapped_errors: Vec<(u32, u32)>,
    steps_completed: usize,
    data_done: u64,
    data_total: u64,
    unloading: bool,
    verification_reads: &'image [(ImageLocation, ServiceRead)],
}

struct ErrorMapping {
    source_control_code: u8,
    original: u32,
    mapped: u32,
}

#[derive(Default)]
struct UnloadAcknowledgements {
    required: usize,
    confirmed: usize,
}

impl<'session, 'a> ProcedureRunner<'session, 'a> {
    pub(in crate::commissioning) fn new(session: &'session mut ExecutionSession<'a>) -> Self {
        Self {
            session,
            tool_state: Default::default(),
            error_mappings: Vec::new(),
            mapped_errors: Vec::new(),
            steps_completed: 0,
            data_done: 0,
            data_total: 0,
            unloading: false,
            verification_reads: &[],
        }
    }

    pub(in crate::commissioning) fn unloading(mut self, unloading: bool) -> Self {
        self.unloading = unloading;
        self
    }

    pub(in crate::commissioning) fn with_verification_reads(
        mut self,
        reads: &'a [(ImageLocation, ServiceRead)],
    ) -> Self {
        self.verification_reads = reads;
        self
    }

    async fn verify_uncovered_image(&mut self, cancel: &impl Fn() -> bool) -> Result<(), Diagnostic> {
        let reads = std::mem::take(&mut self.verification_reads);
        for (location, read) in reads {
            if !self.session.images.needs_observation(location, read.extent.byte_length) {
                continue;
            }
            // Memory permits byte-granular reads: leave already proven bytes
            // alone, including device-owned holes inside a product segment.
            let ranges = if matches!(read.target, OperationTarget::Memory { address: MemoryAddress::Fixed(_), .. }) {
                super::data::changed_ranges(read.extent.byte_length as usize, 1, true, |offset| {
                    let at = ImageLocation { space: location.space.clone(), offset: location.offset + offset as u32 };
                    !self.session.images.needs_observation(&at, 1)
                })
            } else {
                vec![0..read.extent.byte_length as usize]
            };
            for range in ranges {
                if cancel() {
                    return Err(Diagnostic::new("commissioning was cancelled"));
                }
                let at = ImageLocation { space: location.space.clone(), offset: location.offset + range.start as u32 };
                let (target, extent) = match &read.target {
                    OperationTarget::Memory { service, address: MemoryAddress::Fixed(address) } => (
                        OperationTarget::Memory {
                            service: *service,
                            address: MemoryAddress::Fixed(address + range.start as u32),
                        },
                        OperationExtent::bytes(range.len() as u32),
                    ),
                    _ => (read.target.clone(), read.extent),
                };
                let bytes = self.session.read(&target, extent, TransferContext::Public).await?;
                self.session.images.observe(at, &bytes)?;
            }
        }
        Ok(())
    }

    pub(crate) async fn execute<C: Fn() -> bool, F: FnMut(CommissioningEvent)>(
        mut self,
        image: &'a SparseDeviceImage,
        regions: &[crate::commissioning::image::NativeImageRegion],
        procedure: &'a NormalizedProcedure,
        cancel: C,
        mut event: F,
    ) -> Result<ProcedureReport, Diagnostic> {
        validate_secret_bindings(procedure, Some(&self.session.secret_payload))?;
        self.session.seed_property_object_types(procedure)?;
        self.session.images.begin_program(image, regions, &procedure.stamp_output);
        self.tool_state = procedure.initial_state;
        self.data_total = procedure
            .steps
            .iter()
            .map(|step| match &step.operation {
                ProcedureOperation::Write { extent, .. } => u64::from(extent.byte_length),
                ProcedureOperation::AbsoluteSegment { transfers, .. } => {
                    transfers.iter().map(|transfer| u64::from(transfer.extent.byte_length)).sum()
                }
                _ => 0,
            })
            .sum();

        let result = self.execute_steps(&procedure.steps, &cancel, &mut event).await;
        // Disconnect always attempts restoration and close, retaining both
        // failures. No separate executor session counter can disagree with it.
        self.session.finish(result).await?;

        Ok(ProcedureReport {
            steps_completed: self.steps_completed,
            mapped_errors: std::mem::take(&mut self.mapped_errors),
        })
    }

    async fn execute_steps<C: Fn() -> bool, F: FnMut(CommissioningEvent)>(
        &mut self,
        steps: &[ProcedureStep],
        cancel: &C,
        event: &mut F,
    ) -> Result<(), Diagnostic> {
        // Each section needs every authored unload acknowledgement. A single
        // successful table unload cannot hide another table's ignored failure.
        let mut unloads = std::collections::BTreeMap::new();
        if self.unloading {
            for step in steps.iter().filter(|step| unloads_machine(&step.operation)) {
                for section in &step.sections {
                    unloads.entry(*section).or_insert_with(UnloadAcknowledgements::default).required += 1;
                }
            }
        }
        let last_connect = steps.iter().rposition(|step| matches!(step.operation, ProcedureOperation::Connect));
        // A restart inside the procedure (a product fragment restarting the
        // device before the mask's final restart) also ends a session, so
        // the final session ends only after the last other device step.
        let last_device_step = steps.iter().rposition(|step| {
            requires_device(&step.operation)
                && !matches!(
                    step.operation,
                    ProcedureOperation::Restart { .. } | ProcedureOperation::MasterReset { .. }
                )
        });
        let mut opened_session = false;
        for (index, step) in steps.iter().enumerate() {
            if cancel() {
                return Err(Diagnostic::new("commissioning was cancelled"));
            }

            // Downloads reopen a session on demand, like the reference's
            // `AutoConnect` download sessions: every management service
            // first checks the connection and reconnects when a restart
            // closed it. Unloads do not, so a device step there still fails
            // without an open connection.
            if !self.unloading
                && opened_session
                && self.session.connection.is_none()
                && requires_device(&step.operation)
            {
                event(CommissioningEvent::Stage(CommissioningStage::Connecting));
                self.reconnect().await.map_err(|error| error.at_control(step.path.clone()))?;
            }
            opened_session |= matches!(step.operation, ProcedureOperation::Connect);

            event(CommissioningEvent::Step {
                index: index + 1,
                total: steps.len(),
                description: description(&step.operation),
            });
            if step.secure_only
                && !matches!(step.operation, ProcedureOperation::Connect)
                && !(matches!(step.operation, ProcedureOperation::Disconnect) && self.session.connection.is_none())
                && !self.session.secure_management()
            {
                return Err(
                    Diagnostic::new("the commissioning plan requires secure management").at_control(step.path.clone())
                );
            }
            // Read while the final management connection is still alive.
            if last_connect.is_none_or(|last| index > last)
                && last_device_step.is_none_or(|last| index > last)
                && matches!(step.operation, ProcedureOperation::Disconnect | ProcedureOperation::Restart { .. })
            {
                self.verify_uncovered_image(cancel).await?;
            }
            self.session.control_mutated = false;
            let result = self.execute_step(step, cancel, event).await;
            if self.session.control_mutated && !step.sections.is_empty() {
                self.session.effects.record_sections(step.sections.iter().copied());
                event(CommissioningEvent::ProgrammingSectionsMutated {
                    sections: step.sections.iter().copied().collect(),
                });
            }
            if self.unloading && result.is_ok() && unloads_machine(&step.operation) {
                for section in &step.sections {
                    let acknowledgements = unloads.get_mut(section).expect("unload counted before iteration");
                    acknowledgements.confirmed += 1;
                    if acknowledgements.confirmed == acknowledgements.required {
                        self.session.effects.confirm_section_erasure(*section);
                    }
                }
            }
            if cancel() {
                return Err(Diagnostic::new("commissioning was cancelled"));
            }
            if let Err(error) = result {
                if !self.handle_error(step, &error) {
                    return Err(error.at_control(step.path.clone()));
                }
            }
            self.steps_completed += 1;
            let length = match &step.operation {
                ProcedureOperation::Write { extent, .. } => u64::from(extent.byte_length),
                ProcedureOperation::AbsoluteSegment { transfers, .. } => {
                    transfers.iter().map(|transfer| u64::from(transfer.extent.byte_length)).sum()
                }
                _ => 0,
            };
            if length != 0 {
                self.data_done += length;
                event(CommissioningEvent::Data { done: self.data_done, total: self.data_total });
            }
        }
        self.verify_uncovered_image(cancel).await
    }

    /// Reopens the session a restart closed, with the tool state the
    /// authored connection established.
    async fn reconnect(&mut self) -> Result<(), Diagnostic> {
        self.session.connect().await?;
        if let Some(enabled) = self.tool_state.memory_auto_verify {
            self.session.set_memory_verify_mode(enabled).await?;
        }
        Ok(())
    }

    async fn execute_step<C: Fn() -> bool, F: FnMut(CommissioningEvent)>(
        &mut self,
        step: &ProcedureStep,
        cancel: &C,
        event: &mut F,
    ) -> Result<(), Diagnostic> {
        match &step.operation {
            ProcedureOperation::Connect => {
                event(CommissioningEvent::Stage(CommissioningStage::Connecting));
                self.session.connect().await?;
                if step.secure_only && !self.session.secure_management() {
                    return Err(Diagnostic::new("the commissioning plan requires secure management"));
                }
                if let Some(enabled) = self.tool_state.memory_auto_verify {
                    self.session.set_memory_verify_mode(enabled).await?;
                }
            }
            ProcedureOperation::Disconnect => {
                event(CommissioningEvent::Stage(CommissioningStage::RestoringDeviceState));
                event(CommissioningEvent::Stage(CommissioningStage::Disconnecting));
                self.session.disconnect().await?;
            }
            ProcedureOperation::Restart { kind } => self.session.restart_device(*kind).await?,
            ProcedureOperation::MasterReset { erase_code, channel } => {
                self.session.reset_device(*erase_code, *channel).await?
            }
            ProcedureOperation::Delay { milliseconds } => {
                tokio::time::sleep(Duration::from_millis(u64::from(*milliseconds))).await
            }
            ProcedureOperation::SetControlVariable { variable, value } => {
                let mut next = self.tool_state;
                next.set(*variable, *value);
                self.session.apply_state(self.tool_state, next).await?;
                self.tool_state = next;
            }
            ProcedureOperation::MapError { filter, original, mapped } => {
                let filter = filter.unwrap_or(0);
                self.error_mappings
                    .retain(|mapping| (mapping.source_control_code, mapping.original) != (filter, *original));
                if original != mapped {
                    self.error_mappings.push(ErrorMapping {
                        source_control_code: filter,
                        original: *original,
                        mapped: *mapped,
                    });
                }
            }
            ProcedureOperation::ClearCache => {
                self.session.images.forget_cache();
                self.session.forget_described_property_types();
            }
            ProcedureOperation::ProgressText(text) => event(CommissioningEvent::ProgressText(text.clone())),
            ProcedureOperation::LoadRecord(record) => self.session.load_record(record).await?,
            ProcedureOperation::AbsoluteSegment { record, transfers } => {
                self.session.load_record(record).await?;
                if self.tool_state.segment_write {
                    for transfer in transfers {
                        self.session
                            .transfer(
                                &transfer.target,
                                &transfer.data,
                                transfer.extent,
                                transfer.policy,
                                self.tool_state,
                            )
                            .await?;
                    }
                }
            }
            ProcedureOperation::ReadIntoImage { target, image_location, extent, cache, capture_as } => {
                let bytes = self.session.read_cached(target, *extent, *cache, Some(image_location)).await?;
                if let Some(resource) = capture_as {
                    self.session.images.capture_stamp(resource.clone(), bytes.clone());
                }
            }
            ProcedureOperation::LoadImage { target, image_location, extent, alignment } => {
                self.session.load_image(target, image_location, *extent, *alignment).await?
            }
            ProcedureOperation::Write { target, data, extent, policy } => {
                self.session.transfer(target, data, *extent, *policy, self.tool_state).await?
            }
            ProcedureOperation::Compare {
                target,
                comparison,
                extent,
                cache,
                invert,
                retry_interval_milliseconds,
                timeout_milliseconds,
            } => {
                // Native memory comparisons with no selected bits complete before
                // resolving their source or reading the device. Inversion and
                // retry policy do not turn this empty comparison into failure.
                if matches!(target, OperationTarget::Memory { .. })
                    && matches!(comparison, Comparison::Exact { mask: Some(mask), .. } | Comparison::ImageExact { mask: Some(mask), .. }
                    if mask.iter().all(|byte| *byte == 0))
                {
                    return Ok(());
                }
                let comparison = self.session.comparison_data(target, comparison, *extent).await?;
                if matches!(&comparison, Comparison::Exact { mask: Some(mask), .. } if mask.iter().all(|byte| *byte == 0))
                {
                    if matches!(target, OperationTarget::Property { .. }) {
                        return Err(Diagnostic::new(
                            "zero-mask property comparison requires native metadata-only resolution",
                        ));
                    }

                    return Ok(());
                }
                let deadline = timeout_milliseconds
                    .map(|timeout| tokio::time::Instant::now() + Duration::from_millis(u64::from(timeout)));
                loop {
                    if cancel() {
                        return Err(Diagnostic::new("commissioning was cancelled"));
                    }
                    let result = match self.session.read_cached(target, *extent, *cache, None).await {
                        Ok(bytes) => self.compare_value(&bytes, &comparison),
                        Err(error) => Err(error),
                    };
                    let result = if *invert {
                        match result {
                            Ok(()) => Err(self.session.compare_error("inverted comparison matched")),
                            Err(error) if error.load_control_cause == Some(LoadControlCause::CompareMismatch) => Ok(()),
                            Err(error) => Err(error),
                        }
                    } else {
                        result
                    };
                    match result {
                        Ok(()) => break,
                        Err(_) if deadline.is_some_and(|deadline| tokio::time::Instant::now() < deadline) => {
                            let interval = retry_interval_milliseconds.unwrap_or(0);
                            if interval == 0 {
                                tokio::task::yield_now().await;
                            } else {
                                tokio::time::sleep(Duration::from_millis(u64::from(interval))).await;
                            }
                        }
                        Err(mut error) => {
                            // The reference reports a program-version (PID 13)
                            // mismatch as a different loaded application
                            // without an error cause, so the comparison's
                            // CompareMismatch handlers never apply to it.
                            let property_id = match target {
                                OperationTarget::Property {
                                    address: PropertyAddress::Indexed { property_id, .. },
                                    ..
                                } => Some(u16::from(*property_id)),
                                OperationTarget::Property {
                                    address: PropertyAddress::Extended { property_id, .. },
                                    ..
                                } => Some(*property_id),
                                _ => None,
                            };
                            let program_version = property_id == Some(pid::PROGRAM_VERSION);
                            if program_version && error.load_control_cause == Some(LoadControlCause::CompareMismatch) {
                                error.load_control_cause = None;
                            }

                            return Err(error);
                        }
                    }
                }
            }
            ProcedureOperation::FunctionProperty(operation) => self.session.function(operation).await?,
            ProcedureOperation::DescribedProperty(operation) => {
                let property_data_type = match &operation.action {
                    DescribedPropertyAction::CompareRange { lookup: Some(lookup), .. }
                    | DescribedPropertyAction::LoadImage { lookup, .. } => {
                        self.session
                            .numeric_property_type(&operation.target, operation.extended_description, lookup)
                            .await?
                    }
                    _ => {
                        self.session.described_property_type(&operation.target, operation.extended_description).await?
                    }
                };

                // Authored bytes shorter than the described extent, or a
                // missing image segment, leave the reference nothing to send
                // or compare; it skips the control.
                let Some(operation) = operation.resolve(property_data_type)? else {
                    return Ok(());
                };

                let step = ProcedureStep { operation, ..step.clone() };
                Box::pin(self.execute_step(&step, cancel, event)).await?
            }
            ProcedureOperation::DeclarePropertyDescriptor {
                address,
                property_data_type,
                maximum_elements,
                read_access,
                write_access,
                writable,
            } => {
                let descriptor = PropertyDescriptor {
                    property_data_type: property_data_type.clone(),
                    maximum_elements: *maximum_elements,
                    read_access: *read_access,
                    write_access: *write_access,
                    writable: *writable,
                };
                let key = super::DescriptorKey::from(*address);
                // Discovery and declarations occupy the same native descriptor
                // slot. A declaration replaces an earlier reported PDT too.
                match *address {
                    PropertyAddress::Indexed { object_index, property_id } => {
                        self.session.described_property_types.remove(&(object_index, property_id));
                    }
                    PropertyAddress::Extended { object_type, property_id, .. } => {
                        self.session.described_property_types_by_type.remove(&(u16::from(object_type), property_id));
                    }
                }
                // Executed declarations replace the cached descriptor. Source
                // declarations used for image allocation do not set this state.
                self.session.property_descriptors.insert(key, descriptor);
            }
            ProcedureOperation::ClearLineCouplerFilter { address } => {
                self.session.images.forget_device();
                if let Some(address) = address {
                    self.session
                        .function_request(
                            *address,
                            &[0, 1],
                            true,
                            &crate::commissioning::procedure::LoadEffect::InvalidateAll,
                        )
                        .await?;
                } else {
                    self.session
                        .connection_mut()?
                        .filter_table_open()
                        .await
                        .map_err(|error| self.session.mutating_client_error(error))?;
                    self.session.record_mutation();
                }
            }
        }
        Ok(())
    }

    fn handle_error(&mut self, step: &ProcedureStep, error: &Diagnostic) -> bool {
        if !error.cleanup_failures.is_empty() {
            return false;
        }
        if let Some(handler) = step.on_error.iter().find(|handler| handler_matches(handler, error)) {
            match handler.action {
                ErrorAction::Ignore | ErrorAction::MapTo(0) => return true,
                ErrorAction::MapTo(mapped) => {
                    if let Some(original) = error.legacy_error_code() {
                        self.mapped_errors.push((original, mapped));
                    }
                }
                ErrorAction::FailWithMessage { .. } => return false,
            }
        }
        let Some(original) = error.legacy_error_code() else {
            return false;
        };
        let Some(mapping) = self.error_mappings.iter().find(|mapping| {
            mapping.original == original
                && (mapping.source_control_code == 0 || step.source_control_code == Some(mapping.source_control_code))
        }) else {
            return false;
        };
        self.mapped_errors.push((original, mapping.mapped));
        mapping.mapped == 0
    }
}

fn handler_matches(handler: &ErrorHandler, error: &Diagnostic) -> bool {
    match &handler.cause {
        LoadControlCause::DeviceReturnCode(expected) => error.device_return_code() == Some(*expected),
        LoadControlCause::LegacyCode(expected) => error.legacy_error_code() == Some(*expected),
        expected => error.load_control_cause.as_ref() == Some(expected),
    }
}

fn description(operation: &ProcedureOperation) -> String {
    match operation {
        ProcedureOperation::ProgressText(text) => return text.clone(),
        ProcedureOperation::Connect => "Connect",
        ProcedureOperation::Disconnect => "Disconnect",
        ProcedureOperation::Delay { .. } => "Wait",
        ProcedureOperation::Restart { .. } | ProcedureOperation::MasterReset { .. } => "Restart device",
        ProcedureOperation::SetControlVariable { .. } => "Set tool variable",
        ProcedureOperation::MapError { .. } => "Map error",
        ProcedureOperation::ClearCache => "Clear read cache",
        ProcedureOperation::LoadRecord(_) => "Write load record",
        ProcedureOperation::AbsoluteSegment { .. } => "Allocate and write memory segment",
        ProcedureOperation::ReadIntoImage { .. } => "Read device data",
        ProcedureOperation::LoadImage { .. } => "Load device data into working image",
        ProcedureOperation::Write { .. } => "Write device data",
        ProcedureOperation::Compare { .. } => "Compare device data",
        ProcedureOperation::DescribedProperty(operation) => match operation.action {
            DescribedPropertyAction::LoadImage { .. } => "Load device data into working image",
            DescribedPropertyAction::Write { .. }
            | DescribedPropertyAction::WriteImage { .. }
            | DescribedPropertyAction::WriteImageWindow { .. } => "Write device data",
            DescribedPropertyAction::Compare { .. } | DescribedPropertyAction::CompareRange { .. } => {
                "Compare device data"
            }
        },
        ProcedureOperation::FunctionProperty(_) => "Invoke function property",
        ProcedureOperation::DeclarePropertyDescriptor { .. } => "Declare property descriptor",
        ProcedureOperation::ClearLineCouplerFilter { .. } => "Open or clear filter table",
    }
    .to_owned()
}

/// Whether a step talks to the device and therefore needs a management
/// session. Session controls themselves do not, and a descriptor declaration
/// only records the descriptor for later services.
fn requires_device(operation: &ProcedureOperation) -> bool {
    operation.requires_management_session()
        && !matches!(
            operation,
            ProcedureOperation::Connect
                | ProcedureOperation::Disconnect
                | ProcedureOperation::DeclarePropertyDescriptor { .. }
        )
}

fn unloads_machine(operation: &ProcedureOperation) -> bool {
    matches!(operation, ProcedureOperation::LoadRecord(record)
        if record.poll.as_ref().is_some_and(|(_, state)|
            *state == zweidraehte_proto::messages::apdu::load_control::LoadState::Unloaded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_and_legacy_handlers_match_independent_error_identities() {
        let error = Diagnostic::new("function rejected").with_device_return_code(2).with_legacy_error_code(0xC004_2B25);
        for cause in [LoadControlCause::DeviceReturnCode(2), LoadControlCause::LegacyCode(0xC004_2B25)] {
            assert!(handler_matches(&ErrorHandler { cause, action: ErrorAction::Ignore }, &error));
        }
        assert!(!handler_matches(
            &ErrorHandler { cause: LoadControlCause::DeviceReturnCode(3), action: ErrorAction::Ignore },
            &error
        ));
    }
}
