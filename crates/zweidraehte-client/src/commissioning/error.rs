//! Structured failures for preflight and execution.

use super::evidence::SerialDomainPoll;
use super::report::effects::ExecutionEffects;
use crate::bus::BusError as ClientError;
use zweidraehte_proto::address::IndividualAddress;

use super::catalog::profile::AssociationTableEntrySize;
use super::compiler::secrets::SecretPayloadReference;
use super::image::ImageLocation;
use super::procedure::{ControlPath, LoadControlCause};

/// A Master Data token has no supported semantic interpretation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unsupported {category} token {token:?}")]
pub struct UnknownProfileToken {
    pub category: &'static str,
    pub token: String,
}

/// A discovered association-table capability disagrees with the selected profile.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AssociationTableEntrySizeError {
    #[error("{0}")]
    Metadata(String),
    #[error("the profile has no group association table")]
    MissingTable,
    #[error("association-table flavour {flavour:?} does not support a System B entry-size selection")]
    UnsupportedFlavour { flavour: Option<String> },
    #[error("association-table entry size {requested:?} conflicts with profile size {declared:?}")]
    ConflictingSize { declared: AssociationTableEntrySize, requested: AssociationTableEntrySize },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImageError {
    #[error("{0}")]
    InvalidState(String),

    #[error("image segment at {location:?} has {data_length} data bytes but {mask_length} mask bytes")]
    MaskLength { location: ImageLocation, data_length: usize, mask_length: usize },

    #[error("image segment at {location:?} with length {length} exceeds the address space")]
    AddressOverflow { location: ImageLocation, length: usize },

    #[error("image range at {location:?} with length {length} is not completely defined")]
    MissingRange { location: ImageLocation, length: u32 },
}

#[derive(Debug, thiserror::Error)]
pub enum SecretPayloadError {
    #[error("group-key identities do not match the encoded 18-byte rows")]
    GroupKeyRows,
    #[error("a secret commissioning payload exceeds the 32-bit operation extent")]
    SecretPayloadTooLarge,

    #[error("prepared commissioning is missing {0:?}")]
    MissingSecretPayload(SecretPayloadReference),

    #[error("prepared secret {reference:?} contains {actual} bytes")]
    SecretPayloadLength { reference: SecretPayloadReference, actual: usize },
}

/// Actionable compilation outcomes, independent of the compiler's internal phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompileErrorKind {
    InvalidInput,
    Unsupported,
    MissingEvidence,
    MissingProcedure,
    /// The application's options mark it as not loadable over the bus, so no
    /// download is compiled.
    NotLoadable,
    /// The selected hardware has no individual address
    /// (`HasIndividualAddress="false"`), so no management service can reach
    /// it: neither address assignment, download nor unload.
    NoIndividualAddress,
}

/// A compilation diagnostic retains the authored control that caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub kind: CompileErrorKind,
    pub path: Option<Box<ControlPath>>,
    pub message: String,
}

impl CompileError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self { kind: CompileErrorKind::InvalidInput, path: None, message: message.into() }
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self { kind: CompileErrorKind::Unsupported, ..Self::invalid(message) }
    }

    pub fn missing_evidence(message: impl Into<String>) -> Self {
        Self { kind: CompileErrorKind::MissingEvidence, ..Self::invalid(message) }
    }

    pub(crate) fn not_loadable(message: impl Into<String>) -> Self {
        Self { kind: CompileErrorKind::NotLoadable, ..Self::invalid(message) }
    }

    pub(crate) fn no_individual_address(message: impl Into<String>) -> Self {
        Self { kind: CompileErrorKind::NoIndividualAddress, ..Self::invalid(message) }
    }

    pub(crate) fn missing_procedure(message: impl Into<String>) -> Self {
        Self { kind: CompileErrorKind::MissingProcedure, ..Self::invalid(message) }
    }

    pub(crate) fn at(path: &ControlPath, message: impl Into<String>) -> Self {
        Self::invalid(message).with_path(path)
    }

    pub fn with_path(mut self, path: &ControlPath) -> Self {
        self.path = Some(Box::new(path.clone()));
        self
    }
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)?;
        if let Some(path) = &self.path {
            write!(formatter, " at {path:?}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CompileError {}

impl From<ImageError> for CompileError {
    fn from(error: ImageError) -> Self {
        Self::invalid(error.to_string())
    }
}

impl From<SecretPayloadError> for CompileError {
    fn from(error: SecretPayloadError) -> Self {
        Self::invalid(error.to_string())
    }
}

impl From<AssociationTableEntrySizeError> for CompileError {
    fn from(error: AssociationTableEntrySizeError) -> Self {
        Self::invalid(error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationStatus {
    /// Failure occurred during read-only preparation.
    NotStarted,

    /// Execution started, but no mutating service received a positive
    /// confirmation.
    NoConfirmedMutation,

    /// At least one mutation was confirmed, or a mutating request was sent
    /// without a definitive rejection. The device may now contain a prefix
    /// of the plan.
    PartiallyApplied,

    /// The complete plan, including its final verification, succeeded.
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportCause {
    Timeout,
    ConnectionClosed,
    NegativeConfirmation,
    SequenceMismatch,
    SecureSynchronization,
    Other(String),
}

/// Identity learned from a confirmed individual-address assignment.
///
/// A later phase may fail after the device has already moved. Keeping this
/// recovery fact structured lets a frontend persist the new address and, when
/// available, the serial number instead of losing the device behind an error
/// string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LearnedTarget {
    /// Confirmed address at which the device can now be reached.
    pub address: IndividualAddress,

    /// Device serial discovered before assignment, if the profile exposes it.
    pub serial_number: Option<[u8; 6]>,
}

/// Cleanup phase which failed after procedure execution had already started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CleanupOperation {
    RestoreDeviceState,
    DisableProgrammingMode,
    Disconnect,
}

/// A cleanup failure retained alongside the primary procedure failure.
///
/// Keeping the complete nested error preserves a device return code or
/// transport cause from cleanup without replacing the load-control failure
/// which initiated the exit path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupFailure {
    pub operation: CleanupOperation,
    pub error: Box<Diagnostic>,
}

/// An operation's path and typed cause, including mandatory cleanup diagnostics.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub(crate) message: String,
    pub(crate) transport: Option<TransportCause>,
    pub(crate) load_control_cause: Option<LoadControlCause>,
    /// Legacy HRESULT mapping is additional evidence, not the wire return code.
    legacy_code: Option<u32>,
    pub(crate) path: Option<Box<ControlPath>>,
    pub(crate) kind: DiagnosticKind,
    source: Option<std::sync::Arc<ClientError>>,
    /// Failures encountered while restoring device state or closing the
    /// session after the primary operation had already failed.
    pub(crate) cleanup_failures: Vec<CleanupFailure>,
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.kind {
            DiagnosticKind::Compilation(_) => "program compilation failed",
            DiagnosticKind::Preparation => "read-only preparation failed",
            DiagnosticKind::Management => "device-management operation failed",
        })?;
        if let Some(path) = &self.path {
            write!(formatter, " at {:?}", path.control_indices)?;
        }
        write!(formatter, ": {}", self.message)
    }
}

impl std::error::Error for Diagnostic {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|error| error as &(dyn std::error::Error + 'static))
    }
}

// Equality describes diagnostic evidence. The original error's allocation or
// platform-specific I/O representation is not part of that public identity.
impl PartialEq for Diagnostic {
    fn eq(&self, other: &Self) -> bool {
        self.message == other.message
            && self.transport == other.transport
            && self.load_control_cause == other.load_control_cause
            && self.legacy_code == other.legacy_code
            && self.path == other.path
            && self.kind == other.kind
            && self.cleanup_failures == other.cleanup_failures
    }
}
impl Eq for Diagnostic {}

impl Diagnostic {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            transport: None,
            load_control_cause: None,
            legacy_code: None,
            path: None,
            kind: DiagnosticKind::Management,
            source: None,
            cleanup_failures: Vec::new(),
        }
    }

    pub fn at_control(mut self, path: ControlPath) -> Self {
        self.path = Some(Box::new(path));
        self
    }

    pub fn with_transport(mut self, cause: TransportCause) -> Self {
        self.transport = Some(cause);
        self
    }

    pub fn with_device_return_code(mut self, code: u8) -> Self {
        self.load_control_cause = Some(LoadControlCause::DeviceReturnCode(code));
        self
    }

    pub(crate) fn with_legacy_error_code(mut self, code: u32) -> Self {
        self.legacy_code = Some(code);
        if self.load_control_cause.is_none() {
            self.load_control_cause = Some(LoadControlCause::LegacyCode(code));
        }
        self
    }

    /// Add operation context while retaining typed causes and cleanup evidence.
    pub fn context(mut self, context: impl std::fmt::Display) -> Self {
        self.message = format!("{context}: {}", self.message);
        self
    }

    pub(crate) fn preparation_context(mut self, context: impl std::fmt::Display) -> Self {
        self.kind = DiagnosticKind::Preparation;
        self.context(context)
    }

    pub(crate) fn with_cleanup_failure(mut self, operation: CleanupOperation, cleanup_error: Diagnostic) -> Self {
        self.message.push_str(&format!("; {} also failed: {}", operation.description(), cleanup_error.message));
        self.cleanup_failures.push(CleanupFailure { operation, error: Box::new(cleanup_error) });
        self
    }

    pub fn legacy_error_code(&self) -> Option<u32> {
        if let Some(code) = self.legacy_code {
            return Some(code);
        }
        match self.load_control_cause.as_ref()? {
            LoadControlCause::LegacyCode(code) => Some(*code),
            LoadControlCause::DeviceReturnCode(code) => Some(u32::from(*code)),
            _ => None,
        }
    }
}

impl CleanupOperation {
    pub(crate) fn combine<T>(self, primary: DiagnosticResult<T>, cleanup: DiagnosticResult<()>) -> DiagnosticResult<T> {
        match (primary, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(primary), Err(cleanup)) => Err(primary.with_cleanup_failure(self, cleanup)),
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::RestoreDeviceState => "restoring device state",
            Self::DisableProgrammingMode => "disabling programming mode",
            Self::Disconnect => "disconnecting the management session",
        }
    }
}

/// The stage responsible for a diagnostic, independent of execution effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticKind {
    Compilation(CompileErrorKind),
    Preparation,
    Management,
}

impl From<CompileError> for Diagnostic {
    fn from(error: CompileError) -> Self {
        Self { kind: DiagnosticKind::Compilation(error.kind), path: error.path, ..Self::new(error.message) }
    }
}

impl From<ImageError> for Diagnostic {
    fn from(error: ImageError) -> Self {
        Self::new(error.to_string())
    }
}

impl Diagnostic {
    pub fn message(&self) -> &str {
        &self.message
    }
    pub fn path(&self) -> Option<&ControlPath> {
        self.path.as_deref()
    }
    pub fn transport(&self) -> Option<&TransportCause> {
        self.transport.as_ref()
    }
    pub fn load_control_cause(&self) -> Option<&LoadControlCause> {
        self.load_control_cause.as_ref()
    }
    pub fn cleanup_failures(&self) -> &[CleanupFailure] {
        &self.cleanup_failures
    }
    pub fn device_return_code(&self) -> Option<u8> {
        match self.load_control_cause {
            Some(LoadControlCause::DeviceReturnCode(code)) => Some(code),
            _ => None,
        }
    }
    pub fn kind(&self) -> DiagnosticKind {
        self.kind
    }

    pub(crate) fn preparation(message: impl Into<String>) -> Self {
        Self { kind: DiagnosticKind::Preparation, ..Self::new(message) }
    }
}

/// One failed operation and the effects accumulated by its owning session.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct CommissioningError(Box<CommissioningFailure>);

#[derive(Debug, thiserror::Error)]
#[error("{diagnostic}")]
struct CommissioningFailure {
    #[source]
    diagnostic: Diagnostic,
    effects: ExecutionEffects,
}

impl CommissioningError {
    pub(crate) fn before_execution(diagnostic: Diagnostic) -> Self {
        Self(Box::new(CommissioningFailure { diagnostic, effects: ExecutionEffects::default() }))
    }

    pub(crate) fn after_execution(diagnostic: Diagnostic, effects: ExecutionEffects) -> Self {
        Self(Box::new(CommissioningFailure { diagnostic, effects }))
    }

    pub fn diagnostic(&self) -> &Diagnostic {
        &self.0.diagnostic
    }
    pub fn effects(&self) -> &ExecutionEffects {
        &self.0.effects
    }
    pub fn mutation_status(&self) -> MutationStatus {
        self.0.effects.mutation_status()
    }
}

pub type Result<T> = std::result::Result<T, CommissioningError>;
pub(crate) type DiagnosticResult<T> = std::result::Result<T, Diagnostic>;

pub(in crate::commissioning) fn classify_serial_domain_poll(
    result: std::result::Result<Vec<IndividualAddress>, crate::bus::BusError>,
) -> std::result::Result<SerialDomainPoll, crate::bus::BusError> {
    match result {
        Ok(addresses) => match addresses.as_slice() {
            [address] => Ok(SerialDomainPoll::Found(*address)),
            [] => Ok(SerialDomainPoll::NoResponse),
            _ => Err(crate::bus::BusError::DuplicateSerialNumber(addresses.len())),
        },
        Err(crate::bus::BusError::NegativeConfirmation) => Ok(SerialDomainPoll::RejectedSend),
        Err(error) => Err(error),
    }
}

pub(crate) fn mutating_request_may_have_reached_device(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::Io(_)
            | ClientError::Disconnected
            | ClientError::HeartbeatLost
            | ClientError::Timeout
            | ClientError::AckTimeout
            | ClientError::TransportClosed
            | ClientError::UnexpectedResponse
            | ClientError::VerifyMismatch { .. }


            | ClientError::SerialAddressVerification { .. }
            | ClientError::ProgrammingAddressVerification(_)
            | ClientError::SecurityMacMismatch
            // At this boundary every variable-width field has already been
            // validated. A Parse error from a mutating DeviceConnection call
            // therefore describes the response received after the request was
            // sent, not a pre-send input rejection.
            | ClientError::Parse(_)
            | ClientError::WorkerGone
    )
}

impl From<ClientError> for Diagnostic {
    fn from(error: ClientError) -> Self {
        let message = error.to_string();
        let mut mapped = Diagnostic::new(message);

        match &error {
            ClientError::Timeout | ClientError::AckTimeout => {
                mapped.transport = Some(TransportCause::Timeout);
            }
            ClientError::NegativeConfirmation => {
                mapped.transport = Some(TransportCause::NegativeConfirmation);
            }
            ClientError::Disconnected
            | ClientError::HeartbeatLost
            | ClientError::TransportConnectFailed(_)
            | ClientError::TransportClosed
            | ClientError::WorkerGone => {
                mapped.transport = Some(TransportCause::ConnectionClosed);
            }
            ClientError::SecurityMacMismatch
            | ClientError::SecuritySyncTimeout
            | ClientError::SecuritySyncRequired
            | ClientError::SecurityMissingKey => {
                mapped.transport = Some(TransportCause::SecureSynchronization);
            }
            ClientError::UnexpectedResponse => {
                mapped.transport = Some(TransportCause::SequenceMismatch);
            }
            ClientError::DeviceError(code) => {
                mapped = mapped.with_device_return_code(*code);
            }
            ClientError::PropertyValueUnavailable { .. } => {
                // The classic property response only says that the requested
                // value is unavailable; it cannot distinguish a missing PID
                // from access or response-size restrictions. At the resource
                // boundary all of those mean that this realization cannot be
                // used, so preserve that fact as a typed resource failure.
                mapped.load_control_cause = Some(LoadControlCause::ResourceNotFound);
            }
            ClientError::RestartRefused(code) => {
                mapped = mapped.with_device_return_code((*code).into());
            }
            ClientError::VerifyMismatch { .. } => {
                mapped.load_control_cause = Some(LoadControlCause::CompareMismatch);
            }
            _ => {}
        }

        mapped.source = Some(std::sync::Arc::new(error));
        mapped
    }
}

impl Diagnostic {
    pub(crate) fn with_cleanup_failures(self, operation: CleanupOperation, cleanup_failures: Vec<Diagnostic>) -> Self {
        if cleanup_failures.is_empty() {
            return self;
        }

        let mut primary = self;
        for cleanup_failure in cleanup_failures {
            primary = primary.with_cleanup_failure(operation, cleanup_failure);
        }

        primary
    }
}

impl Diagnostic {
    pub(crate) fn advise_full_download(&mut self, is_partial: bool) {
        if is_partial {
            self.message.push_str(
            "; the partial download changed the device before failing and may have left its application load state incomplete; perform a full download before using the device",
        );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CleanupOperation, Diagnostic, LearnedTarget, MutationStatus};
    use crate::commissioning::error::classify_serial_domain_poll;
    use crate::commissioning::error::{TransportCause, mutating_request_may_have_reached_device};
    use crate::commissioning::evidence::SerialDomainPoll;
    use zweidraehte_proto::address::IndividualAddress;

    #[test]
    fn device_return_codes_remain_available_for_exact_mapping() {
        let error = Diagnostic::new("rejected").with_device_return_code(0xf5);

        assert_eq!(error.device_return_code(), Some(0xf5));
        assert_eq!(error.legacy_error_code(), Some(0xf5));
    }

    #[test]
    fn legacy_mapping_retains_raw_device_code() {
        let error = Diagnostic::new("function property rejected")
            .with_device_return_code(2)
            .with_legacy_error_code(0xC004_2B25);
        assert_eq!(error.device_return_code(), Some(2));
        assert_eq!(error.legacy_error_code(), Some(0xC004_2B25));
    }

    #[test]
    fn context_preserves_transport_path_and_cleanup() {
        let path = crate::commissioning::procedure::ControlPath {
            mask_id: "MV-0705".into(),
            variant_index: 0,
            procedure: crate::commissioning::procedure::ProcedureSourceId::Generated { name: "DD0".into() },
            contribution: None,
            control_indices: vec![2],
        };
        let error = Diagnostic::from(crate::bus::BusError::Timeout)
            .at_control(path.clone())
            .with_cleanup_failure(CleanupOperation::Disconnect, Diagnostic::from(crate::bus::BusError::TransportClosed))
            .preparation_context("reading DD0");
        assert_eq!(error.transport(), Some(&super::TransportCause::Timeout));
        assert_eq!(error.path(), Some(&path));
        assert_eq!(error.kind(), super::DiagnosticKind::Preparation);
        assert_eq!(error.cleanup_failures()[0].error.transport(), Some(&super::TransportCause::ConnectionClosed));
        assert!(error.message().starts_with("reading DD0: request timed out"));
    }

    #[test]
    fn diagnostic_retains_original_bus_and_io_sources() {
        use std::error::Error;
        let diagnostic =
            Diagnostic::from(crate::BusError::Io(std::io::Error::other("journal write"))).context("reserve sequence");
        let source = diagnostic.source().expect("original bus error");
        assert!(source.downcast_ref::<crate::BusError>().is_some());
        assert_eq!(source.source().expect("original I/O error").to_string(), "journal write");
        assert_eq!(diagnostic.clone(), diagnostic);
    }

    #[test]
    fn learned_target_survives_as_structured_recovery_data() {
        let learned_target =
            LearnedTarget { address: IndividualAddress::new(1, 0, 10), serial_number: Some([1, 2, 3, 4, 5, 6]) };
        let error = super::CommissioningError::after_execution(Diagnostic::new("download failed"), {
            let mut effects = crate::commissioning::ExecutionEffects::with_status(MutationStatus::PartiallyApplied);
            effects.confirm_address(crate::commissioning::AddressAssignment {
                previous: IndividualAddress::new(1, 0, 1),
                current: learned_target.address,
                serial_number: learned_target.serial_number,
                changed: true,
            });
            effects
        });

        assert_eq!(error.effects().learned_target(), Some(learned_target));
    }

    #[test]
    fn cleanup_failure_preserves_both_structured_causes() {
        let primary = Diagnostic::new("write verification failed").with_device_return_code(0xf5);
        let cleanup = Diagnostic::new("verify-mode restore timed out").with_transport(super::TransportCause::Timeout);

        let error = primary.with_cleanup_failure(CleanupOperation::RestoreDeviceState, cleanup);

        assert_eq!(error.device_return_code(), Some(0xf5));
        assert_eq!(error.cleanup_failures.len(), 1);
        assert_eq!(error.cleanup_failures[0].operation, CleanupOperation::RestoreDeviceState);
        assert_eq!(error.cleanup_failures[0].error.transport, Some(super::TransportCause::Timeout));
        assert!(error.to_string().contains("restoring device state also failed"));
    }

    #[test]
    fn serial_domain_poll_retries_empty_and_rejected_attempts() {
        assert_eq!(
            classify_serial_domain_poll(Ok(Vec::new())).expect("empty response is retryable"),
            SerialDomainPoll::NoResponse
        );
        assert_eq!(
            classify_serial_domain_poll(Err(crate::bus::BusError::NegativeConfirmation))
                .expect("a rejected send is retryable"),
            SerialDomainPoll::RejectedSend
        );
    }

    #[test]
    fn serial_domain_poll_preserves_exact_response_cardinality() {
        let address = IndividualAddress::new(1, 0, 10);

        assert_eq!(
            classify_serial_domain_poll(Ok(vec![address])).expect("one response is unambiguous"),
            SerialDomainPoll::Found(address)
        );
        assert!(matches!(
            classify_serial_domain_poll(Ok(vec![address, address])),
            Err(crate::bus::BusError::DuplicateSerialNumber(2))
        ));
    }

    #[test]
    fn rejected_network_write_has_no_confirmed_mutation() {
        let rejected = crate::bus::BusError::NegativeConfirmation;
        assert!(!mutating_request_may_have_reached_device(&rejected));
        let error = crate::commissioning::CommissioningError::after_execution(
            Diagnostic::from(rejected),
            crate::commissioning::ExecutionEffects::with_status(MutationStatus::NoConfirmedMutation),
        );

        assert_eq!(error.effects().mutation_status(), MutationStatus::NoConfirmedMutation);
        assert_eq!(error.diagnostic().transport, Some(TransportCause::NegativeConfirmation));
    }

    #[test]
    fn timed_out_network_write_is_treated_as_an_uncertain_mutation() {
        let timeout = crate::bus::BusError::AckTimeout;
        assert!(mutating_request_may_have_reached_device(&timeout));
        let error = crate::commissioning::CommissioningError::after_execution(
            Diagnostic::from(timeout),
            crate::commissioning::ExecutionEffects::with_status(MutationStatus::PartiallyApplied),
        );

        assert_eq!(error.effects().mutation_status(), MutationStatus::PartiallyApplied);
        assert_eq!(error.diagnostic().transport, Some(TransportCause::Timeout));
    }

    #[test]
    fn a_confirmed_first_write_promotes_a_rejected_retry() {
        let error = crate::commissioning::CommissioningError::after_execution(
            Diagnostic::from(crate::bus::BusError::NegativeConfirmation),
            crate::commissioning::ExecutionEffects::with_status(MutationStatus::PartiallyApplied),
        );

        assert_eq!(error.effects().mutation_status(), MutationStatus::PartiallyApplied);
        assert_eq!(error.diagnostic().transport, Some(TransportCause::NegativeConfirmation));
    }

    #[test]
    fn failures_after_address_assignment_retain_the_learned_target() {
        let learned_target =
            LearnedTarget { address: IndividualAddress::new(1, 0, 10), serial_number: Some([1, 2, 3, 4, 5, 6]) };
        let error =
            crate::commissioning::CommissioningError::after_execution(Diagnostic::preparation("later phase failed"), {
                let mut effects = crate::commissioning::ExecutionEffects::with_status(MutationStatus::PartiallyApplied);
                effects.confirm_address(crate::commissioning::AddressAssignment {
                    previous: IndividualAddress::new(1, 0, 1),
                    current: learned_target.address,
                    serial_number: learned_target.serial_number,
                    changed: true,
                });
                effects
            });

        assert_eq!(error.effects().mutation_status(), MutationStatus::PartiallyApplied);
        assert_eq!(error.effects().learned_target(), Some(learned_target));
    }

    #[test]
    fn mutated_partial_failure_preserves_the_error_and_requires_full_recovery() {
        let mut error = Diagnostic::new("device value does not satisfy the compiled comparison");

        error.advise_full_download(true);

        assert!(error.message.starts_with("device value does not satisfy"));
        assert!(error.message.contains("perform a full download"));

        let mut untouched = Diagnostic::new("comparison failed");
        untouched.advise_full_download(false);
        assert_eq!(untouched.message, "comparison failed");
    }

    #[test]
    fn programming_mode_cleanup_failure_is_retained_beside_the_primary_error() {
        let primary = Diagnostic::new("IA verification failed").with_device_return_code(0xf5);
        let cleanup = Diagnostic::new("programming-mode clear timed out").with_transport(TransportCause::Timeout);

        let error = primary.with_cleanup_failures(CleanupOperation::DisableProgrammingMode, vec![cleanup]);

        assert_eq!(error.device_return_code(), Some(0xf5));
        assert_eq!(error.cleanup_failures.len(), 1);
        assert_eq!(error.cleanup_failures[0].operation, CleanupOperation::DisableProgrammingMode);
        assert_eq!(error.cleanup_failures[0].error.transport, Some(TransportCause::Timeout));
    }
}
