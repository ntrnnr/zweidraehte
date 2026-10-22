//! Read-only preparation and bound execution of commissioning plans.
//!
//! Physical target acquisition, individual-address assignment, credential
//! selection, and security bootstrap are installation concerns. They remain
//! outside the Master Data load-control interpreter, while every application
//! mutation is executed through the same typed
//! execution session over the existing device connection.

use crate::bus::KnxBus;
use crate::commissioning::catalog::profile::VariantHint;
use crate::commissioning::evidence::{DeploymentRecord, DifferentialPolicy};
use crate::commissioning::report::CommissioningEvent;
use crate::commissioning::runtime::credentials::ManagementAccessOptions;
use crate::commissioning::runtime::prepared::PreparedProgram;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub(in crate::commissioning) use zweidraehte_proto::config::MAX_APDU_LENGTH_TP1_STANDARD as STANDARD_APDU_LENGTH;
pub(in crate::commissioning) const FREE_ACCESS_KEY: [u8; 4] = [u8::MAX; 4];
pub(in crate::commissioning) const OPEN_MEDIUM_COLLECTION_WINDOW: Duration = Duration::from_secs(1);
pub(in crate::commissioning) const SERIAL_DOMAIN_READ_ATTEMPT_WINDOW: Duration = Duration::from_millis(250);
pub(in crate::commissioning) const SERIAL_DOMAIN_WRITE_SETTLE: Duration = Duration::from_secs(1);

/// Runtime policy which is independent of product and Master Data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommissionerOptions {
    pub scan_window: Duration,
    pub restart_delay: Duration,
    /// The caller configures the selected bus access to carry KNX system
    /// broadcasts to the target RF domain and restores every temporary router
    /// or interface mode after Commissioner preparation/execution returns.
    ///
    /// The client cannot infer this from a tunnelling connection. Keep this
    /// false unless the direct interface or an explicitly configured router
    /// provides the path required by 03/05/02 sections 2.12 and 2.13.
    pub caller_manages_open_medium_path: bool,
    pub load_state_poll_attempts: u16,
    pub load_state_poll_interval: Duration,
    pub required_authorization_level: u8,
    pub minimum_equal_run: usize,
}

impl Default for CommissionerOptions {
    fn default() -> Self {
        Self {
            scan_window: Duration::from_secs(2),
            restart_delay: Duration::from_secs(3),
            caller_manages_open_medium_path: false,
            load_state_poll_attempts: 25,
            load_state_poll_interval: Duration::from_millis(200),
            required_authorization_level: 3,
            minimum_equal_run: 4,
        }
    }
}

// ================================================================================
// Observation
// ================================================================================

/// Watches commissioning, approves prepared programs, and requests cancellation.
///
/// One device and a project batch share this contract. `Subject` names what
/// the commissioning concerns: the [`Commissioner`] works on one anonymous
/// device (`()`), while a project batch passes each device's project
/// identity. Every method has a default, so `&mut ()` observes nothing and
/// [`CommissioningCancellation`] only cancels.
///
/// ```
/// use zweidraehte_client::commissioning::{
///     CommissioningEvent, CommissioningObserver, CommissioningVeto, PreparedProgram,
/// };
///
/// /// Logs every event and refuses any program that would assign an address.
/// struct ReadOnlyGuard(Vec<CommissioningEvent>);
///
/// impl CommissioningObserver for ReadOnlyGuard {
///     fn event(&mut self, _device: &(), event: CommissioningEvent) {
///         self.0.push(event);
///     }
///
///     fn approve(&mut self, _device: &(), prepared: &PreparedProgram) -> Result<(), CommissioningVeto> {
///         if prepared.plan().intent().mutates_address() {
///             return Err(CommissioningVeto::new("address assignment is not allowed here"));
///         }
///         Ok(())
///     }
/// }
/// ```
pub trait CommissioningObserver<Subject: ?Sized = ()> {
    /// Progress during preparation and execution. Observation only: the
    /// commissioning continues regardless of what the observer does.
    fn event(&mut self, _subject: &Subject, _event: CommissioningEvent) {}

    /// Inspect a prepared program before its first configuration write.
    /// Called by one-call operations that own the gap between preparation
    /// and execution; callers of [`Commissioner::prepare`] and
    /// [`Commissioner::execute`] hold that gap themselves and are never asked.
    fn approve(&mut self, _subject: &Subject, _prepared: &PreparedProgram) -> Result<(), CommissioningVeto> {
        Ok(())
    }

    /// Polled at every step boundary. Cancellation is cooperative: a running
    /// step completes and mandatory cleanup still runs.
    fn cancelled(&self) -> bool {
        false
    }
}

/// Observes nothing, approves everything, and never cancels.
impl<Subject: ?Sized> CommissioningObserver<Subject> for () {}

impl<Subject: ?Sized, Observer: CommissioningObserver<Subject> + ?Sized> CommissioningObserver<Subject>
    for &mut Observer
{
    fn event(&mut self, subject: &Subject, event: CommissioningEvent) {
        (**self).event(subject, event);
    }

    fn approve(&mut self, subject: &Subject, prepared: &PreparedProgram) -> Result<(), CommissioningVeto> {
        (**self).approve(subject, prepared)
    }

    fn cancelled(&self) -> bool {
        (**self).cancelled()
    }
}

/// An observer's refusal of a prepared program. Nothing was written.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct CommissioningVeto(Box<dyn std::error::Error + Send + Sync>);

impl CommissioningVeto {
    pub fn new(reason: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self(reason.into())
    }

    pub fn into_inner(self) -> Box<dyn std::error::Error + Send + Sync> {
        self.0
    }
}

/// Cooperative cancellation shared by frontends and the executor.
///
/// As an observer it only cancels. Frontends that also report progress
/// keep a clone and answer [`CommissioningObserver::cancelled`] from it.
#[derive(Debug, Clone, Default)]
pub struct CommissioningCancellation(Arc<AtomicBool>);

impl CommissioningCancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl<Subject: ?Sized> CommissioningObserver<Subject> for CommissioningCancellation {
    fn cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

/// Shorthands for the runtime, which always observes one anonymous device.
pub(crate) trait DeviceObservation: CommissioningObserver {
    fn emit(&mut self, event: CommissioningEvent) {
        self.event(&(), event);
    }

    fn checkpoint(&self) -> crate::commissioning::error::DiagnosticResult<()> {
        if self.cancelled() {
            Err(crate::commissioning::Diagnostic::new("commissioning was cancelled"))
        } else {
            Ok(())
        }
    }
}

impl<Observer: CommissioningObserver + ?Sized> DeviceObservation for Observer {}

// ================================================================================
// Options
// ================================================================================

/// Live access and installed evidence, separate from the desired programming input.
#[derive(Debug)]
pub struct PreparationOptions {
    pub access: ManagementAccessOptions,
    pub variant_hint: VariantHint,
    pub differential_policy: DifferentialPolicy,
    /// The previous deployment of this device, required by differential policies.
    pub deployment: Option<DeploymentRecord>,
}

impl PreparationOptions {
    pub fn new(access: ManagementAccessOptions) -> Self {
        Self {
            access,
            variant_hint: VariantHint::Automatic,
            differential_policy: DifferentialPolicy::Disabled,
            deployment: None,
        }
    }
}

/// Preparation and execution over the bus's transport and secure sequence state.
pub struct Commissioner<'a> {
    pub(in crate::commissioning) bus: &'a KnxBus,
    pub(in crate::commissioning) options: CommissionerOptions,
}

impl<'a> Commissioner<'a> {
    pub fn new(bus: &'a KnxBus) -> Self {
        Self { bus, options: CommissionerOptions::default() }
    }

    pub fn with_options(mut self, options: CommissionerOptions) -> Self {
        self.options = options;
        self
    }
}

/// Unit tests record every event in order.
#[cfg(test)]
impl CommissioningObserver for Vec<CommissioningEvent> {
    fn event(&mut self, _device: &(), event: CommissioningEvent) {
        self.push(event);
    }
}

#[cfg(test)]
mod tests {

    use crate::commissioning::runtime::commissioner::CommissioningCancellation;

    #[test]
    fn cancellation_is_shareable_between_frontend_and_executor() {
        let cancellation = CommissioningCancellation::default();
        let frontend = cancellation.clone();

        frontend.cancel();

        assert!(cancellation.is_cancelled());
    }
}
