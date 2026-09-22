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
use crate::commissioning::runtime::credentials::ManagementAccessOptions;
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

/// Cooperative cancellation shared by frontends and the executor.
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

/// Live access and installed evidence, separate from the desired programming input.
#[derive(Debug)]
pub struct PreparationOptions<'a> {
    pub access: ManagementAccessOptions,
    pub variant_hint: VariantHint,
    pub differential_policy: DifferentialPolicy,
    pub deployment: Option<&'a DeploymentRecord>,
}

impl PreparationOptions<'_> {
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

impl CommissioningCancellation {
    pub(crate) fn check(&self) -> crate::commissioning::error::DiagnosticResult<()> {
        if self.is_cancelled() {
            Err(crate::commissioning::Diagnostic::new("commissioning was cancelled"))
        } else {
            Ok(())
        }
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
