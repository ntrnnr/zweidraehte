//! Management credential sessions and explicit security transitions.

use crate::ManagementCredentials;
use crate::bus::access::PlaintextAccess;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::error::DiagnosticResult as Result;
use crate::commissioning::runtime::commissioner::Commissioner;
use crate::commissioning::runtime::credentials::{ManagementAccess, ManagementAccessOptions};
use crate::commissioning::runtime::prepare::profile::AcquiredTarget;
use crate::commissioning::runtime::{AuthorizationPolicy, ExecutionSession, SessionConfig};
use crate::configuration::ResolvedKeyMaterial;
use crate::security::{DeviceSecurityMode, SecurityEntry};

impl Commissioner<'_> {
    pub(in crate::commissioning) fn management_config(
        &self,
        target_max_apdu: u16,
        verify_mode: bool,
        authorization: AuthorizationPolicy,
    ) -> SessionConfig {
        SessionConfig {
            scan_window: self.options.scan_window,
            target_max_apdu,
            verify_mode,
            authorization,
            load_state_poll_attempts: self.options.load_state_poll_attempts,
            load_state_poll_interval: self.options.load_state_poll_interval,
            minimum_restart_delay: self.options.restart_delay,
            minimum_equal_run: self.options.minimum_equal_run,
        }
    }
}

impl ExecutionSession<'_> {
    pub(crate) async fn install_security(&self) -> std::result::Result<(), Diagnostic> {
        let (mode, tool_key, fdsk) = match &self.access {
            ManagementAccess::ToolKey(key) => {
                (DeviceSecurityMode::Secure, Some(key.key16().expect("Tool Key width")), None)
            }
            ManagementAccess::Fdsk(key) => (DeviceSecurityMode::Secure, None, Some(key.key16().expect("FDSK width"))),
            ManagementAccess::Plaintext => (DeviceSecurityMode::Plain, None, None),
        };
        let entry = SecurityEntry::with_credentials(mode, tool_key, fdsk, self.serial_number).map_err(|error| {
            Diagnostic::new(format!("building the {:?} management credential: {error}", self.access.credential()))
        })?;

        self.bus.set_device_security(self.target, entry).await.map_err(Diagnostic::from)
    }
}

impl<'a> Commissioner<'a> {
    pub(in crate::commissioning) async fn select_management_session(
        &self,
        target: AcquiredTarget,
        material: &ResolvedKeyMaterial,
        options: &ManagementAccessOptions,
    ) -> Result<ExecutionSession<'a>> {
        let plaintext = if options.allow_plaintext {
            PlaintextAccess::Allowed { validate_descriptor: false }
        } else {
            PlaintextAccess::Forbidden
        };
        let (connection, credential) = self
            .bus
            .acquire_management(
                target.address,
                ManagementCredentials::new(target.serial_number, material.tool_key(), material.fdsk()),
                plaintext,
                false,
            )
            .await
            .map_err(|error| Diagnostic::from(error).preparation_context("acquiring management access"))?;
        let access = match credential {
            crate::ManagementCredential::ToolKey => {
                ManagementAccess::ToolKey((*material.tool_key().expect("selected Tool Key")).into())
            }
            crate::ManagementCredential::Fdsk => {
                ManagementAccess::Fdsk((*material.fdsk().expect("selected FDSK")).into())
            }
            crate::ManagementCredential::Plaintext => ManagementAccess::Plaintext,
        };
        let mut session = ExecutionSession::new(
            self.bus,
            target.address,
            self.management_config(self.bus.max_apdu(), false, AuthorizationPolicy::None),
            access,
        )?;
        session.connection = Some(connection);
        session.serial_number = target.serial_number;
        session.replacement_tool_key = material.tool_key().copied().map(Into::into);
        Ok(session)
    }
}
