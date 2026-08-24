use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use thiserror::Error;

use crate::model::{
    AuthoredProject, Diagnostic, DiagnosticLevel, MembershipRole, NetSecurityPolicy, ProjectDeviceId, SourceSpan,
};

#[derive(Debug)]
pub struct Download;

/// A project whose format-independent topology invariants hold.
/// Product-aware checks are added by the lowering layer after each MTXML
/// file has been opened.
#[derive(Debug)]
pub struct ValidatedProject<'a, Purpose> {
    project: &'a AuthoredProject,
    diagnostics: Vec<Diagnostic>,
    _purpose: PhantomData<Purpose>,
}

impl<'a, Purpose> ValidatedProject<'a, Purpose> {
    pub fn project(&self) -> &'a AuthoredProject {
        self.project
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
}

#[derive(Debug, Error)]
#[error("project validation failed")]
pub struct ValidationError {
    diagnostics: Vec<Diagnostic>,
}

impl ValidationError {
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
}

impl AuthoredProject {
    pub fn validate_download(&self) -> Result<ValidatedProject<'_, Download>, ValidationError> {
        let mut diagnostics = Vec::new();
        let mut addresses = BTreeMap::new();
        let mut serials = BTreeMap::new();

        for device in self.devices.values() {
            if let Some(previous) = addresses.insert(device.address, &device.id) {
                error(
                    &mut diagnostics,
                    device.span,
                    format!("devices `{previous}` and `{}` both use {}", device.id, device.address),
                );
            }
            if let Some(serial) = device.serial
                && let Some(previous) = serials.insert(serial, &device.id)
            {
                error(
                    &mut diagnostics,
                    device.span,
                    format!("devices `{previous}` and `{}` have the same serial number", device.id),
                );
            }

            let mut parameter_ids = BTreeSet::new();
            for parameter in &device.parameters {
                if !parameter_ids.insert(&parameter.id) {
                    error(
                        &mut diagnostics,
                        parameter.span,
                        format!("device `{}` assigns parameter `{}` more than once", device.id, parameter.id),
                    );
                }
                if !parameter.id.starts_with("M-") || !parameter.id.contains("_P-") {
                    error(
                        &mut diagnostics,
                        parameter.span,
                        format!("device `{}` must use a full MTXML parameter ID, got `{}`", device.id, parameter.id),
                    );
                }
            }

            for object in device.objects.values() {
                let primary_count =
                    object.memberships.iter().filter(|membership| membership.role == MembershipRole::Primary).count();
                if !object.memberships.is_empty() && primary_count != 1 {
                    error(
                        &mut diagnostics,
                        object.span,
                        format!(
                            "device `{}`, object {} has {} memberships but {primary_count} primary associations; exactly one is required",
                            device.id,
                            object.com_object,
                            object.memberships.len()
                        ),
                    );
                }
                let mut policies = BTreeSet::new();
                for membership in &object.memberships {
                    match self.nets.get(&membership.net) {
                        Some(net) => {
                            if net.security != NetSecurityPolicy::Automatic {
                                policies.insert(net.security);
                            }
                        }
                        None => error(
                            &mut diagnostics,
                            membership.span,
                            format!(
                                "device `{}`, object {} refers to unknown net `{}`",
                                device.id, object.com_object, membership.net
                            ),
                        ),
                    }
                }
                if policies.len() > 1 {
                    error(
                        &mut diagnostics,
                        object.span,
                        format!(
                            "device `{}`, object {} belongs to nets with incompatible security policies; PID 61 is per object",
                            device.id, object.com_object
                        ),
                    );
                }

                // These checks use explicit overrides only. Effective
                // product/ref flags are checked again during lowering.
                let flags = object.flags;
                let traffic_without_primary =
                    flags.transmit == Some(true) || flags.read == Some(true) || flags.read_on_init == Some(true);
                if traffic_without_primary && primary_count == 0 {
                    error(
                        &mut diagnostics,
                        object.span,
                        format!(
                            "device `{}`, object {} enables T, R, or I without a primary association",
                            device.id, object.com_object
                        ),
                    );
                }
                if flags.read_on_init == Some(true) && flags.update == Some(false) {
                    warning(
                        &mut diagnostics,
                        object.span,
                        format!(
                            "device `{}`, object {} enables read-on-init while update is disabled; it cannot consume the response",
                            device.id, object.com_object
                        ),
                    );
                }
                let any_traffic = [flags.read, flags.write, flags.transmit, flags.update, flags.read_on_init]
                    .into_iter()
                    .any(|flag| flag == Some(true));
                if flags.communication == Some(false) && any_traffic {
                    warning(
                        &mut diagnostics,
                        object.span,
                        format!(
                            "device `{}`, object {} has traffic flags enabled while communication is disabled; those flags are inert",
                            device.id, object.com_object
                        ),
                    );
                }
            }
        }

        for sender in self.external_senders.values() {
            if sender.nets.is_empty() {
                warning(
                    &mut diagnostics,
                    sender.span,
                    format!("external sender `{}` is not linked to any net", sender.id),
                );
            }
            for net in &sender.nets {
                if !self.nets.contains_key(net) {
                    error(
                        &mut diagnostics,
                        sender.span,
                        format!("external sender `{}` refers to unknown net `{net}`", sender.id),
                    );
                }
            }
        }

        if diagnostics.iter().any(|diagnostic| diagnostic.level == DiagnosticLevel::Error) {
            Err(ValidationError { diagnostics })
        } else {
            Ok(ValidatedProject { project: self, diagnostics, _purpose: PhantomData })
        }
    }

    /// Candidate managed senders based solely on authored overrides.
    /// Product defaults are intentionally not guessed here.
    pub fn explicit_sender_devices(&self, net: &crate::model::NetId) -> BTreeSet<ProjectDeviceId> {
        self.devices
            .values()
            .filter(|device| {
                device.objects.values().any(|object| {
                    let primary = object
                        .memberships
                        .iter()
                        .any(|membership| membership.role == MembershipRole::Primary && &membership.net == net);
                    let flags = object.flags;
                    primary
                        && flags.communication == Some(true)
                        && (flags.transmit == Some(true)
                            || flags.read == Some(true)
                            || flags.read_on_init == Some(true))
                })
            })
            .map(|device| device.id.clone())
            .collect()
    }

    pub fn secured_nets(&self) -> impl Iterator<Item = &crate::model::Net> {
        self.nets.values().filter(|net| net.security != NetSecurityPolicy::Plain)
    }
}

fn error(diagnostics: &mut Vec<Diagnostic>, span: SourceSpan, message: String) {
    diagnostics.push(Diagnostic { level: DiagnosticLevel::Error, message, span });
}

fn warning(diagnostics: &mut Vec<Diagnostic>, span: SourceSpan, message: String) {
    diagnostics.push(Diagnostic { level: DiagnosticLevel::Warning, message, span });
}

#[cfg(test)]
mod tests {
    use crate::{AuthoredProject, DiagnosticLevel};

    fn project(object: &str) -> AuthoredProject {
        AuthoredProject::parse(format!(
            "ga a = 1/0/1\nnet a : 1.001 {{ security plain }}\narea 1 x {{ line 1 x {{ medium tp1 device d {{ product local:\"d.mtxml\" address 1.1.1 object 0 {{ {object} }} }} }} }}"
        ))
        .expect("project parses")
    }

    #[test]
    fn memberships_require_one_primary() {
        let error = project("also on a").validate_download().expect_err("additional-only object is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.message.contains("exactly one")));
    }

    #[test]
    fn write_and_update_do_not_make_a_sender() {
        let project = project("on a flags { communication true write true update true }");
        project.validate_download().expect("project validates");
        assert!(project.explicit_sender_devices(&crate::NetId("a".into())).is_empty());
    }

    #[test]
    fn inert_flags_are_a_warning_not_an_error() {
        let project = project("on a flags { communication false transmit true }");
        let validated = project.validate_download().expect("project validates with warning");
        assert!(validated.diagnostics().iter().any(|diagnostic| diagnostic.level == DiagnosticLevel::Warning));
    }
}
