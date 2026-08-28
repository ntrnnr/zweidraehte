use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use thiserror::Error;

use crate::model::{
    AuthoredProject, Diagnostic, DiagnosticLevel, MembershipRole, NetSecurityPolicy, ProductReference, ProjectDeviceId,
    SourceSpan,
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
            let mut disabled_secure_nets = BTreeSet::new();
            let ProductReference::Local(product_path) = &device.product;
            let is_archive =
                product_path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("knxprod"));
            if !is_archive && (device.catalog_product.is_some() || device.application_program.is_some()) {
                error(
                    &mut diagnostics,
                    device.span,
                    format!("device `{}` selects archive metadata for a non-.knxprod product", device.id),
                );
            }
            if device.catalog_product.is_some() && device.application_program.is_none() {
                error(
                    &mut diagnostics,
                    device.span,
                    format!("device `{}` selects a catalogue product without an application program", device.id),
                );
            }
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
                            // An inactive device retains its links for later
                            // reactivation, but those links are not members of
                            // the currently deployable secure topology.
                            if device.active
                                && !device.data_secure.is_enabled()
                                && matches!(
                                    net.security,
                                    NetSecurityPolicy::Authentication
                                        | NetSecurityPolicy::AuthenticationConfidentiality
                                )
                                && disabled_secure_nets.insert(net.id.clone())
                            {
                                error(
                                    &mut diagnostics,
                                    membership.span,
                                    format!(
                                        "device `{}` has Data Secure disabled but is linked to secured net `{}`",
                                        device.id, net.id
                                    ),
                                );
                            }
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
                match self.nets.get(net) {
                    None => error(
                        &mut diagnostics,
                        sender.span,
                        format!("external sender `{}` refers to unknown net `{net}`", sender.id),
                    ),
                    Some(net)
                        if !sender.data_secure.is_enabled()
                            && matches!(
                                net.security,
                                NetSecurityPolicy::Authentication | NetSecurityPolicy::AuthenticationConfidentiality
                            ) =>
                    {
                        error(
                            &mut diagnostics,
                            sender.span,
                            format!(
                                "external sender `{}` has Data Secure disabled but is linked to secured net `{}`",
                                sender.id, net.id
                            ),
                        );
                    }
                    Some(_) => {}
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
            .filter(|device| device.active)
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
    fn inactive_devices_do_not_participate_in_download_validation() {
        let source = "ga a = 1/0/1\nnet a : 1.001 { security authentication_confidentiality }\narea 1 x { line 1 x { medium tp1 device active { product local:\"a.mtxml\" address 1.1.1 data_secure enabled object 0 { on a } } device parked { active false product local:\"p.mtxml\" address 1.1.2 data_secure disabled object 0 { on a } } } }";
        let project = AuthoredProject::parse(source).expect("project parses");

        project.validate_download().expect("parked secure-topology conflicts are ignored");
    }

    #[test]
    fn memberships_require_one_primary() {
        let error = project("also on a").validate_download().expect_err("additional-only object is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.message.contains("exactly one")));
    }

    #[test]
    fn disabled_device_rejects_primary_secure_membership() {
        let source = "ga a = 1/0/1\nnet a : 1.001 { security authentication_confidentiality }\narea 1 x { line 1 x { medium tp1 device d { product local:\"d.mtxml\" address 1.1.1 object 0 { on a } } } }";
        let error = AuthoredProject::parse(source)
            .expect("project parses")
            .validate_download()
            .expect_err("disabled device is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| {
            diagnostic.message.contains("Data Secure disabled") && diagnostic.message.contains("net `a`")
        }));
    }

    #[test]
    fn disabled_device_rejects_additional_secure_membership() {
        let source = "ga plain = 1/0/1\nga secure = 1/0/2\nnet plain : 1.001 { security plain }\nnet secure : 1.001 { security authentication }\narea 1 x { line 1 x { medium tp1 device d { product local:\"d.mtxml\" address 1.1.1 object 0 { on plain also on secure } } } }";
        let error = AuthoredProject::parse(source)
            .expect("project parses")
            .validate_download()
            .expect_err("secure additional membership is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.message.contains("net `secure`")));
    }

    #[test]
    fn enabled_device_accepts_explicit_secure_membership() {
        let source = "ga a = 1/0/1\nnet a : 1.001 { security authentication_confidentiality }\narea 1 x { line 1 x { medium tp1 device d { product local:\"d.mtxml\" address 1.1.1 data_secure enabled object 0 { on a } } } }";
        AuthoredProject::parse(source)
            .expect("project parses")
            .validate_download()
            .expect("enabled device is accepted");
    }

    #[test]
    fn one_object_cannot_mix_plain_and_secure_memberships() {
        let source = "ga plain = 1/0/1\nga secure = 1/0/2\nnet plain : 1.001 { security plain }\nnet secure : 1.001 { security authentication_confidentiality }\narea 1 x { line 1 x { medium tp1 device d { product local:\"d.mtxml\" address 1.1.1 data_secure enabled object 0 { on plain also on secure } } } }";
        let error = AuthoredProject::parse(source)
            .expect("project parses")
            .validate_download()
            .expect_err("mixed object protection is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.message.contains("PID 61 is per object")));
    }

    #[test]
    fn secure_net_rejects_one_plain_member_among_secure_devices() {
        let source = "ga a = 1/0/1\nnet a : 1.001 { security authentication_confidentiality }\narea 1 x { line 1 x { medium tp1 device secure { product local:\"s.mtxml\" address 1.1.1 data_secure enabled object 0 { on a } } device plain { product local:\"p.mtxml\" address 1.1.2 data_secure disabled object 0 { on a } } } }";
        let error = AuthoredProject::parse(source)
            .expect("project parses")
            .validate_download()
            .expect_err("plain member is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| {
            diagnostic.message.contains("device `plain`") && diagnostic.message.contains("Data Secure disabled")
        }));
        assert!(!error.diagnostics().iter().any(
            |diagnostic| diagnostic.message.contains("device `secure`") && diagnostic.message.contains("disabled")
        ));
    }

    #[test]
    fn secure_net_rejects_a_plain_external_sender() {
        let source = "ga a = 1/0/1\nnet a : 1.001 { security authentication }\nexternal_sender legacy { address 1.1.250 data_secure disabled on a }\narea 1 x { line 1 x { medium tp1 device d { product local:\"d.mtxml\" address 1.1.1 data_secure enabled object 0 { on a } } } }";
        let error = AuthoredProject::parse(source)
            .expect("project parses")
            .validate_download()
            .expect_err("plain external sender is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| {
            diagnostic.message.contains("external sender `legacy`")
                && diagnostic.message.contains("Data Secure disabled")
        }));
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
