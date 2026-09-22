//! Format-independent validation of authored projects before commissioning.
//!
//! Validation establishes topology and security invariants that need no product
//! package. Product-aware checks remain in the lowering/compiler boundary, where
//! the exact project-local catalogue selection is available.

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use thiserror::Error;

use super::AuthoredProject;
use crate::model::{
    Diagnostic, DiagnosticLevel, DomainAddress, IpServiceSecurity, Medium, MembershipRole, NetSecurityPolicy,
    ProductReference, ProjectDeviceId, SourceSpan,
};

#[derive(Debug)]
pub struct Download;

/// A project whose format-independent topology invariants hold.
/// Package-aware checks are added by the lowering layer after each exact
/// package catalogue leaf has been opened from the project-local store.
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
        let mut area_numbers = BTreeMap::new();
        let mut line_numbers = BTreeMap::new();

        // Domain addresses are shared by a complete open-medium line. Validate
        // them before individual devices so no compiler can accidentally fill
        // in a missing domain from one product's defaults.
        for area in &self.areas {
            if let Some(previous) = area_numbers.insert(area.number, area.span) {
                error(
                    &mut diagnostics,
                    area.span,
                    format!(
                        "area {} is declared more than once (the first declaration starts at byte {})",
                        area.number, previous.start
                    ),
                );
            }

            for line in &area.lines {
                if let Some(previous) = line_numbers.insert((area.number, line.number), line.span) {
                    error(
                        &mut diagnostics,
                        line.span,
                        format!(
                            "area {}, line {} is declared more than once (the first declaration starts at byte {})",
                            area.number, line.number, previous.start
                        ),
                    );
                }

                match (line.medium, line.domain) {
                    (Medium::Rf, Some(DomainAddress::Rf(domain))) if domain != [0; 6] && domain != [0xff; 6] => {}
                    (Medium::Rf, Some(DomainAddress::Rf(_))) => error(
                        &mut diagnostics,
                        line.domain_span.unwrap_or(line.span),
                        format!(
                            "RF area {}, line {} uses an uncommissioned all-zero or all-FF domain address",
                            area.number, line.number
                        ),
                    ),
                    (Medium::Rf, Some(DomainAddress::Ip(_))) => error(
                        &mut diagnostics,
                        line.domain_span.unwrap_or(line.span),
                        format!("RF area {}, line {} declares an IP domain address", area.number, line.number),
                    ),
                    (Medium::Rf, None) => error(
                        &mut diagnostics,
                        line.span,
                        format!("RF area {}, line {} is missing its 6-byte `domain`", area.number, line.number),
                    ),
                    (Medium::Ip, Some(DomainAddress::Ip(address))) if address[0] & 0xf0 == 0xe0 => {}
                    (Medium::Ip, Some(DomainAddress::Ip(_))) => error(
                        &mut diagnostics,
                        line.domain_span.unwrap_or(line.span),
                        format!("IP area {}, line {} needs a multicast routing domain", area.number, line.number),
                    ),
                    (Medium::Ip, Some(DomainAddress::Rf(_))) => error(
                        &mut diagnostics,
                        line.domain_span.unwrap_or(line.span),
                        format!("IP area {}, line {} declares an RF domain address", area.number, line.number),
                    ),
                    (Medium::Ip, None) => error(
                        &mut diagnostics,
                        line.span,
                        format!(
                            "IP area {}, line {} is missing its routing-multicast `domain`",
                            area.number, line.number
                        ),
                    ),
                    (Medium::Tp1, Some(_)) => error(
                        &mut diagnostics,
                        line.domain_span.unwrap_or(line.span),
                        format!("TP1 area {}, line {} cannot declare a domain address", area.number, line.number),
                    ),
                    (Medium::Tp1, None) => {}
                }
                match (line.medium, line.ip) {
                    (Medium::Ip, Some(_)) => {}
                    (Medium::Ip, None) => error(
                        &mut diagnostics,
                        line.span,
                        format!("IP area {}, line {} is missing project_installation_id", area.number, line.number),
                    ),
                    (_, Some(_)) => error(
                        &mut diagnostics,
                        line.span,
                        format!(
                            "area {}, line {} declares IP installation values on {:?}",
                            area.number, line.number, line.medium
                        ),
                    ),
                    (_, None) => {}
                }
            }
        }

        for device in self.devices.values() {
            let mut disabled_secure_nets = BTreeSet::new();
            let ProductReference::Package { catalog_item, .. } = &device.product;
            if catalog_item.is_empty() {
                error(&mut diagnostics, device.span, format!("device `{}` has an empty CatalogItem ID", device.id));
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

            if device.medium != Medium::Rf && device.rf_mode.is_some() {
                error(
                    &mut diagnostics,
                    device.rf_mode_span.unwrap_or(device.span),
                    format!("device `{}` uses {:?}, which cannot declare `rf_mode`", device.id, device.medium),
                );
            }

            match (device.medium, &device.ip) {
                (Medium::Ip, Some(ip)) => {
                    if ip.multicast_ttl == 0 {
                        error(&mut diagnostics, device.span, format!("IP device `{}` uses multicast_ttl 0", device.id));
                    }
                    let mut additional = BTreeSet::new();
                    for address in &ip.additional_individual_addresses {
                        if address.area() != device.address.area() || address.line() != device.address.line() {
                            error(
                                &mut diagnostics,
                                device.span,
                                format!(
                                    "IP device `{}` additional address {address} is outside its area/line",
                                    device.id
                                ),
                            );
                        }
                        if *address == device.address || !additional.insert(*address) {
                            error(
                                &mut diagnostics,
                                device.span,
                                format!("IP device `{}` repeats individual address {address}", device.id),
                            );
                        }
                        if let Some(previous) = addresses.insert(*address, &device.id) {
                            error(
                                &mut diagnostics,
                                device.span,
                                format!(
                                    "devices `{previous}` and `{}` both use additional individual address {address}",
                                    device.id
                                ),
                            );
                        }
                    }
                    if let Some(security) = &ip.security {
                        if let Some(line) = self.line_topology(device.area, device.line).and_then(|line| line.ip)
                            && (line.multicast_latency_tolerance_ms != Some(security.multicast_latency_tolerance_ms)
                                || line.sync_latency_fraction != Some(security.sync_latency_fraction))
                        {
                            error(
                                &mut diagnostics,
                                device.span,
                                format!(
                                    "IP Secure device `{}` timing values disagree with its authored line",
                                    device.id
                                ),
                            );
                        }
                        let needs_password = security.device_management == IpServiceSecurity::Secure
                            || security.tunnelling == IpServiceSecurity::Secure;
                        if needs_password && !ip.password_users.iter().any(|user| user.get() == 1) {
                            error(
                                &mut diagnostics,
                                device.span,
                                format!("IP Secure device `{}` is missing management password user 1", device.id),
                            );
                        }
                        for (index, user_id) in ip.password_users.iter().enumerate() {
                            let expected = u8::try_from(index + 1).ok();
                            if expected != Some(user_id.get()) {
                                error(
                                    &mut diagnostics,
                                    device.span,
                                    format!(
                                        "IP Secure device `{}` password users must be dense from user 1",
                                        device.id
                                    ),
                                );
                                break;
                            }
                        }
                        let mut bindings = BTreeMap::new();
                        let mut address_indices = BTreeSet::new();
                        for binding in &security.tunnelling_users {
                            if let Some(previous) = bindings.insert(binding.user_id, binding.address_index) {
                                error(
                                    &mut diagnostics,
                                    device.span,
                                    format!(
                                        "IP Secure device `{}` maps tunnelling user {} to both address indices {previous} and {}",
                                        device.id, binding.user_id, binding.address_index,
                                    ),
                                );
                            }
                            if !address_indices.insert(binding.address_index) {
                                error(
                                    &mut diagnostics,
                                    device.span,
                                    format!(
                                        "IP Secure device `{}` reuses tunnelling address index {}",
                                        device.id, binding.address_index
                                    ),
                                );
                            }
                            if !ip.password_users.contains(&binding.user_id) {
                                error(
                                    &mut diagnostics,
                                    device.span,
                                    format!(
                                        "IP Secure device `{}` binds user {} without declaring its password hash",
                                        device.id, binding.user_id
                                    ),
                                );
                            }
                        }
                    }
                }
                // Whether IP state is tool-managed or product-owned comes
                // from ApplicationProgram/@IPConfig, which is unavailable at
                // syntax validation. Product-aware lowering requires this
                // block for Tool and forbids it for Custom.
                (Medium::Ip, None) => {}
                (_, Some(_)) => error(
                    &mut diagnostics,
                    device.span,
                    format!("non-IP device `{}` declares IP configuration", device.id),
                ),
                (_, None) => {}
            }

            match (device.coupler_role(), device.routing) {
                (Some(_), None) => error(
                    &mut diagnostics,
                    device.span,
                    format!(
                        "topology coupler `{}` at {} is missing its explicit `routing` policy",
                        device.id, device.address
                    ),
                ),
                (None, Some(_)) => error(
                    &mut diagnostics,
                    device.span,
                    format!(
                        "device `{}` at {} declares `routing`, but only an address-zero topology coupler may do so",
                        device.id, device.address
                    ),
                ),
                _ => {}
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
                if !is_full_mtxml_parameter_id(&parameter.id) {
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
                            if device.active {
                                policies.insert(
                                    self.effective_net_security(&net.id)
                                        .expect("the membership net was found in this project"),
                                );
                            } else if net.security != NetSecurityPolicy::Automatic {
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
        self.nets
            .values()
            .filter(|net| self.effective_net_security(&net.id).is_some_and(|policy| policy != NetSecurityPolicy::Plain))
    }
}

/// Project overrides use the exact configuration-value identity. Ordinary
/// products without a reference layer use a base `_P-`/`_UP-` ID. Dynamic
/// products use a `_R-` ParameterRef ID because several independent controls
/// may reuse one UI-only base parameter. Module values prefix that identity
/// with their concrete module instance and `::`.
fn is_full_mtxml_parameter_id(id: &str) -> bool {
    fn base(id: &str) -> bool {
        id.starts_with("M-")
            && ["_P-", "_UP-"].into_iter().any(|marker| {
                id.rsplit_once(marker)
                    .is_some_and(|(_, number)| !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
            })
    }

    fn reference(id: &str) -> bool {
        id.rsplit_once("_R-").is_some_and(|(base_id, number)| {
            base(base_id) && !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        })
    }

    if let Some((instance, parameter)) = id.split_once("::") {
        !instance.is_empty()
            && instance.starts_with("M-")
            && instance.contains("_M-")
            && !parameter.contains("::")
            && (base(parameter) || reference(parameter))
    } else {
        base(id) || reference(id)
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
    use crate::{AuthoredProject, DiagnosticLevel, ProductReference};

    const PRODUCT: &str = concat!(
        "product package:\"sha256:0000000000000000000000000000000000000000000000000000000000000000\" ",
        "catalog_item \"M-00FA_H-1_P-1_CI-1\"",
    );

    fn with_product(source: &str) -> String {
        source.replace("PRODUCT", PRODUCT)
    }

    fn project(object: &str) -> AuthoredProject {
        AuthoredProject::parse(with_product(&format!(
            "ga a = 1/0/1\nnet a : 1.001 {{ security plain }}\narea 1 x {{ line 1 x {{ medium tp1 device d {{ PRODUCT address 1.1.1 object 0 {{ {object} }} }} }} }}"
        )))
        .expect("project parses")
    }

    #[test]
    fn inactive_devices_do_not_participate_in_download_validation() {
        let source = "ga a = 1/0/1\nnet a : 1.001 { security authentication_confidentiality }\narea 1 x { line 1 x { medium tp1 device active { PRODUCT address 1.1.1 data_secure enabled object 0 { on a } } device parked { active false PRODUCT address 1.1.2 data_secure disabled object 0 { on a } } } }";
        let project = AuthoredProject::parse(with_product(source)).expect("project parses");

        project.validate_download().expect("parked secure-topology conflicts are ignored");
    }

    #[test]
    fn validation_rejects_an_empty_catalog_item_after_model_mutation() {
        let mut project = project("on a");
        let ProductReference::Package { catalog_item, .. } =
            &mut project.devices.values_mut().next().expect("project has a device").product;
        catalog_item.clear();

        let error = project.validate_download().expect_err("empty CatalogItem is rejected");

        assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.message.contains("empty CatalogItem")));
    }

    #[test]
    fn full_union_parameter_ids_are_valid_project_overrides() {
        let source = "area 1 x { line 1 x { medium tp1 device d { PRODUCT address 1.1.1 param \"M-0083_A-0095-15-B3F0_UP-570\" = 4 } } }";
        AuthoredProject::parse(with_product(source))
            .expect("union-parameter project parses")
            .validate_download()
            .expect("full union parameter ID validates");
    }

    #[test]
    fn parameter_ref_ids_are_configuration_value_ids() {
        let source = "area 1 x { line 1 x { medium tp1 device d { PRODUCT address 1.1.1 param \"M-0083_A-0095-15-B3F0_UP-570_R-2731\" = 4 } } }";
        AuthoredProject::parse(with_product(source))
            .expect("parameter-ref-shaped project parses")
            .validate_download()
            .expect("a ParameterRef is an exact configuration identity");
    }

    #[test]
    fn module_parameter_ids_are_configuration_value_ids() {
        let source = "area 1 x { line 1 x { medium tp1 device d { PRODUCT address 1.1.1 param \"M-0083_A-018C-23-81D7_MD-2_M-2@M-0083_A-018C-23-81D7_X-3[0000000001]::M-0083_A-018C-23-81D7_MD-2_P-1\" = 4 } } }";
        AuthoredProject::parse(with_product(source))
            .expect("module-parameter project parses")
            .validate_download()
            .expect("a concrete module parameter is an exact configuration identity");
    }

    #[test]
    fn memberships_require_one_primary() {
        let error = project("also on a").validate_download().expect_err("additional-only object is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.message.contains("exactly one")));
    }

    #[test]
    fn disabled_device_rejects_primary_secure_membership() {
        let source = "ga a = 1/0/1\nnet a : 1.001 { security authentication_confidentiality }\narea 1 x { line 1 x { medium tp1 device d { PRODUCT address 1.1.1 object 0 { on a } } } }";
        let error = AuthoredProject::parse(with_product(source))
            .expect("project parses")
            .validate_download()
            .expect_err("disabled device is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| {
            diagnostic.message.contains("Data Secure disabled") && diagnostic.message.contains("net `a`")
        }));
    }

    #[test]
    fn disabled_device_rejects_additional_secure_membership() {
        let source = "ga plain = 1/0/1\nga secure = 1/0/2\nnet plain : 1.001 { security plain }\nnet secure : 1.001 { security authentication }\narea 1 x { line 1 x { medium tp1 device d { PRODUCT address 1.1.1 object 0 { on plain also on secure } } } }";
        let error = AuthoredProject::parse(with_product(source))
            .expect("project parses")
            .validate_download()
            .expect_err("secure additional membership is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.message.contains("net `secure`")));
    }

    #[test]
    fn enabled_device_accepts_explicit_secure_membership() {
        let source = "ga a = 1/0/1\nnet a : 1.001 { security authentication_confidentiality }\narea 1 x { line 1 x { medium tp1 device d { PRODUCT address 1.1.1 data_secure enabled object 0 { on a } } } }";
        AuthoredProject::parse(with_product(source))
            .expect("project parses")
            .validate_download()
            .expect("enabled device is accepted");
    }

    #[test]
    fn one_object_cannot_mix_plain_and_secure_memberships() {
        let source = "ga plain = 1/0/1\nga secure = 1/0/2\nnet plain : 1.001 { security plain }\nnet secure : 1.001 { security authentication_confidentiality }\narea 1 x { line 1 x { medium tp1 device d { PRODUCT address 1.1.1 data_secure enabled object 0 { on plain also on secure } } } }";
        let error = AuthoredProject::parse(with_product(source))
            .expect("project parses")
            .validate_download()
            .expect_err("mixed object protection is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.message.contains("PID 61 is per object")));
    }

    #[test]
    fn secure_net_rejects_one_plain_member_among_secure_devices() {
        let source = "ga a = 1/0/1\nnet a : 1.001 { security authentication_confidentiality }\narea 1 x { line 1 x { medium tp1 device secure { PRODUCT address 1.1.1 data_secure enabled object 0 { on a } } device plain { PRODUCT address 1.1.2 data_secure disabled object 0 { on a } } } }";
        let error = AuthoredProject::parse(with_product(source))
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
        let source = "ga a = 1/0/1\nnet a : 1.001 { security authentication }\nexternal_sender legacy { address 1.1.250 data_secure disabled on a }\narea 1 x { line 1 x { medium tp1 device d { PRODUCT address 1.1.1 data_secure enabled object 0 { on a } } } }";
        let error = AuthoredProject::parse(with_product(source))
            .expect("project parses")
            .validate_download()
            .expect_err("plain external sender is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| {
            diagnostic.message.contains("external sender `legacy`")
                && diagnostic.message.contains("Data Secure disabled")
        }));
    }

    #[test]
    fn automatic_security_requires_every_active_participant_to_be_secure() {
        let all_secure = AuthoredProject::parse(with_product(
            "ga a = 1/0/1\nnet a : 1.001 { security automatic }\narea 1 x { line 1 x { medium tp1 device first { PRODUCT address 1.1.1 data_secure enabled object 0 { on a } } device second { PRODUCT address 1.1.2 data_secure enabled object 0 { on a } } device parked { active false PRODUCT address 1.1.3 data_secure disabled object 0 { on a } } } }",
        ))
        .expect("secure automatic project parses");
        assert_eq!(
            all_secure.effective_net_security(&crate::NetId("a".into())),
            Some(crate::NetSecurityPolicy::AuthenticationConfidentiality),
        );

        let insecure_device = AuthoredProject::parse(with_product(
            "ga a = 1/0/1\nnet a : 1.001 { security automatic }\narea 1 x { line 1 x { medium tp1 device secure { PRODUCT address 1.1.1 data_secure enabled object 0 { on a } } device legacy { PRODUCT address 1.1.2 data_secure disabled object 0 { on a } } } }",
        ))
        .expect("mixed automatic project parses");
        assert_eq!(
            insecure_device.effective_net_security(&crate::NetId("a".into())),
            Some(crate::NetSecurityPolicy::Plain),
        );

        let insecure_external = AuthoredProject::parse(with_product(
            "ga a = 1/0/1\nnet a : 1.001 { security automatic }\nexternal_sender legacy { address 1.1.250 data_secure disabled on a }\narea 1 x { line 1 x { medium tp1 device secure { PRODUCT address 1.1.1 data_secure enabled object 0 { on a } } } }",
        ))
        .expect("external-sender automatic project parses");
        assert_eq!(
            insecure_external.effective_net_security(&crate::NetId("a".into())),
            Some(crate::NetSecurityPolicy::Plain),
        );
    }

    #[test]
    fn effective_automatic_policy_participates_in_object_compatibility() {
        let source = "ga plain = 1/0/1\nga automatic = 1/0/2\nnet plain : 1.001 { security plain }\nnet automatic : 1.001 { security automatic }\narea 1 x { line 1 x { medium tp1 device d { PRODUCT address 1.1.1 data_secure enabled object 0 { on plain also on automatic } } } }";
        let error = AuthoredProject::parse(with_product(source))
            .expect("project parses")
            .validate_download()
            .expect_err("plain and effectively secure memberships conflict");

        assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.message.contains("PID 61 is per object")));
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

    #[test]
    fn rf_lines_require_a_valid_domain_but_device_mode_is_profile_dependent() {
        let rf = AuthoredProject::parse(with_product(
            "area 1 a { line 1 l { medium rf domain \"00:FA:12:34:56:78\" device ready { PRODUCT address 1.1.1 rf_mode ready } device unspecified { PRODUCT address 1.1.2 } } }",
        ))
        .expect("RF project parses");
        rf.validate_download().expect("RF topology with an optional per-device mode validates");

        for (source, expected) in [
            ("area 1 a { line 1 l { medium rf device d { PRODUCT address 1.1.1 } } }", "missing its 6-byte `domain`"),
            (
                "area 1 a { line 1 l { medium rf domain \"00:00:00:00:00:00\" device d { PRODUCT address 1.1.1 rf_mode multi } } }",
                "uncommissioned all-zero or all-FF domain",
            ),
            (
                "area 1 a { line 1 l { medium rf domain \"FF:FF:FF:FF:FF:FF\" device d { PRODUCT address 1.1.1 rf_mode multi } } }",
                "uncommissioned all-zero or all-FF domain",
            ),
        ] {
            let error = AuthoredProject::parse(with_product(source))
                .expect("project parses before semantic validation")
                .validate_download()
                .expect_err("incomplete or mismatched topology is rejected");
            assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.message.contains(expected)));
        }
    }

    #[test]
    fn closed_medium_lines_reject_domain_and_device_rf_mode_values() {
        let domain_error = AuthoredProject::parse(with_product(
            "area 1 a { line 1 l { medium tp1 domain \"00:FA:12:34:56:78\" device d { PRODUCT address 1.1.1 } } }",
        ))
        .expect_err("TP1 domain syntax is rejected before semantic validation");
        assert!(domain_error.message.contains("TP1 lines cannot declare a domain address"));

        let error = AuthoredProject::parse(with_product(
            "area 1 a { line 1 l { medium tp1 device d { PRODUCT address 1.1.1 rf_mode ready } } }",
        ))
        .expect("device RF mode syntax parses before semantic validation")
        .validate_download()
        .expect_err("TP device RF mode is rejected");

        assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.message.contains("cannot declare `rf_mode`")));
    }

    #[test]
    fn routing_is_required_exactly_on_address_zero_couplers() {
        let valid = AuthoredProject::parse(with_product(
            "area 1 a { line 1 l { medium tp1 device c { PRODUCT address 1.1.0 routing filter } } }",
        ))
        .expect("coupler parses");
        valid.validate_download().expect("explicit coupler routing validates");

        let missing = AuthoredProject::parse(with_product(
            "area 1 a { line 1 l { medium tp1 device c { PRODUCT address 1.1.0 } } }",
        ))
        .expect("coupler parses");
        let error = missing.validate_download().expect_err("implicit coupler routing is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.message.contains("missing its explicit")));

        let ordinary = AuthoredProject::parse(with_product(
            "area 1 a { line 1 l { medium tp1 device d { PRODUCT address 1.1.1 routing filter } } }",
        ))
        .expect("ordinary device parses");
        let error = ordinary.validate_download().expect_err("ordinary routing policy is rejected");
        assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.message.contains("only an address-zero")));
    }
}
