//! Validate request limits, management access and installed realization requirements.

use crate::commissioning::catalog::profile::{ResolvedProfile, ResourceManagementStyle};
use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::error::DiagnosticResult as Result;
use crate::commissioning::error::PreparationFailure;
use crate::commissioning::input::{CommissioningIntent, DownloadMode};
use crate::commissioning::runtime::AuthorizationPolicy;
use crate::commissioning::runtime::commissioner::{CommissionerOptions, FREE_ACCESS_KEY, STANDARD_APDU_LENGTH};
use crate::commissioning::runtime::credentials::ManagementAccessOptions;
use crate::configuration::ResolvedKeyMaterial;
use zweidraehte_proto::messages::apdu::secure;

pub(in crate::commissioning) fn validate_options(
    options: &CommissionerOptions,
    configured_max_apdu: Option<u16>,
) -> Result<()> {
    if options.scan_window.is_zero() {
        return Err(Diagnostic::preparation(
            PreparationFailure::InvalidOptions,
            "the target scan window must not be zero",
        ));
    }
    if options.load_state_poll_attempts == 0 {
        return Err(Diagnostic::preparation(
            PreparationFailure::InvalidOptions,
            "load-state polling requires at least one attempt",
        ));
    }
    if options.load_state_poll_interval.is_zero() {
        return Err(Diagnostic::preparation(
            PreparationFailure::InvalidOptions,
            "the load-state polling interval must not be zero",
        ));
    }
    if options.required_authorization_level > 15 {
        return Err(Diagnostic::preparation(
            PreparationFailure::InvalidOptions,
            "the required authorization level exceeds four bits",
        ));
    }
    if options.minimum_equal_run == 0 {
        return Err(Diagnostic::preparation(
            PreparationFailure::InvalidOptions,
            "the differential minimum-equal run must not be zero",
        ));
    }
    if let Some(configured_max_apdu) = configured_max_apdu
        && configured_max_apdu < STANDARD_APDU_LENGTH
    {
        return Err(Diagnostic::preparation(
            PreparationFailure::InvalidOptions,
            format!("the configured maximum APDU {configured_max_apdu} is below the KNX standard-frame capacity"),
        ));
    }

    Ok(())
}

pub(in crate::commissioning) fn validate_credential_inputs(credentials: &ResolvedKeyMaterial) -> Result<()> {
    if credentials.tool_key().is_some() && credentials.tool_key() == credentials.fdsk() {
        return Err(Diagnostic::preparation(
            PreparationFailure::InvalidOptions,
            "the Tool Key must differ from the FDSK",
        ));
    }

    Ok(())
}

pub(in crate::commissioning) fn resolve_profile_authorization(
    profile: &ResolvedProfile,
    required_level: u8,
    access: &ManagementAccessOptions,
) -> Result<AuthorizationPolicy> {
    let Some(declared_levels) = profile
        .feature("AuthorizeLevels")
        .map_err(|error| Diagnostic::preparation(PreparationFailure::Profile, error.to_string()))?
    else {
        return Ok(AuthorizationPolicy::None);
    };
    let declared_levels = u8::try_from(declared_levels).map_err(|_| {
        Diagnostic::preparation(
            PreparationFailure::Profile,
            format!("profile {} has invalid AuthorizeLevels value {declared_levels:?}", profile.mask()),
        )
    })?;
    if !(1..=16).contains(&declared_levels) {
        return Err(Diagnostic::preparation(
            PreparationFailure::Profile,
            format!(
                "profile {} declares {declared_levels} authorization levels, but KNX supports 1 through 16",
                profile.mask()
            ),
        ));
    }

    if required_level >= declared_levels {
        return Err(Diagnostic::preparation(
            PreparationFailure::Capability,
            format!(
                "authorization level {required_level} is unavailable for profile {} with {declared_levels} declared levels",
                profile.mask()
            ),
        ));
    }

    Ok(AuthorizationPolicy::LegacyKey { key: access.access_key().unwrap_or(FREE_ACCESS_KEY).into(), required_level })
}

pub(in crate::commissioning) fn validate_apdu_requirements(
    plan: &CompiledProgram,
    interface_max: u16,
    target_max: u16,
    configured_max: Option<u16>,
    secure_management: bool,
    secure_address_assignment: bool,
) -> Result<()> {
    let wire_max = interface_max.min(target_max).min(configured_max.unwrap_or(u16::MAX));
    let secure_overhead =
        if secure_management { u16::try_from(secure::OVERHEAD).expect("secure envelope overhead fits u16") } else { 0 };

    for (phase, required, overhead) in [
        ("procedure", plan.apdu_requirements().procedure, secure_overhead),
        (
            "address assignment",
            plan.apdu_requirements().address_assignment,
            if secure_address_assignment { secure_overhead } else { 0 },
        ),
        ("network configuration", plan.apdu_requirements().network_configuration, secure_overhead),
    ] {
        let Some(required) = required else {
            continue;
        };
        let required_wire = required.checked_add(overhead).ok_or_else(|| {
            Diagnostic::preparation(
                PreparationFailure::Capability,
                format!("secure {phase} APDU requirement overflows"),
            )
        })?;
        if required_wire > wire_max {
            return Err(Diagnostic::preparation(
                PreparationFailure::Capability,
                format!("{phase} requires wire APDU {required_wire}, but interface/target/project allow {wire_max}"),
            ));
        }
    }

    Ok(())
}

pub(in crate::commissioning) fn validate_partial_management_style(
    observed: Option<ResourceManagementStyle>,
    plan: &CompiledProgram,
) -> Result<()> {
    if operation_requires_installed_management_style(plan)
        && let (Some(observed), Some(target)) = (observed, plan.profile().management_style())
        && observed != target
    {
        return Err(Diagnostic::preparation(
            PreparationFailure::Capability,
            format!(
                "the requested operation needs installed {observed:?} management, but the project resolves {target:?}"
            ),
        ));
    }

    Ok(())
}

pub(in crate::commissioning) fn operation_requires_installed_management_style(plan: &CompiledProgram) -> bool {
    matches!(plan.intent(), CommissioningIntent::Unload(_))
        || match plan.intent().download_mode() {
            Some(DownloadMode::Partial(_)) => true,
            Some(DownloadMode::Automatic) => !plan.is_full_program_scope(),
            _ => false,
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::compiler::binding::tests::preparation_support::authorization_profile;
    use crate::commissioning::runtime::policy::resolve_profile_authorization;

    #[test]
    fn bcu1_profile_skips_legacy_authorization_even_with_a_key() {
        let profile = authorization_profile("Bcu1", None);
        let credentials = ManagementAccessOptions::new().with_access_key([1, 2, 3, 4]);
        let authorization =
            resolve_profile_authorization(&profile, 3, &credentials).expect("profile authorization resolves");

        assert_eq!(authorization, AuthorizationPolicy::None);
    }

    #[test]
    fn bcu2_profile_uses_the_free_access_key_by_default() {
        let profile = authorization_profile("Bcu2", Some(4));
        let credentials = ManagementAccessOptions::new();
        let authorization =
            resolve_profile_authorization(&profile, 3, &credentials).expect("profile authorization resolves");

        assert_eq!(authorization, AuthorizationPolicy::LegacyKey { key: FREE_ACCESS_KEY.into(), required_level: 3 });
    }

    #[test]
    fn profile_authorization_preserves_a_configured_access_key() {
        let profile = authorization_profile("Bcu2", Some(4));
        let credentials = ManagementAccessOptions::new().with_access_key([1, 2, 3, 4]);
        let authorization =
            resolve_profile_authorization(&profile, 2, &credentials).expect("profile authorization resolves");

        assert_eq!(authorization, AuthorizationPolicy::LegacyKey { key: [1, 2, 3, 4].into(), required_level: 2 });
    }

    #[test]
    fn required_authorization_level_must_be_declared_by_the_profile() {
        let profile = authorization_profile("Bcu2", Some(4));

        assert!(resolve_profile_authorization(&profile, 4, &ManagementAccessOptions::default()).is_err());
    }

    #[test]
    fn secure_management_reserves_the_envelope_on_top_of_a_complete_key_row() {
        use crate::commissioning::compiler::binding::tests::preparation_support::partial_plan;
        use crate::commissioning::input::ProgramSections;

        // A group-key row write needs 5 + 18 plaintext bytes. Under secure
        // management its envelope adds 13, so the path must carry 36.
        let plan = partial_plan(authorization_profile("SystemB", None), ProgramSections::GROUP_COMMUNICATION)
            .with_procedure_apdu(23);
        let check = |interface, target, configured, secure| {
            validate_apdu_requirements(&plan, interface, target, configured, secure, false)
        };

        check(36, 36, None, true).expect("the envelope fits around a complete row");
        let error = check(35, 254, None, true).expect_err("one byte short of the envelope");
        assert!(error.to_string().contains("procedure requires wire APDU 36"), "{error}");
        check(254, 35, None, true).expect_err("the target limits the path as well");
        check(254, 254, Some(35), true).expect_err("the project ceiling limits the path as well");
        // Plaintext management needs no envelope.
        check(23, 23, None, false).expect("plaintext needs only the row and header");
    }
}
