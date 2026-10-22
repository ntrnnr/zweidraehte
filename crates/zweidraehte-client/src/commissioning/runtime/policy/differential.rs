//! Differential request eligibility and explicit fallback policy.

use crate::commissioning::error::Diagnostic;
use crate::commissioning::error::DiagnosticResult as Result;
use crate::commissioning::error::PreparationFailure;
use crate::commissioning::evidence::{DeviceStamp, DifferentialDecision, DifferentialFallback, DifferentialPolicy};
use crate::commissioning::input::CommissioningIntent;

pub(in crate::commissioning) fn validate_differential_inputs(
    intent: CommissioningIntent,
    policy: DifferentialPolicy,
    has_deployment_evidence: bool,
) -> Result<()> {
    let downloads_application = intent.download_mode().is_some();
    if !downloads_application && (policy != DifferentialPolicy::Disabled || has_deployment_evidence) {
        return Err(Diagnostic::preparation(
            PreparationFailure::InvalidOptions,
            "differential policy and deployment evidence are valid only for download intents",
        ));
    }

    Ok(())
}

pub(in crate::commissioning) fn differential_fallback(
    policy: DifferentialPolicy,
    reason: DifferentialFallback,
) -> Result<DifferentialDecision> {
    if policy == DifferentialPolicy::RequireVerified {
        return Err(Diagnostic::preparation(
            PreparationFailure::Unsupported,
            format!("verified differential download is unavailable: {reason:?}"),
        ));
    }

    Ok(DifferentialDecision::FellBackToUndifferenced { reason })
}

/// Keep the original semantic procedure when byte masking would not reduce
/// traffic, without discarding the verified physical base used by a partial
/// project deployment. `RequireVerified` intentionally retains its existing
/// contract that a useful sparse procedure must be produced.
pub(in crate::commissioning) fn verified_undifferenced_fallback(
    policy: DifferentialPolicy,
    previous_image_fingerprint: [u8; 32],
    device_stamps: Vec<DeviceStamp>,
) -> Result<DifferentialDecision> {
    if policy == DifferentialPolicy::RequireVerified {
        return Err(Diagnostic::preparation(
            PreparationFailure::Unsupported,
            format!("verified differential download is unavailable: {:?}", DifferentialFallback::NoUsefulDifference),
        ));
    }

    Ok(DifferentialDecision::VerifiedUndifferenced { previous_image_fingerprint, device_stamps })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::commissioning::input::{DownloadMode, UnloadMode};
    use crate::commissioning::runtime::policy::validate_differential_inputs;

    #[test]
    fn non_download_intents_reject_differential_policy_and_evidence() {
        for intent in [
            CommissioningIntent::AssignAddress,
            CommissioningIntent::Unload(UnloadMode::Application),
            CommissioningIntent::Unload(UnloadMode::AllConfiguration),
        ] {
            assert!(validate_differential_inputs(intent, DifferentialPolicy::FallBackToUndifferenced, false).is_err());
            assert!(validate_differential_inputs(intent, DifferentialPolicy::RequireVerified, false).is_err());
            assert!(validate_differential_inputs(intent, DifferentialPolicy::Disabled, true).is_err());
            assert!(validate_differential_inputs(intent, DifferentialPolicy::Disabled, false).is_ok());
        }
    }

    #[test]
    fn download_intents_accept_differential_policy_and_evidence() {
        for intent in [
            CommissioningIntent::Download(DownloadMode::Full),
            CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full),
        ] {
            assert!(validate_differential_inputs(intent, DifferentialPolicy::FallBackToUndifferenced, true).is_ok());
            assert!(validate_differential_inputs(intent, DifferentialPolicy::RequireVerified, true).is_ok());
        }
    }
}
