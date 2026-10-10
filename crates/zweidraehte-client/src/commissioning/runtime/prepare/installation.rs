//! Bind exact installed bytes and stamp presence before choosing a differential base.
use super::installed_contract::partial_installed_state_requirements;
use super::revalidate::read_bound_evidence;
use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::error::DiagnosticResult as Result;
use crate::commissioning::evidence::{
    DeploymentRecord, DeviceStamp, DifferentialDecision, DifferentialFallback, DifferentialPolicy,
};
use crate::commissioning::image::{ImageLocation, SparseDeviceImage, fingerprint_image};
use crate::commissioning::input::ProgrammingInput;
use crate::commissioning::report::{CommissioningEvent, CommissioningStage};
use crate::commissioning::runtime::ExecutionSession;
use crate::commissioning::runtime::commissioner::{Commissioner, CommissioningCancellation};
use crate::commissioning::runtime::policy::{differential_fallback, verified_undifferenced_fallback};
use crate::commissioning::runtime::prepared::{BoundRead, ReadExpectation};
use std::collections::BTreeSet;

impl Commissioner<'_> {
    pub(in crate::commissioning) async fn bind_installation_evidence<F: FnMut(CommissioningEvent)>(
        &self,
        plan: &CompiledProgram,
        session: &mut ExecutionSession<'_>,
        input: &ProgrammingInput,
        differential_policy: DifferentialPolicy,
        deployment: Option<&DeploymentRecord>,
        cancellation: &CommissioningCancellation,
        event: &mut F,
    ) -> Result<(Vec<BoundRead>, Option<SparseDeviceImage>, DifferentialDecision)> {
        event(CommissioningEvent::Stage(CommissioningStage::ValidatingDifferential));
        // Reject unusable local history before asking the device for stamps.
        let (baseline, differential) = prepare_baseline(plan, differential_policy, deployment)?;
        let mut reads = partial_installed_state_requirements(plan, input.device.product())?;
        let partial_count = reads.len();
        if let Some(baseline) = baseline {
            reads.extend(baseline_stamp_reads(plan, baseline)?);
        }
        read_bound_evidence(session, &mut reads, cancellation).await?;
        let (differential, known) = if let Some(baseline) = baseline {
            finish_baseline(
                plan,
                baseline,
                &reads[partial_count..],
                differential_policy,
                self.options.minimum_equal_run,
            )?
        } else {
            (differential, None)
        };
        match &differential {
            DifferentialDecision::FellBackToUndifferenced { reason } => {
                event(CommissioningEvent::DifferentialFallback(*reason))
            }
            DifferentialDecision::VerifiedUndifferenced { .. } => {
                event(CommissioningEvent::DifferentialFallback(DifferentialFallback::NoUsefulDifference))
            }
            _ => {}
        }
        if !matches!(
            differential,
            DifferentialDecision::VerifiedDifference { .. } | DifferentialDecision::VerifiedUndifferenced { .. }
        ) {
            reads.truncate(partial_count);
        }
        Ok((reads, known, differential))
    }
}

/// Probe the recorded extent of present stamps, and one record of each
/// unrecorded candidate to retain absence/presence validation.
pub(crate) fn baseline_stamp_reads(plan: &CompiledProgram, baseline: &DeploymentRecord) -> Result<Vec<BoundRead>> {
    plan.download_stamps()
        .iter()
        .map(|candidate| {
            let service = match baseline.device_stamps.iter().find(|stamp| stamp.resource == candidate.id) {
                Some(stamp) => super::reads::stamp_service(&candidate.read, &stamp.value)
                    .ok_or_else(|| Diagnostic::preparation("download-stamp baseline has an invalid read extent"))?,
                None => candidate.read.clone(),
            };
            Ok(BoundRead {
                resource: candidate.id.clone(),
                service,
                expected: ReadExpectation::Capture { optional: true },
            })
        })
        .collect()
}

/// Local evidence is immutable throughout preparation. Validate it once before
/// reads; only a successful presence/value comparison can install its bytes.
pub(crate) fn prepare_baseline<'a>(
    plan: &CompiledProgram,
    policy: DifferentialPolicy,
    deployment: Option<&'a DeploymentRecord>,
) -> Result<(Option<&'a DeploymentRecord>, DifferentialDecision)> {
    if policy == DifferentialPolicy::Disabled || plan.procedure().is_none() {
        return Ok((None, DifferentialDecision::Undifferenced));
    }
    let reason = if plan.download_stamps().is_empty() {
        // An advertised stamp-less profile or previously observed stamp-less
        // target keeps its selected semantic procedure without a warning.
        (policy == DifferentialPolicy::RequireVerified).then_some(DifferentialFallback::MissingDeviceStamp)
    } else if let Some(deployment) = deployment {
        match validate_baseline(plan, deployment) {
            Err(reason) => Some(reason),
            Ok(()) if deployment.device_stamps.is_empty() => {
                (policy == DifferentialPolicy::RequireVerified).then_some(DifferentialFallback::MissingDeviceStamp)
            }
            Ok(()) if !plan.full_image_stamp_coverage() => Some(DifferentialFallback::UnprovenImageCoverage),
            Ok(()) => return Ok((Some(deployment), DifferentialDecision::Undifferenced)),
        }
    } else {
        Some(DifferentialFallback::MissingDeploymentHistory)
    };
    let decision = match reason {
        Some(reason) => differential_fallback(policy, reason)?,
        None => DifferentialDecision::Undifferenced,
    };
    Ok((None, decision))
}

pub(crate) fn validate_baseline(
    plan: &CompiledProgram,
    deployment: &DeploymentRecord,
) -> std::result::Result<(), DifferentialFallback> {
    // DeploymentRecord is public input: equal stamps cannot authenticate an
    // image whose caller-supplied fingerprint describes different bytes.
    if &deployment.mask != plan.profile().mask()
        || &deployment.variant != plan.profile().variant()
        || deployment.master_data_fingerprint != plan.profile().master_data_fingerprint()
        || deployment.product_fingerprint != plan.product_fingerprint()
        || fingerprint_image(&deployment.image) != deployment.image_fingerprint
    {
        return Err(DifferentialFallback::ProfileChanged);
    }
    let mut seen = BTreeSet::new();
    for stamp in &deployment.device_stamps {
        if !seen.insert(&stamp.resource)
            || plan
                .download_stamps()
                .iter()
                .find(|candidate| candidate.id == stamp.resource)
                .is_none_or(|candidate| super::reads::stamp_service(&candidate.read, &stamp.value).is_none())
        {
            return Err(DifferentialFallback::StampMismatch);
        }
    }
    Ok(())
}

pub(crate) fn finish_baseline(
    plan: &CompiledProgram,
    baseline: &DeploymentRecord,
    reads: &[BoundRead],
    policy: DifferentialPolicy,
    minimum_equal_run: usize,
) -> Result<(DifferentialDecision, Option<SparseDeviceImage>)> {
    if reads.len() != plan.download_stamps().len()
        || reads.iter().zip(plan.download_stamps()).any(|(read, candidate)| read.resource != candidate.id)
    {
        return Err(Diagnostic::preparation("download-stamp observations do not cover the bound candidates"));
    }
    let mut stamps = Vec::new();
    for read in reads {
        let ReadExpectation::Exact(value) = &read.expected else {
            return Err(Diagnostic::preparation("download-stamp evidence has not been observed"));
        };
        let expected = baseline.device_stamps.iter().find(|stamp| stamp.resource == read.resource);
        let reason = match (expected, value) {
            (None, Some(_)) => Some(DifferentialFallback::MissingDeviceStamp),
            (Some(expected), Some(value)) if expected.value == *value => None,
            (None, None) => None,
            _ => Some(DifferentialFallback::StampMismatch),
        };
        if let Some(reason) = reason {
            return differential_fallback(policy, reason).map(|decision| (decision, None));
        }
        if let Some(value) = value {
            stamps.push(DeviceStamp { resource: read.resource.clone(), value: value.clone() });
        }
    }
    let useful = plan.image().segments().iter().any(|segment| {
        let mut equal = 0;
        segment.data().iter().zip(segment.mask()).enumerate().any(|(index, (value, mask))| {
            let location = ImageLocation {
                space: segment.location().space.clone(),
                offset: segment.location().offset + index as u32,
            };
            if baseline
                .image
                .byte(&location)
                .is_some_and(|(previous, known)| known & mask == *mask && previous & mask == value & mask)
            {
                equal += 1;
            } else {
                equal = 0;
            }
            equal >= minimum_equal_run.max(1)
        })
    });
    let differential = if !useful {
        verified_undifferenced_fallback(policy, baseline.image_fingerprint, stamps)?
    } else {
        DifferentialDecision::VerifiedDifference {
            previous_image_fingerprint: baseline.image_fingerprint,
            device_stamps: stamps,
        }
    };
    // Execution updates this knowledge after every allocation, fill and write;
    // later transfers never compare blindly with the installed image.
    Ok((differential, Some(baseline.image.clone())))
}
