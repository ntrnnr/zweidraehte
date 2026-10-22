//! Immutable compiled image and controls, with computed execution requirements.

use crate::commissioning::catalog::profile::ResolvedProfile;
use crate::commissioning::compiler::program::network::NetworkProgram;
use crate::commissioning::image::{SparseDeviceImage, fingerprint_image};
use crate::commissioning::input::facts::{ObservedTarget, ProgrammingFacts};
use crate::commissioning::input::security::{DesiredDataSecurity, ObservedDataSecurity};
use crate::commissioning::input::{CommissioningIntent, ProgramSections, TargetSelection};
use crate::commissioning::procedure::{NormalizedProcedure, RestartKind};

use crate::configuration::TopologyConfiguration;
use zweidraehte_project::DesiredProgrammingManifest;
use zweidraehte_proto::address::IndividualAddress;

/// Conservative plaintext APDU requirements for each commissioning phase.
///
/// These include every reachable service, including ignored failures and
/// runtime branches. They do not claim the smallest APDU for a successful run.
/// An absent phase has no requirement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommissioningApduRequirements {
    pub(crate) address_assignment: Option<u16>,
    pub(crate) network_configuration: Option<u16>,
    pub(crate) procedure: Option<u16>,
}

impl CommissioningApduRequirements {
    pub const fn address_assignment(self) -> Option<u16> {
        self.address_assignment
    }

    pub const fn network_configuration(self) -> Option<u16> {
        self.network_configuration
    }

    pub const fn procedure(self) -> Option<u16> {
        self.procedure
    }

    pub fn maximum(self) -> Option<u16> {
        [self.address_assignment, self.network_configuration, self.procedure].into_iter().flatten().max()
    }
}

/// Computed inspection summary; the image and controls remain authoritative.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProgramSummary {
    pub sections: Option<ProgramSections>,
    pub full_download: bool,
    pub image_bytes: usize,
    pub controls: usize,
    pub apdu: CommissioningApduRequirements,
}

/// Inspectable compiled program before live evidence checks.
///
/// Only a `PreparedProgram` can pass the Commissioner's execution gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledProgram {
    pub(super) intent: CommissioningIntent,
    pub(super) target: TargetSelection,
    /// Project address the network-management phase assigns and the
    /// device-management phase normally targets.
    pub(super) individual_address: IndividualAddress,
    /// Restart service for the network-configuration phase. This is resolved
    /// from the application currently installed on the device and can differ
    /// from the restart operations compiled for the replacement application.
    pub(super) network_restart_kind: RestartKind,
    /// Exact product-owned sections selected after resolving the requested
    /// download mode. Address assignment and unload plans carry none.
    pub(super) program_sections: Option<ProgramSections>,
    /// Whether the resolved procedure replaces every application section the
    /// product actually owns. This is distinct from `ProgramSections::all()`:
    /// an AP1-only product has no AP2 bit, and `Automatic` may resolve to the
    /// same semantic full procedure as an explicit full download.
    pub(super) full_program_scope: bool,
    /// Installation-wide medium and routing values compiled with this device.
    /// These values contain no credentials and are safe to expose in previews.
    pub(super) topology: TopologyConfiguration,
    pub(super) profile: ResolvedProfile,
    pub(super) verify_mode: bool,
    pub(super) programming_mode: Option<(crate::commissioning::procedure::operands::ServiceRead, bool)>,
    pub(super) network: NetworkProgram,
    pub(super) facts: ProgrammingFacts,
    pub(super) configured_max_apdu: Option<u16>,
    pub(super) full_image_stamp_coverage: bool,
    pub(super) desired_data_security: DesiredDataSecurity,
    pub(super) image: SparseDeviceImage,
    pub(super) verification_reads:
        Vec<(crate::commissioning::image::ImageLocation, crate::commissioning::procedure::operands::ServiceRead)>,
    pub(super) native_regions: Vec<crate::commissioning::image::NativeImageRegion>,
    /// Canonical, section-owned desired state generated with the image.
    pub(super) manifest: DesiredProgrammingManifest,
    /// Address assignment is a network-management phase, not a synthetic
    /// load-control procedure. Download and unload plans always carry one.
    pub(super) procedure: Option<NormalizedProcedure>,
    pub(super) apdu_requirements: CommissioningApduRequirements,
    pub(super) product_fingerprint: [u8; 32],
}

impl CompiledProgram {
    /// Replace the sealed procedure requirement so policy tests can check
    /// their wire arithmetic without compiling a procedure of that size.
    #[cfg(test)]
    pub(in crate::commissioning) fn with_procedure_apdu(mut self, length: u16) -> Self {
        self.apdu_requirements.procedure = Some(length);
        self
    }

    pub(in crate::commissioning) fn full_image_stamp_coverage(&self) -> bool {
        self.full_image_stamp_coverage
    }
    pub(in crate::commissioning) fn programming_mode(
        &self,
    ) -> Option<&(crate::commissioning::procedure::operands::ServiceRead, bool)> {
        self.programming_mode.as_ref()
    }
    pub(in crate::commissioning) fn verification_reads(
        &self,
    ) -> &[(crate::commissioning::image::ImageLocation, crate::commissioning::procedure::operands::ServiceRead)] {
        &self.verification_reads
    }
    /// Native allocation boundaries and seeds, including unowned capacity.
    /// Sparse owned bytes alone cannot establish how a load-image read clips.
    pub fn native_regions(&self) -> &[crate::commissioning::image::NativeImageRegion] {
        &self.native_regions
    }
    pub fn summary(&self) -> ProgramSummary {
        ProgramSummary {
            sections: self.program_sections,
            full_download: self.full_program_scope,
            image_bytes: self.image.byte_count(),
            controls: self.procedure.as_ref().map_or(0, |procedure| procedure.steps.len()),
            apdu: self.apdu_requirements,
        }
    }

    pub fn facts(&self) -> ProgrammingFacts {
        self.facts
    }

    pub(crate) fn observed_target(&self) -> ObservedTarget {
        self.facts.target.expect("lowering requires target evidence")
    }

    pub(crate) fn management_secure(&self) -> bool {
        self.observed_target().credential.is_secure()
    }

    /// Reports whether procedure resolution selected a full replacement of
    /// every program section present in this exact product.
    pub const fn is_full_program_scope(&self) -> bool {
        self.full_program_scope
    }
}

impl CompiledProgram {
    pub fn intent(&self) -> CommissioningIntent {
        self.intent
    }

    pub fn target(&self) -> &TargetSelection {
        &self.target
    }

    pub fn profile(&self) -> &ResolvedProfile {
        &self.profile
    }

    pub(crate) const fn verify_mode(&self) -> bool {
        self.verify_mode
    }

    pub fn network(&self) -> &NetworkProgram {
        &self.network
    }

    pub fn image(&self) -> &SparseDeviceImage {
        &self.image
    }

    pub fn manifest(&self) -> &DesiredProgrammingManifest {
        &self.manifest
    }

    pub fn procedure(&self) -> Option<&NormalizedProcedure> {
        self.procedure.as_ref()
    }

    pub(crate) fn download_stamps(&self) -> &[crate::commissioning::procedure::StampDescriptor] {
        self.procedure.as_ref().map_or(&[], |procedure| procedure.stamp_output.descriptors())
    }

    pub fn apdu_requirements(&self) -> CommissioningApduRequirements {
        self.apdu_requirements
    }

    pub fn individual_address(&self) -> IndividualAddress {
        self.individual_address
    }

    pub fn program_sections(&self) -> Option<ProgramSections> {
        self.program_sections
    }

    pub fn product_fingerprint(&self) -> [u8; 32] {
        self.product_fingerprint
    }

    pub fn image_fingerprint(&self) -> [u8; 32] {
        fingerprint_image(&self.image)
    }

    pub fn topology(&self) -> &TopologyConfiguration {
        &self.topology
    }

    pub fn network_restart_kind(&self) -> RestartKind {
        self.network_restart_kind
    }

    pub fn desired_data_security(&self) -> DesiredDataSecurity {
        self.desired_data_security
    }

    pub fn observed_data_security(&self) -> ObservedDataSecurity {
        self.facts.data_security
    }
}

pub(crate) mod network;
