//! Immutable device evidence and persisted deployment history shared by stages.

use crate::commissioning::catalog::profile::MaskIdentity;
use crate::commissioning::catalog::profile::ProfileVariant;
use crate::commissioning::catalog::profile::ResourceManagementStyle;
use crate::commissioning::image::SparseDeviceImage;
pub use zweidraehte_project::DeviceStamp;
use zweidraehte_proto::address::IndividualAddress;

/// Read-only facts bound to a prepared plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub address: Option<IndividualAddress>,
    pub serial_number: Option<[u8; 6]>,
    pub mask: MaskIdentity,
    pub interface_max_apdu: u16,
    pub target_max_apdu: u16,
    pub secure_management: bool,
    /// Management realization observed for an operation which reuses the
    /// installed application. Full replacement leaves this absent because
    /// the product defines the resulting realization and the old user-save
    /// pointer is irrelevant.
    pub observed_management_style: Option<ResourceManagementStyle>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DifferentialDecision {
    /// Execute the complete compiled image for the selected semantic scope.
    ///
    /// For a partial `Grp` download this is still only the group procedure;
    /// it is not a full-device download.
    Undifferenced,
    VerifiedDifference {
        previous_image_fingerprint: [u8; 32],
        device_stamps: Vec<DeviceStamp>,
    },
    /// The persisted base and exact live stamp values were verified, but a
    /// byte-sparse procedure would not reduce traffic. Execution therefore
    /// keeps the compiled semantic procedure unchanged while retaining the
    /// same execute-time and project-persistence binding as a sparse
    /// difference.
    VerifiedUndifferenced {
        previous_image_fingerprint: [u8; 32],
        device_stamps: Vec<DeviceStamp>,
    },
    FellBackToUndifferenced {
        reason: DifferentialFallback,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commissioning) enum SerialDomainPoll {
    Found(IndividualAddress),
    NoResponse,
    RejectedSend,
}

/// Behavior requested when differential preconditions cannot be proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifferentialPolicy {
    Disabled,
    FallBackToUndifferenced,
    RequireVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifferentialFallback {
    MissingDeploymentHistory,
    MissingDeviceStamp,
    StampMismatch,
    ProfileChanged,
    /// Resident stamps have not proven which previous image ranges remain
    /// valid. Matching values alone cannot authorize omitting image writes.
    UnprovenImageCoverage,
    NoUsefulDifference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentRecord {
    pub mask: MaskIdentity,
    pub variant: ProfileVariant,
    pub master_data_fingerprint: [u8; 32],
    pub product_fingerprint: [u8; 32],
    pub image_fingerprint: [u8; 32],
    /// Exact previously deployed image. Its fingerprint and resident stamps
    /// must both validate before it may be used as a differential base.
    pub image: SparseDeviceImage,
    pub device_stamps: Vec<DeviceStamp>,
}
