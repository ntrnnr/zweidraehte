//! The requested operation and physical target, before discovery.

use std::time::Duration;
use zweidraehte_proto::address::IndividualAddress;

/// Independently programmable application sections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ProgramSections(u16);

impl ProgramSections {
    pub const APPLICATION_PROGRAM_1: Self = Self(1 << 0);
    pub const APPLICATION_PROGRAM_2: Self = Self(1 << 1);
    pub const PARAMETERS: Self = Self(1 << 2);
    pub const GROUP_COMMUNICATION: Self = Self(1 << 3);
    pub const CONFIGURATION: Self = Self(1 << 4);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn all() -> Self {
        Self(
            Self::APPLICATION_PROGRAM_1.0
                | Self::APPLICATION_PROGRAM_2.0
                | Self::PARAMETERS.0
                | Self::GROUP_COMMUNICATION.0
                | Self::CONFIGURATION.0,
        )
    }

    pub const fn contains(self, section: Self) -> bool {
        self.0 & section.0 == section.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(crate) const fn extra_section_count(self, required: Self) -> u32 {
        (self.0 & !required.0).count_ones()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadMode {
    Automatic,
    Full,
    Partial(ProgramSections),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnloadMode {
    Application,
    AllConfiguration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommissioningIntent {
    AssignAddress,
    Download(DownloadMode),
    AssignAddressAndDownload(DownloadMode),
    Unload(UnloadMode),
}

impl CommissioningIntent {
    /// Download scope, independent of whether this operation also assigns an address.
    pub const fn download_mode(self) -> Option<DownloadMode> {
        match self {
            Self::Download(mode) | Self::AssignAddressAndDownload(mode) => Some(mode),
            Self::AssignAddress | Self::Unload(_) => None,
        }
    }

    /// Whether the requested download can replace group communication settings.
    pub const fn updates_group_communication(self) -> bool {
        match self.download_mode() {
            Some(DownloadMode::Partial(sections)) => sections.contains(ProgramSections::GROUP_COMMUNICATION),
            Some(DownloadMode::Automatic | DownloadMode::Full) => true,
            None => false,
        }
    }

    pub const fn mutates_address(self) -> bool {
        matches!(self, Self::AssignAddress | Self::AssignAddressAndDownload(_))
    }
}

/// Polling behavior for programming-mode target acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgrammingModePolling {
    pub wait_when_none_found: bool,
    pub timeout: Duration,
    pub poll_interval: Duration,
}

impl Default for ProgrammingModePolling {
    fn default() -> Self {
        Self { wait_when_none_found: true, timeout: Duration::from_secs(5 * 60), poll_interval: Duration::from_secs(2) }
    }
}

/// Explicit physical-target acquisition method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSelection {
    SerialNumber([u8; 6]),
    ProgrammingButton(ProgrammingModePolling),
    KnownPreviousAddress(IndividualAddress),
    ExistingAddress(IndividualAddress),
}
