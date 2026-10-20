//! KNX namespace identity and the schema revisions supported for generation.

use thiserror::Error;

/// KNX XML schema revisions supported for product generation.
///
/// Different ETS versions may require different schema versions.
/// Version 20 is the default as it is the most widely compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KnxSchemaVersion {
    /// Schema version 20 (default, widely compatible)
    #[default]
    V20,
    /// Schema version 21
    V21,
    /// Schema version 22
    V22,
    /// Schema version 23 (used by ETS6)
    V23,
}

impl KnxSchemaVersion {
    /// The newest revision, which an installation's own Master Data uses.
    pub const LATEST: Self = Self::V23;

    /// Get the numeric project-schema version.
    pub const fn as_u16(self) -> u16 {
        match self {
            KnxSchemaVersion::V20 => 20,
            KnxSchemaVersion::V21 => 21,
            KnxSchemaVersion::V22 => 22,
            KnxSchemaVersion::V23 => 23,
        }
    }

    /// Get the version number as a string (e.g., "20", "23")
    pub fn as_str(&self) -> &'static str {
        match self {
            KnxSchemaVersion::V20 => "20",
            KnxSchemaVersion::V21 => "21",
            KnxSchemaVersion::V22 => "22",
            KnxSchemaVersion::V23 => "23",
        }
    }

    /// Get the XML namespace URL for this schema version.
    ///
    /// This is used in the `xmlns` attribute of KNX XML files.
    pub fn namespace_url(&self) -> String {
        format!("http://knx.org/xml/project/{}", self.as_str())
    }

    /// Get the download URL for this schema version's master data.
    pub fn master_data_url(&self) -> String {
        crate::master_data::master_data_url(self.as_u16())
    }

    /// Get the tool version string for the generated XML files.
    ///
    /// Uses the ETS files crate version.
    pub fn tool_version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
}

/// A project-schema version outside the supported generation revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unsupported KNX project schema version {0}; supported versions are 20 through 23")]
pub struct UnsupportedKnxSchemaVersion(pub u16);

impl TryFrom<u16> for KnxSchemaVersion {
    type Error = UnsupportedKnxSchemaVersion;

    fn try_from(version: u16) -> Result<Self, Self::Error> {
        match version {
            20 => Ok(Self::V20),
            21 => Ok(Self::V21),
            22 => Ok(Self::V22),
            23 => Ok(Self::V23),
            version => Err(UnsupportedKnxSchemaVersion(version)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_schema_versions_are_checked_and_typed() {
        assert_eq!(KnxSchemaVersion::try_from(20), Ok(KnxSchemaVersion::V20));
        assert_eq!(KnxSchemaVersion::try_from(21), Ok(KnxSchemaVersion::V21));
        assert_eq!(KnxSchemaVersion::try_from(22), Ok(KnxSchemaVersion::V22));
        assert_eq!(KnxSchemaVersion::try_from(23), Ok(KnxSchemaVersion::V23));
        assert_eq!(KnxSchemaVersion::try_from(19), Err(UnsupportedKnxSchemaVersion(19)));
        assert_eq!(KnxSchemaVersion::try_from(24), Err(UnsupportedKnxSchemaVersion(24)));
    }
}

/// Parse a KNX project namespace without imposing a consumer's supported range.
///
/// Older imported documents and newer inspection-only documents retain their
/// declared version. Generation and commissioning validate their own ranges.
///
/// ```
/// use zweidraehte_ets_files::schema::schema_version_from_namespace;
/// assert_eq!(schema_version_from_namespace("http://knx.org/xml/project/11"), Some(11));
/// assert_eq!(schema_version_from_namespace("urn:other:23"), None);
/// ```
pub fn schema_version_from_namespace(namespace: &str) -> Option<u16> {
    namespace.trim_end_matches('/').strip_prefix("http://knx.org/xml/project/")?.parse().ok()
}
