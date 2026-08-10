//! KNX product signing vocabulary, and the gate to the machinery.
//!
//! This module is split by what a *consumer* needs rather than by
//! topic, because the two halves have wildly different dependency
//! weights:
//!
//! - **Here**: the vocabulary every caller touches — [`KnxSchemaVersion`]
//!   (which project schema an XML targets), [`MasterDataSource`] (where
//!   `knx_master.xml` comes from) and [`SigningError`]. Plain data;
//!   quick-xml and thiserror are the only dependencies.
//! - **[`mod@packaging`]**: everything that actually signs and zips —
//!   SHA1/RSA hashing, the `.knxprod`/`.knxproj` writers, and the
//!   master-data download cache. That pulls in rsa, sha1, zip, reqwest
//!   and icu, so the whole subtree sits behind the `packaging` feature
//!   (on by default).
//!
//! Consumers that only parse XML — the client library's
//! master-data-driven download procedures, for instance — take this
//! crate with `default-features = false` and never build the crypto
//! stack. The split is at the module boundary precisely so that
//! `#[cfg]` appears once rather than on every item.
//!
//! # Example
//!
//! ```rust,ignore
//! use zweidraehte_knxprod::signing::{SigningConfig, MasterDataSource, create_knxprod};
//!
//! let config = SigningConfig {
//!     manufacturer_id: "00FA".to_string(),
//!     application_programs: vec![
//!         ("M-00FA_A-0001-01-0000".to_string(), app_xml),
//!     ],
//!     hardware: hardware_xml,
//!     catalog: catalog_xml,
//!     baggage_files: vec![],
//! };
//!
//! let knxprod_bytes = create_knxprod(&config, MasterDataSource::Download)?;
//! std::fs::write("MyDevice.knxprod", knxprod_bytes)?;
//! ```

#[cfg(feature = "master-data")]
pub mod master_data;
#[cfg(feature = "packaging")]
pub mod packaging;

use std::io;
use std::path::PathBuf;

use thiserror::Error;

// Re-exported flat so `signing::create_knxprod` and
// `signing::get_master_data` keep working; the submodules are public
// as well for callers that prefer the long path.
#[cfg(feature = "master-data")]
pub use master_data::get_master_data;
#[cfg(feature = "packaging")]
pub use packaging::*;

/// Errors that can occur during signing operations.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("XML parsing error: {0}")]
    XmlParse(#[from] quick_xml::DeError),

    #[error("XML read error: {0}")]
    XmlRead(#[from] quick_xml::Error),

    #[error("XML write error: {0}")]
    XmlWrite(String),

    #[error("could not read the converter key file at {path}: {source}")]
    ConverterKeyFile {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("converter key file is missing the <{0}> element")]
    ConverterKeyComponentMissing(&'static str),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    // The three variants below are the only per-item `#[cfg]`s in the
    // crate, and unavoidably so: each wraps a type that does not exist
    // without its dependency. Each therefore follows the feature that
    // brings that dependency in, not `packaging` as a whole. The enum
    // itself stays unconditional because `BuilderError` embeds it in
    // feature-less builds too.
    #[cfg(feature = "product-files")]
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[cfg(feature = "packaging")]
    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[cfg(feature = "master-data")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Missing required element: {0}")]
    MissingElement(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
}

/// KNX XML schema version for master data downloads.
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
        format!("https://update.knx.org/data/XML/project-{}/knx_master.xml", self.as_str())
    }

    /// Get the tool version string for the generated XML files.
    ///
    /// Uses the knxprod crate version.
    pub fn tool_version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
}

/// Source for KNX master data (knx_master.xml).
///
/// The master data file is required in .knxprod packages and contains
/// KNX standard datapoint type definitions.
#[derive(Debug, Clone)]
pub enum MasterDataSource {
    /// Download from update.knx.org using the default schema version (V20).
    /// Will be cached locally after first download.
    Download,

    /// Download from update.knx.org using a specific schema version.
    /// Will be cached locally after first download.
    DownloadVersion(KnxSchemaVersion),

    /// Use a local file at the specified path.
    File(PathBuf),

    /// Use provided XML content directly.
    Content(String),
}
