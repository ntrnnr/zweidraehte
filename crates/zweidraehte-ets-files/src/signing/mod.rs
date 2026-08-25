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
//! - **`packaging`**: everything that actually signs and creates
//!   packages — SHA1/RSA hashing and the `.knxprod`/`.knxproj` writers. That
//!   subtree sits behind the `signing` feature, which implies `archives`.
//! - **[`master_data`]**: local source resolution is always available;
//!   versioned cache/download support is independently gated by
//!   `master-data-download`.
//!
//! Consumers enable only their format boundary. The client, for instance,
//! enables `archives` and `knxkeys` without enabling RSA package signing;
//! HTTP master-data retrieval remains its separate opt-in. The split is at
//! module boundaries so feature choices remain visible in dependency graphs.
//!
//! # Example
//!
//! ```rust,ignore
//! use zweidraehte_ets_files::signing::{ConverterKey, SigningConfig, MasterDataSource, create_knxprod};
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
//! let key = ConverterKey::from_file("converter_key.xml")?;
//! let knxprod_bytes = create_knxprod(&config, MasterDataSource::Download, &key)?;
//! std::fs::write("MyDevice.knxprod", knxprod_bytes)?;
//! ```

pub mod master_data;
#[cfg(feature = "signing")]
pub mod packaging;

use std::io;
use std::path::PathBuf;

use thiserror::Error;

// Re-exported flat so callers do not need to know the internal packaging
// layout.
pub use master_data::get_master_data;
#[cfg(feature = "signing")]
pub use packaging::*;

/// Errors that can occur during signing operations.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("XML parsing error: {0}")]
    XmlParse(#[from] quick_xml::DeError),

    #[error("XML read error: {0}")]
    XmlRead(#[from] quick_xml::Error),

    #[error("signed XML is not UTF-8")]
    Utf8(#[from] std::string::FromUtf8Error),

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
    // brings that dependency in, not `signing` as a whole. The enum
    // itself stays unconditional because `BuilderError` embeds it in
    // feature-less builds too.
    #[cfg(feature = "archives")]
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[cfg(feature = "signing")]
    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[cfg(feature = "master-data-download")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("master-data download support is disabled")]
    MasterDataDownloadDisabled,

    #[error("Missing required element: {0}")]
    MissingElement(String),

    #[error("duplicate manufacturer directory {0}")]
    DuplicateManufacturer(String),

    #[error(
        "cannot faithfully sign the file name {path:?}: it contains {character:?}, \
         which the word-sort collation model is not validated to order the way \
         Windows NLS (and therefore ETS) does, and a mis-ordered digest would \
         make ETS reject the package; rename the file, or extend the model after \
         validating the character against a real ETS-signed database"
    )]
    UnsortableDigestPath { path: String, character: char },

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
    /// Uses the ETS files crate version.
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
