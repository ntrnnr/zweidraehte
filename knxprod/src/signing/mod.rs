//! KNX Product Signing and Packaging
//!
//! This module provides cryptographic signing and ZIP packaging functionality
//! for creating valid `.knxprod` files that can be imported into ETS.
//!
//! # Overview
//!
//! KNX product files require several layers of signing:
//!
//! 1. **Product Hashes** - SHA1 hashes of Hardware and Product element attributes
//! 2. **Hardware2Program Hashes** - SHA1 hashes including application program references
//! 3. **Registration Signatures** - RSA-SHA1 signatures on RegistrationInfo elements
//! 4. **Directory Signatures** - RSA-SHA1 signature of all file hashes in the manufacturer directory
//!
//! All signing uses a well-known "converter key" (RSA 1024-bit) that's embedded
//! in the ETS toolchain.
//!
//! # Example
//!
//! ```rust,ignore
//! use knxprod::signing::{SigningConfig, MasterDataSource, create_knxprod};
//!
//! let config = SigningConfig {
//!     manufacturer_id: "00FA".to_string(),
//!     application_program: app_xml,
//!     hardware: hardware_xml,
//!     catalog: catalog_xml,
//!     baggage_files: vec![],
//! };
//!
//! let knxprod_bytes = create_knxprod(&config, MasterDataSource::Download)?;
//! std::fs::write("MyDevice.knxprod", knxprod_bytes)?;
//! ```

mod attributes;
mod binary_writer;
mod hashes;
mod keys;
mod packager;
mod signatures;

use std::io;
use std::path::PathBuf;

use thiserror::Error;

// Re-export public API
pub use attributes::normalize_appl_prog_id;
pub use hashes::{compute_application_program_hash, compute_hardware2program_hash, compute_product_hash};
pub use packager::{create_knxprod, sign_application_program_xml, sign_hardware_xml};
pub use signatures::{
    sign_directory_contents, verify_directory_signature, verify_hardware_xml, verify_registration_signature,
};

/// Errors that can occur during signing operations.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("XML parsing error: {0}")]
    XmlParse(#[from] quick_xml::DeError),

    #[error("XML write error: {0}")]
    XmlWrite(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Missing required element: {0}")]
    MissingElement(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
}

/// Configuration for signing a KNX product package.
#[derive(Debug, Clone)]
pub struct SigningConfig {
    /// Manufacturer ID (e.g., "00FA")
    pub manufacturer_id: String,

    /// Application program XML content
    pub application_program: String,

    /// Application program ID (e.g., "M-00FA_A-0070-35-1740")
    pub application_program_id: String,

    /// Hardware XML content (will have hashes/signatures injected)
    pub hardware: String,

    /// Catalog XML content
    pub catalog: String,

    /// Optional baggage files (icons, etc.) as (relative_path, content) pairs
    pub baggage_files: Vec<(String, Vec<u8>)>,
}

/// KNX XML schema version for master data downloads.
///
/// Different ETS versions may require different schema versions.
/// Version 23 is the current version used by ETS6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KnxSchemaVersion {
    /// Schema version 20
    V20,
    /// Schema version 21
    V21,
    /// Schema version 22
    V22,
    /// Schema version 23 (current, used by ETS6)
    #[default]
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
    /// Download from update.knx.org using the default schema version (V23).
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

/// Result of verifying a Hardware.xml file.
#[derive(Debug, Clone)]
pub struct HardwareVerificationResult {
    /// Results for Product hash verification
    pub products: Vec<ProductHashResult>,

    /// Results for Hardware2Program hash verification
    pub hardware2programs: Vec<Hardware2ProgramHashResult>,

    /// Results for RegistrationSignature verification
    pub registration_signatures: Vec<RegistrationSignatureResult>,
}

/// Result of verifying a single Product hash.
#[derive(Debug, Clone)]
pub struct ProductHashResult {
    pub id: String,
    pub hardware_id: String,
    pub expected: String,
    pub computed: String,
    pub valid: bool,
}

/// Result of verifying a single Hardware2Program hash.
#[derive(Debug, Clone)]
pub struct Hardware2ProgramHashResult {
    pub id: String,
    pub hardware_id: String,
    pub expected: String,
    pub computed: String,
    pub valid: bool,
    pub app_refs: Vec<String>,
    pub app_hashes_found: usize,
}

/// Result of verifying a single RegistrationSignature.
#[derive(Debug, Clone)]
pub struct RegistrationSignatureResult {
    pub parent_id: String,
    pub parent_type: String,
    pub status: Option<String>,
    pub date: Option<String>,
    pub number: Option<String>,
    pub valid: bool,
    pub key: Option<String>,
    pub error: Option<String>,
}

/// Result of verifying a directory signature.
#[derive(Debug, Clone)]
pub struct DirectorySignatureResult {
    pub valid: bool,
    pub key: Option<String>,
    pub files: usize,
    pub error: Option<String>,
}

impl HardwareVerificationResult {
    /// Returns true if all hashes and signatures are valid.
    pub fn all_valid(&self) -> bool {
        self.products.iter().all(|p| p.valid)
            && self.hardware2programs.iter().all(|h| h.valid)
            && self.registration_signatures.iter().all(|s| s.valid)
    }
}
