//! KNX product signing vocabulary, and the gate to the machinery.
//!
//! This module is split by what a *consumer* needs rather than by
//! topic, because the two halves have wildly different dependency
//! weights:
//!
//! - **Here**: signing errors and compatibility re-exports — [`KnxSchemaVersion`]
//!   (which project schema an XML targets), [`MasterDataSource`] (where
//!   `knx_master.xml` comes from) and [`SigningError`]. Plain data;
//!   quick-xml and thiserror are the only dependencies.
//! - **`packaging`**: everything that actually signs and creates
//!   packages — SHA1/RSA hashing and the `.knxprod`/`.knxproj` writers. That
//!   subtree sits behind the `signing` feature, which implies `archives`.
//! - **[`crate::master_data`]**: shared acquisition outside signing;
//!   local source resolution is always available;
//!   versioned cache/download support is independently gated by
//!   `master-data-download`.
//!
//! Consumers can enable `archives` and `knxkeys` without RSA package signing;
//! HTTP master-data retrieval remains a separate opt-in. The split is at
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

// Preserve existing source paths while acquisition has one non-signing owner.
pub use crate::master_data;
#[cfg(feature = "signing")]
pub mod packaging;

use std::io;

use thiserror::Error;

// Re-exported flat so callers do not need to know the internal packaging
// layout.
pub use master_data::{MasterDataSource, get_master_data, get_master_data_for_schema};
#[cfg(feature = "signing")]
pub use packaging::*;

/// Errors that can occur during signing operations.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("XML parsing error")]
    XmlParse(#[from] quick_xml::DeError),

    #[error("XML read error")]
    XmlRead(#[from] quick_xml::Error),

    #[error("signed XML is not UTF-8")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("could not read the converter key file at {path}")]
    ConverterKeyFile {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("converter key file is missing the <{0}> element")]
    ConverterKeyComponentMissing(&'static str),

    #[error("I/O error")]
    Io(#[from] io::Error),

    // Dependency-specific errors follow the feature that provides their type.
    // The enum stays unconditional for feature-less builders.
    #[cfg(feature = "archives")]
    #[error("ZIP error")]
    Zip(#[from] zip::result::ZipError),

    #[cfg(feature = "signing")]
    #[error("RSA error")]
    Rsa(#[from] rsa::Error),

    #[error("Base64 decode error")]
    Base64(#[from] base64::DecodeError),

    #[error(transparent)]
    MasterData(#[from] crate::MasterDataError),

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

// Preserve the former import path while schema vocabulary lives with XML types.
pub use crate::schema::{KnxSchemaVersion, UnsupportedKnxSchemaVersion};
