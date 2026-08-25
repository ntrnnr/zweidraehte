//! Signing and packaging machinery for `.knxprod` / `.knxproj` files.
//!
//! The whole subtree is gated on the `signing` feature by its single
//! declaration in [`super`], so nothing inside carries a `#[cfg]` of
//! its own.
//!
//! KNX product files require several layers of signing:
//!
//! 1. **Product Hashes** — SHA1 hashes of Hardware and Product element
//!    attributes.
//! 2. **Hardware2Program Hashes** — SHA1 hashes including application
//!    program references.
//! 3. **Registration Signatures** — RSA-SHA1 signatures on
//!    RegistrationInfo elements.
//! 4. **Directory Signatures** — RSA-SHA1 signature of all file hashes
//!    in the manufacturer directory.
//!
//! Signing uses a caller-supplied converter key. The foundation parses the
//! git-ignored key file but never discovers or embeds private key material.

mod attributes;
mod binary_writer;
mod hashes;
mod keys;
mod packager;
mod signatures;

pub use attributes::normalize_appl_prog_id;
pub use hashes::{compute_application_program_hash, compute_hardware2program_hash, compute_product_hash};
pub use keys::ConverterKey;
pub use packager::{
    ProjectConfig, create_knxprod, create_knxproj, create_knxproj_multi, sign_application_program_xml,
    sign_hardware_xml,
};
pub use signatures::{
    sign_directory_contents, verify_directory_signature, verify_hardware_xml, verify_registration_signature,
};

/// Configuration for signing a KNX product package.
#[derive(Debug, Clone)]
pub struct SigningConfig {
    /// Manufacturer ID (e.g., "00FA")
    pub manufacturer_id: String,

    /// Application programs as `(program_id, xml_content)` pairs.
    ///
    /// Each entry becomes a separate XML file in the knxprod package,
    /// named `<program_id>.xml`. The program ID is also used to compute
    /// hashes that are embedded in Hardware.xml.
    pub application_programs: Vec<(String, String)>,

    /// Hardware XML content (will have hashes/signatures injected)
    pub hardware: String,

    /// Catalog XML content
    pub catalog: String,

    /// Optional baggage files (icons, etc.) as (relative_path, content) pairs
    pub baggage_files: Vec<(String, Vec<u8>)>,
}

impl From<&crate::product::ManufacturerContent> for SigningConfig {
    fn from(content: &crate::product::ManufacturerContent) -> Self {
        Self {
            manufacturer_id: content.manufacturer_id.strip_prefix("M-").unwrap_or(&content.manufacturer_id).to_owned(),
            application_programs: content.application_programs.clone(),
            hardware: content.hardware.clone(),
            catalog: content.catalogue.clone(),
            baggage_files: content.auxiliary_files.clone(),
        }
    }
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
