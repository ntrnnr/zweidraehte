//! Unified builder for KNX product generation.
//!
//! The `KnxprodBuilder` provides a fluent API for generating KNX product files,
//! combining all the individual generators (MTXML, Hardware, Catalog, Baggage)
//! and optionally creating signed .knxprod packages.
//!
//! # Use Cases
//!
//! 1. **Generate MTXML files only** - For use with Manufacturing Tool projects
//! 2. **Generate and write to disk** - Create the complete directory structure
//! 3. **Create signed .knxprod** - Full ETS-importable package
//!
//! # Example: Generate All Files
//!
//! ```rust,ignore
//! use knxprod::{KnxprodBuilder, ApplicationProgramConfig};
//!
//! let config = ApplicationProgramConfig { /* ... */ };
//! let output = KnxprodBuilder::new(&config)
//!     .generate_all()?;
//!
//! println!("App XML: {} bytes", output.application_program.len());
//! ```
//!
//! # Example: Write to Directory
//!
//! ```rust,ignore
//! use knxprod::KnxprodBuilder;
//!
//! KnxprodBuilder::new(&config)
//!     .output_dir("out/MyDevice")
//!     .write_mtxml()?;
//! ```
//!
//! # Example: Create Signed Package
//!
//! ```rust,ignore
//! use knxprod::{KnxprodBuilder, MasterDataSource};
//!
//! let knxprod_bytes = KnxprodBuilder::new(&config)
//!     .master_data(MasterDataSource::Download)
//!     .build_knxprod()?;
//!
//! std::fs::write("MyDevice.knxprod", knxprod_bytes)?;
//! ```

use std::path::PathBuf;
use std::{fs, io};

use super::baggage::BaggageGenerator;
use super::catalog::CatalogGenerator;
use super::hardware::HardwareGenerator;
use super::mtxml::MtxmlGenerator;
use super::{ApplicationProgramConfig, GeneratorError};
use crate::signing::{create_knxprod, KnxSchemaVersion, MasterDataSource, SigningConfig, SigningError};

// ============================================================================
// Generated Output
// ============================================================================

/// Output from KNX product generation.
///
/// Contains all the generated XML content that can be used directly
/// or written to files.
#[derive(Debug, Clone)]
pub struct KnxprodOutput {
    /// ApplicationProgram XML content
    pub application_program: String,

    /// Hardware XML content
    pub hardware: String,

    /// Catalog XML content
    pub catalog: String,

    /// Baggages XML content (if baggages are defined)
    pub baggages: Option<String>,

    /// Baggage files for signing (relative_path, content)
    pub baggage_files: Vec<(String, Vec<u8>)>,

    /// Manufacturer ID (4 hex chars, e.g., "0083")
    pub manufacturer_id: String,

    /// Application program ID (e.g., "M-0083_A-009B-14-E59D")
    pub application_program_id: String,
}

impl KnxprodOutput {
    /// Get all generated XML files as (filename, content) pairs.
    ///
    /// Useful for iterating over files to write or display.
    pub fn xml_files(&self) -> Vec<(&'static str, &str)> {
        let mut files = vec![
            ("ApplicationProgram1.mtxml", self.application_program.as_str()),
            ("Hardware1.mtxml", self.hardware.as_str()),
            ("Catalog1.mtxml", self.catalog.as_str()),
        ];

        if let Some(ref baggages) = self.baggages {
            files.push(("Baggages.mtxml", baggages.as_str()));
        }

        files
    }
}

// ============================================================================
// Builder Error
// ============================================================================

/// Errors that can occur during KNX product building.
#[derive(Debug)]
pub enum BuilderError {
    /// Error during XML generation
    Generation(GeneratorError),

    /// Error during signing/packaging
    Signing(SigningError),

    /// I/O error (file operations)
    Io(io::Error),

    /// Configuration error
    Config(String),
}

impl std::fmt::Display for BuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuilderError::Generation(e) => write!(f, "Generation error: {}", e),
            BuilderError::Signing(e) => write!(f, "Signing error: {}", e),
            BuilderError::Io(e) => write!(f, "I/O error: {}", e),
            BuilderError::Config(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for BuilderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BuilderError::Generation(e) => Some(e),
            BuilderError::Signing(e) => Some(e),
            BuilderError::Io(e) => Some(e),
            BuilderError::Config(_) => None,
        }
    }
}

impl From<GeneratorError> for BuilderError {
    fn from(e: GeneratorError) -> Self {
        BuilderError::Generation(e)
    }
}

impl From<SigningError> for BuilderError {
    fn from(e: SigningError) -> Self {
        BuilderError::Signing(e)
    }
}

impl From<io::Error> for BuilderError {
    fn from(e: io::Error) -> Self {
        BuilderError::Io(e)
    }
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for KNX product generation and packaging.
///
/// Provides a fluent API for generating MTXML files and optionally
/// creating signed .knxprod packages.
///
/// # Example
///
/// ```rust,ignore
/// let output = KnxprodBuilder::new(&config)
///     .output_dir("out/MyDevice")
///     .file_prefix("My")  // Creates MyApplicationProgram1.mtxml, etc.
///     .generate_all()?;
/// ```
pub struct KnxprodBuilder<'a> {
    config: &'a ApplicationProgramConfig<'a>,
    output_dir: Option<PathBuf>,
    file_prefix: String,
    master_data: Option<MasterDataSource>,
    schema_version: Option<KnxSchemaVersion>,
}

impl<'a> KnxprodBuilder<'a> {
    /// Create a new builder with the given configuration.
    pub fn new(config: &'a ApplicationProgramConfig<'a>) -> Self {
        Self { config, output_dir: None, file_prefix: String::new(), master_data: None, schema_version: None }
    }

    /// Set the output directory for writing files.
    ///
    /// The directory structure will be:
    /// ```text
    /// {output_dir}/M-{manufacturer_id}/
    ///   ApplicationProgram1.mtxml
    ///   Hardware1.mtxml
    ///   Catalog1.mtxml
    ///   Baggages.mtxml (if baggages defined)
    ///   Baggages/
    ///     {baggage files}
    /// ```
    pub fn output_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.output_dir = Some(dir.into());
        self
    }

    /// Set a prefix for generated filenames.
    ///
    /// For example, `file_prefix("Mdt")` will generate:
    /// - MdtApplicationProgram1.mtxml
    /// - MdtHardware1.mtxml
    /// - MdtCatalog1.mtxml
    pub fn file_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.file_prefix = prefix.into();
        self
    }

    /// Set the master data source for knxprod generation.
    ///
    /// Required when calling `build_knxprod()`.
    pub fn master_data(mut self, source: MasterDataSource) -> Self {
        self.master_data = Some(source);
        self
    }

    /// Set the KNX XML schema version to use.
    ///
    /// This affects the xmlns namespace and tool version in generated XML files.
    /// Also determines which schema version to download for master data when
    /// using `MasterDataSource::Download`.
    ///
    /// If not set, defaults to V20.
    pub fn schema_version(mut self, version: KnxSchemaVersion) -> Self {
        self.schema_version = Some(version);
        self
    }

    // ========================================================================
    // Generation Methods
    // ========================================================================

    /// Generate all XML content without writing to disk.
    ///
    /// Returns a `KnxprodOutput` containing all generated content.
    pub fn generate_all(&self) -> Result<KnxprodOutput, BuilderError> {
        let application_program = MtxmlGenerator::generate(self.config, self.schema_version)?;
        let hardware = HardwareGenerator::generate(self.config, self.schema_version)?;
        let catalog = CatalogGenerator::generate(self.config, self.schema_version)?;
        let baggages = BaggageGenerator::generate(self.config, self.schema_version)?;
        let baggage_files = BaggageGenerator::get_files_for_signing(self.config, self.schema_version)?;

        let manufacturer_id = format!("{:04X}", self.config.device.manufacturer_id);
        let application_program_id = self.format_application_program_id();

        Ok(KnxprodOutput {
            application_program,
            hardware,
            catalog,
            baggages,
            baggage_files,
            manufacturer_id,
            application_program_id,
        })
    }

    /// Generate only the ApplicationProgram XML.
    pub fn generate_application_program(&self) -> Result<String, BuilderError> {
        Ok(MtxmlGenerator::generate(self.config, self.schema_version)?)
    }

    /// Generate only the Hardware XML.
    pub fn generate_hardware(&self) -> Result<String, BuilderError> {
        Ok(HardwareGenerator::generate(self.config, self.schema_version)?)
    }

    /// Generate only the Catalog XML.
    pub fn generate_catalog(&self) -> Result<String, BuilderError> {
        Ok(CatalogGenerator::generate(self.config, self.schema_version)?)
    }

    /// Generate only the Baggages XML (if baggages are defined).
    pub fn generate_baggages(&self) -> Result<Option<String>, BuilderError> {
        Ok(BaggageGenerator::generate(self.config, self.schema_version)?)
    }

    // ========================================================================
    // Write Methods
    // ========================================================================

    /// Write all MTXML files to the configured output directory.
    ///
    /// Creates the directory structure:
    /// ```text
    /// {output_dir}/M-{manufacturer_id}/
    ///   {prefix}ApplicationProgram1.mtxml
    ///   {prefix}Hardware1.mtxml
    ///   {prefix}Catalog1.mtxml
    ///   Baggages.mtxml (if baggages defined)
    ///   Baggages/
    ///     {baggage files}
    /// ```
    ///
    /// Returns the generated output for further use.
    pub fn write_mtxml(&self) -> Result<KnxprodOutput, BuilderError> {
        let output_dir = self.get_manufacturer_dir()?;
        let output = self.generate_all()?;

        // Create output directory
        fs::create_dir_all(&output_dir)?;

        // Write XML files
        let app_path = output_dir.join(format!("{}ApplicationProgram1.mtxml", self.file_prefix));
        fs::write(&app_path, &output.application_program)?;

        let hw_path = output_dir.join(format!("{}Hardware1.mtxml", self.file_prefix));
        fs::write(&hw_path, &output.hardware)?;

        let cat_path = output_dir.join(format!("{}Catalog1.mtxml", self.file_prefix));
        fs::write(&cat_path, &output.catalog)?;

        if let Some(ref baggages_xml) = output.baggages {
            // MT project expects Baggages.mtxml
            fs::write(output_dir.join("Baggages.mtxml"), baggages_xml)?;
        }

        // Write baggage files
        BaggageGenerator::write_files(&output_dir, self.config)?;

        Ok(output)
    }

    /// Write MTXML files and return file paths that were created.
    ///
    /// Similar to `write_mtxml()` but returns a list of created file paths.
    pub fn write_mtxml_with_paths(&self) -> Result<(KnxprodOutput, Vec<PathBuf>), BuilderError> {
        let output_dir = self.get_manufacturer_dir()?;
        let output = self.generate_all()?;

        // Create output directory
        fs::create_dir_all(&output_dir)?;

        let mut paths = Vec::new();

        // Write XML files
        let app_path = output_dir.join(format!("{}ApplicationProgram1.mtxml", self.file_prefix));
        fs::write(&app_path, &output.application_program)?;
        paths.push(app_path);

        let hw_path = output_dir.join(format!("{}Hardware1.mtxml", self.file_prefix));
        fs::write(&hw_path, &output.hardware)?;
        paths.push(hw_path);

        let cat_path = output_dir.join(format!("{}Catalog1.mtxml", self.file_prefix));
        fs::write(&cat_path, &output.catalog)?;
        paths.push(cat_path);

        if let Some(ref baggages_xml) = output.baggages {
            let bag_path = output_dir.join("Baggages.mtxml");
            fs::write(&bag_path, baggages_xml)?;
            paths.push(bag_path);
        }

        // Write baggage files
        BaggageGenerator::write_files(&output_dir, self.config)?;

        // Add baggage file paths
        if let Some(baggages) = self.config.baggages {
            let baggages_dir = output_dir.join("Baggages");
            for baggage in baggages {
                let file_path = if baggage.target_path.is_empty() {
                    baggages_dir.join(baggage.name)
                } else {
                    baggages_dir.join(baggage.target_path).join(baggage.name)
                };
                paths.push(file_path);
            }
        }

        Ok((output, paths))
    }

    // ========================================================================
    // Knxprod Generation
    // ========================================================================

    /// Build a signed .knxprod package.
    ///
    /// Requires `master_data()` to be set.
    ///
    /// When using `MasterDataSource::Download`, the schema version set via
    /// `schema_version()` is used to determine which master data to download.
    /// If no schema version is set, defaults to V20.
    ///
    /// Returns the raw bytes of the .knxprod ZIP file.
    pub fn build_knxprod(&self) -> Result<Vec<u8>, BuilderError> {
        let master_data = self.master_data.clone().ok_or_else(|| {
            BuilderError::Config("master_data() must be set before calling build_knxprod()".to_string())
        })?;

        // Resolve master data source - if Download, use the builder's schema version
        let resolved_master_data = match master_data {
            MasterDataSource::Download => {
                let version = self.schema_version.unwrap_or(KnxSchemaVersion::V20);
                MasterDataSource::DownloadVersion(version)
            }
            other => other,
        };

        let output = self.generate_all()?;
        let signing_config = self.create_signing_config(&output);

        let knxprod_bytes = create_knxprod(&signing_config, resolved_master_data)?;
        Ok(knxprod_bytes)
    }

    /// Build and write a signed .knxprod package to a file.
    ///
    /// If output_dir is set, the file is written to `{output_dir}/{name}.knxprod`.
    /// Otherwise, it's written to `{name}.knxprod` in the current directory.
    pub fn write_knxprod(&self) -> Result<PathBuf, BuilderError> {
        let knxprod_bytes = self.build_knxprod()?;

        let output_path = if let Some(ref dir) = self.output_dir {
            dir.join(format!("{}.knxprod", self.config.name))
        } else {
            PathBuf::from(format!("{}.knxprod", self.config.name))
        };

        // Create parent directory if needed
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&output_path, knxprod_bytes)?;
        Ok(output_path)
    }

    /// Build everything: write MTXML files and create .knxprod package.
    ///
    /// Convenience method that combines `write_mtxml()` and `write_knxprod()`.
    ///
    /// Returns the output data and the path to the .knxprod file.
    pub fn build_all(&self) -> Result<(KnxprodOutput, PathBuf), BuilderError> {
        let output = self.write_mtxml()?;
        let knxprod_path = self.write_knxprod_with_output(&output)?;
        Ok((output, knxprod_path))
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Get the manufacturer directory path.
    fn get_manufacturer_dir(&self) -> Result<PathBuf, BuilderError> {
        let base_dir =
            self.output_dir.clone().ok_or_else(|| BuilderError::Config("output_dir() must be set".to_string()))?;

        let manufacturer_id = format!("M-{:04X}", self.config.device.manufacturer_id);
        Ok(base_dir.join(manufacturer_id))
    }

    /// Format the application program ID.
    fn format_application_program_id(&self) -> String {
        let hash = self.config.application_hash.unwrap_or("0000");
        format!(
            "M-{:04X}_A-{:04X}-{:02X}-{}",
            self.config.device.manufacturer_id,
            self.config.device.application_id,
            self.config.device.application_version,
            hash
        )
    }

    /// Create a SigningConfig from the generated output.
    fn create_signing_config(&self, output: &KnxprodOutput) -> SigningConfig {
        SigningConfig {
            manufacturer_id: output.manufacturer_id.clone(),
            application_program: output.application_program.clone(),
            application_program_id: output.application_program_id.clone(),
            hardware: output.hardware.clone(),
            catalog: output.catalog.clone(),
            baggage_files: output.baggage_files.clone(),
        }
    }

    /// Write knxprod using pre-generated output.
    fn write_knxprod_with_output(&self, output: &KnxprodOutput) -> Result<PathBuf, BuilderError> {
        let master_data = self.master_data.clone().ok_or_else(|| {
            BuilderError::Config("master_data() must be set before calling write_knxprod()".to_string())
        })?;

        // Resolve master data source - if Download, use the builder's schema version
        let resolved_master_data = match master_data {
            MasterDataSource::Download => {
                let version = self.schema_version.unwrap_or(KnxSchemaVersion::V20);
                MasterDataSource::DownloadVersion(version)
            }
            other => other,
        };

        let signing_config = self.create_signing_config(output);
        let knxprod_bytes = create_knxprod(&signing_config, resolved_master_data)?;

        let output_path = if let Some(ref dir) = self.output_dir {
            dir.join(format!("{}.knxprod", self.config.name))
        } else {
            PathBuf::from(format!("{}.knxprod", self.config.name))
        };

        // Create parent directory if needed
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&output_path, knxprod_bytes)?;
        Ok(output_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would go here, but require a valid ApplicationProgramConfig
    // which needs device descriptors, params, etc.
}
