//! Unified builder for KNX product generation.
//!
//! The `KnxprodBuilder` provides a fluent API for generating KNX product files,
//! combining all the individual generators (MTXML, Hardware, Catalog, Baggage)
//! and optionally creating signed .knxprod packages.
//!
//! # Single Device (common case)
//!
//! ```rust,ignore
//! use knxprod::{KnxprodBuilder, ApplicationProgramDef, SingleDeviceDef};
//!
//! let app = ApplicationProgramDef { /* ... */ };
//! let output = KnxprodBuilder::single_device(SingleDeviceDef {
//!     app: &app,
//!     serial_number: [0x00, 0xFA, 0x00, 0x00, 0x00, 0x01],
//!     hardware_version: 1,
//!     hardware_name: "My Device",
//!     product_name: "My Device v1",
//!     order_number: "DEV-001",
//!     is_rail_mounted: false,
//!     catalog_section: "My Devices",
//! })
//! .output_dir("out/MyDevice")
//! .schema_version(KnxSchemaVersion::V20)
//! .generate_all()?;
//! ```
//!
//! # Multi-Device
//!
//! ```rust,ignore
//! let mut builder = KnxprodBuilder::new(0x0083);
//! let app1_ref = builder.application_program(&app1);
//! let app2_ref = builder.application_program(&app2);
//! let hw_ref = builder.hardware(HardwareDef {
//!     serial_number: [0x00, 0x83, 0x00, 0x97, 0x00, 0x01],
//!     hardware_version: 1,
//!     name: "Push Button Lite",
//!     bus_current: Some(8),
//!     products: vec![
//!         ProductDef { name: "PB Lite 55", order_number: "KP_BE_55", .. },
//!         ProductDef { name: "PB Lite 63", order_number: "KP_BE_63", .. },
//!     ],
//!     application_programs: vec![app1_ref],
//! });
//! builder.catalog(CatalogSectionDef {
//!     name: "Push Buttons",
//!     entries: vec![
//!         CatalogEntryDef { name: "PB Lite 55", hardware: hw_ref, .. },
//!     ],
//!     subsections: vec![],
//! });
//! let output = builder
//!     .schema_version(KnxSchemaVersion::V20)
//!     .output_dir("out/MyDevice")
//!     .generate_all()?;
//! ```

use std::path::PathBuf;
use std::{fs, io};

use super::baggage::BaggageGenerator;
use super::catalog::CatalogGenerator;
use super::hardware::HardwareGenerator;
use super::mtxml::MtxmlGenerator;
use super::{
    ApplicationProgramConfig, ApplicationProgramDef, CatalogEntryDef, CatalogSectionDef,
    GeneratorError, HardwareDef, ProductDef, SingleDeviceDef,
};
use crate::signing::{create_knxprod, KnxSchemaVersion, MasterDataSource, SigningConfig, SigningError};

// ============================================================================
// Handle Types
// ============================================================================

/// Typed handle referencing an application program registered with a builder.
///
/// Returned by [`KnxprodBuilder::application_program`]. Pass into
/// [`HardwareDef::application_programs`] and [`CatalogEntryDef::application_program`]
/// to create cross-references.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppProgramRef(pub(super) usize);

/// Typed handle referencing a hardware definition registered with a builder.
///
/// Returned by [`KnxprodBuilder::hardware`]. Pass into
/// [`CatalogEntryDef::hardware`] to create cross-references.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardwareRef(pub(super) usize);

// ============================================================================
// Generated Output
// ============================================================================

/// Output from KNX product generation.
///
/// Contains all the generated XML content that can be used directly
/// or written to files.
#[derive(Debug, Clone)]
pub struct KnxprodOutput {
    /// ApplicationProgram XML files: `(program_id, xml_content)` pairs.
    ///
    /// For single-device builds this contains exactly one entry.
    pub application_programs: Vec<(String, String)>,

    /// Hardware XML content (single file containing all hardware definitions).
    pub hardware: String,

    /// Catalog XML content (single file containing all catalog sections).
    pub catalog: String,

    /// Baggages XML content (if any application program defines baggages).
    pub baggages: Option<String>,

    /// Baggage files for signing: `(relative_path, content)` pairs.
    pub baggage_files: Vec<(String, Vec<u8>)>,

    /// Manufacturer ID (4 hex chars, e.g., "0083").
    pub manufacturer_id: String,
}

impl KnxprodOutput {
    /// Get all generated XML files as `(filename, content)` pairs.
    pub fn xml_files(&self) -> Vec<(String, &str)> {
        let mut files = Vec::new();

        // For single-app case, keep the traditional filename for compatibility.
        // For multi-app, use the program ID as filename (matching real knxprod format).
        if self.application_programs.len() == 1 {
            files.push((
                "ApplicationProgram1.mtxml".to_string(),
                self.application_programs[0].1.as_str(),
            ));
        } else {
            for (id, content) in &self.application_programs {
                files.push((format!("{}.mtxml", id), content.as_str()));
            }
        }

        files.push(("Hardware1.mtxml".to_string(), self.hardware.as_str()));
        files.push(("Catalog1.mtxml".to_string(), self.catalog.as_str()));

        if let Some(ref baggages) = self.baggages {
            files.push(("Baggages.mtxml".to_string(), baggages.as_str()));
        }

        files
    }

    /// Get the single application program ID.
    ///
    /// Convenience for the common single-device case. Panics if there are
    /// multiple application programs.
    pub fn application_program_id(&self) -> &str {
        assert_eq!(
            self.application_programs.len(),
            1,
            "application_program_id() requires exactly one application program"
        );
        &self.application_programs[0].0
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
/// Supports two usage patterns:
///
/// 1. **Single device** via [`KnxprodBuilder::single_device`] — the common case
///    with one application program, one hardware, one product, one catalog entry.
///
/// 2. **Multi-device** via [`KnxprodBuilder::new`] — multiple application programs,
///    hardware definitions, and catalog entries in one package.
pub struct KnxprodBuilder<'a> {
    manufacturer_id: u16,
    application_programs: Vec<&'a ApplicationProgramDef<'a>>,
    hardware_defs: Vec<HardwareDef<'a>>,
    catalog_sections: Vec<CatalogSectionDef<'a>>,

    // Name used for the knxprod filename (derived from first app program).
    knxprod_name: Option<String>,

    output_dir: Option<PathBuf>,
    file_prefix: String,
    master_data: Option<MasterDataSource>,
    schema_version: Option<KnxSchemaVersion>,
}

impl<'a> KnxprodBuilder<'a> {
    /// Create a multi-device builder for the given manufacturer.
    ///
    /// Register application programs, hardware, and catalog sections using
    /// the `.application_program()`, `.hardware()`, and `.catalog()` methods.
    pub fn new(manufacturer_id: u16) -> Self {
        Self {
            manufacturer_id,
            application_programs: Vec::new(),
            hardware_defs: Vec::new(),
            catalog_sections: Vec::new(),
            knxprod_name: None,
            output_dir: None,
            file_prefix: String::new(),
            master_data: None,
            schema_version: None,
        }
    }

    /// Create a builder for the common single-device case.
    ///
    /// This sets up one hardware with one product, one Hardware2Program,
    /// one catalog section, and one catalog item — all wired together
    /// automatically.
    pub fn single_device(def: SingleDeviceDef<'a>) -> Self {
        let manufacturer_id = def.app.device.manufacturer_id;
        let mut builder = Self::new(manufacturer_id);
        builder.knxprod_name = Some(def.app.name.to_string());

        let app_ref = builder.application_program(def.app);
        let hw_ref = builder.hardware(HardwareDef {
            serial_number: def.serial_number,
            hardware_version: def.hardware_version,
            name: def.hardware_name,
            bus_current: None,
            products: vec![ProductDef {
                name: def.product_name,
                order_number: def.order_number,
                is_rail_mounted: def.is_rail_mounted,
                visible_description: None,
            }],
            application_programs: vec![app_ref],
        });
        builder.catalog(CatalogSectionDef {
            name: def.catalog_section,
            entries: vec![CatalogEntryDef {
                name: def.product_name,
                hardware: hw_ref,
                product_order_number: def.order_number,
                application_program: app_ref,
            }],
            subsections: vec![],
        });

        builder
    }

    // ========================================================================
    // Registration Methods
    // ========================================================================

    /// Register an application program and get a typed handle.
    ///
    /// The handle is used in [`HardwareDef`] and [`CatalogEntryDef`] to
    /// create cross-references.
    pub fn application_program(&mut self, app: &'a ApplicationProgramDef<'a>) -> AppProgramRef {
        let idx = self.application_programs.len();
        self.application_programs.push(app);
        if self.knxprod_name.is_none() {
            self.knxprod_name = Some(app.name.to_string());
        }
        AppProgramRef(idx)
    }

    /// Register a hardware definition and get a typed handle.
    ///
    /// The handle is used in [`CatalogEntryDef`] to reference this hardware.
    pub fn hardware(&mut self, hw: HardwareDef<'a>) -> HardwareRef {
        let idx = self.hardware_defs.len();
        self.hardware_defs.push(hw);
        HardwareRef(idx)
    }

    /// Add a catalog section.
    pub fn catalog(&mut self, section: CatalogSectionDef<'a>) {
        self.catalog_sections.push(section);
    }

    // ========================================================================
    // Configuration Methods (chainable, consume self)
    // ========================================================================

    /// Set the output directory for writing files.
    pub fn output_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.output_dir = Some(dir.into());
        self
    }

    /// Set a prefix for generated filenames.
    pub fn file_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.file_prefix = prefix.into();
        self
    }

    /// Set the master data source for knxprod generation.
    pub fn master_data(mut self, source: MasterDataSource) -> Self {
        self.master_data = Some(source);
        self
    }

    /// Set the KNX XML schema version to use.
    pub fn schema_version(mut self, version: KnxSchemaVersion) -> Self {
        self.schema_version = Some(version);
        self
    }

    // ========================================================================
    // Generation Methods
    // ========================================================================

    /// Generate all XML content without writing to disk.
    pub fn generate_all(&self) -> Result<KnxprodOutput, BuilderError> {
        if self.application_programs.is_empty() {
            return Err(BuilderError::Config("no application programs registered".to_string()));
        }
        if self.hardware_defs.is_empty() {
            return Err(BuilderError::Config("no hardware definitions registered".to_string()));
        }

        let manufacturer_id = format!("{:04X}", self.manufacturer_id);

        // Generate each application program XML independently via the
        // MtxmlGenerator adapter (builds a temporary ApplicationProgramConfig).
        let mut app_programs = Vec::new();
        let mut all_baggages_xml = None;
        let mut all_baggage_files = Vec::new();

        for app_def in &self.application_programs {
            let config = Self::build_legacy_config_for_app(app_def);
            let xml = MtxmlGenerator::generate(&config, self.schema_version)?;
            let app_id = Self::format_app_id(app_def);
            app_programs.push((app_id, xml));

            // Collect baggages from all app programs.
            if let Some(baggages) = app_def.baggages {
                if let Ok(Some(bag_xml)) = BaggageGenerator::generate(self.manufacturer_id, Some(baggages), self.schema_version) {
                    all_baggages_xml = Some(bag_xml);
                }
                if let Ok(files) = BaggageGenerator::get_files_for_signing(self.manufacturer_id, baggages, self.schema_version) {
                    all_baggage_files.extend(files);
                }
            }
        }

        // Generate Hardware XML from all hardware definitions.
        let hardware = HardwareGenerator::generate_multi(
            self.manufacturer_id,
            &self.hardware_defs,
            &self.application_programs,
            self.schema_version,
        )?;

        // Generate Catalog XML from all catalog sections.
        let catalog = CatalogGenerator::generate_multi(
            self.manufacturer_id,
            &self.catalog_sections,
            &self.hardware_defs,
            &self.application_programs,
            self.schema_version,
        )?;

        Ok(KnxprodOutput {
            application_programs: app_programs,
            hardware,
            catalog,
            baggages: all_baggages_xml,
            baggage_files: all_baggage_files,
            manufacturer_id,
        })
    }

    /// Write all MTXML files to the configured output directory.
    pub fn write_mtxml(&self) -> Result<KnxprodOutput, BuilderError> {
        let output_dir = self.get_manufacturer_dir()?;
        let output = self.generate_all()?;

        fs::create_dir_all(&output_dir)?;

        // Write XML files (ApplicationProgram, Hardware, Catalog, Baggages)
        for (filename, content) in output.xml_files() {
            let path = output_dir.join(format!("{}{}", self.file_prefix, filename));
            fs::write(&path, content)?;
        }

        // Write baggage files (the actual content files, not the XML manifest)
        self.write_baggage_files(&output_dir)?;

        Ok(output)
    }

    /// Write MTXML files and return file paths that were created.
    pub fn write_mtxml_with_paths(&self) -> Result<(KnxprodOutput, Vec<PathBuf>), BuilderError> {
        let output_dir = self.get_manufacturer_dir()?;
        let output = self.generate_all()?;

        fs::create_dir_all(&output_dir)?;

        let mut paths = Vec::new();

        for (filename, content) in output.xml_files() {
            let path = output_dir.join(format!("{}{}", self.file_prefix, filename));
            fs::write(&path, content)?;
            paths.push(path);
        }

        // Write baggage files
        if !output.baggage_files.is_empty() {
            self.write_baggage_files(&output_dir)?;

            let baggages_dir = output_dir.join("Baggages");
            for (rel_path, _) in &output.baggage_files {
                paths.push(baggages_dir.join(rel_path));
            }
        }

        Ok((output, paths))
    }

    // ========================================================================
    // Knxprod Generation
    // ========================================================================

    /// Build a signed .knxprod package.
    pub fn build_knxprod(&self) -> Result<Vec<u8>, BuilderError> {
        let master_data = self.master_data.clone().ok_or_else(|| {
            BuilderError::Config("master_data() must be set before calling build_knxprod()".to_string())
        })?;

        let resolved_master_data = match master_data {
            MasterDataSource::Download => {
                let version = self.schema_version.unwrap_or(KnxSchemaVersion::V20);
                MasterDataSource::DownloadVersion(version)
            }
            other => other,
        };

        let output = self.generate_all()?;
        let signing_config = Self::create_signing_config(&output);
        let knxprod_bytes = create_knxprod(&signing_config, resolved_master_data)?;
        Ok(knxprod_bytes)
    }

    /// Build and write a signed .knxprod package to a file.
    pub fn write_knxprod(&self) -> Result<PathBuf, BuilderError> {
        let knxprod_bytes = self.build_knxprod()?;
        let name = self.knxprod_name.as_deref().unwrap_or("knxprod");

        let output_path = if let Some(ref dir) = self.output_dir {
            dir.join(format!("{}.knxprod", name))
        } else {
            PathBuf::from(format!("{}.knxprod", name))
        };

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&output_path, knxprod_bytes)?;
        Ok(output_path)
    }

    /// Build everything: write MTXML files and create .knxprod package.
    pub fn build_all(&self) -> Result<(KnxprodOutput, PathBuf), BuilderError> {
        let output = self.write_mtxml()?;
        let knxprod_path = self.write_knxprod()?;
        Ok((output, knxprod_path))
    }

    // ========================================================================
    // Internal: ApplicationProgramConfig Adapter
    // ========================================================================

    /// Build an internal `ApplicationProgramConfig` from an `ApplicationProgramDef`.
    ///
    /// This is the adapter that lets us reuse the existing `MtxmlGenerator`
    /// without modifying its interface. The hardware/catalog fields are filled
    /// with dummy values since the MTXML generator only uses them for
    /// System 7 load procedures (serial_number).
    fn build_legacy_config_for_app(app: &'a ApplicationProgramDef<'a>) -> ApplicationProgramConfig<'a> {
        ApplicationProgramConfig {
            name: app.name,
            device: app.device,
            params: app.params,
            virtual_params: app.virtual_params,
            param_defaults: app.param_defaults,
            comm_objects: app.comm_objects,
            comm_object_refs: app.comm_object_refs,
            union_fields: app.union_fields,
            channel_name: app.channel_name,
            absolute_segment_address: app.absolute_segment_address,
            system7_layout: app.system7_layout.clone(),
            application_hash: app.application_hash,
            non_reg_relevant_data_version: app.non_reg_relevant_data_version,
            replaces_versions: app.replaces_versions,
            application_data_hash: app.application_data_hash,
            page_layout: app.page_layout.clone(),
            modules: app.modules.clone(),
            baggages: app.baggages,
            translations: app.translations,
        }
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Write baggage content files to the output directory.
    fn write_baggage_files(&self, output_dir: &std::path::Path) -> Result<(), BuilderError> {
        for app_def in &self.application_programs {
            if let Some(baggages) = app_def.baggages {
                BaggageGenerator::write_files(output_dir, baggages)?;
            }
        }
        Ok(())
    }

    fn get_manufacturer_dir(&self) -> Result<PathBuf, BuilderError> {
        let base_dir =
            self.output_dir.clone().ok_or_else(|| BuilderError::Config("output_dir() must be set".to_string()))?;

        let manufacturer_id = format!("M-{:04X}", self.manufacturer_id);
        Ok(base_dir.join(manufacturer_id))
    }

    fn format_app_id(app: &ApplicationProgramDef) -> String {
        let hash = app.application_hash.unwrap_or("0000");
        format!(
            "M-{:04X}_A-{:04X}-{:02X}-{}",
            app.device.manufacturer_id,
            app.device.application_id,
            app.device.application_version,
            hash
        )
    }

    fn create_signing_config(output: &KnxprodOutput) -> SigningConfig {
        SigningConfig {
            manufacturer_id: output.manufacturer_id.clone(),
            application_programs: output.application_programs.clone(),
            hardware: output.hardware.clone(),
            catalog: output.catalog.clone(),
            baggage_files: output.baggage_files.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests require valid device definitions — covered by gen binary integration tests.
}
