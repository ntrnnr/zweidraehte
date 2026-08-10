//! `KnxprodBuilder`'s packaging half: turning generated MTXML into
//! signed `.knxprod` / `.knxproj` archives.
//!
//! Split out of [`super::builder`] so the `packaging` feature is gated
//! once — at this module's declaration in [`super`] — instead of on
//! every method. Everything here needs the crypto/ZIP/HTTP stack;
//! [`super::builder`] itself needs only quick-xml, so a consumer that
//! merely generates or parses XML never builds those dependencies.

use std::fs;
use std::path::PathBuf;

use super::builder::{BuilderError, KnxprodOutput};
use super::{ApplicationProgramDef, KnxprodBuilder};
use crate::signing::{KnxSchemaVersion, MasterDataSource, SigningConfig, create_knxprod};

impl<'a> KnxprodBuilder<'a> {
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
    // Knxproj Generation
    // ========================================================================

    /// Build a signed `.knxproj` package containing both product data and
    /// an ETS project with the registered device instances.
    ///
    /// Requires [`Self::project_name`], [`Self::master_data`], and at least
    /// one device instance registered via [`Self::device_instance`].
    pub fn build_knxproj(&self) -> Result<Vec<u8>, BuilderError> {
        use super::project_gen::ProjectGenerator;
        use crate::signing::{ProjectConfig, create_knxproj};

        let project_name = self.project_name.as_deref().ok_or_else(|| {
            BuilderError::Config("project_name() must be set before calling build_knxproj()".to_string())
        })?;
        if self.device_instances.is_empty() {
            return Err(BuilderError::Config(
                "at least one device_instance() must be registered before calling build_knxproj()".to_string(),
            ));
        }

        let master_data = self.master_data.clone().ok_or_else(|| {
            BuilderError::Config("master_data() must be set before calling build_knxproj()".to_string())
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

        let project_id = "P-0001";

        // ETS reserves Puid 1 and 2 for internal use; device Puids start at 3.
        let last_used_puid = 2 + self.device_instances.len() as u32;

        let project_xml =
            ProjectGenerator::generate_project_xml(project_id, project_name, last_used_puid, self.schema_version)?;

        let app_refs: Vec<&ApplicationProgramDef> = self.application_programs.to_vec();
        let topology_xml = ProjectGenerator::generate_topology_xml(
            project_id,
            self.manufacturer_id,
            &self.device_instances,
            &self.hardware_defs,
            &app_refs,
            self.schema_version,
        )?;

        let project_config = ProjectConfig { project_id: project_id.to_string(), project_xml, topology_xml };

        let knxproj_bytes = create_knxproj(&signing_config, &project_config, resolved_master_data)?;
        Ok(knxproj_bytes)
    }

    /// Build and write a signed `.knxproj` package to a file.
    pub fn write_knxproj(&self) -> Result<PathBuf, BuilderError> {
        let knxproj_bytes = self.build_knxproj()?;
        let name = self.project_name.as_deref().unwrap_or("project");

        let output_path = if let Some(ref dir) = self.output_dir {
            dir.join(format!("{}.knxproj", name))
        } else {
            PathBuf::from(format!("{}.knxproj", name))
        };

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&output_path, knxproj_bytes)?;
        Ok(output_path)
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
