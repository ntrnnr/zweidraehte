//! `KnxprodBuilder`'s packaging half: turning generated MTXML into
//! signed `.knxprod` archives.
//!
//! Split out of [`super::builder`] so the `packaging` feature is gated
//! once — at this module's declaration in [`super`] — instead of on
//! every method. Everything here needs the package foundation's signing
//! stack; [`super::builder`] itself only generates schema values and XML.

use std::fs;
use std::path::PathBuf;

use super::KnxprodBuilder;
use super::builder::{BuilderError, KnxprodOutput};
use zweidraehte_ets_files::signing::{ConverterKey, KnxSchemaVersion, MasterDataSource, SigningConfig, create_knxprod};

impl<'a> KnxprodBuilder<'a> {
    /// Select the git-ignored converter key file used to sign packages.
    pub fn converter_key_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.converter_key_file = Some(path.into());
        self
    }

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
        let converter_key_path = self.converter_key_file.as_ref().ok_or_else(|| {
            BuilderError::Config("converter_key_file() must be set before calling build_knxprod()".to_string())
        })?;
        let converter_key = ConverterKey::from_file(converter_key_path)?;
        let knxprod_bytes = create_knxprod(&signing_config, resolved_master_data, &converter_key)?;
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
