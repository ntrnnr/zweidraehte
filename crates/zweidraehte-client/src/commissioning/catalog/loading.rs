//! Load self-identifying Master Data from explicit, archived or cached sources.

use super::{CompileError, ProgrammingCatalog};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_ets_files::schema::master_data::MaskVersion;
use zweidraehte_ets_files::{MasterData, MasterDataError};

// Existing client paths name the shared acquisition vocabulary. Only live
// commissioning policy and catalog fingerprints belong to this layer.
pub use zweidraehte_ets_files::master_data::{
    MasterDataLoadRequest as ProgrammingCatalogLoadRequest, MasterDataOrigin as ProgrammingCatalogSource,
};

/// Acquiring a catalog can fail before any target is selected or compiled.
/// Keep the original file/XML/network error separate from commissioning policy
/// (for example, a schema generation the compiler cannot support).
#[derive(Debug, thiserror::Error)]
pub enum ProgrammingCatalogLoadError {
    #[error(transparent)]
    MasterData(#[from] MasterDataError),
    #[error(transparent)]
    Policy(#[from] CompileError),
}

/// Auditable identity of one loaded Master Data document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgrammingCatalogProvenance {
    pub master_data_schema_version: u16,
    pub master_data_id: Option<String>,
    pub master_data_version: String,
    pub source: ProgrammingCatalogSource,
    pub fingerprint: [u8; 32],
}

/// A catalog paired with the exact source and version that produced it.
pub struct LoadedProgrammingCatalog {
    catalog: ProgrammingCatalog,
    provenance: ProgrammingCatalogProvenance,
}

impl LoadedProgrammingCatalog {
    pub fn catalog(&self) -> &ProgrammingCatalog {
        &self.catalog
    }

    pub fn provenance(&self) -> &ProgrammingCatalogProvenance {
        &self.provenance
    }

    pub fn into_catalog(self) -> ProgrammingCatalog {
        self.catalog
    }
}

pub(super) fn supported_master_data_schema(version: u16) -> Result<(), CompileError> {
    match version {
        10..=23 => Ok(()),
        version => Err(CompileError::unsupported(format!(
            "Master Data uses unsupported project schema {version}; live commissioning supports project-10 through project-23"
        ))),
    }
}

impl ProgrammingCatalog {
    /// Parse a document for inspection, retaining XML errors and allowing
    /// schema generations which live commissioning does not yet support.
    pub fn from_xml(xml: &str) -> Result<Self, ProgrammingCatalogLoadError> {
        let master_data = xml.parse::<MasterData>()?;
        Ok(Self::from_document(Arc::new(master_data)))
    }

    pub fn from_document(master_data: Arc<MasterData>) -> Self {
        let fingerprint = Sha256::digest(master_data.source_xml().as_bytes()).into();
        Self { master_data, fingerprint }
    }

    /// Access only the product's associated document. This never performs I/O.
    pub fn for_product(product: &ProductData) -> Result<Self, CompileError> {
        product
            .master_data()
            .cloned()
            .map(Self::from_document)
            .ok_or_else(|| CompileError::missing_evidence(format!("product `{}` has no associated Master Data; bind its package document or supply one before compilation", product.id())))
    }

    /// Share this exact document with a loose product or evaluated device.
    pub fn document(&self) -> Arc<MasterData> {
        Arc::clone(&self.master_data)
    }

    /// Read an inspectable document, retaining its path and I/O or XML cause.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ProgrammingCatalogLoadError> {
        Ok(Self::from_document(Arc::new(MasterData::from_file(path)?)))
    }

    /// Load the exact catalog; compilation validates the selected target.
    ///
    /// Product-derived selection fails when schema provenance is missing or
    /// its generation is unsupported. An override never falls back to another
    /// source when reading, downloading, or validating it fails.
    pub fn load(
        request: ProgrammingCatalogLoadRequest<'_>,
    ) -> Result<LoadedProgrammingCatalog, ProgrammingCatalogLoadError> {
        let source = select_source(request)?;
        let catalog = Self::from_document(request.load()?);
        let master_data_schema_version = catalog.master_data.schema_version().expect("loader validates namespace");

        supported_master_data_schema(master_data_schema_version)?;

        let provenance = ProgrammingCatalogProvenance {
            master_data_schema_version,
            master_data_id: catalog.master_data.document_id().map(str::to_owned),
            master_data_version: catalog.master_data.document_version().to_owned(),
            source,
            fingerprint: catalog.fingerprint,
        };

        Ok(LoadedProgrammingCatalog { catalog, provenance })
    }
}

/// Resolve source identity before doing any file or network I/O.
pub(super) fn select_source(
    request: ProgrammingCatalogLoadRequest<'_>,
) -> Result<ProgrammingCatalogSource, ProgrammingCatalogLoadError> {
    let source = request.source()?;
    if let ProgrammingCatalogSource::VersionedResolver(version) = &source {
        supported_master_data_schema(*version)?;
    }
    Ok(source)
}

pub(super) fn validate_mask_tokens(mask: &MaskVersion) -> Result<(), CompileError> {
    for medium in [mask.medium_type_ref_id.as_deref(), mask.other_medium_type_ref_id.as_deref()].into_iter().flatten() {
        if !matches!(medium, "MT-0" | "MT-1" | "MT-2" | "MT-5" | "MT-6") {
            return Err(CompileError::unsupported(format!("unknown Master Data medium type {medium:?}")));
        }
    }
    Ok(())
}

impl ProgrammingCatalog {
    pub(crate) fn validate_for_live_commissioning(&self) -> Result<(), CompileError> {
        let version =
            self.master_data.schema_version().ok_or_else(|| CompileError::missing_evidence(format!(
                "Master Data has no unambiguous project-schema namespace ({:?}); live commissioning requires a versioned project-10 through project-23 catalog", self.master_data.namespace()
            )))?;
        supported_master_data_schema(version)
    }
}
