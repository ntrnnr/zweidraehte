//! Select each product's catalog before project compilation or bus access.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use zweidraehte_ets_files::master_data::MasterDataInstallation;
use zweidraehte_ets_files::product::ProductData;

use crate::commissioning::{ProgrammingCatalog, ProgrammingCatalogLoadError};
use crate::project::error::{Error, Result};

/// The installation catalog every product of a project compiles against.
///
/// Loading starts from the installation's own catalog, an explicit file or the
/// newest generation from the cache/download, and offers each product's
/// package document as installing that package would
/// ([`MasterDataInstallation`]). A product with a bound catalog keeps it;
/// binding already checked that catalog against the same rule. Selection is complete before preparation starts: looking up a
/// product never reads files or downloads Master Data.
#[derive(Clone, Default)]
pub struct ProjectProgrammingCatalogs {
    installation: Option<ProgrammingCatalog>,
}

impl std::fmt::Debug for ProjectProgrammingCatalogs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProjectProgrammingCatalogs")
            .field("installation_fingerprint", &self.installation.as_ref().map(ProgrammingCatalog::fingerprint))
            .finish()
    }
}

impl ProjectProgrammingCatalogs {
    /// Use a catalog already selected for every product in scope.
    pub fn with_installation(catalog: ProgrammingCatalog) -> Self {
        Self { installation: Some(catalog) }
    }

    /// Retrieve the catalog selected for this product, without performing I/O.
    pub fn for_product(&self, product: &ProductData) -> Result<ProgrammingCatalog> {
        if product.master_data().is_some() {
            return ProgrammingCatalog::for_product(product).map_err(Error::Catalog);
        }

        self.installation.clone().ok_or_else(|| Error::MissingCatalog { product: product.id().into() })
    }
}

/// Select the installation catalog from an explicit file or the cache/server.
impl ProjectProgrammingCatalogs {
    /// Explicit acquisition for the same loaded inputs supplied to a planner.
    pub fn load_for(
        products: &BTreeMap<zweidraehte_project::ProjectDeviceId, super::ProjectProduct>,
        installation: Option<&Path>,
    ) -> Result<Self> {
        Self::load(products.values().map(|product| product.product()), installation)
    }

    /// Offer every unbound product's package document to one installation.
    ///
    /// An explicit installation file never falls back to the cache/download.
    /// A package for a newer project schema than the installation fails.
    pub fn load<'a>(
        products: impl IntoIterator<Item = &'a ProductData>,
        installation: Option<&Path>,
    ) -> Result<ProjectProgrammingCatalogs> {
        let products: Vec<_> = products.into_iter().filter(|product| product.master_data().is_none()).collect();
        if products.is_empty() {
            return Ok(Self::default());
        }

        let mut selected = MasterDataInstallation::load(installation).map_err(ProgrammingCatalogLoadError::from)?;
        for product in products {
            selected.offer_product(product).map_err(ProgrammingCatalogLoadError::from)?;
        }

        // Adoption never changes the installation's schema, so checking the
        // selected catalog also covers the installation's own document.
        let catalog = ProgrammingCatalog::from_document(Arc::clone(selected.document()));
        catalog.validate_for_live_commissioning().map_err(ProgrammingCatalogLoadError::from)?;
        Ok(Self::with_installation(catalog))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::CompileErrorKind;
    use std::error::Error as _;
    use zweidraehte_ets_files::MasterDataError;
    use zweidraehte_ets_files::schema::KnxSchemaVersion;

    fn xml(schema: u16, version: u64) -> String {
        format!(r#"<KNX xmlns="http://knx.org/xml/project/{schema}"><MasterData Version="{version}" /></KNX>"#)
    }

    fn catalog(schema: u16, version: u64) -> ProgrammingCatalog {
        ProgrammingCatalog::from_xml(&xml(schema, version)).expect("catalog fixture")
    }

    fn packaged(schema: u16, version: u64) -> ProductData {
        ProductData::default().with_package_master_data(catalog(schema, version).document())
    }

    #[test]
    fn project_catalog_loading_preserves_file_xml_and_policy_failures() {
        let product = ProductData::default().bind_schema_version(KnxSchemaVersion::V20).expect("schema binds");
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("knx_master.xml");

        let error = ProjectProgrammingCatalogs::load([&product], Some(&path)).expect_err("missing explicit file");
        let cause = error
            .source()
            .expect("loading cause")
            .downcast_ref::<ProgrammingCatalogLoadError>()
            .expect("typed loader error");
        assert!(matches!(cause, ProgrammingCatalogLoadError::MasterData(MasterDataError::Io {
            path: retained, source,
        }) if retained == &path && source.kind() == std::io::ErrorKind::NotFound));
        assert!(cause.source().expect("I/O cause").is::<std::io::Error>());

        // An explicit invalid file must fail in place, never fall back to a
        // downloaded/cached document.
        std::fs::write(&path, "<KNX><MasterData").expect("malformed fixture writes");
        assert!(matches!(
            ProjectProgrammingCatalogs::load([&product], Some(&path)),
            Err(Error::CatalogLoad(ProgrammingCatalogLoadError::MasterData(MasterDataError::Xml(_))))
        ));

        std::fs::write(&path, xml(24, 1)).expect("unsupported fixture writes");
        assert!(matches!(
            ProjectProgrammingCatalogs::load([&product], Some(&path)),
            Err(Error::CatalogLoad(ProgrammingCatalogLoadError::Policy(error)))
                if error.kind == CompileErrorKind::Unsupported && error.message.contains("schema 24")
        ));
    }

    #[test]
    fn package_documents_advance_one_shared_installation_catalog() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("knx_master.xml");
        std::fs::write(&path, xml(23, 198)).expect("installation catalog writes");

        // Older schemas and older tables keep the installation's catalog.
        let old = [packaged(14, 1658), packaged(23, 168), ProductData::default()];
        let catalogs = ProjectProgrammingCatalogs::load(&old, Some(&path)).expect("installation selects");
        let installed = catalog(23, 198);
        for product in &old {
            assert_eq!(catalogs.for_product(product).expect("installation").fingerprint(), installed.fingerprint());
        }

        // One newer table of the installation's schema serves every product.
        let mixed = [packaged(14, 1658), packaged(23, 199)];
        let catalogs = ProjectProgrammingCatalogs::load(&mixed, Some(&path)).expect("installation advances");
        let newer = catalog(23, 199);
        for product in &mixed {
            assert_eq!(catalogs.for_product(product).expect("advanced").fingerprint(), newer.fingerprint());
        }

        assert!(matches!(
            ProjectProgrammingCatalogs::load([&packaged(24, 1)], Some(&path)),
            Err(Error::CatalogLoad(ProgrammingCatalogLoadError::MasterData(MasterDataError::NewerPackageSchema {
                package: 24,
                installation: 23,
            })))
        ));
    }

    #[test]
    fn bound_catalogs_are_kept_and_never_read_an_installation_file() {
        let first = catalog(23, 1);
        let second = catalog(23, 2);
        let first_product = ProductData::default().bind_master_data(first.document()).expect("first binding");
        let second_product = ProductData::default().bind_master_data(second.document()).expect("second binding");
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing = directory.path().join("unused-master-data.xml");

        let catalogs = ProjectProgrammingCatalogs::load([&first_product, &second_product], Some(&missing))
            .expect("bound products need no installation");
        assert_eq!(catalogs.for_product(&first_product).expect("first document").fingerprint(), first.fingerprint());
        assert_eq!(catalogs.for_product(&second_product).expect("second document").fingerprint(), second.fingerprint());
        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn missing_catalog_is_typed_and_empty_loading_performs_no_io() {
        let product = ProductData::default().bind_schema_version(KnxSchemaVersion::V23).expect("schema binds");
        assert!(matches!(
            ProjectProgrammingCatalogs::default().for_product(&product),
            Err(Error::MissingCatalog { .. })
        ));
        let loaded = ProjectProgrammingCatalogs::load([], Some(Path::new("/missing/catalog.xml")))
            .expect("empty scope never reads the supplied file");
        assert!(matches!(loaded.for_product(&product), Err(Error::MissingCatalog { .. })));
    }
}
