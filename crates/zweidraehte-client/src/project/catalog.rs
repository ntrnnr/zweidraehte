//! Select each product's catalog before project compilation or bus access.

use std::collections::BTreeMap;
use std::path::Path;

use zweidraehte_ets_files::product::ProductData;

use crate::commissioning::{
    ProgrammingCatalog, ProgrammingCatalogLoadError, ProgrammingCatalogLoadRequest, ProgrammingCatalogSource,
};
use crate::project::error::{Error, Result};

/// Supplied Master Data for loose products; packaged products retain their own document.
///
/// Selection is complete before preparation starts. Looking up a product never
/// reads files or downloads Master Data.
#[derive(Clone)]
pub struct ProjectProgrammingCatalogs {
    selection: CatalogSelection,
}

impl Default for ProjectProgrammingCatalogs {
    fn default() -> Self {
        Self { selection: CatalogSelection::ProductSchemas(BTreeMap::new()) }
    }
}

#[derive(Clone)]
enum CatalogSelection {
    Fallback(ProgrammingCatalog),
    ProductSchemas(BTreeMap<u16, ProgrammingCatalog>),
}

impl std::fmt::Debug for ProjectProgrammingCatalogs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.selection {
            CatalogSelection::Fallback(catalog) => formatter
                .debug_struct("ProjectProgrammingCatalogs")
                .field("fallback_fingerprint", &catalog.fingerprint())
                .finish(),
            CatalogSelection::ProductSchemas(catalogs) => formatter
                .debug_struct("ProjectProgrammingCatalogs")
                .field("product_schemas", &catalogs.keys().collect::<Vec<_>>())
                .finish(),
        }
    }
}

impl ProjectProgrammingCatalogs {
    /// Supply a document for products which have no associated Master Data.
    pub fn with_fallback(catalog: ProgrammingCatalog) -> Self {
        Self { selection: CatalogSelection::Fallback(catalog) }
    }

    /// Retrieve the catalog selected for this product, without performing I/O.
    pub fn for_product(&self, product: &ProductData) -> Result<ProgrammingCatalog> {
        if product.master_data().is_some() {
            return ProgrammingCatalog::for_product(product).map_err(Error::Catalog);
        }

        match &self.selection {
            CatalogSelection::Fallback(catalog) => Ok(catalog.clone()),
            CatalogSelection::ProductSchemas(catalogs) => {
                let version = product
                    .schema_provenance()
                    .schema_version()
                    .ok_or_else(|| Error::MissingCatalog { product: product.id().into(), schema: None })?;

                catalogs
                    .get(&version)
                    .cloned()
                    .ok_or_else(|| Error::MissingCatalog { product: product.id().into(), schema: Some(version) })
            }
        }
    }
}

/// Load missing associations from the cache/server, or an explicitly supplied file.
impl ProjectProgrammingCatalogs {
    /// Explicit acquisition for the same loaded inputs supplied to a planner.
    pub fn load_for(
        products: &BTreeMap<zweidraehte_project::ProjectDeviceId, super::ProjectProduct>,
        explicit_file: Option<&Path>,
    ) -> Result<Self> {
        Self::load(products.values().map(|product| product.product()), explicit_file)
    }

    pub fn load<'a>(
        products: impl IntoIterator<Item = &'a ProductData>,
        explicit_file: Option<&Path>,
    ) -> Result<ProjectProgrammingCatalogs> {
        let products: Vec<_> = products.into_iter().collect();
        if products.is_empty() {
            return Ok(Self::default());
        }

        if products.iter().all(|product| product.master_data().is_some()) {
            return Ok(ProjectProgrammingCatalogs { selection: CatalogSelection::ProductSchemas(BTreeMap::new()) });
        }

        // An explicit source fills a missing association. It cannot replace a
        // package document, even when both documents use the same schema version.
        if let Some(path) = explicit_file {
            let loaded = ProgrammingCatalog::load(ProgrammingCatalogLoadRequest::File(path))?;
            return Ok(ProjectProgrammingCatalogs::with_fallback(loaded.into_catalog()));
        }

        // Group using the loader's provenance rules so missing schema evidence
        // has the same typed cause here and when loading a catalog directly.
        let mut products_by_schema = BTreeMap::new();
        for product in products.into_iter().filter(|product| product.master_data().is_none()) {
            let source =
                ProgrammingCatalogLoadRequest::Product(product).source().map_err(ProgrammingCatalogLoadError::from)?;
            let ProgrammingCatalogSource::VersionedResolver(version) = source else {
                unreachable!("unassociated products resolve their schema generation");
            };
            products_by_schema.entry(version).or_insert(product);
        }

        let mut catalogs = BTreeMap::new();
        for (version, product) in products_by_schema {
            let loaded = ProgrammingCatalog::load(ProgrammingCatalogLoadRequest::Product(product))?;
            catalogs.insert(version, loaded.into_catalog());
        }

        Ok(ProjectProgrammingCatalogs { selection: CatalogSelection::ProductSchemas(catalogs) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::CompileErrorKind;
    use std::error::Error as _;
    use zweidraehte_ets_files::MasterDataError;
    use zweidraehte_ets_files::schema::KnxSchemaVersion;

    fn catalog(version: u16) -> ProgrammingCatalog {
        ProgrammingCatalog::from_xml(&format!(
            r#"<KNX xmlns="http://knx.org/xml/project/{version}"><MasterData Version="1" /></KNX>"#
        ))
        .expect("catalog fixture")
    }

    #[test]
    fn project_catalog_loading_preserves_file_xml_and_policy_failures() {
        assert!(matches!(
            ProjectProgrammingCatalogs::load([&ProductData::default()], None),
            Err(Error::CatalogLoad(ProgrammingCatalogLoadError::MasterData(MasterDataError::MissingProductSchema {
                namespace: None,
                ..
            })))
        ));
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

        // An explicit invalid file must fail in place, never fall back to the
        // product's supported schema or a downloaded/cached document.
        std::fs::write(&path, "<KNX><MasterData").expect("malformed fixture writes");
        assert!(matches!(
            ProjectProgrammingCatalogs::load([&product], Some(&path)),
            Err(Error::CatalogLoad(ProgrammingCatalogLoadError::MasterData(MasterDataError::Xml(_))))
        ));

        std::fs::write(&path, r#"<KNX xmlns="http://knx.org/xml/project/24"><MasterData Version="1" /></KNX>"#)
            .expect("unsupported fixture writes");
        assert!(matches!(
            ProjectProgrammingCatalogs::load([&product], Some(&path)),
            Err(Error::CatalogLoad(ProgrammingCatalogLoadError::Policy(error)))
                if error.kind == CompileErrorKind::Unsupported && error.message.contains("schema 24")
        ));
    }

    #[test]
    fn associated_revisions_are_distinct_and_never_replaced_by_a_fallback() {
        let first = catalog(23);
        let second = ProgrammingCatalog::from_xml(
            r#"<KNX xmlns="http://knx.org/xml/project/23"><MasterData Version="2" /></KNX>"#,
        )
        .expect("second revision");
        let first_product = ProductData::default().bind_master_data(first.document()).expect("first binding");
        let second_product = ProductData::default().bind_master_data(second.document()).expect("second binding");
        let catalogs = ProjectProgrammingCatalogs::with_fallback(catalog(20));

        assert_eq!(catalogs.for_product(&first_product).expect("first document").fingerprint(), first.fingerprint());
        assert_eq!(catalogs.for_product(&second_product).expect("second document").fingerprint(), second.fingerprint());
        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn complete_package_associations_do_not_read_a_fallback_file() {
        let expected = catalog(23);
        let product = ProductData::default().bind_master_data(expected.document()).expect("package binding");
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing = directory.path().join("unused-master-data.xml");

        let catalogs = ProjectProgrammingCatalogs::load([&product], Some(&missing))
            .expect("the package is complete without a fallback");
        assert_eq!(catalogs.for_product(&product).expect("package document").fingerprint(), expected.fingerprint());
    }

    #[test]
    fn mixed_products_keep_distinct_catalogs_and_missing_generations_fail() {
        let old_product = ProductData::default().bind_schema_version(KnxSchemaVersion::V20).expect("schema binds");
        let new_product = ProductData::default().bind_schema_version(KnxSchemaVersion::V23).expect("schema binds");
        let unexpected = ProductData::default().bind_schema_version(KnxSchemaVersion::V21).expect("schema binds");
        let old_catalog = catalog(20);
        let new_catalog = catalog(23);
        let catalogs = ProjectProgrammingCatalogs {
            selection: CatalogSelection::ProductSchemas(BTreeMap::from([
                (20, old_catalog.clone()),
                (23, new_catalog.clone()),
            ])),
        };

        assert_eq!(catalogs.for_product(&old_product).expect("old catalog").fingerprint(), old_catalog.fingerprint());
        assert_eq!(catalogs.for_product(&new_product).expect("new catalog").fingerprint(), new_catalog.fingerprint());
        assert!(catalogs.for_product(&unexpected).is_err());
    }

    #[test]
    fn explicit_catalog_supplies_loose_products_across_generations() {
        let selected = catalog(23);
        let catalogs = ProjectProgrammingCatalogs::with_fallback(selected.clone());
        let product = ProductData::default().bind_schema_version(KnxSchemaVersion::V20).expect("schema binds");

        assert_eq!(catalogs.for_product(&product).expect("override selected").fingerprint(), selected.fingerprint());
    }

    #[test]
    fn missing_catalog_is_typed_and_empty_loading_performs_no_io() {
        let product = ProductData::default().bind_schema_version(KnxSchemaVersion::V23).expect("schema binds");
        assert!(matches!(
            ProjectProgrammingCatalogs::default().for_product(&product),
            Err(Error::MissingCatalog { schema: Some(23), .. })
        ));
        let loaded = ProjectProgrammingCatalogs::load([], Some(Path::new("/missing/catalog.xml")))
            .expect("empty scope never reads the supplied file");
        assert!(matches!(loaded.for_product(&product), Err(Error::MissingCatalog { .. })));
    }
}
