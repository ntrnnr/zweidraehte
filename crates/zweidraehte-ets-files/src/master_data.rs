//! Master Data acquisition shared by packaging, inspection and commissioning.
//!
//! This is also the single place which selects the catalog a product compiles
//! against: [`MasterDataInstallation`] applies the installation rule, and
//! [`MasterDataLoadRequest::Product`] composes it for one product. Explicit
//! files and supplied XML work without optional features; versioned
//! cache/download access, including a `Product` request's default
//! installation catalog, needs `master-data-download`. Consumers decide which
//! schema generations they can interpret; this module verifies that a
//! requested generation matches the document's own namespace.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::product::ProductData;
use crate::schema::KnxSchemaVersion;
use crate::{MasterData, MasterDataError};

/// Owned source retained by package builders until they write the archive.
#[derive(Debug, Clone)]
pub enum MasterDataSource {
    /// Resolve the packaging default schema (V20), using the versioned cache.
    Download,
    /// Resolve the specified packaging schema, using the versioned cache.
    DownloadVersion(KnxSchemaVersion),
    /// Embed the exact contents of this file.
    File(PathBuf),
    /// Embed supplied XML without interpreting or rewriting it.
    Content(String),
}

/// Borrowed request for a parsed, self-identifying Master Data document.
///
/// Unlike a package builder's `Download` default, explicit sources never guess
/// a generation. A product compiles against its installation's catalog, not
/// the document its package was built with; see [`MasterDataInstallation`].
///
/// ```no_run
/// use std::path::Path;
/// use zweidraehte_ets_files::master_data::MasterDataLoadRequest;
///
/// let document = MasterDataLoadRequest::File(Path::new("knx_master.xml")).load()?;
/// println!("Master Data publication {}", document.document_version());
/// # Ok::<(), zweidraehte_ets_files::MasterDataError>(())
/// ```
#[derive(Debug, Clone, Copy)]
pub enum MasterDataLoadRequest<'a> {
    /// Reuse the product's bound catalog, or select it from an installation of
    /// the newest generation, resolved through the shared cache/download.
    Product(&'a ProductData),
    /// As `Product`, with this file as the installation's own catalog.
    InstalledProduct { product: &'a ProductData, installation: &'a Path },
    /// Resolve exactly this project-schema generation, including legacy schemas.
    Version(u16),
    /// Read an explicit file which identifies its own schema.
    File(&'a Path),
    /// Parse supplied XML which identifies its own schema.
    Xml(&'a str),
}

/// Source identity, available before loading so callers can apply their policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MasterDataOrigin {
    /// Catalog already bound to the product for compilation.
    ProductDocument,
    /// Explicitly selected file; its name does not imply a generation.
    ExplicitFile(PathBuf),
    /// Caller-supplied XML bytes.
    SuppliedXml,
    /// Exact generation selected for the shared cache/download resolver.
    VersionedResolver(u16),
    /// An installation catalog loaded from this baseline, which the product's
    /// package document may have advanced.
    Installation(Box<MasterDataOrigin>),
}

impl<'a> MasterDataLoadRequest<'a> {
    /// Select `product`'s catalog, from an explicit installation catalog file
    /// when one is supplied.
    pub fn for_product(product: &'a ProductData, installation: Option<&'a Path>) -> Self {
        match installation {
            Some(installation) => Self::InstalledProduct { product, installation },
            None => Self::Product(product),
        }
    }

    /// Select a source without file or network I/O.
    pub fn source(self) -> Result<MasterDataOrigin, MasterDataError> {
        match self {
            Self::File(path) => Ok(MasterDataOrigin::ExplicitFile(path.to_owned())),
            Self::Xml(_) => Ok(MasterDataOrigin::SuppliedXml),
            Self::Version(version) => Ok(MasterDataOrigin::VersionedResolver(version)),
            Self::Product(product) | Self::InstalledProduct { product, .. } if product.master_data().is_some() => {
                Ok(MasterDataOrigin::ProductDocument)
            }
            Self::Product(_) => Ok(MasterDataOrigin::Installation(Box::new(installation_origin(None)))),
            Self::InstalledProduct { installation, .. } => {
                Ok(MasterDataOrigin::Installation(Box::new(installation_origin(Some(installation)))))
            }
        }
    }

    /// Load and parse one exact document, retaining an existing product `Arc`.
    ///
    /// Fails on I/O, malformed XML, a missing document namespace, a versioned
    /// resolver returning another generation, or a package document which the
    /// installation cannot accept. Explicit sources never fall back.
    pub fn load(self) -> Result<Arc<MasterData>, MasterDataError> {
        let source = self.source()?;
        match (self, &source) {
            (Self::Product(product) | Self::InstalledProduct { product, .. }, MasterDataOrigin::ProductDocument) => {
                Ok(Arc::clone(product.master_data().expect("bound source selected")))
            }
            (
                Self::Product(product) | Self::InstalledProduct { product, .. },
                MasterDataOrigin::Installation(baseline),
            ) => {
                let mut installation = MasterDataInstallation::new(load_origin(baseline, None)?)?;
                installation.offer_product(product)?;
                Ok(Arc::clone(installation.document()))
            }
            (Self::Xml(xml), _) => load_origin(&source, Some(xml)),
            _ => load_origin(&source, None),
        }
    }
}

/// An installation's own catalog: an explicit file, or the newest generation.
fn installation_origin(catalog: Option<&Path>) -> MasterDataOrigin {
    match catalog {
        Some(path) => MasterDataOrigin::ExplicitFile(path.to_owned()),
        None => MasterDataOrigin::VersionedResolver(KnxSchemaVersion::LATEST.as_u16()),
    }
}

/// Load a single-document source; installation selection composes these.
fn load_origin(source: &MasterDataOrigin, xml: Option<&str>) -> Result<Arc<MasterData>, MasterDataError> {
    let document = match (source, xml) {
        (MasterDataOrigin::SuppliedXml, Some(xml)) => Arc::new(xml.parse()?),
        (MasterDataOrigin::ExplicitFile(path), _) => Arc::new(MasterData::from_file(path)?),
        (MasterDataOrigin::VersionedResolver(version), _) => Arc::new(get_master_data_for_schema(*version)?.parse()?),
        _ => unreachable!("only single-document sources load directly"),
    };
    validate_document(&document, source)?;
    Ok(document)
}

fn validate_document(document: &MasterData, source: &MasterDataOrigin) -> Result<(), MasterDataError> {
    let actual = document
        .schema_version()
        .ok_or_else(|| MasterDataError::MissingSchema { namespace: document.namespace().map(str::to_owned) })?;
    if let MasterDataOrigin::VersionedResolver(expected) = source
        && actual != *expected
    {
        return Err(MasterDataError::SchemaMismatch { expected: *expected, actual });
    }
    Ok(())
}

// ================================================================================
// Installation catalog
// ================================================================================

/// One installation-wide catalog which product packages can only advance.
///
/// A package ships the Master Data it was built against, which is usually
/// older than the installation's. Installing the package offers that document
/// to the installation, which adopts it only when it is a strictly newer table
/// of the installation's own project schema. A package for an older schema is
/// converted on installation and its document replaced by the installation's
/// catalog, so it changes nothing; a package for a newer schema cannot be
/// installed at all.
///
/// The catalog depends only on the set of offered documents, never on their
/// order, because it advances only to a strictly higher table version.
#[derive(Debug, Clone)]
pub struct MasterDataInstallation {
    document: Arc<MasterData>,
    schema: u16,
    version: u64,
}

/// The effect of offering one package document to an installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterDataOffer {
    /// A newer table of the installation's schema replaced its catalog.
    Adopted,
    /// The package uses an older schema; conversion keeps the installed catalog.
    OlderSchema,
    /// The package document is not newer than the installed catalog.
    NotNewer,
    /// The product has no package document to offer.
    NoPackageDocument,
}

impl MasterDataInstallation {
    /// Start from the installation's own catalog, which fixes the project
    /// schema the installation implements.
    pub fn new(catalog: Arc<MasterData>) -> Result<Self, MasterDataError> {
        let (schema, version) = table_identity(&catalog)?;
        Ok(Self { document: catalog, schema, version })
    }

    /// Load the installation's own catalog from this file, or the newest
    /// generation through the shared cache/download when none is given.
    pub fn load(catalog: Option<&Path>) -> Result<Self, MasterDataError> {
        Self::new(load_origin(&installation_origin(catalog), None)?)
    }

    /// The catalog every product of this installation compiles against.
    pub fn document(&self) -> &Arc<MasterData> {
        &self.document
    }

    /// Offer a package's own document as installing that package would.
    ///
    /// Returns an error for a newer project schema, or for a document whose
    /// table version cannot be compared.
    pub fn offer(&mut self, package: &Arc<MasterData>) -> Result<MasterDataOffer, MasterDataError> {
        let (schema, version) = table_identity(package)?;

        if schema > self.schema {
            return Err(MasterDataError::NewerPackageSchema { package: schema, installation: self.schema });
        }
        if schema < self.schema {
            return Ok(MasterDataOffer::OlderSchema);
        }
        if version <= self.version {
            return Ok(MasterDataOffer::NotNewer);
        }

        self.document = Arc::clone(package);
        self.version = version;
        Ok(MasterDataOffer::Adopted)
    }

    /// Offer the document shipped with `product`'s package, if any.
    ///
    /// An application written for a newer project schema cannot be installed
    /// either, even when its package ships no Master Data.
    pub fn offer_product(&mut self, product: &ProductData) -> Result<MasterDataOffer, MasterDataError> {
        if let Some(schema) = product.schema_provenance().schema_version()
            && schema > self.schema
        {
            return Err(MasterDataError::NewerPackageSchema { package: schema, installation: self.schema });
        }

        match product.package_master_data() {
            Some(document) => self.offer(document),
            None => Ok(MasterDataOffer::NoPackageDocument),
        }
    }
}

/// The two values that order catalogs: a table version is numbered per schema.
fn table_identity(document: &MasterData) -> Result<(u16, u64), MasterDataError> {
    let schema = document
        .schema_version()
        .ok_or_else(|| MasterDataError::MissingSchema { namespace: document.namespace().map(str::to_owned) })?;
    let version = document
        .document_version()
        .parse()
        .map_err(|_| MasterDataError::InvalidTableVersion { version: document.document_version().to_owned() })?;
    Ok((schema, version))
}

pub(crate) fn read_xml(path: &Path) -> Result<String, MasterDataError> {
    fs::read_to_string(path).map_err(|source| MasterDataError::Io { path: path.to_owned(), source })
}

/// Get or download the KNX master data.
pub fn get_master_data(source: &MasterDataSource) -> Result<String, MasterDataError> {
    match source {
        MasterDataSource::Download => get_master_data_for_schema(KnxSchemaVersion::default().as_u16()),
        MasterDataSource::DownloadVersion(version) => get_master_data_for_schema(version.as_u16()),
        MasterDataSource::File(path) => read_xml(path),
        MasterDataSource::Content(content) => Ok(content.clone()),
    }
}

/// Resolve the exact project-schema generation through the shared versioned
/// cache, downloading it from KNX when absent. This also supports legacy
/// product generations which the package signer does not emit.
#[cfg(feature = "master-data-download")]
pub fn get_master_data_for_schema(version: u16) -> Result<String, MasterDataError> {
    download_and_cache_master_data(version)
}

/// Return an error when versioned retrieval is disabled at build time.
#[cfg(not(feature = "master-data-download"))]
pub fn get_master_data_for_schema(_version: u16) -> Result<String, MasterDataError> {
    Err(MasterDataError::DownloadDisabled)
}

pub(crate) fn master_data_url(version: u16) -> String {
    format!("https://update.knx.org/data/XML/project-{version}/knx_master.xml")
}

/// Download master data and cache it locally.
#[cfg(feature = "master-data-download")]
fn download_and_cache_master_data(version: u16) -> Result<String, MasterDataError> {
    resolve_cached_master_data(version, get_cache_dir().as_deref(), |url| {
        Ok(reqwest::blocking::get(url)?.error_for_status()?.text()?)
    })
}

/// Keep cache lookup and storage together so every caller uses the same
/// versioned name. A failed download must never become a cached document.
#[cfg(feature = "master-data-download")]
fn resolve_cached_master_data(
    version: u16,
    cache_dir: Option<&Path>,
    fetch: impl FnOnce(&str) -> Result<String, MasterDataError>,
) -> Result<String, MasterDataError> {
    // Cache filename includes version to support multiple versions
    let cache_filename = format!("knx_master_v{version}.xml");

    // Check cache first
    if let Some(cache_dir) = cache_dir {
        let cache_path = cache_dir.join(&cache_filename);
        if cache_path.exists()
            && let Ok(content) = fs::read_to_string(&cache_path)
        {
            log::info!("Using cached {} from {:?}", cache_filename, cache_path);
            return Ok(content);
        }
    }

    // Download
    let url = master_data_url(version);
    log::info!("Downloading knx_master.xml from {}", url);
    let content = fetch(&url)?;

    // Cache for future use
    if let Some(cache_dir) = cache_dir {
        let _ = fs::create_dir_all(cache_dir);
        let cache_path = cache_dir.join(&cache_filename);
        if let Err(e) = fs::write(&cache_path, &content) {
            log::warn!("Failed to cache {}: {}", cache_filename, e);
        } else {
            log::info!("Cached {} to {:?}", cache_filename, cache_path);
        }
    }

    Ok(content)
}

/// Get the cache directory for KNX data.
#[cfg(feature = "master-data-download")]
fn get_cache_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("org", "knx", "knxprod").map(|dirs| dirs.cache_dir().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/23"><MasterData Id="MD" Version="7"/></KNX>"#;

    #[test]
    fn file_and_inline_sources_preserve_the_same_document_for_packaging_and_parsing() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("explicit.xml");
        fs::write(&path, XML).expect("fixture writes");

        let parsed = MasterData::from_file(&path).expect("raw parser");
        for request in [MasterDataLoadRequest::File(&path), MasterDataLoadRequest::Xml(XML)] {
            let document = request.load().expect("explicit document loads offline");
            assert_eq!(document.source_xml(), parsed.source_xml());
            assert_eq!(document.schema_version(), Some(23));
            assert_eq!(document.document_id(), Some("MD"));
            assert_eq!(document.document_version(), "7");
        }
        assert_eq!(
            MasterDataLoadRequest::File(&path).source().expect("file source"),
            MasterDataOrigin::ExplicitFile(path.clone())
        );
        assert_eq!(get_master_data(&MasterDataSource::File(path)).expect("package content"), XML);

        let missing = directory.path().join("missing.xml");
        assert!(
            matches!(MasterDataLoadRequest::File(&missing).load(), Err(MasterDataError::Io { path, .. }) if path == missing)
        );
        assert!(matches!(MasterDataLoadRequest::Xml("<broken>").load(), Err(MasterDataError::Xml(_))));
    }

    fn document(schema: u16, version: u64) -> Arc<MasterData> {
        Arc::new(
            format!(r#"<KNX xmlns="http://knx.org/xml/project/{schema}"><MasterData Id="MD-{schema}-{version}" Version="{version}"/></KNX>"#)
                .parse()
                .expect("fixture document"),
        )
    }

    #[test]
    fn bound_catalog_keeps_its_arc_and_overrides_installation_selection() {
        let document = Arc::new(XML.parse::<MasterData>().expect("fixture document"));
        let product = ProductData::default()
            .bind_schema_version(KnxSchemaVersion::V20)
            .expect("product generation")
            .bind_master_data(Arc::clone(&document))
            .expect("associated document");
        let request = MasterDataLoadRequest::Product(&product);

        assert_eq!(request.source().expect("associated source"), MasterDataOrigin::ProductDocument);
        let loaded = request.load().expect("association needs no download");
        assert!(Arc::ptr_eq(&document, &loaded), "no reparsing or document copy");
        assert_eq!(loaded.schema_version(), Some(23));
    }

    #[test]
    fn installation_adopts_only_a_newer_table_of_its_own_schema() {
        let installed = document(23, 198);
        for (package, expected) in [
            // Table versions are numbered per schema: 1658 is not newer than 198.
            (document(14, 1658), MasterDataOffer::OlderSchema),
            (document(20, 447), MasterDataOffer::OlderSchema),
            (document(23, 168), MasterDataOffer::NotNewer),
            (document(23, 198), MasterDataOffer::NotNewer),
            (document(23, 199), MasterDataOffer::Adopted),
        ] {
            let mut installation = MasterDataInstallation::new(Arc::clone(&installed)).expect("installed catalog");
            assert_eq!(installation.offer(&package).expect("importable package"), expected);

            let selected = if expected == MasterDataOffer::Adopted { &package } else { &installed };
            assert!(Arc::ptr_eq(installation.document(), selected), "{}", package.document_version());
        }

        let mut installation = MasterDataInstallation::new(installed).expect("installed catalog");
        assert!(matches!(
            installation.offer(&document(24, 1)),
            Err(MasterDataError::NewerPackageSchema { package: 24, installation: 23 })
        ));
        let unversioned = Arc::new(
            r#"<KNX xmlns="http://knx.org/xml/project/23"><MasterData Version="draft"/></KNX>"#
                .parse::<MasterData>()
                .expect("fixture document"),
        );
        assert!(matches!(installation.offer(&unversioned), Err(MasterDataError::InvalidTableVersion { .. })));
    }

    #[test]
    fn installation_outcome_is_independent_of_offer_order() {
        let packages = [document(23, 201), document(20, 900), document(23, 199), document(23, 200)];
        for order in [[0, 1, 2, 3], [3, 2, 1, 0], [2, 0, 3, 1]] {
            let mut installation = MasterDataInstallation::new(document(23, 198)).expect("installed catalog");
            for index in order {
                installation.offer(&packages[index]).expect("importable package");
            }
            assert_eq!(installation.document().document_version(), "201");
        }
    }

    #[test]
    fn product_requests_offer_the_package_document_to_the_installation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("installed.xml");
        fs::write(&path, document(23, 198).source_xml()).expect("installation catalog writes");

        let unpackaged = ProductData::default();
        let old = ProductData::default().with_package_master_data(document(14, 1658));
        let newer = ProductData::default().with_package_master_data(document(23, 199));
        for (product, expected) in [(&unpackaged, "198"), (&old, "198"), (&newer, "199")] {
            let request = MasterDataLoadRequest::InstalledProduct { product, installation: &path };
            assert_eq!(
                request.source().expect("installation source"),
                MasterDataOrigin::Installation(Box::new(MasterDataOrigin::ExplicitFile(path.clone())))
            );
            assert_eq!(request.load().expect("installation selection").document_version(), expected);
        }

        assert_eq!(
            MasterDataLoadRequest::Product(&unpackaged).source().expect("default installation"),
            MasterDataOrigin::Installation(Box::new(MasterDataOrigin::VersionedResolver(23)))
        );
        let future = ProductData::default().with_package_master_data(document(24, 1));
        assert!(matches!(
            MasterDataLoadRequest::InstalledProduct { product: &future, installation: &path }.load(),
            Err(MasterDataError::NewerPackageSchema { .. })
        ));
        let mut installation = MasterDataInstallation::new(document(20, 447)).expect("older installation");
        let application = ProductData::default().bind_schema_version(KnxSchemaVersion::V23).expect("schema binds");
        assert!(matches!(
            installation.offer_product(&application),
            Err(MasterDataError::NewerPackageSchema { package: 23, installation: 20 })
        ));
    }

    #[test]
    fn inspection_parses_generations_which_installations_may_not_accept() {
        // Inspection may parse generations that live commissioning cannot use.
        let future = XML.replace("/project/23", "/project/24");
        assert_eq!(
            MasterDataLoadRequest::Xml(&future).load().expect("self-identifying document").schema_version(),
            Some(24)
        );
        let missing_namespace = XML.replace(r#" xmlns="http://knx.org/xml/project/23""#, "");
        assert!(matches!(
            MasterDataLoadRequest::Xml(&missing_namespace).load(),
            Err(MasterDataError::MissingSchema { namespace: None })
        ));
    }

    #[test]
    fn versioned_resolution_must_match_the_document_namespace() {
        let document = XML.parse::<MasterData>().expect("fixture document");
        validate_document(&document, &MasterDataOrigin::VersionedResolver(23)).expect("matching generation");
        assert!(matches!(
            validate_document(&document, &MasterDataOrigin::VersionedResolver(11)),
            Err(MasterDataError::SchemaMismatch { expected: 11, actual: 23 })
        ));
        validate_document(&document, &MasterDataOrigin::ExplicitFile("project-11.xml".into()))
            .expect("file names are not provenance");
    }

    #[cfg(not(feature = "master-data-download"))]
    #[test]
    fn versioned_loading_reports_disabled_downloads_without_trying_other_sources() {
        assert!(matches!(MasterDataLoadRequest::Version(23).load(), Err(MasterDataError::DownloadDisabled)));
    }

    #[cfg(feature = "master-data-download")]
    #[test]
    fn absent_generation_is_fetched_once_and_reused_from_its_versioned_cache() {
        let directory = tempfile::tempdir().expect("temporary cache");
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/11"/>"#;

        let downloaded = resolve_cached_master_data(11, Some(directory.path()), |url| {
            assert_eq!(url, "https://update.knx.org/data/XML/project-11/knx_master.xml");
            Ok(xml.to_owned())
        })
        .expect("missing catalog downloads");

        assert_eq!(downloaded, xml);
        assert_eq!(fs::read_to_string(directory.path().join("knx_master_v11.xml")).expect("cached XML"), xml);

        let cached = resolve_cached_master_data(11, Some(directory.path()), |_| {
            panic!("a cached generation must not be downloaded again")
        })
        .expect("cached catalog loads");

        assert_eq!(cached, xml);
    }

    #[cfg(feature = "master-data-download")]
    #[test]
    fn failed_fetch_does_not_cache_an_error_or_use_another_generation() {
        let directory = tempfile::tempdir().expect("temporary cache");
        fs::write(directory.path().join("knx_master_v23.xml"), "other generation").expect("other catalog");

        let result = resolve_cached_master_data(11, Some(directory.path()), |_| {
            Err(MasterDataError::Io {
                path: directory.path().join("unavailable-download.xml"),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing generation"),
            })
        });

        assert!(result.is_err());
        assert!(!directory.path().join("knx_master_v11.xml").exists());
    }

    /// The cache directory is platform-dependent and may legitimately
    /// be unavailable (no HOME); the contract is only that resolving
    /// it never panics.
    #[cfg(feature = "master-data-download")]
    #[test]
    fn cache_dir_resolves_without_panicking() {
        let _ = get_cache_dir();
    }

    /// `File` and `Content` resolve without touching the network.
    #[test]
    fn local_sources_resolve_offline() {
        let content = get_master_data(&MasterDataSource::Content("<KNX/>".to_string())).expect("inline content");
        assert_eq!(content, "<KNX/>");

        let missing = get_master_data(&MasterDataSource::File("/nonexistent/knx_master.xml".into()));
        assert!(missing.is_err(), "a missing file is an error, not a silent download");
    }
}
