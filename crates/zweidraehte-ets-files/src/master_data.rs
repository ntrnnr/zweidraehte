//! Master Data acquisition shared by packaging, inspection and commissioning.
//!
//! Local sources and product-owned documents work without optional features.
//! Only versioned cache/download access needs `master-data-download`. Consumers
//! decide which schema generations they can interpret; this module verifies
//! that a requested generation matches the document's own namespace.

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
/// Unlike a package builder's `Download` default, product loading never guesses
/// a generation. An associated document is authoritative even when the product
/// uses another schema; loose products must declare their own generation.
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
    /// Reuse the associated document, or resolve the loose product's generation.
    Product(&'a ProductData),
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
    /// Document already bound to a product, usually by its archive.
    ProductDocument,
    /// Explicitly selected file; its name does not imply a generation.
    ExplicitFile(PathBuf),
    /// Caller-supplied XML bytes.
    SuppliedXml,
    /// Exact generation selected for the shared cache/download resolver.
    VersionedResolver(u16),
}

impl MasterDataLoadRequest<'_> {
    /// Select a source without file or network I/O.
    ///
    /// Returns an error if a loose product has no unambiguous schema namespace.
    pub fn source(self) -> Result<MasterDataOrigin, MasterDataError> {
        match self {
            Self::File(path) => Ok(MasterDataOrigin::ExplicitFile(path.to_owned())),
            Self::Xml(_) => Ok(MasterDataOrigin::SuppliedXml),
            Self::Version(version) => Ok(MasterDataOrigin::VersionedResolver(version)),
            Self::Product(product) => {
                if product.master_data().is_some() {
                    return Ok(MasterDataOrigin::ProductDocument);
                }
                let provenance = product.schema_provenance();
                let version = provenance.schema_version().ok_or_else(|| MasterDataError::MissingProductSchema {
                    product: product.id().to_owned(),
                    namespace: provenance.namespace().map(str::to_owned),
                })?;
                Ok(MasterDataOrigin::VersionedResolver(version))
            }
        }
    }

    /// Load and parse one exact document, retaining an existing product `Arc`.
    ///
    /// Fails on I/O, malformed XML, a missing document namespace, or a versioned
    /// resolver returning another generation. Explicit sources never fall back.
    pub fn load(self) -> Result<Arc<MasterData>, MasterDataError> {
        let source = self.source()?;
        let document = match (self, &source) {
            (Self::Product(product), MasterDataOrigin::ProductDocument) => {
                Arc::clone(product.master_data().expect("associated source selected"))
            }
            (Self::Xml(xml), _) => Arc::new(xml.parse()?),
            (_, MasterDataOrigin::ExplicitFile(path)) => Arc::new(MasterData::from_file(path)?),
            (_, MasterDataOrigin::VersionedResolver(version)) => {
                Arc::new(get_master_data_for_schema(*version)?.parse()?)
            }
            _ => unreachable!("source belongs to the request"),
        };
        validate_document(&document, &source)?;
        Ok(document)
    }
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

    #[test]
    fn associated_document_keeps_its_arc_and_overrides_the_products_generation() {
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
    fn source_selection_requires_provenance_without_imposing_a_consumers_schema_limit() {
        assert!(matches!(
            MasterDataLoadRequest::Product(&ProductData::default()).source(),
            Err(MasterDataError::MissingProductSchema { .. })
        ));
        let product = ProductData::default().bind_schema_version(KnxSchemaVersion::V21).expect("product generation");
        assert_eq!(
            MasterDataLoadRequest::Product(&product).source().expect("declared generation"),
            MasterDataOrigin::VersionedResolver(21)
        );

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
