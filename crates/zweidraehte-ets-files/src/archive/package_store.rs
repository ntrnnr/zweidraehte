//! Shared `.knxprod` indexing, selected-product reading, and project-local storage.
//!
//! A package is addressed by the SHA-256 of its original ZIP bytes. The
//! compressed source is retained so any catalogue leaf can be instantiated
//! later, while a small versioned index carries the catalogue presentation and
//! exact application-program ZIP paths. Normal opening therefore never
//! inflates unrelated application programs, plug-ins, or baggage.
//! [`PackageArchive`] uses that same index without importing the source;
//! resource extraction and persistent store publication are explicit operations.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use super::knxprod::application_program_id;
use super::product_loader::resolve_document_application_pairing;
use super::{
    ApplicationProgramRelation, ArchiveError, KnxprodArchive, KnxprodDevice, SelectedProduct, master_data_path,
};
use crate::product::ProductError;
use crate::runtime::parser::{ParseError, parse_application_program};
use crate::schema::schema_version_from_namespace;
use crate::schema::{
    ApplicationProgram, BaggagesKnx, CatalogItem, CatalogKnx, CatalogSection, HardwareKnx, Knx, ParameterTypeDef,
};
use crate::schema::{HardwareApplicationProgram2, HardwareApplicationProgramPairing};
#[cfg(feature = "signing")]
use crate::signing::{verify_directory_signature, verify_hardware_xml};

const SOURCE_ARCHIVE: &str = "source.knxprod";
const CONTENT_DIRECTORY: &str = "content";
const MATERIALIZED_DIRECTORY: &str = "materialized";
// Materialized resources are a disposable derived cache. Include the extractor
// format in its path so adding a newly understood reference source cannot make
// an older, incomplete directory look complete forever.
const MATERIALIZED_BAGGAGE_VERSION: u32 = 2;
const PACKAGE_INDEX: &str = "index.json";
const PACKAGE_INDEX_VERSION: u32 = 3;
const DIGEST_TEXT_PREFIX: &str = "sha256:";
const DIGEST_DIRECTORY_PREFIX: &str = "sha256-";
const SHA256_BYTES: usize = 32;

// Product databases routinely carry large plug-ins and baggages.  These caps
// are intentionally far above ordinary packages while still preventing an
// untrusted ZIP from allocating an unbounded amount before path validation.
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_ENTRY_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_COMPRESSION_RATIO: u64 = 1_000;
const COMPRESSION_RATIO_FLOOR_BYTES: u64 = 1024 * 1024;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// SHA-256 identity of the exact imported `.knxprod` bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageDigest([u8; SHA256_BYTES]);

impl PackageDigest {
    pub const fn from_bytes(bytes: [u8; SHA256_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn of(bytes: &[u8]) -> Self {
        let mut digest = [0; SHA256_BYTES];
        digest.copy_from_slice(&Sha256::digest(bytes));
        Self(digest)
    }

    pub const fn as_bytes(&self) -> &[u8; SHA256_BYTES] {
        &self.0
    }

    pub fn directory_name(self) -> String {
        format!("{DIGEST_DIRECTORY_PREFIX}{}", encode_hex(&self.0))
    }
}

impl fmt::Debug for PackageDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for PackageDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{DIGEST_TEXT_PREFIX}{}", encode_hex(&self.0))
    }
}

impl Serialize for PackageDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PackageDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?.parse().map_err(serde::de::Error::custom)
    }
}

impl FromStr for PackageDigest {
    type Err = PackageDigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hexadecimal = value
            .strip_prefix(DIGEST_TEXT_PREFIX)
            .or_else(|| value.strip_prefix(DIGEST_DIRECTORY_PREFIX))
            .ok_or_else(|| PackageDigestError(value.to_owned()))?;
        if hexadecimal.len() != SHA256_BYTES * 2
            || !hexadecimal.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(PackageDigestError(value.to_owned()));
        }

        let mut digest = [0; SHA256_BYTES];
        for (index, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hexadecimal[index * 2..index * 2 + 2], 16)
                .map_err(|_| PackageDigestError(value.to_owned()))?;
        }
        Ok(Self(digest))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid package digest {0:?}; expected canonical sha256:<64 lowercase hexadecimal digits>")]
pub struct PackageDigestError(String);

/// Exact durable selector authored into a project device.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageCatalogSelector {
    pub package: PackageDigest,
    pub catalog_item_id: String,
}

/// Registration status written in the exact `Hardware.xml` relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PackageRegistrationStatus {
    /// No `RegistrationInfo` element exists for this exact parent.
    Unsigned,
    Unregistered,
    Registered,
    Certified,
    FutureUseNotRecommended,
    FutureUseNotAllowed,
}

impl PackageRegistrationStatus {
    pub const fn is_instantiable(self) -> bool {
        !matches!(self, Self::FutureUseNotRecommended | Self::FutureUseNotAllowed)
    }
}

impl fmt::Display for PackageRegistrationStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unsigned => "Unsigned",
            Self::Unregistered => "Unregistered",
            Self::Registered => "Registered",
            Self::Certified => "Certified",
            Self::FutureUseNotRecommended => "FutureUseNotRecommended",
            Self::FutureUseNotAllowed => "FutureUseNotAllowed",
        })
    }
}

/// Registration metadata declared by one exact Product or H2P parent.
///
/// Signature details are intentionally absent. Import checks signatures once
/// and reports mismatches as notices; the catalogue needs only the product's
/// declared registration state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRegistration {
    pub status: PackageRegistrationStatus,
    pub registration_number: Option<String>,
    pub registration_date: Option<String>,
}

impl PackageRegistration {
    fn unsigned() -> Self {
        Self { status: PackageRegistrationStatus::Unsigned, registration_number: None, registration_date: None }
    }
}

/// Ordered application-program references selected by one exact H2P relation.
///
/// `None` is not an invalid or incomplete relation. It represents an H2P
/// relation with no application reference and therefore belongs in the
/// catalogue even though ETS cannot download an application through that
/// relation. `Hardware/@HasApplicationProgram` describes capability, so it may
/// still be `true` for such a leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageProgramBinding {
    None,
    Application { primary: String, secondary: Option<String> },
}

impl PackageProgramBinding {
    pub fn primary(&self) -> Option<&str> {
        match self {
            Self::None => None,
            Self::Application { primary, .. } => Some(primary),
        }
    }

    pub fn secondary(&self) -> Option<&str> {
        match self {
            Self::None | Self::Application { secondary: None, .. } => None,
            Self::Application { secondary: Some(secondary), .. } => Some(secondary),
        }
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        [self.primary(), self.secondary()].into_iter().flatten()
    }
}

/// Why a valid catalogue leaf has no application which this project model can
/// instantiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageCatalogOnlyReason {
    NoApplicationProgram,
}

/// Why a leaf with an application is retained but cannot be instantiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageInstantiationBlock {
    RegistrationStatus(PackageRegistrationStatus),
}

/// Typed selection status derived from application presence and the declared
/// registration state. Import-time signature notices deliberately do not
/// become catalogue state or an instantiation gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageInstantiation {
    Programmable,
    CatalogOnly(PackageCatalogOnlyReason),
    Blocked(PackageInstantiationBlock),
}

/// One exact, instantiable (or explicitly blocked) catalogue leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageCatalogLeaf {
    pub selector: PackageCatalogSelector,
    pub manufacturer_id: String,
    pub product_id: String,
    pub hardware_id: String,
    pub hardware2program_id: String,
    pub programs: PackageProgramBinding,
    pub name: String,
    pub order_number: String,
    /// `CatalogItem/@Number`, used to retain catalogue presentation order.
    pub catalog_number: String,
    pub medium_types: String,
    /// AP1 metadata. Catalogue-only hardware has no mask version.
    pub mask_version: Option<String>,
    /// AP1 metadata. `None` means the leaf has no application, not that Data
    /// Secure is unsupported.
    pub supports_data_secure: Option<bool>,
    pub product_registration: PackageRegistration,
    pub hardware2program_registration: PackageRegistration,
    pub effective_registration: PackageRegistration,
    pub instantiation: PackageInstantiation,
    /// `false` for FutureUse* declarations and catalogue-only hardware.
    /// Prefer `instantiation` when presenting the exact reason.
    pub instantiable: bool,
    /// `Hardware/@HasIndividualAddress`. Indexes written before this field
    /// existed lack it; they read as addressable, the attribute's usual value.
    #[serde(default = "addressable")]
    pub has_individual_address: bool,
    /// Digest of the source-package identity, exact Catalog/Hardware documents,
    /// and selected IDs. Application bodies stay covered transitively by the
    /// source package digest without being inflated while indexing.
    pub chain_digest: PackageDigest,
}

impl PackageCatalogLeaf {
    pub fn application_program_id(&self) -> Option<&str> {
        self.programs.primary()
    }

    pub fn application_program_2_id(&self) -> Option<&str> {
        self.programs.secondary()
    }

    pub fn application_program_ids(&self) -> impl Iterator<Item = &str> {
        self.programs.ids()
    }
}

/// A virtual catalogue section.  Equal metadata from several packages is
/// merged for presentation; conflicting revisions remain separate branches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageCatalogSection {
    pub id: String,
    pub name: String,
    pub number: String,
    pub default_language: String,
    pub packages: Vec<PackageDigest>,
    pub items: Vec<PackageCatalogLeaf>,
    pub subsections: Vec<PackageCatalogSection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageCatalogManufacturer {
    pub id: String,
    /// Display name from the newest Master Data carried by the imported
    /// package, when available.
    #[serde(default)]
    pub name: Option<String>,
    /// Project-schema namespace version of the Master Data source.
    #[serde(default)]
    pub name_source_schema_version: Option<u16>,
    /// Numeric `MasterData/@Version` of the name source.
    #[serde(default)]
    pub name_source_version: Option<u64>,
    pub sections: Vec<PackageCatalogSection>,
}

/// Read-only catalogue derived from all untouched packages in a store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageCatalogIndex {
    pub manufacturers: Vec<PackageCatalogManufacturer>,
}

impl PackageCatalogIndex {
    pub fn leaves(&self) -> impl Iterator<Item = &PackageCatalogLeaf> {
        self.manufacturers.iter().flat_map(|manufacturer| section_leaves(&manufacturer.sections))
    }

    pub fn leaf(&self, selector: &PackageCatalogSelector) -> Option<&PackageCatalogLeaf> {
        self.leaves().find(|leaf| &leaf.selector == selector)
    }
}

/// Persisted derived metadata. The source archive remains the authority for
/// application bytes; this file is deliberately unsigned and carries no
/// signature-verification state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedPackageIndex {
    version: u32,
    package: PackageDigest,
    catalog: Vec<PackageCatalogManufacturer>,
    application_programs: BTreeMap<String, String>,
}

/// Project-local package store rooted at `.zweidraehte/packages`.
#[derive(Debug, Clone)]
pub struct PackageStore {
    root: PathBuf,
}

impl PackageStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn package_directory(&self, digest: PackageDigest) -> PathBuf {
        self.root.join(digest.directory_name())
    }

    pub fn source_archive_path(&self, digest: PackageDigest) -> PathBuf {
        self.package_directory(digest).join(SOURCE_ARCHIVE)
    }

    #[cfg(feature = "signing")]
    pub fn import(&self, path: impl AsRef<Path>) -> Result<ImportedPackage, PackageStoreError> {
        let path = path.as_ref();
        let bytes =
            fs::read(path).map_err(|source| PackageStoreError::ReadArchive { path: path.to_owned(), source })?;
        self.import_bytes(&bytes)
    }

    #[cfg(feature = "signing")]
    pub fn import_bytes(&self, bytes: &[u8]) -> Result<ImportedPackage, PackageStoreError> {
        let digest = PackageDigest::of(bytes);
        ensure_store_root(&self.root)?;
        let destination = self.package_directory(digest);
        match fs::symlink_metadata(&destination) {
            Ok(metadata) => {
                require_plain_directory(&destination, &metadata)?;
                preflight_archive(bytes)?;
                let notices = inspect_package_signatures(bytes)?;
                let package = self.open(digest)?;
                return Ok(ImportedPackage { package, already_present: true, notices });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(PackageStoreError::ReadStore { path: destination.clone(), source }),
        }

        let index = build_package_index(bytes, digest)?;
        let notices = inspect_package_signatures(bytes)?;
        let temporary = self.create_temporary_directory(digest)?;
        let mut temporary_guard = TemporaryDirectoryGuard::new(temporary.clone());
        write_synced_file(&temporary.join(SOURCE_ARCHIVE), bytes)?;
        write_package_index(&temporary.join(PACKAGE_INDEX), &index)?;
        sync_directory(&temporary)?;

        match fs::rename(&temporary, &destination) {
            Ok(()) => temporary_guard.disarm(),
            Err(source) if fs::symlink_metadata(&destination).is_ok() => {
                // Another importer won the same content-addressed race. Its
                // persisted index and store-node types are checked below.
                drop(source);
            }
            Err(source) => {
                return Err(PackageStoreError::InstallPackage { path: destination, source });
            }
        }
        sync_directory(&self.root)?;

        let package = self.open(digest)?;
        debug_assert_eq!(
            package.catalog.iter().map(count_manufacturer_leaves).sum::<usize>(),
            index.catalog.iter().map(count_manufacturer_leaves).sum::<usize>()
        );
        Ok(ImportedPackage { package, already_present: false, notices })
    }

    pub fn open(&self, digest: PackageDigest) -> Result<StoredPackage, PackageStoreError> {
        let directory = self.package_directory(digest);
        let directory_metadata = fs::symlink_metadata(&directory)
            .map_err(|source| PackageStoreError::ReadStoredArchive { path: directory.clone(), source })?;
        require_plain_directory(&directory, &directory_metadata)?;
        let source_path = directory.join(SOURCE_ARCHIVE);
        let source_metadata = fs::symlink_metadata(&source_path)
            .map_err(|source| PackageStoreError::ReadStoredArchive { path: source_path.clone(), source })?;
        require_plain_file(&source_path, &source_metadata)?;
        let index_path = directory.join(PACKAGE_INDEX);
        let index = match fs::symlink_metadata(&index_path) {
            Ok(metadata) => {
                require_plain_file(&index_path, &metadata)?;
                read_package_index(&index_path, digest).map_err(|error| match error {
                    PackageStoreError::UnsupportedIndexVersion { actual, .. } if actual < PACKAGE_INDEX_VERSION => {
                        PackageStoreError::ReimportRequired {
                            path: directory.clone(),
                            reason: format!("package index version {actual} predates version {PACKAGE_INDEX_VERSION}"),
                        }
                    }
                    error => error,
                })?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(PackageStoreError::ReimportRequired {
                    path: directory,
                    reason: "package index is missing".to_owned(),
                });
            }
            Err(source) => return Err(PackageStoreError::ReadIndex { path: index_path, source }),
        };

        Ok(StoredPackage {
            digest,
            directory,
            catalog: index.catalog,
            application_programs: index.application_programs,
        })
    }

    pub fn packages(&self) -> Result<Vec<StoredPackage>, PackageStoreError> {
        self.package_digests()?.into_iter().map(|digest| self.open(digest)).collect()
    }

    pub fn catalog_index(&self) -> Result<PackageCatalogIndex, PackageStoreError> {
        let mut index = PackageCatalogIndex::default();
        for digest in self.package_digests()? {
            let package = self.open(digest)?;
            merge_package_catalog(&mut index, package.catalog);
        }
        index.manufacturers.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(index)
    }

    pub fn resolve_catalog_item(
        &self,
        selector: &PackageCatalogSelector,
    ) -> Result<PackageCatalogLeaf, PackageStoreError> {
        self.open(selector.package)?
            .catalog
            .into_iter()
            .flat_map(|manufacturer| owned_section_leaves(manufacturer.sections))
            .find(|leaf| leaf.selector == *selector)
            .ok_or_else(|| PackageStoreError::UnknownCatalogItem(selector.clone()))
    }

    #[cfg(feature = "signing")]
    fn create_temporary_directory(&self, digest: PackageDigest) -> Result<PathBuf, PackageStoreError> {
        loop {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = self.root.join(format!(".{}.tmp-{}-{sequence}", digest.directory_name(), std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(PackageStoreError::CreateTemporary { path, source }),
            }
        }
    }

    fn package_digests(&self) -> Result<Vec<PackageDigest>, PackageStoreError> {
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) => require_plain_directory(&self.root, &metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(PackageStoreError::ReadStore { path: self.root.clone(), source }),
        }
        let mut digests = Vec::new();
        for entry in fs::read_dir(&self.root)
            .map_err(|source| PackageStoreError::ReadStore { path: self.root.clone(), source })?
        {
            let entry = entry.map_err(|source| PackageStoreError::ReadStore { path: self.root.clone(), source })?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with(DIGEST_DIRECTORY_PREFIX) {
                let metadata = fs::symlink_metadata(entry.path())
                    .map_err(|source| PackageStoreError::ReadStore { path: entry.path(), source })?;
                require_plain_directory(&entry.path(), &metadata)?;
                digests.push(PackageDigest::from_str(name)?);
            }
        }
        digests.sort_unstable();
        Ok(digests)
    }
}

#[derive(Debug, Clone)]
pub struct StoredPackage {
    digest: PackageDigest,
    directory: PathBuf,
    catalog: Vec<PackageCatalogManufacturer>,
    application_programs: BTreeMap<String, String>,
}

impl StoredPackage {
    pub const fn digest(&self) -> PackageDigest {
        self.digest
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn source_archive_path(&self) -> PathBuf {
        self.directory.join(SOURCE_ARCHIVE)
    }

    pub fn content_root(&self) -> PathBuf {
        self.directory.join(CONTENT_DIRECTORY)
    }

    pub fn manufacturer_content_root(&self, leaf: &PackageCatalogLeaf) -> Option<PathBuf> {
        (leaf.selector.package == self.digest
            && !leaf.manufacturer_id.is_empty()
            && !leaf.manufacturer_id.chars().any(|character| matches!(character, '/' | '\\'))
            && leaf.manufacturer_id != "."
            && leaf.manufacturer_id != "..")
            .then(|| self.content_root().join(&leaf.manufacturer_id))
    }

    /// Re-open the exact source archive for consumers which need product XML.
    /// Catalogue-only listing deliberately does not retain archive payloads.
    pub fn open_archive(&self) -> Result<KnxprodArchive, ArchiveError> {
        KnxprodArchive::open(self.source_archive_path())
    }

    /// Read the package's exact Master Data without inflating unrelated members.
    pub fn master_data_xml(&self) -> Result<Option<String>, PackageStoreError> {
        read_master_data_xml(&mut self.open_source_zip()?)
    }

    /// Read exactly one indexed application-program member from the retained
    /// source ZIP. No other member is inflated.
    pub fn application_program_xml(&self, id: &str) -> Result<String, PackageStoreError> {
        let path = self
            .application_programs
            .get(id)
            .ok_or_else(|| PackageStoreError::UnknownApplicationProgram(id.to_owned()))?;
        let mut archive = self.open_source_zip()?;
        let bytes = read_zip_member(&mut archive, path)?;
        String::from_utf8(bytes)
            .map_err(|source| PackageStoreError::ApplicationUtf8 { path: path.clone(), source: source.utf8_error() })
    }

    /// Parse exactly one indexed application-program member.
    pub fn parse_application_program(&self, id: &str) -> Result<Knx, PackageStoreError> {
        read_application_document(&mut self.open_source_zip()?, &self.application_programs, id)
    }

    pub fn application_program_path(&self, id: &str) -> Option<&str> {
        self.application_programs.get(id).map(String::as_str)
    }

    /// Materialize only the baggage files referenced by a selected catalogue
    /// leaf. References include both application extensions and pictures used
    /// as parameter values. The original manifest is retained because
    /// reserializing it would discard schema vocabulary this reader does not
    /// model; callers must therefore request only entries referenced by this
    /// application.
    ///
    /// The returned path is the manufacturer root accepted by
    /// `BaggageIndex::from_directory`. `None` means the selected application
    /// has no baggage references.
    pub fn materialize_baggages(&self, leaf: &PackageCatalogLeaf) -> Result<Option<PathBuf>, PackageStoreError> {
        let application_id = leaf
            .application_program_id()
            .ok_or_else(|| PackageStoreError::UnknownCatalogItem(leaf.selector.clone()))?;
        let application = self.parse_application_program(application_id)?;
        self.materialize_baggages_from_document(leaf, &application)
    }

    /// Materialize selected baggage while reusing an application document the
    /// caller has already parsed for instantiation.
    pub fn materialize_baggages_from_document(
        &self,
        leaf: &PackageCatalogLeaf,
        application: &Knx,
    ) -> Result<Option<PathBuf>, PackageStoreError> {
        if leaf.selector.package != self.digest {
            return Err(PackageStoreError::UnknownCatalogItem(leaf.selector.clone()));
        }
        materialize_baggages(
            &mut self.open_source_zip()?,
            &self.application_programs,
            &leaf.manufacturer_id,
            leaf.application_program_id()
                .ok_or_else(|| PackageStoreError::UnknownCatalogItem(leaf.selector.clone()))?,
            leaf.chain_digest,
            application,
            &self.directory.join(MATERIALIZED_DIRECTORY),
        )
    }

    fn open_source_zip(&self) -> Result<zip::ZipArchive<File>, PackageStoreError> {
        let source_path = self.source_archive_path();
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|source| PackageStoreError::ReadStoredArchive { path: source_path.clone(), source })?;
        require_plain_file(&source_path, &metadata)?;
        let source = File::open(&source_path)
            .map_err(|source| PackageStoreError::ReadStoredArchive { path: source_path, source })?;
        zip::ZipArchive::new(source).map_err(|source| PackageStoreError::Archive(ArchiveError::Zip(source)))
    }

    /// Load the exact catalogue leaf, its document, AP1/AP2 binding and Master Data.
    pub fn load_product(&self, selector: &PackageCatalogSelector) -> Result<SelectedProduct, PackageStoreError> {
        let leaf = self
            .leaves()
            .find(|leaf| &leaf.selector == selector)
            .ok_or_else(|| PackageStoreError::UnknownCatalogItem(selector.clone()))?;
        if !leaf.instantiable {
            return Err(PackageStoreError::NotInstantiable {
                catalog_item: selector.catalog_item_id.clone(),
                reason: leaf.instantiation,
            });
        }
        load_selected_product(&mut self.open_source_zip()?, &self.application_programs, leaf)
    }

    pub fn catalog(&self) -> &[PackageCatalogManufacturer] {
        &self.catalog
    }

    pub fn leaves(&self) -> impl Iterator<Item = &PackageCatalogLeaf> {
        self.catalog.iter().flat_map(|manufacturer| section_leaves(&manufacturer.sections))
    }
}

fn referenced_application_baggages(program: &ApplicationProgram) -> BTreeSet<String> {
    let mut baggage_ids = BTreeSet::new();

    if let Some(extension) = &program.static_section.extension {
        baggage_ids.extend(extension.baggages.iter().map(|baggage| baggage.ref_id.clone()));
    }

    // `TypePicture/@RefId` points directly into `Baggages.xml`; Manufacturer
    // Tool does not also repeat these references in `Static/Extension`.
    if let Some(parameter_types) = &program.static_section.parameter_types {
        baggage_ids.extend(parameter_types.types.iter().filter_map(|parameter_type| {
            let ParameterTypeDef::TypePicture(picture) = &parameter_type.type_def else {
                return None;
            };
            Some(picture.ref_id.clone())
        }));
    }

    baggage_ids
}

#[derive(Debug, Clone)]
pub struct ImportedPackage {
    pub package: StoredPackage,
    pub already_present: bool,
    /// Non-fatal problems found while checking signatures and their hash
    /// chain. Missing signatures are deliberately silent.
    pub notices: Vec<PackageImportNotice>,
}

impl ImportedPackage {
    pub fn catalog_item_count(&self) -> usize {
        self.package.leaves().count()
    }
}

/// A non-fatal problem found while checking a package during explicit import.
///
/// These notices are never persisted: opening an existing project store must
/// remain an index-only operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageImportNotice {
    pub path: String,
    pub message: String,
}

impl fmt::Display for PackageImportNotice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.message)
    }
}

#[derive(Debug, Error)]
pub enum PackageStoreError {
    #[error("application {application:?} has {count} catalogue items; select an exact CatalogItem")]
    AmbiguousApplicationSelection { application: String, count: usize },
    #[error(transparent)]
    Product(#[from] ProductError),
    #[error("catalogue item {catalog_item:?} is not instantiable: {reason:?}")]
    NotInstantiable { catalog_item: String, reason: PackageInstantiation },
    #[error(transparent)]
    Digest(#[from] PackageDigestError),
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error("cannot read .knxprod {path}")]
    ReadArchive {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot create package store {path}")]
    CreateStore {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read package store {path}")]
    ReadStore {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot create temporary package directory {path}")]
    CreateTemporary {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot install immutable package directory {path}")]
    InstallPackage {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read stored package archive {path}")]
    ReadStoredArchive {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read stored package index {path}")]
    ReadIndex {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse stored package index {path}")]
    ParseIndex {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("cannot serialize stored package index {path}")]
    SerializeIndex {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("stored package index {path} has version {actual}; this build supports version {supported}")]
    UnsupportedIndexVersion { path: PathBuf, actual: u32, supported: u32 },
    #[error(
        "stored package {path} cannot be opened because {reason}; remove that stored package directory and re-import the original .knxprod"
    )]
    ReimportRequired { path: PathBuf, reason: String },
    #[error("stored package index {path} belongs to {actual}, not directory identity {expected}")]
    IndexDigestMismatch { path: PathBuf, expected: PackageDigest, actual: PackageDigest },
    #[error("stored package index {path} is inconsistent: {reason}")]
    InvalidIndex { path: PathBuf, reason: String },
    #[error("package store path {path} is a symlink or is not a plain {expected}")]
    UnsafeStoreNode { path: PathBuf, expected: &'static str },
    #[error("unsafe ZIP member {path:?}: {reason}")]
    UnsafeEntry { path: String, reason: &'static str },
    #[error("duplicate ZIP member path {0:?}")]
    DuplicateEntry(String),
    #[error(".knxprod has {actual} ZIP members; the safety limit is {limit}")]
    ArchiveEntryLimit { actual: usize, limit: usize },
    #[error(
        ".knxprod central directory declares {declared} members but the ZIP index exposes {indexed}; duplicate member names are not allowed"
    )]
    ArchiveDirectoryEntryMismatch { declared: u64, indexed: usize },
    #[error("ZIP member {path:?} expands to {actual} bytes; the safety limit is {limit} bytes")]
    ArchiveEntrySizeLimit { path: String, actual: u64, limit: u64 },
    #[error(".knxprod expands to more than the safety limit of {limit} bytes")]
    ArchiveTotalSizeLimit { limit: u64 },
    #[error(
        "ZIP member {path:?} has an extreme compression ratio ({uncompressed} uncompressed bytes from {compressed} compressed bytes)"
    )]
    ArchiveCompressionRatio { path: String, uncompressed: u64, compressed: u64 },
    #[error("ZIP member {path:?} conflicts with file member {ancestor:?}")]
    EntryKindConflict { path: String, ancestor: String },
    #[error("cannot write package store file {path}")]
    WriteStoredFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot inspect extracted package content {path}")]
    InspectExtractedContent {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("extracted package content is missing or has an unexpected path {0:?}")]
    ExtractedPathMismatch(String),
    #[error("extracted package member {path:?} differs from source.knxprod")]
    ExtractedBytesMismatch { path: String },
    #[error("cannot parse {path:?} as KNX XML")]
    Xml {
        path: String,
        #[source]
        source: quick_xml::DeError,
    },
    #[error("cannot stream {path:?} as XML")]
    XmlRead {
        path: String,
        #[source]
        source: quick_xml::Error,
    },
    #[error("cannot read an XML attribute in {path:?}")]
    XmlAttribute {
        path: String,
        #[source]
        source: quick_xml::events::attributes::AttrError,
    },
    #[error("application-program document {path:?} is malformed: {reason}")]
    InvalidApplicationProgram { path: String, reason: String },
    #[error("Master Data document {path:?} is malformed: {reason}")]
    InvalidMasterData { path: String, reason: String },
    #[error("package has no application program {0:?}")]
    UnknownApplicationProgram(String),
    #[error("application-program entry {path:?} is not UTF-8")]
    ApplicationUtf8 {
        path: String,
        #[source]
        source: std::str::Utf8Error,
    },
    #[error("application program {application:?} is invalid")]
    ApplicationParse {
        application: String,
        #[source]
        source: ParseError,
    },
    #[error("baggage manifest {path:?} is invalid: {reason}")]
    InvalidBaggageManifest { path: String, reason: String },
    #[error("Hardware.xml {path:?} has invalid RegistrationInfo for {kind} {id:?}: {reason}")]
    InvalidRegistration { path: String, kind: &'static str, id: String, reason: String },
    #[error("catalogue item {catalog_item:?} in {path:?} has a broken package relation: {reason}")]
    BrokenCatalogRelation { path: String, catalog_item: String, reason: String },
    #[error("package has no catalogue item {0:?}")]
    UnknownCatalogItem(PackageCatalogSelector),
}

struct IndexedCatalogDocument {
    path: String,
    bytes: Vec<u8>,
    document: CatalogKnx,
}

struct IndexedHardwareDocument {
    bytes: Vec<u8>,
    document: HardwareKnx,
    registrations: BTreeMap<DeclaredRegistrationParent, PackageRegistration>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum DeclaredRegistrationParent {
    Product(String),
    Hardware2Program(String),
}

impl DeclaredRegistrationParent {
    fn id(&self) -> &str {
        match self {
            Self::Product(id) | Self::Hardware2Program(id) => id,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Product(_) => "Product",
            Self::Hardware2Program(_) => "Hardware2Program",
        }
    }
}

#[derive(Debug, Clone)]
struct ApplicationHeader {
    name: String,
    program_type: String,
    mask_version: String,
    is_secure_enabled: bool,
    #[cfg(feature = "signing")]
    declared_hash: Option<String>,
}

#[derive(Debug, Clone)]
struct MasterDataNames {
    schema_version: u16,
    master_version: u64,
    manufacturers: BTreeMap<String, String>,
}

fn build_package_index(bytes: &[u8], digest: PackageDigest) -> Result<PersistedPackageIndex, PackageStoreError> {
    build_package_index_with_size_limit(bytes, digest, MAX_TOTAL_UNCOMPRESSED_BYTES)
}

fn build_package_index_with_size_limit(
    bytes: &[u8],
    digest: PackageDigest,
    max_expanded_bytes: u64,
) -> Result<PersistedPackageIndex, PackageStoreError> {
    // ZIP safety is established entirely from the central directory before a
    // single payload is inflated. The second pass records names and reads only
    // the two small relation documents needed for catalogue selection.
    preflight_archive_with_size_limit(bytes, max_expanded_bytes)?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(ArchiveError::from)?;
    let mut application_programs = BTreeMap::new();
    let mut catalog_paths = Vec::new();
    let mut hardware_paths = Vec::new();
    let mut master_data_paths = Vec::new();

    for index in 0..archive.len() {
        let member = archive.by_index_raw(index).map_err(ArchiveError::from)?;
        if member.is_dir() {
            continue;
        }
        let path = member.name().to_owned();
        if let Some(application) = application_program_id(&path) {
            if let Some(previous) = application_programs.insert(application.clone(), path.clone()) {
                return Err(PackageStoreError::InvalidApplicationProgram {
                    path,
                    reason: format!(
                        "application ID {application:?} occurs in both {previous:?} and another package member"
                    ),
                });
            }
        } else if path == "Catalog.xml" || path.ends_with("/Catalog.xml") {
            catalog_paths.push(path);
        } else if path == "Hardware.xml" || path.ends_with("/Hardware.xml") {
            hardware_paths.push(path);
        } else if path == "knx_master.xml" || path.ends_with("/knx_master.xml") {
            master_data_paths.push(path);
        }
    }

    let mut hardware = BTreeMap::new();
    for path in hardware_paths {
        let bytes = read_zip_member(&mut archive, &path)?;
        let xml = std::str::from_utf8(&bytes).map_err(|source| ArchiveError::Utf8 { path: path.clone(), source })?;
        let document = quick_xml::de::from_str(xml.trim_start_matches('\u{feff}'))
            .map_err(|source| PackageStoreError::Xml { path: path.clone(), source })?;
        let registrations = parse_declared_registrations(&path, xml)?;
        validate_declared_registration_parents(&path, &document, &registrations)?;
        hardware.insert(path, IndexedHardwareDocument { bytes, document, registrations });
    }

    let mut catalogs = Vec::new();
    for path in catalog_paths {
        let bytes = read_zip_member(&mut archive, &path)?;
        let xml = std::str::from_utf8(&bytes).map_err(|source| ArchiveError::Utf8 { path: path.clone(), source })?;
        let document = quick_xml::de::from_str(xml.trim_start_matches('\u{feff}'))
            .map_err(|source| PackageStoreError::Xml { path: path.clone(), source })?;
        catalogs.push(IndexedCatalogDocument { path, bytes, document });
    }

    let mut catalog = derive_package_catalog(digest, &catalogs, &hardware, &application_programs)?;
    let referenced_programs = catalog
        .iter()
        .flat_map(|manufacturer| section_leaves(&manufacturer.sections))
        .filter_map(|leaf| leaf.application_program_id().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let mut headers = BTreeMap::new();
    for id in referenced_programs {
        let path = application_programs.get(&id).expect("catalogue derivation accepts only indexed application IDs");
        headers.insert(id.clone(), read_application_header(&mut archive, path, &id)?);
    }
    apply_application_headers(&mut catalog, &headers);
    let mut master_data_names = Vec::new();
    for path in master_data_paths {
        master_data_names.push(read_master_data_names(&mut archive, &path)?);
    }
    apply_master_data_names(&mut catalog, &master_data_names);
    let index =
        PersistedPackageIndex { version: PACKAGE_INDEX_VERSION, package: digest, catalog, application_programs };
    validate_package_index(&index, Path::new("<new package index>"), digest)?;
    Ok(index)
}

/// Check the signing chain once at the explicit import boundary. The archive
/// has already passed `preflight_archive`, so reading every file covered by a
/// present directory signature cannot exceed the package resource limits.
/// Nothing from this pass is retained in the project catalogue.
#[cfg(feature = "signing")]
fn inspect_package_signatures(bytes: &[u8]) -> Result<Vec<PackageImportNotice>, PackageStoreError> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(ArchiveError::from)?;
    let mut application_paths = Vec::new();
    let mut hardware_paths = Vec::new();
    let mut directory_signatures = Vec::new();
    for index in 0..archive.len() {
        let member = archive.by_index_raw(index).map_err(ArchiveError::from)?;
        if member.is_dir() {
            continue;
        }
        let path = member.name().to_owned();
        if let Some(id) = application_program_id(&path) {
            application_paths.push((id, path));
        } else if path == "Hardware.xml" || path.ends_with("/Hardware.xml") {
            hardware_paths.push(path);
        } else if !path.contains('/') && path.ends_with(".signature") {
            directory_signatures.push(path);
        }
    }

    let mut notices = Vec::new();
    let mut application_hashes = HashMap::new();
    for (id, path) in application_paths {
        // Indexing already checks every referenced opening declaration. An
        // unrelated malformed application remains lazy, so it cannot make an
        // otherwise useful import fail merely because its hash is unreadable.
        let Ok(header) = read_application_header(&mut archive, &path, &id) else { continue };
        if let Some(declared) = header.declared_hash {
            // The AP hash is an input to the H2P chain. It cannot currently be
            // recomputed generically because each project-schema version adds
            // registration-relevant AP attributes; `verify_hardware_xml`
            // checks the H2P declaration and its registration signature using
            // the exact value carried by that AP.
            application_hashes.insert(id, declared);
        }
    }

    for path in hardware_paths {
        let hardware_bytes = read_zip_member(&mut archive, &path)?;
        let hardware_xml = match std::str::from_utf8(&hardware_bytes) {
            Ok(xml) => xml.trim_start_matches('\u{feff}'),
            Err(error) => {
                notices.push(PackageImportNotice {
                    path: path.clone(),
                    message: format!("cannot check signing chain because Hardware.xml is not UTF-8: {error}"),
                });
                continue;
            }
        };
        let verification = match verify_hardware_xml(hardware_xml, &application_hashes) {
            Ok(verification) => verification,
            Err(error) => {
                notices.push(PackageImportNotice {
                    path: path.clone(),
                    message: format!("cannot check signing chain: {error}"),
                });
                continue;
            }
        };

        for product in verification.products.into_iter().filter(|result| !result.valid) {
            notices.push(PackageImportNotice {
                path: path.clone(),
                message: format!(
                    "Product {:?} signing hash does not match (declared {:?}, computed {:?})",
                    product.id, product.expected, product.computed
                ),
            });
        }
        for relation in verification
            .hardware2programs
            .into_iter()
            .filter(|result| !result.valid || result.app_hashes_found != result.app_refs.len())
        {
            let missing = relation.app_refs.len().saturating_sub(relation.app_hashes_found);
            let missing = if missing == 0 {
                String::new()
            } else {
                format!(", {missing} referenced application hash(es) missing")
            };
            notices.push(PackageImportNotice {
                path: path.clone(),
                message: format!(
                    "Hardware2Program {:?} signing hash does not match (declared {:?}, computed {:?}{missing})",
                    relation.id, relation.expected, relation.computed
                ),
            });
        }
        for signature in verification.registration_signatures.into_iter().filter(|result| !result.valid) {
            notices.push(PackageImportNotice {
                path: path.clone(),
                message: format!(
                    "{} {:?} registration signature does not match: {}",
                    signature.parent_type,
                    signature.parent_id,
                    signature.error.unwrap_or_else(|| "signature verification failed".to_owned())
                ),
            });
        }
    }

    for signature_path in directory_signatures {
        let directory = signature_path.trim_end_matches(".signature");
        let prefix = format!("{directory}/");
        let mut member_paths = Vec::new();
        for index in 0..archive.len() {
            let member = archive.by_index_raw(index).map_err(ArchiveError::from)?;
            if !member.is_dir() && member.name().starts_with(&prefix) {
                member_paths.push((member.name()[prefix.len()..].to_owned(), member.name().to_owned()));
            }
        }
        let mut files = Vec::with_capacity(member_paths.len());
        for (relative, full) in member_paths {
            files.push((relative, read_zip_member(&mut archive, &full)?));
        }
        let signature_bytes = read_zip_member(&mut archive, &signature_path)?;
        let signature = match std::str::from_utf8(&signature_bytes) {
            Ok(signature) => signature,
            Err(error) => {
                notices.push(PackageImportNotice {
                    path: signature_path,
                    message: format!("directory signature is not UTF-8: {error}"),
                });
                continue;
            }
        };
        let file_refs = files.iter().map(|(path, bytes)| (path.clone(), bytes.as_slice())).collect::<Vec<_>>();
        match verify_directory_signature(&file_refs, signature) {
            Ok(result) if result.valid => {}
            Ok(result) => notices.push(PackageImportNotice {
                path: signature_path,
                message: result.error.unwrap_or_else(|| "directory signature does not match".to_owned()),
            }),
            Err(error) => notices.push(PackageImportNotice {
                path: signature_path,
                message: format!("cannot verify directory signature: {error}"),
            }),
        }
    }

    Ok(notices)
}

fn read_zip_member<R: Read + Seek>(archive: &mut zip::ZipArchive<R>, path: &str) -> Result<Vec<u8>, PackageStoreError> {
    let mut member = archive.by_name(path).map_err(ArchiveError::from)?;
    validate_member_resource_limits(path, member.size(), member.compressed_size())?;
    let mut bytes = Vec::with_capacity(usize::try_from(member.size()).unwrap_or(0));
    member.read_to_end(&mut bytes).map_err(ArchiveError::from)?;
    Ok(bytes)
}

fn read_application_header<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    path: &str,
    expected_id: &str,
) -> Result<ApplicationHeader, PackageStoreError> {
    let member = archive.by_name(path).map_err(ArchiveError::from)?;
    validate_member_resource_limits(path, member.size(), member.compressed_size())?;

    // BufReader may decompress one small look-ahead buffer, but returning as
    // soon as the opening declaration is seen prevents the multi-megabyte
    // Static and Dynamic bodies from being inflated during package import.
    let mut reader = Reader::from_reader(BufReader::with_capacity(8 * 1024, member));
    reader.config_mut().trim_text(true);
    let mut ancestors = Vec::<Vec<u8>>::new();
    let mut buffer = Vec::new();
    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|source| PackageStoreError::XmlRead { path: path.to_owned(), source })?;
        let element = match &event {
            Event::Start(element) | Event::Empty(element) => Some(element),
            _ => None,
        };
        if let Some(element) = element
            && matches!(element.local_name().as_ref(), b"ApplicationProgram" | b"AP")
            && application_header_parent(&ancestors)
        {
            let attributes = xml_attributes(path, element)?;
            let id = attributes.get("Id").cloned().ok_or_else(|| PackageStoreError::InvalidApplicationProgram {
                path: path.to_owned(),
                reason: "ApplicationProgram/@Id is missing".to_owned(),
            })?;
            if id != expected_id {
                return Err(PackageStoreError::InvalidApplicationProgram {
                    path: path.to_owned(),
                    reason: format!("ZIP member names {expected_id:?}, but XML contains {id:?}"),
                });
            }
            let mask_version =
                attributes.get("MaskVersion").cloned().ok_or_else(|| PackageStoreError::InvalidApplicationProgram {
                    path: path.to_owned(),
                    reason: "ApplicationProgram/@MaskVersion is missing".to_owned(),
                })?;
            let is_secure_enabled = attributes
                .get("IsSecureEnabled")
                .map(|value| parse_xml_bool(path, "ApplicationProgram/@IsSecureEnabled", &value))
                .transpose()?
                .unwrap_or(false);
            #[cfg(feature = "signing")]
            let declared_hash = attributes.get("Hash").cloned();
            return Ok(ApplicationHeader {
                name: attributes.get("Name").cloned().unwrap_or_default(),
                program_type: attributes.get("ProgramType").cloned().unwrap_or_else(|| "ApplicationProgram".to_owned()),
                mask_version,
                is_secure_enabled,
                #[cfg(feature = "signing")]
                declared_hash,
            });
        }

        match event {
            Event::Start(element) => ancestors.push(element.local_name().as_ref().to_vec()),
            Event::End(_) => {
                ancestors.pop();
            }
            Event::Eof => {
                return Err(PackageStoreError::InvalidApplicationProgram {
                    path: path.to_owned(),
                    reason: "document has no direct ApplicationProgram declaration".to_owned(),
                });
            }
            _ => {}
        }
        buffer.clear();
    }
}

fn application_header_parent(ancestors: &[Vec<u8>]) -> bool {
    ancestors.len() == 4
        && ancestors[0] == b"KNX"
        && ancestors[1] == b"ManufacturerData"
        && ancestors[2] == b"Manufacturer"
        && matches!(ancestors[3].as_slice(), b"ApplicationPrograms" | b"APS")
}

fn apply_application_headers(
    manufacturers: &mut [PackageCatalogManufacturer],
    headers: &BTreeMap<String, ApplicationHeader>,
) {
    fn apply(sections: &mut [PackageCatalogSection], headers: &BTreeMap<String, ApplicationHeader>) {
        for section in sections {
            for leaf in &mut section.items {
                if let Some(header) = leaf.application_program_id().and_then(|id| headers.get(id)) {
                    leaf.mask_version = Some(header.mask_version.clone());
                    leaf.supports_data_secure = Some(header.is_secure_enabled);
                }
            }
            apply(&mut section.subsections, headers);
        }
    }

    for manufacturer in manufacturers {
        apply(&mut manufacturer.sections, headers);
    }
}

fn read_master_data_names<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    path: &str,
) -> Result<MasterDataNames, PackageStoreError> {
    let member = archive.by_name(path).map_err(ArchiveError::from)?;
    validate_member_resource_limits(path, member.size(), member.compressed_size())?;
    let mut reader = Reader::from_reader(BufReader::with_capacity(16 * 1024, member));
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut ancestors = Vec::<Vec<u8>>::new();
    let mut schema_version = None;
    let mut master_version = None;
    let mut manufacturers = BTreeMap::new();

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|source| PackageStoreError::XmlRead { path: path.to_owned(), source })?;
        let element = match &event {
            Event::Start(element) | Event::Empty(element) => Some(element),
            _ => None,
        };
        if let Some(element) = element {
            match element.local_name().as_ref() {
                b"KNX" if ancestors.is_empty() => {
                    let namespace = xml_attribute(path, element, b"xmlns")?.unwrap_or_default();
                    schema_version = schema_version_from_namespace(&namespace);
                }
                b"MasterData" if ancestors.as_slice() == [b"KNX".as_slice()] => {
                    let value = xml_attribute(path, element, b"Version")?.ok_or_else(|| {
                        PackageStoreError::InvalidMasterData {
                            path: path.to_owned(),
                            reason: "MasterData/@Version is missing".to_owned(),
                        }
                    })?;
                    master_version = Some(value.parse::<u64>().map_err(|_| PackageStoreError::InvalidMasterData {
                        path: path.to_owned(),
                        reason: format!("MasterData/@Version {value:?} is not numeric"),
                    })?);
                }
                b"Manufacturer"
                    if ancestors.len() == 3
                        && ancestors[0] == b"KNX"
                        && ancestors[1] == b"MasterData"
                        && ancestors[2] == b"Manufacturers" =>
                {
                    let id =
                        xml_attribute(path, element, b"Id")?.ok_or_else(|| PackageStoreError::InvalidMasterData {
                            path: path.to_owned(),
                            reason: "Manufacturer/@Id is missing".to_owned(),
                        })?;
                    let name =
                        xml_attribute(path, element, b"Name")?.ok_or_else(|| PackageStoreError::InvalidMasterData {
                            path: path.to_owned(),
                            reason: format!("manufacturer {id:?} has no Name"),
                        })?;
                    if manufacturers.insert(id.clone(), name).is_some() {
                        return Err(PackageStoreError::InvalidMasterData {
                            path: path.to_owned(),
                            reason: format!("manufacturer {id:?} occurs more than once"),
                        });
                    }
                }
                _ => {}
            }
        }

        match event {
            Event::Start(element) => ancestors.push(element.local_name().as_ref().to_vec()),
            Event::End(element)
                if element.local_name().as_ref() == b"Manufacturers"
                    && ancestors.len() == 3
                    && ancestors[0] == b"KNX"
                    && ancestors[1] == b"MasterData"
                    && ancestors[2] == b"Manufacturers" =>
            {
                break;
            }
            Event::End(_) => {
                ancestors.pop();
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    let schema_version = schema_version.ok_or_else(|| PackageStoreError::InvalidMasterData {
        path: path.to_owned(),
        reason: "KNX namespace has no numeric project-schema version".to_owned(),
    })?;
    let master_version = master_version.ok_or_else(|| PackageStoreError::InvalidMasterData {
        path: path.to_owned(),
        reason: "document has no direct MasterData element".to_owned(),
    })?;
    Ok(MasterDataNames { schema_version, master_version, manufacturers })
}

fn apply_master_data_names(manufacturers: &mut [PackageCatalogManufacturer], sources: &[MasterDataNames]) {
    for manufacturer in manufacturers {
        let newest = sources
            .iter()
            .filter_map(|source| {
                source
                    .manufacturers
                    .get(&manufacturer.id)
                    .map(|name| (source.schema_version, source.master_version, name))
            })
            .max_by_key(|(schema_version, master_version, _)| (*schema_version, *master_version));
        if let Some((schema_version, master_version, name)) = newest {
            manufacturer.name = Some(name.clone());
            manufacturer.name_source_schema_version = Some(schema_version);
            manufacturer.name_source_version = Some(master_version);
        }
    }
}

fn parse_declared_registrations(
    path: &str,
    xml: &str,
) -> Result<BTreeMap<DeclaredRegistrationParent, PackageRegistration>, PackageStoreError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut current_parent = None::<(DeclaredRegistrationParent, usize)>;
    let mut depth = 0_usize;
    let mut registrations = BTreeMap::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                depth += 1;
                match element.local_name().as_ref() {
                    b"Product" => {
                        if let Some(id) = xml_attribute(path, &element, b"Id")? {
                            current_parent = Some((DeclaredRegistrationParent::Product(id), depth));
                        }
                    }
                    b"Hardware2Program" => {
                        if let Some(id) = xml_attribute(path, &element, b"Id")? {
                            current_parent = Some((DeclaredRegistrationParent::Hardware2Program(id), depth));
                        }
                    }
                    b"RegistrationInfo" => {
                        record_declared_registration(
                            path,
                            &element,
                            current_parent.as_ref(),
                            depth,
                            &mut registrations,
                        )?;
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(element)) if element.local_name().as_ref() == b"RegistrationInfo" => {
                record_declared_registration(path, &element, current_parent.as_ref(), depth + 1, &mut registrations)?;
            }
            Ok(Event::End(element)) => {
                if matches!(element.local_name().as_ref(), b"Product" | b"Hardware2Program")
                    && current_parent.as_ref().is_some_and(|(_, parent_depth)| *parent_depth == depth)
                {
                    current_parent = None;
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(source) => return Err(PackageStoreError::XmlRead { path: path.to_owned(), source }),
        }
    }
    Ok(registrations)
}

fn record_declared_registration(
    path: &str,
    element: &BytesStart<'_>,
    parent: Option<&(DeclaredRegistrationParent, usize)>,
    registration_depth: usize,
    registrations: &mut BTreeMap<DeclaredRegistrationParent, PackageRegistration>,
) -> Result<(), PackageStoreError> {
    let Some((parent, parent_depth)) = parent else {
        return Err(PackageStoreError::InvalidRegistration {
            path: path.to_owned(),
            kind: "unknown parent",
            id: String::new(),
            reason: "RegistrationInfo is not nested in Product or Hardware2Program".to_owned(),
        });
    };
    if registration_depth != parent_depth + 1 {
        return Err(invalid_declared_registration(
            path,
            parent,
            "RegistrationInfo must be a direct child of its parent",
        ));
    }
    let status = required_xml_attribute(path, element, b"RegistrationStatus")?;
    let status = parse_declared_registration_status(path, parent, &status)?;
    let registration = PackageRegistration {
        status,
        registration_number: xml_attribute(path, element, b"RegistrationNumber")?,
        registration_date: xml_attribute(path, element, b"RegistrationDate")?,
    };
    if registrations.insert(parent.clone(), registration).is_some() {
        return Err(invalid_declared_registration(path, parent, "expected at most one RegistrationInfo"));
    }
    Ok(())
}

fn validate_declared_registration_parents(
    path: &str,
    hardware: &HardwareKnx,
    registrations: &BTreeMap<DeclaredRegistrationParent, PackageRegistration>,
) -> Result<(), PackageStoreError> {
    let mut parents = BTreeSet::new();
    for definition in &hardware.manufacturer_data.manufacturer.hardware.hardware {
        for product in &definition.products.products {
            let parent = DeclaredRegistrationParent::Product(product.id.clone());
            if !parents.insert(parent.clone()) {
                return Err(invalid_declared_registration(path, &parent, "parent ID occurs more than once"));
            }
        }
        for relation in &definition.hardware2programs.hardware2programs {
            let parent = DeclaredRegistrationParent::Hardware2Program(relation.id.clone());
            if !parents.insert(parent.clone()) {
                return Err(invalid_declared_registration(path, &parent, "parent ID occurs more than once"));
            }
        }
    }
    if let Some(parent) = registrations.keys().find(|parent| !parents.contains(*parent)) {
        return Err(invalid_declared_registration(
            path,
            parent,
            "registration parent is absent from parsed Hardware.xml",
        ));
    }
    Ok(())
}

fn parse_declared_registration_status(
    path: &str,
    parent: &DeclaredRegistrationParent,
    status: &str,
) -> Result<PackageRegistrationStatus, PackageStoreError> {
    match status {
        "Unregistered" => Ok(PackageRegistrationStatus::Unregistered),
        "Registered" => Ok(PackageRegistrationStatus::Registered),
        "Certified" => Ok(PackageRegistrationStatus::Certified),
        "FutureUseNotRecommended" => Ok(PackageRegistrationStatus::FutureUseNotRecommended),
        "FutureUseNotAllowed" => Ok(PackageRegistrationStatus::FutureUseNotAllowed),
        _ => Err(invalid_declared_registration(path, parent, "unknown RegistrationStatus")),
    }
}

fn invalid_declared_registration(path: &str, parent: &DeclaredRegistrationParent, reason: &str) -> PackageStoreError {
    PackageStoreError::InvalidRegistration {
        path: path.to_owned(),
        kind: parent.kind(),
        id: parent.id().to_owned(),
        reason: reason.to_owned(),
    }
}

fn required_xml_attribute(path: &str, element: &BytesStart<'_>, name: &[u8]) -> Result<String, PackageStoreError> {
    xml_attribute(path, element, name)?.ok_or_else(|| PackageStoreError::InvalidApplicationProgram {
        path: path.to_owned(),
        reason: format!(
            "{}/@{} is missing",
            String::from_utf8_lossy(element.local_name().as_ref()),
            String::from_utf8_lossy(name)
        ),
    })
}

fn xml_attribute(path: &str, element: &BytesStart<'_>, name: &[u8]) -> Result<Option<String>, PackageStoreError> {
    for attribute in element.attributes() {
        let attribute =
            attribute.map_err(|source| PackageStoreError::XmlAttribute { path: path.to_owned(), source })?;
        if attribute.key.as_ref() == name {
            return attribute
                .unescape_value()
                .map(|value| Some(value.into_owned()))
                .map_err(|source| PackageStoreError::XmlRead { path: path.to_owned(), source });
        }
    }
    Ok(None)
}

fn xml_attributes(path: &str, element: &BytesStart<'_>) -> Result<HashMap<String, String>, PackageStoreError> {
    let mut attributes = HashMap::new();
    for attribute in element.attributes() {
        let attribute =
            attribute.map_err(|source| PackageStoreError::XmlAttribute { path: path.to_owned(), source })?;
        let name = String::from_utf8_lossy(attribute.key.as_ref()).into_owned();
        let value = attribute
            .unescape_value()
            .map_err(|source| PackageStoreError::XmlRead { path: path.to_owned(), source })?
            .into_owned();
        attributes.insert(name, value);
    }
    Ok(attributes)
}

fn parse_xml_bool(path: &str, field: &str, value: &str) -> Result<bool, PackageStoreError> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(PackageStoreError::InvalidApplicationProgram {
            path: path.to_owned(),
            reason: format!("{field} has invalid XML Schema boolean {value:?}"),
        }),
    }
}

fn read_package_index(path: &Path, digest: PackageDigest) -> Result<PersistedPackageIndex, PackageStoreError> {
    let bytes = fs::read(path).map_err(|source| PackageStoreError::ReadIndex { path: path.to_owned(), source })?;
    let index: PersistedPackageIndex = serde_json::from_slice(&bytes)
        .map_err(|source| PackageStoreError::ParseIndex { path: path.to_owned(), source })?;
    validate_package_index(&index, path, digest)?;
    Ok(index)
}

#[cfg(feature = "signing")]
fn write_package_index(path: &Path, index: &PersistedPackageIndex) -> Result<(), PackageStoreError> {
    let bytes = serde_json::to_vec_pretty(index)
        .map_err(|source| PackageStoreError::SerializeIndex { path: path.to_owned(), source })?;
    write_synced_file(path, &bytes)
}

fn validate_package_index(
    index: &PersistedPackageIndex,
    path: &Path,
    digest: PackageDigest,
) -> Result<(), PackageStoreError> {
    if index.version != PACKAGE_INDEX_VERSION {
        return Err(PackageStoreError::UnsupportedIndexVersion {
            path: path.to_owned(),
            actual: index.version,
            supported: PACKAGE_INDEX_VERSION,
        });
    }
    if index.package != digest {
        return Err(PackageStoreError::IndexDigestMismatch {
            path: path.to_owned(),
            expected: digest,
            actual: index.package,
        });
    }

    for (id, entry_path) in &index.application_programs {
        validate_member_path(entry_path, false)?;
        if application_program_id(entry_path).as_deref() != Some(id) {
            return Err(PackageStoreError::InvalidIndex {
                path: path.to_owned(),
                reason: format!("application {id:?} maps to non-matching ZIP member {entry_path:?}"),
            });
        }
    }

    let mut catalog_items = BTreeSet::new();
    let mut section_ids = BTreeSet::new();
    for manufacturer in &index.catalog {
        validate_store_component(&manufacturer.id, "manufacturer ID is not a portable store component")?;
        let complete_name_source = manufacturer.name.is_some()
            && manufacturer.name_source_schema_version.is_some()
            && manufacturer.name_source_version.is_some();
        let absent_name_source = manufacturer.name.is_none()
            && manufacturer.name_source_schema_version.is_none()
            && manufacturer.name_source_version.is_none();
        if !complete_name_source && !absent_name_source {
            return Err(PackageStoreError::InvalidIndex {
                path: path.to_owned(),
                reason: format!("manufacturer {:?} has incomplete Master Data name provenance", manufacturer.id),
            });
        }
        validate_index_sections(&manufacturer.sections, digest, path, &mut section_ids)?;
        for leaf in section_leaves(&manufacturer.sections) {
            if leaf.selector.package != digest {
                return Err(PackageStoreError::InvalidIndex {
                    path: path.to_owned(),
                    reason: format!(
                        "CatalogItem {:?} selects package {}, not {digest}",
                        leaf.selector.catalog_item_id, leaf.selector.package
                    ),
                });
            }
            if !catalog_items.insert(leaf.selector.catalog_item_id.clone()) {
                return Err(PackageStoreError::InvalidIndex {
                    path: path.to_owned(),
                    reason: format!("CatalogItem {:?} occurs more than once", leaf.selector.catalog_item_id),
                });
            }
            if leaf.manufacturer_id != manufacturer.id {
                return Err(PackageStoreError::InvalidIndex {
                    path: path.to_owned(),
                    reason: format!(
                        "CatalogItem {:?} names manufacturer {:?} inside manufacturer {:?}",
                        leaf.selector.catalog_item_id, leaf.manufacturer_id, manufacturer.id
                    ),
                });
            }
            let effective =
                effective_declared_registration(&leaf.product_registration, &leaf.hardware2program_registration);
            if leaf.effective_registration != effective {
                return Err(PackageStoreError::InvalidIndex {
                    path: path.to_owned(),
                    reason: format!(
                        "CatalogItem {:?} has inconsistent effective registration",
                        leaf.selector.catalog_item_id
                    ),
                });
            }
            for application in leaf.application_program_ids() {
                if !index.application_programs.contains_key(application) {
                    return Err(PackageStoreError::InvalidIndex {
                        path: path.to_owned(),
                        reason: format!(
                            "CatalogItem {:?} references missing application {application:?}",
                            leaf.selector.catalog_item_id
                        ),
                    });
                }
                let member = &index.application_programs[application];
                let directory = member.rsplit_once('/').map_or("", |(directory, _)| directory);
                if !directory.is_empty() && directory != manufacturer.id {
                    return Err(PackageStoreError::InvalidIndex {
                        path: path.to_owned(),
                        reason: format!(
                            "CatalogItem {:?} references application outside manufacturer directory",
                            leaf.selector.catalog_item_id
                        ),
                    });
                }
            }
            let expected_instantiation = match &leaf.programs {
                PackageProgramBinding::None => {
                    if leaf.mask_version.is_some() || leaf.supports_data_secure.is_some() {
                        return Err(PackageStoreError::InvalidIndex {
                            path: path.to_owned(),
                            reason: format!(
                                "catalogue-only item {:?} carries application metadata",
                                leaf.selector.catalog_item_id
                            ),
                        });
                    }
                    PackageInstantiation::CatalogOnly(PackageCatalogOnlyReason::NoApplicationProgram)
                }
                PackageProgramBinding::Application { .. } => {
                    if leaf.mask_version.is_none() || leaf.supports_data_secure.is_none() {
                        return Err(PackageStoreError::InvalidIndex {
                            path: path.to_owned(),
                            reason: format!(
                                "programmable item {:?} lacks application-header metadata",
                                leaf.selector.catalog_item_id
                            ),
                        });
                    }
                    if leaf.effective_registration.status.is_instantiable() {
                        PackageInstantiation::Programmable
                    } else {
                        PackageInstantiation::Blocked(PackageInstantiationBlock::RegistrationStatus(
                            leaf.effective_registration.status,
                        ))
                    }
                }
            };
            if leaf.instantiation != expected_instantiation
                || leaf.instantiable != (expected_instantiation == PackageInstantiation::Programmable)
            {
                return Err(PackageStoreError::InvalidIndex {
                    path: path.to_owned(),
                    reason: format!(
                        "CatalogItem {:?} has inconsistent instantiation state",
                        leaf.selector.catalog_item_id
                    ),
                });
            }
        }
    }
    Ok(())
}

fn validate_index_sections(
    sections: &[PackageCatalogSection],
    digest: PackageDigest,
    path: &Path,
    section_ids: &mut BTreeSet<String>,
) -> Result<(), PackageStoreError> {
    for section in sections {
        if !section_ids.insert(section.id.clone()) {
            return Err(PackageStoreError::InvalidIndex {
                path: path.to_owned(),
                reason: format!("CatalogSection {:?} occurs more than once", section.id),
            });
        }
        if section.packages.as_slice() != [digest] {
            return Err(PackageStoreError::InvalidIndex {
                path: path.to_owned(),
                reason: format!("CatalogSection {:?} has inconsistent package provenance", section.id),
            });
        }
        validate_index_sections(&section.subsections, digest, path, section_ids)?;
    }
    Ok(())
}

#[cfg(feature = "signing")]
fn preflight_archive(bytes: &[u8]) -> Result<(), PackageStoreError> {
    preflight_archive_with_size_limit(bytes, MAX_TOTAL_UNCOMPRESSED_BYTES)
}

fn preflight_archive_with_size_limit(bytes: &[u8], max_expanded_bytes: u64) -> Result<(), PackageStoreError> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(ArchiveError::from)?;
    let declared_entries = central_directory_entry_count(bytes).ok_or_else(|| {
        PackageStoreError::Archive(ArchiveError::Zip(zip::result::ZipError::InvalidArchive(
            "cannot locate a consistent ZIP central directory",
        )))
    })?;
    if declared_entries != archive.len() as u64 {
        return Err(PackageStoreError::ArchiveDirectoryEntryMismatch {
            declared: declared_entries,
            indexed: archive.len(),
        });
    }
    if declared_entries > MAX_ARCHIVE_ENTRIES as u64 {
        return Err(PackageStoreError::ArchiveEntryLimit {
            actual: usize::try_from(declared_entries).unwrap_or(usize::MAX),
            limit: MAX_ARCHIVE_ENTRIES,
        });
    }

    let mut total = 0_u64;
    let mut kinds = BTreeMap::new();
    let mut portable_paths = BTreeMap::<String, String>::new();
    for index in 0..archive.len() {
        let member = archive.by_index_raw(index).map_err(ArchiveError::from)?;
        let name = validate_member_path(member.name(), member.is_dir())?;
        if kinds.insert(name.clone(), member.is_dir()).is_some() {
            return Err(PackageStoreError::DuplicateEntry(name));
        }
        let portable = portable_path_key(&name);
        if let Some(existing) = portable_paths.insert(portable, name.clone())
            && existing != name
        {
            return Err(PackageStoreError::UnsafeEntry {
                path: name,
                reason: "path aliases another member on a case-insensitive filesystem",
            });
        }
        if let Some(mode) = member.unix_mode() {
            let file_type = mode & 0o170000;
            let allowed = file_type == 0
                || (!member.is_dir() && file_type == 0o100000)
                || (member.is_dir() && file_type == 0o040000);
            if !allowed {
                return Err(PackageStoreError::UnsafeEntry {
                    path: name,
                    reason: "symlink or special-file members are not allowed",
                });
            }
        }

        let uncompressed = member.size();
        validate_member_resource_limits(&name, uncompressed, member.compressed_size())?;
        total = total
            .checked_add(uncompressed)
            .ok_or(PackageStoreError::ArchiveTotalSizeLimit { limit: max_expanded_bytes })?;
        if total > max_expanded_bytes {
            return Err(PackageStoreError::ArchiveTotalSizeLimit { limit: max_expanded_bytes });
        }
    }

    for (path, _) in &kinds {
        let mut prefix = String::new();
        for component in path.split('/').take(path.split('/').count().saturating_sub(1)) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if kinds.get(&prefix).is_some_and(|directory| !directory) {
                return Err(PackageStoreError::EntryKindConflict { path: path.clone(), ancestor: prefix });
            }
        }
    }
    Ok(())
}

fn validate_member_resource_limits(path: &str, uncompressed: u64, compressed: u64) -> Result<(), PackageStoreError> {
    if uncompressed > MAX_ENTRY_UNCOMPRESSED_BYTES {
        return Err(PackageStoreError::ArchiveEntrySizeLimit {
            path: path.to_owned(),
            actual: uncompressed,
            limit: MAX_ENTRY_UNCOMPRESSED_BYTES,
        });
    }
    if uncompressed >= COMPRESSION_RATIO_FLOOR_BYTES
        && (compressed == 0 || uncompressed / compressed.max(1) > MAX_COMPRESSION_RATIO)
    {
        return Err(PackageStoreError::ArchiveCompressionRatio { path: path.to_owned(), uncompressed, compressed });
    }
    Ok(())
}

fn central_directory_entry_count(bytes: &[u8]) -> Option<u64> {
    const END_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
    const ZIP64_LOCATOR_SIGNATURE: &[u8; 4] = b"PK\x06\x07";
    const ZIP64_END_SIGNATURE: &[u8; 4] = b"PK\x06\x06";
    const MAX_END_SEARCH: usize = u16::MAX as usize + 22;

    let search_start = bytes.len().saturating_sub(MAX_END_SEARCH);
    let end_offset = (search_start..=bytes.len().saturating_sub(22)).rev().find(|&offset| {
        bytes.get(offset..offset + 4) == Some(END_SIGNATURE)
            && read_u16(bytes, offset + 20).is_some_and(|comment| offset + 22 + usize::from(comment) == bytes.len())
    })?;
    let disk = read_u16(bytes, end_offset + 4)?;
    let central_disk = read_u16(bytes, end_offset + 6)?;
    if disk != 0 || central_disk != 0 {
        return None;
    }
    let entries_on_disk = read_u16(bytes, end_offset + 8)?;
    let entries = read_u16(bytes, end_offset + 10)?;
    if entries != u16::MAX {
        return (entries == entries_on_disk).then_some(u64::from(entries));
    }

    let locator_offset = end_offset.checked_sub(20)?;
    if bytes.get(locator_offset..locator_offset + 4) != Some(ZIP64_LOCATOR_SIGNATURE) {
        return None;
    }
    if read_u32(bytes, locator_offset + 4)? != 0 || read_u32(bytes, locator_offset + 16)? != 1 {
        return None;
    }
    let zip64_offset = usize::try_from(read_u64(bytes, locator_offset + 8)?).ok()?;
    if bytes.get(zip64_offset..zip64_offset + 4) != Some(ZIP64_END_SIGNATURE) {
        return None;
    }
    if read_u32(bytes, zip64_offset + 16)? != 0 || read_u32(bytes, zip64_offset + 20)? != 0 {
        return None;
    }
    let entries_on_disk = read_u64(bytes, zip64_offset + 24)?;
    let entries = read_u64(bytes, zip64_offset + 32)?;
    (entries == entries_on_disk).then_some(entries)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?))
}

#[cfg(feature = "signing")]
fn ensure_store_root(root: &Path) -> Result<(), PackageStoreError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => return require_plain_directory(root, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(PackageStoreError::CreateStore { path: root.to_owned(), source }),
    }
    fs::create_dir_all(root).map_err(|source| PackageStoreError::CreateStore { path: root.to_owned(), source })?;
    let metadata = fs::symlink_metadata(root)
        .map_err(|source| PackageStoreError::CreateStore { path: root.to_owned(), source })?;
    require_plain_directory(root, &metadata)
}

fn require_plain_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), PackageStoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PackageStoreError::UnsafeStoreNode { path: path.to_owned(), expected: "directory" });
    }
    Ok(())
}

fn require_plain_file(path: &Path, metadata: &fs::Metadata) -> Result<(), PackageStoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PackageStoreError::UnsafeStoreNode { path: path.to_owned(), expected: "regular file" });
    }
    Ok(())
}

fn validate_member_path(path: &str, directory: bool) -> Result<String, PackageStoreError> {
    if path.is_empty() || path.starts_with('/') || path.starts_with('\\') || path.contains('\\') || path.contains('\0')
    {
        return Err(PackageStoreError::UnsafeEntry {
            path: path.to_owned(),
            reason: "absolute or platform-specific path",
        });
    }
    let path = if directory { path.strip_suffix('/').unwrap_or(path) } else { path };
    if path.is_empty() {
        return Err(PackageStoreError::UnsafeEntry { path: path.to_owned(), reason: "empty path" });
    }
    let mut components = path.split('/');
    let first = components.next().expect("a non-empty path has one component");
    let drive_prefix =
        first.as_bytes().len() == 2 && first.as_bytes()[0].is_ascii_alphabetic() && first.as_bytes()[1] == b':';
    if drive_prefix || first.is_empty() || first == "." || first == ".." {
        return Err(PackageStoreError::UnsafeEntry { path: path.to_owned(), reason: "absolute or traversing path" });
    }
    if components.clone().any(|component| component.is_empty() || component == "." || component == "..") {
        return Err(PackageStoreError::UnsafeEntry { path: path.to_owned(), reason: "empty or traversing component" });
    }
    for component in path.split('/') {
        if component.ends_with('.')
            || component.ends_with(' ')
            || component
                .chars()
                .any(|character| character <= '\u{1f}' || matches!(character, ':' | '<' | '>' | '"' | '|' | '?' | '*'))
            || windows_reserved_component(component)
        {
            return Err(PackageStoreError::UnsafeEntry {
                path: path.to_owned(),
                reason: "component is not a portable regular file name",
            });
        }
    }
    Ok(path.to_owned())
}

fn validate_store_component(component: &str, description: &'static str) -> Result<(), PackageStoreError> {
    if component.contains('/') || component.contains('\\') {
        return Err(PackageStoreError::UnsafeEntry {
            path: component.to_owned(),
            reason: "store identity contains a path separator",
        });
    }
    validate_member_path(component, false).map(|_| ()).map_err(|error| match error {
        PackageStoreError::UnsafeEntry { path, .. } => PackageStoreError::UnsafeEntry { path, reason: description },
        other => other,
    })
}

fn baggage_relative_path(target_path: &str, name: &str) -> Result<String, PackageStoreError> {
    if name.contains('/') || name.contains('\\') {
        return Err(PackageStoreError::UnsafeEntry {
            path: name.to_owned(),
            reason: "baggage Name must be one portable file name",
        });
    }
    let path = if target_path.is_empty() {
        format!("Baggages/{name}")
    } else {
        if target_path.contains('\\') {
            return Err(PackageStoreError::UnsafeEntry {
                path: target_path.to_owned(),
                reason: "baggage TargetPath must use ZIP path separators",
            });
        }
        format!("Baggages/{target_path}/{name}")
    };
    validate_member_path(&path, false)
}

fn ensure_plain_cache_directory(path: &Path) -> Result<(), PackageStoreError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(PackageStoreError::CreateStore { path: path.to_owned(), source }),
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| PackageStoreError::CreateStore { path: path.to_owned(), source })?;
    require_plain_directory(path, &metadata)
}

fn existing_materialized_root(destination: &Path, manufacturer_id: &str) -> Result<Option<PathBuf>, PackageStoreError> {
    let metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(PackageStoreError::ReadStore { path: destination.to_owned(), source }),
    };
    require_plain_directory(destination, &metadata)?;
    let root = destination.join(manufacturer_id);
    let metadata =
        fs::symlink_metadata(&root).map_err(|source| PackageStoreError::ReadStore { path: root.clone(), source })?;
    require_plain_directory(&root, &metadata)?;
    Ok(Some(root))
}

fn portable_path_key(path: &str) -> String {
    path.to_lowercase()
}

fn windows_reserved_component(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component).to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|number| matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
}

fn write_synced_file(path: &Path, bytes: &[u8]) -> Result<(), PackageStoreError> {
    let mut file =
        File::create(path).map_err(|source| PackageStoreError::WriteStoredFile { path: path.to_owned(), source })?;
    file.write_all(bytes).map_err(|source| PackageStoreError::WriteStoredFile { path: path.to_owned(), source })?;
    file.sync_all().map_err(|source| PackageStoreError::WriteStoredFile { path: path.to_owned(), source })
}

fn sync_directory(path: &Path) -> Result<(), PackageStoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| PackageStoreError::WriteStoredFile { path: path.to_owned(), source })
}

fn sync_directory_tree(path: &Path) -> Result<(), PackageStoreError> {
    for entry in fs::read_dir(path).map_err(|source| PackageStoreError::ReadStore { path: path.to_owned(), source })? {
        let entry = entry.map_err(|source| PackageStoreError::ReadStore { path: path.to_owned(), source })?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|source| PackageStoreError::ReadStore { path: entry.path(), source })?;
        if metadata.is_dir() {
            sync_directory_tree(&entry.path())?;
        }
    }
    sync_directory(path)
}

struct TemporaryDirectoryGuard {
    path: Option<PathBuf>,
}

impl TemporaryDirectoryGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TemporaryDirectoryGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

// ============================================================================
// Exact catalogue-chain derivation
// ============================================================================

fn derive_package_catalog(
    digest: PackageDigest,
    catalogs: &[IndexedCatalogDocument],
    hardware_documents: &BTreeMap<String, IndexedHardwareDocument>,
    application_programs: &BTreeMap<String, String>,
) -> Result<Vec<PackageCatalogManufacturer>, PackageStoreError> {
    let mut manufacturers = Vec::new();
    let mut package_section_ids = BTreeSet::new();
    let mut package_item_ids = BTreeSet::new();
    for indexed_catalog in catalogs {
        let catalog_path = indexed_catalog.path.as_str();
        let catalog = &indexed_catalog.document;
        let directory = catalog_path.rsplit_once('/').map_or("", |(directory, _)| directory);
        let hardware_path =
            if directory.is_empty() { "Hardware.xml".to_owned() } else { format!("{directory}/Hardware.xml") };
        let indexed_hardware =
            hardware_documents.get(&hardware_path).ok_or_else(|| PackageStoreError::BrokenCatalogRelation {
                path: catalog_path.to_owned(),
                catalog_item: String::new(),
                reason: format!("sibling {hardware_path:?} is missing"),
            })?;
        let hardware = &indexed_hardware.document;
        let manufacturer_id = catalog.manufacturer_data.manufacturer.ref_id.clone();
        validate_catalogue_ids(
            catalog_path,
            &catalog.manufacturer_data.manufacturer.catalog.catalog_sections,
            &mut package_section_ids,
            &mut package_item_ids,
        )?;
        if hardware.manufacturer_data.manufacturer.ref_id != manufacturer_id {
            return Err(PackageStoreError::BrokenCatalogRelation {
                path: catalog_path.to_owned(),
                catalog_item: String::new(),
                reason: "Catalog.xml and Hardware.xml name different manufacturers".to_owned(),
            });
        }
        if catalog.xmlns.trim_end_matches('/') != hardware.xmlns.trim_end_matches('/') {
            return Err(PackageStoreError::BrokenCatalogRelation {
                path: catalog_path.to_owned(),
                catalog_item: String::new(),
                reason: format!(
                    "Catalog.xml schema {:?} conflicts with Hardware.xml schema {:?}",
                    catalog.xmlns, hardware.xmlns
                ),
            });
        }
        if schema_version_from_namespace(&catalog.xmlns).is_none() {
            return Err(PackageStoreError::BrokenCatalogRelation {
                path: catalog_path.to_owned(),
                catalog_item: String::new(),
                reason: format!("package uses non-canonical KNX project namespace {:?}", catalog.xmlns),
            });
        }
        if !directory.is_empty() && directory != manufacturer_id {
            return Err(PackageStoreError::BrokenCatalogRelation {
                path: catalog_path.to_owned(),
                catalog_item: String::new(),
                reason: format!("manufacturer {manufacturer_id:?} is stored in directory {directory:?}"),
            });
        }
        let sections = catalog
            .manufacturer_data
            .manufacturer
            .catalog
            .catalog_sections
            .iter()
            .map(|section| {
                derive_catalog_section(
                    digest,
                    catalog_path,
                    &indexed_catalog.bytes,
                    &indexed_hardware.bytes,
                    &manufacturer_id,
                    section,
                    hardware,
                    &indexed_hardware.registrations,
                    application_programs,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        manufacturers.push(PackageCatalogManufacturer {
            id: manufacturer_id,
            name: None,
            name_source_schema_version: None,
            name_source_version: None,
            sections,
        });
    }
    Ok(manufacturers)
}

fn validate_catalogue_ids(
    path: &str,
    sections: &[CatalogSection],
    section_ids: &mut BTreeSet<String>,
    item_ids: &mut BTreeSet<String>,
) -> Result<(), PackageStoreError> {
    fn visit(
        path: &str,
        sections: &[CatalogSection],
        section_ids: &mut BTreeSet<String>,
        item_ids: &mut BTreeSet<String>,
    ) -> Result<(), PackageStoreError> {
        for section in sections {
            if !section_ids.insert(section.id.clone()) {
                return Err(PackageStoreError::BrokenCatalogRelation {
                    path: path.to_owned(),
                    catalog_item: String::new(),
                    reason: format!("CatalogSection ID {:?} occurs more than once", section.id),
                });
            }
            for item in &section.catalog_items {
                if !item_ids.insert(item.id.clone()) {
                    return Err(PackageStoreError::BrokenCatalogRelation {
                        path: path.to_owned(),
                        catalog_item: item.id.clone(),
                        reason: "CatalogItem ID occurs more than once in this package".to_owned(),
                    });
                }
            }
            visit(path, &section.subsections, section_ids, item_ids)?;
        }
        Ok(())
    }

    visit(path, sections, section_ids, item_ids)
}

#[allow(clippy::too_many_arguments)]
fn derive_catalog_section(
    digest: PackageDigest,
    catalog_path: &str,
    catalog_bytes: &[u8],
    hardware_bytes: &[u8],
    manufacturer_id: &str,
    section: &CatalogSection,
    hardware: &HardwareKnx,
    registrations: &BTreeMap<DeclaredRegistrationParent, PackageRegistration>,
    application_programs: &BTreeMap<String, String>,
) -> Result<PackageCatalogSection, PackageStoreError> {
    let items = section
        .catalog_items
        .iter()
        .map(|item| {
            derive_catalog_leaf(
                digest,
                catalog_path,
                catalog_bytes,
                hardware_bytes,
                manufacturer_id,
                item,
                hardware,
                registrations,
                application_programs,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let subsections = section
        .subsections
        .iter()
        .map(|subsection| {
            derive_catalog_section(
                digest,
                catalog_path,
                catalog_bytes,
                hardware_bytes,
                manufacturer_id,
                subsection,
                hardware,
                registrations,
                application_programs,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PackageCatalogSection {
        id: section.id.clone(),
        name: section.name.clone(),
        number: section.number.clone(),
        default_language: section.default_language.clone(),
        packages: vec![digest],
        items,
        subsections,
    })
}

#[allow(clippy::too_many_arguments)]
fn derive_catalog_leaf(
    digest: PackageDigest,
    catalog_path: &str,
    catalog_bytes: &[u8],
    hardware_bytes: &[u8],
    manufacturer_id: &str,
    item: &CatalogItem,
    hardware_document: &HardwareKnx,
    registrations: &BTreeMap<DeclaredRegistrationParent, PackageRegistration>,
    application_programs: &BTreeMap<String, String>,
) -> Result<PackageCatalogLeaf, PackageStoreError> {
    let candidates =
        hardware_document.product_relations(&item.product_ref_id, &item.hardware2program_ref_id).collect::<Vec<_>>();
    let [(hardware, product, relation)] = candidates.as_slice() else {
        return Err(broken_catalog(
            catalog_path,
            item,
            format!("Product/H2P selectors resolve to {} exact chains, expected one", candidates.len()),
        ));
    };

    hardware
        .validate_application_program_relation(relation)
        .map_err(|error| broken_catalog(catalog_path, item, error.to_string()))?;

    let programs = if let Some(primary_reference) = relation.application_program_refs.first() {
        require_application_member(
            catalog_path,
            item,
            manufacturer_id,
            &primary_reference.ref_id,
            application_programs,
        )?;
        let secondary = relation
            .application_program_refs
            .get(1)
            .map(|reference| {
                require_application_member(
                    catalog_path,
                    item,
                    manufacturer_id,
                    &reference.ref_id,
                    application_programs,
                )?;
                Ok::<_, PackageStoreError>(reference.ref_id.clone())
            })
            .transpose()?;

        PackageProgramBinding::Application { primary: primary_reference.ref_id.clone(), secondary }
    } else {
        PackageProgramBinding::None
    };

    // RegistrationInfo remains useful product metadata, but its signature is
    // checked only at explicit import and never becomes catalogue state.
    let product_registration = registrations
        .get(&DeclaredRegistrationParent::Product(product.id.clone()))
        .cloned()
        .unwrap_or_else(PackageRegistration::unsigned);
    let hardware2program_registration = registrations
        .get(&DeclaredRegistrationParent::Hardware2Program(relation.id.clone()))
        .cloned()
        .unwrap_or_else(PackageRegistration::unsigned);
    let effective_registration = effective_declared_registration(&product_registration, &hardware2program_registration);
    let instantiation = if matches!(programs, PackageProgramBinding::None) {
        PackageInstantiation::CatalogOnly(PackageCatalogOnlyReason::NoApplicationProgram)
    } else if !effective_registration.status.is_instantiable() {
        PackageInstantiation::Blocked(PackageInstantiationBlock::RegistrationStatus(effective_registration.status))
    } else {
        PackageInstantiation::Programmable
    };
    let instantiable = instantiation == PackageInstantiation::Programmable;

    let mut chain_hasher = Sha256::new();
    hash_part(&mut chain_hasher, digest.as_bytes());
    hash_part(&mut chain_hasher, manufacturer_id.as_bytes());
    hash_part(&mut chain_hasher, item.id.as_bytes());
    hash_part(&mut chain_hasher, product.id.as_bytes());
    hash_part(&mut chain_hasher, hardware.id.as_bytes());
    hash_part(&mut chain_hasher, relation.id.as_bytes());
    hash_part(&mut chain_hasher, catalog_bytes);
    hash_part(&mut chain_hasher, hardware_bytes);
    for id in programs.ids() {
        hash_part(&mut chain_hasher, id.as_bytes());
    }
    let chain_digest = {
        let mut bytes = [0; SHA256_BYTES];
        bytes.copy_from_slice(&chain_hasher.finalize());
        PackageDigest(bytes)
    };

    Ok(PackageCatalogLeaf {
        selector: PackageCatalogSelector { package: digest, catalog_item_id: item.id.clone() },
        manufacturer_id: manufacturer_id.to_owned(),
        product_id: product.id.clone(),
        hardware_id: hardware.id.clone(),
        hardware2program_id: relation.id.clone(),
        programs,
        name: if item.name.trim().is_empty() {
            if !product.text.trim().is_empty() { product.text.clone() } else { hardware.name.clone() }
        } else {
            item.name.clone()
        },
        order_number: product.order_number.clone(),
        catalog_number: item.number.clone(),
        medium_types: relation.medium_types.clone(),
        mask_version: None,
        supports_data_secure: None,
        product_registration,
        hardware2program_registration,
        effective_registration,
        instantiation,
        instantiable,
        has_individual_address: hardware.has_individual_address,
        chain_digest,
    })
}

fn addressable() -> bool {
    true
}

fn require_application_member(
    catalog_path: &str,
    item: &CatalogItem,
    manufacturer_id: &str,
    application: &str,
    application_programs: &BTreeMap<String, String>,
) -> Result<(), PackageStoreError> {
    let path = application_programs
        .get(application)
        .ok_or_else(|| broken_catalog(catalog_path, item, format!("application program {application:?} is missing")))?;
    if !application.starts_with(&format!("{manufacturer_id}_A-")) {
        return Err(broken_catalog(
            catalog_path,
            item,
            format!("application {application:?} belongs to another manufacturer"),
        ));
    }
    let directory = catalog_path.rsplit_once('/').map_or("", |(directory, _)| directory);
    let expected =
        if directory.is_empty() { format!("{application}.xml") } else { format!("{directory}/{application}.xml") };
    if path != &expected {
        return Err(broken_catalog(
            catalog_path,
            item,
            format!("application {application:?} is stored at {path:?}, not canonical sibling path {expected:?}"),
        ));
    }
    Ok(())
}

fn effective_declared_registration(
    product: &PackageRegistration,
    relation: &PackageRegistration,
) -> PackageRegistration {
    fn rank(status: PackageRegistrationStatus) -> u8 {
        match status {
            PackageRegistrationStatus::FutureUseNotAllowed => 0,
            PackageRegistrationStatus::FutureUseNotRecommended => 1,
            PackageRegistrationStatus::Unsigned => 2,
            PackageRegistrationStatus::Unregistered => 3,
            PackageRegistrationStatus::Registered => 4,
            PackageRegistrationStatus::Certified => 5,
        }
    }

    if rank(product.status) < rank(relation.status) { product.clone() } else { relation.clone() }
}

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn broken_catalog(path: &str, item: &CatalogItem, reason: impl Into<String>) -> PackageStoreError {
    PackageStoreError::BrokenCatalogRelation {
        path: path.to_owned(),
        catalog_item: item.id.clone(),
        reason: reason.into(),
    }
}

// ============================================================================
// Virtual cross-package catalogue merge
// ============================================================================

fn section_leaves(sections: &[PackageCatalogSection]) -> std::vec::IntoIter<&PackageCatalogLeaf> {
    fn collect<'a>(sections: &'a [PackageCatalogSection], output: &mut Vec<&'a PackageCatalogLeaf>) {
        for section in sections {
            output.extend(&section.items);
            collect(&section.subsections, output);
        }
    }
    let mut output = Vec::new();
    collect(sections, &mut output);
    output.into_iter()
}

fn owned_section_leaves(sections: Vec<PackageCatalogSection>) -> std::vec::IntoIter<PackageCatalogLeaf> {
    fn collect(sections: Vec<PackageCatalogSection>, output: &mut Vec<PackageCatalogLeaf>) {
        for section in sections {
            output.extend(section.items);
            collect(section.subsections, output);
        }
    }
    let mut output = Vec::new();
    collect(sections, &mut output);
    output.into_iter()
}

#[cfg(feature = "signing")]
fn count_manufacturer_leaves(manufacturer: &PackageCatalogManufacturer) -> usize {
    section_leaves(&manufacturer.sections).count()
}

fn merge_package_catalog(index: &mut PackageCatalogIndex, package: Vec<PackageCatalogManufacturer>) {
    for manufacturer in package {
        if let Some(existing) = index.manufacturers.iter_mut().find(|candidate| candidate.id == manufacturer.id) {
            let incoming_provenance = manufacturer.name_source_schema_version.zip(manufacturer.name_source_version);
            let existing_provenance = existing.name_source_schema_version.zip(existing.name_source_version);
            if incoming_provenance > existing_provenance {
                existing.name = manufacturer.name.clone();
                existing.name_source_schema_version = manufacturer.name_source_schema_version;
                existing.name_source_version = manufacturer.name_source_version;
            }
            merge_sections(&mut existing.sections, manufacturer.sections);
        } else {
            index.manufacturers.push(manufacturer);
        }
    }
}

fn merge_sections(target: &mut Vec<PackageCatalogSection>, source: Vec<PackageCatalogSection>) {
    for mut incoming in source {
        let compatible = target.iter_mut().find(|section| {
            section.id == incoming.id
                && section.name == incoming.name
                && section.number == incoming.number
                && section.default_language == incoming.default_language
        });
        if let Some(existing) = compatible {
            existing.packages.append(&mut incoming.packages);
            existing.packages.sort_unstable();
            existing.packages.dedup();
            existing.items.append(&mut incoming.items);
            existing.items.sort_by(|left, right| left.selector.cmp(&right.selector));
            merge_sections(&mut existing.subsections, incoming.subsections);
        } else {
            target.push(incoming);
        }
    }
    target.sort_by(|left, right| {
        (&left.number, &left.name, &left.id, &left.packages).cmp(&(
            &right.number,
            &right.name,
            &right.id,
            &right.packages,
        ))
    });
}

fn materialize_baggages<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    application_programs: &BTreeMap<String, String>,
    manufacturer_id: &str,
    application_id: &str,
    cache_key: PackageDigest,
    application: &Knx,
    cache_root: &Path,
) -> Result<Option<PathBuf>, PackageStoreError> {
    validate_store_component(manufacturer_id, "manufacturer ID is not a portable store component")?;

    let application_path = application_programs
        .get(application_id)
        .ok_or_else(|| PackageStoreError::UnknownApplicationProgram(application_id.to_owned()))?;
    let program = application
        .manufacturer_data
        .manufacturer
        .application_programs
        .programs
        .iter()
        .find(|program| program.id == application_id)
        .ok_or_else(|| PackageStoreError::InvalidApplicationProgram {
            path: application_path.clone(),
            reason: format!("document does not declare indexed application {application_id:?}"),
        })?;
    let baggage_ids = referenced_application_baggages(program);
    if baggage_ids.is_empty() {
        return Ok(None);
    }

    let manufacturer_directory = application_path.rsplit_once('/').map(|(directory, _)| directory).unwrap_or("");
    let manifest_path = if manufacturer_directory.is_empty() {
        "Baggages.xml".to_owned()
    } else {
        format!("{manufacturer_directory}/Baggages.xml")
    };
    let manifest_bytes = read_zip_member(archive, &manifest_path)?;
    let manifest_xml = std::str::from_utf8(&manifest_bytes)
        .map_err(|source| ArchiveError::Utf8 { path: manifest_path.clone(), source })?;
    let manifest: BaggagesKnx = quick_xml::de::from_str(manifest_xml.trim_start_matches('\u{feff}'))
        .map_err(|source| PackageStoreError::Xml { path: manifest_path.clone(), source })?;
    if manifest.manufacturer_data.manufacturer.ref_id != manufacturer_id {
        return Err(PackageStoreError::InvalidBaggageManifest {
            path: manifest_path,
            reason: format!(
                "manifest manufacturer {:?} does not match selected manufacturer {:?}",
                manifest.manufacturer_data.manufacturer.ref_id, manufacturer_id
            ),
        });
    }

    let mut entries = BTreeMap::new();
    if let Some(baggages) = manifest.manufacturer_data.manufacturer.baggages {
        for baggage in baggages.items {
            if entries.insert(baggage.id.clone(), baggage).is_some() {
                return Err(PackageStoreError::InvalidBaggageManifest {
                    path: manifest_path,
                    reason: "a baggage ID occurs more than once".to_owned(),
                });
            }
        }
    }

    let mut requested_entries = Vec::with_capacity(baggage_ids.len());
    for id in baggage_ids {
        let entry = entries.get(&id).ok_or_else(|| PackageStoreError::InvalidBaggageManifest {
            path: manifest_path.clone(),
            reason: format!("application references missing baggage {id:?}"),
        })?;
        let relative_path = baggage_relative_path(&entry.target_path, &entry.name)?;
        let member_path = if manufacturer_directory.is_empty() {
            relative_path.clone()
        } else {
            format!("{manufacturer_directory}/{relative_path}")
        };
        requested_entries.push((relative_path, member_path));
    }

    ensure_plain_cache_directory(&cache_root)?;
    let destination =
        cache_root.join(format!("{}-baggage-v{MATERIALIZED_BAGGAGE_VERSION}", cache_key.directory_name()));
    if let Some(root) = existing_materialized_root(&destination, manufacturer_id)? {
        return Ok(Some(root));
    }

    // Opening a cached device should only parse the small manifest. Inflate
    // image and plug-in payloads once, when constructing this cache version.
    let mut payloads = Vec::with_capacity(requested_entries.len());
    for (relative_path, member_path) in requested_entries {
        let bytes = read_zip_member(archive, &member_path)?;
        payloads.push((relative_path, bytes));
    }

    let temporary = cache_root.join(format!(
        ".{}.tmp-{}-{}",
        cache_key.directory_name(),
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&temporary)
        .map_err(|source| PackageStoreError::CreateTemporary { path: temporary.clone(), source })?;
    let mut temporary_guard = TemporaryDirectoryGuard::new(temporary.clone());
    let manufacturer_root = temporary.join(manufacturer_id);
    fs::create_dir(&manufacturer_root)
        .map_err(|source| PackageStoreError::CreateTemporary { path: manufacturer_root.clone(), source })?;
    write_synced_file(&manufacturer_root.join("Baggages.xml"), &manifest_bytes)?;
    for (relative_path, bytes) in payloads {
        let target = manufacturer_root.join(&relative_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|source| PackageStoreError::WriteStoredFile { path: parent.to_owned(), source })?;
        }
        write_synced_file(&target, &bytes)?;
    }
    sync_directory_tree(&temporary)?;

    match fs::rename(&temporary, &destination) {
        Ok(()) => temporary_guard.disarm(),
        Err(source) if fs::symlink_metadata(&destination).is_ok() => drop(source),
        Err(source) => return Err(PackageStoreError::InstallPackage { path: destination.clone(), source }),
    }
    sync_directory(&cache_root)?;
    let root = existing_materialized_root(&destination, manufacturer_id)?.ok_or_else(|| {
        PackageStoreError::UnsafeStoreNode { path: destination.clone(), expected: "complete baggage directory" }
    })?;
    Ok(Some(root))
}

fn read_master_data_xml<R: Read + Seek>(archive: &mut zip::ZipArchive<R>) -> Result<Option<String>, PackageStoreError> {
    let path = master_data_path(archive.file_names())?.map(str::to_owned);
    path.map(|path| {
        String::from_utf8(read_zip_member(archive, &path)?)
            .map_err(|error| PackageStoreError::InvalidMasterData { path, reason: error.to_string() })
    })
    .transpose()
}

fn load_selected_product<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    applications: &BTreeMap<String, String>,
    leaf: &PackageCatalogLeaf,
) -> Result<SelectedProduct, PackageStoreError> {
    load_selected_product_inner(archive, applications, leaf, true)
}

fn load_selected_product_inner<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    applications: &BTreeMap<String, String>,
    leaf: &PackageCatalogLeaf,
    bind_bundled_master: bool,
) -> Result<SelectedProduct, PackageStoreError> {
    let id = leaf.application_program_id().ok_or_else(|| PackageStoreError::NotInstantiable {
        catalog_item: leaf.selector.catalog_item_id.clone(),
        reason: leaf.instantiation,
    })?;
    let document = read_application_document(archive, applications, id)?;
    let relation = ApplicationProgramRelation {
        catalog_item_id: Some(leaf.selector.catalog_item_id.clone()),
        product_id: Some(leaf.product_id.clone()),
        hardware: HardwareApplicationProgramPairing {
            hardware_id: leaf.hardware_id.clone(),
            hardware2program_id: leaf.hardware2program_id.clone(),
            application_program_id: id.to_owned(),
            application_program_2: match leaf.application_program_2_id() {
                Some(id) => HardwareApplicationProgram2::Present { application_program_id: id.to_owned() },
                None => HardwareApplicationProgram2::Absent,
            },
            has_individual_address: leaf.has_individual_address,
        },
    };
    let master = if bind_bundled_master { read_master_data_xml(archive)? } else { None };
    let selected = SelectedProduct::from_document(document, Some(relation), master.as_deref())?;
    bind_secondary_application(archive, applications, selected)
}

/// Bind the selected relation's secondary PEI Program when the package
/// contains it. A missing document leaves AP2 declared but unbound, so
/// compilation still refuses the product instead of omitting the program.
fn bind_secondary_application<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    applications: &BTreeMap<String, String>,
    selected: SelectedProduct,
) -> Result<SelectedProduct, PackageStoreError> {
    let crate::product::ApplicationProgram2Binding::Present { application_program_id, .. } =
        selected.product().application_program_2()
    else {
        return Ok(selected);
    };
    if !applications.contains_key(application_program_id) {
        return Ok(selected);
    }
    let document = read_application_document(archive, applications, &application_program_id.clone())?;
    Ok(selected.with_secondary_document(document)?)
}

fn read_application_document<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    applications: &BTreeMap<String, String>,
    id: &str,
) -> Result<Knx, PackageStoreError> {
    let path = applications.get(id).ok_or_else(|| PackageStoreError::UnknownApplicationProgram(id.to_owned()))?;
    let bytes = read_zip_member(archive, path)?;
    let xml = std::str::from_utf8(&bytes).map_err(|source| ArchiveError::Utf8 { path: path.clone(), source })?;
    let document = parse_application_program(xml)
        .map_err(|source| PackageStoreError::ApplicationParse { application: id.to_owned(), source })?;
    let programs = &document.manufacturer_data.manufacturer.application_programs.programs;
    if !matches!(programs.as_slice(), [program] if program.id == id) {
        return Err(PackageStoreError::InvalidApplicationProgram {
            path: path.clone(),
            reason: format!("document must contain exactly the indexed application {id:?}"),
        });
    }
    Ok(document)
}

/// Read-only, header-indexed `.knxprod` source. Opening never imports, extracts,
/// verifies signatures, or fully parses an application. Selection loads only
/// the requested document; immutable store imports use the same index builder.
///
/// ```no_run
/// use zweidraehte_ets_files::archive::{PackageArchive, PackageStoreError};
///
/// let archive = PackageArchive::open("switch.knxprod")?;
/// let selected = archive.load_product("M-00FA_CI-1")?;
/// println!("{}", selected.program().name);
/// # Ok::<(), PackageStoreError>(())
/// ```
#[derive(Debug, Clone)]
pub struct PackageArchive {
    bytes: Vec<u8>,
    index: PersistedPackageIndex,
}

impl PackageArchive {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PackageStoreError> {
        let path = path.as_ref();
        let bytes =
            fs::read(path).map_err(|source| PackageStoreError::ReadArchive { path: path.to_owned(), source })?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, PackageStoreError> {
        let index = build_package_index(&bytes, PackageDigest::of(&bytes))?;
        Ok(Self { bytes, index })
    }

    /// Index a standalone package with an explicit aggregate expanded-size limit.
    ///
    /// Large multi-product packages can exceed the default 512 MiB even when
    /// each selected application is small. This changes only the sum of declared
    /// member sizes, not the per-member size, compression-ratio, entry-count or
    /// path checks. It is not a bound on the parsed product's memory footprint.
    pub fn from_bytes_with_expanded_size_limit(
        bytes: Vec<u8>,
        max_expanded_bytes: u64,
    ) -> Result<Self, PackageStoreError> {
        let index = build_package_index_with_size_limit(&bytes, PackageDigest::of(&bytes), max_expanded_bytes)?;
        Ok(Self { bytes, index })
    }

    pub fn catalog(&self) -> &[PackageCatalogManufacturer] {
        &self.index.catalog
    }

    pub fn leaves(&self) -> impl Iterator<Item = &PackageCatalogLeaf> {
        self.index.catalog.iter().flat_map(|manufacturer| section_leaves(&manufacturer.sections))
    }

    /// Read the exact bundled Master Data without inflating application bodies.
    ///
    /// Returns `None` when absent and an error for ambiguous documents, invalid
    /// UTF-8, decompression or CRC failure. The caller owns the returned buffer;
    /// this archive does not cache decompressed members.
    pub fn master_data_xml(&self) -> Result<Option<String>, PackageStoreError> {
        read_master_data_xml(&mut self.open_zip()?)
    }

    /// Load an exact catalogue selection for binding to caller-selected Master Data.
    ///
    /// AP1 and its declared AP2 are parsed on demand; catalogue and hardware
    /// identity are checked as for [`Self::load_product`]. Bundled Master Data
    /// is intentionally not read or bound. The caller must bind its authoritative
    /// document before commissioning. Missing/invalid selected entries return
    /// errors; unrelated member bodies are not validated by this operation.
    pub fn load_product_unbound(&self, catalog_item: &str) -> Result<SelectedProduct, PackageStoreError> {
        let leaf = self.leaves().find(|leaf| leaf.selector.catalog_item_id == catalog_item).ok_or_else(|| {
            PackageStoreError::UnknownCatalogItem(PackageCatalogSelector {
                package: self.index.package,
                catalog_item_id: catalog_item.to_owned(),
            })
        })?;

        load_selected_product_inner(&mut self.open_zip()?, &self.index.application_programs, leaf, false)
    }

    /// Inspect a catalogue item, including items blocked for project instantiation.
    pub fn load_product(&self, catalog_item: &str) -> Result<SelectedProduct, PackageStoreError> {
        let leaf = self.leaves().find(|leaf| leaf.selector.catalog_item_id == catalog_item).ok_or_else(|| {
            PackageStoreError::UnknownCatalogItem(PackageCatalogSelector {
                package: self.index.package,
                catalog_item_id: catalog_item.to_owned(),
            })
        })?;
        load_selected_product(&mut self.open_zip()?, &self.index.application_programs, leaf)
    }

    /// Materialize referenced baggage into an explicitly selected cache directory.
    /// The caller owns that directory's lifetime; opening a package never creates it.
    pub fn materialize_baggages_from_document(
        &self,
        document: &Knx,
        cache: &Path,
    ) -> Result<Option<PathBuf>, PackageStoreError> {
        let programs = &document.manufacturer_data.manufacturer.application_programs.programs;
        let [program] = programs.as_slice() else {
            return Err(ProductError::AmbiguousApplicationProgram { count: programs.len() }.into());
        };
        let key = PackageDigest::of(format!("{}/{}", self.index.package, program.id).as_bytes());
        materialize_baggages(
            &mut self.open_zip()?,
            &self.index.application_programs,
            &document.manufacturer_data.manufacturer.ref_id,
            &program.id,
            key,
            document,
            cache,
        )
    }

    /// Load an application when its catalogue identity is unambiguous or absent.
    /// Multiple catalogue leaves require `load_product` with an exact item ID.
    pub fn load_application(&self, id: &str) -> Result<SelectedProduct, PackageStoreError> {
        let leaves = self.leaves().filter(|leaf| leaf.application_program_id() == Some(id)).collect::<Vec<_>>();
        match leaves.as_slice() {
            [leaf] => return self.load_product(&leaf.selector.catalog_item_id),
            [] => {}
            _ => {
                return Err(PackageStoreError::AmbiguousApplicationSelection {
                    application: id.to_owned(),
                    count: leaves.len(),
                });
            }
        }
        let mut archive = self.open_zip()?;
        let document = read_application_document(&mut archive, &self.index.application_programs, id)?;
        let application_path = &self.index.application_programs[id];
        let directory = application_path.rsplit_once('/').map_or("", |(directory, _)| directory);
        let hardware_path =
            if directory.is_empty() { "Hardware.xml".to_owned() } else { format!("{directory}/Hardware.xml") };
        let has_hardware = archive.file_names().any(|path| path == hardware_path);
        let relation = if has_hardware {
            let bytes = read_zip_member(&mut archive, &hardware_path)?;
            let xml = std::str::from_utf8(&bytes)
                .map_err(|source| ArchiveError::Utf8 { path: hardware_path.clone(), source })?;
            let hardware = quick_xml::de::from_str(xml.trim_start_matches('\u{feff}'))
                .map_err(|source| PackageStoreError::Xml { path: hardware_path, source })?;
            resolve_document_application_pairing(&document, &hardware)?
        } else {
            None
        };
        let master = read_master_data_xml(&mut archive)?;
        let selected = SelectedProduct::from_document(document, relation, master.as_deref())?;
        bind_secondary_application(&mut archive, &self.index.application_programs, selected)
    }

    pub fn importable_devices(&self) -> Result<Vec<KnxprodDevice>, PackageStoreError> {
        let mut devices = Vec::new();
        let mut represented = BTreeSet::new();
        for leaf in self.leaves() {
            represented.extend(leaf.application_program_ids().map(str::to_owned));
            if let Some(application) = leaf.application_program_id() {
                devices.push(KnxprodDevice {
                    catalog_item_id: Some(leaf.selector.catalog_item_id.clone()),
                    product_id: Some(leaf.product_id.clone()),
                    hardware_id: Some(leaf.hardware_id.clone()),
                    application_program_id: application.to_owned(),
                    name: leaf.name.clone(),
                    order_number: Some(leaf.order_number.clone()),
                    mask_version: leaf.mask_version.clone().unwrap_or_default(),
                    supports_data_secure: leaf.supports_data_secure.unwrap_or(false),
                });
            }
        }
        // Incomplete/generated archives may have no catalogue. Retain those
        // choices using headers too, and never expose an already-bound AP2 as AP1.
        let mut archive = self.open_zip()?;
        for (id, path) in &self.index.application_programs {
            if represented.contains(id) {
                continue;
            }
            let header = read_application_header(&mut archive, path, id)?;
            if header.program_type != "ApplicationProgram" {
                continue;
            }
            devices.push(KnxprodDevice {
                catalog_item_id: None,
                product_id: None,
                hardware_id: None,
                application_program_id: id.clone(),
                name: header.name,
                order_number: None,
                mask_version: header.mask_version,
                supports_data_secure: header.is_secure_enabled,
            });
        }
        devices.sort_by(|a, b| {
            (&a.name, &a.order_number, &a.application_program_id, &a.catalog_item_id).cmp(&(
                &b.name,
                &b.order_number,
                &b.application_program_id,
                &b.catalog_item_id,
            ))
        });
        Ok(devices)
    }

    fn open_zip(&self) -> Result<zip::ZipArchive<std::io::Cursor<&[u8]>>, PackageStoreError> {
        zip::ZipArchive::new(std::io::Cursor::new(self.bytes.as_slice()))
            .map_err(ArchiveError::from)
            .map_err(Into::into)
    }
}

#[cfg(all(test, feature = "signing"))]
mod index_tests {
    use std::io::{Cursor, Write as _};

    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;

    use super::*;

    const ROOT: &str = r#"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="test" ToolVersion="1" xmlns="http://knx.org/xml/project/23""#;
    const MANUFACTURER: &str = "M-00FA";
    const AP1: &str = "M-00FA_A-0001-01-0000";
    const AP2: &str = "M-00FA_A-0002-01-0000";
    const PRODUCT: &str = "M-00FA_H-1_P-1";
    const RELATION: &str = "M-00FA_H-1_HP-1";
    const ITEM: &str = "M-00FA_CI-1";
    const BAGGAGE: &str = "M-00FA_BG--icon.2Epng";

    fn application(id: &str, secure: bool, baggage: Option<&str>) -> String {
        let baggage =
            baggage.map(|id| format!(r#"<Extension><Baggage RefId="{id}"/></Extension>"#)).unwrap_or_default();
        format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="{MANUFACTURER}"><ApplicationPrograms><ApplicationProgram Id="{id}" ApplicationNumber="1" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-07B0" Name="Switch Program" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="en-US" DynamicTableManagement="false" Linkable="false" IsSecureEnabled="{secure}"><Static><Code/>{baggage}</Static></ApplicationProgram></ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#
        )
    }

    fn application_with_picture(id: &str, baggage: &str) -> String {
        application(id, false, None).replacen(
            "<Static><Code/>",
            &format!(
                r#"<Static><Code/><ParameterTypes><ParameterType Id="{id}_PT-1" Name="Preview"><TypePicture RefId="{baggage}" HorizontalAlignment="Middle"/></ParameterType></ParameterTypes>"#
            ),
            1,
        )
    }

    fn malformed_application_header(id: &str) -> String {
        format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="{MANUFACTURER}"><ApplicationPrograms><ApplicationProgram Id="{id}" ApplicationNumber="1" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="Broken after header" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="en-US" DynamicTableManagement="false" Linkable="false"><Static>"#
        )
    }

    fn hardware(product_registration: &str, relation_registration: &str, has_application: bool) -> String {
        let reference =
            has_application.then(|| format!(r#"<ApplicationProgramRef RefId="{AP1}"/>"#)).unwrap_or_default();
        format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="{MANUFACTURER}"><Hardware><Hardware Id="M-00FA_H-1" Name="Hardware" SerialNumber="1" VersionNumber="1" HasIndividualAddress="true" HasApplicationProgram="{has_application}"><Products><Product Id="{PRODUCT}" Text="Switch" OrderNumber="S-1" IsRailMounted="false" DefaultLanguage="en-US">{product_registration}</Product></Products><Hardware2Programs><Hardware2Program Id="{RELATION}" MediumTypes="MT-0">{reference}{relation_registration}</Hardware2Program></Hardware2Programs></Hardware></Hardware></Manufacturer></ManufacturerData></KNX>"#
        )
    }

    fn catalog(item_id: &str) -> String {
        format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="{MANUFACTURER}"><Catalog><CatalogSection Id="M-00FA_CS-1" Name="Switches" Number="1" DefaultLanguage="en-US"><CatalogItem Id="{item_id}" Name="Bench switch" Number="7" ProductRefId="{PRODUCT}" Hardware2ProgramRefId="{RELATION}" DefaultLanguage="en-US"/></CatalogSection></Catalog></Manufacturer></ManufacturerData></KNX>"#
        )
    }

    fn master_data(schema: u16, version: u64, name: &str) -> String {
        format!(
            r#"<KNX xmlns="http://knx.org/xml/project/{schema}"><MasterData Version="{version}"><DatapointTypes/><Manufacturers><Manufacturer Id="{MANUFACTURER}" Name="{name}"/><Manufacturer Id="M-0001" Name="Other"/></Manufacturers><Languages><Language Identifier="en-US"/></Languages></MasterData></KNX>"#
        )
    }

    fn baggages() -> String {
        format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="{MANUFACTURER}"><Baggages><Baggage TargetPath="" Name="icon.png" Id="{BAGGAGE}"><FileInfo TimeInfo="2026-01-01T00:00:00Z"/></Baggage><Baggage TargetPath="" Name="unused.bin" Id="M-00FA_BG--unused.2Ebin"/></Baggages></Manufacturer></ManufacturerData></KNX>"#
        )
    }

    fn archive(entries: Vec<(String, Vec<u8>)>) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (path, bytes) in entries {
            writer.start_file(path, options).expect("entry starts");
            writer.write_all(&bytes).expect("entry writes");
        }
        writer.finish().expect("archive finishes").into_inner()
    }

    fn product_archive(application_xml: String, master: Option<String>) -> Vec<u8> {
        let mut entries = vec![
            (format!("{MANUFACTURER}/{AP1}.xml"), application_xml.into_bytes()),
            (format!("{MANUFACTURER}/Hardware.xml"), hardware("", "", true).into_bytes()),
            (format!("{MANUFACTURER}/Catalog.xml"), catalog(ITEM).into_bytes()),
        ];
        if let Some(master) = master {
            entries.push(("knx_master.xml".to_owned(), master.into_bytes()));
        }
        archive(entries)
    }

    fn store() -> (TempDir, PackageStore) {
        let temporary = TempDir::new().expect("temporary directory");
        let store = PackageStore::new(temporary.path().join("packages"));
        (temporary, store)
    }

    #[test]
    fn archive_paths_agree_on_application_capability_rules() {
        // Capabilities permit fewer bindings, including catalogue-only leaves.
        // AP1 and AP2 bindings win over false flags, as in ETS; references
        // beyond AP1/AP2 are invalid.
        for (has_ap1, has_ap2, references, valid) in [
            (false, false, 0, true),
            (true, true, 0, true),
            (true, true, 1, true),
            (true, true, 2, true),
            (false, true, 1, true),
            (true, false, 2, true),
            (true, true, 3, false),
        ] {
            let refs = [AP1, AP2, AP2][..references]
                .iter()
                .map(|id| format!(r#"<ApplicationProgramRef RefId="{id}"/>"#))
                .collect::<String>();
            let hardware = hardware("", "", true)
                .replace(
                    r#"HasApplicationProgram="true""#,
                    &format!(r#"HasApplicationProgram="{has_ap1}" HasApplicationProgram2="{has_ap2}""#),
                )
                .replace(&format!(r#"<ApplicationProgramRef RefId="{AP1}"/>"#), &refs);
            let bytes = archive(vec![
                (format!("{MANUFACTURER}/{AP1}.xml"), application(AP1, false, None).into_bytes()),
                (
                    format!("{MANUFACTURER}/{AP2}.xml"),
                    application(AP2, false, None)
                        .replace(r#"ProgramType="ApplicationProgram""#, r#"ProgramType="PeiProgram""#)
                        .into_bytes(),
                ),
                (format!("{MANUFACTURER}/Hardware.xml"), hardware.into_bytes()),
                (format!("{MANUFACTURER}/Catalog.xml"), catalog(ITEM).into_bytes()),
            ]);
            let legacy = KnxprodArchive::from_bytes(&bytes).expect("archive bytes are valid");
            let pairing = legacy.application_program_pairing(AP1);
            let indexed = PackageArchive::from_bytes(bytes);
            assert_eq!(pairing.is_ok(), valid, "legacy: AP1={has_ap1}, AP2={has_ap2}, refs={references}");
            assert_eq!(indexed.is_ok(), valid, "indexed: AP1={has_ap1}, AP2={has_ap2}, refs={references}");
            if valid {
                let indexed = indexed.expect("valid indexed relation");
                let leaf = indexed.leaves().next().expect("catalogue leaf");
                if references == 0 {
                    assert_eq!(pairing.expect("valid empty relation"), None);
                    assert_eq!(leaf.programs, PackageProgramBinding::None);
                } else {
                    let relation = legacy
                        .application_program_relation(AP1, Some(PRODUCT))
                        .expect("exact legacy selection")
                        .expect("selected relation");
                    let selected = indexed.load_product(ITEM).expect("exact indexed selection");
                    assert_eq!(selected.relation(), Some(&relation));
                }
            } else {
                assert!(matches!(indexed, Err(PackageStoreError::BrokenCatalogRelation { .. })));
            }
        }
    }

    #[test]
    fn duplicate_catalogue_chains_are_ambiguous_in_both_readers() {
        let hardware = hardware("", "", true);
        let mut document: HardwareKnx = crate::xml::from_str(&hardware).expect("valid hardware fixture");
        let relations =
            &mut document.manufacturer_data.manufacturer.hardware.hardware[0].hardware2programs.hardware2programs;
        relations.push(relations[0].clone());
        let hardware = crate::xml::to_string(&document).expect("hardware serializes");
        let bytes = archive(vec![
            (format!("{MANUFACTURER}/{AP1}.xml"), application(AP1, false, None).into_bytes()),
            (format!("{MANUFACTURER}/Hardware.xml"), hardware.into_bytes()),
            (format!("{MANUFACTURER}/Catalog.xml"), catalog(ITEM).into_bytes()),
        ]);
        let legacy = KnxprodArchive::from_bytes(&bytes).expect("valid archive bytes");
        assert!(matches!(
            legacy.application_program_relation(AP1, Some(PRODUCT)),
            Err(ProductError::AmbiguousCatalogueProgramRelation { count: 2, .. })
        ));
        let error = match PackageArchive::from_bytes(bytes) {
            Ok(_) => panic!("duplicate relation must be rejected"),
            Err(error) => error,
        };
        // The indexed reader checks uniqueness of registration parent IDs
        // before resolving catalogue chains; retain that earlier diagnostic.
        assert!(matches!(error, PackageStoreError::InvalidRegistration { id, reason, .. }
            if id == RELATION && reason == "parent ID occurs more than once"));
    }

    #[test]
    fn standalone_and_stored_loading_preserve_exact_catalogue_items() {
        let second_item = "M-00FA_CI-second";
        let mut catalogue: CatalogKnx = quick_xml::de::from_str(&catalog(ITEM)).expect("catalogue fixture");
        let section = &mut catalogue.manufacturer_data.manufacturer.catalog.catalog_sections[0];
        let mut second = section.catalog_items[0].clone();
        second.id = second_item.to_owned();
        section.catalog_items.push(second);
        let catalogue = crate::xml::to_string(&catalogue).expect("catalogue serializes");
        let bytes = archive(vec![
            (format!("{MANUFACTURER}/{AP1}.xml"), application(AP1, false, None).into_bytes()),
            (format!("{MANUFACTURER}/Hardware.xml"), hardware("", "", true).into_bytes()),
            (format!("{MANUFACTURER}/Catalog.xml"), catalogue.into_bytes()),
            ("knx_master.xml".to_owned(), master_data(23, 168, "Vendor").into_bytes()),
        ]);
        let reader = PackageArchive::from_bytes(bytes.clone()).expect("standalone index");
        let editing_archive = KnxprodArchive::from_bytes(&bytes).expect("editing archive");
        assert_eq!(reader.importable_devices().expect("choices").len(), 2);
        assert_eq!(editing_archive.importable_devices().expect("same choices").len(), 2);
        assert!(matches!(
            reader.load_application(AP1),
            Err(PackageStoreError::AmbiguousApplicationSelection { count: 2, .. })
        ));

        let (_temporary, store) = store();
        let imported = store.import_bytes(&bytes).expect("package import");
        for item in [ITEM, second_item] {
            let direct = reader.load_product(item).expect("exact standalone selection");
            let stored = imported
                .package
                .load_product(&PackageCatalogSelector {
                    package: imported.package.digest(),
                    catalog_item_id: item.to_owned(),
                })
                .expect("exact stored selection");
            assert_eq!(direct.relation().expect("selected relation").catalog_item_id.as_deref(), Some(item));
            assert_eq!(direct.product().application_program_2(), stored.product().application_program_2());
            assert_eq!(direct.product().master_data().expect("bundled master").document_version(), "168");
            assert_eq!(direct.program().id, AP1);
        }
    }

    #[test]
    fn standalone_catalogue_does_not_parse_application_bodies() {
        let reader = PackageArchive::from_bytes(product_archive(malformed_application_header(AP1), None))
            .expect("headers suffice for opening");
        assert_eq!(reader.importable_devices().expect("headers suffice for listing").len(), 1);
        assert!(matches!(reader.load_product(ITEM), Err(PackageStoreError::ApplicationParse { .. })));
    }

    #[test]
    fn explicit_expanded_size_limit_has_an_exact_boundary() {
        let bytes = product_archive(application(AP1, false, None), None);
        let mut zip = zip::ZipArchive::new(Cursor::new(&bytes)).expect("ZIP index");
        let total: u64 = (0..zip.len()).map(|index| zip.by_index_raw(index).expect("member").size()).sum();
        drop(zip);

        let error = PackageArchive::from_bytes_with_expanded_size_limit(bytes.clone(), total - 1)
            .expect_err("one byte below declared total");
        assert!(matches!(error, PackageStoreError::ArchiveTotalSizeLimit { limit } if limit == total - 1));

        let reader = PackageArchive::from_bytes_with_expanded_size_limit(bytes, total).expect("exact limit");
        assert_eq!(reader.load_product_unbound(ITEM).expect("selected application").program().id, AP1);
    }

    #[test]
    fn unbound_selection_preserves_identity_and_caller_master_data() {
        let bundled = master_data(23, 168, "Bundled");
        let bytes = product_archive(application(AP1, false, None), Some(bundled.clone()));
        let reader = PackageArchive::from_bytes(bytes).expect("package index");
        assert_eq!(reader.master_data_xml().expect("bundled document"), Some(bundled));

        let selected = reader.load_product_unbound(ITEM).expect("unbound selection");
        assert_eq!(selected.program().id, AP1);
        assert_eq!(selected.relation().expect("relation").hardware.hardware2program_id, RELATION);
        assert!(selected.product().master_data().is_none());
        let caller = master_data(23, 169, "Caller");
        let document = std::sync::Arc::new(caller.parse().expect("caller document"));
        let bound = selected.bind_master_data(document).expect("bind caller document once");
        assert_eq!(bound.product().master_data().expect("bound document").source_xml(), caller);
        assert!(reader.load_product_unbound("missing").is_err());
    }

    #[test]
    fn selected_reader_skips_unrelated_crc_failure_but_rejects_selected_failure() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        let application_path = format!("{MANUFACTURER}/{AP1}.xml");
        for (path, bytes) in [
            (application_path.clone(), application(AP1, false, None).into_bytes()),
            (format!("{MANUFACTURER}/Hardware.xml"), hardware("", "", true).into_bytes()),
            (format!("{MANUFACTURER}/Catalog.xml"), catalog(ITEM).into_bytes()),
            ("unrelated.bin".to_owned(), vec![42; 1024]),
        ] {
            writer.start_file(path, options).expect("entry starts");
            writer.write_all(&bytes).expect("entry writes");
        }
        let original = writer.finish().expect("ZIP finishes").into_inner();

        let mut index = zip::ZipArchive::new(Cursor::new(&original)).expect("ZIP index");
        let unused_offset = index.by_name("unrelated.bin").expect("unrelated entry").data_start() as usize;
        let selected = index.by_name(&application_path).expect("application entry");
        let selected_end = (selected.data_start() + selected.size() - 1) as usize;
        drop(selected);
        drop(index);

        let mut unrelated_corrupt = original.clone();
        unrelated_corrupt[unused_offset] ^= 1;
        assert!(super::super::RawArchive::from_bytes(&unrelated_corrupt).is_err());
        let reader = PackageArchive::from_bytes(unrelated_corrupt).expect("metadata only index");
        assert_eq!(reader.load_product_unbound(ITEM).expect("unrelated payload is not read").program().id, AP1);

        let mut selected_corrupt = original;
        selected_corrupt[selected_end] ^= 1;
        let reader = PackageArchive::from_bytes(selected_corrupt).expect("header remains readable");
        assert!(reader.load_product_unbound(ITEM).is_err());
    }

    #[test]
    fn package_readers_agree_on_nested_and_ambiguous_master_data() {
        for ambiguous in [false, true] {
            let master = master_data(23, 168, "Vendor");
            let mut entries = vec![
                (format!("{MANUFACTURER}/{AP1}.xml"), application(AP1, false, None).into_bytes()),
                (format!("{MANUFACTURER}/Hardware.xml"), hardware("", "", true).into_bytes()),
                (format!("{MANUFACTURER}/Catalog.xml"), catalog(ITEM).into_bytes()),
                (format!("{MANUFACTURER}/knx_master.xml"), master.as_bytes().to_vec()),
            ];
            if ambiguous {
                entries.push(("knx_master.xml".to_owned(), master.as_bytes().to_vec()));
            }
            let bytes = archive(entries);
            let reader =
                PackageArchive::from_bytes(bytes.clone()).expect("catalogue may inspect multiple name sources");
            let (_temporary, store) = store();
            let imported = store.import_bytes(&bytes).expect("package import");
            if ambiguous {
                assert!(matches!(KnxprodArchive::from_bytes(&bytes), Err(ArchiveError::AmbiguousMasterData(_))));
                assert!(matches!(
                    reader.load_product(ITEM),
                    Err(PackageStoreError::Archive(ArchiveError::AmbiguousMasterData(_)))
                ));
                assert!(matches!(
                    imported.package.master_data_xml(),
                    Err(PackageStoreError::Archive(ArchiveError::AmbiguousMasterData(_)))
                ));
            } else {
                assert_eq!(
                    KnxprodArchive::from_bytes(&bytes).expect("editing archive").master_data_xml(),
                    Some(master.as_str())
                );
                assert_eq!(
                    imported.package.master_data_xml().expect("stored master").as_deref(),
                    Some(master.as_str())
                );
                assert_eq!(
                    reader
                        .load_product(ITEM)
                        .expect("selected product")
                        .product()
                        .master_data()
                        .expect("bound master")
                        .document_version(),
                    "168"
                );
            }
        }
    }

    #[test]
    fn digest_text_is_canonical_lowercase() {
        let digest = PackageDigest::of(b"package");
        assert_eq!(digest.to_string().parse::<PackageDigest>().expect("canonical digest parses"), digest);
        assert!(digest.to_string().to_uppercase().parse::<PackageDigest>().is_err());
    }

    #[test]
    fn import_writes_only_source_and_v3_index() {
        let (_temporary, store) = store();
        let bytes = product_archive(application(AP1, true, None), Some(master_data(23, 168, "Test Vendor")));

        let imported = store.import_bytes(&bytes).expect("package imports");

        assert!(!imported.already_present);
        assert_eq!(fs::read(imported.package.source_archive_path()).expect("source remains exact"), bytes);
        assert!(!imported.package.content_root().exists(), "import must not extract the archive");
        let index_path = imported.package.directory().join(PACKAGE_INDEX);
        let index: PersistedPackageIndex =
            serde_json::from_slice(&fs::read(index_path).expect("index reads")).expect("index parses");
        assert_eq!(index.version, PACKAGE_INDEX_VERSION);
        assert_eq!(index.application_programs[AP1], format!("{MANUFACTURER}/{AP1}.xml"));
        let manufacturer = &index.catalog[0];
        assert_eq!(manufacturer.name.as_deref(), Some("Test Vendor"));
        assert_eq!(manufacturer.name_source_schema_version, Some(23));
        assert_eq!(manufacturer.name_source_version, Some(168));
        let leaf = imported.package.leaves().next().expect("catalogue leaf");
        assert_eq!(leaf.mask_version.as_deref(), Some("MV-07B0"));
        assert_eq!(leaf.supports_data_secure, Some(true));
        assert!(imported.notices.is_empty(), "unsigned packages need no signature notice");
    }

    #[test]
    fn import_streams_referenced_header_without_parsing_application_body() {
        let (_temporary, store) = store();
        let bytes = product_archive(malformed_application_header(AP1), None);

        let imported = store.import_bytes(&bytes).expect("opening declaration is sufficient for indexing");
        let leaf = imported.package.leaves().next().expect("catalogue leaf");
        assert_eq!(leaf.mask_version.as_deref(), Some("MV-0705"));
        assert_eq!(leaf.supports_data_secure, Some(false));
        assert!(
            matches!(imported.package.parse_application_program(AP1), Err(PackageStoreError::ApplicationParse { .. })),
            "the selected full parser still rejects the malformed body"
        );
    }

    #[test]
    fn invalid_present_signatures_are_notices_and_not_catalogue_metadata() {
        let (_temporary, store) = store();
        let registration = r#"<RegistrationInfo RegistrationStatus="Certified" RegistrationNumber="2026/1" RegistrationDate="2026-08-31" RegistrationSignature="not-verified"/>"#;
        let bytes = archive(vec![
            (format!("{MANUFACTURER}/{AP1}.xml"), application(AP1, false, None).into_bytes()),
            (format!("{MANUFACTURER}/Hardware.xml"), hardware(registration, registration, true).into_bytes()),
            (format!("{MANUFACTURER}/Catalog.xml"), catalog(ITEM).into_bytes()),
            (format!("{MANUFACTURER}.signature"), b"invalid envelope deliberately ignored".to_vec()),
        ]);

        let imported = store.import_bytes(&bytes).expect("signature mismatches do not block import");
        let leaf = imported.package.leaves().next().expect("catalogue leaf");
        assert_eq!(leaf.product_registration.status, PackageRegistrationStatus::Certified);
        assert_eq!(leaf.hardware2program_registration.status, PackageRegistrationStatus::Certified);
        assert_eq!(leaf.effective_registration.status, PackageRegistrationStatus::Certified);
        assert_eq!(leaf.effective_registration.registration_number.as_deref(), Some("2026/1"));
        assert!(leaf.instantiable);
        assert_eq!(imported.notices.len(), 3);
        assert!(imported.notices.iter().any(|notice| notice.path.ends_with(".signature")));
        assert_eq!(
            imported.notices.iter().filter(|notice| notice.message.contains("registration signature")).count(),
            2
        );

        let repeated = store.import_bytes(&bytes).expect("re-import checks signatures again");
        assert!(repeated.already_present);
        assert_eq!(repeated.notices, imported.notices);
    }

    #[test]
    fn product_and_relation_signing_hash_mismatches_are_notices() {
        let (_temporary, store) = store();
        let application = application(AP1, false, None).replacen(
            " ApplicationNumber=",
            r#" Hash="wrong-application-hash" ApplicationNumber="#,
            1,
        );
        let hardware = hardware("", "", true)
            .replacen(r#" Text="Switch""#, r#" Hash="wrong-product-hash" Text="Switch""#, 1)
            .replacen(r#" MediumTypes="MT-0""#, r#" Hash="wrong-relation-hash" MediumTypes="MT-0""#, 1);
        let bytes = archive(vec![
            (format!("{MANUFACTURER}/{AP1}.xml"), application.into_bytes()),
            (format!("{MANUFACTURER}/Hardware.xml"), hardware.into_bytes()),
            (format!("{MANUFACTURER}/Catalog.xml"), catalog(ITEM).into_bytes()),
        ]);

        let imported = store.import_bytes(&bytes).expect("hash mismatches do not block import");

        assert_eq!(imported.notices.len(), 2);
        assert!(imported.notices.iter().any(|notice| notice.message.contains("Product")));
        assert!(imported.notices.iter().any(|notice| notice.message.contains("Hardware2Program")));
    }

    #[test]
    fn catalog_only_hardware_does_not_require_an_application() {
        let (_temporary, store) = store();
        let bytes = archive(vec![
            (format!("{MANUFACTURER}/Hardware.xml"), hardware("", "", false).into_bytes()),
            (format!("{MANUFACTURER}/Catalog.xml"), catalog(ITEM).into_bytes()),
        ]);

        let imported = store.import_bytes(&bytes).expect("catalogue-only package imports");
        let leaf = imported.package.leaves().next().expect("catalogue leaf");
        assert_eq!(leaf.programs, PackageProgramBinding::None);
        assert_eq!(leaf.mask_version, None);
        assert_eq!(leaf.supports_data_secure, None);
        assert_eq!(
            leaf.instantiation,
            PackageInstantiation::CatalogOnly(PackageCatalogOnlyReason::NoApplicationProgram)
        );
    }

    #[test]
    fn selected_application_read_does_not_touch_unrelated_body() {
        let (_temporary, store) = store();
        let bytes = archive(vec![
            (format!("{MANUFACTURER}/{AP1}.xml"), application(AP1, false, None).into_bytes()),
            (format!("{MANUFACTURER}/{AP2}.xml"), b"not XML".to_vec()),
            (format!("{MANUFACTURER}/Hardware.xml"), hardware("", "", true).into_bytes()),
            (format!("{MANUFACTURER}/Catalog.xml"), catalog(ITEM).into_bytes()),
        ]);
        let imported = store.import_bytes(&bytes).expect("unrelated malformed application is not parsed");

        let selected = imported.package.parse_application_program(AP1).expect("selected application parses");
        assert_eq!(selected.manufacturer_data.manufacturer.application_programs.programs[0].id, AP1);
        assert!(matches!(
            imported.package.parse_application_program(AP2),
            Err(PackageStoreError::ApplicationParse { .. })
        ));
        assert!(matches!(
            imported.package.parse_application_program("missing"),
            Err(PackageStoreError::UnknownApplicationProgram(_))
        ));
    }

    #[test]
    fn open_and_repeat_import_use_only_persisted_index() {
        let (_temporary, store) = store();
        let bytes = product_archive(application(AP1, false, None), None);
        let imported = store.import_bytes(&bytes).expect("package imports");
        fs::write(imported.package.source_archive_path(), b"source deliberately damaged")
            .expect("fixture damages source");

        let reopened = store.open(imported.package.digest()).expect("open reads only the index");
        assert_eq!(reopened.leaves().count(), 1);
        assert_eq!(store.catalog_index().expect("catalog index reads only indexes").leaves().count(), 1);
        let repeated = store.import_bytes(&bytes).expect("repeat import does not reparse existing digest");
        assert!(repeated.already_present);
        assert!(repeated.package.parse_application_program(AP1).is_err());
    }

    #[test]
    fn missing_and_old_indexes_require_reimport_without_touching_content() {
        let temporary = TempDir::new().expect("temporary directory");
        let root = temporary.path().join("packages");
        fs::create_dir(&root).expect("store root");
        let bytes = product_archive(application(AP1, false, None), Some(master_data(23, 170, "Migrated Vendor")));
        let digest = PackageDigest::of(&bytes);
        let directory = root.join(digest.directory_name());
        fs::create_dir(&directory).expect("stored package directory");
        fs::write(directory.join(SOURCE_ARCHIVE), &bytes).expect("stored source");
        fs::create_dir(directory.join(CONTENT_DIRECTORY)).expect("existing content remains");
        fs::write(directory.join(CONTENT_DIRECTORY).join("sentinel"), b"keep").expect("content sentinel");
        let store = PackageStore::new(&root);

        let error = store.open(digest).expect_err("missing index is rejected");
        assert!(matches!(error, PackageStoreError::ReimportRequired { .. }));
        assert!(error.to_string().contains("re-import"));
        assert_eq!(fs::read(directory.join(CONTENT_DIRECTORY).join("sentinel")).expect("sentinel remains"), b"keep");

        let current = build_package_index(&bytes, digest).expect("current index builds");
        write_package_index(&directory.join(PACKAGE_INDEX), &current).expect("current index writes");
        let mut index: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join(PACKAGE_INDEX)).expect("current index reads"))
                .expect("current index parses");
        index["version"] = serde_json::json!(1);
        fs::write(directory.join(PACKAGE_INDEX), serde_json::to_vec(&index).expect("v1 serializes"))
            .expect("fixture writes v1");

        let error = store.open(digest).expect_err("v1 index is rejected");
        assert!(matches!(error, PackageStoreError::ReimportRequired { .. }));
        assert_eq!(fs::read(directory.join(CONTENT_DIRECTORY).join("sentinel")).expect("sentinel remains"), b"keep");
    }

    #[test]
    fn v2_index_requires_reimport() {
        let (_temporary, store) = store();
        let bytes = product_archive(application(AP1, false, None), None);
        let imported = store.import_bytes(&bytes).expect("package imports");
        let index_path = imported.package.directory().join(PACKAGE_INDEX);
        let mut index: serde_json::Value =
            serde_json::from_slice(&fs::read(&index_path).expect("index reads")).expect("index parses");
        index["version"] = serde_json::json!(2);
        let leaf = &mut index["catalog"][0]["sections"][0]["items"][0];
        leaf["directory_signature"] = serde_json::json!("VerifiedConverter");
        leaf["effective_registration"]["signature_present"] = serde_json::json!(true);
        leaf["effective_registration"]["signer"] = serde_json::json!("Converter");
        fs::write(&index_path, serde_json::to_vec_pretty(&index).expect("v2 serializes")).expect("v2 index writes");
        let error = store.open(imported.package.digest()).expect_err("v2 index is rejected");
        assert!(matches!(error, PackageStoreError::ReimportRequired { .. }));
        let unchanged: serde_json::Value =
            serde_json::from_slice(&fs::read(index_path).expect("v2 index remains")).expect("v2 index parses");
        assert_eq!(unchanged["version"], 2);
    }

    #[test]
    fn invalid_or_future_indexes_fail_closed() {
        for mutation in ["unsafe path", "future version"] {
            let (_temporary, store) = store();
            let imported =
                store.import_bytes(&product_archive(application(AP1, false, None), None)).expect("package imports");
            let index_path = imported.package.directory().join(PACKAGE_INDEX);
            let mut index: PersistedPackageIndex =
                serde_json::from_slice(&fs::read(&index_path).expect("index reads")).expect("index parses");
            if mutation == "unsafe path" {
                index.application_programs.insert(AP1.to_owned(), "../escape.xml".to_owned());
            } else {
                index.version = PACKAGE_INDEX_VERSION + 1;
            }
            write_package_index(&index_path, &index).expect("mutated index writes");

            let error = store.open(imported.package.digest()).expect_err("invalid index is rejected");
            if mutation == "unsafe path" {
                assert!(matches!(error, PackageStoreError::UnsafeEntry { .. }));
            } else {
                assert!(matches!(error, PackageStoreError::UnsupportedIndexVersion { .. }));
            }
        }
    }

    #[test]
    fn materializes_only_selected_baggage_payloads() {
        let (_temporary, store) = store();
        let bytes = archive(vec![
            (format!("{MANUFACTURER}/{AP1}.xml"), application(AP1, false, Some(BAGGAGE)).into_bytes()),
            (format!("{MANUFACTURER}/Hardware.xml"), hardware("", "", true).into_bytes()),
            (format!("{MANUFACTURER}/Catalog.xml"), catalog(ITEM).into_bytes()),
            (format!("{MANUFACTURER}/Baggages.xml"), baggages().into_bytes()),
            (format!("{MANUFACTURER}/Baggages/icon.png"), vec![0, 1, 2, 255]),
            (format!("{MANUFACTURER}/Baggages/unused.bin"), vec![9; 4096]),
        ]);
        let imported = store.import_bytes(&bytes).expect("package imports");
        let standalone_cache = TempDir::new().expect("standalone resource lifetime");
        let reader = PackageArchive::from_bytes(bytes).expect("standalone source");
        let selected = reader.load_product(ITEM).expect("standalone selection");
        let standalone_root = reader
            .materialize_baggages_from_document(selected.document(), standalone_cache.path())
            .expect("standalone baggage")
            .expect("referenced baggage");
        assert_eq!(fs::read(standalone_root.join("Baggages/icon.png")).expect("standalone payload"), [0, 1, 2, 255]);
        assert!(!standalone_root.join("Baggages/unused.bin").exists());
        let leaf = imported.package.leaves().next().expect("leaf").clone();
        let document = imported.package.parse_application_program(AP1).expect("selected application parses once");

        let root = imported
            .package
            .materialize_baggages_from_document(&leaf, &document)
            .expect("baggage materializes")
            .expect("application references baggage");
        assert_eq!(fs::read(root.join("Baggages/icon.png")).expect("selected payload"), [0, 1, 2, 255]);
        assert!(!root.join("Baggages/unused.bin").exists());
        assert_eq!(fs::read_to_string(root.join("Baggages.xml")).expect("original manifest"), baggages());
        assert_eq!(
            imported.package.materialize_baggages_from_document(&leaf, &document).expect("cache reopens"),
            Some(root)
        );
    }

    #[test]
    fn materializes_type_picture_baggage_despite_an_obsolete_cache() {
        let (_temporary, store) = store();
        let bytes = archive(vec![
            (format!("{MANUFACTURER}/{AP1}.xml"), application_with_picture(AP1, BAGGAGE).into_bytes()),
            (format!("{MANUFACTURER}/Hardware.xml"), hardware("", "", true).into_bytes()),
            (format!("{MANUFACTURER}/Catalog.xml"), catalog(ITEM).into_bytes()),
            (format!("{MANUFACTURER}/Baggages.xml"), baggages().into_bytes()),
            (format!("{MANUFACTURER}/Baggages/icon.png"), vec![0, 1, 2, 255]),
            (format!("{MANUFACTURER}/Baggages/unused.bin"), vec![9; 4096]),
        ]);
        let imported = store.import_bytes(&bytes).expect("package imports");
        let leaf = imported.package.leaves().next().expect("leaf").clone();
        let obsolete_root = imported
            .package
            .directory()
            .join(MATERIALIZED_DIRECTORY)
            .join(leaf.chain_digest.directory_name())
            .join(MANUFACTURER);
        fs::create_dir_all(&obsolete_root).expect("obsolete cache creates");
        fs::write(obsolete_root.join("Baggages.xml"), baggages()).expect("obsolete manifest writes");
        let document = imported.package.parse_application_program(AP1).expect("selected application parses once");

        let root = imported
            .package
            .materialize_baggages_from_document(&leaf, &document)
            .expect("picture baggage materializes")
            .expect("picture type references baggage");

        assert_ne!(root, obsolete_root);
        assert_eq!(fs::read(root.join("Baggages/icon.png")).expect("picture payload"), [0, 1, 2, 255]);
        assert!(!root.join("Baggages/unused.bin").exists());
        assert_eq!(
            imported.package.materialize_baggages_from_document(&leaf, &document).expect("cache reopens"),
            Some(root)
        );
    }

    #[test]
    fn newest_master_data_name_prefers_schema_before_table_version() {
        let (_temporary, store) = store();
        for (item, schema, version, name) in [
            ("M-00FA_CI-old", 14, 1728, "Obsolete Name"),
            ("M-00FA_CI-new", 23, 168, "Current Name"),
            ("M-00FA_CI-newer", 23, 169, "Newest Name"),
        ] {
            let bytes = archive(vec![
                (format!("{MANUFACTURER}/{AP1}.xml"), application(AP1, false, None).into_bytes()),
                (format!("{MANUFACTURER}/Hardware.xml"), hardware("", "", true).into_bytes()),
                (format!("{MANUFACTURER}/Catalog.xml"), catalog(item).into_bytes()),
                ("knx_master.xml".to_owned(), master_data(schema, version, name).into_bytes()),
            ]);
            store.import_bytes(&bytes).expect("package imports");
        }

        let catalog = store.catalog_index().expect("catalog merges");
        let manufacturer = &catalog.manufacturers[0];
        assert_eq!(manufacturer.name.as_deref(), Some("Newest Name"));
        assert_eq!(manufacturer.name_source_schema_version, Some(23));
        assert_eq!(manufacturer.name_source_version, Some(169));
    }

    #[test]
    fn rejects_unsafe_or_extremely_compressed_archives() {
        for bytes in [
            archive(vec![("../escape".to_owned(), Vec::new())]),
            archive(vec![("zeros.bin".to_owned(), vec![0; 2 * 1024 * 1024])]),
        ] {
            let error = PackageStore::new("unused").import_bytes(&bytes).expect_err("unsafe archive fails");
            assert!(matches!(
                error,
                PackageStoreError::UnsafeEntry { .. } | PackageStoreError::ArchiveCompressionRatio { .. }
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn open_rejects_symlinked_digest_directory() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().expect("temporary directory");
        let root = temporary.path().join("packages");
        fs::create_dir(&root).expect("store root");
        let digest = PackageDigest::of(b"package");
        symlink(temporary.path(), root.join(digest.directory_name())).expect("fixture symlink");

        let error = PackageStore::new(root).open(digest).expect_err("symlink boundary is rejected");
        assert!(matches!(error, PackageStoreError::UnsafeStoreNode { .. }));
    }
}
