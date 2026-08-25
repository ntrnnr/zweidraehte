//! ETS ZIP containers and format-specific archive views.
//!
//! The raw layer deliberately knows nothing about ETS XML. It keeps every ZIP
//! member so opening a newer package and editing one document cannot silently
//! discard files this crate does not understand yet.

mod knxprod;
mod knxproj;
mod raw;

pub mod product_loader;

pub use knxprod::{KnxprodArchive, KnxprodDevice};
pub use knxproj::KnxprojArchive;
pub use product_loader::{LoadedProgram, ProductLoadError, ProgramSelection, load_program};
pub use raw::{ArchiveEntry, RawArchive};

/// Errors at the ZIP/container boundary.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("cannot read ETS archive")]
    Io(#[from] std::io::Error),
    #[error("invalid ETS ZIP archive")]
    Zip(#[from] zip::result::ZipError),
    #[error("archive entry {path:?} is not UTF-8")]
    Utf8 {
        path: String,
        #[source]
        source: std::str::Utf8Error,
    },
    #[error("cannot parse {path:?}")]
    Xml {
        path: String,
        #[source]
        source: quick_xml::DeError,
    },
    #[error("cannot serialize {path:?}")]
    XmlSerialize {
        path: String,
        #[source]
        source: quick_xml::SeError,
    },
    #[error("archive does not contain {0}")]
    MissingEntry(String),
    #[error("a signed ETS archive was modified; supply a converter key to re-sign it")]
    SigningRequired,
    #[cfg(feature = "signing")]
    #[error("cannot re-sign ETS archive")]
    Signing(#[source] crate::signing::SigningError),
}

#[cfg(feature = "signing")]
pub(crate) fn signed_archive_bytes(
    raw: &RawArchive,
    key: &crate::signing::ConverterKey,
) -> Result<Vec<u8>, ArchiveError> {
    if !raw.is_dirty() || !raw.has_directory_signatures() {
        return raw.to_bytes();
    }

    let mut signed = raw.clone();
    let directories = signed
        .entries()
        .iter()
        .filter_map(|entry| entry.path().strip_suffix(".signature"))
        .map(str::to_owned)
        .collect::<Vec<_>>();

    for directory in directories {
        let prefix = format!("{directory}/");
        let files = signed
            .entries()
            .iter()
            .filter(|entry| !entry.is_directory() && entry.path().starts_with(&prefix))
            .map(|entry| (entry.path()[prefix.len()..].to_owned(), entry.bytes().to_vec()))
            .collect::<Vec<_>>();
        let refs = files.iter().map(|(path, bytes)| (path.clone(), bytes.as_slice())).collect::<Vec<_>>();
        let signature = crate::signing::sign_directory_contents(&refs, key).map_err(ArchiveError::Signing)?;
        let mut payload = vec![0xEF, 0xBB, 0xBF];
        payload.extend_from_slice(signature.as_bytes());
        signed.replace(&format!("{directory}.signature"), payload)?;
    }

    signed.to_bytes_unchecked()
}
