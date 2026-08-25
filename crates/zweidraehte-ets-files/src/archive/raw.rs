use std::io::{Cursor, Read, Write};

use super::ArchiveError;

/// One ZIP member retained exactly at the ETS archive boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    path: String,
    bytes: Vec<u8>,
    directory: bool,
    compression: zip::CompressionMethod,
    unix_mode: Option<u32>,
}

impl ArchiveEntry {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn is_directory(&self) -> bool {
        self.directory
    }
}

/// Lossless-in-content representation of an ETS ZIP archive.
///
/// If no entry changes, [`to_bytes`](Self::to_bytes) returns the original ZIP
/// bytes. After an edit the ZIP envelope is rebuilt, while every untouched
/// path and payload is copied byte-for-byte.
#[derive(Debug, Clone)]
pub struct RawArchive {
    original: Option<Vec<u8>>,
    entries: Vec<ArchiveEntry>,
    dirty: bool,
}

impl RawArchive {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, ArchiveError> {
        Self::from_bytes(&std::fs::read(path)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArchiveError> {
        let mut zip = zip::ZipArchive::new(Cursor::new(bytes))?;
        let mut entries = Vec::with_capacity(zip.len());

        for index in 0..zip.len() {
            let mut member = zip.by_index(index)?;
            let mut payload = Vec::new();
            if member.is_file() {
                member.read_to_end(&mut payload)?;
            }
            entries.push(ArchiveEntry {
                path: member.name().to_owned(),
                bytes: payload,
                directory: member.is_dir(),
                compression: member.compression(),
                unix_mode: member.unix_mode(),
            });
        }

        Ok(Self { original: Some(bytes.to_vec()), entries, dirty: false })
    }

    pub fn entries(&self) -> &[ArchiveEntry] {
        &self.entries
    }

    pub fn entry(&self, path: &str) -> Option<&ArchiveEntry> {
        self.entries.iter().find(|entry| entry.path == path)
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Replace exactly one member without altering any other payload.
    ///
    /// A missing path is an error: callers editing a known document should
    /// not accidentally create a second, differently located copy.
    pub fn replace(&mut self, path: &str, bytes: Vec<u8>) -> Result<(), ArchiveError> {
        let entry = self.entry_mut(path).ok_or_else(|| ArchiveError::MissingEntry(path.to_owned()))?;
        if entry.bytes != bytes {
            entry.bytes = bytes;
            self.original = None;
            self.dirty = true;
        }
        Ok(())
    }

    /// Insert or replace a file member. Package builders use this when a
    /// generated format legitimately gains a new known document.
    pub fn upsert(&mut self, path: impl Into<String>, bytes: Vec<u8>) {
        let path = path.into();
        if let Some(entry) = self.entry_mut(&path) {
            if entry.bytes != bytes || entry.directory {
                entry.bytes = bytes;
                entry.directory = false;
                self.original = None;
                self.dirty = true;
            }
            return;
        }
        self.entries.push(ArchiveEntry {
            path,
            bytes,
            directory: false,
            compression: zip::CompressionMethod::Deflated,
            unix_mode: None,
        });
        self.original = None;
        self.dirty = true;
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ArchiveError> {
        if self.dirty && self.has_directory_signatures() {
            return Err(ArchiveError::SigningRequired);
        }
        self.to_bytes_unchecked()
    }

    pub(crate) fn to_bytes_unchecked(&self) -> Result<Vec<u8>, ArchiveError> {
        if let Some(original) = &self.original {
            return Ok(original.clone());
        }

        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        for entry in &self.entries {
            let mut options = zip::write::SimpleFileOptions::default().compression_method(entry.compression);
            if let Some(mode) = entry.unix_mode {
                options = options.unix_permissions(mode);
            }
            if entry.directory {
                writer.add_directory(&entry.path, options)?;
            } else {
                writer.start_file(&entry.path, options)?;
                writer.write_all(&entry.bytes)?;
            }
        }
        Ok(writer.finish()?.into_inner())
    }

    fn entry_mut(&mut self, path: &str) -> Option<&mut ArchiveEntry> {
        self.entries.iter_mut().find(|entry| entry.path == path)
    }

    pub(crate) fn has_directory_signatures(&self) -> bool {
        self.entries.iter().any(|entry| !entry.directory && entry.path.ends_with(".signature"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        writer.start_file("P-1/project.xml", options).expect("entry starts");
        writer.write_all(b"old").expect("entry writes");
        writer.start_file("future/data.bin", options).expect("entry starts");
        writer.write_all(&[0, 1, 2, 255]).expect("entry writes");
        writer.finish().expect("archive finishes").into_inner()
    }

    #[test]
    fn unmodified_archive_returns_the_original_envelope() {
        let bytes = fixture();
        let archive = RawArchive::from_bytes(&bytes).expect("archive opens");
        assert_eq!(archive.to_bytes().expect("archive writes"), bytes);
    }

    #[test]
    fn replacing_a_known_entry_preserves_unknown_payloads() {
        let mut archive = RawArchive::from_bytes(&fixture()).expect("archive opens");
        archive.replace("P-1/project.xml", b"new".to_vec()).expect("known entry replaces");

        let rewritten = RawArchive::from_bytes(&archive.to_bytes().expect("archive writes")).expect("rewrite opens");
        assert_eq!(rewritten.entry("P-1/project.xml").expect("project remains").bytes(), b"new");
        assert_eq!(rewritten.entry("future/data.bin").expect("unknown remains").bytes(), &[0, 1, 2, 255]);
    }
}
