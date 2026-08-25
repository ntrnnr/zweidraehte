use std::path::Path;

use crate::product::ManufacturerContent;
use crate::schema::{CatalogKnx, HardwareKnx, Knx, ProjectKnx};
use crate::xml;

use super::knxprod::{KnxprodArchive, application_program_id};
use super::{ArchiveError, RawArchive};

/// Typed, preservation-safe view over a `.knxproj` archive.
#[derive(Debug, Clone)]
pub struct KnxprojArchive {
    raw: RawArchive,
}

impl KnxprojArchive {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ArchiveError> {
        Ok(Self { raw: RawArchive::open(path)? })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArchiveError> {
        Ok(Self { raw: RawArchive::from_bytes(bytes)? })
    }

    pub fn raw_archive(&self) -> &RawArchive {
        &self.raw
    }

    pub fn into_raw_archive(self) -> RawArchive {
        self.raw
    }

    /// All known project metadata documents, including nested project roots.
    pub fn project_document_paths(&self) -> impl Iterator<Item = &str> {
        self.raw
            .entries()
            .iter()
            .map(|entry| entry.path())
            .filter(|path| *path == "project.xml" || path.ends_with("/project.xml"))
    }

    /// Installation/topology documents (`0.xml`, `1.xml`, ...), kept separate
    /// from metadata because a project may contain several installations.
    pub fn topology_document_paths(&self) -> impl Iterator<Item = &str> {
        self.raw.entries().iter().map(|entry| entry.path()).filter(|path| {
            let Some((_, file)) = path.rsplit_once('/') else { return false };
            file.strip_suffix(".xml").is_some_and(|stem| stem.chars().all(|character| character.is_ascii_digit()))
        })
    }

    /// Manufacturer application-program documents carried by the project.
    pub fn application_program_document_paths(&self) -> impl Iterator<Item = &str> {
        self.raw.entries().iter().map(|entry| entry.path()).filter(|path| application_program_id(path).is_some())
    }

    pub fn parse_application_program_document(&self, path: &str) -> Result<Knx, ArchiveError> {
        self.parse_xml(path)
    }

    pub fn replace_application_program_document(&mut self, path: &str, document: &Knx) -> Result<(), ArchiveError> {
        if application_program_id(path).is_none() {
            return Err(ArchiveError::MissingEntry(path.to_owned()));
        }
        self.replace_xml(path, document)
    }

    pub fn hardware_document_paths(&self) -> impl Iterator<Item = &str> {
        self.raw
            .entries()
            .iter()
            .map(|entry| entry.path())
            .filter(|path| *path == "Hardware.xml" || path.ends_with("/Hardware.xml"))
    }

    pub fn parse_hardware_document(&self, path: &str) -> Result<HardwareKnx, ArchiveError> {
        self.parse_xml(path)
    }

    pub fn replace_hardware_document(&mut self, path: &str, document: &HardwareKnx) -> Result<(), ArchiveError> {
        if !self.hardware_document_paths().any(|candidate| candidate == path) {
            return Err(ArchiveError::MissingEntry(path.to_owned()));
        }
        self.replace_xml(path, document)
    }

    pub fn catalogue_document_paths(&self) -> impl Iterator<Item = &str> {
        self.raw
            .entries()
            .iter()
            .map(|entry| entry.path())
            .filter(|path| *path == "Catalog.xml" || path.ends_with("/Catalog.xml"))
    }

    pub fn parse_catalogue_document(&self, path: &str) -> Result<CatalogKnx, ArchiveError> {
        self.parse_xml(path)
    }

    pub fn replace_catalogue_document(&mut self, path: &str, document: &CatalogKnx) -> Result<(), ArchiveError> {
        if !self.catalogue_document_paths().any(|candidate| candidate == path) {
            return Err(ArchiveError::MissingEntry(path.to_owned()));
        }
        self.replace_xml(path, document)
    }

    /// Lower every manufacturer directory to package-neutral content.
    pub fn manufacturer_contents(&self) -> Result<Vec<ManufacturerContent>, ArchiveError> {
        KnxprodArchive::from_raw_archive(self.raw.clone())?.manufacturer_contents()
    }

    pub fn parse_project_document(&self, path: &str) -> Result<ProjectKnx, ArchiveError> {
        let entry = self.raw.entry(path).ok_or_else(|| ArchiveError::MissingEntry(path.to_owned()))?;
        let source = std::str::from_utf8(entry.bytes())
            .map_err(|source| ArchiveError::Utf8 { path: path.to_owned(), source })?;
        xml::from_str(source).map_err(|error| match error {
            xml::XmlError::Deserialize(source) => ArchiveError::Xml { path: path.to_owned(), source },
            xml::XmlError::Serialize(_) => unreachable!("parsing cannot return a serialization error"),
        })
    }

    pub fn replace_project_document(&mut self, path: &str, document: &ProjectKnx) -> Result<(), ArchiveError> {
        self.replace_xml(path, document)
    }

    /// Write an unsigned or unmodified archive.
    ///
    /// A dirty signed archive returns [`ArchiveError::SigningRequired`]; use
    /// [`to_signed_bytes`](Self::to_signed_bytes) so stale packaging metadata
    /// cannot escape accidentally.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ArchiveError> {
        self.raw.to_bytes()
    }

    /// Refresh directory signatures and write an edited signed archive.
    #[cfg(feature = "signing")]
    pub fn to_signed_bytes(&self, key: &crate::signing::ConverterKey) -> Result<Vec<u8>, ArchiveError> {
        super::signed_archive_bytes(&self.raw, key)
    }

    fn parse_xml<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ArchiveError> {
        let entry = self.raw.entry(path).ok_or_else(|| ArchiveError::MissingEntry(path.to_owned()))?;
        let source = std::str::from_utf8(entry.bytes())
            .map_err(|source| ArchiveError::Utf8 { path: path.to_owned(), source })?;
        xml::from_str(source).map_err(|error| match error {
            xml::XmlError::Deserialize(source) => ArchiveError::Xml { path: path.to_owned(), source },
            xml::XmlError::Serialize(_) => unreachable!("parsing cannot return a serialization error"),
        })
    }

    fn replace_xml<T: serde::Serialize>(&mut self, path: &str, document: &T) -> Result<(), ArchiveError> {
        let source = xml::to_string(document).map_err(|error| match error {
            xml::XmlError::Serialize(source) => ArchiveError::XmlSerialize { path: path.to_owned(), source },
            xml::XmlError::Deserialize(_) => unreachable!("serialization cannot return a parse error"),
        })?;
        self.raw.replace(path, source.into_bytes())
    }
}

#[cfg(all(test, feature = "signing"))]
mod tests {
    use std::io::{Cursor, Write};

    use super::*;
    use crate::project::{KnxprojBuilder, ProjectDefinition};
    use crate::signing::ConverterKey;

    fn fixture() -> Vec<u8> {
        let documents =
            KnxprojBuilder::new(ProjectDefinition::new("Before")).generate().expect("project documents generate");
        let application = xml::to_string(&Knx::default()).expect("application document serializes");
        let hardware = xml::to_string(&HardwareKnx::default()).expect("hardware document serializes");
        let catalogue = xml::to_string(&CatalogKnx::default()).expect("catalogue document serializes");
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        for (path, contents) in [
            ("P-0001/project.xml", documents.project_xml.as_bytes()),
            ("P-0001/0.xml", documents.topology_xml.as_bytes()),
            ("P-0001/future.bin", b"unknown".as_slice()),
            ("P-0001.signature", b"old-signature".as_slice()),
            ("M-00FA/M-00FA_A-0001-01-0000.xml", application.as_bytes()),
            ("M-00FA/Hardware.xml", hardware.as_bytes()),
            ("M-00FA/Catalog.xml", catalogue.as_bytes()),
            ("M-00FA/future.bin", b"manufacturer-unknown".as_slice()),
            ("M-00FA.signature", b"old-manufacturer-signature".as_slice()),
        ] {
            writer.start_file(path, options).expect("entry starts");
            writer.write_all(contents).expect("entry writes");
        }
        writer.finish().expect("archive finishes").into_inner()
    }

    #[test]
    fn edited_projects_require_and_refresh_the_directory_signature() {
        let mut archive = KnxprojArchive::from_bytes(&fixture()).expect("project opens");
        assert_eq!(archive.topology_document_paths().collect::<Vec<_>>(), ["P-0001/0.xml"]);
        assert_eq!(archive.application_program_document_paths().collect::<Vec<_>>(), [
            "M-00FA/M-00FA_A-0001-01-0000.xml"
        ]);
        assert_eq!(archive.hardware_document_paths().collect::<Vec<_>>(), ["M-00FA/Hardware.xml"]);
        assert_eq!(archive.catalogue_document_paths().collect::<Vec<_>>(), ["M-00FA/Catalog.xml"]);
        archive.parse_application_program_document("M-00FA/M-00FA_A-0001-01-0000.xml").expect("application parses");
        assert_eq!(archive.manufacturer_contents().expect("manufacturer lowers").len(), 1);
        let mut project = archive.parse_project_document("P-0001/project.xml").expect("metadata parses");
        project.project.project_information.as_mut().expect("metadata exists").name = "After".to_owned();
        archive.replace_project_document("P-0001/project.xml", &project).expect("metadata replaces");

        assert!(matches!(archive.to_bytes(), Err(ArchiveError::SigningRequired)));
        let key_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join("converter_key.xml");
        let key = ConverterKey::from_file(key_path).expect("converter key loads");
        let bytes = archive.to_signed_bytes(&key).expect("archive re-signs");
        let rewritten = RawArchive::from_bytes(&bytes).expect("rewrite opens");
        assert_eq!(rewritten.entry("P-0001/future.bin").expect("unknown remains").bytes(), b"unknown");
        assert_eq!(
            rewritten.entry("M-00FA/future.bin").expect("manufacturer unknown remains").bytes(),
            b"manufacturer-unknown"
        );
        assert_ne!(rewritten.entry("P-0001.signature").expect("signature remains").bytes(), b"old-signature");
        assert_ne!(
            rewritten.entry("M-00FA.signature").expect("manufacturer signature remains").bytes(),
            b"old-manufacturer-signature"
        );
    }
}
