//! Reading `.knxprod` archives.
//!
//! A `.knxprod` is a ZIP holding everything ETS needs to know about a
//! product — and, usefully for a management client, **both** of the
//! upper two data layers at once:
//!
//! ```text
//! knx_master.xml                     ← the mask layer (all 34 masks)
//! M-XXXX/M-XXXX_A-nnnn-vv-hhhh.xml   ← the product layer (one per
//! M-XXXX/Hardware.xml                   application program)
//! M-XXXX/Catalog.xml
//! M-XXXX.signature
//! ```
//!
//! The archive supplies the product's segments, load procedures and exact
//! `knx_master.xml`. Product extraction retains this document association for
//! programming; callers supply Master Data only when the package has none.
//!
//! This module provides preservation-safe archive views and known-document
//! replacement. New signed package generation lives in
//! [`crate::signing::packaging`]. Gated on the `archives` feature, which
//! costs the `zip` dependency.
//!
//! This low-level archive view does **not** verify signatures on read. Project
//! package import is the trust boundary that verifies and classifies signed
//! packages; keeping this parser permissive also allows unsigned generator test
//! fixtures to be inspected without pretending that they are registered.

use std::collections::BTreeSet;
use std::path::Path;

#[cfg(test)]
use std::io::Cursor;

use crate::product::{ManufacturerContent, ProductError};
use crate::runtime::parser::{ParseError, parse_application_program};
use crate::schema::{
    CatalogItem, CatalogKnx, CatalogSection, HardwareApplicationProgramError, HardwareApplicationProgramPairing,
    HardwareKnx, Knx,
};
use crate::xml;

use super::{ApplicationProgramRelation, ArchiveError, RawArchive};

/// A `.knxprod` archive opened for reading.
///
/// Entries are retained eagerly for preservation and editing. For catalogue
/// inspection and loading one product, use [`super::PackageArchive`], which
/// indexes opening declarations and inflates only selected application bodies.
#[derive(Debug, Clone)]
pub struct KnxprodArchive {
    raw: RawArchive,
    master_data: Option<String>,
    /// `(application program id, archive path)`, in archive order.
    programs: Vec<(String, String)>,
    hardware: Vec<String>,
    catalogs: Vec<String>,
}

struct ApplicationHardwareContext {
    directory: String,
    program_type: String,
    hardware: HardwareKnx,
}

/// One selectable catalogue product from a `.knxprod` archive.
///
/// A catalogue product is not itself downloadable: its
/// `Hardware2Program` relation selects the application program that is. Both
/// identities are retained so frontends can show the human product while the
/// project stores the deterministic application-program selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnxprodDevice {
    pub catalog_item_id: Option<String>,
    pub product_id: Option<String>,
    pub hardware_id: Option<String>,
    pub application_program_id: String,
    pub name: String,
    pub order_number: Option<String>,
    pub mask_version: String,
    pub supports_data_secure: bool,
}

impl KnxprodArchive {
    /// Open a `.knxprod` from disk.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ArchiveError> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Open a `.knxprod` held in memory.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArchiveError> {
        let raw = RawArchive::from_bytes(bytes)?;
        Self::from_raw_archive(raw)
    }

    pub(super) fn from_raw_archive(raw: RawArchive) -> Result<Self, ArchiveError> {
        let master_data = super::master_data_path(
            raw.entries().iter().filter(|entry| !entry.is_directory()).map(|entry| entry.path()),
        )?
        .map(str::to_owned);
        let mut programs = Vec::new();
        let mut hardware = Vec::new();
        let mut catalogs = Vec::new();

        for entry in raw.entries() {
            if entry.is_directory() {
                continue;
            }
            let name = entry.path().to_owned();

            let is_master = master_data.as_deref() == Some(name.as_str());
            let program_id = application_program_id(&name);
            let is_hardware = name.ends_with("/Hardware.xml") || name == "Hardware.xml";
            let is_catalog = name.ends_with("/Catalog.xml") || name == "Catalog.xml";
            if !is_master && program_id.is_none() && !is_hardware && !is_catalog {
                continue; // baggages, signatures and other support files
            }

            std::str::from_utf8(entry.bytes()).map_err(|source| ArchiveError::Utf8 { path: name.clone(), source })?;

            if let Some(id) = program_id {
                programs.push((id, name));
            } else if is_hardware {
                hardware.push(name);
            } else if is_catalog {
                catalogs.push(name);
            }
        }

        Ok(Self { raw, master_data, programs, hardware, catalogs })
    }

    /// The preservation layer containing known and unknown members alike.
    pub fn raw_archive(&self) -> &RawArchive {
        &self.raw
    }

    pub fn into_raw_archive(self) -> RawArchive {
        self.raw
    }

    /// Write an unsigned or unmodified product archive.
    ///
    /// Edited signed packages require [`to_signed_bytes`](Self::to_signed_bytes).
    pub fn to_bytes(&self) -> Result<Vec<u8>, ArchiveError> {
        self.raw.to_bytes()
    }

    /// Refresh every signed directory before writing an edited package.
    #[cfg(feature = "signing")]
    pub fn to_signed_bytes(&self, key: &crate::signing::ConverterKey) -> Result<Vec<u8>, ArchiveError> {
        super::signed_archive_bytes(&self.raw, key)
    }

    /// The bundled `knx_master.xml`, if the archive carries one.
    ///
    /// Product extraction associates this exact document with its application.
    pub fn master_data_xml(&self) -> Option<&str> {
        self.master_data.as_deref().map(|path| self.xml(path))
    }

    /// Application program IDs in the archive, e.g.
    /// `M-00FA_A-0306-02-0000`.
    pub fn application_program_ids(&self) -> impl Iterator<Item = &str> {
        self.programs.iter().map(|(id, _)| id.as_str())
    }

    /// Raw XML of one application program.
    pub fn application_program_xml(&self, id: &str) -> Option<&str> {
        self.programs.iter().find(|(pid, _)| pid == id).map(|(_, path)| self.xml(path))
    }

    /// Parse one application program by ID.
    pub fn parse_application_program(&self, id: &str) -> Option<Result<Knx, ParseError>> {
        self.application_program_xml(id).map(parse_application_program)
    }

    /// Resolve a selected AP1 through its canonical sibling `Hardware.xml`.
    ///
    /// `Ok(None)` keeps a package with no matching hardware relation distinct
    /// from a relation which authoritatively declares AP2 absent. A malformed
    /// or contradictory relation is an error, not an invitation to probe the
    /// device and guess.
    pub fn application_program_pairing(
        &self,
        application_program_id: &str,
    ) -> crate::product::Result<Option<HardwareApplicationProgramPairing>> {
        self.application_program_relation(application_program_id, None)
            .map(|relation| relation.map(|relation| relation.hardware))
    }

    /// Resolve the exact package chain selected for an application:
    /// `CatalogItem -> Product -> Hardware2Program -> ordered AP refs`.
    ///
    /// A `catalog_product` is the stable `Product/@Id` persisted by project
    /// selection. It must identify exactly one catalogue item and relation for
    /// this AP1. Without a product selector, catalogue metadata is attached
    /// only when the AP1 has one unambiguous catalogue path.
    pub fn application_program_relation(
        &self,
        application_program_id: &str,
        catalog_product: Option<&str>,
    ) -> crate::product::Result<Option<ApplicationProgramRelation>> {
        let context = match self.application_hardware_context(application_program_id)? {
            Some(context) => context,
            None => {
                return match catalog_product {
                    Some(product) => Err(ProductError::MissingCatalogueProgramRelation {
                        product: product.to_owned(),
                        application: application_program_id.to_owned(),
                    }),
                    None => Ok(None),
                };
            }
        };
        let catalogue_path = if context.directory.is_empty() {
            "Catalog.xml".to_owned()
        } else {
            format!("{}/Catalog.xml", context.directory)
        };
        let catalogue = self
            .catalogs
            .iter()
            .any(|candidate| candidate == &catalogue_path)
            .then(|| quick_xml::de::from_str::<CatalogKnx>(self.xml(&catalogue_path).trim_start_matches('\u{feff}')))
            .transpose()
            .map_err(ProductError::CatalogueXml)?;

        if let Some(product_id) = catalog_product {
            let Some(catalogue) = catalogue else {
                return Err(ProductError::MissingCatalogueProgramRelation {
                    product: product_id.to_owned(),
                    application: application_program_id.to_owned(),
                });
            };
            let mut items = Vec::new();
            collect_catalog_items(&catalogue.manufacturer_data.manufacturer.catalog.catalog_sections, &mut items);
            let mut candidates = Vec::new();
            for item in items.into_iter().filter(|item| item.product_ref_id == product_id) {
                for (hardware, _, relation) in
                    context.hardware.product_relations(product_id, &item.hardware2program_ref_id)
                {
                    if relation
                        .application_program_refs
                        .first()
                        .is_some_and(|reference| reference.ref_id == application_program_id)
                    {
                        candidates.push((item, hardware.id.as_str(), relation.id.as_str()));
                    }
                }
            }

            let (item, hardware_id, hardware2program_id) = match candidates.as_slice() {
                [candidate] => *candidate,
                [] => {
                    return Err(ProductError::MissingCatalogueProgramRelation {
                        product: product_id.to_owned(),
                        application: application_program_id.to_owned(),
                    });
                }
                candidates => {
                    return Err(ProductError::AmbiguousCatalogueProgramRelation {
                        product: product_id.to_owned(),
                        application: application_program_id.to_owned(),
                        count: candidates.len(),
                    });
                }
            };
            let hardware = context
                .hardware
                .resolve_application_program_pairing_in_relation(
                    hardware_id,
                    hardware2program_id,
                    application_program_id,
                    Some(&context.program_type),
                )?
                .ok_or_else(|| ProductError::MissingCatalogueProgramRelation {
                    product: product_id.to_owned(),
                    application: application_program_id.to_owned(),
                })?;
            return Ok(Some(ApplicationProgramRelation {
                catalog_item_id: Some(item.id.clone()),
                product_id: Some(product_id.to_owned()),
                hardware,
            }));
        }

        let Some(hardware) = context
            .hardware
            .resolve_application_program_pairing(application_program_id, Some(&context.program_type))?
        else {
            return Ok(None);
        };
        let Some(catalogue) = catalogue else {
            return Ok(Some(ApplicationProgramRelation { catalog_item_id: None, product_id: None, hardware }));
        };
        let mut items = Vec::new();
        collect_catalog_items(&catalogue.manufacturer_data.manufacturer.catalog.catalog_sections, &mut items);
        let candidates = items
            .into_iter()
            .filter(|item| {
                item.hardware2program_ref_id == hardware.hardware2program_id
                    && context
                        .hardware
                        .product_relations(&item.product_ref_id, &item.hardware2program_ref_id)
                        .any(|(candidate, _, _)| candidate.id == hardware.hardware_id)
            })
            .collect::<Vec<_>>();
        match candidates.as_slice() {
            [] => Ok(Some(ApplicationProgramRelation { catalog_item_id: None, product_id: None, hardware })),
            [item] => Ok(Some(ApplicationProgramRelation {
                catalog_item_id: Some(item.id.clone()),
                product_id: Some(item.product_ref_id.clone()),
                hardware,
            })),
            candidates => Err(ProductError::AmbiguousCatalogueApplication {
                application: application_program_id.to_owned(),
                count: candidates.len(),
            }),
        }
    }

    fn application_hardware_context(
        &self,
        application_program_id: &str,
    ) -> crate::product::Result<Option<ApplicationHardwareContext>> {
        let (_, application_path) = self
            .programs
            .iter()
            .find(|(candidate, _)| candidate == application_program_id)
            .ok_or_else(|| ProductError::UnknownApplicationProgram(application_program_id.to_owned()))?;
        let application = parse_application_program(self.xml(application_path))?;
        let programs = &application.manufacturer_data.manufacturer.application_programs.programs;
        let program = match programs.as_slice() {
            [program] if program.id == application_program_id => program,
            [] => return Err(ProductError::MissingApplicationProgram),
            [_] => return Err(ProductError::UnknownApplicationProgram(application_program_id.to_owned())),
            programs => return Err(ProductError::AmbiguousApplicationProgram { count: programs.len() }),
        };

        let directory = application_path.rsplit_once('/').map_or("", |(directory, _)| directory).to_owned();
        let hardware_path =
            if directory.is_empty() { "Hardware.xml".to_owned() } else { format!("{directory}/Hardware.xml") };
        if !self.hardware.iter().any(|candidate| candidate == &hardware_path) {
            return Ok(None);
        }

        let hardware: HardwareKnx = quick_xml::de::from_str(self.xml(&hardware_path).trim_start_matches('\u{feff}'))
            .map_err(ProductError::HardwareXml)?;
        let application_manufacturer = &application.manufacturer_data.manufacturer.ref_id;
        let hardware_manufacturer = &hardware.manufacturer_data.manufacturer.ref_id;
        if application_manufacturer != hardware_manufacturer {
            return Err(ProductError::from(HardwareApplicationProgramError::ManufacturerMismatch {
                application_program_id: application_program_id.to_owned(),
                expected: application_manufacturer.clone(),
                actual: hardware_manufacturer.clone(),
            }));
        }
        hardware.validate_application_schema(&application.xmlns)?;
        Ok(Some(ApplicationHardwareContext { directory, program_type: program.program_type.clone(), hardware }))
    }

    /// Canonically rewrite one known application-program entry.
    pub fn replace_application_program(&mut self, id: &str, document: &Knx) -> Result<(), ArchiveError> {
        let path = self
            .programs
            .iter()
            .find_map(|(program_id, path)| (program_id == id).then(|| path.clone()))
            .ok_or_else(|| ArchiveError::MissingEntry(format!("application program {id}")))?;
        self.replace_xml(&path, document)
    }

    pub fn hardware_document_paths(&self) -> impl Iterator<Item = &str> {
        self.hardware.iter().map(String::as_str)
    }

    pub fn parse_hardware_document(&self, path: &str) -> Result<HardwareKnx, ArchiveError> {
        self.parse_xml(path)
    }

    pub fn replace_hardware_document(&mut self, path: &str, document: &HardwareKnx) -> Result<(), ArchiveError> {
        if !self.hardware.iter().any(|candidate| candidate == path) {
            return Err(ArchiveError::MissingEntry(path.to_owned()));
        }
        self.replace_xml(path, document)
    }

    pub fn catalogue_document_paths(&self) -> impl Iterator<Item = &str> {
        self.catalogs.iter().map(String::as_str)
    }

    pub fn parse_catalogue_document(&self, path: &str) -> Result<CatalogKnx, ArchiveError> {
        self.parse_xml(path)
    }

    pub fn replace_catalogue_document(&mut self, path: &str, document: &CatalogKnx) -> Result<(), ArchiveError> {
        if !self.catalogs.iter().any(|candidate| candidate == path) {
            return Err(ArchiveError::MissingEntry(path.to_owned()));
        }
        self.replace_xml(path, document)
    }

    /// Parse the archive's only application program.
    ///
    /// Convenience for the common single-product package; `None` when
    /// the archive holds zero or several, since picking one for the
    /// caller would be a guess.
    pub fn parse_sole_application_program(&self) -> Option<Result<Knx, ParseError>> {
        match self.programs.as_slice() {
            [(_, path)] => Some(parse_application_program(self.xml(path))),
            _ => None,
        }
    }

    /// How many application programs the archive holds.
    pub fn application_program_count(&self) -> usize {
        self.programs.len()
    }

    /// Resolve the archive's catalogue products to application programs.
    ///
    /// Real ETS archives may list the same application for several order
    /// numbers. Those remain separate choices. Programs absent from the
    /// catalogue are returned as fallback choices so locally generated and
    /// incomplete packages are still usable.
    pub fn importable_devices(&self) -> Result<Vec<KnxprodDevice>, super::PackageStoreError> {
        // Editing views retain all payloads for lossless rewriting; selection
        // nevertheless uses the same header index as standalone/store readers.
        super::PackageArchive::from_bytes(self.raw.to_bytes_unchecked()?)?.importable_devices()
    }

    /// Lower each manufacturer directory to package-neutral content.
    ///
    /// Old directory signatures are deliberately not copied: a new package
    /// signs the retained payloads again after any edit.
    pub fn manufacturer_contents(&self) -> Result<Vec<ManufacturerContent>, ArchiveError> {
        let mut directories = self
            .hardware
            .iter()
            .filter_map(|path| path.rsplit_once('/').map(|(directory, _)| directory.to_owned()))
            .collect::<Vec<_>>();
        directories.sort();
        directories.dedup();

        directories
            .into_iter()
            .map(|directory| {
                let hardware_path = format!("{directory}/Hardware.xml");
                let catalogue_path = format!("{directory}/Catalog.xml");
                let hardware =
                    self.raw.entry(&hardware_path).ok_or_else(|| ArchiveError::MissingEntry(hardware_path.clone()))?;
                let catalogue = self
                    .raw
                    .entry(&catalogue_path)
                    .ok_or_else(|| ArchiveError::MissingEntry(catalogue_path.clone()))?;
                let application_programs = self
                    .programs
                    .iter()
                    .filter(|(_, path)| path.starts_with(&format!("{directory}/")))
                    .map(|(id, path)| (id.clone(), self.xml(path).to_owned()))
                    .collect::<Vec<_>>();
                let known = application_programs
                    .iter()
                    .map(|(id, _)| format!("{directory}/{id}.xml"))
                    .chain([hardware_path.clone(), catalogue_path.clone()])
                    .collect::<BTreeSet<_>>();
                let prefix = format!("{directory}/");
                let auxiliary_files = self
                    .raw
                    .entries()
                    .iter()
                    .filter(|entry| {
                        !entry.is_directory() && entry.path().starts_with(&prefix) && !known.contains(entry.path())
                    })
                    .map(|entry| (entry.path()[prefix.len()..].to_owned(), entry.bytes().to_vec()))
                    .collect();

                Ok(ManufacturerContent {
                    manufacturer_id: directory.strip_prefix("M-").unwrap_or(&directory).to_owned(),
                    application_programs,
                    hardware: std::str::from_utf8(hardware.bytes())
                        .expect("known XML is validated when the archive opens")
                        .to_owned(),
                    catalogue: std::str::from_utf8(catalogue.bytes())
                        .expect("known XML is validated when the archive opens")
                        .to_owned(),
                    auxiliary_files,
                })
            })
            .collect()
    }

    fn xml(&self, path: &str) -> &str {
        let bytes = self.raw.entry(path).expect("indexed archive entry remains present").bytes();
        std::str::from_utf8(bytes).expect("known XML entries are validated when the archive opens")
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

fn collect_catalog_items<'a>(sections: &'a [CatalogSection], output: &mut Vec<&'a CatalogItem>) {
    for section in sections {
        output.extend(&section.catalog_items);
        collect_catalog_items(&section.subsections, output);
    }
}

/// Extract the application program ID from an archive entry name.
///
/// Application programs are `M-XXXX/M-XXXX_A-....xml`; the sibling
/// `Hardware.xml` / `Catalog.xml` / `Baggages.xml` in the same
/// directory are told apart by the `_A-` infix that only a program ID
/// carries.
pub(super) fn application_program_id(entry_name: &str) -> Option<String> {
    let file = entry_name.rsplit('/').next()?;
    let stem = file.strip_suffix(".xml")?;
    if stem.starts_with("M-") && stem.contains("_A-") { Some(stem.to_string()) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_application_program_entries() {
        assert_eq!(
            application_program_id("M-00FA/M-00FA_A-0306-02-0000.xml").as_deref(),
            Some("M-00FA_A-0306-02-0000")
        );
        // Everything else in the manufacturer directory is not a program.
        assert_eq!(application_program_id("M-00FA/Hardware.xml"), None);
        assert_eq!(application_program_id("M-00FA/Catalog.xml"), None);
        assert_eq!(application_program_id("M-00FA/Baggages.xml"), None);
        assert_eq!(application_program_id("knx_master.xml"), None);
        assert_eq!(application_program_id("M-00FA.signature"), None);
    }

    /// Round-trip against an archive built the same way
    /// `create_knxprod` builds one, so the reader is pinned to the
    /// writer's layout without needing the signing stack here.
    #[test]
    fn reads_master_data_and_programs_from_an_archive() {
        use std::io::Write;
        use zip::write::SimpleFileOptions;

        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            let opts = SimpleFileOptions::default();
            zip.start_file("knx_master.xml", opts).expect("entry");
            zip.write_all(b"<KNX><MasterData Id=\"MD-1\" Version=\"1\"/></KNX>").expect("write");
            zip.start_file("M-00FA/Hardware.xml", opts).expect("entry");
            zip.write_all(b"<KNX/>").expect("write");
            zip.start_file("M-00FA/M-00FA_A-0306-02-0000.xml", opts).expect("entry");
            zip.write_all(b"<KNX/>").expect("write");
            zip.start_file("M-00FA.signature", opts).expect("entry");
            zip.write_all(b"sig").expect("write");
            zip.finish().expect("finish");
        }

        let archive = KnxprodArchive::from_bytes(&buf.into_inner()).expect("archive opens");
        assert!(archive.master_data_xml().expect("bundled master data").contains("MasterData"));
        assert_eq!(archive.application_program_ids().collect::<Vec<_>>(), ["M-00FA_A-0306-02-0000"]);
        assert_eq!(archive.application_program_count(), 1, "Hardware.xml is not a program");
        assert!(archive.parse_sole_application_program().is_some());
    }

    #[test]
    fn resolves_catalogue_products_to_their_application_programs() {
        use std::io::Write;
        use zip::write::SimpleFileOptions;

        const ROOT: &str = r#"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="test" ToolVersion="1" xmlns="http://knx.org/xml/project/23""#;
        let application = format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms><ApplicationProgram Id="M-00FA_A-0001-01-0000" ApplicationNumber="1" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="Switch Program" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="en-US" DynamicTableManagement="false" Linkable="false" IsSecureEnabled="true"><Static><Code/></Static></ApplicationProgram></ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#
        );
        let hardware = format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><Hardware><Hardware Id="M-00FA_H-1" Name="Switch Hardware" SerialNumber="1" VersionNumber="1" HasIndividualAddress="true" HasApplicationProgram="true"><Products><Product Id="M-00FA_H-1_P-1" Text="Two-gang switch" OrderNumber="SW-2" IsRailMounted="false" DefaultLanguage="en-US"/></Products><Hardware2Programs><Hardware2Program Id="M-00FA_H-1_HP-1" MediumTypes="MT-0"><ApplicationProgramRef RefId="M-00FA_A-0001-01-0000"/></Hardware2Program></Hardware2Programs></Hardware></Hardware></Manufacturer></ManufacturerData></KNX>"#
        );
        let catalog = format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><Catalog><CatalogSection Id="M-00FA_CS-1" Name="Switches" Number="1" DefaultLanguage="en-US"><CatalogItem Id="M-00FA_CI-1" Name="Bench switch" Number="1" ProductRefId="M-00FA_H-1_P-1" Hardware2ProgramRefId="M-00FA_H-1_HP-1" DefaultLanguage="en-US"/></CatalogSection></Catalog></Manufacturer></ManufacturerData></KNX>"#
        );

        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            let options = SimpleFileOptions::default();
            for (name, contents) in [
                ("M-00FA/M-00FA_A-0001-01-0000.xml", application.as_str()),
                ("M-00FA/Hardware.xml", hardware.as_str()),
                ("M-00FA/Catalog.xml", catalog.as_str()),
                ("M-00FA/future.xml", "<Future value=\"untouched\"/>"),
            ] {
                zip.start_file(name, options).expect("archive entry starts");
                zip.write_all(contents.as_bytes()).expect("archive entry writes");
            }
            zip.finish().expect("archive finishes");
        }

        let mut archive = KnxprodArchive::from_bytes(&buf.into_inner()).expect("archive opens");
        let devices = archive.importable_devices().expect("catalogue resolves");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "Bench switch");
        assert_eq!(devices[0].order_number.as_deref(), Some("SW-2"));
        assert_eq!(devices[0].product_id.as_deref(), Some("M-00FA_H-1_P-1"));
        assert_eq!(devices[0].application_program_id, "M-00FA_A-0001-01-0000");
        assert!(devices[0].supports_data_secure);

        let mut document = archive
            .parse_application_program("M-00FA_A-0001-01-0000")
            .expect("program exists")
            .expect("program parses");
        document.manufacturer_data.manufacturer.application_programs.programs[0].name = "Edited".to_owned();
        archive.replace_application_program("M-00FA_A-0001-01-0000", &document).expect("program replaces");
        let rewritten = RawArchive::from_bytes(&archive.to_bytes().expect("archive writes")).expect("rewrite opens");
        assert_eq!(
            rewritten.entry("M-00FA/future.xml").expect("unknown document remains").bytes(),
            b"<Future value=\"untouched\"/>"
        );
    }

    #[test]
    fn second_pei_program_is_relation_metadata_not_a_standalone_device() {
        use std::io::Write;
        use zip::write::SimpleFileOptions;

        const ROOT: &str = r#"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="test" ToolVersion="1" xmlns="http://knx.org/xml/project/23""#;
        const AP1: &str = "M-00FA_A-0001-01-0000";
        const AP2: &str = "M-00FA_A-0002-01-0000";
        const PRODUCT: &str = "M-00FA_H-1_P-1";
        let application = |id: &str, program_type: &str| {
            format!(
                r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms><ApplicationProgram Id="{id}" ApplicationNumber="1" ApplicationVersion="1" ProgramType="{program_type}" MaskVersion="MV-0705" Name="Program" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="en-US" DynamicTableManagement="false" Linkable="false"><Static><Code/></Static></ApplicationProgram></ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#
            )
        };
        let hardware = format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><Hardware><Hardware Id="M-00FA_H-1" Name="Hardware" SerialNumber="1" VersionNumber="1" HasIndividualAddress="true" HasApplicationProgram="true" HasApplicationProgram2="true"><Products><Product Id="{PRODUCT}" Text="Product" OrderNumber="P-1" IsRailMounted="false" DefaultLanguage="en-US"/></Products><Hardware2Programs><Hardware2Program Id="M-00FA_H-1_HP-1" MediumTypes="MT-0"><ApplicationProgramRef RefId="{AP1}"/><ApplicationProgramRef RefId="{AP2}"/></Hardware2Program></Hardware2Programs></Hardware></Hardware></Manufacturer></ManufacturerData></KNX>"#
        );
        let catalogue = format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><Catalog><CatalogSection Id="M-00FA_CS-1" Name="Products" Number="1" DefaultLanguage="en-US"><CatalogItem Id="M-00FA_CI-1" Name="Product" Number="1" ProductRefId="{PRODUCT}" Hardware2ProgramRefId="M-00FA_H-1_HP-1" DefaultLanguage="en-US"/></CatalogSection></Catalog></Manufacturer></ManufacturerData></KNX>"#
        );

        let mut bytes = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            let options = SimpleFileOptions::default();
            for (name, contents) in [
                (format!("M-00FA/{AP1}.xml"), application(AP1, "ApplicationProgram")),
                (format!("M-00FA/{AP2}.xml"), application(AP2, "PeiProgram")),
                ("M-00FA/Hardware.xml".to_owned(), hardware),
                ("M-00FA/Catalog.xml".to_owned(), catalogue),
            ] {
                zip.start_file(name, options).expect("archive entry starts");
                zip.write_all(contents.as_bytes()).expect("archive entry writes");
            }
            zip.finish().expect("archive finishes");
        }

        let archive = KnxprodArchive::from_bytes(&bytes.into_inner()).expect("archive opens");
        let devices = archive.importable_devices().expect("catalogue resolves");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].application_program_id, AP1);

        let relation = archive
            .application_program_relation(AP1, Some(PRODUCT))
            .expect("relation validates")
            .expect("relation exists");
        assert_eq!(relation.ordered_application_program_ids(), [AP1, AP2]);
        assert_eq!(relation.hardware.application_program_2, crate::schema::HardwareApplicationProgram2::Present {
            application_program_id: AP2.to_owned()
        });

        let selected = super::super::PackageArchive::from_bytes(archive.to_bytes().expect("unchanged archive"))
            .expect("header index")
            .load_product("M-00FA_CI-1")
            .expect("fully bound selected product");
        assert_eq!(selected.relation(), Some(&relation));
        assert_eq!(selected.product().application_program_2(), &relation.into());
    }
}

#[cfg(all(test, feature = "signing"))]
mod roundtrip_tests {
    use super::*;

    /// The reader must handle what our own writer produces, including
    /// the bundled master data. Uses the real `create_knxprod`, so a
    /// layout change on either side breaks this.
    #[test]
    fn reads_an_archive_written_by_create_knxprod() {
        use crate::signing::{ConverterKey, MasterDataSource, SigningConfig, create_knxprod};

        // The `Knx` root requires the xsi/xsd/CreatedBy/ToolVersion
        // attributes that every real ETS document (and our generator)
        // carries; a fixture without them fails to parse.
        const ROOT_ATTRS: &str = r#"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20""#;

        let app_xml = format!(
            r#"<KNX {ROOT_ATTRS}><ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms><ApplicationProgram Id="M-00FA_A-0306-02-0000" ApplicationNumber="774" ApplicationVersion="2" ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="Test" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="false" Linkable="false"><Static><Code/></Static></ApplicationProgram></ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#
        );
        let app_xml = app_xml.as_str();

        let config = SigningConfig {
            manufacturer_id: "00FA".to_string(),
            application_programs: vec![("M-00FA_A-0306-02-0000".to_string(), app_xml.to_string())],
            hardware: format!(
                "<KNX {ROOT_ATTRS}><ManufacturerData><Manufacturer RefId=\"M-00FA\"><Hardware/></Manufacturer></ManufacturerData></KNX>"
            ),
            catalog: format!(
                "<KNX {ROOT_ATTRS}><ManufacturerData><Manufacturer RefId=\"M-00FA\"><Catalog/></Manufacturer></ManufacturerData></KNX>"
            ),
            baggage_files: vec![],
        };

        let master = "<KNX><MasterData Id=\"MD-1\" Version=\"1\"/></KNX>";
        let key_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join("converter_key.xml");
        let key = ConverterKey::from_file(key_path).expect("converter key loads");
        let bytes = create_knxprod(&config, MasterDataSource::Content(master.to_string()), &key)
            .expect("packaging a minimal product succeeds");

        let archive = KnxprodArchive::from_bytes(&bytes).expect("our own archive opens");
        assert_eq!(archive.master_data_xml(), Some(master), "master data survives the round-trip");
        assert_eq!(archive.application_program_ids().collect::<Vec<_>>(), ["M-00FA_A-0306-02-0000"]);

        let knx = archive.parse_sole_application_program().expect("exactly one program").expect("it parses");
        let program = &knx.manufacturer_data.manufacturer.application_programs.programs[0];
        assert_eq!(program.mask_version, "MV-0705");
    }
}
