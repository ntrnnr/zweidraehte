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
//! So pointing the download engine at a single `.knxprod` supplies the
//! mask resources *and* the product's segments and load procedures,
//! with no separate master-data resolution needed.
//!
//! Only reading lives here; writing (and signing) is
//! [`crate::signing::packaging`]. Gated on the `product-files`
//! feature, which costs the `zip` dependency.
//!
//! Signatures are **not** verified on read. ETS uses them to police
//! its catalogue; for reading a product's memory layout the useful
//! failure mode is a parse error on malformed XML, not a refusal to
//! open an unsigned or self-generated archive — our own test fixtures
//! are exactly that.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::Path;

use crate::runtime::parser::{ParseError, parse_application_program};
use crate::schema::{CatalogItem, CatalogKnx, CatalogSection, HardwareKnx, Knx};

/// The entry holding master data at the archive root.
const MASTER_DATA_ENTRY: &str = "knx_master.xml";

/// A `.knxprod` archive opened for reading.
///
/// Entries are read eagerly into memory: the XML inside is a few
/// hundred kilobytes and every consumer wants the whole document
/// anyway, so streaming would buy nothing but lifetimes.
#[derive(Debug, Clone)]
pub struct KnxprodArchive {
    master_data: Option<String>,
    /// `(application program id, xml)`, in archive order.
    programs: Vec<(String, String)>,
    hardware: Vec<String>,
    catalogs: Vec<String>,
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
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ParseError> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Open a `.knxprod` held in memory.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
            .map_err(|e| ParseError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

        let mut master_data = None;
        let mut programs = Vec::new();
        let mut hardware = Vec::new();
        let mut catalogs = Vec::new();

        for i in 0..archive.len() {
            let mut entry = archive
                .by_index(i)
                .map_err(|e| ParseError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            if !entry.is_file() {
                continue;
            }
            let name = entry.name().to_string();

            let is_master = name == MASTER_DATA_ENTRY;
            let program_id = application_program_id(&name);
            let is_hardware = name.ends_with("/Hardware.xml") || name == "Hardware.xml";
            let is_catalog = name.ends_with("/Catalog.xml") || name == "Catalog.xml";
            if !is_master && program_id.is_none() && !is_hardware && !is_catalog {
                continue; // baggages, signatures and other support files
            }

            let mut content = String::new();
            entry.read_to_string(&mut content)?;

            if is_master {
                master_data = Some(content);
            } else if let Some(id) = program_id {
                programs.push((id, content));
            } else if is_hardware {
                hardware.push(content);
            } else if is_catalog {
                catalogs.push(content);
            }
        }

        Ok(Self { master_data, programs, hardware, catalogs })
    }

    /// The bundled `knx_master.xml`, if the archive carries one.
    ///
    /// Feed it to the client's mask database instead of resolving
    /// master data separately.
    pub fn master_data_xml(&self) -> Option<&str> {
        self.master_data.as_deref()
    }

    /// Application program IDs in the archive, e.g.
    /// `M-00FA_A-0306-02-0000`.
    pub fn application_program_ids(&self) -> impl Iterator<Item = &str> {
        self.programs.iter().map(|(id, _)| id.as_str())
    }

    /// Raw XML of one application program.
    pub fn application_program_xml(&self, id: &str) -> Option<&str> {
        self.programs.iter().find(|(pid, _)| pid == id).map(|(_, xml)| xml.as_str())
    }

    /// Parse one application program by ID.
    pub fn parse_application_program(&self, id: &str) -> Option<Result<Knx, ParseError>> {
        self.application_program_xml(id).map(parse_application_program)
    }

    /// Parse the archive's only application program.
    ///
    /// Convenience for the common single-product package; `None` when
    /// the archive holds zero or several, since picking one for the
    /// caller would be a guess.
    pub fn parse_sole_application_program(&self) -> Option<Result<Knx, ParseError>> {
        match self.programs.as_slice() {
            [(_, xml)] => Some(parse_application_program(xml)),
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
    pub fn importable_devices(&self) -> Result<Vec<KnxprodDevice>, ParseError> {
        let mut programs = BTreeMap::new();
        for (id, xml) in &self.programs {
            let knx = parse_application_program(xml)?;
            if let Some(program) = knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next() {
                programs.insert(
                    id.clone(),
                    (program.name, program.mask_version, program.is_secure_enabled.unwrap_or(false)),
                );
            }
        }

        let hardware = self
            .hardware
            .iter()
            .map(|xml| quick_xml::de::from_str::<HardwareKnx>(xml).map_err(ParseError::from))
            .collect::<Result<Vec<_>, _>>()?;
        let catalogs = self
            .catalogs
            .iter()
            .map(|xml| quick_xml::de::from_str::<CatalogKnx>(xml).map_err(ParseError::from))
            .collect::<Result<Vec<_>, _>>()?;

        let mut products = BTreeMap::new();
        let mut relations = BTreeMap::new();
        for document in &hardware {
            for hardware in &document.manufacturer_data.manufacturer.hardware.hardware {
                for product in &hardware.products.products {
                    products.insert(product.id.clone(), (hardware.id.clone(), product));
                }
                for relation in &hardware.hardware2programs.hardware2programs {
                    relations.insert(relation.id.clone(), (hardware.id.clone(), relation));
                }
            }
        }

        let mut catalog_items = Vec::new();
        for document in &catalogs {
            collect_catalog_items(
                &document.manufacturer_data.manufacturer.catalog.catalog_sections,
                &mut catalog_items,
            );
        }

        let mut represented_programs = BTreeSet::new();
        let mut represented_products = BTreeSet::new();
        let mut devices = Vec::new();
        for item in catalog_items {
            let Some((product_hardware, product)) = products.get(&item.product_ref_id) else { continue };
            let Some((relation_hardware, relation)) = relations.get(&item.hardware2program_ref_id) else { continue };
            if product_hardware != relation_hardware {
                continue;
            }
            let application_program_id = relation.application_program_ref.ref_id.clone();
            let Some((program_name, mask_version, supports_data_secure)) = programs.get(&application_program_id) else {
                continue;
            };
            if !represented_products.insert((product.id.clone(), relation.id.clone())) {
                continue;
            }
            represented_programs.insert(application_program_id.clone());
            devices.push(KnxprodDevice {
                catalog_item_id: Some(item.id.clone()),
                product_id: Some(product.id.clone()),
                hardware_id: Some(product_hardware.clone()),
                application_program_id,
                name: if item.name.trim().is_empty() {
                    if product.text.trim().is_empty() { program_name.clone() } else { product.text.clone() }
                } else {
                    item.name.clone()
                },
                order_number: (!product.order_number.trim().is_empty()).then(|| product.order_number.clone()),
                mask_version: mask_version.clone(),
                supports_data_secure: *supports_data_secure,
            });
        }

        for (id, (name, mask_version, supports_data_secure)) in programs {
            if represented_programs.contains(&id) {
                continue;
            }
            devices.push(KnxprodDevice {
                catalog_item_id: None,
                product_id: None,
                hardware_id: None,
                application_program_id: id,
                name,
                order_number: None,
                mask_version,
                supports_data_secure,
            });
        }
        devices.sort_by(|left, right| {
            (&left.name, &left.order_number, &left.application_program_id).cmp(&(
                &right.name,
                &right.order_number,
                &right.application_program_id,
            ))
        });
        Ok(devices)
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
fn application_program_id(entry_name: &str) -> Option<String> {
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
            ] {
                zip.start_file(name, options).expect("archive entry starts");
                zip.write_all(contents.as_bytes()).expect("archive entry writes");
            }
            zip.finish().expect("archive finishes");
        }

        let archive = KnxprodArchive::from_bytes(&buf.into_inner()).expect("archive opens");
        let devices = archive.importable_devices().expect("catalogue resolves");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "Bench switch");
        assert_eq!(devices[0].order_number.as_deref(), Some("SW-2"));
        assert_eq!(devices[0].product_id.as_deref(), Some("M-00FA_H-1_P-1"));
        assert_eq!(devices[0].application_program_id, "M-00FA_A-0001-01-0000");
        assert!(devices[0].supports_data_secure);
    }
}

#[cfg(all(test, feature = "packaging"))]
mod roundtrip_tests {
    use super::*;

    /// The reader must handle what our own writer produces, including
    /// the bundled master data. Uses the real `create_knxprod`, so a
    /// layout change on either side breaks this.
    #[test]
    fn reads_an_archive_written_by_create_knxprod() {
        use crate::signing::{MasterDataSource, SigningConfig, create_knxprod};

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
        let bytes = create_knxprod(&config, MasterDataSource::Content(master.to_string()))
            .expect("packaging a minimal product succeeds");

        let archive = KnxprodArchive::from_bytes(&bytes).expect("our own archive opens");
        assert_eq!(archive.master_data_xml(), Some(master), "master data survives the round-trip");
        assert_eq!(archive.application_program_ids().collect::<Vec<_>>(), ["M-00FA_A-0306-02-0000"]);

        let knx = archive.parse_sole_application_program().expect("exactly one program").expect("it parses");
        let program = &knx.manufacturer_data.manufacturer.application_programs.programs[0];
        assert_eq!(program.mask_version, "MV-0705");
    }
}
