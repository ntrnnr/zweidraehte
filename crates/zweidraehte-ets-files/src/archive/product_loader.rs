//! Deterministic application-program selection for MTXML and `.knxprod`.

use std::path::{Path, PathBuf};

use thiserror::Error;

use super::{ApplicationProgramRelation, ArchiveError, KnxprodArchive};
use crate::product::{ProductData, ProductError, extract_product};
use crate::runtime::{ParseError, Translations, parse_application_program_from_file};
use crate::schema::{ApplicationProgram, HardwareApplicationProgramError, HardwareKnx, Knx};

#[derive(Debug, Clone, Copy, Default)]
pub struct ProgramSelection<'a> {
    pub catalog_product: Option<&'a str>,
    pub application_program: Option<&'a str>,
}

#[derive(Debug, Error)]
pub enum ProductLoadError {
    #[error(transparent)]
    Product(#[from] ProductError),
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error("{path}: a loose MTXML cannot select a catalogue product")]
    LooseCatalogueSelection { path: PathBuf },
    #[error("{path}: defines {count} application programs; exactly one is required")]
    ApplicationCount { path: PathBuf, count: usize },
    #[error("{path}: contains application {actual:?}, not {expected:?}")]
    ApplicationMismatch { path: PathBuf, actual: String, expected: String },
    #[error("{path}: a catalogue product requires an application-program selection")]
    CatalogueRequiresApplication { path: PathBuf },
    #[error("{path}: has no catalogue product {product:?}")]
    MissingCatalogueProduct { path: PathBuf, product: String },
    #[error("{path}: catalogue product {product:?} uses application {actual:?}, not {expected:?}")]
    CatalogueApplicationMismatch { path: PathBuf, product: String, actual: String, expected: String },
    #[error("{path}: has no application program {application:?}")]
    MissingApplication { path: PathBuf, application: String },
    #[error("{path}: contains no application program")]
    MissingApplications { path: PathBuf },
    #[error("{path}: contains {count} application programs ({available}); select one explicitly")]
    AmbiguousApplication { path: PathBuf, count: usize, available: String },
    #[error("{path}: cannot resolve the selected application's Hardware.xml relation")]
    ApplicationProgramPairing {
        path: PathBuf,
        #[source]
        source: ProductError,
    },
}

#[derive(Debug, Clone)]
pub struct LoadedProgram {
    pub document: Knx,
    pub archive: Option<KnxprodArchive>,
    catalog_product: Option<String>,
    source: PathBuf,
}

impl LoadedProgram {
    /// Extract the selected product together with its package-owned Master Data.
    pub fn product_data(&self) -> Result<ProductData, ProductLoadError> {
        let relation = self.application_program_pairing()?;
        Ok(extract_product(&self.document, relation, self.archive.as_ref().and_then(KnxprodArchive::master_data_xml))?)
    }

    /// Resolve the selected AP1 through package hardware metadata.
    ///
    /// For an archive this resolves the exact catalogue/product/hardware
    /// chain. Loose MTXML deliberately returns `None`: an adjacent file is not
    /// package authority for live commissioning. Editor/import tooling which
    /// intentionally works on an extracted directory may call
    /// [`resolve_loose_application_program_pairing`] explicitly.
    pub fn application_program_pairing(&self) -> Result<Option<ApplicationProgramRelation>, ProductLoadError> {
        let programs = &self.document.manufacturer_data.manufacturer.application_programs.programs;
        let [program] = programs.as_slice() else {
            return Err(ProductLoadError::ApplicationCount { path: self.source.clone(), count: programs.len() });
        };

        match &self.archive {
            Some(archive) => archive
                .application_program_relation(&program.id, self.catalog_product.as_deref())
                .map_err(|source| ProductLoadError::ApplicationProgramPairing { path: self.source.clone(), source }),
            None => Ok(None),
        }
    }

    pub fn into_parts(self) -> Result<(ApplicationProgram, Translations, Option<KnxprodArchive>), ProductLoadError> {
        let Self { document, archive, catalog_product: _, source } = self;
        let translations = Translations::from_knx(&document);
        let mut programs = document.manufacturer_data.manufacturer.application_programs.programs;
        match programs.len() {
            1 => Ok((programs.remove(0), translations, archive)),
            count => Err(ProductLoadError::ApplicationCount { path: source, count }),
        }
    }
}

/// Resolve an extracted application-program MTXML through its canonical
/// sibling `Hardware.xml`.
///
/// A missing sibling or a valid sibling with no matching first reference
/// returns `None`, preserving the unknown state for genuinely loose MTXML.
/// Once a matching relation exists, its AP2-absent/present result is
/// authoritative and contradictions fail closed.
pub fn resolve_loose_application_program_pairing(
    application_path: impl AsRef<Path>,
    application: &Knx,
) -> Result<Option<ApplicationProgramRelation>, ProductLoadError> {
    let application_path = application_path.as_ref();
    let programs = &application.manufacturer_data.manufacturer.application_programs.programs;
    let [_] = programs.as_slice() else {
        return Err(ProductLoadError::ApplicationCount { path: application_path.to_owned(), count: programs.len() });
    };
    let hardware_path = application_path.with_file_name("Hardware.xml");
    let source = match std::fs::read_to_string(&hardware_path) {
        Ok(source) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ProductLoadError::ApplicationProgramPairing {
                path: hardware_path,
                source: ProductError::Io(error),
            });
        }
    };
    let hardware: HardwareKnx = quick_xml::de::from_str(source.trim_start_matches('\u{feff}')).map_err(|error| {
        ProductLoadError::ApplicationProgramPairing {
            path: hardware_path.clone(),
            source: ProductError::HardwareXml(error),
        }
    })?;

    resolve_document_application_pairing(application, &hardware)
        .map_err(|source| ProductLoadError::ApplicationProgramPairing { path: hardware_path, source })
}

/// Resolve an application and its explicitly supplied Hardware.xml document.
/// The caller owns catalogue selection; this is the unambiguous AP1 fallback.
pub fn resolve_document_application_pairing(
    application: &Knx,
    hardware: &HardwareKnx,
) -> Result<Option<ApplicationProgramRelation>, ProductError> {
    let programs = &application.manufacturer_data.manufacturer.application_programs.programs;
    let application_program = match programs.as_slice() {
        [program] => program,
        [] => return Err(ProductError::MissingApplicationProgram),
        _ => return Err(ProductError::AmbiguousApplicationProgram { count: programs.len() }),
    };
    let application_manufacturer = &application.manufacturer_data.manufacturer.ref_id;
    let hardware_manufacturer = &hardware.manufacturer_data.manufacturer.ref_id;
    if application_manufacturer != hardware_manufacturer {
        return Err(HardwareApplicationProgramError::ManufacturerMismatch {
            application_program_id: application_program.id.clone(),
            expected: application_manufacturer.clone(),
            actual: hardware_manufacturer.clone(),
        }
        .into());
    }
    hardware.validate_application_schema(&application.xmlns)?;
    Ok(hardware
        .resolve_application_program_pairing(&application_program.id, Some(&application_program.program_type))?
        .map(|hardware| ApplicationProgramRelation { catalog_item_id: None, product_id: None, hardware }))
}

pub fn load_program(
    path: impl AsRef<Path>,
    selection: ProgramSelection<'_>,
) -> Result<LoadedProgram, ProductLoadError> {
    let path = path.as_ref();
    let is_archive = path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("knxprod"));
    if !is_archive {
        if selection.catalog_product.is_some() {
            return Err(ProductLoadError::LooseCatalogueSelection { path: path.to_path_buf() });
        }
        let document = parse_application_program_from_file(path)?;
        let programs = &document.manufacturer_data.manufacturer.application_programs.programs;
        if programs.len() != 1 {
            return Err(ProductLoadError::ApplicationCount { path: path.to_path_buf(), count: programs.len() });
        }
        if let Some(expected) = selection.application_program
            && programs[0].id != expected
        {
            return Err(ProductLoadError::ApplicationMismatch {
                path: path.to_path_buf(),
                actual: programs[0].id.clone(),
                expected: expected.to_owned(),
            });
        }
        return Ok(LoadedProgram { document, archive: None, catalog_product: None, source: path.to_path_buf() });
    }

    let archive = KnxprodArchive::open(path)?;
    if selection.catalog_product.is_some() && selection.application_program.is_none() {
        return Err(ProductLoadError::CatalogueRequiresApplication { path: path.to_path_buf() });
    }

    // The ZIP member name is only an index. Treat the parsed document as the
    // authority and prove that it contains exactly the application that the
    // caller (or the sole-entry fallback) selected. Otherwise a malformed
    // archive could make a catalogue relation name one application while the
    // loader silently programs another one from that entry.
    let selected = match selection.application_program {
        Some(id) => id.to_owned(),
        None => match archive.application_program_count() {
            1 => archive.application_program_ids().next().expect("one archive application has an id").to_owned(),
            0 => return Err(ProductLoadError::MissingApplications { path: path.to_path_buf() }),
            count => {
                let ids = archive.application_program_ids().collect::<Vec<_>>().join(", ");
                return Err(ProductLoadError::AmbiguousApplication { path: path.to_path_buf(), count, available: ids });
            }
        },
    };
    let document = archive.parse_application_program(&selected).ok_or_else(|| {
        ProductLoadError::MissingApplication { path: path.to_path_buf(), application: selected.clone() }
    })??;
    let programs = &document.manufacturer_data.manufacturer.application_programs.programs;
    let [program] = programs.as_slice() else {
        return Err(ProductLoadError::ApplicationCount { path: path.to_path_buf(), count: programs.len() });
    };
    if program.id != selected {
        return Err(ProductLoadError::ApplicationMismatch {
            path: path.to_path_buf(),
            actual: program.id.clone(),
            expected: selected,
        });
    }
    if let Some(product) = selection.catalog_product {
        archive
            .application_program_relation(&program.id, Some(product))
            .map_err(|source| ProductLoadError::ApplicationProgramPairing { path: path.to_path_buf(), source })?
            .ok_or_else(|| ProductLoadError::MissingCatalogueProduct {
                path: path.to_path_buf(),
                product: product.to_owned(),
            })?;
    }

    Ok(LoadedProgram {
        document,
        archive: Some(archive),
        catalog_product: selection.catalog_product.map(str::to_owned),
        source: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write as _;

    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;

    use super::*;

    const ROOT: &str = r#"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="test" ToolVersion="1" xmlns="http://knx.org/xml/project/23""#;
    const FIRST: &str = "M-00FA_A-0001-01-0000";
    const SECOND: &str = "M-00FA_A-0002-01-0000";
    const PRODUCT: &str = "M-00FA_H-1_P-1";

    fn application(id: &str) -> String {
        format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms><ApplicationProgram Id="{id}" ApplicationNumber="1" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="Test" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="en-US" DynamicTableManagement="false" Linkable="false"><Static><Code/></Static></ApplicationProgram></ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#
        )
    }

    fn hardware(has_ap2: Option<bool>, refs: &[&str]) -> String {
        let has_ap2 = has_ap2.map(|value| format!(r#" HasApplicationProgram2="{value}""#)).unwrap_or_default();
        let refs = refs.iter().map(|id| format!(r#"<ApplicationProgramRef RefId="{id}"/>"#)).collect::<String>();
        format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><Hardware><Hardware Id="M-00FA_H-1" Name="Hardware" SerialNumber="1" VersionNumber="256" BusCurrent="12.5" HasIndividualAddress="true" HasApplicationProgram="true"{has_ap2}><Products/><Hardware2Programs><Hardware2Program Id="M-00FA_H-1_HP-1" MediumTypes="MT-0">{refs}</Hardware2Program></Hardware2Programs></Hardware></Hardware></Manufacturer></ManufacturerData></KNX>"#
        )
    }

    fn archive_entries(programs: &[(&str, &str)], with_catalog: bool) -> (TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("fixture.knxprod");
        let mut archive = zip::ZipWriter::new(File::create(&path).expect("archive creates"));
        let options = SimpleFileOptions::default();
        for (entry_id, document_id) in programs {
            archive.start_file(format!("M-00FA/{entry_id}.xml"), options).expect("program entry starts");
            archive.write_all(application(document_id).as_bytes()).expect("program entry writes");
        }
        if with_catalog {
            let hardware = format!(
                r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><Hardware><Hardware Id="M-00FA_H-1" Name="Hardware" SerialNumber="1" VersionNumber="1" HasIndividualAddress="true" HasApplicationProgram="true"><Products><Product Id="{PRODUCT}" Text="Product" OrderNumber="P-1" IsRailMounted="false" DefaultLanguage="en-US"/></Products><Hardware2Programs><Hardware2Program Id="M-00FA_H-1_HP-1" MediumTypes="MT-0"><ApplicationProgramRef RefId="{FIRST}"/></Hardware2Program></Hardware2Programs></Hardware></Hardware></Manufacturer></ManufacturerData></KNX>"#
            );
            let catalog = format!(
                r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><Catalog><CatalogSection Id="M-00FA_CS-1" Name="Products" Number="1" DefaultLanguage="en-US"><CatalogItem Id="M-00FA_CI-1" Name="Product" Number="1" ProductRefId="{PRODUCT}" Hardware2ProgramRefId="M-00FA_H-1_HP-1" DefaultLanguage="en-US"/></CatalogSection></Catalog></Manufacturer></ManufacturerData></KNX>"#
            );
            for (name, contents) in [("M-00FA/Hardware.xml", hardware), ("M-00FA/Catalog.xml", catalog)] {
                archive.start_file(name, options).expect("catalogue entry starts");
                archive.write_all(contents.as_bytes()).expect("catalogue entry writes");
            }
        }
        archive.finish().expect("archive finishes");
        (directory, path)
    }

    fn archive(programs: &[&str], with_catalog: bool) -> (TempDir, PathBuf) {
        let entries = programs.iter().map(|id| (*id, *id)).collect::<Vec<_>>();
        archive_entries(&entries, with_catalog)
    }

    fn archive_with_shared_product_relations() -> (TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("shared-product.knxprod");
        let hardware = format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><Hardware><Hardware Id="M-00FA_H-1" Name="Hardware" SerialNumber="1" VersionNumber="1" HasIndividualAddress="true" HasApplicationProgram="true"><Products><Product Id="{PRODUCT}" Text="Product" OrderNumber="P-1" IsRailMounted="false" DefaultLanguage="en-US"/></Products><Hardware2Programs><Hardware2Program Id="M-00FA_H-1_HP-1" MediumTypes="MT-0"><ApplicationProgramRef RefId="{FIRST}"/></Hardware2Program><Hardware2Program Id="M-00FA_H-1_HP-2" MediumTypes="MT-0"><ApplicationProgramRef RefId="{SECOND}"/></Hardware2Program></Hardware2Programs></Hardware></Hardware></Manufacturer></ManufacturerData></KNX>"#
        );
        let catalogue = format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><Catalog><CatalogSection Id="M-00FA_CS-1" Name="Products" Number="1" DefaultLanguage="en-US"><CatalogItem Id="M-00FA_CI-1" Name="First" Number="1" ProductRefId="{PRODUCT}" Hardware2ProgramRefId="M-00FA_H-1_HP-1" DefaultLanguage="en-US"/><CatalogItem Id="M-00FA_CI-2" Name="Second" Number="2" ProductRefId="{PRODUCT}" Hardware2ProgramRefId="M-00FA_H-1_HP-2" DefaultLanguage="en-US"/></CatalogSection></Catalog></Manufacturer></ManufacturerData></KNX>"#
        );
        let mut archive = zip::ZipWriter::new(File::create(&path).expect("archive creates"));
        let options = SimpleFileOptions::default();
        for (name, contents) in [
            (format!("M-00FA/{FIRST}.xml"), application(FIRST)),
            (format!("M-00FA/{SECOND}.xml"), application(SECOND)),
            ("M-00FA/Hardware.xml".to_owned(), hardware),
            ("M-00FA/Catalog.xml".to_owned(), catalogue),
        ] {
            archive.start_file(name, options).expect("archive entry starts");
            archive.write_all(contents.as_bytes()).expect("archive entry writes");
        }
        archive.finish().expect("archive finishes");
        (directory, path)
    }

    #[test]
    fn loose_mtxml_accepts_only_a_matching_application_selector() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("application.xml");
        std::fs::write(&path, application(FIRST)).expect("fixture writes");

        let loaded = load_program(&path, ProgramSelection::default()).expect("loose product loads");
        assert_eq!(loaded.into_parts().expect("one program").0.id, FIRST);
        assert!(
            load_program(&path, ProgramSelection { catalog_product: None, application_program: Some(FIRST) }).is_ok()
        );
        assert!(
            load_program(&path, ProgramSelection { catalog_product: None, application_program: Some(SECOND) }).is_err()
        );
        assert!(
            load_program(&path, ProgramSelection { catalog_product: Some(PRODUCT), application_program: Some(FIRST) })
                .is_err()
        );
    }

    #[test]
    fn loose_mtxml_uses_only_its_canonical_sibling_hardware_relation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join(format!("{FIRST}.xml"));
        std::fs::write(&path, application(FIRST)).expect("application fixture writes");

        let loaded = load_program(&path, ProgramSelection::default()).expect("loose product loads");
        assert_eq!(loaded.application_program_pairing().expect("missing sibling is not an error"), None);

        std::fs::write(directory.path().join("Hardware.xml"), hardware(None, &[FIRST]))
            .expect("hardware fixture writes");
        assert_eq!(loaded.application_program_pairing().expect("loose loading stays unbound"), None);
        let pairing = resolve_loose_application_program_pairing(&path, &loaded.document)
            .expect("sibling relation resolves")
            .expect("the first reference matches");
        assert_eq!(pairing.hardware.application_program_2, crate::schema::HardwareApplicationProgram2::Absent);
    }

    #[test]
    fn loose_mtxml_retains_an_explicit_second_application() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join(format!("{FIRST}.xml"));
        std::fs::write(&path, application(FIRST)).expect("application fixture writes");
        std::fs::write(directory.path().join("Hardware.xml"), hardware(Some(true), &[FIRST, SECOND]))
            .expect("hardware fixture writes");

        let loaded = load_program(&path, ProgramSelection::default()).expect("loose product loads");
        let pairing = resolve_loose_application_program_pairing(&path, &loaded.document)
            .expect("sibling relation resolves")
            .expect("the first reference matches");
        assert_eq!(pairing.hardware.application_program_2, crate::schema::HardwareApplicationProgram2::Present {
            application_program_id: SECOND.to_owned()
        });
    }

    #[test]
    fn loose_mtxml_rejects_an_incompatible_existing_hardware_sibling() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join(format!("{FIRST}.xml"));
        std::fs::write(&path, application(FIRST)).expect("application fixture writes");

        let wrong_manufacturer = hardware(None, &[FIRST]).replace("M-00FA", "M-00FB");
        std::fs::write(directory.path().join("Hardware.xml"), wrong_manufacturer).expect("hardware fixture writes");
        let loaded = load_program(&path, ProgramSelection::default()).expect("application itself loads");
        assert!(matches!(
            resolve_loose_application_program_pairing(&path, &loaded.document),
            Err(ProductLoadError::ApplicationProgramPairing {
                source: ProductError::HardwareApplicationProgram(
                    HardwareApplicationProgramError::ManufacturerMismatch { .. }
                ),
                ..
            })
        ));

        let wrong_schema =
            hardware(None, &[FIRST]).replace("http://knx.org/xml/project/23", "http://knx.org/xml/project/20");
        std::fs::write(directory.path().join("Hardware.xml"), wrong_schema).expect("hardware fixture rewrites");
        assert!(matches!(
            resolve_loose_application_program_pairing(&path, &loaded.document),
            Err(ProductLoadError::ApplicationProgramPairing {
                source: ProductError::HardwareApplicationProgram(
                    HardwareApplicationProgramError::SchemaConflict { .. }
                ),
                ..
            })
        ));
    }

    #[test]
    fn archives_require_unambiguous_application_selection() {
        let (_directory, single) = archive(&[FIRST], false);
        assert_eq!(
            load_program(&single, ProgramSelection::default())
                .expect("single archive loads")
                .into_parts()
                .expect("one")
                .0
                .id,
            FIRST
        );

        let (_directory, multiple) = archive(&[FIRST, SECOND], false);
        assert!(load_program(&multiple, ProgramSelection::default()).is_err());
        assert_eq!(
            load_program(&multiple, ProgramSelection { catalog_product: None, application_program: Some(SECOND) },)
                .expect("selected archive loads")
                .into_parts()
                .expect("one")
                .0
                .id,
            SECOND
        );
        assert!(
            load_program(&multiple, ProgramSelection { catalog_product: None, application_program: Some("MISSING") },)
                .is_err()
        );
    }

    #[test]
    fn archive_entry_must_contain_the_selected_application() {
        let (_directory, path) = archive_entries(&[(FIRST, SECOND), (SECOND, SECOND)], true);

        assert_eq!(
            load_program(&path, ProgramSelection { catalog_product: None, application_program: Some(SECOND) })
                .expect("the valid entry remains selectable")
                .into_parts()
                .expect("the valid entry contains one application")
                .0
                .id,
            SECOND
        );

        let error =
            load_program(&path, ProgramSelection { catalog_product: Some(PRODUCT), application_program: Some(FIRST) })
                .err()
                .expect("the entry name and catalogue cannot impersonate another application");
        assert!(matches!(
            error,
            ProductLoadError::ApplicationMismatch { actual, expected, .. }
                if actual == SECOND && expected == FIRST
        ));
    }

    #[test]
    fn catalogue_and_application_selectors_must_match() {
        let (_directory, path) = archive(&[FIRST, SECOND], true);
        assert!(
            load_program(
                &path,
                ProgramSelection { catalog_product: Some(PRODUCT), application_program: Some(SECOND) },
            )
            .is_err()
        );
        let loaded =
            load_program(&path, ProgramSelection { catalog_product: Some(PRODUCT), application_program: Some(FIRST) })
                .expect("matching selection loads");
        let relation =
            loaded.application_program_pairing().expect("archive hardware resolves").expect("archive relation exists");
        assert_eq!(relation.catalog_item_id.as_deref(), Some("M-00FA_CI-1"));
        assert_eq!(relation.product_id.as_deref(), Some(PRODUCT));
        assert_eq!(relation.hardware.hardware_id, "M-00FA_H-1");
        assert_eq!(relation.hardware.hardware2program_id, "M-00FA_H-1_HP-1");
        assert_eq!(relation.ordered_application_program_ids(), [FIRST]);
        assert_eq!(relation.hardware.application_program_2, crate::schema::HardwareApplicationProgram2::Absent);
        assert_eq!(loaded.into_parts().expect("one").0.id, FIRST);
    }

    #[test]
    fn product_and_ap1_select_the_exact_relation_instead_of_the_first_catalogue_item() {
        let (_directory, path) = archive_with_shared_product_relations();

        let loaded =
            load_program(&path, ProgramSelection { catalog_product: Some(PRODUCT), application_program: Some(SECOND) })
                .expect("product plus AP1 is an exact relation selector");
        let relation = loaded.application_program_pairing().expect("relation resolves").expect("relation exists");

        assert_eq!(relation.catalog_item_id.as_deref(), Some("M-00FA_CI-2"));
        assert_eq!(relation.hardware.hardware2program_id, "M-00FA_H-1_HP-2");
        assert_eq!(relation.ordered_application_program_ids(), [SECOND]);
    }
}
