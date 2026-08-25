//! Deterministic application-program selection for MTXML and `.knxprod`.

use std::path::{Path, PathBuf};

use thiserror::Error;

use super::{KnxprodArchive, ParseError, Translations, parse_application_program_from_file};
use crate::schema::{ApplicationProgram, Knx};

#[derive(Debug, Clone, Copy, Default)]
pub struct ProgramSelection<'a> {
    pub catalog_product: Option<&'a str>,
    pub application_program: Option<&'a str>,
}

#[derive(Debug, Error)]
pub enum ProductLoadError {
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("{path}: {message}")]
    Selection { path: PathBuf, message: String },
}

pub struct LoadedProgram {
    pub document: Knx,
    pub archive: Option<KnxprodArchive>,
    source: PathBuf,
}

impl LoadedProgram {
    pub fn into_parts(self) -> Result<(ApplicationProgram, Translations, Option<KnxprodArchive>), ProductLoadError> {
        let Self { document, archive, source } = self;
        let translations = Translations::from_knx(&document);
        let mut programs = document.manufacturer_data.manufacturer.application_programs.programs;
        match programs.len() {
            1 => Ok((programs.remove(0), translations, archive)),
            count => Err(ProductLoadError::Selection {
                path: source,
                message: format!("defines {count} application programs; exactly one is required"),
            }),
        }
    }
}

pub fn load_program(
    path: impl AsRef<Path>,
    selection: ProgramSelection<'_>,
) -> Result<LoadedProgram, ProductLoadError> {
    let path = path.as_ref();
    let is_archive = path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("knxprod"));
    if !is_archive {
        if selection.catalog_product.is_some() {
            return selection_error(path, "a loose MTXML cannot select a catalogue product");
        }
        let document = parse_application_program_from_file(path)?;
        let programs = &document.manufacturer_data.manufacturer.application_programs.programs;
        if programs.len() != 1 {
            return selection_error(
                path,
                format!("defines {} application programs; exactly one is required", programs.len()),
            );
        }
        if let Some(expected) = selection.application_program
            && programs[0].id != expected
        {
            return selection_error(path, format!("contains application `{}`, not `{expected}`", programs[0].id));
        }
        return Ok(LoadedProgram { document, archive: None, source: path.to_path_buf() });
    }

    let archive = KnxprodArchive::open(path)?;
    if let Some(product) = selection.catalog_product {
        let selected = selection.application_program.ok_or_else(|| ProductLoadError::Selection {
            path: path.to_path_buf(),
            message: "a catalogue product requires an application-program selection".into(),
        })?;
        let device = archive
            .importable_devices()?
            .into_iter()
            .find(|device| device.product_id.as_deref() == Some(product))
            .ok_or_else(|| ProductLoadError::Selection {
                path: path.to_path_buf(),
                message: format!("has no catalogue product `{product}`"),
            })?;
        if device.application_program_id != selected {
            return selection_error(
                path,
                format!(
                    "catalogue product `{product}` uses application `{}`, not `{selected}`",
                    device.application_program_id
                ),
            );
        }
    }

    let document = match selection.application_program {
        Some(id) => archive.parse_application_program(id).ok_or_else(|| ProductLoadError::Selection {
            path: path.to_path_buf(),
            message: format!("has no application program `{id}`"),
        })??,
        None => match archive.application_program_count() {
            1 => archive.parse_sole_application_program().expect("one program has a sole parser")?,
            0 => return selection_error(path, "contains no application program"),
            count => {
                let ids = archive.application_program_ids().collect::<Vec<_>>().join(", ");
                return selection_error(
                    path,
                    format!("contains {count} application programs ({ids}); select one explicitly"),
                );
            }
        },
    };
    Ok(LoadedProgram { document, archive: Some(archive), source: path.to_path_buf() })
}

fn selection_error<T>(path: &Path, message: impl Into<String>) -> Result<T, ProductLoadError> {
    Err(ProductLoadError::Selection { path: path.to_path_buf(), message: message.into() })
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

    fn archive(programs: &[&str], with_catalog: bool) -> (TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("fixture.knxprod");
        let mut archive = zip::ZipWriter::new(File::create(&path).expect("archive creates"));
        let options = SimpleFileOptions::default();
        for id in programs {
            archive.start_file(format!("M-00FA/{id}.xml"), options).expect("program entry starts");
            archive.write_all(application(id).as_bytes()).expect("program entry writes");
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
    fn catalogue_and_application_selectors_must_match() {
        let (_directory, path) = archive(&[FIRST, SECOND], true);
        assert!(
            load_program(
                &path,
                ProgramSelection { catalog_product: Some(PRODUCT), application_program: Some(SECOND) },
            )
            .is_err()
        );
        assert_eq!(
            load_program(&path, ProgramSelection { catalog_product: Some(PRODUCT), application_program: Some(FIRST) },)
                .expect("matching selection loads")
                .into_parts()
                .expect("one")
                .0
                .id,
            FIRST
        );
    }
}
