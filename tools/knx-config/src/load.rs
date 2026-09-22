//! Product-file and master-data loading shared by both binaries.

use std::path::Path;

use anyhow::{Context, Result};

use zweidraehte_client::commissioning::{LoadedProgrammingCatalog, ProgrammingCatalog, ProgrammingCatalogLoadRequest};
use zweidraehte_ets_files::archive::{KnxprodArchive, ProgramSelection};
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_ets_files::runtime::Translations;
use zweidraehte_ets_files::schema::ApplicationProgram;

/// Read the application program out of a loose MTXML file or a
/// `.knxprod` archive, along with the document's translations (they
/// live at the manufacturer level, outside the program element). The
/// archive (when there is one) comes back too, because it may carry
/// the bundled `knx_master.xml`.
pub fn load_program(path: &Path) -> Result<(ApplicationProgram, Translations, Option<KnxprodArchive>)> {
    load_program_selected(path, None)
}

/// Load one explicitly selected application program. Multi-program archives
/// require the selector; loose MTXML accepts it only when it matches the
/// document's own ID.
pub fn load_program_selected(
    path: &Path,
    application_program: Option<&str>,
) -> Result<(ApplicationProgram, Translations, Option<KnxprodArchive>)> {
    load_program_selection(path, None, application_program)
}

/// Load one application and verify its catalogue-product relation.
///
/// Projects retain both IDs because several saleable products can share an
/// application program. Checking the relation on every open prevents a
/// hand-edited or replaced archive from silently selecting a different
/// downloadable application.
pub fn load_program_selection(
    path: &Path,
    catalog_product: Option<&str>,
    application_program: Option<&str>,
) -> Result<(ApplicationProgram, Translations, Option<KnxprodArchive>)> {
    zweidraehte_ets_files::archive::load_program(path, ProgramSelection { catalog_product, application_program })?
        .into_parts()
        .map_err(Into::into)
}

/// Use associated Master Data, or supply a document for a loose product.
pub fn load_programming_catalog(product: &ProductData, explicit: Option<&Path>) -> Result<LoadedProgrammingCatalog> {
    let request = match explicit.filter(|_| product.master_data().is_none()) {
        Some(path) => ProgrammingCatalogLoadRequest::File(path),
        None => ProgrammingCatalogLoadRequest::Product(product),
    };

    ProgrammingCatalog::load(request).context("while attempting to load product Master Data")
}

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_client::commissioning::ProgrammingCatalogLoadError;
    use zweidraehte_ets_files::MasterDataError;

    #[test]
    fn catalog_reporting_retains_the_typed_error_and_its_cause() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("missing-master.xml");
        let error = load_programming_catalog(&ProductData::default(), Some(&path)).err().expect("missing catalog");

        let cause = error.downcast_ref::<ProgrammingCatalogLoadError>().expect("typed catalog error");
        assert!(matches!(cause, ProgrammingCatalogLoadError::MasterData(MasterDataError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound));
        let report = format!("{error:#}");
        assert!(report.contains("while attempting to load product Master Data"));
        assert!(report.contains(&path.display().to_string()));
        assert!(report.contains(&error.root_cause().to_string()));
    }
}
