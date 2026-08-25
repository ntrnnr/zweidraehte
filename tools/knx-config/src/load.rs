//! Product-file and master-data loading shared by both binaries.

use std::path::Path;

use anyhow::{Context, Result};

use zweidraehte_client::download::MaskDb;
use zweidraehte_ets_files::archive::{KnxprodArchive, ProgramSelection};
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

/// Resolve the mask layer: an explicit `--master-data` path first, the
/// product archive's bundled copy second, then `MaskDb::resolve()`
/// (the `KNX_MASTER_DATA` env var, the on-disk cache, or a download).
pub fn load_mask_db(explicit: Option<&Path>, archive: Option<&KnxprodArchive>) -> Result<MaskDb> {
    if let Some(path) = explicit {
        return MaskDb::from_file(path)
            .with_context(|| format!("while attempting to read master data from {}", path.display()));
    }
    if let Some(archive) = archive
        && archive.master_data_xml().is_some()
    {
        return MaskDb::from_knxprod(archive).context("while attempting to read the archive's bundled master data");
    }
    MaskDb::resolve().context("while attempting to resolve knx_master.xml (set KNX_MASTER_DATA or pass --master-data)")
}
