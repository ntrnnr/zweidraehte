//! Product-file and master-data loading shared by both binaries.

use std::path::Path;

use anyhow::{Context, Result, bail};

use zweidraehte_client::download::MaskDb;
use zweidraehte_knxprod::runtime::parser::parse_application_program_from_file;
use zweidraehte_knxprod::runtime::{KnxprodArchive, Translations};
use zweidraehte_knxprod::schema::ApplicationProgram;

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
    let is_archive = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("knxprod"));

    let (knx, archive) = if is_archive {
        let archive = KnxprodArchive::open(path)
            .with_context(|| format!("while attempting to open the archive {}", path.display()))?;
        if let Some(product) = catalog_product {
            let selected = application_program.context("a catalogue product requires an application selection")?;
            let device = archive
                .importable_devices()
                .context("while attempting to read the archive catalogue")?
                .into_iter()
                .find(|device| device.product_id.as_deref() == Some(product))
                .with_context(|| format!("archive {} has no catalogue product `{product}`", path.display()))?;
            if device.application_program_id != selected {
                bail!(
                    "catalogue product `{product}` uses application `{}`, not `{selected}`",
                    device.application_program_id
                );
            }
        }
        let knx = match application_program {
            Some(id) => archive
                .parse_application_program(id)
                .with_context(|| format!("archive {} has no application program `{id}`", path.display()))?
                .with_context(|| format!("while attempting to parse application program `{id}`"))?,
            None => match archive.application_program_count() {
                1 => archive
                    .parse_sole_application_program()
                    .expect("count says exactly one program exists")
                    .context("while attempting to parse the archive's application program")?,
                0 => bail!("{} contains no application program", path.display()),
                n => {
                    let ids: Vec<&str> = archive.application_program_ids().collect();
                    bail!(
                        "{} contains {n} application programs ({}); select one while importing the device",
                        path.display(),
                        ids.join(", ")
                    )
                }
            },
        };
        (knx, Some(archive))
    } else {
        if catalog_product.is_some() {
            bail!("a loose MTXML cannot select a catalogue product");
        }
        let knx = parse_application_program_from_file(path)
            .with_context(|| format!("while attempting to parse {}", path.display()))?;
        (knx, None)
    };

    let translations = Translations::from_knx(&knx);
    let mut programs = knx.manufacturer_data.manufacturer.application_programs.programs;
    match programs.len() {
        1 => {
            let program = programs.remove(0);
            if !is_archive
                && let Some(expected) = application_program
                && expected != program.id
            {
                bail!("{} contains application `{}`, not `{expected}`", path.display(), program.id);
            }
            Ok((program, translations, archive))
        }
        0 => bail!("{} defines no application program", path.display()),
        n => bail!("{} defines {n} application programs; split the file", path.display()),
    }
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
