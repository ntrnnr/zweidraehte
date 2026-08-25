//! Shared glue for the MTXML/`.knxprod` generator binaries.
//!
//! Each binary in `src/bin/` pairs one device definition with
//! [`KnxprodBuilder`]. The
//! parts that do not vary between devices — turning the parameter struct
//! into its on-wire default blob, and the `--knxprod` output handling —
//! live here so they are written once.

use std::env;
use std::path::Path;

use zerocopy::{Immutable, IntoBytes};
use zweidraehte_ets_files::signing::MasterDataSource;
use zweidraehte_knxprod::KnxprodBuilder;

/// View a parameter struct as the raw default-value blob ETS stores.
///
/// Every generator previously hand-rolled this as
///
/// ```rust,ignore
/// let param_bytes = unsafe {
///     core::slice::from_raw_parts(
///         &defaults as *const MyParams as *const u8,
///         core::mem::size_of::<MyParams>(),
///     )
/// };
/// ```
///
/// which is **unsound for any struct with padding**: the padding bytes are
/// uninitialized, so reading them is UB and yields whatever happened to be
/// on the stack. That is not a theoretical concern here — the bytes land at
/// real parameter offsets in the `<Data>` blob that ETS reads back
/// byte-for-byte, so a struct with padding produces a product database whose
/// defaults change from build to build.
///
/// The [`IntoBytes`] bound makes that impossible to express: zerocopy's
/// derive rejects any struct that has padding, so a params type either has a
/// deterministic byte image or it does not compile. Add explicit filler
/// fields where the compiler reports padding rather than reaching for
/// `unsafe` again.
pub fn params_as_bytes<T: IntoBytes + Immutable>(params: &T) -> &[u8] {
    params.as_bytes()
}

/// Run a configured [`KnxprodBuilder`] and report what it wrote.
///
/// Honours the `--knxprod` flag (build a signed package in addition to the
/// loose MTXML files). Collapses the block that was duplicated verbatim
/// across the generator binaries — including one copy that used `eprintln!`
/// where the others used `println!`, quietly breaking stdout capture.
pub fn run_generator(builder: KnxprodBuilder<'_>, out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let generate_knxprod = env::args().any(|arg| arg == "--knxprod");

    if generate_knxprod {
        let (output, knxprod_path) =
            builder.master_data(MasterDataSource::Download).converter_key_file("converter_key.xml").build_all()?;
        let manuf_dir = out_dir.join(format!("M-{}", output.manufacturer_id));
        println!("Output directory: {}", manuf_dir.display());
        for (filename, _) in output.xml_files() {
            println!("Generated: {}", manuf_dir.join(filename).display());
        }
        let size = std::fs::metadata(&knxprod_path).map(|m| m.len()).unwrap_or(0);
        println!("\nGenerated: {} ({} bytes)", knxprod_path.display(), size);
    } else {
        let (_output, paths) = builder.write_mtxml_with_paths()?;
        for path in &paths {
            println!("Generated: {}", path.display());
        }
    }

    Ok(())
}
