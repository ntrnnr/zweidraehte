//! Shared glue for the MTXML/`.knxprod` generator binaries.
//!
//! Each binary in `src/bin/` pairs one device definition with
//! [`KnxprodBuilder`]. The
//! parts that do not vary between devices — turning the parameter struct
//! into its on-wire default blob, and the `--knxprod` output handling —
//! live here so they are written once.

use std::io::Write;
use std::path::Path;

use zerocopy::{Immutable, IntoBytes};
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

/// Product outputs supported by every device generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductOutput {
    Mtxml,
    Knxprod,
}

impl ProductOutput {
    /// Read the shared flag while leaving device-specific arguments to callers.
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Self {
        if args.into_iter().any(|arg| arg == "--knxprod") { Self::Knxprod } else { Self::Mtxml }
    }
}

/// Write product artifacts and report their paths to the caller's output stream.
///
/// The caller configures the builder's Master Data and converter key explicitly
/// for signed output. Device summaries and project generation remain with the
/// binaries; this function neither reads process arguments nor selects a key.
pub fn run_generator(
    builder: KnxprodBuilder<'_>,
    out_dir: &Path,
    format: ProductOutput,
    mut report: impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let builder = builder.output_dir(out_dir);
    if format == ProductOutput::Knxprod {
        let (output, knxprod_path) = builder.build_all()?;
        let manuf_dir = out_dir.join(format!("M-{}", output.manufacturer_id));
        writeln!(report, "Output directory: {}", manuf_dir.display())?;
        for (filename, _) in output.xml_files() {
            writeln!(report, "Generated: {}", manuf_dir.join(filename).display())?;
        }
        if !output.baggage_files.is_empty() {
            writeln!(report, "Generated: Baggages/ directory with {} files", output.baggage_files.len())?;
        }
        writeln!(
            report,
            "\nGenerated: {} ({} bytes)",
            knxprod_path.display(),
            std::fs::metadata(&knxprod_path)?.len()
        )?;
    } else {
        let (output, paths) = builder.write_mtxml_with_paths()?;
        writeln!(report, "Output directory: {}", out_dir.join(format!("M-{}", output.manufacturer_id)).display())?;
        for path in &paths {
            writeln!(report, "Generated: {}", path.display())?;
        }
    }

    Ok(())
}
