//! Dump a product's configurable surface as a mods-file skeleton.
//!
//! ```text
//! knx-dump --product M-0083_A-009B-14-E59D.xml > mods.toml
//! # edit mods.toml, then regenerate the skeleton around your edits
//! # (a changed selection can reveal new parameters):
//! knx-dump --product M-0083_A-009B-14-E59D.xml --mods mods.toml
//! ```

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use knx_config::{dump, load};
use zweidraehte_knxprod::runtime::Device;
use zweidraehte_knxprod::runtime::mods::{DeviceMods, apply_mods};

/// Dump a mods-file skeleton for a KNX product.
#[derive(Parser)]
struct Args {
    /// The product: a loose MTXML application program or a .knxprod
    #[arg(short, long)]
    product: PathBuf,

    /// An existing mods file to apply first; its entries come back
    /// un-commented, and the skeleton reflects the visibility they
    /// produce
    #[arg(short, long)]
    mods: Option<PathBuf>,

    /// Write here instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Emit texts in this language (e.g. de-DE) instead of the
    /// program's default language
    #[arg(short, long)]
    language: Option<String>,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let (mut program, translations, _archive) = load::load_program(&args.product)?;
    if let Some(language) = &args.language {
        let applied = translations.apply(&mut program, language).with_context(|| {
            format!("the product has no language {language:?}; available: {:?}", translations.languages())
        })?;
        eprintln!("Applied {applied} {language} translations");
    }
    let mut device = Device::new(program, None, None);

    let mods = match &args.mods {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("while attempting to read {}", path.display()))?;
            let mods: DeviceMods =
                toml::from_str(&text).with_context(|| format!("while attempting to parse {}", path.display()))?;
            apply_mods(&mut device, &mods).context("while attempting to apply the mods file")?;
            mods
        }
        None => DeviceMods::default(),
    };

    let skeleton = dump::dump_skeleton(&device, &mods);
    match &args.output {
        Some(path) => {
            std::fs::write(path, skeleton).with_context(|| format!("while attempting to write {}", path.display()))?
        }
        None => print!("{skeleton}"),
    }
    Ok(())
}
