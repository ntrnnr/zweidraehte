//! Generate a commented one-device `project.knx` skeleton.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use knx_config::{dump, load};
use zweidraehte_ets_files::runtime::Device;

#[derive(Parser)]
struct Args {
    /// A loose MTXML application program or `.knxprod` archive.
    product: PathBuf,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(short, long)]
    language: Option<String>,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let (mut program, translations, _) = load::load_program(&args.product)?;
    if let Some(language) = &args.language {
        translations
            .apply(&mut program, language)
            .with_context(|| format!("while attempting to apply product language {language:?}"))?;
    }
    let device = Device::new(program, None);
    let skeleton = dump::dump_project_skeleton(&device, &args.product);
    match &args.output {
        Some(path) => {
            std::fs::write(path, skeleton).with_context(|| format!("while attempting to write {}", path.display()))?
        }
        None => print!("{skeleton}"),
    }
    Ok(())
}
