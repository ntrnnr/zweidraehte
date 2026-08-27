//! Repository automation that must keep several Cargo artifacts in sync.
//!
//! Conformance runners spawn separate DUT executables. Running one through
//! `cargo run` only guarantees that the runner itself is current, so this task
//! first builds every conformance binary in one Cargo invocation and then
//! launches the requested runner from that build.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use clap::{Args, Parser, Subcommand};
use serde_json::Value;

const CONFORMANCE_PACKAGE: &str = "zweidraehte-conformance";
const EITT_PROFILES_DIR: &str = "conformance/profiles";

#[derive(Debug, Parser)]
#[command(about = "Repository maintenance tasks")]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Debug, Subcommand)]
enum Task {
    /// Build current DUTs and run one conformance test frontend.
    Conformance(ConformanceArgs),
}

#[derive(Debug, Args)]
struct ConformanceArgs {
    /// Build and run the release-profile binaries.
    #[arg(long)]
    release: bool,

    #[command(subcommand)]
    command: ConformanceCommand,
}

#[derive(Debug, Subcommand)]
enum ConformanceCommand {
    /// Run the hand-written Rust conformance suites.
    Handwritten(PassthroughArgs),

    /// Run the client-driven configuration download scenarios.
    Configuration(PassthroughArgs),

    /// Run vendor EITT XML through a committed device profile.
    Eitt(EittArgs),

    /// List the available EITT device profile names.
    Profiles,
}

#[derive(Debug, Args)]
struct PassthroughArgs {
    /// Arguments forwarded verbatim to the selected runner.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    arguments: Vec<OsString>,
}

#[derive(Debug, Args)]
struct EittArgs {
    /// Profile path or shorthand such as `full/tp1-systemb`.
    #[arg(long, value_name = "PROFILE")]
    profile: PathBuf,

    /// Remaining EITT options and filters, forwarded verbatim.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    arguments: Vec<OsString>,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let root = workspace_root();

    match cli.task {
        Task::Conformance(args) => run_conformance(&root, args),
    }
}

fn run_conformance(root: &Path, args: ConformanceArgs) -> Result<(), String> {
    let (runner, runner_args) = match args.command {
        ConformanceCommand::Handwritten(args) => ("conformance-runner", args.arguments),
        ConformanceCommand::Configuration(args) => ("conformance-configuration", args.arguments),
        ConformanceCommand::Eitt(args) => {
            let profile = resolve_eitt_profile(root, &args.profile)?;
            let mut runner_args = vec![OsString::from("--profile"), profile.into_os_string()];

            runner_args.extend(args.arguments);

            ("conformance-eitt", runner_args)
        }
        ConformanceCommand::Profiles => {
            for profile in eitt_profile_names(root)? {
                println!("{profile}");
            }

            return Ok(());
        }
    };

    let executable = build_conformance_binaries(root, runner, args.release)?;

    launch_runner(root, &executable, &runner_args)
}

// ============================================================================
// Cargo build and runner launch
// ============================================================================

fn build_conformance_binaries(root: &Path, runner: &str, release: bool) -> Result<PathBuf, String> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);

    command.current_dir(root);
    command.args(["build", "--package", CONFORMANCE_PACKAGE, "--bins"]);

    if release {
        command.arg("--release");
    }

    command.arg("--message-format=json-render-diagnostics");
    command.stdout(Stdio::piped());

    let cargo_profile = if release { "release" } else { "dev" };
    eprintln!("Building all conformance binaries with the {cargo_profile} profile...");

    let mut child = command.spawn().map_err(|error| format!("failed to start Cargo: {error}"))?;
    let stdout = child.stdout.take().ok_or_else(|| "Cargo stdout was not captured".to_owned())?;
    let mut reader = BufReader::new(stdout);
    let mut executable = None;
    let mut malformed_message = None;
    let mut line = String::new();

    loop {
        line.clear();

        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line.trim().is_empty() => continue,
            Ok(_) => match serde_json::from_str::<Value>(&line) {
                Ok(message) => inspect_cargo_message(&message, runner, &mut executable),
                Err(error) => {
                    malformed_message.get_or_insert_with(|| format!("invalid Cargo build message: {error}"));
                }
            },
            Err(error) => {
                malformed_message = Some(format!("failed to read Cargo build output: {error}"));
                break;
            }
        }
    }

    let status = child.wait().map_err(|error| format!("failed to wait for Cargo: {error}"))?;

    if !status.success() {
        return Err(format!("Cargo failed to build the conformance binaries ({status})"));
    }

    if let Some(error) = malformed_message {
        return Err(error);
    }

    let executable = executable.ok_or_else(|| format!("Cargo did not report an executable for `{runner}`"))?;

    eprintln!("Running {runner}...\n");

    Ok(executable)
}

fn inspect_cargo_message(message: &Value, runner: &str, executable: &mut Option<PathBuf>) {
    match message.get("reason").and_then(Value::as_str) {
        Some("compiler-message") => {
            if let Some(rendered) = message.pointer("/message/rendered").and_then(Value::as_str) {
                eprint!("{rendered}");
                let _ = std::io::stderr().flush();
            }
        }
        Some("compiler-artifact") if message.pointer("/target/name").and_then(Value::as_str) == Some(runner) => {
            if let Some(path) = message.get("executable").and_then(Value::as_str) {
                *executable = Some(PathBuf::from(path));
            }
        }
        _ => {}
    }
}

#[cfg(unix)]
fn launch_runner(root: &Path, executable: &Path, arguments: &[OsString]) -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    let error = Command::new(executable).current_dir(root).args(arguments).exec();

    Err(format!("failed to launch {}: {error}", executable.display()))
}

#[cfg(not(unix))]
fn launch_runner(root: &Path, executable: &Path, arguments: &[OsString]) -> Result<(), String> {
    let status = Command::new(executable)
        .current_dir(root)
        .args(arguments)
        .status()
        .map_err(|error| format!("failed to launch {}: {error}", executable.display()))?;

    std::process::exit(status.code().unwrap_or(1));
}

// ============================================================================
// EITT profile discovery
// ============================================================================

fn resolve_eitt_profile(root: &Path, requested: &Path) -> Result<PathBuf, String> {
    let current_dir = env::current_dir().map_err(|error| format!("failed to read the current directory: {error}"))?;
    let profiles_dir = root.join(EITT_PROFILES_DIR);
    let mut shorthand = profiles_dir.join(requested);

    if shorthand.extension().is_none() {
        shorthand.set_extension("toml");
    }

    let candidates = if requested.is_absolute() {
        vec![requested.to_owned()]
    } else {
        vec![current_dir.join(requested), root.join(requested), shorthand]
    };

    for candidate in candidates {
        if candidate.is_file() {
            return candidate
                .canonicalize()
                .map_err(|error| format!("failed to resolve profile {}: {error}", candidate.display()));
        }
    }

    Err(format!(
        "unknown EITT profile `{}`; run `cargo xtask conformance profiles` to list the committed profiles",
        requested.display(),
    ))
}

fn eitt_profile_names(root: &Path) -> Result<Vec<String>, String> {
    let profiles_dir = root.join(EITT_PROFILES_DIR);
    let mut files = Vec::new();

    collect_toml_files(&profiles_dir, &mut files)?;

    let mut names = files
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&profiles_dir)
                .expect("collected profile stays below profile directory")
                .with_extension("");

            relative.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/")
        })
        .collect::<Vec<_>>();

    names.sort();

    Ok(names)
}

fn collect_toml_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("failed to read profile directory {}: {error}", directory.display()))?;

    for entry in entries {
        let entry = entry.map_err(|error| format!("failed to read an entry in {}: {error}", directory.display()))?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;

        if file_type.is_dir() {
            collect_toml_files(&path, files)?;
        } else if file_type.is_file() && path.extension() == Some(OsStr::new("toml")) {
            files.push(path);
        }
    }

    Ok(())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("xtask lives in tools/xtask")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_shorthand_resolves_below_the_profile_directory() {
        let root = workspace_root();
        let requested = Path::new("full/tp1-systemb");
        let profile = resolve_eitt_profile(&root, requested).expect("committed System B profile resolves");

        assert_eq!(profile, root.join("conformance/profiles/full/tp1-systemb.toml"));
    }

    #[test]
    fn eitt_options_after_the_profile_are_forwarded() {
        let cli = Cli::try_parse_from([
            "xtask",
            "conformance",
            "--release",
            "eitt",
            "--profile",
            "full/tp1-systemb",
            "--template",
            "GroupObjects",
            "1.4.1.1",
        ])
        .expect("valid EITT command parses");

        let Task::Conformance(conformance) = cli.task;
        assert!(conformance.release);

        let ConformanceCommand::Eitt(eitt) = conformance.command else {
            panic!("EITT subcommand stays selected");
        };

        assert_eq!(eitt.profile, Path::new("full/tp1-systemb"));
        assert_eq!(eitt.arguments, ["--template", "GroupObjects", "1.4.1.1"].map(OsString::from));
    }

    #[test]
    fn profile_listing_is_sorted_and_extensionless() {
        let profiles = eitt_profile_names(&workspace_root()).expect("committed profiles are readable");

        assert!(profiles.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(profiles.contains(&"full/tp1-systemb".to_owned()));
        assert!(profiles.contains(&"micro/tp1-bcu2-secure".to_owned()));
        assert!(profiles.iter().all(|profile| !profile.ends_with(".toml")));
    }
}
