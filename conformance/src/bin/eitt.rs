//! Run KNX conformance test templates directly from their EITT XML.
//!
//! The companion to `conformance-runner`, which runs the hand-written
//! Rust transcriptions of the same tests. Both drive the same DUT
//! through the same [`engine`](zweidraehte_conformance::engine); the
//! difference is only where the steps come from.
//!
//! The templates are licensed material and live outside the repository.
//! A profile names the ones it can run by file name and says what each
//! needs; the directory they live in comes from the environment, so the
//! committed profile stays machine-independent.
//!
//! Usage:
//!   EITT_TEMPLATES=<dir> \
//!   cargo run --bin conformance-eitt -- --profile <file.toml>
//!                                       [--templates-dir <dir>]
//!                                       [--template <name-or-path>]
//!                                       [--patch <file.toml>]
//!                                       [--realtime] [--list] [filter...]
//!
//! Arguments:
//!   --profile        Device profile listing the templates to run.
//!                    Required unless `--template` names one directly.
//!   --templates-dir  Where the templates live; overrides
//!                    `$EITT_TEMPLATES`.
//!   --template       Run one template. Either a substring of a file
//!                    name the profile lists, or a path to an XML the
//!                    profile knows nothing about.
//!   --patch          Extra patch set to overlay, on top of whatever the
//!                    profile names. May be repeated.
//!   --realtime       Spec-compliant timeouts instead of the 50x fast mode.
//!   --list           Lower and print what would run, without touching a
//!                    DUT. The quickest way to see what a new template
//!                    revision changed.
//!   filter           Case-insensitive substring match on suite/case names.
//!
//! Environment:
//!   EITT_TEMPLATES   Directory holding the
//!                    `KnxConformanceTestTemplate-*.xml` files.
//!   RUST_LOG, LIVE_LOGS, KNX_TIME_DIVISOR — as for `conformance-runner`.

use std::env;
use std::process::ExitCode;

use log::LevelFilter;

use zweidraehte_conformance::eitt::profile::{TEMPLATES_DIR_ENV, TemplateRef};
use zweidraehte_conformance::eitt::{self, PatchSet, Profile};
use zweidraehte_conformance::engine::{self, DEFAULT_TIME_DIVISOR, EngineOptions, Summary, matches_filter};
use zweidraehte_conformance::logger;

/// Parsed command line.
struct Args {
    profile: Option<String>,
    templates_dir: Option<String>,
    template: Option<String>,
    patches: Vec<String>,
    realtime: bool,
    list_only: bool,
    filters: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        profile: None,
        templates_dir: None,
        template: None,
        patches: Vec::new(),
        realtime: false,
        list_only: false,
        filters: Vec::new(),
    };

    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--profile" => args.profile = Some(it.next().ok_or("--profile needs a path")?),
            "--templates-dir" => args.templates_dir = Some(it.next().ok_or("--templates-dir needs a path")?),
            "--template" => args.template = Some(it.next().ok_or("--template needs a name or path")?),
            "--patch" => args.patches.push(it.next().ok_or("--patch needs a path")?),
            "--realtime" => args.realtime = true,
            "--list" => args.list_only = true,
            other if other.starts_with("--") => return Err(format!("unknown flag {other}")),
            other => args.filters.push(other.to_string()),
        }
    }

    if args.profile.is_none() && args.template.is_none() {
        return Err("give --profile, or --template to run one template directly".to_string());
    }
    Ok(args)
}

#[embassy_executor::main]
async fn main(_spawner: embassy_executor::Spawner) {
    let code = run().await;
    std::process::exit(match code {
        ExitCode::SUCCESS => 0,
        _ => 1,
    });
}

async fn run() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("❌ {e}");
            eprintln!(
                "usage: conformance-eitt --profile <f.toml> [--templates-dir <dir>] \
                 [--template <name>] [--patch <f.toml>] [--realtime] [--list] [filter...]"
            );
            return ExitCode::FAILURE;
        }
    };

    let time_divisor: u64 = if args.realtime { 1 } else { DEFAULT_TIME_DIVISOR };
    // The DUT child scales its own timers to match.
    // SAFETY: single-threaded, before any child is spawned.
    unsafe { env::set_var("KNX_TIME_DIVISOR", time_divisor.to_string()) };

    let log_level = match env::var("RUST_LOG").ok().as_deref() {
        Some("error") => LevelFilter::Error,
        Some("warn") => LevelFilter::Warn,
        Some("info") => LevelFilter::Info,
        Some("debug") => LevelFilter::Debug,
        Some("trace") => LevelFilter::Trace,
        _ => LevelFilter::Debug,
    };
    let live_logs = env::var("LIVE_LOGS").is_ok();
    logger::init(log_level, live_logs);

    println!("╔═════════════════════════════════════════════════════════════╗");
    println!("║              KNX Conformance Runner — EITT XML               ║");
    println!("╚═════════════════════════════════════════════════════════════╝\n");

    let profile = match &args.profile {
        Some(p) => match Profile::load(p) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("❌ {e}");
                return ExitCode::FAILURE;
            }
        },
        None => {
            println!("No --profile given; using the built-in plain TP1 defaults.");
            match toml::from_str::<Profile>(DEFAULT_PROFILE) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("❌ the built-in default profile is malformed: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
    };

    // Which templates to run. `--template` with a path runs something
    // the profile has never heard of; `--template` with a bare name
    // narrows the profile's own list.
    let direct;
    let selected: Vec<&TemplateRef> = match &args.template {
        Some(t) if t.contains('/') || t.ends_with(".xml") => {
            direct = TemplateRef {
                file: t.clone(),
                collections: Vec::new(),
                patches: Vec::new(),
                not_applicable: Vec::new(),
                commands: Vec::new(),
                variables: Default::default(),
                tl_sequence: None,
            };
            vec![&direct]
        }
        other => {
            let found = profile.templates_matching(other.as_deref());
            if found.is_empty() {
                match other {
                    Some(t) => eprintln!("❌ the profile lists no template matching {t:?}"),
                    None => eprintln!(
                        "❌ the profile lists no templates. Add a [[template]] section, \
                         or name one with --template."
                    ),
                }
                return ExitCode::FAILURE;
            }
            found
        }
    };

    println!("Profile:  medium {}, {:?} DUT", profile.medium, profile.dut);
    if time_divisor > 1 {
        println!("Time scale: {time_divisor}x fast mode (use --realtime for spec timeouts)");
    } else {
        println!("Time scale: realtime (spec-compliant timeouts)");
    }
    println!();

    let mut total = Summary::default();
    let mut any_failed = false;

    for template_ref in selected {
        match run_one(template_ref, &profile, &args, time_divisor).await {
            Ok(Some(summary)) => {
                total.suites += summary.suites;
                total.tests += summary.tests;
                total.passed += summary.passed;
                total.failed += summary.failed;
                total.steps += summary.steps;
                any_failed |= summary.failed > 0;
            }
            // Listed only, nothing ran.
            Ok(None) => {}
            Err(e) => {
                eprintln!("❌ {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    if !args.list_only {
        println!("====================================================================");
        println!("SUMMARY");
        println!("====================================================================");
        println!("  Test Suites:  {}", total.suites);
        println!("  Total Tests:  {}", total.tests);
        println!("  Passed:       {} ✅", total.passed);
        println!("  Failed:       {} ❌", total.failed);
        println!("  Total Steps:  {}", total.steps);
        println!("====================================================================");
    }

    if any_failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

/// Load, lower and (unless listing) run one template.
async fn run_one(
    template_ref: &TemplateRef,
    profile: &Profile,
    args: &Args,
    time_divisor: u64,
) -> Result<Option<Summary>, String> {
    let path = template_ref.resolve(args.templates_dir.as_deref()).map_err(|e| e.to_string())?;
    let xml = std::fs::read_to_string(&path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let template = eitt::schema::parse(&xml).map_err(|e| format!("could not parse {}: {e}", path.display()))?;

    // The profile's per-template not-applicable list folded in, plus any
    // patch sets it names and any given on the command line.
    let scoped = profile.for_template(template_ref);
    let mut patch_set: Option<PatchSet> = None;
    for p in template_ref.patches.iter().chain(args.patches.iter()) {
        let set = PatchSet::load(p).map_err(|e| e.to_string())?;
        match &mut patch_set {
            Some(existing) => existing.patches.extend(set.patches),
            None => patch_set = Some(set),
        }
    }

    println!("====================================================================");
    println!("Template: {}", template.describe());
    println!("File:     {}", path.display());
    if let Some(v) = template.header.as_ref().and_then(|h| h.volume.as_ref()) {
        println!("Realises: {v}");
    }
    if let Some(last) = template.history.as_ref().and_then(|h| h.items.last())
        && let Some(change) = &last.change
    {
        println!("Latest change (v{}): {}", last.version.as_deref().unwrap_or("?"), truncate(change, 110));
    }
    if !template_ref.patches.is_empty() {
        println!("Patches:  {}", template_ref.patches.join(", "));
    }
    println!();

    eitt::lower::register_durations(&template);
    let (mut suites, report) = eitt::lower(&template, &scoped, patch_set.as_ref()).map_err(|e| e.to_string())?;

    println!("Lowered {} suite(s), {} case(s):", suites.len(), suites.iter().map(|s| s.cases.len()).sum::<usize>());
    report.print();
    println!();

    if !args.filters.is_empty() {
        suites.retain(|s| {
            args.filters.iter().any(|f| matches_filter(&s.name, f))
                || s.cases.iter().any(|c| args.filters.iter().any(|f| matches_filter(&c.name, f)))
        });
        if suites.is_empty() {
            println!("No suites or cases matched filters: {:?}\n", args.filters);
            return Ok(None);
        }
    }

    if args.list_only {
        for suite in &suites {
            println!("Suite: {}", suite.name);
            for case in &suite.cases {
                println!("  {} — {} step(s)", case.name, case.steps.len());
            }
        }
        println!();
        return Ok(None);
    }

    let opts =
        EngineOptions { divisor: time_divisor, dut_mode: profile.dut.into(), case_filters: args.filters.clone() };
    Ok(Some(engine::run_suites(&suites, &opts).await))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect::<String>() + "…"
}

/// Used when no `--profile` is given: the plain TP1 conformance DUT with
/// the addresses its tables are built around, and no templates — those
/// have to come from `--template`.
const DEFAULT_PROFILE: &str = r#"
medium = "tp"
dut = "plain"

[addresses]
EDI = "AF FE"
BDUT = "10 01"
"#;

// Silence the unused-import warning when the env-var constant is only
// referenced from the usage text above.
const _: &str = TEMPLATES_DIR_ENV;
