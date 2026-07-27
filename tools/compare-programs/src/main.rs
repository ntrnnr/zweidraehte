//! Compare two KNX application programs for equivalence.
//!
//! Usage:
//!   cargo run --bin compare_programs -- --reference <ref.xml> --generated <gen.xml> [OPTIONS]
//!
//! Options:
//!   --strict          Enable strict mode (compare ordering and ID structure)
//!   --compare-ordering Compare element ordering
//!   --compare-ids     Compare ID correspondence structure
//!   --no-text         Skip text comparison
//!   --no-visibility   Skip Dynamic-section visibility comparison
//!   --no-memory       Skip memory layout comparison
//!   --warn-missing    Treat missing entities as warnings instead of errors

use std::env;
use std::path::Path;
use std::process;

mod equivalence;

use crate::equivalence::{CanonicalProgram, ComparisonConfig, EquivalenceChecker};

/// Print what a program contains, before any differences are reported.
///
/// The mask version and application number are shown but never compared: a
/// replication frequently targets a different mask than the device it mirrors
/// (the MDT reference is System 7, ours is System B), so a mismatch there is
/// context for reading the report rather than a defect in its own right.
fn print_program_summary(role: &str, program: &CanonicalProgram) {
    let metadata = &program.metadata;
    println!("{} program: {} ({})", role, metadata.name, metadata.id);
    println!(
        "  Application: {} v{}, mask {}",
        metadata.application_number, metadata.application_version, metadata.mask_version
    );
    println!("  Parameters: {}", program.parameters.len());
    println!("  Communication objects: {}", program.com_objects.len());
    println!("  Parameter refs: {}", program.param_refs.len());
    println!("  ComObject refs: {}", program.com_object_refs.len());
    match program.memory_image_size() {
        Ok(size) => println!("  Parameter memory: {} bytes", size),
        Err(reason) => println!("  Parameter memory: n/a ({})", reason),
    }
    println!();
}

fn print_usage() {
    eprintln!(
        r#"Compare two KNX application programs for equivalence.

Usage:
  cargo run --bin compare_programs -- --reference <ref.xml> --generated <gen.xml> [OPTIONS]

Arguments:
  --reference <file>    Reference XML file (typically manufacturer XML)
  --generated <file>    Generated XML file (typically from DSL)

Options:
  --strict              Enable strict mode (compare ordering and ID structure)
  --compare-ordering    Compare element ordering
  --compare-ids         Compare ID correspondence structure
  --no-text             Skip text comparison
  --no-visibility       Skip Dynamic-section visibility comparison
  --no-memory           Skip memory layout comparison
  --warn-missing        Treat missing entities as warnings instead of errors
  --help, -h            Show this help message

Examples:
  # Basic semantic comparison
  cargo run --bin compare_programs -- \
    --reference manuf_tool_data/MDT.../M-0083_A-009B-14-E59D.xml \
    --generated output/mdt_generated.xml

  # Strict comparison including ordering
  cargo run --bin compare_programs -- \
    --reference ref.xml --generated gen.xml --strict
"#
    );
}

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    let mut reference_path: Option<String> = None;
    let mut generated_path: Option<String> = None;
    let mut config = ComparisonConfig::default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            "--reference" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --reference requires a file path");
                    process::exit(1);
                }
                reference_path = Some(args[i].clone());
            }
            "--generated" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --generated requires a file path");
                    process::exit(1);
                }
                generated_path = Some(args[i].clone());
            }
            // Set the individual switches rather than replacing the config, so
            // that --strict composes with the --no-* flags in any order.
            "--strict" => {
                config.compare_ordering = true;
                config.compare_id_structure = true;
            }
            "--compare-ordering" => {
                config.compare_ordering = true;
            }
            "--compare-ids" => {
                config.compare_id_structure = true;
            }
            "--no-text" => {
                config.compare_text = false;
            }
            "--no-visibility" => {
                config.compare_visibility = false;
            }
            "--no-memory" => {
                config.compare_memory = false;
            }
            "--warn-missing" => {
                config.strict_missing = false;
            }
            arg if arg.starts_with('-') => {
                eprintln!("Error: Unknown option: {}", arg);
                print_usage();
                process::exit(1);
            }
            _ => {
                // Positional argument - treat first as reference, second as generated
                if reference_path.is_none() {
                    reference_path = Some(args[i].clone());
                } else if generated_path.is_none() {
                    generated_path = Some(args[i].clone());
                } else {
                    eprintln!("Error: Too many positional arguments");
                    print_usage();
                    process::exit(1);
                }
            }
        }
        i += 1;
    }

    let reference_path = match reference_path {
        Some(p) => p,
        None => {
            eprintln!("Error: --reference is required");
            print_usage();
            process::exit(1);
        }
    };

    let generated_path = match generated_path {
        Some(p) => p,
        None => {
            eprintln!("Error: --generated is required");
            print_usage();
            process::exit(1);
        }
    };

    // Check files exist
    if !Path::new(&reference_path).exists() {
        eprintln!("Error: Reference file not found: {}", reference_path);
        process::exit(1);
    }
    if !Path::new(&generated_path).exists() {
        eprintln!("Error: Generated file not found: {}", generated_path);
        process::exit(1);
    }

    println!("Comparing application programs:");
    println!("  Reference: {}", reference_path);
    println!("  Generated: {}", generated_path);
    println!();

    // Create checker
    let checker = match EquivalenceChecker::from_xml_files(Path::new(&reference_path), Path::new(&generated_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error loading XML files: {}", e);
            process::exit(1);
        }
    };

    // Print some metadata
    print_program_summary("Reference", &checker.reference);
    print_program_summary("Generated", &checker.generated);

    // Run comparison
    let report = checker.compare(&config);

    // Print report
    println!("{}", report);

    // Exit with appropriate code
    if report.has_differences() {
        process::exit(1);
    } else {
        process::exit(0);
    }
}
