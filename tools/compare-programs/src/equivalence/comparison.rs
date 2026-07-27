//! Comparison logic for canonical programs.
//!
//! This module provides the comparison engine that detects differences
//! between two canonical programs.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::path::Path;

use zweidraehte_knxprod::parse_application_program_from_file;

use super::canonical::{CanonicalProgram, ComObjectFlags, ParameterKey, TypeSignature};
use super::memory::{MemoryComparator, MemoryComparisonReport};
use super::visibility::{RefKey, VisibilityDiff, compare_visibility};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the comparison.
#[derive(Debug, Clone)]
pub struct ComparisonConfig {
    /// Compare display text (normalized).
    pub compare_text: bool,
    /// Treat missing entities as errors.
    pub strict_missing: bool,
    /// Include memory layout comparison.
    pub compare_memory: bool,
    /// Compare the visibility constraints from the Dynamic section.
    pub compare_visibility: bool,
    /// Compare element ordering (parameters, refs, objects).
    pub compare_ordering: bool,
    /// Build and verify ID correspondence between programs.
    pub compare_id_structure: bool,
}

impl Default for ComparisonConfig {
    fn default() -> Self {
        Self {
            compare_text: true,
            strict_missing: true,
            compare_memory: true,
            compare_visibility: true,
            compare_ordering: false,
            compare_id_structure: false,
        }
    }
}

// ============================================================================
// Difference Types
// ============================================================================

/// Source indicator for differences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Reference,
    Generated,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::Reference => write!(f, "reference"),
            Source::Generated => write!(f, "generated"),
        }
    }
}

/// A difference found in parameter definitions.
#[derive(Debug, Clone)]
pub enum ParameterDiff {
    /// Parameter exists in one program but not the other.
    Missing { key: ParameterKey, in_source: Source, name: String, original_id: String },
    /// Parameter type signatures differ.
    TypeMismatch { key: ParameterKey, name: String, ref_type: TypeSignature, gen_type: TypeSignature },
    /// Default values differ.
    DefaultMismatch { key: ParameterKey, name: String, ref_default: String, gen_default: String },
    /// Display text differs (when compare_text is enabled).
    TextMismatch { key: ParameterKey, name: String, ref_text: String, gen_text: String },
    /// Hidden status differs.
    HiddenMismatch { key: ParameterKey, name: String, ref_hidden: bool, gen_hidden: bool },
    /// Suffix text (the unit shown after the input, e.g. "s") differs.
    SuffixMismatch { key: ParameterKey, name: String, ref_suffix: Option<String>, gen_suffix: Option<String> },
}

impl fmt::Display for ParameterDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParameterDiff::Missing { key, in_source, name, original_id } => {
                write!(f, "Parameter {} ({}, '{}') missing in {}", key, name, original_id, in_source)
            }
            ParameterDiff::TypeMismatch { key, name, ref_type, gen_type } => {
                write!(f, "Parameter {} ({}) type mismatch: ref={:?}, gen={:?}", key, name, ref_type, gen_type)
            }
            ParameterDiff::DefaultMismatch { key, name, ref_default, gen_default } => {
                write!(f, "Parameter {} ({}) default mismatch: ref='{}', gen='{}'", key, name, ref_default, gen_default)
            }
            ParameterDiff::TextMismatch { key, name, ref_text, gen_text } => {
                write!(f, "Parameter {} ({}) text mismatch: ref='{}', gen='{}'", key, name, ref_text, gen_text)
            }
            ParameterDiff::HiddenMismatch { key, name, ref_hidden, gen_hidden } => {
                write!(f, "Parameter {} ({}) hidden mismatch: ref={}, gen={}", key, name, ref_hidden, gen_hidden)
            }
            ParameterDiff::SuffixMismatch { key, name, ref_suffix, gen_suffix } => {
                write!(
                    f,
                    "Parameter {} ({}) suffix mismatch: ref={}, gen={}",
                    key,
                    name,
                    describe_override(ref_suffix),
                    describe_override(gen_suffix)
                )
            }
        }
    }
}

/// A difference found in communication objects.
#[derive(Debug, Clone)]
pub enum ComObjectDiff {
    /// Object exists in one program but not the other.
    Missing { number: u16, in_source: Source, name: String, original_id: String },
    /// Object flags differ.
    FlagsMismatch { number: u16, name: String, ref_flags: ComObjectFlags, gen_flags: ComObjectFlags },
    /// Object size differs.
    SizeMismatch { number: u16, name: String, ref_size: String, gen_size: String },
    /// Display text differs.
    TextMismatch { number: u16, name: String, ref_text: String, gen_text: String },
    /// Function text differs.
    FunctionTextMismatch { number: u16, name: String, ref_text: String, gen_text: String },
    /// The object's default datapoint type differs.
    DatapointTypeMismatch { number: u16, name: String, ref_dpt: Option<String>, gen_dpt: Option<String> },
}

impl fmt::Display for ComObjectDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComObjectDiff::Missing { number, in_source, name, original_id } => {
                write!(f, "ComObject {} ({}, '{}') missing in {}", number, name, original_id, in_source)
            }
            ComObjectDiff::FlagsMismatch { number, name, ref_flags, gen_flags } => {
                write!(f, "ComObject {} ({}) flags mismatch: ref={:?}, gen={:?}", number, name, ref_flags, gen_flags)
            }
            ComObjectDiff::SizeMismatch { number, name, ref_size, gen_size } => {
                write!(f, "ComObject {} ({}) size mismatch: ref='{}', gen='{}'", number, name, ref_size, gen_size)
            }
            ComObjectDiff::TextMismatch { number, name, ref_text, gen_text } => {
                write!(f, "ComObject {} ({}) text mismatch: ref='{}', gen='{}'", number, name, ref_text, gen_text)
            }
            ComObjectDiff::FunctionTextMismatch { number, name, ref_text, gen_text } => {
                write!(
                    f,
                    "ComObject {} ({}) function text mismatch: ref='{}', gen='{}'",
                    number, name, ref_text, gen_text
                )
            }
            ComObjectDiff::DatapointTypeMismatch { number, name, ref_dpt, gen_dpt } => {
                write!(
                    f,
                    "ComObject {} ({}) datapoint type mismatch: ref={}, gen={}",
                    number,
                    name,
                    describe_override(ref_dpt),
                    describe_override(gen_dpt)
                )
            }
        }
    }
}

/// A difference in a parameter or communication object *reference*.
///
/// References are where ETS puts per-placement overrides: the same parameter can
/// be shown under two different labels, the same object bound to a different
/// datapoint type. Comparing only the definitions would miss all of that.
#[derive(Debug, Clone)]
pub enum RefDiff {
    /// The reference exists in one program but not the other.
    Missing { ref_key: RefKey, in_source: Source, original_id: String },
    /// The reference overrides an attribute differently.
    AttributeMismatch { ref_key: RefKey, attribute: &'static str, ref_value: String, gen_value: String },
}

impl fmt::Display for RefDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefDiff::Missing { ref_key, in_source, original_id } => {
                write!(f, "Ref {} ('{}') missing in {}", ref_key, original_id, in_source)
            }
            RefDiff::AttributeMismatch { ref_key, attribute, ref_value, gen_value } => {
                write!(f, "Ref {} {} mismatch: ref='{}', gen='{}'", ref_key, attribute, ref_value, gen_value)
            }
        }
    }
}

/// Render an optional override for reporting; `None` means "not overridden".
fn describe_override<T: fmt::Debug>(value: &Option<T>) -> String {
    match value {
        Some(v) => format!("{:?}", v),
        None => "<none>".to_string(),
    }
}

/// A difference in ordering (for strict mode).
#[derive(Debug, Clone)]
pub enum OrderingDiff {
    /// Parameter order differs.
    ParameterOrder { expected: Vec<ParameterKey>, actual: Vec<ParameterKey>, first_diff_index: usize },
    /// Parameter ref order differs.
    ParamRefOrder { expected_count: usize, actual_count: usize },
    /// ComObject ref order differs.
    ComObjectRefOrder { expected_count: usize, actual_count: usize },
}

impl fmt::Display for OrderingDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrderingDiff::ParameterOrder { expected, actual, first_diff_index } => {
                // The full orders are usually hundreds of entries; the pair that
                // first diverges is what actually locates the problem.
                write!(f, "Parameter order differs at index {}", first_diff_index)?;
                match (expected.get(*first_diff_index), actual.get(*first_diff_index)) {
                    (Some(expected), Some(actual)) => write!(f, ": ref={}, gen={}", expected, actual),
                    // One order ran out before the other.
                    _ => write!(f, ": ref has {} entries, gen has {}", expected.len(), actual.len()),
                }
            }
            OrderingDiff::ParamRefOrder { expected_count, actual_count } => {
                write!(f, "Parameter ref count differs: expected {}, got {}", expected_count, actual_count)
            }
            OrderingDiff::ComObjectRefOrder { expected_count, actual_count } => {
                write!(f, "ComObject ref count differs: expected {}, got {}", expected_count, actual_count)
            }
        }
    }
}

// ============================================================================
// Comparison Report
// ============================================================================

/// Complete comparison report.
#[derive(Debug, Clone, Default)]
pub struct ComparisonReport {
    /// Parameter differences.
    pub parameter_diffs: Vec<ParameterDiff>,
    /// Communication object differences.
    pub com_object_diffs: Vec<ComObjectDiff>,
    /// Reference-level differences (per-placement overrides).
    pub ref_diffs: Vec<RefDiff>,
    /// Ordering differences (strict mode only).
    pub ordering_diffs: Vec<OrderingDiff>,
    /// Visibility constraint differences.
    pub visibility_diffs: Vec<VisibilityDiff>,
    /// Memory layout comparison, when enabled.
    pub memory: Option<MemoryComparisonReport>,
    /// Statistics.
    pub stats: ComparisonStats,
}

/// Comparison statistics.
#[derive(Debug, Clone, Default)]
pub struct ComparisonStats {
    pub parameters_compared: usize,
    pub parameters_matched: usize,
    pub com_objects_compared: usize,
    pub com_objects_matched: usize,
    pub param_refs_compared: usize,
    pub com_object_refs_compared: usize,
    pub visibility_refs_compared: usize,
}

impl ComparisonReport {
    /// Check if there are any differences.
    pub fn has_differences(&self) -> bool {
        self.total_differences() > 0
    }

    /// Get total number of differences.
    ///
    /// A skipped memory comparison contributes nothing — see
    /// [`MemoryComparisonReport::skipped`].
    pub fn total_differences(&self) -> usize {
        self.parameter_diffs.len()
            + self.com_object_diffs.len()
            + self.ref_diffs.len()
            + self.ordering_diffs.len()
            + self.visibility_diffs.len()
            + self.memory.as_ref().map(|m| m.diffs.len()).unwrap_or(0)
    }
}

impl fmt::Display for ComparisonReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Equivalence Comparison Report ===")?;
        writeln!(f)?;

        // Parameter comparison
        writeln!(f, "--- Parameter Comparison ---")?;
        writeln!(f, "Compared: {}, Matched: {}", self.stats.parameters_compared, self.stats.parameters_matched)?;
        if self.parameter_diffs.is_empty() {
            writeln!(f, "✓ All parameters matched")?;
        } else {
            writeln!(f, "✗ {} differences:", self.parameter_diffs.len())?;
            for diff in &self.parameter_diffs {
                writeln!(f, "  - {}", diff)?;
            }
        }
        writeln!(f)?;

        // ComObject comparison
        writeln!(f, "--- Communication Object Comparison ---")?;
        writeln!(f, "Compared: {}, Matched: {}", self.stats.com_objects_compared, self.stats.com_objects_matched)?;
        if self.com_object_diffs.is_empty() {
            writeln!(f, "✓ All communication objects matched")?;
        } else {
            writeln!(f, "✗ {} differences:", self.com_object_diffs.len())?;
            for diff in &self.com_object_diffs {
                writeln!(f, "  - {}", diff)?;
            }
        }
        writeln!(f)?;

        // Reference comparison
        writeln!(f, "--- Reference Comparison ---")?;
        writeln!(
            f,
            "Parameter refs: {}, ComObject refs: {}",
            self.stats.param_refs_compared, self.stats.com_object_refs_compared
        )?;
        if self.ref_diffs.is_empty() {
            writeln!(f, "✓ All references matched")?;
        } else {
            writeln!(f, "✗ {} differences:", self.ref_diffs.len())?;
            for diff in &self.ref_diffs {
                writeln!(f, "  - {}", diff)?;
            }
        }
        writeln!(f)?;

        // Visibility comparison
        if self.stats.visibility_refs_compared > 0 {
            writeln!(f, "--- Visibility Comparison ---")?;
            writeln!(
                f,
                "Compared: {}, Matched: {}",
                self.stats.visibility_refs_compared,
                self.stats.visibility_refs_compared - self.visibility_diffs.len()
            )?;
            if self.visibility_diffs.is_empty() {
                writeln!(f, "✓ All visibility constraints matched")?;
            } else {
                writeln!(f, "✗ {} differences:", self.visibility_diffs.len())?;
                for diff in &self.visibility_diffs {
                    writeln!(f, "  - {}", diff)?;
                }
            }
            writeln!(f)?;
        }

        // Memory layout comparison
        if let Some(ref memory) = self.memory {
            write!(f, "{}", memory)?;
            writeln!(f)?;
        }

        // Ordering comparison
        if !self.ordering_diffs.is_empty() {
            writeln!(f, "--- Ordering Comparison ---")?;
            writeln!(f, "✗ {} ordering differences:", self.ordering_diffs.len())?;
            for diff in &self.ordering_diffs {
                writeln!(f, "  - {}", diff)?;
            }
            writeln!(f)?;
        }

        // Summary
        writeln!(f, "--- Summary ---")?;
        if self.has_differences() {
            writeln!(f, "✗ {} total differences found", self.total_differences())?;
        } else {
            writeln!(f, "✓ Programs are equivalent")?;
        }

        Ok(())
    }
}

// ============================================================================
// Equivalence Checker
// ============================================================================

/// Main equivalence checker.
pub struct EquivalenceChecker {
    /// Reference program (typically manufacturer XML).
    pub reference: CanonicalProgram,
    /// Generated program (typically from DSL).
    pub generated: CanonicalProgram,
}

impl EquivalenceChecker {
    /// Create a checker from two canonical programs.
    pub fn new(reference: CanonicalProgram, generated: CanonicalProgram) -> Self {
        Self { reference, generated }
    }

    /// Create a checker from two XML files.
    pub fn from_xml_files(reference_path: &Path, generated_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let ref_knx = parse_application_program_from_file(reference_path)?;
        let gen_knx = parse_application_program_from_file(generated_path)?;

        let ref_program = ref_knx
            .manufacturer_data
            .manufacturer
            .application_programs
            .programs
            .first()
            .ok_or("Reference XML has no application program")?;
        let gen_program = gen_knx
            .manufacturer_data
            .manufacturer
            .application_programs
            .programs
            .first()
            .ok_or("Generated XML has no application program")?;

        Ok(Self::new(CanonicalProgram::from_parsed(ref_program), CanonicalProgram::from_parsed(gen_program)))
    }

    /// Run comparison with the given configuration.
    pub fn compare(&self, config: &ComparisonConfig) -> ComparisonReport {
        let mut report = ComparisonReport::default();

        // Compare parameters
        self.compare_parameters(config, &mut report);

        // Compare communication objects
        self.compare_com_objects(config, &mut report);

        // Compare the per-placement overrides carried by references
        self.compare_refs(config, &mut report);

        // Compare the show/hide behaviour encoded in the Dynamic section
        if config.compare_visibility {
            self.compare_visibility(&mut report);
        }

        // Compare the byte image both programs produce
        if config.compare_memory {
            report.memory = Some(self.compare_memory());
        }

        // Compare ordering (if strict mode)
        if config.compare_ordering {
            self.compare_ordering(&mut report);
        }

        report
    }

    /// Compare parameter and communication object references.
    ///
    /// Refs are paired by the same semantic key the visibility comparison uses,
    /// so the two sections agree on what "the same reference" means.
    fn compare_refs(&self, config: &ComparisonConfig, report: &mut ComparisonReport) {
        let ref_params: BTreeMap<_, _> = self.reference.param_refs.iter().map(|r| (r.ref_key(), r)).collect();
        let gen_params: BTreeMap<_, _> = self.generated.param_refs.iter().map(|r| (r.ref_key(), r)).collect();

        let all_param_refs: BTreeSet<_> = ref_params.keys().chain(gen_params.keys()).copied().collect();
        report.stats.param_refs_compared = all_param_refs.len();

        for ref_key in all_param_refs {
            match (ref_params.get(&ref_key), gen_params.get(&ref_key)) {
                (Some(reference), Some(generated)) => {
                    let mut mismatch = |attribute, ref_value: String, gen_value: String| {
                        if ref_value != gen_value {
                            report.ref_diffs.push(RefDiff::AttributeMismatch {
                                ref_key,
                                attribute,
                                ref_value,
                                gen_value,
                            });
                        }
                    };

                    if config.compare_text {
                        mismatch(
                            "text override",
                            describe_override(&reference.text_override),
                            describe_override(&generated.text_override),
                        );
                    }
                    mismatch(
                        "value override",
                        describe_override(&reference.value_override),
                        describe_override(&generated.value_override),
                    );
                    mismatch("hidden", reference.hidden.to_string(), generated.hidden.to_string());
                }
                (Some(reference), None) => {
                    if config.strict_missing {
                        report.ref_diffs.push(RefDiff::Missing {
                            ref_key,
                            in_source: Source::Generated,
                            original_id: reference.original_id.clone(),
                        });
                    }
                }
                (None, Some(generated)) => {
                    if config.strict_missing {
                        report.ref_diffs.push(RefDiff::Missing {
                            ref_key,
                            in_source: Source::Reference,
                            original_id: generated.original_id.clone(),
                        });
                    }
                }
                (None, None) => unreachable!("key came from one of the two maps"),
            }
        }

        let ref_objects: BTreeMap<_, _> = self.reference.com_object_refs.iter().map(|r| (r.ref_key(), r)).collect();
        let gen_objects: BTreeMap<_, _> = self.generated.com_object_refs.iter().map(|r| (r.ref_key(), r)).collect();

        let all_object_refs: BTreeSet<_> = ref_objects.keys().chain(gen_objects.keys()).copied().collect();
        report.stats.com_object_refs_compared = all_object_refs.len();

        for ref_key in all_object_refs {
            match (ref_objects.get(&ref_key), gen_objects.get(&ref_key)) {
                (Some(reference), Some(generated)) => {
                    let mut mismatch = |attribute, ref_value: String, gen_value: String| {
                        if ref_value != gen_value {
                            report.ref_diffs.push(RefDiff::AttributeMismatch {
                                ref_key,
                                attribute,
                                ref_value,
                                gen_value,
                            });
                        }
                    };

                    if config.compare_text {
                        mismatch(
                            "text override",
                            describe_override(&reference.text_override),
                            describe_override(&generated.text_override),
                        );
                        mismatch(
                            "function text override",
                            describe_override(&reference.function_text_override),
                            describe_override(&generated.function_text_override),
                        );
                    }
                    mismatch(
                        "datapoint type",
                        describe_override(&reference.datapoint_type),
                        describe_override(&generated.datapoint_type),
                    );
                    mismatch(
                        "flag overrides",
                        describe_override(&reference.flag_overrides),
                        describe_override(&generated.flag_overrides),
                    );
                }
                (Some(reference), None) => {
                    if config.strict_missing {
                        report.ref_diffs.push(RefDiff::Missing {
                            ref_key,
                            in_source: Source::Generated,
                            original_id: reference.original_id.clone(),
                        });
                    }
                }
                (None, Some(generated)) => {
                    if config.strict_missing {
                        report.ref_diffs.push(RefDiff::Missing {
                            ref_key,
                            in_source: Source::Reference,
                            original_id: generated.original_id.clone(),
                        });
                    }
                }
                (None, None) => unreachable!("key came from one of the two maps"),
            }
        }
    }

    /// Compare the visibility constraints of both programs.
    ///
    /// This is what distinguishes a replication that merely declares the right
    /// parameters from one that also shows and hides them at the right times.
    fn compare_visibility(&self, report: &mut ComparisonReport) {
        report.stats.visibility_refs_compared = self
            .reference
            .visibility
            .visibility
            .keys()
            .chain(self.generated.visibility.visibility.keys())
            .collect::<HashSet<_>>()
            .len();

        report.visibility_diffs = compare_visibility(&self.reference.visibility, &self.generated.visibility);
    }

    /// Compare the memory image both programs produce.
    ///
    /// Unlike the parameter comparison this asks a byte-level question: given
    /// the same configuration, do both programs write the same memory? Two
    /// programs can carve a byte into different parameters — a vendor's single
    /// 8-bit enum against our two 4-bit fields — and still be interchangeable to
    /// the device, which parameter-by-parameter matching would call a
    /// difference.
    fn compare_memory(&self) -> MemoryComparisonReport {
        // Both programs must agree on a segment size for the images to be
        // comparable at all; the larger of the two covers either program
        // writing past the other's end.
        let memory_size = match (self.reference.memory_image_size(), self.generated.memory_image_size()) {
            (Ok(ref_size), Ok(gen_size)) => ref_size.max(gen_size) as usize,
            (Err(reason), _) => return MemoryComparisonReport::skipped(format!("reference: {}", reason)),
            (_, Err(reason)) => return MemoryComparisonReport::skipped(format!("generated: {}", reason)),
        };

        let comparator = MemoryComparator::new(&self.reference, &self.generated);
        let configs = comparator.generate_default_configs();
        comparator.compare_report(&configs, memory_size)
    }

    /// Compare parameters between the two programs.
    fn compare_parameters(&self, config: &ComparisonConfig, report: &mut ComparisonReport) {
        // Collect all parameter keys from both programs
        let ref_keys: HashSet<_> = self.reference.parameters.keys().cloned().collect();
        let gen_keys: HashSet<_> = self.generated.parameters.keys().cloned().collect();

        let all_keys: HashSet<_> = ref_keys.union(&gen_keys).cloned().collect();
        report.stats.parameters_compared = all_keys.len();

        for key in all_keys {
            let ref_param = self.reference.parameters.get(&key);
            let gen_param = self.generated.parameters.get(&key);

            match (ref_param, gen_param) {
                (Some(rp), Some(gp)) => {
                    let mut matched = true;

                    // Compare type signatures
                    if rp.type_signature != gp.type_signature {
                        report.parameter_diffs.push(ParameterDiff::TypeMismatch {
                            key,
                            name: rp.name.clone(),
                            ref_type: rp.type_signature.clone(),
                            gen_type: gp.type_signature.clone(),
                        });
                        matched = false;
                    }

                    // Compare default values
                    if rp.default_value != gp.default_value {
                        report.parameter_diffs.push(ParameterDiff::DefaultMismatch {
                            key,
                            name: rp.name.clone(),
                            ref_default: rp.default_value.clone(),
                            gen_default: gp.default_value.clone(),
                        });
                        matched = false;
                    }

                    // Compare hidden status
                    if rp.hidden != gp.hidden {
                        report.parameter_diffs.push(ParameterDiff::HiddenMismatch {
                            key,
                            name: rp.name.clone(),
                            ref_hidden: rp.hidden,
                            gen_hidden: gp.hidden,
                        });
                        matched = false;
                    }

                    // Compare text (if enabled)
                    if config.compare_text && rp.text != gp.text {
                        report.parameter_diffs.push(ParameterDiff::TextMismatch {
                            key,
                            name: rp.name.clone(),
                            ref_text: rp.text.clone(),
                            gen_text: gp.text.clone(),
                        });
                        matched = false;
                    }

                    // The suffix is user-visible text, so it follows compare_text
                    if config.compare_text && rp.suffix_text != gp.suffix_text {
                        report.parameter_diffs.push(ParameterDiff::SuffixMismatch {
                            key,
                            name: rp.name.clone(),
                            ref_suffix: rp.suffix_text.clone(),
                            gen_suffix: gp.suffix_text.clone(),
                        });
                        matched = false;
                    }

                    if matched {
                        report.stats.parameters_matched += 1;
                    }
                }
                (Some(rp), None) => {
                    if config.strict_missing {
                        report.parameter_diffs.push(ParameterDiff::Missing {
                            key,
                            in_source: Source::Generated,
                            name: rp.name.clone(),
                            original_id: rp.original_id.clone(),
                        });
                    }
                }
                (None, Some(gp)) => {
                    if config.strict_missing {
                        report.parameter_diffs.push(ParameterDiff::Missing {
                            key,
                            in_source: Source::Reference,
                            name: gp.name.clone(),
                            original_id: gp.original_id.clone(),
                        });
                    }
                }
                (None, None) => unreachable!(),
            }
        }
    }

    /// Compare communication objects between the two programs.
    fn compare_com_objects(&self, config: &ComparisonConfig, report: &mut ComparisonReport) {
        // Collect all object numbers from both programs
        let ref_nums: HashSet<_> = self.reference.com_objects.keys().cloned().collect();
        let gen_nums: HashSet<_> = self.generated.com_objects.keys().cloned().collect();

        let all_nums: HashSet<_> = ref_nums.union(&gen_nums).cloned().collect();
        report.stats.com_objects_compared = all_nums.len();

        for num in all_nums {
            let ref_obj = self.reference.com_objects.get(&num);
            let gen_obj = self.generated.com_objects.get(&num);

            match (ref_obj, gen_obj) {
                (Some(ro), Some(go)) => {
                    let mut matched = true;

                    // Compare flags
                    if ro.flags != go.flags {
                        report.com_object_diffs.push(ComObjectDiff::FlagsMismatch {
                            number: num,
                            name: ro.name.clone(),
                            ref_flags: ro.flags,
                            gen_flags: go.flags,
                        });
                        matched = false;
                    }

                    // Compare object size
                    if ro.object_size != go.object_size {
                        report.com_object_diffs.push(ComObjectDiff::SizeMismatch {
                            number: num,
                            name: ro.name.clone(),
                            ref_size: ro.object_size.clone(),
                            gen_size: go.object_size.clone(),
                        });
                        matched = false;
                    }

                    // Compare text (if enabled)
                    if config.compare_text && ro.text != go.text {
                        report.com_object_diffs.push(ComObjectDiff::TextMismatch {
                            number: num,
                            name: ro.name.clone(),
                            ref_text: ro.text.clone(),
                            gen_text: go.text.clone(),
                        });
                        matched = false;
                    }

                    // Compare function text (if enabled)
                    if config.compare_text && ro.function_text != go.function_text {
                        report.com_object_diffs.push(ComObjectDiff::FunctionTextMismatch {
                            number: num,
                            name: ro.name.clone(),
                            ref_text: ro.function_text.clone(),
                            gen_text: go.function_text.clone(),
                        });
                        matched = false;
                    }

                    // The object's own datapoint type; refs may still override it
                    if ro.datapoint_type != go.datapoint_type {
                        report.com_object_diffs.push(ComObjectDiff::DatapointTypeMismatch {
                            number: num,
                            name: ro.name.clone(),
                            ref_dpt: ro.datapoint_type.clone(),
                            gen_dpt: go.datapoint_type.clone(),
                        });
                        matched = false;
                    }

                    if matched {
                        report.stats.com_objects_matched += 1;
                    }
                }
                (Some(ro), None) => {
                    if config.strict_missing {
                        report.com_object_diffs.push(ComObjectDiff::Missing {
                            number: num,
                            in_source: Source::Generated,
                            name: ro.name.clone(),
                            original_id: ro.original_id.clone(),
                        });
                    }
                }
                (None, Some(go)) => {
                    if config.strict_missing {
                        report.com_object_diffs.push(ComObjectDiff::Missing {
                            number: num,
                            in_source: Source::Reference,
                            name: go.name.clone(),
                            original_id: go.original_id.clone(),
                        });
                    }
                }
                (None, None) => unreachable!(),
            }
        }
    }

    /// Compare ordering between the two programs.
    fn compare_ordering(&self, report: &mut ComparisonReport) {
        // Compare parameter order
        if self.reference.parameter_order != self.generated.parameter_order {
            let first_diff = self
                .reference
                .parameter_order
                .iter()
                .zip(self.generated.parameter_order.iter())
                .position(|(a, b)| a != b)
                .unwrap_or(self.reference.parameter_order.len().min(self.generated.parameter_order.len()));

            report.ordering_diffs.push(OrderingDiff::ParameterOrder {
                expected: self.reference.parameter_order.clone(),
                actual: self.generated.parameter_order.clone(),
                first_diff_index: first_diff,
            });
        }

        // Compare param ref counts
        if self.reference.param_refs.len() != self.generated.param_refs.len() {
            report.ordering_diffs.push(OrderingDiff::ParamRefOrder {
                expected_count: self.reference.param_refs.len(),
                actual_count: self.generated.param_refs.len(),
            });
        }

        // Compare com object ref counts
        if self.reference.com_object_refs.len() != self.generated.com_object_refs.len() {
            report.ordering_diffs.push(OrderingDiff::ComObjectRefOrder {
                expected_count: self.reference.com_object_refs.len(),
                actual_count: self.generated.com_object_refs.len(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comparison_config_default() {
        let config = ComparisonConfig::default();
        assert!(config.compare_text);
        assert!(config.strict_missing);
        assert!(config.compare_memory);
        assert!(config.compare_visibility);
        assert!(!config.compare_ordering);
        assert!(!config.compare_id_structure);
    }

    /// A skipped memory comparison reports nothing, so it must not push the run
    /// into a failing exit code.
    #[test]
    fn test_skipped_memory_comparison_is_not_a_difference() {
        let report = ComparisonReport {
            memory: Some(MemoryComparisonReport::skipped("parameters span 3 code segments")),
            ..ComparisonReport::default()
        };

        assert!(!report.has_differences());
        assert_eq!(report.total_differences(), 0);
    }
}
