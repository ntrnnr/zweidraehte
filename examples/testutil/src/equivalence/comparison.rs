//! Comparison logic for canonical programs.
//!
//! This module provides the comparison engine that detects differences
//! between two canonical programs.

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use zweidraehte_knxprod::parse_application_program_from_file;

use super::canonical::{CanonicalProgram, ComObjectFlags, ParameterKey, TypeSignature};

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
            compare_ordering: false,
            compare_id_structure: false,
        }
    }
}

impl ComparisonConfig {
    /// Create a strict configuration that also compares ordering and ID structure.
    pub fn strict() -> Self {
        Self { compare_ordering: true, compare_id_structure: true, ..Self::default() }
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
    Missing { key: ParameterKey, in_source: Source, name: String },
    /// Parameter type signatures differ.
    TypeMismatch { key: ParameterKey, name: String, ref_type: TypeSignature, gen_type: TypeSignature },
    /// Default values differ.
    DefaultMismatch { key: ParameterKey, name: String, ref_default: String, gen_default: String },
    /// Display text differs (when compare_text is enabled).
    TextMismatch { key: ParameterKey, name: String, ref_text: String, gen_text: String },
    /// Hidden status differs.
    HiddenMismatch { key: ParameterKey, name: String, ref_hidden: bool, gen_hidden: bool },
}

impl fmt::Display for ParameterDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParameterDiff::Missing { key, in_source, name } => {
                write!(f, "Parameter {} ({}) missing in {}", key, name, in_source)
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
        }
    }
}

/// A difference found in communication objects.
#[derive(Debug, Clone)]
pub enum ComObjectDiff {
    /// Object exists in one program but not the other.
    Missing { number: u16, in_source: Source, name: String },
    /// Object flags differ.
    FlagsMismatch { number: u16, name: String, ref_flags: ComObjectFlags, gen_flags: ComObjectFlags },
    /// Object size differs.
    SizeMismatch { number: u16, name: String, ref_size: String, gen_size: String },
    /// Display text differs.
    TextMismatch { number: u16, name: String, ref_text: String, gen_text: String },
    /// Function text differs.
    FunctionTextMismatch { number: u16, name: String, ref_text: String, gen_text: String },
}

impl fmt::Display for ComObjectDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComObjectDiff::Missing { number, in_source, name } => {
                write!(f, "ComObject {} ({}) missing in {}", number, name, in_source)
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
        }
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
            OrderingDiff::ParameterOrder { first_diff_index, .. } => {
                write!(f, "Parameter order differs at index {}", first_diff_index)
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
    /// Ordering differences (strict mode only).
    pub ordering_diffs: Vec<OrderingDiff>,
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
}

impl ComparisonReport {
    /// Check if there are any differences.
    pub fn has_differences(&self) -> bool {
        !self.parameter_diffs.is_empty() || !self.com_object_diffs.is_empty() || !self.ordering_diffs.is_empty()
    }

    /// Get total number of differences.
    pub fn total_differences(&self) -> usize {
        self.parameter_diffs.len() + self.com_object_diffs.len() + self.ordering_diffs.len()
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

        // Compare ordering (if strict mode)
        if config.compare_ordering {
            self.compare_ordering(&mut report);
        }

        report
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
                        });
                    }
                }
                (None, Some(gp)) => {
                    if config.strict_missing {
                        report.parameter_diffs.push(ParameterDiff::Missing {
                            key,
                            in_source: Source::Reference,
                            name: gp.name.clone(),
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
                        });
                    }
                }
                (None, Some(go)) => {
                    if config.strict_missing {
                        report.com_object_diffs.push(ComObjectDiff::Missing {
                            number: num,
                            in_source: Source::Reference,
                            name: go.name.clone(),
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
        assert!(!config.compare_ordering);
        assert!(!config.compare_id_structure);
    }

    #[test]
    fn test_comparison_config_strict() {
        let config = ComparisonConfig::strict();
        assert!(config.compare_ordering);
        assert!(config.compare_id_structure);
    }
}
