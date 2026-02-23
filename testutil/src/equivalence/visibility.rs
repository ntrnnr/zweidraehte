//! Visibility constraint extraction and comparison.
//!
//! This module extracts visibility constraints from the Dynamic section
//! of an ApplicationProgram and provides tools to compare constraints
//! for semantic equivalence.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;

use knxprod::schema::{
    ApplicationProgram, Channel, ChannelIndependentBlock, ChannelIndependentItem, ChannelItem, Choose, ParameterBlock,
    ParameterBlockItem, WhenItem,
};

// ============================================================================
// Visibility Constraint
// ============================================================================

/// A visibility constraint representing when an element is visible.
///
/// Constraints form a tree structure representing boolean conditions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VisibilityConstraint {
    /// Always visible (no conditions).
    Always,
    /// Never visible (contradiction).
    Never,
    /// Visible when selector equals one of the specified values.
    Equals {
        /// The selector parameter (by its ref ID or key).
        selector: String,
        /// The set of values that make this visible.
        values: BTreeSet<i64>,
    },
    /// Visible when selector does NOT equal the specified value.
    NotEquals { selector: String, value: i64 },
    /// Visible when selector is greater than value.
    GreaterThan { selector: String, value: i64 },
    /// Visible when selector is less than value.
    LessThan { selector: String, value: i64 },
    /// Conjunction of constraints (all must be true).
    And(Vec<VisibilityConstraint>),
    /// Disjunction of constraints (at least one must be true).
    Or(Vec<VisibilityConstraint>),
}

impl VisibilityConstraint {
    /// Create an Equals constraint.
    pub fn equals(selector: impl Into<String>, values: impl IntoIterator<Item = i64>) -> Self {
        VisibilityConstraint::Equals { selector: selector.into(), values: values.into_iter().collect() }
    }

    /// Create an And constraint.
    pub fn and(constraints: Vec<VisibilityConstraint>) -> Self {
        // Flatten nested Ands and simplify
        let mut flat: Vec<VisibilityConstraint> = Vec::new();
        for c in constraints {
            match c {
                VisibilityConstraint::Always => continue,
                VisibilityConstraint::Never => return VisibilityConstraint::Never,
                VisibilityConstraint::And(inner) => flat.extend(inner),
                other => flat.push(other),
            }
        }
        match flat.len() {
            0 => VisibilityConstraint::Always,
            1 => flat.remove(0),
            _ => VisibilityConstraint::And(flat),
        }
    }

    /// Create an Or constraint.
    pub fn or(constraints: Vec<VisibilityConstraint>) -> Self {
        // Flatten nested Ors and simplify
        let mut flat: Vec<VisibilityConstraint> = Vec::new();
        for c in constraints {
            match c {
                VisibilityConstraint::Never => continue,
                VisibilityConstraint::Always => return VisibilityConstraint::Always,
                VisibilityConstraint::Or(inner) => flat.extend(inner),
                other => flat.push(other),
            }
        }
        match flat.len() {
            0 => VisibilityConstraint::Never,
            1 => flat.remove(0),
            _ => VisibilityConstraint::Or(flat),
        }
    }

    /// Parse a test condition string from a When clause.
    ///
    /// Supported formats:
    /// - "1" - equals 1
    /// - "0 1 2" - equals 0 OR 1 OR 2
    /// - "!=0" - not equals 0
    /// - ">5" - greater than 5
    /// - "<10" - less than 10
    /// - ">=5" - greater than or equal to 5
    /// - "<=10" - less than or equal to 10
    pub fn from_test(selector: &str, test: &str) -> Self {
        let test = test.trim();

        // Check for comparison operators
        if let Some(rest) = test.strip_prefix("!=")
            && let Ok(val) = rest.trim().parse::<i64>() {
                return VisibilityConstraint::NotEquals { selector: selector.to_string(), value: val };
            }
        if let Some(rest) = test.strip_prefix(">=")
            && let Ok(val) = rest.trim().parse::<i64>() {
                // >= is equivalent to > (val - 1)
                return VisibilityConstraint::GreaterThan { selector: selector.to_string(), value: val - 1 };
            }
        if let Some(rest) = test.strip_prefix("<=")
            && let Ok(val) = rest.trim().parse::<i64>() {
                // <= is equivalent to < (val + 1)
                return VisibilityConstraint::LessThan { selector: selector.to_string(), value: val + 1 };
            }
        if let Some(rest) = test.strip_prefix('>')
            && let Ok(val) = rest.trim().parse::<i64>() {
                return VisibilityConstraint::GreaterThan { selector: selector.to_string(), value: val };
            }
        if let Some(rest) = test.strip_prefix('<')
            && let Ok(val) = rest.trim().parse::<i64>() {
                return VisibilityConstraint::LessThan { selector: selector.to_string(), value: val };
            }

        // Space-separated OR values
        let values: BTreeSet<i64> = test.split_whitespace().filter_map(|s| s.parse::<i64>().ok()).collect();

        if values.is_empty() {
            VisibilityConstraint::Always
        } else {
            VisibilityConstraint::Equals { selector: selector.to_string(), values }
        }
    }

    /// Evaluate the constraint against a set of parameter values.
    pub fn evaluate(&self, values: &HashMap<String, i64>) -> bool {
        match self {
            VisibilityConstraint::Always => true,
            VisibilityConstraint::Never => false,
            VisibilityConstraint::Equals { selector, values: eq_values } => {
                values.get(selector).map(|v| eq_values.contains(v)).unwrap_or(false)
            }
            VisibilityConstraint::NotEquals { selector, value } => {
                values.get(selector).map(|v| v != value).unwrap_or(true)
            }
            VisibilityConstraint::GreaterThan { selector, value } => {
                values.get(selector).map(|v| v > value).unwrap_or(false)
            }
            VisibilityConstraint::LessThan { selector, value } => {
                values.get(selector).map(|v| v < value).unwrap_or(false)
            }
            VisibilityConstraint::And(constraints) => constraints.iter().all(|c| c.evaluate(values)),
            VisibilityConstraint::Or(constraints) => constraints.iter().any(|c| c.evaluate(values)),
        }
    }

    /// Simplify the constraint.
    pub fn simplify(self) -> Self {
        match self {
            VisibilityConstraint::And(constraints) => {
                let simplified: Vec<_> = constraints.into_iter().map(|c| c.simplify()).collect();
                VisibilityConstraint::and(simplified)
            }
            VisibilityConstraint::Or(constraints) => {
                let simplified: Vec<_> = constraints.into_iter().map(|c| c.simplify()).collect();
                VisibilityConstraint::or(simplified)
            }
            other => other,
        }
    }
}

impl fmt::Display for VisibilityConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VisibilityConstraint::Always => write!(f, "always"),
            VisibilityConstraint::Never => write!(f, "never"),
            VisibilityConstraint::Equals { selector, values } => {
                let vals: Vec<_> = values.iter().map(|v| v.to_string()).collect();
                write!(f, "{}={}", selector, vals.join("|"))
            }
            VisibilityConstraint::NotEquals { selector, value } => {
                write!(f, "{}!={}", selector, value)
            }
            VisibilityConstraint::GreaterThan { selector, value } => {
                write!(f, "{}>{}", selector, value)
            }
            VisibilityConstraint::LessThan { selector, value } => {
                write!(f, "{}<{}", selector, value)
            }
            VisibilityConstraint::And(constraints) => {
                let parts: Vec<_> = constraints.iter().map(|c| format!("{}", c)).collect();
                write!(f, "({})", parts.join(" AND "))
            }
            VisibilityConstraint::Or(constraints) => {
                let parts: Vec<_> = constraints.iter().map(|c| format!("{}", c)).collect();
                write!(f, "({})", parts.join(" OR "))
            }
        }
    }
}

// ============================================================================
// Visibility Map
// ============================================================================

/// A map of entity references to their visibility constraints.
#[derive(Debug, Clone, Default)]
pub struct VisibilityMap {
    /// Parameter ref ID -> visibility constraint.
    pub param_ref_visibility: HashMap<String, VisibilityConstraint>,
    /// ComObject ref ID -> visibility constraint.
    pub com_object_ref_visibility: HashMap<String, VisibilityConstraint>,
}

impl VisibilityMap {
    /// Extract visibility constraints from a parsed ApplicationProgram.
    pub fn from_program(program: &ApplicationProgram) -> Self {
        let mut map = Self::default();

        if let Some(ref dynamic) = program.dynamic {
            // Process channel-independent block
            if let Some(ref cib) = dynamic.channel_independent_block {
                map.process_channel_independent_block(cib, VisibilityConstraint::Always);
            }

            // Process channels
            for channel in &dynamic.channels {
                map.process_channel(channel, VisibilityConstraint::Always);
            }
        }

        map
    }

    fn process_channel_independent_block(
        &mut self,
        block: &ChannelIndependentBlock,
        parent_constraint: VisibilityConstraint,
    ) {
        for item in &block.items {
            match item {
                ChannelIndependentItem::ParameterBlock(pb) => {
                    self.process_parameter_block(pb, parent_constraint.clone());
                }
                ChannelIndependentItem::Choose(choose) => {
                    self.process_choose(choose, parent_constraint.clone());
                }
            }
        }
    }

    fn process_channel(&mut self, channel: &Channel, parent_constraint: VisibilityConstraint) {
        for item in &channel.items {
            match item {
                ChannelItem::ParameterBlock(pb) => {
                    self.process_parameter_block(pb, parent_constraint.clone());
                }
                ChannelItem::Choose(choose) => {
                    self.process_choose(choose, parent_constraint.clone());
                }
                ChannelItem::Module(_) => {
                    // Modules are instantiated templates - visibility is handled within the module definition
                }
            }
        }
    }

    fn process_parameter_block(&mut self, block: &ParameterBlock, parent_constraint: VisibilityConstraint) {
        for item in &block.items {
            match item {
                ParameterBlockItem::ParameterRefRef(prr) => {
                    self.param_ref_visibility.insert(prr.ref_id.clone(), parent_constraint.clone());
                }
                ParameterBlockItem::ComObjectRefRef(corr) => {
                    self.com_object_ref_visibility.insert(corr.ref_id.clone(), parent_constraint.clone());
                }
                ParameterBlockItem::Choose(choose) => {
                    self.process_choose(choose, parent_constraint.clone());
                }
                ParameterBlockItem::ParameterSeparator(_) => {
                    // Separators don't have visibility
                }
                ParameterBlockItem::Module(_) => {
                    // Module instances have their own internal visibility
                }
                ParameterBlockItem::Button(_) => {
                    // Buttons are UI elements, don't have visibility
                }
                ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => {
                    // Table layout elements don't have visibility
                }
            }
        }
    }

    fn process_choose(&mut self, choose: &Choose, parent_constraint: VisibilityConstraint) {
        let selector = &choose.param_ref_id;

        for when in &choose.whens {
            // Build constraint for this when clause
            let when_constraint = if when.default == Some(true) {
                // Default clause - we'd need to know all other values to compute the complement
                // For now, treat as always (conservative)
                VisibilityConstraint::Always
            } else if let Some(ref test) = when.test {
                VisibilityConstraint::from_test(selector, test)
            } else {
                VisibilityConstraint::Always
            };

            // Combine with parent constraint
            let combined = VisibilityConstraint::and(vec![parent_constraint.clone(), when_constraint]);

            // Process items in this when clause
            for item in &when.items {
                self.process_when_item(item, combined.clone());
            }
        }
    }

    fn process_when_item(&mut self, item: &WhenItem, constraint: VisibilityConstraint) {
        match item {
            WhenItem::ParameterRefRef(prr) => {
                self.param_ref_visibility.insert(prr.ref_id.clone(), constraint);
            }
            WhenItem::ComObjectRefRef(corr) => {
                self.com_object_ref_visibility.insert(corr.ref_id.clone(), constraint);
            }
            WhenItem::ParameterBlock(pb) => {
                self.process_parameter_block(pb, constraint);
            }
            WhenItem::Choose(choose) => {
                self.process_choose(choose, constraint);
            }
            WhenItem::ParameterSeparator(_) => {
                // Separators don't have visibility
            }
            WhenItem::Assign(_) => {
                // Assignments don't affect visibility
            }
            WhenItem::Module(_) => {
                // Modules are instantiated templates - visibility is handled within the module definition
            }
        }
    }
}

// ============================================================================
// Visibility Comparison
// ============================================================================

/// A difference in visibility constraints.
#[derive(Debug, Clone)]
pub struct VisibilityDiff {
    /// The entity reference ID.
    pub ref_id: String,
    /// Whether this is a parameter or com object ref.
    pub entity_type: VisibilityEntityType,
    /// Constraint in reference program.
    pub ref_constraint: VisibilityConstraint,
    /// Constraint in generated program.
    pub gen_constraint: VisibilityConstraint,
    /// Example configuration where they differ (if found).
    pub counterexample: Option<HashMap<String, i64>>,
}

/// Type of entity for visibility comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibilityEntityType {
    ParameterRef,
    ComObjectRef,
}

impl fmt::Display for VisibilityDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} '{}': ref={}, gen={}",
            self.entity_type, self.ref_id, self.ref_constraint, self.gen_constraint
        )?;
        if let Some(ref ce) = self.counterexample {
            write!(f, " (counterexample: {:?})", ce)?;
        }
        Ok(())
    }
}

/// Compare visibility maps for two programs.
pub fn compare_visibility(reference: &VisibilityMap, generated: &VisibilityMap) -> Vec<VisibilityDiff> {
    let mut diffs = Vec::new();

    // Compare parameter ref visibility
    let all_param_refs: HashSet<_> =
        reference.param_ref_visibility.keys().chain(generated.param_ref_visibility.keys()).collect();

    for ref_id in all_param_refs {
        let ref_constraint = reference.param_ref_visibility.get(ref_id).cloned().unwrap_or(VisibilityConstraint::Never);
        let gen_constraint = generated.param_ref_visibility.get(ref_id).cloned().unwrap_or(VisibilityConstraint::Never);

        if ref_constraint != gen_constraint {
            diffs.push(VisibilityDiff {
                ref_id: ref_id.clone(),
                entity_type: VisibilityEntityType::ParameterRef,
                ref_constraint,
                gen_constraint,
                counterexample: None, // TODO: Find counterexample
            });
        }
    }

    // Compare com object ref visibility
    let all_com_refs: HashSet<_> =
        reference.com_object_ref_visibility.keys().chain(generated.com_object_ref_visibility.keys()).collect();

    for ref_id in all_com_refs {
        let ref_constraint =
            reference.com_object_ref_visibility.get(ref_id).cloned().unwrap_or(VisibilityConstraint::Never);
        let gen_constraint =
            generated.com_object_ref_visibility.get(ref_id).cloned().unwrap_or(VisibilityConstraint::Never);

        if ref_constraint != gen_constraint {
            diffs.push(VisibilityDiff {
                ref_id: ref_id.clone(),
                entity_type: VisibilityEntityType::ComObjectRef,
                ref_constraint,
                gen_constraint,
                counterexample: None,
            });
        }
    }

    diffs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_from_test_single_value() {
        let c = VisibilityConstraint::from_test("sel", "5");
        assert_eq!(c, VisibilityConstraint::Equals { selector: "sel".to_string(), values: [5].into_iter().collect() });
    }

    #[test]
    fn test_constraint_from_test_multiple_values() {
        let c = VisibilityConstraint::from_test("sel", "1 2 3");
        assert_eq!(c, VisibilityConstraint::Equals {
            selector: "sel".to_string(),
            values: [1, 2, 3].into_iter().collect(),
        });
    }

    #[test]
    fn test_constraint_from_test_not_equals() {
        let c = VisibilityConstraint::from_test("sel", "!=0");
        assert_eq!(c, VisibilityConstraint::NotEquals { selector: "sel".to_string(), value: 0 });
    }

    #[test]
    fn test_constraint_from_test_greater_than() {
        let c = VisibilityConstraint::from_test("sel", ">5");
        assert_eq!(c, VisibilityConstraint::GreaterThan { selector: "sel".to_string(), value: 5 });
    }

    #[test]
    fn test_constraint_evaluate() {
        let c = VisibilityConstraint::equals("sel", [1, 2, 3]);
        let mut vals = HashMap::new();

        vals.insert("sel".to_string(), 2);
        assert!(c.evaluate(&vals));

        vals.insert("sel".to_string(), 5);
        assert!(!c.evaluate(&vals));
    }

    #[test]
    fn test_constraint_and_simplify() {
        let c = VisibilityConstraint::and(vec![VisibilityConstraint::Always, VisibilityConstraint::equals("sel", [1])]);
        assert_eq!(c, VisibilityConstraint::equals("sel", [1]));

        let c2 = VisibilityConstraint::and(vec![VisibilityConstraint::Never, VisibilityConstraint::equals("sel", [1])]);
        assert_eq!(c2, VisibilityConstraint::Never);
    }

    #[test]
    fn test_constraint_display() {
        let c = VisibilityConstraint::equals("sel", [1, 2, 3]);
        assert_eq!(format!("{}", c), "sel=1|2|3");

        let c2 = VisibilityConstraint::and(vec![
            VisibilityConstraint::equals("a", [1]),
            VisibilityConstraint::equals("b", [2]),
        ]);
        assert_eq!(format!("{}", c2), "(a=1 AND b=2)");
    }
}
