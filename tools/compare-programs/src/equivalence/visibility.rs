//! Visibility constraint extraction and comparison.
//!
//! This module extracts visibility constraints from the Dynamic section
//! of an ApplicationProgram and provides tools to compare constraints
//! for semantic equivalence.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use zweidraehte_knxprod::schema::{
    ApplicationProgram, Channel, ChannelIndependentBlock, ChannelIndependentItem, ChannelItem, Choose, ParameterBlock,
    ParameterBlockItem, WhenItem,
};

use super::canonical::{CanonicalProgram, ParameterKey};

// ============================================================================
// Visibility Constraint
// ============================================================================

/// A visibility constraint representing when an element is visible.
///
/// Constraints form a tree structure representing boolean conditions.
///
/// `Ord` is derived purely so that the children of [`VisibilityConstraint::And`]
/// and [`VisibilityConstraint::Or`] can be kept in a canonical order — two
/// programs that list the same branches in a different order must still compare
/// equal. The ordering itself carries no meaning.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    ///
    /// Extraction builds constraints through [`VisibilityConstraint::from_test`];
    /// this is the convenience form for constructing them directly.
    #[allow(dead_code)]
    pub fn equals(selector: impl Into<String>, values: impl IntoIterator<Item = i64>) -> Self {
        VisibilityConstraint::Equals { selector: selector.into(), values: values.into_iter().collect() }
    }

    /// Create an And constraint.
    ///
    /// Children are flattened, sorted and deduplicated so that structurally
    /// equal conjunctions built in different orders compare equal.
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

        // `sel=1|2 AND sel=2|3` is `sel=2`, so fold same-selector equalities into
        // their intersection. An empty intersection cannot be satisfied at all.
        fold_equals_by_selector(&mut flat, |accumulated, incoming| {
            accumulated.retain(|value| incoming.contains(value));
        });
        if flat.iter().any(|c| matches!(c, VisibilityConstraint::Equals { values, .. } if values.is_empty())) {
            return VisibilityConstraint::Never;
        }

        flat.sort();
        flat.dedup();
        match flat.len() {
            0 => VisibilityConstraint::Always,
            1 => flat.remove(0),
            _ => VisibilityConstraint::And(flat),
        }
    }

    /// Create an Or constraint.
    ///
    /// Children are flattened, sorted and deduplicated for the same reason as
    /// in [`VisibilityConstraint::and`].
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

        // The same element placed under `when test="0"` and `when test="1"` must
        // canonicalize to what a single `when test="0 1"` would have produced.
        fold_equals_by_selector(&mut flat, |accumulated, incoming| {
            accumulated.extend(incoming.iter().copied());
        });

        flat.sort();
        flat.dedup();
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
            && let Ok(val) = rest.trim().parse::<i64>()
        {
            return VisibilityConstraint::NotEquals { selector: selector.to_string(), value: val };
        }
        if let Some(rest) = test.strip_prefix(">=")
            && let Ok(val) = rest.trim().parse::<i64>()
        {
            // >= is equivalent to > (val - 1)
            return VisibilityConstraint::GreaterThan { selector: selector.to_string(), value: val - 1 };
        }
        if let Some(rest) = test.strip_prefix("<=")
            && let Ok(val) = rest.trim().parse::<i64>()
        {
            // <= is equivalent to < (val + 1)
            return VisibilityConstraint::LessThan { selector: selector.to_string(), value: val + 1 };
        }
        if let Some(rest) = test.strip_prefix('>')
            && let Ok(val) = rest.trim().parse::<i64>()
        {
            return VisibilityConstraint::GreaterThan { selector: selector.to_string(), value: val };
        }
        if let Some(rest) = test.strip_prefix('<')
            && let Ok(val) = rest.trim().parse::<i64>()
        {
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

    /// Rewrite every selector in the constraint tree through `f`.
    ///
    /// Selectors are `ParameterRefId` strings as they appear in the XML, which
    /// are program-specific. Canonicalization maps them onto semantic keys so
    /// that two programs' constraints can be compared at all — see
    /// [`VisibilityMap::canonicalize`].
    pub fn map_selectors(&self, f: &impl Fn(&str) -> String) -> Self {
        match self {
            VisibilityConstraint::Always => VisibilityConstraint::Always,
            VisibilityConstraint::Never => VisibilityConstraint::Never,
            VisibilityConstraint::Equals { selector, values } => {
                VisibilityConstraint::Equals { selector: f(selector), values: values.clone() }
            }
            VisibilityConstraint::NotEquals { selector, value } => {
                VisibilityConstraint::NotEquals { selector: f(selector), value: *value }
            }
            VisibilityConstraint::GreaterThan { selector, value } => {
                VisibilityConstraint::GreaterThan { selector: f(selector), value: *value }
            }
            VisibilityConstraint::LessThan { selector, value } => {
                VisibilityConstraint::LessThan { selector: f(selector), value: *value }
            }
            // Rebuild through the smart constructors: rewriting selectors can
            // change the sort order of the children, and equal-after-rewrite
            // children must collapse.
            VisibilityConstraint::And(constraints) => {
                VisibilityConstraint::and(constraints.iter().map(|c| c.map_selectors(f)).collect())
            }
            VisibilityConstraint::Or(constraints) => {
                VisibilityConstraint::or(constraints.iter().map(|c| c.map_selectors(f)).collect())
            }
        }
    }

    // Deliberately no `simplify`: `and`/`or` normalize as they build, so every
    // constraint reaching the comparison is already in its simplified form.
}

/// Collapse the `Equals` terms in `constraints` so that each selector appears at
/// most once, combining their value sets with `combine`.
///
/// The point is that two programs can express the same condition either as one
/// multi-valued test or as several single-valued ones; unless both spellings
/// reduce to the same tree, every such pair reads as a visibility difference.
/// Only `Equals` is folded — the comparison operators cannot be combined into a
/// single term without a range representation.
fn fold_equals_by_selector(
    constraints: &mut Vec<VisibilityConstraint>,
    combine: impl Fn(&mut BTreeSet<i64>, &BTreeSet<i64>),
) {
    let mut folded: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
    let mut others = Vec::new();

    for constraint in constraints.drain(..) {
        match constraint {
            VisibilityConstraint::Equals { selector, values } => match folded.get_mut(&selector) {
                Some(accumulated) => combine(accumulated, &values),
                None => {
                    folded.insert(selector, values);
                }
            },
            other => others.push(other),
        }
    }

    constraints.extend(folded.into_iter().map(|(selector, values)| VisibilityConstraint::Equals { selector, values }));
    constraints.extend(others);
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
///
/// Keyed by the raw XML ref IDs, so a `VisibilityMap` is only meaningful within
/// the program it was extracted from. Run it through
/// [`VisibilityMap::canonicalize`] before comparing two programs.
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

    /// Record a parameter ref's visibility.
    ///
    /// The same ref may be placed under several mutually exclusive branches
    /// (e.g. the same parameter shown in both the "switch" and "dim" variant of
    /// a channel), so an existing constraint is OR-ed with the new one rather
    /// than overwritten — the ref is visible under *either* condition.
    fn add_param_ref(&mut self, ref_id: &str, constraint: VisibilityConstraint) {
        merge_or(&mut self.param_ref_visibility, ref_id, constraint);
    }

    /// Record a com-object ref's visibility; see [`VisibilityMap::add_param_ref`].
    fn add_com_object_ref(&mut self, ref_id: &str, constraint: VisibilityConstraint) {
        merge_or(&mut self.com_object_ref_visibility, ref_id, constraint);
    }

    fn process_parameter_block(&mut self, block: &ParameterBlock, parent_constraint: VisibilityConstraint) {
        for item in &block.items {
            match item {
                ParameterBlockItem::ParameterRefRef(prr) => {
                    self.add_param_ref(&prr.ref_id, parent_constraint.clone());
                }
                ParameterBlockItem::ComObjectRefRef(corr) => {
                    self.add_com_object_ref(&corr.ref_id, parent_constraint.clone());
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
                // Default clause - we'd need to know all other values to compute the complement.
                // Treated as unconditional, which overstates visibility. That is acceptable here
                // because both programs are analysed the same way, so the overstatement cancels
                // out in the comparison; it does mean a difference that lives purely in a default
                // branch goes unnoticed.
                // TODO: model the complement (a NotIn variant) to make default branches comparable.
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
                self.add_param_ref(&prr.ref_id, constraint);
            }
            WhenItem::ComObjectRefRef(corr) => {
                self.add_com_object_ref(&corr.ref_id, constraint);
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

/// OR an incoming constraint into an existing entry, if any.
fn merge_or(map: &mut HashMap<String, VisibilityConstraint>, key: &str, constraint: VisibilityConstraint) {
    match map.get_mut(key) {
        Some(existing) => {
            let combined = VisibilityConstraint::or(vec![existing.clone(), constraint]);
            *existing = combined;
        }
        None => {
            map.insert(key.to_string(), constraint);
        }
    }
}

// ============================================================================
// Canonicalization
// ============================================================================

/// Semantic identity of a parameter or communication object reference.
///
/// Ref IDs are program-specific (`M-0083_A-009B-14-E59D_P-1_R-1` in the vendor
/// XML vs. `M-00FA_A-0200-01-0000_P-1_R-1` in ours), so visibility can only be
/// compared once every ref is reduced to what it actually points at: the
/// referenced entity's semantic key, plus which of that entity's refs it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefKey {
    /// A `ParameterRefRef`, identified by the referenced parameter's memory location.
    Param { key: ParameterKey, ref_index: usize },
    /// A `ComObjectRefRef`, identified by the referenced object's number.
    ComObject { number: u16, ref_index: usize },
}

impl fmt::Display for RefKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefKey::Param { key, ref_index } => write!(f, "param[{}]#{}", key, ref_index),
            RefKey::ComObject { number, ref_index } => write!(f, "object[{}]#{}", number, ref_index),
        }
    }
}

/// A visibility map reduced to semantic keys, comparable across programs.
#[derive(Debug, Clone, Default)]
pub struct CanonicalVisibilityMap {
    /// Visibility constraint per reference.
    pub visibility: BTreeMap<RefKey, VisibilityConstraint>,
}

impl VisibilityMap {
    /// Reduce this map to semantic keys using the program it was extracted from.
    ///
    /// Refs that cannot be resolved against the canonical program (dangling
    /// `RefId`s, or refs into module templates that the canonical form does not
    /// expand) are dropped: reporting them as visibility differences would only
    /// produce noise, since the entity comparison already flags them.
    ///
    /// The `ref_index` component makes this exact only for parameters with a
    /// single ref — the overwhelming majority. Where a parameter has several
    /// refs, the index comes from document order, so two programs listing the
    /// same refs in a different order will pair them up wrongly.
    pub fn canonicalize(&self, program: &CanonicalProgram) -> CanonicalVisibilityMap {
        // Selectors in the constraints are ParameterRefIds too, and have to be
        // rewritten alongside the keys or the constraints stay incomparable.
        let rewrite_selector = |selector: &str| match param_ref_key(program, selector) {
            Some(key) => key.to_string(),
            None => format!("<unresolved:{}>", selector),
        };

        let mut canonical = CanonicalVisibilityMap::default();

        for (ref_id, constraint) in &self.param_ref_visibility {
            if let Some(key) = param_ref_key(program, ref_id) {
                canonical.visibility.insert(key, constraint.map_selectors(&rewrite_selector));
            }
        }

        for (ref_id, constraint) in &self.com_object_ref_visibility {
            if let Some(key) = com_object_ref_key(program, ref_id) {
                canonical.visibility.insert(key, constraint.map_selectors(&rewrite_selector));
            }
        }

        canonical
    }
}

/// Resolve a `ParameterRefId` to its semantic key.
fn param_ref_key(program: &CanonicalProgram, ref_id: &str) -> Option<RefKey> {
    let index = *program.param_ref_id_to_index.get(ref_id)?;
    Some(program.param_refs.get(index)?.ref_key())
}

/// Resolve a `ComObjectRefId` to its semantic key.
fn com_object_ref_key(program: &CanonicalProgram, ref_id: &str) -> Option<RefKey> {
    let index = *program.com_object_ref_id_to_index.get(ref_id)?;
    Some(program.com_object_refs.get(index)?.ref_key())
}

// ============================================================================
// Visibility Comparison
// ============================================================================

/// A difference in visibility constraints.
#[derive(Debug, Clone)]
pub struct VisibilityDiff {
    /// The reference whose visibility differs.
    pub ref_key: RefKey,
    /// Constraint in reference program.
    pub ref_constraint: VisibilityConstraint,
    /// Constraint in generated program.
    pub gen_constraint: VisibilityConstraint,
    /// A parameter assignment under which the two constraints disagree.
    pub counterexample: Option<HashMap<String, i64>>,
}

impl fmt::Display for VisibilityDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ref={}, gen={}", self.ref_key, self.ref_constraint, self.gen_constraint)?;
        if let Some(ref counterexample) = self.counterexample {
            let mut assignments: Vec<_> = counterexample.iter().collect();
            assignments.sort();
            let rendered: Vec<_> = assignments.iter().map(|(s, v)| format!("{}={}", s, v)).collect();
            write!(f, " (differ when {})", rendered.join(", "))?;
        }
        Ok(())
    }
}

/// Compare canonicalized visibility maps for two programs.
///
/// A ref present in only one program gets [`VisibilityConstraint::Never`] on the
/// other side — "never visible" is the honest reading of "not placed anywhere in
/// the Dynamic section".
pub fn compare_visibility(
    reference: &CanonicalVisibilityMap,
    generated: &CanonicalVisibilityMap,
) -> Vec<VisibilityDiff> {
    let all_refs: BTreeSet<_> = reference.visibility.keys().chain(generated.visibility.keys()).copied().collect();

    all_refs
        .into_iter()
        .filter_map(|ref_key| {
            let ref_constraint = reference.visibility.get(&ref_key).cloned().unwrap_or(VisibilityConstraint::Never);
            let gen_constraint = generated.visibility.get(&ref_key).cloned().unwrap_or(VisibilityConstraint::Never);

            if ref_constraint == gen_constraint {
                return None;
            }

            let counterexample = find_counterexample(&ref_constraint, &gen_constraint);
            Some(VisibilityDiff { ref_key, ref_constraint, gen_constraint, counterexample })
        })
        .collect()
}

/// Search for a parameter assignment under which two constraints disagree.
///
/// Structural inequality does not imply behavioural inequality — `a=1 AND a=1`
/// and `a=1` are different trees with identical behaviour. Rather than
/// implementing a solver, we enumerate the values that literally appear in
/// either constraint (plus one value outside all of them, to exercise the
/// "matches nothing" case) and try every combination. That is exhaustive for
/// the equality-and-comparison constraints ETS actually produces, and cheap as
/// long as a single element's visibility depends on few selectors.
///
/// Returns `None` when no assignment distinguishes them, i.e. the constraints
/// differ only in shape. Callers should treat that as "no real difference".
fn find_counterexample(
    reference: &VisibilityConstraint,
    generated: &VisibilityConstraint,
) -> Option<HashMap<String, i64>> {
    let mut candidates: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
    collect_candidate_values(reference, &mut candidates);
    collect_candidate_values(generated, &mut candidates);

    // Nothing to vary: the constraints differ unconditionally (typically
    // `Always` vs `Never`, i.e. a ref only one program places at all), which
    // the printed constraints already say.
    if candidates.is_empty() {
        return None;
    }

    // Guard against combinatorial blow-up on pathological constraints.
    const MAX_ASSIGNMENTS: usize = 4096;
    let total: usize = candidates.values().map(|v| v.len()).product();
    if total > MAX_ASSIGNMENTS {
        return None;
    }

    let selectors: Vec<_> = candidates.keys().cloned().collect();
    let value_sets: Vec<Vec<i64>> = candidates.values().map(|v| v.iter().copied().collect()).collect();

    for mut index in 0..total {
        let mut assignment = HashMap::new();
        for (selector, values) in selectors.iter().zip(value_sets.iter()) {
            assignment.insert(selector.clone(), values[index % values.len()]);
            index /= values.len();
        }

        if reference.evaluate(&assignment) != generated.evaluate(&assignment) {
            return Some(assignment);
        }
    }

    None
}

/// Collect, per selector, the values worth trying in a counterexample search.
fn collect_candidate_values(constraint: &VisibilityConstraint, out: &mut BTreeMap<String, BTreeSet<i64>>) {
    match constraint {
        VisibilityConstraint::Always | VisibilityConstraint::Never => {}
        VisibilityConstraint::Equals { selector, values } => {
            let entry = out.entry(selector.clone()).or_default();
            entry.extend(values.iter().copied());
            // A value outside the set, so "selector matches none of them" is covered.
            entry.insert(values.iter().max().copied().unwrap_or(0) + 1);
        }
        VisibilityConstraint::NotEquals { selector, value } => {
            let entry = out.entry(selector.clone()).or_default();
            entry.insert(*value);
            entry.insert(value + 1);
        }
        VisibilityConstraint::GreaterThan { selector, value } | VisibilityConstraint::LessThan { selector, value } => {
            // Straddle the threshold: below, at, and above.
            let entry = out.entry(selector.clone()).or_default();
            entry.insert(value - 1);
            entry.insert(*value);
            entry.insert(value + 1);
        }
        VisibilityConstraint::And(constraints) | VisibilityConstraint::Or(constraints) => {
            for c in constraints {
                collect_candidate_values(c, out);
            }
        }
    }
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

    /// Two programs may list the branches of a conjunction in either order;
    /// that must not read as a visibility difference.
    #[test]
    fn test_constraint_children_are_order_insensitive() {
        let a = VisibilityConstraint::equals("a", [1]);
        let b = VisibilityConstraint::equals("b", [2]);

        assert_eq!(
            VisibilityConstraint::and(vec![a.clone(), b.clone()]),
            VisibilityConstraint::and(vec![b.clone(), a.clone()])
        );
        assert_eq!(VisibilityConstraint::or(vec![a.clone(), b.clone()]), VisibilityConstraint::or(vec![b, a]));
    }

    /// A ref placed under two mutually exclusive branches is visible under
    /// either, not just the one that happened to be processed last.
    #[test]
    fn test_repeated_ref_visibility_is_ored() {
        let mut map = VisibilityMap::default();
        map.add_param_ref("P-1_R-1", VisibilityConstraint::equals("sel", [0]));
        map.add_param_ref("P-1_R-1", VisibilityConstraint::equals("sel", [1]));

        assert_eq!(map.param_ref_visibility["P-1_R-1"], VisibilityConstraint::equals("sel", [0, 1]));
    }

    /// Conjunction narrows a selector to the values both terms allow, and an
    /// empty intersection means the element can never be shown.
    #[test]
    fn test_same_selector_equalities_intersect_under_and() {
        let narrowed = VisibilityConstraint::and(vec![
            VisibilityConstraint::equals("sel", [1, 2, 3]),
            VisibilityConstraint::equals("sel", [2, 3, 4]),
        ]);
        assert_eq!(narrowed, VisibilityConstraint::equals("sel", [2, 3]));

        let contradiction = VisibilityConstraint::and(vec![
            VisibilityConstraint::equals("sel", [1]),
            VisibilityConstraint::equals("sel", [2]),
        ]);
        assert_eq!(contradiction, VisibilityConstraint::Never);
    }

    /// Folding must only merge terms that share a selector.
    #[test]
    fn test_distinct_selectors_are_not_folded() {
        let combined = VisibilityConstraint::or(vec![
            VisibilityConstraint::equals("a", [1]),
            VisibilityConstraint::equals("b", [2]),
        ]);

        assert_eq!(
            combined,
            VisibilityConstraint::Or(vec![
                VisibilityConstraint::equals("a", [1]),
                VisibilityConstraint::equals("b", [2]),
            ])
        );
    }

    #[test]
    fn test_map_selectors_rewrites_nested_constraints() {
        let constraint = VisibilityConstraint::and(vec![
            VisibilityConstraint::equals("raw-a", [1]),
            VisibilityConstraint::NotEquals { selector: "raw-b".to_string(), value: 0 },
        ]);

        let rewritten = constraint.map_selectors(&|s: &str| s.replace("raw-", "key-"));

        assert_eq!(
            rewritten,
            VisibilityConstraint::and(vec![
                VisibilityConstraint::equals("key-a", [1]),
                VisibilityConstraint::NotEquals { selector: "key-b".to_string(), value: 0 },
            ])
        );
    }

    #[test]
    fn test_find_counterexample_distinguishes_constraints() {
        let reference = VisibilityConstraint::equals("sel", [1, 2]);
        let generated = VisibilityConstraint::equals("sel", [1]);

        let counterexample = find_counterexample(&reference, &generated).expect("value 2 separates the two sets");
        assert_eq!(counterexample.get("sel"), Some(&2));
    }

    /// Structurally different but behaviourally identical constraints have no
    /// counterexample; the caller uses that to soften the report.
    #[test]
    fn test_find_counterexample_none_for_equivalent_constraints() {
        let reference = VisibilityConstraint::Equals { selector: "sel".to_string(), values: [1].into_iter().collect() };
        let generated = VisibilityConstraint::Or(vec![reference.clone(), reference.clone()]);

        assert!(find_counterexample(&reference, &generated).is_none());
    }
}
