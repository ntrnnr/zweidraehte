//! Turning a parsed template into suites the engine can run.
//!
//! This is where every EITT semantic gets decided, so the reasoning is
//! recorded next to each decision rather than in a commit message. The
//! two that are easiest to get wrong:
//!
//! - **`TimeToNext` means different things per direction.** For an
//!   `OUT` telegram it is the window in which the frame must arrive —
//!   the expect timeout. For an `IN` telegram it is the gap before the
//!   *next* telegram goes out. Reading it as one uniform "delay" gives
//!   expects a 0 ms timeout and injects a spurious wait.
//! - **Our `Inject` delays before the frame, EITT's `TimeToNext` comes
//!   after it.** Folding the delay into `delay_before_ms` is off by one
//!   step, which only shows up at case boundaries. Emitting an explicit
//!   `Wait` afterwards is exact.
//!
//! Anything not understood is an error, not a guess. A template that
//! has moved on must stop the run; the alternative is a green report
//! for a test that no longer does what its name says.

use std::collections::BTreeMap;

use crate::eitt::comment::{self, CommentCommand};
use crate::eitt::patch::{Anchor, PatchError, PatchSet};
use crate::eitt::profile::{Policy, Profile};
use crate::eitt::schema::{self, SequenceItem, Template};
use crate::tests::helpers;
use crate::{TestCase, TestStep, TestSuite, TestVariable};

/// What lowering dropped, and why. Printed before a run so that "8 of
/// 16 cases" is never a surprise.
#[derive(Debug, Default, Clone)]
pub struct LowerReport {
    /// Collections the profile did not select, with their case counts.
    pub skipped_collections: Vec<(String, usize)>,
    /// Cases skipped because the profile says they do not apply.
    pub not_applicable: Vec<(String, String)>,
    /// Cases skipped by a patch.
    pub skipped_by_patch: Vec<(String, String)>,
    /// Telegrams dropped because `Activate="no"`.
    pub deactivated: usize,
    /// Telegrams dropped because they are for another medium, counted
    /// per medium.
    pub wrong_medium: BTreeMap<String, usize>,
    /// Comment commands ignored under an `ignore` policy.
    pub ignored_commands: Vec<String>,
    /// Patches that applied, by reason.
    pub applied_patches: Vec<String>,
}

impl LowerReport {
    /// Print the report. Silent sections are omitted; a run with
    /// nothing to report prints nothing.
    pub fn print(&self) {
        for (name, cases) in &self.skipped_collections {
            println!("  ⊘ collection {name:?} not selected ({cases} case(s))");
        }
        for (name, why) in &self.not_applicable {
            println!("  ⊘ {name}: not applicable — {why}");
        }
        for (name, why) in &self.skipped_by_patch {
            println!("  ⊘ {name}: skipped by patch — {why}");
        }
        if self.deactivated > 0 {
            println!("  · {} deactivated telegram(s) skipped (Activate=\"no\")", self.deactivated);
        }
        for (medium, count) in &self.wrong_medium {
            println!("  · {count} telegram(s) skipped: medium {medium}");
        }
        for why in &self.applied_patches {
            println!("  ✎ patched: {why}");
        }
        for cmd in &self.ignored_commands {
            println!("  ⏸ ignored comment command: {cmd}");
        }
    }
}

/// Why a template could not be lowered.
#[derive(Debug)]
pub enum LowerError {
    /// A patch set names a different template than the one loaded.
    TemplateMismatch { patch_set: String, template: String },
    /// A comment command we do not implement, under an `error` policy.
    UnsupportedCommand { case: String, command: String, text: String },
    /// A telegram attribute whose value we do not know.
    UnknownAttribute { case: String, telegram: String, attr: &'static str, value: String },
    /// A telegram carrying KNX Data Security attributes. Sending it
    /// plain would silently turn a security test into a plaintext one.
    SecureTelegram { case: String, telegram: String, attrs: Vec<&'static str> },
    /// A telegram with no `Data`.
    MissingData { case: String, telegram: String },
    /// A patch that did not apply.
    Patch(PatchError),
}

impl std::fmt::Display for LowerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TemplateMismatch { patch_set, template } => {
                write!(f, "the patch set is for {patch_set:?} but the template is {template:?}")
            }
            Self::UnsupportedCommand { case, command, text } => write!(
                f,
                "{case}: the comment command {command} is not implemented ({text:?}). \
                 It changes what runs, so it cannot be ignored — implement it, or set its \
                 category to \"ignore\" in the profile once you are sure that is right here."
            ),
            Self::UnknownAttribute { case, telegram, attr, value } => {
                write!(f, "{case}: telegram {telegram} has {attr}={value:?}, which this lowerer does not know")
            }
            Self::SecureTelegram { case, telegram, attrs } => write!(
                f,
                "{case}: telegram {telegram} carries KNX Data Security attributes {attrs:?}; \
                 lowering it would send it in the clear"
            ),
            Self::MissingData { case, telegram } => write!(f, "{case}: telegram {telegram} has no Data"),
            Self::Patch(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LowerError {}

impl From<PatchError> for LowerError {
    fn from(e: PatchError) -> Self {
        Self::Patch(e)
    }
}

/// Lower a template into runnable suites.
pub fn lower(
    template: &Template,
    profile: &Profile,
    patches: Option<&PatchSet>,
) -> Result<(Vec<TestSuite>, LowerReport), LowerError> {
    if let Some(set) = patches {
        let name = template.name.as_deref().unwrap_or_default();
        // Substring rather than equality: templates are named
        // "8/3/7 - Group Object Tests" inside the file but referred to
        // by their file stem everywhere else.
        if !name.contains(&set.template) && !set.template.contains(name) && !file_stem_matches(&set.template, name) {
            return Err(LowerError::TemplateMismatch { patch_set: set.template.clone(), template: name.to_string() });
        }
    }

    let mut report = LowerReport::default();
    let by_anchor = patches.map(|p| p.by_anchor()).unwrap_or_default();
    let mut used_anchors: Vec<String> = Vec::new();
    let global_vars = collect_fields(&template.fields);

    let mut suites = Vec::new();
    for collection in template.test_collections.iter().flat_map(|c| &c.collections) {
        // A template's collections are often alternatives, each wanting
        // a different application program loaded into the BDUT, so the
        // profile picks the one matching the program we actually have.
        if !profile.accepts_collection(collection.name.as_deref()) {
            let cases = collection
                .test_suites
                .iter()
                .flat_map(|s| &s.suites)
                .flat_map(|s| s.test_cases.iter())
                .map(|tc| tc.cases.len())
                .sum();
            report
                .skipped_collections
                .push((collection.name.clone().unwrap_or_else(|| "(unnamed)".to_string()), cases));
            continue;
        }

        // Collection-scoped variables shadow template-global ones.
        let mut vars = global_vars.clone();
        vars.extend(collect_fields(&collection.fields));
        // Then the profile: first the addresses the template never
        // declares, then any deliberate override.
        for (name, value) in profile.addresses.iter().chain(profile.variables.iter()) {
            vars.insert(name.clone(), TestVariable::Bytes(parse_hex(value)));
        }

        for suite in collection.test_suites.iter().flat_map(|s| &s.suites) {
            let mut cases = Vec::new();
            for case in suite.test_cases.iter().flat_map(|tc| &tc.cases) {
                let case_name = case.name.clone().unwrap_or_else(|| "(unnamed case)".to_string());

                if let Some(why) = profile.not_applicable_reason(case.id.as_deref()) {
                    report.not_applicable.push((case_name, why.to_string()));
                    continue;
                }
                if let Some(id) = case.id.as_deref()
                    && let Some(entries) = by_anchor.get(&id.to_ascii_uppercase())
                    && let Some((patch, _)) = entries.iter().find(|(_, a)| *a == Anchor::SkipCase)
                {
                    used_anchors.push(id.to_ascii_uppercase());
                    report.skipped_by_patch.push((case_name, patch.why.clone()));
                    continue;
                }

                let steps = lower_sequence(case, &case_name, profile, &by_anchor, &mut used_anchors, &mut report)?;
                cases.push(TestCase::new(case_name).with_steps(steps));
            }

            if cases.is_empty() {
                continue;
            }
            let suite_name = suite.name.clone().unwrap_or_else(|| "(unnamed suite)".to_string());
            suites.push(TestSuite::new(suite_name, vars.clone()).with_cases(cases));
        }
    }

    // Every patch must have found its anchor. One that silently stopped
    // applying leaves a case that still runs and still reports, but no
    // longer tests what the patch made testable.
    if let Some(set) = patches {
        for patch in &set.patches {
            let (id, _) = patch.anchor()?;
            if !used_anchors.iter().any(|u| u == &id.to_ascii_uppercase()) {
                return Err(PatchError::UnknownAnchor { id: id.to_string(), why: patch.why.clone() }.into());
            }
        }
    }

    Ok((suites, report))
}

/// Compare a patch set's `template` against the template's own name via
/// the file stem, e.g. `KnxConformanceTestTemplate-GroupObjects` for
/// "8/3/7 - Group Object Tests".
fn file_stem_matches(patch_template: &str, template_name: &str) -> bool {
    let stem = patch_template.rsplit('-').next().unwrap_or(patch_template);
    let squashed: String = template_name.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase();
    let want: String = stem.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase();
    // "GroupObjects" vs "GroupObjectTests" — compare on the singular
    // stem so plural/`Tests` suffixes do not matter.
    let want = want.trim_end_matches('s').to_string();
    squashed.contains(&want) || want.contains(squashed.trim_end_matches('s'))
}

// ============================================================================
// Sequence lowering
// ============================================================================

fn lower_sequence(
    case: &schema::TestCase,
    case_name: &str,
    profile: &Profile,
    by_anchor: &BTreeMap<String, Vec<(&crate::eitt::patch::Patch, Anchor)>>,
    used_anchors: &mut Vec<String>,
    report: &mut LowerReport,
) -> Result<Vec<TestStep>, LowerError> {
    let mut steps = Vec::new();
    let Some(sequence) = &case.sequence else { return Ok(steps) };

    for item in &sequence.items {
        let id_key = item.id().map(|i| i.to_ascii_uppercase());
        let anchored = id_key.as_ref().and_then(|k| by_anchor.get(k)).map(|v| v.as_slice()).unwrap_or(&[]);
        if !anchored.is_empty() {
            used_anchors.push(id_key.clone().unwrap_or_default());
        }

        let has = |kind: Anchor| anchored.iter().find(|(_, a)| *a == kind);

        if let Some((patch, _)) = has(Anchor::Skip) {
            report.applied_patches.push(format!("skipped a step — {}", patch.why));
            continue;
        }
        if let Some((patch, _)) = has(Anchor::Before) {
            report.applied_patches.push(patch.why.clone());
            steps.extend(patch.insert.iter().map(|s| s.to_step()));
        }

        if let Some((patch, _)) = has(Anchor::Replace) {
            report.applied_patches.push(format!("replaced a step — {}", patch.why));
            steps.extend(patch.insert.iter().map(|s| s.to_step()));
        } else {
            match item {
                SequenceItem::Comment(c) => {
                    lower_comment(c.text.as_deref().unwrap_or(""), case_name, profile, report, &mut steps)?;
                }
                SequenceItem::Telegram(t) => {
                    lower_telegram(t, case_name, profile, report, &mut steps)?;
                }
            }
        }

        if let Some((patch, _)) = has(Anchor::After) {
            report.applied_patches.push(patch.why.clone());
            steps.extend(patch.insert.iter().map(|s| s.to_step()));
        }
    }

    Ok(steps)
}

fn lower_comment(
    text: &str,
    case_name: &str,
    profile: &Profile,
    report: &mut LowerReport,
    steps: &mut Vec<TestStep>,
) -> Result<(), LowerError> {
    let cmd = comment::parse(text);
    let policies = &profile.commands;

    // The category each unimplemented command falls under, or None if
    // we implement it.
    let policy = match &cmd {
        CommentCommand::Pause { .. } => Some(policies.pause),
        CommentCommand::Interface(_) => Some(policies.interface),
        CommentCommand::CallSequence { .. } | CommentCommand::ParallelCall { .. } | CommentCommand::StopParallel(_) => {
            Some(policies.sequence)
        }
        CommentCommand::Security(_) => Some(policies.security),
        CommentCommand::PointApi { .. } => Some(policies.point_api),
        // `@AP` suppresses failure marking. Not implementing it can
        // only make us stricter than EITT, never laxer, so it does not
        // need a policy — but it is worth saying out loud.
        CommentCommand::AutoPass(_) => {
            report.ignored_commands.push(format!("{} (auto-pass is not implemented; we stay strict)", cmd.token()));
            return Ok(());
        }
        _ => None,
    };

    if let Some(Policy::Error) = policy {
        return Err(LowerError::UnsupportedCommand {
            case: case_name.to_string(),
            command: cmd.token().to_string(),
            text: cmd.text().to_string(),
        });
    }
    if let Some(Policy::Ignore) = policy {
        report.ignored_commands.push(format!("{} {:?}", cmd.token(), cmd.text()));
        if !cmd.text().is_empty() {
            steps.push(helpers::comment(cmd.text()));
        }
        return Ok(());
    }

    match cmd {
        CommentCommand::Wait { duration, text } => {
            if !text.is_empty() {
                steps.push(helpers::comment(&text));
            }
            steps.push(helpers::wait(duration.as_millis() as u32));
        }
        other => {
            let text = other.text();
            if !text.is_empty() {
                steps.push(helpers::comment(text));
            }
        }
    }
    Ok(())
}

fn lower_telegram(
    t: &schema::Telegram,
    case_name: &str,
    profile: &Profile,
    report: &mut LowerReport,
    steps: &mut Vec<TestStep>,
) -> Result<(), LowerError> {
    let tid = || t.id.clone().unwrap_or_else(|| "(no ID)".to_string());

    if !t.is_active() {
        report.deactivated += 1;
        return Ok(());
    }
    if !profile.accepts_medium(t.medium.as_deref()) {
        *report.wrong_medium.entry(t.medium.clone().unwrap_or_default()).or_default() += 1;
        return Ok(());
    }

    let secure_attrs = t.security_attrs_set();
    if !secure_attrs.is_empty() {
        return Err(LowerError::SecureTelegram { case: case_name.to_string(), telegram: tid(), attrs: secure_attrs });
    }

    let Some(data) = t.data.as_deref().filter(|d| !d.trim().is_empty()) else {
        return Err(LowerError::MissingData { case: case_name.to_string(), telegram: tid() });
    };

    let time_to_next =
        parse_time_to_next(t.time_to_next.as_deref(), profile).ok_or_else(|| LowerError::UnknownAttribute {
            case: case_name.to_string(),
            telegram: tid(),
            attr: "TimeToNext",
            value: t.time_to_next.clone().unwrap_or_default(),
        })?;

    match t.cway.as_deref().map(str::trim) {
        Some(d) if d.eq_ignore_ascii_case("IN") => {
            // Inject with no leading delay, then honour the wait-end-time
            // flag. `Inject`'s own delay runs *before* the frame, which
            // is the wrong side of it.
            steps.push(helpers::inject(data));
            if t.waits_out_time() && time_to_next > 0 {
                steps.push(helpers::wait(time_to_next));
            }
        }
        Some(d) if d.eq_ignore_ascii_case("OUT") => {
            // `TimeToNext` is the receive window. Zero means "no
            // window specified"; the engine already substitutes a
            // second for a zero timeout.
            steps.push(helpers::expect(data, time_to_next));
            if t.waits_out_time() && time_to_next > 0 {
                // Over-waits by however long the frame took to arrive.
                // No current template needs this, so a tighter
                // implementation would be untested code.
                steps.push(helpers::wait(time_to_next));
            }
        }
        other => {
            return Err(LowerError::UnknownAttribute {
                case: case_name.to_string(),
                telegram: tid(),
                attr: "CWay",
                value: other.unwrap_or_default().to_string(),
            });
        }
    }
    Ok(())
}

// ============================================================================
// Variables and times
// ============================================================================

/// Flatten `<Fields>` blocks into the engine's variable map.
///
/// `NumberField`s marked as durations are deliberately excluded: they
/// are referenced from `TimeToNext`, not from telegram data, and
/// admitting them here would let a duration be substituted into a frame
/// as bytes.
fn collect_fields(fields: &[schema::Fields]) -> BTreeMap<String, TestVariable> {
    let mut vars = BTreeMap::new();
    for block in fields {
        for f in block.byte_fields() {
            let bytes = parse_hex(f.default_value.as_deref().unwrap_or(""));
            vars.insert(f.name.clone(), TestVariable::Bytes(bytes));
        }
        for f in block.number_fields() {
            if f.is_duration() {
                continue;
            }
            let raw = f.default_value.as_deref().unwrap_or("0");
            let value = u32::from_str_radix(raw.trim().trim_start_matches("0x"), 16).unwrap_or(0);
            // `SizeInBits` decides the width. 16 bits is two octets on
            // the wire; anything else contributes one.
            let bytes =
                if f.size_in_bits == Some(16) { vec![(value >> 8) as u8, value as u8] } else { vec![value as u8] };
            vars.insert(f.name.clone(), TestVariable::Bytes(bytes));
        }
    }
    vars
}

fn parse_hex(s: &str) -> Vec<u8> {
    s.split_whitespace().filter_map(|b| u8::from_str_radix(b, 16).ok()).collect()
}

/// Parse a `TimeToNext` value into milliseconds.
///
/// Three notations occur: a bare decimal number of seconds (`0.0`),
/// `hh:mm:ss.t`, and a `#VAR` reference to a `NumberField` whose format
/// is `TimeToNextTelegram` — those hold plain milliseconds.
fn parse_time_to_next(raw: Option<&str>, profile: &Profile) -> Option<u32> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else { return Some(0) };

    if let Some(name) = raw.strip_prefix('#') {
        // A duration variable. The profile may override it; otherwise
        // fall back to the template's own default, which the caller
        // resolved into `duration_defaults`.
        return profile
            .variables
            .get(name)
            .and_then(|v| v.trim().parse::<u32>().ok())
            .or_else(|| DURATION_DEFAULTS.with(|d| d.borrow().get(name).copied()));
    }

    if raw.contains(':') {
        let mut secs = 0f64;
        for part in raw.split(':') {
            secs = secs * 60.0 + part.trim().parse::<f64>().ok()?;
        }
        return Some((secs * 1000.0).round() as u32);
    }

    raw.parse::<f64>().ok().map(|s| (s * 1000.0).round() as u32)
}

thread_local! {
    /// Defaults for `TimeToNextTelegram` variables, keyed by name.
    ///
    /// These are referenced from an attribute rather than from telegram
    /// data, so they cannot live in the `TestVariable` map the engine
    /// resolves — that one holds byte strings. Populated by
    /// [`register_durations`] before lowering.
    static DURATION_DEFAULTS: std::cell::RefCell<BTreeMap<String, u32>> =
        std::cell::RefCell::new(BTreeMap::new());
}

/// Record the template's duration variables so `TimeToNext="#VAR"`
/// resolves. Call before [`lower`].
pub fn register_durations(template: &Template) {
    let mut map = BTreeMap::new();
    let blocks = template
        .fields
        .iter()
        .chain(template.test_collections.iter().flat_map(|c| &c.collections).flat_map(|c| &c.fields));
    for block in blocks {
        for f in block.number_fields() {
            if !f.is_duration() {
                continue;
            }
            if let Some(v) = f.default_value.as_deref().and_then(|d| d.trim().parse::<u32>().ok()) {
                map.insert(f.name.clone(), v);
            }
        }
    }
    DURATION_DEFAULTS.with(|d| *d.borrow_mut() = map);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Profile {
        toml::from_str("medium = \"tp\"").expect("profile")
    }

    #[test]
    fn time_to_next_understands_all_three_notations() {
        let p = profile();
        assert_eq!(parse_time_to_next(Some("0.0"), &p), Some(0));
        assert_eq!(parse_time_to_next(Some("2.5"), &p), Some(2500));
        assert_eq!(parse_time_to_next(Some("00:00:02.0"), &p), Some(2000));
        assert_eq!(parse_time_to_next(Some("00:01:30"), &p), Some(90_000));
        assert_eq!(parse_time_to_next(None, &p), Some(0));
    }

    #[test]
    fn an_unresolvable_variable_is_an_error_not_a_zero() {
        // Silently substituting 0 would give every expect in the case a
        // 1 s default window instead of the template's, which is the
        // sort of difference that turns into a flaky suite.
        DURATION_DEFAULTS.with(|d| d.borrow_mut().clear());
        assert_eq!(parse_time_to_next(Some("#NOPE"), &profile()), None);
    }

    #[test]
    fn duration_variables_resolve_from_the_template() {
        DURATION_DEFAULTS.with(|d| {
            d.borrow_mut().insert("GENERAL_TIME_TO_NEXT".to_string(), 500);
        });
        assert_eq!(parse_time_to_next(Some("#GENERAL_TIME_TO_NEXT"), &profile()), Some(500));
    }

    #[test]
    fn number_fields_widen_by_size_in_bits() {
        let number = |name: &str, bits: u32, default: &str, format: &str| {
            schema::Field::NumberField(schema::NumberField {
                name: name.into(),
                size_in_bits: Some(bits),
                default_value: Some(default.into()),
                format: Some(format.into()),
                display_name: None,
                min_value: None,
                max_value: None,
            })
        };
        let fields = vec![schema::Fields {
            name: None,
            fields: vec![
                number("WIDE", 16, "100", "Hex"),
                number("NARROW", 8, "2", "Hex"),
                // A duration must not become telegram bytes.
                number("TTN", 0, "500", "TimeToNextTelegram"),
            ],
        }];
        let vars = collect_fields(&fields);
        assert_eq!(vars["WIDE"].as_bytes(), vec![0x01, 0x00]);
        assert_eq!(vars["NARROW"].as_bytes(), vec![0x02]);
        assert!(!vars.contains_key("TTN"));
    }

    #[test]
    fn patch_template_names_match_by_stem() {
        assert!(file_stem_matches("KnxConformanceTestTemplate-GroupObjects", "8/3/7 - Group Object Tests"));
        assert!(!file_stem_matches("KnxConformanceTestTemplate-Management", "8/3/7 - Group Object Tests"));
    }
}
