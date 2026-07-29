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
    /// Comment commands ignored under an `ignore` policy, counted by
    /// the text they were written as. The transport-layer template
    /// alone has 22 interface commands, and 22 identical lines say less
    /// than one line with a count.
    pub ignored_commands: BTreeMap<String, usize>,
    /// Attributes we model and then deliberately do not act on,
    /// counted per attribute. Reported so that "decided to ignore" and
    /// "never noticed" stay distinguishable.
    pub ignored_attrs: BTreeMap<&'static str, usize>,
    /// Patches that applied, by reason.
    pub applied_patches: Vec<String>,
    /// Exceptions the profile made for this template.
    pub overrides: Vec<String>,
}

impl LowerReport {
    /// Print the report. Silent sections are omitted; a run with
    /// nothing to report prints nothing.
    pub fn print(&self) {
        for why in &self.overrides {
            println!("  ⚑ {why}");
        }
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
        for (cmd, count) in &self.ignored_commands {
            println!("  ⏸ ignored {count}× comment command: {cmd}");
        }
        for (attr, count) in &self.ignored_attrs {
            let why = IGNORED_ATTR_REASONS.iter().find(|(a, _)| a == attr).map_or("no reason on record", |(_, w)| *w);
            println!("  · {count} telegram(s): ignored {attr} — {why}");
        }
    }
}

/// Why each modelled-but-unused telegram attribute is safe to ignore
/// *for us*. Kept next to the report rather than at the use site so a
/// run states the reasoning out loud instead of leaving it in a
/// comment nobody reads.
const IGNORED_ATTR_REASONS: &[(&str, &str)] = &[
    (
        "Connection",
        "we drive one mock link layer that models no L2 acknowledgement, so \
         there is no second tool interface to switch between; the two tool \
         addresses are already distinguished by the source address in Data",
    ),
    (
        "RFInfo",
        "RFInfo/RFInfoEval/RFSerial/LFN are cEMI additional info (EITT manual \
         12.12.1, 'Add Info 0 (RF info) on Req'), which we do not model, and \
         they are not a medium declaration — EITT takes the medium from the \
         interface the telegram goes out on, configured per bus connection, \
         which for us is the profile's `medium`. A telegram carrying them is \
         therefore sent exactly as its Data says",
    ),
];

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
    /// A `TLSeqNum` we cannot apply to the telegram's `Data`.
    TlSeqNum { case: String, telegram: String, why: String },
    /// A `@[w` argument that is neither a literal time nor a duration
    /// variable we can resolve.
    UnresolvedDuration { case: String, raw: String },
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
            Self::TlSeqNum { case, telegram, why } => {
                write!(f, "{case}: telegram {telegram} has a TLSeqNum this lowerer cannot apply: {why}")
            }
            Self::UnresolvedDuration { case, raw } => write!(
                f,
                "{case}: the wait command asks for {raw:?}, which is neither a time nor a duration \
                 variable this template declares — running it as a zero wait would quietly change \
                 what the case proves"
            ),
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

    let mut report = LowerReport { overrides: profile.applied_overrides.clone(), ..Default::default() };
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

                let steps =
                    lower_sequence(case, &case_name, profile, &vars, &by_anchor, &mut used_anchors, &mut report)?;
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

/// A `TimeToNext` below this is "no gap": EITT manual §12.2.3.6,
/// "intervals below 0.2 seconds are treated as zero". It is what makes
/// consecutive telegrams one block.
const BLOCK_JOIN_MS: u32 = 200;

/// One `OUT` telegram waiting to be flushed, alone or as part of a
/// block. See [`flush_block`].
struct BlockMember {
    /// The frame template, `#VAR` references intact.
    data: String,
    /// The receive window this member contributes if it closes the block.
    time_to_next: u32,
    waits_out_time: bool,
}

/// Emit the pending `OUT` telegrams and clear the buffer.
///
/// A single member stays a plain `Expect`: that is what most of a
/// template is, and it keeps the run log readable. Two or more become
/// one any-order `ExpectBlock` whose window is the *closing* member's
/// `TimeToNext` — which is the whole point of blocks. EITT gives a
/// block one window rather than one per telegram (§12.2.3.6), and the
/// transport-layer repetition cases lean on it: 6.3.5.2 expects three
/// identical retransmissions and a disconnect inside 12.5 s, arriving
/// roughly 3 s apart. Timed individually, the second one would run into
/// the engine's 1 s default and fail on a harness artefact.
fn flush_block(block: &mut Vec<BlockMember>, steps: &mut Vec<TestStep>) {
    let Some(last) = block.last() else { return };
    let timeout_ms = last.time_to_next;
    let waits_out_time = last.waits_out_time;

    if let [only] = block.as_slice() {
        steps.push(helpers::expect(&only.data, timeout_ms));
    } else {
        let elements = block.iter().map(|m| helpers::block_plain(&m.data)).collect();
        steps.push(helpers::expect_block(elements, timeout_ms));
    }

    // Only the closing member's wait-end-time flag can mean anything:
    // the others have no gap left to wait out, by construction.
    if waits_out_time && timeout_ms > 0 {
        steps.push(helpers::wait(timeout_ms));
    }
    block.clear();
}

fn lower_sequence(
    case: &schema::TestCase,
    case_name: &str,
    profile: &Profile,
    vars: &BTreeMap<String, TestVariable>,
    by_anchor: &BTreeMap<String, Vec<(&crate::eitt::patch::Patch, Anchor)>>,
    used_anchors: &mut Vec<String>,
    report: &mut LowerReport,
) -> Result<Vec<TestStep>, LowerError> {
    let mut steps = Vec::new();
    let mut block: Vec<BlockMember> = Vec::new();
    // Fresh per case: a case that forgets to disconnect must not leave
    // the next one numbering from the middle.
    let mut tl_sequence = profile.recompute_tl_sequence.then(TlSequence::default);
    let Some(sequence) = &case.sequence else { return Ok(steps) };

    for item in &sequence.items {
        let id_key = item.id().map(|i| i.to_ascii_uppercase());
        let anchored = id_key.as_ref().and_then(|k| by_anchor.get(k)).map(|v| v.as_slice()).unwrap_or(&[]);
        if !anchored.is_empty() {
            used_anchors.push(id_key.clone().unwrap_or_default());
            // Patched steps have to land exactly where the template puts
            // them, so an anchor closes the pending block instead of
            // letting a `before` insert drift behind telegrams that
            // syntactically precede it. No current patch anchors inside
            // a block, so this costs nothing today.
            flush_block(&mut block, &mut steps);
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
                    let text = c.text.as_deref().unwrap_or("");
                    lower_comment(text, case_name, profile, report, &mut block, &mut steps)?;
                }
                SequenceItem::Telegram(t) => {
                    let ctx = TelegramCtx {
                        case_name,
                        profile,
                        vars,
                        joinable: anchored.is_empty(),
                        tl_sequence: tl_sequence.as_mut(),
                    };
                    lower_telegram(t, ctx, report, &mut block, &mut steps)?;
                }
            }
        }

        if let Some((patch, _)) = has(Anchor::After) {
            report.applied_patches.push(patch.why.clone());
            steps.extend(patch.insert.iter().map(|s| s.to_step()));
        }
    }

    flush_block(&mut block, &mut steps);
    Ok(steps)
}

fn lower_comment(
    text: &str,
    case_name: &str,
    profile: &Profile,
    report: &mut LowerReport,
    block: &mut Vec<BlockMember>,
    steps: &mut Vec<TestStep>,
) -> Result<(), LowerError> {
    // Lower into a scratch buffer first. The templates annotate the
    // middle of a block freely — "---> BDUT sends repetition every 3
    // seconds" sits between two of the telegrams it describes — so pure
    // narration has to be transparent to a pending block, or every
    // block would be cut into pieces of one. Anything that actually
    // does something, above all a `@[w` wait, must happen after the
    // block it follows instead.
    let mut emitted = Vec::new();
    lower_comment_steps(text, case_name, profile, report, &mut emitted)?;
    if emitted.iter().any(|s| !matches!(s, TestStep::Comment(_))) {
        flush_block(block, steps);
    }
    steps.extend(emitted);
    Ok(())
}

fn lower_comment_steps(
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
            let note = format!("{} (auto-pass is not implemented; we stay strict)", cmd.token());
            *report.ignored_commands.entry(note).or_default() += 1;
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
        // Keyed on the raw text, not on `cmd.text()`: the commands that
        // get ignored are the ones whose payload is an argument rather
        // than prose, and `@if-` on its own says nothing about which
        // interface it was.
        *report.ignored_commands.entry(text.trim().to_string()).or_default() += 1;
        if !cmd.text().is_empty() {
            steps.push(helpers::comment(cmd.text()));
        }
        return Ok(());
    }

    match cmd {
        CommentCommand::Wait { duration, raw, text } => {
            // A literal `hh:mm:ss` parses on its own; `#WAIT` is one of
            // the template's `TimeToNextTelegram` variables and resolves
            // the same way a telegram's `TimeToNext="#VAR"` does.
            let ms = match duration {
                Some(d) => d.as_millis() as u32,
                None => resolve_duration(&raw, profile)
                    .ok_or_else(|| LowerError::UnresolvedDuration { case: case_name.to_string(), raw: raw.clone() })?,
            };
            if !text.is_empty() {
                steps.push(helpers::comment(&text));
            }
            steps.push(helpers::wait(ms));
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

/// What lowering one telegram needs beyond the telegram itself.
struct TelegramCtx<'a> {
    case_name: &'a str,
    profile: &'a Profile,
    vars: &'a BTreeMap<String, TestVariable>,
    /// Whether this telegram may join a pending block. A patch anchored
    /// on it says no — see [`lower_sequence`].
    joinable: bool,
    /// The running numbering, when this template's own is not believed.
    tl_sequence: Option<&'a mut TlSequence>,
}

fn lower_telegram(
    t: &schema::Telegram,
    ctx: TelegramCtx<'_>,
    report: &mut LowerReport,
    block: &mut Vec<BlockMember>,
    steps: &mut Vec<TestStep>,
) -> Result<(), LowerError> {
    let TelegramCtx { case_name, profile, vars, joinable, tl_sequence } = ctx;
    let tid = || t.id.clone().unwrap_or_else(|| "(no ID)".to_string());

    if !t.is_active() {
        report.deactivated += 1;
        return Ok(());
    }

    // `Medium` is the telegram saying which bus it belongs on, and it is
    // an either/or: every `rf` telegram in the templates we run has a
    // `tp` twin in the same case (group objects 1.4.1.7 carries 54 of
    // each, transport layer 2.5 carries 29). Running both halves against
    // a single-medium device tests the same thing twice, once wrongly.
    let declared = t.medium.as_deref().map(str::trim).filter(|m| !m.is_empty());
    if !profile.accepts_medium(declared) {
        *report.wrong_medium.entry(declared.unwrap_or_default().to_string()).or_default() += 1;
        return Ok(());
    }

    // Deliberately *not* a second source of medium: see the reason in
    // `IGNORED_ATTR_REASONS`.
    if !t.rf_attrs_set().is_empty() {
        *report.ignored_attrs.entry("RFInfo").or_default() += 1;
    }

    if t.connection.as_deref().is_some_and(|c| !c.trim().is_empty()) {
        *report.ignored_attrs.entry("Connection").or_default() += 1;
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

    let waits_out_time = t.wait_flag().ok_or_else(|| LowerError::UnknownAttribute {
        case: case_name.to_string(),
        telegram: tid(),
        attr: "Wait",
        value: t.wait.clone().unwrap_or_default(),
    })?;

    let cway = t.cway.as_deref().map(str::trim);
    let inbound = cway.is_some_and(|d| d.eq_ignore_ascii_case("IN"));
    let pinned = t.tl_seq_num.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let data = apply_tl_sequence(data, pinned, tl_sequence, inbound, vars).map_err(|why| LowerError::TlSeqNum {
        case: case_name.to_string(),
        telegram: tid(),
        why,
    })?;

    match cway {
        Some(d) if d.eq_ignore_ascii_case("IN") => {
            // Anything we send closes a pending block: the frames before
            // it have to have arrived first.
            flush_block(block, steps);
            // Inject with no leading delay, then honour the wait-end-time
            // flag. `Inject`'s own delay runs *before* the frame, which
            // is the wrong side of it.
            steps.push(helpers::inject(&data));
            if waits_out_time && time_to_next > 0 {
                steps.push(helpers::wait(time_to_next));
            }
        }
        Some(d) if d.eq_ignore_ascii_case("OUT") => {
            // `TimeToNext` is the receive window. Zero means "no window
            // specified"; the engine substitutes a second for a zero
            // timeout. It also decides whether this telegram closes the
            // block it just joined — see `flush_block`.
            if !joinable {
                steps.push(helpers::expect(&data, time_to_next));
                if waits_out_time && time_to_next > 0 {
                    steps.push(helpers::wait(time_to_next));
                }
            } else {
                block.push(BlockMember { data, time_to_next, waits_out_time });
                if time_to_next >= BLOCK_JOIN_MS {
                    flush_block(block, steps);
                }
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
// Transport-layer sequence numbers
// ============================================================================

/// EITT's running transport-layer sequence numbers within one test case.
///
/// EITT computes a sequence number for every management telegram before
/// running a sequence, unless the telegram pins one (manual §12.2.3.14,
/// recorded in the XML as `TLSeqNum` — §15.6). So the numbers a
/// template's `Data` carries are whatever its author last typed, and
/// whether they can be believed is a per-template question the profile
/// answers; see [`crate::eitt::profile::TlSequencePolicy`].
///
/// The two counters are the connection's, per 03/03/04 §5.4: `send` is
/// SeqNoSend for the telegrams we transmit, `recv` is SeqNoRcv for the
/// ones we expect. They advance on the acknowledgement rather than on
/// the data, which is what makes a request and its response carry the
/// same number.
#[derive(Debug, Default, Clone, Copy)]
struct TlSequence {
    send: u8,
    recv: u8,
}

impl TlSequence {
    /// Number one telegram and advance, given its TPCI and direction.
    ///
    /// `None` for a telegram that carries no sequence number — an
    /// unnumbered data packet, or a connect/disconnect, which also
    /// restarts the numbering.
    fn number(&mut self, tpci: u8, inbound: bool) -> Option<u8> {
        match tpci & 0xC0 {
            // T_Connect / T_Disconnect: a fresh connection numbers from
            // zero in both directions, and the control PDU itself has a
            // sequence number of zero by definition.
            0x80 => {
                *self = Self::default();
                None
            }
            // Numbered data: ours goes out under SeqNoSend, theirs is
            // expected under SeqNoRcv.
            0x40 => Some(if inbound { self.send } else { self.recv }),
            // Numbered control, i.e. an acknowledgement. It carries the
            // number of the data packet it answers, and completes it.
            0xC0 => {
                let seq = if inbound { self.recv } else { self.send };
                if inbound {
                    self.recv = (self.recv + 1) & 0x0F;
                } else {
                    self.send = (self.send + 1) & 0x0F;
                }
                Some(seq)
            }
            _ => None,
        }
    }
}

/// Where a telegram's TPCI octet is and what it holds.
struct Tpci {
    tokens: Vec<String>,
    index: usize,
    value: u8,
}

/// Find the TPCI octet in a `Data` string.
///
/// `Ok(None)` when there is no literal octet to work with — a `??`
/// wildcard, or a variable spanning the position. The caller decides
/// whether that is fine (the running numbering just skips it) or an
/// error (a `TLSeqNum` naming an octet we cannot write).
fn locate_tpci(data: &str, vars: &BTreeMap<String, TestVariable>) -> Result<Option<Tpci>, String> {
    let tokens: Vec<String> = data.split_whitespace().map(str::to_string).collect();

    // The control field decides the frame layout, and only the standard
    // one puts TPCI at octet 6. Refusing the extended layout is not a
    // limitation we have hit — every telegram in these templates is
    // standard — it is a guard against reading the wrong octet.
    let ctrl = tokens.first().and_then(|t| u8::from_str_radix(t, 16).ok());
    match ctrl {
        Some(c) if c & 0x80 != 0 => {}
        Some(c) => return Err(format!("control field {c:#04X} is an extended frame, whose TPCI is elsewhere")),
        None => return Ok(None),
    }

    const TPCI_OFFSET: usize = 6;
    let mut offset = 0usize;
    let Some(index) = tokens.iter().position(|tok| {
        let width = token_width(tok, vars);
        let covers = (offset..offset + width).contains(&TPCI_OFFSET);
        offset += width;
        covers
    }) else {
        return Ok(None);
    };

    match u8::from_str_radix(&tokens[index], 16) {
        Ok(value) => Ok(Some(Tpci { tokens, index, value })),
        Err(_) => Ok(None),
    }
}

/// Put `seq` in the TPCI octet's four sequence-number bits.
fn write_seq(mut tpci: Tpci, seq: u8) -> String {
    tpci.tokens[tpci.index] = format!("{:02X}", (tpci.value & !0x3C) | ((seq & 0x0F) << 2));
    tpci.tokens.join(" ")
}

/// Settle a telegram's transport-layer sequence number.
///
/// Three things can decide it, in order: a `TLSeqNum` pin always wins;
/// otherwise the running numbering when the profile says this
/// template's own numbers cannot be believed; otherwise the literal in
/// `Data` stands. A pinned telegram deliberately does not advance the
/// counters — pinning is how a template writes a number that the
/// running sequence would not have produced.
fn apply_tl_sequence(
    data: &str,
    pinned: Option<&str>,
    tracker: Option<&mut TlSequence>,
    inbound: bool,
    vars: &BTreeMap<String, TestVariable>,
) -> Result<String, String> {
    let Some(raw) = pinned else {
        let Some(tracker) = tracker else { return Ok(data.to_string()) };
        let Some(tpci) = locate_tpci(data, vars)? else { return Ok(data.to_string()) };
        return Ok(match tracker.number(tpci.value, inbound) {
            Some(seq) => write_seq(tpci, seq),
            None => data.to_string(),
        });
    };

    let seq: u8 = raw.parse().map_err(|_| format!("{raw:?} is not a number"))?;
    if seq > 0x0F {
        return Err(format!("{seq} does not fit in the four sequence-number bits"));
    }
    let tpci =
        locate_tpci(data, vars)?.ok_or_else(|| format!("{data:?} has no literal TPCI octet to write {seq} into"))?;

    // Only numbered data and numbered control carry a sequence number;
    // a template asking us to put one anywhere else means we have
    // misread which octet is the TPCI.
    if !matches!(tpci.value & 0xC0, 0x40 | 0xC0) {
        return Err(format!("TPCI {:#04X} is unnumbered, so it has no sequence number to fix", tpci.value));
    }
    Ok(write_seq(tpci, seq))
}

/// How many octets a `Data` token contributes to the frame.
///
/// Mirrors the expression grammar in [`crate::telegram`]: a bare `#VAR`
/// and an offset `#VAR±N` are as wide as the variable, an indexed
/// `#VAR.N` picks a single octet out of it, and everything else — a hex
/// literal or a `??` wildcard — is one.
fn token_width(token: &str, vars: &BTreeMap<String, TestVariable>) -> usize {
    let Some(expr) = token.strip_prefix('#') else { return 1 };
    let name = expr.split(['.', '+', '-']).next().unwrap_or(expr);
    if expr[name.len()..].starts_with('.') {
        return 1;
    }
    vars.get(name).map_or(1, |v| v.as_bytes().len())
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

    if raw.starts_with('#') {
        return resolve_duration(raw, profile);
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

/// Resolve a `#VAR` duration reference to milliseconds.
///
/// The profile may override it; otherwise the template's own
/// `TimeToNextTelegram` default applies, which [`register_durations`]
/// put into `DURATION_DEFAULTS`. Both `TimeToNext="#VAR"` on a telegram
/// and `@[w"#VAR"` in a comment come through here, so the two cannot
/// drift apart.
fn resolve_duration(raw: &str, profile: &Profile) -> Option<u32> {
    let name = raw.trim().strip_prefix('#')?;
    profile
        .variables
        .get(name)
        .and_then(|v| v.trim().parse::<u32>().ok())
        .or_else(|| DURATION_DEFAULTS.with(|d| d.borrow().get(name).copied()))
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

    // ------------------------------------------------------------------
    // Block lowering
    // ------------------------------------------------------------------

    fn telegram(cway: &str, data: &str, time_to_next: &str) -> SequenceItem {
        SequenceItem::Telegram(schema::Telegram {
            data: Some(data.into()),
            cway: Some(cway.into()),
            time_to_next: Some(time_to_next.into()),
            ..Default::default()
        })
    }

    fn comment_item(text: &str) -> SequenceItem {
        SequenceItem::Comment(schema::Comment { id: None, text: Some(text.into()) })
    }

    fn lower_items(items: Vec<SequenceItem>) -> Vec<TestStep> {
        let case = schema::TestCase { id: None, name: Some("case".into()), sequence: Some(schema::Sequence { items }) };
        let vars = BTreeMap::new();
        let mut report = LowerReport::default();
        lower_sequence(&case, "case", &profile(), &vars, &BTreeMap::new(), &mut Vec::new(), &mut report)
            .expect("lowering")
    }

    #[test]
    fn consecutive_expects_become_one_any_order_block() {
        // The shape transport-layer 6.3.5.2 relies on: three
        // retransmissions and a disconnect, timed as one 12.5 s window.
        let steps = lower_items(vec![
            telegram("OUT", "B0 11 22 33 44 63 43 40", "0.0"),
            telegram("OUT", "B0 11 22 33 44 63 43 40", "0.0"),
            telegram("OUT", "B0 11 22 33 44 60 81", "00:00:12.5"),
        ]);
        match steps.as_slice() {
            [TestStep::ExpectBlockTemplate { templates, timeout_ms }] => {
                assert_eq!(templates.len(), 3);
                assert_eq!(*timeout_ms, 12_500);
            }
            other => panic!("expected one block, got {other:#?}"),
        }
    }

    #[test]
    fn a_lone_expect_stays_a_plain_expect() {
        let steps = lower_items(vec![telegram("OUT", "B0 11 22 33 44 60 C2", "0.5")]);
        assert!(matches!(steps.as_slice(), [TestStep::ExpectTemplate { timeout_ms: 500, .. }]), "{steps:#?}");
    }

    #[test]
    fn an_inject_closes_the_block_before_it() {
        // We cannot send until what precedes it has arrived, so the two
        // expects flush with the second one's window.
        let steps = lower_items(vec![
            telegram("OUT", "B0 11 22 33 44 60 C2", "0.0"),
            telegram("OUT", "B0 11 22 33 44 63 43 40", "0.0"),
            telegram("IN", "B0 55 66 33 44 60 81", "0.2"),
        ]);
        assert!(
            matches!(steps.as_slice(), [TestStep::ExpectBlockTemplate { .. }, TestStep::InjectTemplate { .. }]),
            "{steps:#?}"
        );
    }

    #[test]
    fn narration_does_not_cut_a_block_in_half() {
        // The templates annotate the middle of a block freely. Letting a
        // trace comment close it would give the second half the engine's
        // 1 s default window instead of the template's.
        let steps = lower_items(vec![
            telegram("OUT", "B0 11 22 33 44 63 43 40", "0.0"),
            comment_item("@[tBDUT repeats the response every 3 seconds."),
            telegram("OUT", "B0 11 22 33 44 63 43 40", "00:00:03.2"),
        ]);
        match steps.as_slice() {
            [TestStep::Comment(_), TestStep::ExpectBlockTemplate { templates, timeout_ms }] => {
                assert_eq!(templates.len(), 2);
                assert_eq!(*timeout_ms, 3200);
            }
            other => panic!("expected narration then one block, got {other:#?}"),
        }
    }

    #[test]
    fn a_wait_comment_does_cut_a_block() {
        let steps = lower_items(vec![
            telegram("OUT", "B0 11 22 33 44 63 43 40", "0.0"),
            comment_item("@[w\"00:00:05\""),
            telegram("OUT", "B0 11 22 33 44 60 81", "00:00:01.2"),
        ]);
        assert!(
            matches!(steps.as_slice(), [
                TestStep::ExpectTemplate { .. },
                TestStep::Wait { .. },
                TestStep::ExpectTemplate { .. }
            ]),
            "{steps:#?}"
        );
    }

    #[test]
    fn an_unknown_wait_flag_is_an_error() {
        let case = schema::TestCase {
            id: None,
            name: Some("case".into()),
            sequence: Some(schema::Sequence {
                items: vec![SequenceItem::Telegram(schema::Telegram {
                    data: Some("B0 11 22 33 44 60 C2".into()),
                    cway: Some("OUT".into()),
                    time_to_next: Some("0.5".into()),
                    wait: Some("maybe".into()),
                    ..Default::default()
                })],
            }),
        };
        let err = lower_sequence(
            &case,
            "case",
            &profile(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &mut Vec::new(),
            &mut LowerReport::default(),
        )
        .expect_err("an unrecognised Wait must not read as \"no\"");
        assert!(matches!(err, LowerError::UnknownAttribute { attr: "Wait", .. }), "{err}");
    }

    // ------------------------------------------------------------------
    // Fixed transport-layer sequence numbers
    // ------------------------------------------------------------------

    fn addr_vars() -> BTreeMap<String, TestVariable> {
        BTreeMap::from([
            ("EDI".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE])),
            ("BDUT".to_string(), TestVariable::Bytes(vec![0x10, 0x01])),
        ])
    }

    fn pin(data: &str, seq: &str) -> Result<String, String> {
        apply_tl_sequence(data, Some(seq), None, true, &addr_vars())
    }

    #[test]
    fn tl_seq_num_finds_the_tpci_octet_past_two_byte_variables() {
        // `#EDI` and `#BDUT` are two octets each, so the TPCI is the
        // fifth *token* but the seventh octet. Pinning it to what it
        // already carries must leave the frame alone.
        let data = "B0 #EDI #BDUT 61 47 00";
        assert_eq!(pin(data, "1").expect("applies"), data);
    }

    #[test]
    fn tl_seq_num_rewrites_only_the_sequence_bits() {
        // T_ACK sequence 0 (0xC2) pinned to 5 becomes 0xD6: the two type
        // bits and the two below the sequence field must survive.
        assert_eq!(pin("B0 #EDI #BDUT 60 C2", "5").expect("applies"), "B0 #EDI #BDUT 60 D6");
    }

    #[test]
    fn tl_seq_num_on_an_unnumbered_tpci_is_an_error() {
        // TPCI 0x00 is T_Data_Group: no sequence number exists there, so
        // being asked to fix one means we have misread the frame.
        let err = pin("BC #EDI #BDUT E2 00 80 DF", "0").expect_err("unnumbered");
        assert!(err.contains("unnumbered"), "{err}");
    }

    #[test]
    fn tl_seq_num_refuses_an_extended_frame() {
        let err = pin("3C E0 #EDI #BDUT 01 40 80", "0").expect_err("extended");
        assert!(err.contains("extended frame"), "{err}");
    }

    #[test]
    fn tl_seq_num_refuses_a_tpci_hidden_inside_a_variable() {
        let vars = BTreeMap::from([("WHOLE".to_string(), TestVariable::Bytes(vec![0; 8]))]);
        let err = apply_tl_sequence("B0 #WHOLE", Some("0"), None, true, &vars).expect_err("no literal TPCI");
        assert!(err.contains("no literal TPCI octet"), "{err}");
    }

    #[test]
    fn the_running_numbering_reproduces_a_request_response_exchange() {
        // The shape every load-state-machine case opens with. The
        // template's own numbers here are 47 / C2 / 47 / C2 — the data
        // packets stale from an earlier revision — and recomputing
        // gives what the hand-written transcription renumbered them to.
        let mut tl = TlSequence::default();
        let vars = addr_vars();
        let mut go =
            |data: &str, inbound: bool| apply_tl_sequence(data, None, Some(&mut tl), inbound, &vars).expect("numbers");
        assert_eq!(go("B0 #EDI #BDUT 60 80", true), "B0 #EDI #BDUT 60 80");
        assert_eq!(go("BC #EDI #BDUT 6F 47 D7 02", true), "BC #EDI #BDUT 6F 43 D7 02");
        assert_eq!(go("B0 #BDUT #EDI 60 C2", false), "B0 #BDUT #EDI 60 C2");
        assert_eq!(go("BC #BDUT #EDI 66 47 D6 02", false), "BC #BDUT #EDI 66 43 D6 02");
        assert_eq!(go("B0 #EDI #BDUT 60 C2", true), "B0 #EDI #BDUT 60 C2");
        // Second exchange on the same connection, now numbered one.
        assert_eq!(go("BC #EDI #BDUT 6F 4B D7 02", true), "BC #EDI #BDUT 6F 47 D7 02");
        assert_eq!(go("B0 #BDUT #EDI 60 C6", false), "B0 #BDUT #EDI 60 C6");
        assert_eq!(go("BC #BDUT #EDI 66 4B D6 02", false), "BC #BDUT #EDI 66 47 D6 02");
        assert_eq!(go("B0 #EDI #BDUT 60 C6", true), "B0 #EDI #BDUT 60 C6");
    }

    #[test]
    fn a_new_connection_restarts_the_numbering() {
        let mut tl = TlSequence::default();
        let vars = addr_vars();
        let mut go =
            |data: &str, inbound: bool| apply_tl_sequence(data, None, Some(&mut tl), inbound, &vars).expect("numbers");
        go("BC #EDI #BDUT 6F 43 D7 02", true);
        go("B0 #BDUT #EDI 60 C2", false);
        go("B0 #EDI #BDUT 60 81", true);
        // Back to zero, not to one.
        assert_eq!(go("BC #EDI #BDUT 6F 4B D7 02", true), "BC #EDI #BDUT 6F 43 D7 02");
    }

    #[test]
    fn a_pinned_number_survives_the_running_numbering() {
        // Pinning is how a template writes a number the running
        // sequence would not have produced, so it must win and must not
        // move the counters on.
        let mut tl = TlSequence::default();
        let vars = addr_vars();
        let out = apply_tl_sequence("B0 #EDI #BDUT 61 43 00", Some("5"), Some(&mut tl), true, &vars).expect("pinned");
        assert_eq!(out, "B0 #EDI #BDUT 61 57 00");
        let next = apply_tl_sequence("B0 #EDI #BDUT 61 43 00", None, Some(&mut tl), true, &vars).expect("numbers");
        assert_eq!(next, "B0 #EDI #BDUT 61 43 00");
    }
}
