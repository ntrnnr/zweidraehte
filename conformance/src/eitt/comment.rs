//! EITT comment commands.
//!
//! `Comment/@Text` in an EITT template is not prose — it is a small
//! command language documented in the EITT user manual §13.3.5 and
//! enumerated machine-readably in `KnxCommentCommandsScheme.xml`
//! (Version 2, 2025-06-16). Most occurrences really are documentation
//! (`@[t`, "append to trace buffer", accounts for well over 90% of all
//! comments across the templates), but a handful carry runtime
//! semantics: waiting, pausing for an operator, activating a bus
//! interface, calling another sequence, rewriting the security tables.
//!
//! We cannot ship the scheme file — it is vendor material like the
//! templates themselves — so the table below is transcribed. The unit
//! test at the bottom cross-checks it against the real file when
//! `EITT_COMMENT_SCHEME` points at one, the same optional-vendor-data
//! arrangement as `manuf_tool_data/`.
//!
//! # Why unknown text is lenient but unknown *commands* are not
//!
//! A comment that we fail to recognise as a command cannot change what
//! the test does — it was only ever going to be displayed. An
//! unimplemented command very much can: ignoring `@#` silently drops a
//! whole called sequence, ignoring `@if-` leaves us expecting traffic
//! from a link the template just took down. So [`parse`] never fails,
//! and it is the *lowering* step that refuses to continue when it meets
//! a recognised-but-unsupported command.

use core::time::Duration;

// ============================================================================
// Command model
// ============================================================================

/// A parsed `Comment/@Text`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommentCommand {
    /// No leading `@` — plain documentation.
    Plain(String),
    /// `@` / `@!` — show in the tool bar, optionally with a beep.
    Show { text: String, beep: bool },
    /// `@[t` — append to the trace buffer.
    Trace(String),
    /// `@@` / `@@!` / `@@+` — suspend until the operator acknowledges.
    Pause { text: String, kind: PauseKind },
    /// `@[w` / `@@[w` — delay for the quoted time.
    Wait { duration: Duration, text: String },
    /// `@AP"on"` / `@AP"off"` — suppress failure marking.
    AutoPass(bool),
    /// `@if+` / `@if-` — activate or deactivate a bus connection.
    Interface(InterfaceOp),
    /// `@#` / `@##` — call another telegram sequence by name.
    CallSequence { name: String, conformance: bool },
    /// `@>` / `@>w` — start a sequence in parallel, optionally joining.
    ParallelCall { name: String, loops: Option<u32>, wait: bool },
    /// `@<` — stop a parallel sequence.
    StopParallel(String),
    /// The `@@[…` security-table family.
    Security(SecurityCmd),
    /// The `@@[pah…` KNX IoT Point API family. Carried verbatim; we do
    /// not model it because we run no Point API templates.
    PointApi { command: String, args: String },
    /// Leading `@` but no recognised command. Treated as documentation
    /// — see the module docs. The template has one such typo (`@[Test`
    /// for `@[tTest`).
    Unrecognised(String),
}

/// Which flavour of operator pause a `@@`-family command asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseKind {
    /// `@@` — message box.
    Plain,
    /// `@@!` — message box with a beep.
    Beep,
    /// `@@+` — message box that also lets the operator record a BDUT
    /// error, i.e. a manual verdict.
    Verdict,
}

/// `@if+` / `@if-` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceOp {
    /// `@if+"<layer>;<connection>"` where layer is `ll`, `bm` or `rw`.
    Activate { layer: String, connection: String },
    /// `@if-"<connection>"`.
    Deactivate { connection: String },
}

/// The `@@[…` security-table family. Arguments are kept as the raw
/// semicolon-separated string: we reject these during lowering, so
/// parsing them further would be code without a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityCmd {
    /// `@@[rc` — clear the runtime challenge table.
    ClearChallenges,
    /// `@@[rn` — reset the sequence-number table.
    ResetSequenceNumbers,
    /// `@@[sk"…"` — change a key.
    SetKey(String),
    /// `@@[sn"…"` — change a sequence number.
    SetSequenceNumber(String),
    /// `@@[import"…"` — import a security configuration table.
    Import(String),
}

impl CommentCommand {
    /// The human-readable text this command carries, if any. Used to
    /// build the `Comment` step that keeps the template's narration in
    /// our output.
    pub fn text(&self) -> &str {
        match self {
            Self::Plain(t) | Self::Trace(t) | Self::Unrecognised(t) => t,
            Self::Show { text, .. } | Self::Pause { text, .. } | Self::Wait { text, .. } => text,
            _ => "",
        }
    }

    /// The command token as it appears in the template, for diagnostics.
    pub fn token(&self) -> &'static str {
        match self {
            Self::Plain(_) | Self::Unrecognised(_) => "",
            Self::Show { beep: false, .. } => "@",
            Self::Show { beep: true, .. } => "@!",
            Self::Trace(_) => "@[t",
            Self::Pause { kind: PauseKind::Plain, .. } => "@@",
            Self::Pause { kind: PauseKind::Beep, .. } => "@@!",
            Self::Pause { kind: PauseKind::Verdict, .. } => "@@+",
            Self::Wait { .. } => "@[w",
            Self::AutoPass(_) => "@AP",
            Self::Interface(InterfaceOp::Activate { .. }) => "@if+",
            Self::Interface(InterfaceOp::Deactivate { .. }) => "@if-",
            Self::CallSequence { conformance: false, .. } => "@#",
            Self::CallSequence { conformance: true, .. } => "@##",
            Self::ParallelCall { wait: false, .. } => "@>",
            Self::ParallelCall { wait: true, .. } => "@>w",
            Self::StopParallel(_) => "@<",
            Self::Security(SecurityCmd::ClearChallenges) => "@@[rc",
            Self::Security(SecurityCmd::ResetSequenceNumbers) => "@@[rn",
            Self::Security(SecurityCmd::SetKey(_)) => "@@[sk",
            Self::Security(SecurityCmd::SetSequenceNumber(_)) => "@@[sn",
            Self::Security(SecurityCmd::Import(_)) => "@@[import",
            Self::PointApi { .. } => "@@[pah",
        }
    }
}

// ============================================================================
// The command table
// ============================================================================

/// Every command token from `KnxCommentCommandsScheme.xml`, longest
/// first.
///
/// Order is load-bearing: `parse` takes the first prefix that matches,
/// so `@@[w` must be tried before `@@`, `@@!` before `@@`, and `@##`
/// before `@#`. The unit tests pin the ordering property rather than
/// the literal list, so adding a command cannot silently shadow an
/// existing one.
const COMMANDS: &[&str] = &[
    // Point API — longest tokens in the catalogue.
    "@@[pahdiscover",
    "@@[pahmcast",
    "@@[pahmdns",
    "@@[pahctx",
    "@@[pahdev",
    "@@[pahsnc",
    // Security.
    "@@[import",
    "@@[rc",
    "@@[rn",
    "@@[sk",
    "@@[sn",
    // Timing.
    "@@[w",
    "@[w",
    // Common — `@@!`/`@@+` before `@@`, `@[t` before `@`.
    "@@!",
    "@@+",
    "@@",
    "@AP",
    "@[t",
    "@!",
    // Sequence.
    "@##",
    "@#",
    "@>w",
    "@>",
    "@<",
    // Bare `@` last: it prefixes everything above.
    "@",
];

/// Interface commands are matched separately: `@if+` and `@if-` share
/// the `@if` stem, and folding them into [`COMMANDS`] would put two
/// entries in front of `@!` for no benefit.
const INTERFACE_COMMANDS: &[&str] = &["@if+", "@if-"];

// ============================================================================
// Parsing
// ============================================================================

/// Parse one `Comment/@Text`.
///
/// Never fails: text that does not look like a known command comes back
/// as [`CommentCommand::Plain`] or [`CommentCommand::Unrecognised`].
/// Rejecting unsupported commands is the lowering step's job.
pub fn parse(text: &str) -> CommentCommand {
    let trimmed = text.trim_end();
    if !trimmed.starts_with('@') {
        return CommentCommand::Plain(trimmed.trim().to_string());
    }

    for token in INTERFACE_COMMANDS {
        if let Some(rest) = trimmed.strip_prefix(token) {
            let args = strip_quoted(rest);
            return match *token {
                "@if+" => {
                    let (layer, connection) = split_once_semi(&args);
                    CommentCommand::Interface(InterfaceOp::Activate { layer, connection })
                }
                _ => CommentCommand::Interface(InterfaceOp::Deactivate { connection: args }),
            };
        }
    }

    for token in COMMANDS {
        let Some(rest) = trimmed.strip_prefix(token) else { continue };
        return build(token, rest);
    }

    CommentCommand::Unrecognised(trimmed.trim().to_string())
}

fn build(token: &str, rest: &str) -> CommentCommand {
    let body = || rest.trim().to_string();
    match token {
        "@" => CommentCommand::Show { text: body(), beep: false },
        "@!" => CommentCommand::Show { text: body(), beep: true },
        "@[t" => CommentCommand::Trace(body()),
        "@@" => CommentCommand::Pause { text: body(), kind: PauseKind::Plain },
        "@@!" => CommentCommand::Pause { text: body(), kind: PauseKind::Beep },
        "@@+" => CommentCommand::Pause { text: body(), kind: PauseKind::Verdict },

        "@[w" | "@@[w" => {
            let (quoted, tail) = take_quoted(rest);
            CommentCommand::Wait { duration: parse_wait_time(&quoted), text: tail.trim().to_string() }
        }
        "@AP" => CommentCommand::AutoPass(strip_quoted(rest).eq_ignore_ascii_case("on")),

        "@#" | "@##" => CommentCommand::CallSequence { name: strip_quoted(rest), conformance: token == "@##" },
        "@>" | "@>w" => {
            let (name, loops) = split_once_semi(&strip_quoted(rest));
            CommentCommand::ParallelCall { name, loops: loops.parse().ok(), wait: token == "@>w" }
        }
        "@<" => CommentCommand::StopParallel(strip_quoted(rest)),

        "@@[rc" => CommentCommand::Security(SecurityCmd::ClearChallenges),
        "@@[rn" => CommentCommand::Security(SecurityCmd::ResetSequenceNumbers),
        "@@[sk" => CommentCommand::Security(SecurityCmd::SetKey(strip_quoted(rest))),
        "@@[sn" => CommentCommand::Security(SecurityCmd::SetSequenceNumber(strip_quoted(rest))),
        "@@[import" => CommentCommand::Security(SecurityCmd::Import(strip_quoted(rest))),

        other if other.starts_with("@@[pah") => {
            CommentCommand::PointApi { command: other.to_string(), args: strip_quoted(rest) }
        }
        // `COMMANDS` and this match are edited together; a token in one
        // and not the other is a bug, not a template problem.
        other => unreachable!("comment command {other} is listed but not built"),
    }
}

/// Take the leading `"…"` argument, returning it and whatever follows.
///
/// Templates use both ASCII `"` and the typographic quotes Word leaves
/// behind, so all three open a quoted section.
fn take_quoted(input: &str) -> (String, &str) {
    let s = input.trim_start();
    let Some(first) = s.chars().next() else { return (String::new(), "") };
    if !is_quote(first) {
        return (String::new(), s);
    }
    let after_open = &s[first.len_utf8()..];
    match after_open.char_indices().find(|(_, c)| is_quote(*c)) {
        Some((end, c)) => (after_open[..end].to_string(), &after_open[end + c.len_utf8()..]),
        None => (after_open.to_string(), ""),
    }
}

fn strip_quoted(input: &str) -> String {
    take_quoted(input).0
}

fn is_quote(c: char) -> bool {
    matches!(c, '"' | '\u{201C}' | '\u{201D}')
}

fn split_once_semi(s: &str) -> (String, String) {
    match s.split_once(';') {
        Some((a, b)) => (a.trim().to_string(), b.trim().to_string()),
        None => (s.trim().to_string(), String::new()),
    }
}

/// Parse `hh:mm:ss` or `hh:mm:ss.t` as used by `@[w` / `@@[w`.
///
/// Anything unparseable yields a zero duration rather than an error:
/// the alternative is refusing to run a whole case over a malformed
/// comment, and a zero wait is the same thing the sequence would do if
/// the comment were absent.
fn parse_wait_time(s: &str) -> Duration {
    let mut secs = 0f64;
    for part in s.trim().split(':') {
        secs = secs * 60.0 + part.trim().parse::<f64>().unwrap_or(0.0);
    }
    Duration::from_secs_f64(secs.max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_documentation() {
        assert_eq!(
            parse("Next telegram shall be enabled."),
            CommentCommand::Plain("Next telegram shall be enabled.".into())
        );
    }

    #[test]
    fn trace_is_the_common_case() {
        assert_eq!(
            parse("@[tAcceptance: Update flag set."),
            CommentCommand::Trace("Acceptance: Update flag set.".into())
        );
    }

    #[test]
    fn longer_tokens_win_over_their_prefixes() {
        // Each of these would parse as the shorter command if the table
        // were ordered wrongly, and every one of them changes meaning:
        // a pause is not a display, a wait is not a pause.
        assert!(matches!(parse("@@!beep"), CommentCommand::Pause { kind: PauseKind::Beep, .. }));
        assert!(matches!(parse("@@+verdict"), CommentCommand::Pause { kind: PauseKind::Verdict, .. }));
        assert!(matches!(parse("@@[w\"00:00:02\""), CommentCommand::Wait { .. }));
        assert!(matches!(parse("@[w\"00:00:02\""), CommentCommand::Wait { .. }));
        assert!(matches!(parse("@[tsomething"), CommentCommand::Trace(_)));
        assert!(matches!(parse("@!beep"), CommentCommand::Show { beep: true, .. }));
        assert!(matches!(parse("@@[rn"), CommentCommand::Security(SecurityCmd::ResetSequenceNumbers)));
        assert!(matches!(parse("@##\"seq\""), CommentCommand::CallSequence { conformance: true, .. }));
        assert!(matches!(parse("@#\"seq\""), CommentCommand::CallSequence { conformance: false, .. }));
        assert!(matches!(parse("@>w\"seq;3\""), CommentCommand::ParallelCall { wait: true, .. }));
    }

    #[test]
    fn command_table_is_ordered_so_no_token_shadows_a_longer_one() {
        for (i, a) in COMMANDS.iter().enumerate() {
            for b in &COMMANDS[i + 1..] {
                assert!(!b.starts_with(*a), "{a} precedes {b} and would shadow it");
            }
        }
    }

    #[test]
    fn wait_times_parse_in_both_resolutions() {
        assert_eq!(parse_wait_time("00:00:02"), Duration::from_secs(2));
        assert_eq!(parse_wait_time("00:00:02.5"), Duration::from_millis(2500));
        assert_eq!(parse_wait_time("00:01:30"), Duration::from_secs(90));
        assert_eq!(parse_wait_time("01:00:00"), Duration::from_secs(3600));
        // Malformed input must not panic.
        assert_eq!(parse_wait_time("nonsense"), Duration::ZERO);
    }

    #[test]
    fn wait_carries_its_trailing_comment() {
        let CommentCommand::Wait { duration, text } = parse("@[w\"00:00:05\"settle time") else {
            panic!("expected a wait");
        };
        assert_eq!(duration, Duration::from_secs(5));
        assert_eq!(text, "settle time");
    }

    #[test]
    fn typographic_quotes_are_accepted() {
        // The templates are authored in Word; `@if+` in particular
        // appears with curly quotes in the manual and in several
        // templates.
        assert_eq!(
            parse("@if+\u{201C}ll;usb\u{201D}"),
            CommentCommand::Interface(InterfaceOp::Activate { layer: "ll".into(), connection: "usb".into() })
        );
        assert_eq!(
            parse("@if-\u{201C}usb\u{201D}"),
            CommentCommand::Interface(InterfaceOp::Deactivate { connection: "usb".into() })
        );
    }

    #[test]
    fn auto_pass_reads_its_argument() {
        assert_eq!(parse("@AP\"on\""), CommentCommand::AutoPass(true));
        assert_eq!(parse("@AP\"off\""), CommentCommand::AutoPass(false));
    }

    #[test]
    fn a_typo_degrades_to_a_display_not_an_error() {
        // The GroupObjects template contains `@[Test…`, a typo for
        // `@[tTest…`. It must not stop the run.
        assert!(matches!(parse("@[Test"), CommentCommand::Show { .. }));
    }

    /// Cross-check the transcribed table against the vendor scheme file
    /// when one is available. Set `EITT_COMMENT_SCHEME` to the path of
    /// `KnxCommentCommandsScheme.xml`; without it the test is a no-op,
    /// because the file is licensed material we neither ship nor
    /// require.
    #[test]
    fn table_covers_the_vendor_scheme_when_present() {
        let Ok(path) = std::env::var("EITT_COMMENT_SCHEME") else { return };
        let xml = std::fs::read_to_string(&path).expect("read EITT_COMMENT_SCHEME");
        let mut missing = Vec::new();
        for chunk in xml.split("<CommentCommand").skip(1) {
            let Some(rest) = chunk.split_once("Command=\"") else { continue };
            let Some((raw, _)) = rest.1.split_once('"') else { continue };
            // `@>`, `@>w` and `@<` are stored as XML entities.
            let cmd = raw.replace("&gt;", ">").replace("&lt;", "<").replace("&amp;", "&");
            let known = COMMANDS.contains(&cmd.as_str())
                || INTERFACE_COMMANDS.contains(&cmd.as_str())
                || cmd.starts_with("@@[pah");
            if !known {
                missing.push(cmd);
            }
        }
        assert!(missing.is_empty(), "comment commands missing from our table: {missing:?}");
    }
}
