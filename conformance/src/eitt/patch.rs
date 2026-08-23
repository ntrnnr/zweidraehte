//! Patch sets: harness-specific edits overlaid on a vendor template.
//!
//! Some things EITT assumes are simply not true of our stack. The
//! clearest case: EITT drives a BCU whose Group Object Server transmits
//! by itself when the application sets the request flag, so 1.4.1.1
//! writes the flag and then waits for a telegram. Ours separates
//! communication object state from bus operations, and the send has to
//! be kicked. Editing the vendor XML to say so would make it ours, and
//! the next revision would silently drop the edit.
//!
//! A patch set instead names the GUID of the telegram to hang off:
//!
//! ```toml
//! template = "KnxConformanceTestTemplate-GroupObjects"
//!
//! [[patch]]
//! after = "1114B318-ED15-44F5-A6D9-3B257518CCC2"
//! why   = "our stack does not auto-transmit on a comm-flag write"
//! insert = [{ trigger_read = 1 }]
//! ```
//!
//! An anchor that no longer resolves is an error rather than a
//! warning. A patch that quietly stops applying is worse than no patch:
//! the case still runs, still reports, and no longer tests what the
//! patch was there to make testable.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::TestStep;
use crate::tests::helpers;

/// A loaded patch set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchSet {
    /// Which template this is for. Checked against the template's own
    /// name so a patch set cannot be applied to the wrong file.
    pub template: String,
    /// Ordered list of edits.
    #[serde(default, rename = "patch")]
    pub patches: Vec<Patch>,
}

/// One edit, anchored on a GUID.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    /// Insert after this Telegram or Comment.
    #[serde(default)]
    pub after: Option<String>,
    /// Insert before this Telegram or Comment.
    #[serde(default)]
    pub before: Option<String>,
    /// Replace this Telegram or Comment with `insert`.
    #[serde(default)]
    pub replace: Option<String>,
    /// Drop this Telegram or Comment.
    #[serde(default)]
    pub skip: Option<String>,
    /// Drop a whole TestCase. Prefer `not_applicable` in the profile
    /// when the case simply does not apply to the device; use this when
    /// the reason is about the harness.
    #[serde(default)]
    pub skip_case: Option<String>,
    /// Drop an inclusive range of sequence items. This is for a
    /// profile-specific subsection inside an otherwise applicable case;
    /// both endpoints remain stable GUID anchors and are validated.
    #[serde(default)]
    pub skip_range: Option<SkipRange>,
    /// Run this Telegram exactly as written, but do not let it advance
    /// EITT's recomputed transport sequence. Used when the device drops a
    /// frame before TL while the template also describes an alternative in
    /// which the same frame reaches TL.
    #[serde(default)]
    pub without_tl_sequence: Option<String>,
    /// Why. Printed with the applied-patch report.
    pub why: String,
    /// Steps to insert. Required by `after` / `before` / `replace`.
    #[serde(default)]
    pub insert: Vec<InsertStep>,
}

impl Patch {
    /// The GUID this patch anchors on, and what it does there.
    pub fn anchor(&self) -> Result<(&str, Anchor), PatchError> {
        let candidates = [
            (self.after.as_deref(), Anchor::After),
            (self.before.as_deref(), Anchor::Before),
            (self.replace.as_deref(), Anchor::Replace),
            (self.skip.as_deref(), Anchor::Skip),
            (self.skip_case.as_deref(), Anchor::SkipCase),
            (self.skip_range.as_ref().map(|range| range.from.as_str()), Anchor::SkipRange),
            (self.without_tl_sequence.as_deref(), Anchor::WithoutTlSequence),
        ];
        let mut found = candidates.iter().filter_map(|(id, kind)| id.map(|i| (i, *kind)));
        let first = found.next().ok_or_else(|| PatchError::NoAnchor(self.why.clone()))?;
        if found.next().is_some() {
            return Err(PatchError::MultipleAnchors(self.why.clone()));
        }
        if matches!(first.1, Anchor::After | Anchor::Before | Anchor::Replace) && self.insert.is_empty() {
            return Err(PatchError::EmptyInsert(self.why.clone()));
        }
        if matches!(first.1, Anchor::Skip | Anchor::SkipCase | Anchor::SkipRange) && !self.insert.is_empty() {
            return Err(PatchError::SkipWithInsert(self.why.clone()));
        }
        if self.skip_range.as_ref().is_some_and(|range| range.through.trim().is_empty()) {
            return Err(PatchError::EmptyRangeEnd(self.why.clone()));
        }
        Ok(first)
    }
}

/// Inclusive endpoints of a profile-specific sequence subsection.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkipRange {
    pub from: String,
    pub through: String,
}

/// What a patch does at its anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    After,
    Before,
    Replace,
    Skip,
    SkipCase,
    SkipRange,
    WithoutTlSequence,
}

/// A step a patch can insert.
///
/// These are the harness operations the XML has no way to express —
/// process lifecycle, our explicit group-object triggers, the negative
/// "nothing arrives" assertion EITT leaves to the operator watching the
/// trace — plus raw telegrams for the occasional bit of state the
/// template assumes was set up out of band.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum InsertStep {
    /// Send a `GroupValue_Read` for an ASAP.
    TriggerRead(u16),
    /// Send a `GroupValue_Write` for an ASAP.
    TriggerWrite(u16),
    /// Make the DUT initiate an `S-A_Sync_Req` to a peer.
    ///
    /// The bench equivalent of the 3.4 prose "Please stimulate the BDUT
    /// to send a S-A_Sync_Req" — EITT leaves the stimulation to the
    /// operator, our DUT has no buttons, so the IPC side channel does it.
    TriggerSync {
        peer_ia: u16,
        #[serde(default)]
        tool: bool,
        #[serde(default)]
        broadcast: bool,
    },
    /// Assert nothing arrives within the timeout.
    ExpectNone(u32),
    /// Idle for a while (scaled).
    Wait(u32),
    /// Discard buffered frames after settling.
    Drain(u32),
    /// Wait for the DUT child to exit and respawn without draining the
    /// frames it emits on the way back up.
    WaitForRestart(u32),
    /// Set programming mode over the IPC side channel.
    SetProgrammingMode(bool),
    /// Wipe shared memory and respawn.
    FullReset(u32),
    /// Drive the DUT's own local master reset over the IPC side channel.
    ///
    /// The bench equivalent of "Please perform manual Factory Reset" —
    /// EITT stops for the operator to press the device's button; our DUT
    /// has none, and unlike [`FullReset`](Self::FullReset) this runs the
    /// device's *own* erase handling (tool key back to FDSK, tables
    /// cleared, IA wiped for erase code 02h) rather than restoring the
    /// bench snapshot.
    MasterReset { erase: u8, timeout_ms: u32 },
    /// A comment, for annotating why the surrounding patch exists.
    Comment(String),
    /// Send a raw telegram template.
    Inject {
        data: String,
        #[serde(default)]
        delay_ms: u32,
    },
    /// Expect a raw telegram template.
    Expect { data: String, timeout_ms: u32 },
    /// Send a plaintext telegram wrapped tool-access under a named key
    /// (the runner's tool counter supplies the sequence number). A+C by
    /// default; `auth_only = true` for authentication without
    /// confidentiality.
    ///
    /// For state the template's prose assumes the bench operator
    /// provisioned — a "Required BDUT Setting" that only secure
    /// management can put in place once security mode is on — and for
    /// replacing a secure telegram whose octets need a device-specific
    /// correction.
    InjectSecure {
        data: String,
        key: String,
        #[serde(default)]
        auth_only: bool,
    },
    /// Expect a secure tool-access response under a named key. A+C by
    /// default; `auth_only = true` for authentication only.
    ExpectSecure {
        data: String,
        key: String,
        timeout_ms: u32,
        #[serde(default)]
        auth_only: bool,
    },
}

impl InsertStep {
    /// Convert to the engine's step type.
    pub fn to_step(&self) -> TestStep {
        match self {
            Self::TriggerRead(asap) => helpers::trigger_read(*asap),
            Self::TriggerWrite(asap) => helpers::trigger_write(*asap),
            Self::TriggerSync { peer_ia, tool, broadcast } => {
                if *broadcast {
                    helpers::trigger_sync_broadcast(*peer_ia, *tool)
                } else {
                    helpers::trigger_sync(*peer_ia, *tool)
                }
            }
            Self::ExpectNone(ms) => helpers::expect_none(*ms),
            Self::Wait(ms) => helpers::wait(*ms),
            Self::Drain(ms) => helpers::drain(*ms),
            Self::WaitForRestart(ms) => helpers::wait_for_restart(*ms),
            Self::SetProgrammingMode(on) => helpers::set_programming_mode(*on),
            Self::FullReset(ms) => helpers::full_reset(*ms),
            Self::MasterReset { erase, timeout_ms } => helpers::master_reset(*erase, *timeout_ms),
            Self::Comment(text) => helpers::comment(text),
            Self::Inject { data, delay_ms } => helpers::inject_delay(data, *delay_ms),
            Self::Expect { data, timeout_ms } => helpers::expect(data, *timeout_ms),
            Self::InjectSecure { data, key, auth_only } => {
                if *auth_only {
                    helpers::inject_secure_ao(data, key)
                } else {
                    helpers::inject_secure_ac(data, key)
                }
            }
            Self::ExpectSecure { data, key, timeout_ms, auth_only } => {
                if *auth_only {
                    helpers::expect_secure_ao(data, key, *timeout_ms)
                } else {
                    helpers::expect_secure_ac(data, key, *timeout_ms)
                }
            }
        }
    }
}

impl PatchSet {
    /// Load from a TOML file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PatchError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| PatchError::Io(path.display().to_string(), e))?;
        let set: Self =
            toml::from_str(&text).map_err(|e| PatchError::Parse(path.display().to_string(), Box::new(e)))?;
        // Validate every anchor now rather than at the point of use, so
        // a malformed patch file is reported before anything runs.
        for patch in &set.patches {
            patch.anchor()?;
        }
        Ok(set)
    }

    /// Index the patches by the GUID they anchor on.
    ///
    /// Several patches may target the same anchor — inserting a comment
    /// and a trigger after one telegram, say — so the values are lists,
    /// applied in file order.
    pub fn by_anchor(&self) -> BTreeMap<String, Vec<(&Patch, Anchor)>> {
        let mut map: BTreeMap<String, Vec<(&Patch, Anchor)>> = BTreeMap::new();
        for patch in &self.patches {
            let Ok((id, kind)) = patch.anchor() else { continue };
            map.entry(id.to_ascii_uppercase()).or_default().push((patch, kind));
        }
        map
    }
}

/// Failure to load or apply a patch set.
#[derive(Debug)]
pub enum PatchError {
    Io(String, std::io::Error),
    Parse(String, Box<toml::de::Error>),
    /// A patch names no supported anchor operation.
    NoAnchor(String),
    /// A patch names more than one anchor.
    MultipleAnchors(String),
    /// An inserting patch has nothing to insert.
    EmptyInsert(String),
    /// A skipping patch has steps to insert, which it cannot use.
    SkipWithInsert(String),
    /// A range patch names no final GUID.
    EmptyRangeEnd(String),
    /// A range started but its final GUID was not found later in that case.
    UnknownRangeEnd {
        from: String,
        through: String,
        why: String,
    },
    /// An anchor GUID is not in the template.
    UnknownAnchor {
        id: String,
        why: String,
    },
}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(p, e) => write!(f, "could not read the patch set {p}: {e}"),
            Self::Parse(p, e) => write!(f, "could not parse the patch set {p}: {e}"),
            Self::NoAnchor(why) => {
                write!(
                    f,
                    "the patch {why:?} names no anchor \
                     (after/before/replace/skip/skip_case/skip_range/without_tl_sequence)"
                )
            }
            Self::MultipleAnchors(why) => write!(f, "the patch {why:?} names more than one anchor"),
            Self::EmptyInsert(why) => write!(f, "the patch {why:?} inserts nothing"),
            Self::SkipWithInsert(why) => write!(f, "the patch {why:?} both skips and inserts"),
            Self::EmptyRangeEnd(why) => write!(f, "the range patch {why:?} has an empty `through` anchor"),
            Self::UnknownRangeEnd { from, through, why } => write!(
                f,
                "the range patch {why:?} starts at {from}, but its inclusive end {through} is not later in the same case"
            ),
            Self::UnknownAnchor { id, why } => write!(
                f,
                "the patch {why:?} anchors on {id}, which is not in this template — \
                 the template has most likely been revised, so re-check what the patch was compensating for"
            ),
        }
    }
}

impl std::error::Error for PatchError {}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
template = "KnxConformanceTestTemplate-GroupObjects"

[[patch]]
after = "1114B318-ED15-44F5-A6D9-3B257518CCC2"
why = "our stack does not auto-transmit on a comm-flag write"
insert = [{ trigger_read = 1 }]

[[patch]]
before = "B8709B3D-060D-46CD-9BC9-DB48FAFEE736"
why = "restore config flags a previous case left disabled"
insert = [
  { inject = { data = "BC #EDI #GO_2_ADDR E2 00 80 DF", delay_ms = 200 } },
]

[[patch]]
skip = "DEADBEEF-0000-0000-0000-000000000000"
why = "not reachable on TP1"

[[patch]]
skip_range = { from = "AAAAAAAA-0000-0000-0000-000000000000", through = "BBBBBBBB-0000-0000-0000-000000000000" }
why = "subsection belongs to another profile"

[[patch]]
without_tl_sequence = "CCCCCCCC-0000-0000-0000-000000000000"
why = "the bounded receiver drops this frame before TL"
insert = [{ expect_none = 1000 }]
"#;

    #[test]
    fn a_patch_set_round_trips() {
        let set: PatchSet = toml::from_str(SAMPLE).expect("parse");
        assert_eq!(set.patches.len(), 5);
        assert_eq!(set.patches[0].anchor().expect("anchor").1, Anchor::After);
        assert_eq!(set.patches[1].anchor().expect("anchor").1, Anchor::Before);
        assert_eq!(set.patches[2].anchor().expect("anchor").1, Anchor::Skip);
        assert_eq!(set.patches[3].anchor().expect("anchor").1, Anchor::SkipRange);
        assert_eq!(set.patches[4].anchor().expect("anchor").1, Anchor::WithoutTlSequence);
    }

    #[test]
    fn anchors_are_indexed_case_insensitively() {
        // GUIDs are copied out of the XML by hand; casing should not
        // decide whether a patch applies.
        let set: PatchSet = toml::from_str(SAMPLE).expect("parse");
        let by = set.by_anchor();
        assert!(by.contains_key("1114B318-ED15-44F5-A6D9-3B257518CCC2"));
    }

    #[test]
    fn a_patch_must_say_what_it_does_and_where() {
        assert!(
            toml::from_str::<PatchSet>("template = \"t\"\n[[patch]]\nwhy = \"x\"\n")
                .map(|s| s.patches[0].anchor().is_ok())
                .unwrap_or(false)
                .eq(&false)
        );
        // Two anchors is ambiguous, not a shorthand for "both".
        let two = toml::from_str::<PatchSet>(
            "template = \"t\"\n[[patch]]\nafter = \"A\"\nbefore = \"B\"\nwhy = \"x\"\ninsert = [{ wait = 1 }]\n",
        )
        .expect("parse");
        assert!(matches!(two.patches[0].anchor(), Err(PatchError::MultipleAnchors(_))));
    }

    #[test]
    fn inserting_nothing_and_skipping_something_are_both_rejected() {
        let empty =
            toml::from_str::<PatchSet>("template = \"t\"\n[[patch]]\nafter = \"A\"\nwhy = \"x\"\n").expect("parse");
        assert!(matches!(empty.patches[0].anchor(), Err(PatchError::EmptyInsert(_))));

        let both = toml::from_str::<PatchSet>(
            "template = \"t\"\n[[patch]]\nskip = \"A\"\nwhy = \"x\"\ninsert = [{ wait = 1 }]\n",
        )
        .expect("parse");
        assert!(matches!(both.patches[0].anchor(), Err(PatchError::SkipWithInsert(_))));
    }

    #[test]
    fn why_is_mandatory() {
        assert!(toml::from_str::<PatchSet>("template = \"t\"\n[[patch]]\nskip = \"A\"\n").is_err());
    }
}
