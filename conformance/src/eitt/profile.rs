//! The device profile: everything about *our* DUT that the vendor
//! template cannot know.
//!
//! EITT gets these from its project settings, not from the template —
//! `#EDI` and `#BDUT` are used by every single telegram and declared
//! nowhere in the XML. A profile supplies them, says which medium and
//! DUT binary we are, and lists the cases that do not apply to us.
//!
//! This is the same job `KnxConformanceTestProfiles.xml` does for EITT
//! with its `<Optional>` / `<NotApplicable>` GUID lists. We keep our
//! own because the vendor profiles describe neither our device nor our
//! harness.
//!
//! A profile also lists the templates it knows how to run, with the
//! patches and not-applicable cases that belong to each. Those GUID
//! lists only mean anything inside one template, so this is where they
//! belong — and it means a run needs nothing on the command line but
//! the profile.
//!
//! ```toml
//! medium = "tp"
//! dut = "plain"
//!
//! [addresses]
//! EDI  = "AF FE"
//! BDUT = "10 01"
//!
//! [commands]
//! pause = "ignore"
//!
//! [[template]]
//! file = "KnxConformanceTestTemplate-GroupObjects.xml"
//! patches = ["conformance/patches/group-objects.toml"]
//! not_applicable = [
//!   { id = "2B58DCC3-...", why = "UINT8 variant; our GO0 is 1 bit" },
//! ]
//! ```
//!
//! Templates are named by file, never by path: they are licensed
//! material living outside the repository at a machine-specific
//! location, and a committed profile that hardcoded one directory would
//! be wrong on every other machine. The directory comes from
//! `$EITT_TEMPLATES`, or `--templates-dir` when that is given.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::harness::DutMode;

/// A loaded profile.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Which medium's telegrams we run. Telegrams tagged with another
    /// medium are dropped — 1.4.1.7 carries every invalid APCI twice,
    /// once for TP and once for RF.
    #[serde(default = "default_medium")]
    pub medium: String,
    /// Which DUT binary to drive.
    #[serde(default)]
    pub dut: Dut,
    /// Variables the template does not declare, notably `EDI` and
    /// `BDUT`. Values are space-separated hex.
    #[serde(default)]
    pub addresses: BTreeMap<String, String>,
    /// Overrides for variables the template *does* declare, for when a
    /// default does not suit our DUT.
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    /// What to do with each family of comment command.
    #[serde(default)]
    pub commands: CommandPolicies,
    /// The templates this profile knows how to run.
    #[serde(default, rename = "template")]
    pub templates: Vec<TemplateRef>,
    /// Cases to skip regardless of template. Prefer the per-template
    /// list: a GUID only means anything inside the template that
    /// defines it.
    #[serde(default)]
    pub not_applicable: Vec<NotApplicable>,
    /// Collections to run, filled in per template by
    /// [`Profile::for_template`]. Not read from the profile-wide TOML,
    /// where a collection name would have no template to belong to.
    #[serde(skip)]
    pub collections: Vec<String>,
    /// Whether to recompute transport-layer sequence numbers, filled in
    /// per template by [`Profile::for_template`]. See
    /// [`TlSequencePolicy`].
    #[serde(skip)]
    pub recompute_tl_sequence: bool,
    /// The per-template exceptions that were applied, already rendered
    /// for the run report. Filled in by [`Profile::for_template`] for
    /// the same reason as `collections`.
    #[serde(skip)]
    pub applied_overrides: Vec<String>,
}

/// One template the profile can run, and what it needs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateRef {
    /// File name, resolved against `$EITT_TEMPLATES`. Not a path: the
    /// templates are licensed material kept outside the repository, so
    /// a committed profile cannot know where they live.
    pub file: String,
    /// Which `TestCollection`s to run, by substring of their name.
    /// Empty runs all of them.
    ///
    /// A template's collections are frequently *alternatives* rather
    /// than parts of one run: the group-object template ships a UINT1
    /// and a UINT8 collection that address the same group addresses and
    /// each begin "the following sample application program shall be
    /// loaded into the BDUT". Only one of those programs can be loaded
    /// at a time, so a device runs the collection matching the one it
    /// has.
    #[serde(default)]
    pub collections: Vec<String>,
    /// Patch sets to overlay, as repository-relative paths.
    #[serde(default)]
    pub patches: Vec<String>,
    /// Cases in *this* template that do not apply to this device.
    #[serde(default)]
    pub not_applicable: Vec<NotApplicable>,
    /// Variable overrides for this template only.
    ///
    /// Templates reuse variable names for different things: `GO_ADDR`
    /// is a 1-bit object in the transport-layer template and an 8-bit
    /// one in the network-layer template, and our DUT keeps those at
    /// different group addresses. A profile-wide override could only
    /// ever be right for one of them.
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    /// Whether the transport-layer sequence numbers in this template's
    /// telegram data can be trusted. See [`TlSequencePolicy`].
    #[serde(default)]
    pub tl_sequence: Option<TlSequencePolicy>,
    /// Command-policy exceptions that hold for this template only.
    ///
    /// The profile-wide `[commands]` cannot express these: `@if+` is a
    /// no-op for the transport-layer template, where the second tool
    /// interface has no counterpart in our single mock bus, and is
    /// emphatically not one for the coupler templates, where it decides
    /// which side of the coupler a frame enters on.
    #[serde(default, rename = "command")]
    pub commands: Vec<CommandOverride>,
}

/// Whether to recompute a template's transport-layer sequence numbers.
///
/// EITT computes one for every management telegram before running a
/// sequence, unless the telegram pins it (manual §12.2.3.14), so the
/// numbers a template's `Data` carries are whatever the author last
/// typed and need not be right. Whether that matters is a property of
/// the template, not of the device, which is why this is per template
/// and not a profile-wide switch:
///
/// - The load-state-machine template's numbers are demonstrably stale.
///   Cases 2.2.2 and 2.3.2 open with the identical telegram and expect
///   different acknowledgements from it; only recomputation reconciles
///   them, and it produces exactly what the hand-written transcription
///   of those cases renumbered them to.
/// - The transport-layer template's numbers are the subject of the
///   test. Its negative cases send deliberately wrong ones, and
///   recomputing would turn them into positive tests.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlSequencePolicy {
    pub recompute: bool,
    /// Why the template's own numbers are or are not to be believed.
    /// Required for the same reason every other exception's is.
    pub why: String,
}

/// A per-template override of one command-policy category.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOverride {
    pub category: CommandCategory,
    pub policy: Policy,
    /// Why the override is right *here*. Required, for the same reason
    /// [`NotApplicable::why`] is: an unexplained exception cannot be
    /// told apart from an oversight when the template is next revised.
    pub why: String,
}

/// The command families [`CommandPolicies`] holds a policy for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandCategory {
    Pause,
    Interface,
    Sequence,
    Security,
    PointApi,
}

/// The environment variable naming the directory that holds the EITT
/// `KnxConformanceTestTemplate-*.xml` files.
pub const TEMPLATES_DIR_ENV: &str = "EITT_TEMPLATES";

impl TemplateRef {
    /// Resolve `file` to a path.
    ///
    /// `override_dir` is the `--templates-dir` flag and wins when given;
    /// otherwise `$EITT_TEMPLATES`. An absolute `file` bypasses both,
    /// for the odd one-off.
    pub fn resolve(&self, override_dir: Option<&str>) -> Result<std::path::PathBuf, ProfileError> {
        let given = std::path::Path::new(&self.file);
        if given.is_absolute() {
            return Ok(given.to_path_buf());
        }
        let dir = match override_dir {
            Some(d) => d.to_string(),
            None => std::env::var(TEMPLATES_DIR_ENV).map_err(|_| ProfileError::NoTemplatesDir(self.file.clone()))?,
        };
        Ok(std::path::Path::new(&dir).join(&self.file))
    }
}

fn default_medium() -> String {
    "tp".to_string()
}

/// Which DUT child binary a run drives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Dut {
    /// `conformance-dut`.
    #[default]
    Plain,
    /// `conformance-dut-secure`.
    Secure,
}

impl From<Dut> for DutMode {
    fn from(d: Dut) -> Self {
        match d {
            Dut::Plain => DutMode::Plain,
            Dut::Secure => DutMode::Secure,
        }
    }
}

/// A case we deliberately do not run.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotApplicable {
    /// TestCase GUID.
    pub id: String,
    /// Why it does not apply. Required — an unexplained skip is
    /// indistinguishable from a bug.
    pub why: String,
}

/// What to do when a comment command we do not implement turns up.
///
/// The defaults are chosen by what happens if we are wrong. Ignoring a
/// pause is safe: it only ever blocked for a human. Ignoring an
/// interface command, a sequence call or a security-table rewrite is
/// not — each silently changes what runs or what state exists, so those
/// stop the run until someone decides what they should mean here.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandPolicies {
    /// `@@`, `@@!`, `@@+`.
    #[serde(default = "policy_ignore")]
    pub pause: Policy,
    /// `@if+`, `@if-`.
    #[serde(default = "policy_error")]
    pub interface: Policy,
    /// `@#`, `@##`, `@>`, `@>w`, `@<`.
    #[serde(default = "policy_error")]
    pub sequence: Policy,
    /// `@@[rc`, `@@[rn`, `@@[sk`, `@@[sn`, `@@[import`.
    #[serde(default = "policy_error")]
    pub security: Policy,
    /// `@@[pah…`.
    #[serde(default = "policy_error")]
    pub point_api: Policy,
}

impl Default for CommandPolicies {
    fn default() -> Self {
        Self {
            pause: Policy::Ignore,
            interface: Policy::Error,
            sequence: Policy::Error,
            security: Policy::Error,
            point_api: Policy::Error,
        }
    }
}

fn policy_ignore() -> Policy {
    Policy::Ignore
}
fn policy_error() -> Policy {
    Policy::Error
}

/// How to treat an unimplemented command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    /// Log it, keep its text as a comment, carry on.
    Ignore,
    /// Refuse to lower the template.
    Error,
}

impl Profile {
    /// Load from a TOML file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ProfileError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| ProfileError::Io(path.display().to_string(), e))?;
        toml::from_str(&text).map_err(|e| ProfileError::Parse(path.display().to_string(), Box::new(e)))
    }

    /// Whether a telegram tagged with `medium` runs under this profile.
    /// A telegram with no medium runs on any: the attribute is only
    /// present where a template offers per-medium variants.
    pub fn accepts_medium(&self, medium: Option<&str>) -> bool {
        match medium {
            None => true,
            Some(m) => m.eq_ignore_ascii_case(&self.medium),
        }
    }

    /// The reason this case is skipped, if it is.
    pub fn not_applicable_reason(&self, case_id: Option<&str>) -> Option<&str> {
        let id = case_id?;
        self.not_applicable.iter().find(|n| n.id.eq_ignore_ascii_case(id)).map(|n| n.why.as_str())
    }

    /// A copy of this profile scoped to one template: the template's own
    /// not-applicable list folded into the profile-wide one and its
    /// collection selection carried across, so the lowering pass sees a
    /// single profile.
    pub fn for_template(&self, template: &TemplateRef) -> Self {
        let mut scoped = self.clone();
        scoped.not_applicable.extend(template.not_applicable.iter().cloned());
        scoped.collections.clone_from(&template.collections);
        scoped.variables.extend(template.variables.iter().map(|(k, v)| (k.clone(), v.clone())));

        for over in &template.commands {
            let slot = match over.category {
                CommandCategory::Pause => &mut scoped.commands.pause,
                CommandCategory::Interface => &mut scoped.commands.interface,
                CommandCategory::Sequence => &mut scoped.commands.sequence,
                CommandCategory::Security => &mut scoped.commands.security,
                CommandCategory::PointApi => &mut scoped.commands.point_api,
            };
            *slot = over.policy;
            scoped
                .applied_overrides
                .push(format!("{:?} commands are {:?} for this template — {}", over.category, over.policy, over.why));
        }

        if let Some(tl) = &template.tl_sequence {
            scoped.recompute_tl_sequence = tl.recompute;
            let what = if tl.recompute { "recomputed" } else { "taken from the template" };
            scoped.applied_overrides.push(format!("transport-layer sequence numbers are {what} — {}", tl.why));
        }
        scoped
    }

    /// Whether a `TestCollection` with this name runs. No selection
    /// means every collection runs.
    pub fn accepts_collection(&self, name: Option<&str>) -> bool {
        if self.collections.is_empty() {
            return true;
        }
        let name = name.unwrap_or_default().to_lowercase();
        self.collections.iter().any(|c| name.contains(&c.to_lowercase()))
    }

    /// The templates matching a filter, or all of them when there is no
    /// filter. Matching is on the file name, so `GroupObjects` is enough.
    pub fn templates_matching(&self, filter: Option<&str>) -> Vec<&TemplateRef> {
        match filter {
            None => self.templates.iter().collect(),
            Some(f) => {
                let f = f.to_lowercase();
                self.templates.iter().filter(|t| t.file.to_lowercase().contains(&f)).collect()
            }
        }
    }
}

/// Failure to load a profile.
#[derive(Debug)]
pub enum ProfileError {
    Io(String, std::io::Error),
    Parse(String, Box<toml::de::Error>),
    /// A template was named but there is nowhere to look for it.
    NoTemplatesDir(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(p, e) => write!(f, "could not read the profile {p}: {e}"),
            Self::Parse(p, e) => write!(f, "could not parse the profile {p}: {e}"),
            Self::NoTemplatesDir(file) => write!(
                f,
                "the profile asks for the template {file}, but neither --templates-dir nor \
                 ${TEMPLATES_DIR_ENV} says where the EITT templates live. They are licensed \
                 material kept outside this repository; point one of them at the directory \
                 holding the KnxConformanceTestTemplate-*.xml files."
            ),
        }
    }
}

impl std::error::Error for ProfileError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minimal_profile_gets_safe_defaults() {
        let p: Profile = toml::from_str("").expect("empty profile");
        assert_eq!(p.medium, "tp");
        assert_eq!(p.dut, Dut::Plain);
        // Pauses are inert without an operator; everything else stops
        // the run until someone decides what it means here.
        assert_eq!(p.commands.pause, Policy::Ignore);
        assert_eq!(p.commands.interface, Policy::Error);
        assert_eq!(p.commands.sequence, Policy::Error);
        assert_eq!(p.commands.security, Policy::Error);
        assert_eq!(p.commands.point_api, Policy::Error);
    }

    #[test]
    fn medium_filtering_keeps_untagged_telegrams() {
        let p: Profile = toml::from_str("medium = \"tp\"").expect("profile");
        assert!(p.accepts_medium(None));
        assert!(p.accepts_medium(Some("tp")));
        assert!(p.accepts_medium(Some("TP")));
        assert!(!p.accepts_medium(Some("rf")));
    }

    #[test]
    fn collections_are_selected_per_template() {
        let p: Profile = toml::from_str(
            r#"
            [[template]]
            file = "KnxConformanceTestTemplate-GroupObjects.xml"
            collections = ["UINT1"]
            "#,
        )
        .expect("profile");
        // Nothing selected at profile level: every collection runs.
        assert!(p.accepts_collection(Some("Group Objects (UINT8)")));

        let scoped = p.for_template(&p.templates[0]);
        assert!(scoped.accepts_collection(Some("Group Objects (UINT1)")));
        assert!(!scoped.accepts_collection(Some("Group Objects (UINT8)")));
        // An unnamed collection cannot match a selector, so a template
        // that stops naming its collections fails loudly (nothing runs)
        // rather than silently running the wrong one.
        assert!(!scoped.accepts_collection(None));
    }

    #[test]
    fn command_policies_are_relaxed_per_template_only() {
        let p: Profile = toml::from_str(
            r#"
            [[template]]
            file = "KnxConformanceTestTemplate-TransportLayer.xml"

            [[template.command]]
            category = "interface"
            policy = "ignore"
            why = "one mock bus carries both tool addresses"

            [[template]]
            file = "KnxConformanceTestTemplate-Coupler TP-TP.xml"
            "#,
        )
        .expect("profile");

        let relaxed = p.for_template(&p.templates[0]);
        assert_eq!(relaxed.commands.interface, Policy::Ignore);
        // Untouched categories keep the profile-wide policy, and the
        // reason travels with the override so the run can print it.
        assert_eq!(relaxed.commands.sequence, Policy::Error);
        assert_eq!(relaxed.applied_overrides.len(), 1);

        // The next template starts from the profile-wide policy again:
        // `@if+` is a no-op for us on the transport-layer template and
        // decides which side of a coupler a frame enters on for that one.
        let coupler = p.for_template(&p.templates[1]);
        assert_eq!(coupler.commands.interface, Policy::Error);
        assert!(coupler.applied_overrides.is_empty());
    }

    #[test]
    fn a_command_override_must_say_why() {
        let toml = "[[template]]\nfile = \"x.xml\"\n\n\
                    [[template.command]]\ncategory = \"interface\"\npolicy = \"ignore\"\n";
        assert!(toml::from_str::<Profile>(toml).is_err(), "an unexplained override reads as an oversight");
    }

    #[test]
    fn no_collection_selection_runs_everything() {
        let p: Profile = toml::from_str("[[template]]\nfile = \"x.xml\"\n").expect("profile");
        let scoped = p.for_template(&p.templates[0]);
        assert!(scoped.accepts_collection(Some("anything")));
        assert!(scoped.accepts_collection(None));
    }

    #[test]
    fn not_applicable_requires_a_reason() {
        // `why` has no default, so a bare id fails to parse. An
        // unexplained skip would be indistinguishable from a bug.
        let err = toml::from_str::<Profile>("[[not_applicable]]\nid = \"X\"\n");
        assert!(err.is_err());
    }

    #[test]
    fn typos_in_a_profile_are_rejected() {
        // `deny_unknown_fields` throughout: a misspelled key that
        // silently defaults is exactly how a profile stops describing
        // the device it claims to.
        assert!(toml::from_str::<Profile>("medum = \"tp\"").is_err());
        assert!(toml::from_str::<Profile>("[commands]\npauze = \"ignore\"").is_err());
    }
}
