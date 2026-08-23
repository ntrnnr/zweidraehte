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
//! extends = "tp1-bcu2.toml" # optional, relative to this profile
//! medium = "tp"
//! dut = "systemb"
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
//! patches = ["conformance/patches/full/common/group-objects.toml"]
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
use std::path::{Path, PathBuf};

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
    /// The reasons the unselected collections are unselected, filled in
    /// per template alongside `collections`.
    #[serde(skip)]
    pub skipped_collections: Vec<SkippedCollection>,
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
    /// Which DUT this template needs, when it is not the profile's.
    ///
    /// The data-security template has to be driven against
    /// `conformance-dut-systemb-secure`, which boots with the tool and group
    /// keys installed; the other templates want the plain DUT, which has
    /// no security at all. One profile covers both because they are the
    /// same device otherwise — same medium, same addresses, same tables.
    #[serde(default)]
    pub dut: Option<Dut>,
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
    ///
    /// Selecting any at all obliges the profile to account for the rest
    /// in [`TemplateRef::skipped_collections`].
    #[serde(default)]
    pub collections: Vec<String>,
    /// Why each collection `collections` leaves out is left out.
    ///
    /// Dropping a collection drops every case in it — 52 of the
    /// management template's 238 in one entry — and `collections` on its
    /// own is a bare list of substrings with nowhere to say why. Pairing
    /// the two makes lowering able to check that every collection a
    /// template declares is either run or explained, and to fail when
    /// one is neither. That is the same bargain the patch anchors make:
    /// a template that gains or renames a collection stops the run
    /// instead of quietly shrinking it.
    #[serde(default, rename = "skipped_collection")]
    pub skipped_collections: Vec<SkippedCollection>,
    /// Patch sets to overlay, as repository-relative paths.
    #[serde(default)]
    pub patches: Vec<String>,
    /// Cases in *this* template that do not apply to this device.
    #[serde(default)]
    pub not_applicable: Vec<NotApplicable>,
    /// Cases inherited as not applicable which this profile variant does
    /// support. This is primarily for a composition with a larger frame
    /// budget reusing the base family profile.
    #[serde(default)]
    pub applicable: Vec<ApplicableOverride>,
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
    /// `conformance-dut-bcu1` — BCU1 family (mask 0012h) on the
    /// polling micro stack.
    Bcu1,
    /// `conformance-dut-systemb`. Spelled `systemb` in profile TOML.
    #[default]
    SystemB,
    /// `conformance-dut-systemb-secure`. Spelled `systemb-secure` in profile
    /// TOML.
    #[serde(rename = "systemb-secure")]
    SystemBSecure,
    /// `conformance-dut-system7` — System 7 family (mask 0705h).
    System7,
    /// `conformance-dut-system7-secure` — System 7 family with Data
    /// Secure. Spelled `system7-secure` in profile TOML.
    #[serde(rename = "system7-secure")]
    System7Secure,
    /// `conformance-dut-bcu2` — BCU2 family (mask 0020h) on the
    /// no-async micro stack.
    Bcu2,
    /// `conformance-dut-bcu2-secure` — BCU2 family (mask 0021h) with
    /// the composable micro Data Secure profile. Spelled `bcu2-secure`
    /// in profile TOML.
    #[serde(rename = "bcu2-secure")]
    Bcu2Secure,
    /// `conformance-dut-bcu2-secure-base` — the same secure composition
    /// with the ordinary BCU2 application. Spelled `bcu2-secure-base` in
    /// profile TOML.
    #[serde(rename = "bcu2-secure-base")]
    Bcu2SecureBase,
    /// `conformance-dut-micro-system7` — System 7 family on the
    /// no-async micro stack. Spelled `micro-system7` in profile TOML.
    #[serde(rename = "micro-system7")]
    MicroSystem7,
    /// `conformance-dut-micro-system7-secure` — the polling System 7
    /// composition with Data Secure. Spelled `micro-system7-secure` in TOML.
    #[serde(rename = "micro-system7-secure")]
    MicroSystem7Secure,
}

impl From<Dut> for DutMode {
    fn from(d: Dut) -> Self {
        match d {
            Dut::Bcu1 => DutMode::Bcu1,
            Dut::SystemB => DutMode::SystemB,
            Dut::SystemBSecure => DutMode::SystemBSecure,
            Dut::System7 => DutMode::System7,
            Dut::System7Secure => DutMode::System7Secure,
            Dut::Bcu2 => DutMode::Bcu2,
            Dut::Bcu2Secure => DutMode::Bcu2Secure,
            Dut::Bcu2SecureBase => DutMode::Bcu2SecureBase,
            Dut::MicroSystem7 => DutMode::MicroSystem7,
            Dut::MicroSystem7Secure => DutMode::MicroSystem7Secure,
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

/// An inherited exclusion which a more capable profile variant re-enables.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicableOverride {
    /// TestCase GUID inherited through `extends`.
    pub id: String,
    /// Which capability makes the case applicable to this variant.
    pub why: String,
}

/// A whole `TestCollection` we deliberately do not run.
///
/// Matched by substring of the collection's name, the same way
/// [`TemplateRef::collections`] selects. Collections are named for the
/// clause range they cover — "2.22 to 2.24 Routing Table Access" — so a
/// prefix is enough and survives the wording being tidied up.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkippedCollection {
    /// Substring of the collection name.
    pub name: String,
    /// Why the whole collection does not apply. Required, for the same
    /// reason [`NotApplicable::why`] is.
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
        let value = load_profile_value(path, &mut Vec::new())?;
        let profile: Self =
            value.try_into().map_err(|e| ProfileError::Parse(path.display().to_string(), Box::new(e)))?;
        profile.validate_applicable_overrides(path)?;
        Ok(profile)
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
        for applicable in &template.applicable {
            scoped.not_applicable.retain(|entry| !entry.id.eq_ignore_ascii_case(&applicable.id));
            scoped.applied_overrides.push(format!("case {} is applicable — {}", applicable.id, applicable.why));
        }
        scoped.collections.clone_from(&template.collections);
        scoped.skipped_collections.clone_from(&template.skipped_collections);
        if let Some(dut) = template.dut {
            scoped.dut = dut;
            scoped.applied_overrides.push(format!("driven against the {dut:?} DUT for this template"));
        }
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

    /// Why a `TestCollection` with this name is not run, if the profile
    /// says. Only consulted for collections `accepts_collection` turned
    /// down; one it cannot account for is an error, raised by the caller.
    pub fn skipped_collection_reason(&self, name: Option<&str>) -> Option<&str> {
        let name = name.unwrap_or_default().to_lowercase();
        self.skipped_collections.iter().find(|s| name.contains(&s.name.to_lowercase())).map(|s| s.why.as_str())
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

    fn validate_applicable_overrides(&self, path: &Path) -> Result<(), ProfileError> {
        for template in &self.templates {
            for applicable in &template.applicable {
                let inherited = self
                    .not_applicable
                    .iter()
                    .chain(template.not_applicable.iter())
                    .any(|entry| entry.id.eq_ignore_ascii_case(&applicable.id));
                if !inherited {
                    return Err(ProfileError::Inheritance(
                        path.display().to_string(),
                        format!(
                            "template {} marks case {} applicable, but no inherited exclusion has that ID",
                            template.file, applicable.id
                        ),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Recursively load one profile and merge its child overrides over the base.
///
/// Ordinary TOML tables merge by key and scalar/array values replace their
/// parent. The one domain-specific rule is `[[template]]`: entries merge by
/// their `file`, so a derived profile can replace one patch list or variable
/// without copying every other template and exception in the family profile.
fn load_profile_value(path: &Path, stack: &mut Vec<PathBuf>) -> Result<toml::Value, ProfileError> {
    let canonical = path.canonicalize().map_err(|e| ProfileError::Io(path.display().to_string(), e))?;
    if stack.contains(&canonical) {
        let mut cycle = stack.iter().map(|entry| entry.display().to_string()).collect::<Vec<_>>();
        cycle.push(canonical.display().to_string());
        return Err(ProfileError::Inheritance(
            path.display().to_string(),
            format!("inheritance cycle: {}", cycle.join(" -> ")),
        ));
    }
    stack.push(canonical);

    let text = std::fs::read_to_string(path).map_err(|e| ProfileError::Io(path.display().to_string(), e))?;
    let mut child: toml::Value =
        toml::from_str(&text).map_err(|e| ProfileError::Parse(path.display().to_string(), Box::new(e)))?;
    let extends = child
        .as_table_mut()
        .ok_or_else(|| ProfileError::Inheritance(path.display().to_string(), "profile root is not a table".into()))?
        .remove("extends");

    let result = if let Some(extends) = extends {
        let parent_name = extends.as_str().ok_or_else(|| {
            ProfileError::Inheritance(path.display().to_string(), "`extends` must be a relative profile path".into())
        })?;
        if !Path::new(parent_name).is_relative() {
            return Err(ProfileError::Inheritance(
                path.display().to_string(),
                "`extends` must be a relative profile path".into(),
            ));
        }
        let parent_path = path.parent().unwrap_or_else(|| Path::new(".")).join(parent_name);
        let mut parent = load_profile_value(&parent_path, stack)?;
        merge_profile_values(&mut parent, child, true);
        parent
    } else {
        child
    };

    stack.pop();
    Ok(result)
}

fn merge_profile_values(parent: &mut toml::Value, child: toml::Value, root: bool) {
    match (parent, child) {
        (toml::Value::Table(parent), toml::Value::Table(child)) => {
            for (key, child_value) in child {
                match parent.get_mut(&key) {
                    Some(parent_value) if root && key == "template" => {
                        merge_template_arrays(parent_value, child_value);
                    }
                    Some(parent_value) if key == "not_applicable" => {
                        merge_keyed_arrays(parent_value, child_value, "id");
                    }
                    Some(parent_value) => merge_profile_values(parent_value, child_value, false),
                    None => {
                        parent.insert(key, child_value);
                    }
                }
            }
        }
        (parent, child) => *parent = child,
    }
}

fn merge_keyed_arrays(parent: &mut toml::Value, child: toml::Value, key: &str) {
    let child = match child {
        toml::Value::Array(child) => child,
        child => {
            *parent = child;
            return;
        }
    };
    let Some(parent) = parent.as_array_mut() else {
        *parent = toml::Value::Array(child);
        return;
    };
    for child_entry in child {
        let identity = child_entry.get(key).and_then(toml::Value::as_str);
        let existing = identity.and_then(|identity| {
            parent.iter_mut().find(|entry| {
                entry
                    .get(key)
                    .and_then(toml::Value::as_str)
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(identity))
            })
        });
        if let Some(existing) = existing {
            *existing = child_entry;
        } else {
            parent.push(child_entry);
        }
    }
}

fn merge_template_arrays(parent: &mut toml::Value, child: toml::Value) {
    let child = match child {
        toml::Value::Array(child) => child,
        child => {
            *parent = child;
            return;
        }
    };
    let Some(parent) = parent.as_array_mut() else {
        *parent = toml::Value::Array(child);
        return;
    };
    for child_template in child {
        let file = child_template.get("file").and_then(toml::Value::as_str);
        let existing = file.and_then(|file| {
            parent.iter_mut().find(|entry| entry.get("file").and_then(toml::Value::as_str) == Some(file))
        });
        if let Some(existing) = existing {
            merge_profile_values(existing, child_template, false);
        } else {
            parent.push(child_template);
        }
    }
}

/// Failure to load a profile.
#[derive(Debug)]
pub enum ProfileError {
    Io(String, std::io::Error),
    Parse(String, Box<toml::de::Error>),
    /// A derived profile has an invalid parent or override.
    Inheritance(String, String),
    /// A template was named but there is nowhere to look for it.
    NoTemplatesDir(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(p, e) => write!(f, "could not read the profile {p}: {e}"),
            Self::Parse(p, e) => write!(f, "could not parse the profile {p}: {e}"),
            Self::Inheritance(p, e) => write!(f, "could not inherit the profile {p}: {e}"),
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

    fn temp_profile_dir(label: &str) -> PathBuf {
        let unique = format!(
            "zweidraehte-profile-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time follows the Unix epoch")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir(&dir).expect("create isolated profile directory");
        dir
    }

    #[test]
    fn a_minimal_profile_gets_safe_defaults() {
        let p: Profile = toml::from_str("").expect("empty profile");
        assert_eq!(p.medium, "tp");
        assert_eq!(p.dut, Dut::SystemB);
        // Pauses are inert without an operator; everything else stops
        // the run until someone decides what it means here.
        assert_eq!(p.commands.pause, Policy::Ignore);
        assert_eq!(p.commands.interface, Policy::Error);
        assert_eq!(p.commands.sequence, Policy::Error);
        assert_eq!(p.commands.security, Policy::Error);
        assert_eq!(p.commands.point_api, Policy::Error);
    }

    #[test]
    fn micro_dut_names_select_the_existing_harness_modes() {
        for (name, expected) in [
            ("bcu2", DutMode::Bcu2),
            ("bcu2-secure", DutMode::Bcu2Secure),
            ("bcu2-secure-base", DutMode::Bcu2SecureBase),
            ("micro-system7", DutMode::MicroSystem7),
            ("micro-system7-secure", DutMode::MicroSystem7Secure),
        ] {
            let profile: Profile = toml::from_str(&format!("dut = \"{name}\"")).expect("micro DUT profile");
            assert_eq!(DutMode::from(profile.dut), expected);
        }
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
    fn a_derived_profile_overrides_one_template_without_copying_the_others() {
        let dir = temp_profile_dir("inheritance");
        std::fs::write(
            dir.join("base.toml"),
            r#"
                dut = "bcu2"

                [[template]]
                file = "Management.xml"
                patches = ["plain.toml"]
                [template.variables]
                DD0_RESPONSE = "00 20"
                [[template.not_applicable]]
                id = "EFF"
                why = "the base profile has standard frames"

                [[template]]
                file = "Transport.xml"
            "#,
        )
        .expect("write base profile");
        std::fs::write(
            dir.join("secure.toml"),
            r#"
                extends = "base.toml"
                dut = "bcu2-secure-base"

                [[template]]
                file = "Management.xml"
                patches = ["secure.toml"]
                [template.variables]
                DD0_RESPONSE = "00 21"
                [[template.applicable]]
                id = "EFF"
                why = "the secure composition has extended frames"
            "#,
        )
        .expect("write derived profile");

        let profile = Profile::load(dir.join("secure.toml")).expect("load derived profile");
        assert_eq!(profile.dut, Dut::Bcu2SecureBase);
        assert_eq!(profile.templates.len(), 2, "the untouched transport template is inherited");
        let management = &profile.templates[0];
        assert_eq!(management.patches, ["secure.toml"]);
        assert_eq!(management.variables["DD0_RESPONSE"], "00 21");
        assert!(profile.for_template(management).not_applicable_reason(Some("EFF")).is_none());

        std::fs::remove_dir_all(dir).expect("remove isolated profile directory");
    }

    #[test]
    fn an_applicable_override_must_name_an_inherited_exclusion() {
        let dir = temp_profile_dir("applicable");
        std::fs::write(dir.join("base.toml"), "[[template]]\nfile = \"Management.xml\"\n").expect("write base profile");
        std::fs::write(
            dir.join("derived.toml"),
            r#"
                extends = "base.toml"
                [[template]]
                file = "Management.xml"
                [[template.applicable]]
                id = "NOT-IN-BASE"
                why = "would otherwise hide a profile typo"
            "#,
        )
        .expect("write derived profile");

        let error = Profile::load(dir.join("derived.toml")).expect_err("unknown exclusion must fail");
        assert!(error.to_string().contains("no inherited exclusion"), "{error}");
        std::fs::remove_dir_all(dir).expect("remove isolated profile directory");
    }

    #[test]
    fn profile_inheritance_cycles_are_rejected() {
        let dir = temp_profile_dir("cycle");
        std::fs::write(dir.join("a.toml"), "extends = \"b.toml\"\n").expect("write first profile");
        std::fs::write(dir.join("b.toml"), "extends = \"a.toml\"\n").expect("write second profile");

        let error = Profile::load(dir.join("a.toml")).expect_err("cycle must fail");
        assert!(error.to_string().contains("inheritance cycle"), "{error}");
        std::fs::remove_dir_all(dir).expect("remove isolated profile directory");
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
