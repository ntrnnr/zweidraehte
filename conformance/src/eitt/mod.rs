//! Executing EITT conformance templates from their original XML.
//!
//! The KNX conformance test suites ship as `KnxConformanceTestTemplate-*.xml`
//! files for EITT, the association's test tool. Hand-transcribing those
//! into Rust is how [`crate::tests`] came to be, and it is lossy: this
//! module exists because that transcription had silently drifted several
//! template revisions behind, and because two separate errors in it were
//! mistaken for stack bugs.
//!
//! The templates are licensed material. Nothing vendor-derived is
//! committed — a template is named on the command line, and the pieces
//! we *do* commit ([profiles](profile) and [patch sets](patch)) contain
//! only GUID references and our own step names.
//!
//! ```text
//! template.xml ──parse──▶ schema::Template ──┐
//! profile.toml ──────────────────────────────┼──lower──▶ Vec<TestSuite> ──▶ engine
//! patches.toml ──────────────────────────────┘
//! ```
//!
//! - [`schema`] mirrors the XML.
//! - [`comment`] parses the `@`-command language that `Comment/@Text`
//!   carries.
//! - [`profile`] describes *our* device: medium, DUT binary, the `#EDI`
//!   and `#BDUT` addresses EITT supplies from project settings rather
//!   than the template, and which cases do not apply.
//! - [`patch`] overlays harness-specific steps onto the vendor sequence
//!   without editing it.
//! - [`lower`] combines the three into suites the engine can run.

pub mod comment;
mod frame;
pub mod lower;
pub mod patch;
pub mod profile;
pub mod schema;
pub mod secure;

pub use lower::{LowerReport, lower};
pub use patch::PatchSet;
pub use profile::Profile;
pub use schema::Template;
