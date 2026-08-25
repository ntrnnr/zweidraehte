//! ETS file formats and package mechanics.
//!
//! This crate owns the host-side representation of ETS XML documents and the
//! containers that carry them. Product-definition generation remains in
//! `zweidraehte-knxprod`; consumers that only parse or package ETS data do not
//! need the generator DSL.
//!
//! The crate has no default features. [`schema`], [`xml`], [`runtime`],
//! [`product`], local master-data parsing, and project-document generation are
//! always available. Optional boundaries are:
//!
//! - `archives`: lossless `.knxprod` / `.knxproj` ZIP containers and selection;
//! - `signing`: explicit converter-key signing and package creation (implies
//!   `archives`);
//! - `knxkeys`: password-protected ETS keyring import/export;
//! - `master-data-download`: versioned cache and retrieval from
//!   `update.knx.org`.
//!
//! Archive views preserve entries they do not understand. Modifying a known
//! document replaces only that entry; writing a dirty signed directory
//! requires a caller-supplied `signing::ConverterKey`. The custom
//! `zweidraehte-project` syntax is a separate commissioning format, not the
//! [`project`] module's ETS `.knxproj` model.

pub mod runtime;
pub mod schema;
pub mod xml;

#[cfg(feature = "archives")]
pub mod archive;
#[cfg(feature = "knxkeys")]
pub mod keyring;
pub mod product;
pub mod project;
pub mod signing;

pub use runtime::device::Device;
pub use runtime::parser::{ParseError, parse_application_program, parse_application_program_from_file};
pub use schema::master_data::{MasterData, MasterDataError};
