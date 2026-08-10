//! ETS-style device configuration download (03/05/02 download
//! procedures).
//!
//! Structured the way ETS is, in three layers with different sources
//! and different lifetimes:
//!
//! | Layer | Source | Per | Carries |
//! |---|---|---|---|
//! | [`mask`] | `knx_master.xml` | mask version | resource locations, procedure templates |
//! | [`product`] | `.knxprod` / MTXML | product | segments, load procedures, object and parameter layout |
//! | [`project`] | the caller | installation | individual address, group links, parameter values |
//!
//! ```text
//!   knx_master.xml ──► MaskDb ──┐
//!                               ├──► assemble() ──► Vec<Instruction> ──┐
//!   .knxprod/.mtxml ──► ProductData ──┐                                ├─► Downloader
//!                                     ├──► compile() ──► DeviceImage ──┘        │
//!   ProjectConfig ────────────────────┘                                          ▼
//!                                                                     DeviceConnection (RCo)
//! ```
//!
//! The mask layer is **always** required and never hardcoded — the
//! published master data describes 34 masks, MV-07B0 alone with 145
//! load-control instructions, and transcribing that by hand is how
//! drift gets in. See [`mask`] for where the file comes from.
//!
//! Design note: ETS interleaves the data writes implicitly (its engine
//! writes segment content while a machine is `Loading`); our compiled
//! procedures make them explicit [`Instruction::WriteImage`] steps —
//! byte-identical on the wire, inspectable in the IR.

pub mod assemble;
mod image;
mod image_layout;
mod interpreter;
pub mod ir;
pub mod mask;
pub mod product;
pub mod project;
mod table_coding;

pub use assemble::{ProcedureKind, assemble, assemble_controls};
pub use image::DeviceImage;
pub use interpreter::{DownloadTarget, Downloader, LoadControlPath};
pub use ir::{Instruction, controls_to_instructions};
pub use mask::{MASTER_DATA_ENV, MaskData, MaskDb, MemoryResources};
pub use product::{ComObjectDef, LoadProcedureStyle, ParameterLocation, ProductData, Segment};
pub use project::{CompiledDownload, GroupLink, ParameterValue, ProjectConfig, compile};
pub use table_coding::{Addr7, Addr8, Asso6, Asso8, Co7, ComObjectEntry, CotM112, CountWidth, TableCoding};
