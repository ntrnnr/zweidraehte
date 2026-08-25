//! ETS-style device configuration download (03/05/02 download
//! procedures).
//!
//! Structured the way ETS is, in three layers with different sources
//! and different lifetimes:
//!
//! | Layer | Source | Per | Carries |
//! |---|---|---|---|
//! | [`mask`] | `knx_master.xml` | mask version | resource locations, procedure templates |
//! | [`zweidraehte_ets_files::product`] | `.knxprod` / MTXML | product | segments, load procedures, object and parameter layout |
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
pub mod configuration;
mod image;
mod interpreter;
pub mod ir;
pub mod mask;
mod model;
mod preview;
pub mod product_configuration;
pub mod project;
mod table_coding;

pub use assemble::{DownloadScope, ProcedureKind, assemble, assemble_controls, procedure_kind_for_scope};
pub use configuration::{
    DeviceConfiguration, DeviceIdentity, LoweredDeviceConfiguration, MembershipRole, NetSecurityPolicy,
    ObjectMembership,
};
pub use image::DeviceImage;
pub(crate) use interpreter::LoadedProperty;
#[cfg(test)]
pub(crate) use interpreter::system_b_tests::{MASK_XML as SYSTEM_B_MASK_XML, PRODUCT_XML as SYSTEM_B_PRODUCT_XML};
pub use interpreter::{DownloadEvent, DownloadTarget, Downloader, LoadControlPath, MemoryService, ProgressSink};
pub use ir::{Instruction, InstructionData, LsmTarget, controls_to_instructions};
pub use zweidraehte_ets_files::product::ApplicationIdentity;
// The IR embeds proto's load-control vocabulary; re-exported so
// consumers can match on `Instruction` fields without a direct proto
// dependency.
pub use mask::{MASTER_DATA_ENV, MachineRole, MaskData, MaskDb, MemoryResources, select_download_mask};
pub use model::{DownloadModel, LoadControlPolicy, MemoryServicePolicy};
pub use preview::{
    ConfigurationPreview, ConfigurationPreviewBuilder, PreviewCompleteness, PreviewPlacement, PreviewSegment,
    PreviewTableKind, PreviewTableSpan,
};
pub use product_configuration::{ResolvedProject, resolve_product_configuration};
pub use project::{
    CompiledDownload, GroupLink, GroupObjectProtection, GroupObjectSecurity, ParameterValue, ProjectConfig,
    SecurityConfig, compile, compile_scoped, load_control_path,
};
pub use table_coding::{
    Addr1, Addr2, Addr7, Addr8, Asso1, Asso2, Asso6, Asso8, Co7, ComObjectEntry, ComObjectEntry2, Cot1, Cot2,
    CountWidth, System7AssociationTableCoding, System7ComObjectTableCoding, TableCoding,
};
pub use zweidraehte_ets_files::product::{
    ComObjectDef, FixupDef, LoadProcedureStyle, ParameterLocation, ProductData, Segment,
};
pub use zweidraehte_proto::messages::apdu::load_control::{LoadEvent, LoadState};

/// Convert a device/interface wire APDU ceiling into the budget available to
/// the management service carried inside it.
///
/// PID 56 limits the complete APDU on the wire. Data Secure wraps the original
/// management APDU in an S-A_Data envelope, so every download entry point must
/// reserve that overhead before the interpreter chooses chunk sizes.
pub(crate) fn management_plaintext_apdu_budget(wire_max_apdu: u16, data_secure: bool) -> u16 {
    if data_secure {
        wire_max_apdu.saturating_sub(zweidraehte_proto::messages::apdu::secure::OVERHEAD as u16)
    } else {
        wire_max_apdu
    }
}

#[cfg(test)]
mod tests {
    use super::management_plaintext_apdu_budget;

    #[test]
    fn secure_management_reserves_the_data_secure_envelope() {
        assert_eq!(management_plaintext_apdu_budget(40, false), 40);
        assert_eq!(management_plaintext_apdu_budget(40, true), 27);
    }
}
