//! Device State Storage
//!
//! Host-side persistence for the Linux device shells:
//!
//! - [`FileIdentity`] / [`FileSecureIdentity`] — the factory identity (serial
//!   number, FDSK), provisioned into a JSON file on first run;
//! - [`open_config_nv`] — the ETS configuration as write-through persistent
//!   sections in a binary file ([`LinuxConfigNv`]), with [`dump_config`] to
//!   print what a file holds;
//! - [`open_siat_store`] — the Data Secure sequence counters and SIAT in a
//!   file, for the secure shells.
//!
//! The config backend and the SIAT store plug into the framework's stores
//! structs (`ConfigStorage`, `SecureStorage`), so the host devices ride the
//! same router flush and `storage_task` as the embedded targets.

mod file_identity;
pub use file_identity::{FileIdentity, FileIdentityError, FileSecureIdentity};

mod nv_config;
pub use nv_config::{CONFIG_FILE_LEN, LinuxConfigNv, dump_config, open_config_nv};

mod secure_seq;
pub use secure_seq::{FileByteIo, LinuxSiatStore, SIAT_SLOTS, open_siat_store};
