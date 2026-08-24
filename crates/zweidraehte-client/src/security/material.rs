//! Compatibility re-exports for the project-owned key vocabulary.
//!
//! Key identity and persistence are project concerns. Keeping this module
//! avoids breaking low-level client callers while the loader and TUI move to
//! [`zweidraehte_project::ProjectKeyStore`].

pub use zweidraehte_project::{
    DecodedFdsk, KeyEncoding, KeyEpoch, KeyId, KeyKind, KeyMaterialSource, KeyMaterialStore, KeyMaterialTransaction,
    KeyMetadata, KeyOrigin, KeyRecord, KeyScope, KeyState, KeyStoreError, SecretBytes, format_serial, parse_fdsk,
    parse_key16, parse_serial,
};
