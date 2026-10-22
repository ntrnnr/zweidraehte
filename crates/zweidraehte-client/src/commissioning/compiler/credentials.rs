//! Public identities of credentials a commissioning write replaces.
//!
//! Key material is ordinary compiled image content, exactly like every other
//! configured byte: a credential write reads its bytes from the program image
//! and is verified, observed and persisted with it. The compiler and client
//! are trusted, and project storage is secured at another level. What remains
//! special about these writes is their effect on the caller's credential
//! store, which this module names.

use std::num::NonZeroU8;
use zweidraehte_proto::address::GroupAddress;

/// Identity of a credential replaced by a confirmed commissioning write.
///
/// Execution reports and partial-failure diagnostics retain this metadata so
/// the caller can advance its credential store after the device accepted the
/// new value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CredentialTransition {
    ToolKey,
    IpBackboneKey,
    IpDeviceAuthenticationCode,
    IpPasswordHash { user_id: NonZeroU8 },
}

/// What a credential write changes besides its image bytes.
///
/// `transitions` advance once the whole write is confirmed. `group_keys` name
/// the group address of each 18-byte group-key row in write order, so a split
/// transfer reports exactly the rows that may have reached the device without
/// inferring keys from bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CredentialEffects {
    pub transitions: Vec<CredentialTransition>,
    pub group_keys: Vec<GroupAddress>,
}

impl CredentialEffects {
    pub fn transitions(transitions: Vec<CredentialTransition>) -> Self {
        Self { transitions, group_keys: Vec::new() }
    }

    pub fn group_keys(group_keys: Vec<GroupAddress>) -> Self {
        Self { transitions: Vec::new(), group_keys }
    }
}
