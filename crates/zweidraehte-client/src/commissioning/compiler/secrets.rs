//! Opaque secret handles and the zeroizing store owned by a compilation.
//!
//! Allocation identities prevent cross-compilation references from binding to
//! unrelated bytes. Debug output reveals only lengths.

use crate::commissioning::error::CompileError;
use crate::commissioning::error::SecretPayloadError;
use crate::commissioning::procedure::{Comparison, NormalizedProcedure, OperationData, ProcedureOperation};
use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU8;
use std::sync::atomic::{AtomicU64, Ordering};
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_util::secret::SecretBytes;

/// Non-secret identity of a credential replaced by a confirmed commissioning
/// write.
///
/// Execution reports and partial-failure diagnostics retain this metadata so
/// the caller can advance its credential store without exposing the new bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CredentialTransition {
    ToolKey,
    IpBackboneKey,
    IpDeviceAuthenticationCode,
    IpPasswordHash { user_id: NonZeroU8 },
}

/// Opaque handle from a public plan to one privately retained byte string.
///
/// A handle intentionally has no content-derived commitment. A public hash of
/// a 128-bit group key would let anyone with a candidate confirm that key
/// offline, which is unnecessary for executing or previewing a download.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretPayloadReference {
    allocation: u64,
    byte_length: u32,
}

impl SecretPayloadReference {
    pub const fn byte_length(self) -> u32 {
        self.byte_length
    }
}

impl fmt::Debug for SecretPayloadReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SecretPayloadReference").field("byte_length", &self.byte_length).finish()
    }
}

/// Secret material compiled alongside, but never into, a public plan.
///
/// `SecretBytes` zeroizes every payload on drop. The custom debug output is
/// intentionally useful only for structural diagnostics.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct SecretCommissioningPayload {
    values: BTreeMap<u64, SecretPayloadEntry>,
}

#[derive(Clone, PartialEq, Eq)]
struct SecretPayloadEntry {
    value: SecretBytes,
    transitions: Vec<CredentialTransition>,
    group_keys: Vec<GroupAddress>,
}

// Identities are unrelated to secret bytes and never enter public diagnostics.
// Retaining them across clones preserves existing handles. Each inserted value
// gets a new identity, including independently extended clones of one store.
fn next_secret_identity() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| value.checked_add(1))
        .expect("secret binding identity space cannot be exhausted")
}

impl SecretCommissioningPayload {
    pub(crate) fn insert(&mut self, value: SecretBytes) -> Result<SecretPayloadReference, SecretPayloadError> {
        self.insert_with_transitions(value, Vec::new())
    }

    pub(crate) fn insert_with_transitions(
        &mut self,
        value: SecretBytes,
        transitions: Vec<CredentialTransition>,
    ) -> Result<SecretPayloadReference, SecretPayloadError> {
        let byte_length = u32::try_from(value.len()).map_err(|_| SecretPayloadError::SecretPayloadTooLarge)?;
        let allocation = next_secret_identity();
        self.values.insert(allocation, SecretPayloadEntry { value, transitions, group_keys: Vec::new() });

        Ok(SecretPayloadReference { allocation, byte_length })
    }

    pub(crate) fn insert_group_keys(
        &mut self,
        value: SecretBytes,
        group_keys: Vec<GroupAddress>,
    ) -> Result<SecretPayloadReference, SecretPayloadError> {
        if group_keys.len().checked_mul(18) != Some(value.len()) {
            return Err(SecretPayloadError::GroupKeyRows);
        }
        let reference = self.insert(value)?;
        self.values.get_mut(&reference.allocation).expect("payload was inserted").group_keys = group_keys;
        Ok(reference)
    }

    pub(crate) fn group_keys(&self, reference: SecretPayloadReference) -> Result<&[GroupAddress], SecretPayloadError> {
        Ok(&self.entry(reference)?.group_keys)
    }

    pub(crate) fn resolve(&self, reference: SecretPayloadReference) -> Result<&[u8], SecretPayloadError> {
        Ok(self.entry(reference)?.value.as_slice())
    }

    fn entry(&self, reference: SecretPayloadReference) -> Result<&SecretPayloadEntry, SecretPayloadError> {
        let entry =
            self.values.get(&reference.allocation).ok_or(SecretPayloadError::MissingSecretPayload(reference))?;
        if entry.value.len() != reference.byte_length as usize {
            return Err(SecretPayloadError::SecretPayloadLength { reference, actual: entry.value.len() });
        }

        Ok(entry)
    }

    pub(crate) fn transitions(
        &self,
        reference: SecretPayloadReference,
    ) -> Result<&[CredentialTransition], SecretPayloadError> {
        Ok(&self.entry(reference)?.transitions)
    }

    #[cfg(test)]
    pub(crate) fn insert_for_test(&mut self, value: SecretBytes) -> SecretPayloadReference {
        self.insert(value).expect("test secret payload fits")
    }
}

/// Validate every selected reference before binding permits network mutations.
pub(crate) fn validate_secret_bindings(
    procedure: &NormalizedProcedure,
    secret_payload: Option<&SecretCommissioningPayload>,
) -> Result<(), CompileError> {
    for step in &procedure.steps {
        match &step.operation {
            ProcedureOperation::Write { data: OperationData::Secret(reference), extent, .. } => {
                let result = secret_payload
                    .ok_or_else(|| "the prepared secret payload is unavailable".to_owned())
                    .and_then(|payload| payload.resolve(*reference).map_err(|error| error.to_string()))
                    .and_then(|bytes| {
                        if bytes.len() == extent.byte_length as usize {
                            Ok(())
                        } else {
                            Err(format!(
                                "secret payload has {} bytes, expected {} for the write",
                                bytes.len(),
                                extent.byte_length
                            ))
                        }
                    });
                result.map_err(|message| CompileError::invalid(message).with_path(&step.path))?;
            }
            ProcedureOperation::Compare {
                comparison: Comparison::Exact { data: OperationData::Secret(_), .. },
                ..
            } => {
                return Err(CompileError::invalid("secret payload references are valid only for prepared writes")
                    .with_path(&step.path));
            }
            _ => {}
        }
    }
    Ok(())
}

impl fmt::Debug for SecretCommissioningPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let byte_length: usize = self.values.values().map(|entry| entry.value.len()).sum();
        let transitions: usize = self.values.values().map(|entry| entry.transitions.len()).sum();

        formatter
            .debug_struct("SecretCommissioningPayload")
            .field("entries", &self.values.len())
            .field("byte_length", &byte_length)
            .field("credential_transitions", &transitions)
            .field("values", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests;
