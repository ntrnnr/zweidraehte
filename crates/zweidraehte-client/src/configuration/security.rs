//! Owned security values shared by configuration and commissioning.
//!
//! Source selection, conflict policy and provenance construction belong to the
//! installation adapter. These values retain one set of application tables and
//! lend management credentials to the bus without teaching it project policy.

use crate::bus::access::ManagementCredentials;
use std::collections::BTreeMap;
use std::num::NonZeroU8;
use zweidraehte_project::KeyMetadata;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_util::secret::SecretBytes;

/// Private IP Secure bytes resolved alongside the public topology intent.
///
/// These values are passed only to prepared compilation. The inspectable
/// `CompiledProgram` contains opaque secret slots, never these bytes.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ResolvedIpSecureConfiguration {
    pub(crate) backbone_key: Option<SecretBytes>,
    pub(crate) device_authentication_code: Option<SecretBytes>,
    pub(crate) password_hashes: Vec<(NonZeroU8, SecretBytes)>,
}

impl ResolvedIpSecureConfiguration {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_backbone_key(mut self, key: Option<[u8; 16]>) -> Self {
        self.backbone_key = key.map(Into::into);
        self
    }

    pub fn with_device_authentication_code(mut self, code: Option<[u8; 16]>) -> Self {
        self.device_authentication_code = code.map(Into::into);
        self
    }

    pub fn with_password_hash(mut self, user_id: NonZeroU8, hash: [u8; 16]) -> Self {
        if let Some((_, existing)) = self.password_hashes.iter_mut().find(|(existing, _)| *existing == user_id) {
            *existing = hash.into();
        } else {
            self.password_hashes.push((user_id, hash.into()));
            self.password_hashes.sort_by_key(|(user_id, _)| *user_id);
        }
        self
    }

    pub fn backbone_key(&self) -> Option<&[u8; 16]> {
        self.backbone_key.as_ref().map(|key| key.key16_ref().expect("backbone keys have fixed width"))
    }

    pub fn device_authentication_code(&self) -> Option<&[u8; 16]> {
        self.device_authentication_code
            .as_ref()
            .map(|code| code.key16_ref().expect("device authentication codes have fixed width"))
    }

    pub fn password_hashes(&self) -> impl ExactSizeIterator<Item = (NonZeroU8, &[u8; 16])> {
        self.password_hashes
            .iter()
            .map(|(user_id, hash)| (*user_id, hash.key16_ref().expect("IP password hashes have fixed width")))
    }
}

impl core::fmt::Debug for ResolvedIpSecureConfiguration {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ResolvedIpSecureConfiguration")
            .field("backbone_key", &self.backbone_key.as_ref().map(|_| "[REDACTED]"))
            .field("device_authentication_code", &self.device_authentication_code.as_ref().map(|_| "[REDACTED]"))
            .field("password_users", &self.password_hashes.iter().map(|(user_id, _)| *user_id).collect::<Vec<_>>())
            .finish()
    }
}

/// Key material and device tables resolved before any bus mutation.
#[derive(Clone)]
pub struct ResolvedKeyMaterial {
    serial_number: Option<[u8; 6]>,
    fdsk: Option<SecretBytes>,
    tool_key: Option<SecretBytes>,
    application_security: Option<SecurityConfig>,
    ip_secure: Option<ResolvedIpSecureConfiguration>,
    secured_groups: BTreeMap<GroupAddress, GroupObjectProtection>,
    needs_tool_key_generation: bool,
    /// Non-secret audit trail for every value which participated in the
    /// merge. Equal values retain both origins instead of collapsing into an
    /// untraceable byte array.
    provenance: Vec<KeyMetadata>,
}

impl core::fmt::Debug for ResolvedKeyMaterial {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ResolvedKeyMaterial")
            .field("serial_number", &self.serial_number)
            .field("fdsk", &self.fdsk.as_ref().map(|_| "[REDACTED]"))
            .field("tool_key", &self.tool_key.as_ref().map(|_| "[REDACTED]"))
            .field("application_security", &self.application_security.as_ref().map(|_| "[REDACTED]"))
            .field("ip_secure", &self.ip_secure)
            .field("secured_groups", &self.secured_groups)
            .field("needs_tool_key_generation", &self.needs_tool_key_generation)
            .field("provenance", &self.provenance)
            .finish()
    }
}

impl ResolvedKeyMaterial {
    pub fn management_credentials(&self) -> ManagementCredentials<'_> {
        ManagementCredentials::new(self.serial_number, self.tool_key(), self.fdsk())
    }

    pub fn new(serial_number: Option<[u8; 6]>) -> Self {
        Self {
            serial_number,
            fdsk: None,
            tool_key: None,
            application_security: None,
            ip_secure: None,
            secured_groups: BTreeMap::new(),
            needs_tool_key_generation: false,
            provenance: Vec::new(),
        }
    }

    pub fn with_fdsk(mut self, fdsk: Option<[u8; 16]>) -> Self {
        self.fdsk = fdsk.map(Into::into);
        self
    }

    pub fn with_tool_key(mut self, tool_key: Option<[u8; 16]>) -> Self {
        self.tool_key = tool_key.map(Into::into);
        self
    }

    pub fn with_application_security(mut self, security: Option<SecurityConfig>) -> Self {
        self.application_security = security;
        self
    }

    pub fn with_ip_secure(mut self, security: Option<ResolvedIpSecureConfiguration>) -> Self {
        self.ip_secure = security;
        self
    }

    pub fn with_secured_groups(mut self, secured_groups: BTreeMap<GroupAddress, GroupObjectProtection>) -> Self {
        self.secured_groups = secured_groups;
        self
    }

    pub fn requiring_tool_key_generation(mut self) -> Self {
        self.needs_tool_key_generation = true;
        self
    }

    pub fn with_provenance(mut self, provenance: Vec<KeyMetadata>) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn serial_number(&self) -> Option<[u8; 6]> {
        self.serial_number
    }

    pub fn fdsk(&self) -> Option<&[u8; 16]> {
        self.fdsk.as_ref().map(|key| key.key16_ref().expect("FDSKs have fixed width"))
    }

    pub fn tool_key(&self) -> Option<&[u8; 16]> {
        self.tool_key.as_ref().map(|key| key.key16_ref().expect("tool keys have fixed width"))
    }

    pub fn application_security(&self) -> Option<&SecurityConfig> {
        self.application_security.as_ref()
    }

    pub fn ip_secure(&self) -> Option<&ResolvedIpSecureConfiguration> {
        self.ip_secure.as_ref()
    }

    pub fn secured_groups(&self) -> &BTreeMap<GroupAddress, GroupObjectProtection> {
        &self.secured_groups
    }

    pub fn needs_tool_key_generation(&self) -> bool {
        self.needs_tool_key_generation
    }

    pub fn provenance(&self) -> &[KeyMetadata] {
        &self.provenance
    }
}

/// Installation-specific KNX Data Secure tables.
#[derive(Clone, Default)]
pub struct SecurityConfig {
    group_keys: Vec<(GroupAddress, SecretBytes)>,
    siat: Vec<(IndividualAddress, u64)>,
    group_objects: Vec<GroupObjectSecurity>,
}

impl SecurityConfig {
    pub fn new(
        group_keys: Vec<(GroupAddress, [u8; 16])>,
        siat: Vec<(IndividualAddress, u64)>,
        group_objects: Vec<GroupObjectSecurity>,
    ) -> Self {
        Self {
            group_keys: group_keys.into_iter().map(|(address, key)| (address, key.into())).collect(),
            siat,
            group_objects,
        }
    }

    pub fn group_keys(&self) -> impl ExactSizeIterator<Item = (GroupAddress, &[u8; 16])> {
        self.group_keys.iter().map(|(address, key)| (*address, key.key16_ref().expect("group keys have fixed width")))
    }

    pub fn siat(&self) -> &[(IndividualAddress, u64)] {
        &self.siat
    }

    pub fn group_objects(&self) -> &[GroupObjectSecurity] {
        &self.group_objects
    }
}

impl core::fmt::Debug for SecurityConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SecurityConfig")
            .field("group_keys", &format_args!("[REDACTED; {} entries]", self.group_keys.len()))
            .field("siat", &self.siat)
            .field("group_objects", &self.group_objects)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupObjectSecurity {
    pub com_object: u16,
    pub protection: GroupObjectProtection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GroupObjectProtection {
    Plain,
    Authentication,
    AuthenticationConfidentiality,
}

// Project coordination fills generated credentials and authenticated replay floors
// after resolving the immutable compiler inputs. Keep that mutation surface local.
#[cfg(feature = "project")]
mod project {
    use super::*;

    impl ResolvedKeyMaterial {
        pub(crate) fn application_security_mut(&mut self) -> Option<&mut SecurityConfig> {
            self.application_security.as_mut()
        }

        /// Install the value with provenance supplied by the owning adapter.
        pub(crate) fn install_generated_tool_key(&mut self, key: [u8; 16], metadata: KeyMetadata) {
            self.tool_key = Some(key.into());
            self.needs_tool_key_generation = false;
            self.provenance.push(metadata);
        }

        /// Transfer already checked secrets without copying them through raw arrays.
        pub(crate) fn with_management_secrets(
            mut self,
            fdsk: Option<SecretBytes>,
            tool_key: Option<SecretBytes>,
        ) -> Self {
            self.fdsk = fdsk;
            self.tool_key = tool_key;
            self
        }
    }

    impl SecurityConfig {
        pub(crate) fn replace_siat(&mut self, siat: Vec<(IndividualAddress, u64)>) {
            self.siat = siat;
        }
    }
}
