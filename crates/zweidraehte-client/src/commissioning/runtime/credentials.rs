//! Operational access policy and the concrete credential selected during discovery.

use crate::bus::access::ManagementCredential;
use std::fmt;
use zweidraehte_util::secret::SecretBytes;

/// Access policy for preparation. Device keys come from the materialized device.
pub struct ManagementAccessOptions {
    access_key: Option<SecretBytes>,
    pub(in crate::commissioning) allow_plaintext: bool,
}

impl ManagementAccessOptions {
    pub fn new() -> Self {
        Self { access_key: None, allow_plaintext: true }
    }

    /// Override the free-access key for profiles declaring `AuthorizeLevels`.
    pub fn with_access_key(mut self, key: [u8; 4]) -> Self {
        self.access_key = Some(key.into());
        self
    }

    pub const fn allow_plaintext(mut self, allow: bool) -> Self {
        self.allow_plaintext = allow;
        self
    }

    pub(in crate::commissioning) fn access_key(&self) -> Option<[u8; 4]> {
        self.access_key.as_ref().map(|key| key.as_slice().try_into().expect("access keys have fixed width"))
    }
}

impl Default for ManagementAccessOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ManagementAccessOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagementAccessOptions(REDACTED)")
    }
}

/// Secure variants own the key that made discovery succeed. There is no pending selection.
#[derive(Debug)]
pub(in crate::commissioning) enum ManagementAccess {
    Plaintext,
    ToolKey(SecretBytes),
    Fdsk(SecretBytes),
}

impl ManagementAccess {
    pub(in crate::commissioning) fn credential(&self) -> ManagementCredential {
        match self {
            Self::Plaintext => ManagementCredential::Plaintext,
            Self::ToolKey(_) => ManagementCredential::ToolKey,
            Self::Fdsk(_) => ManagementCredential::Fdsk,
        }
    }
}
