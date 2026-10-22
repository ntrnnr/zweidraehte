//! Low-level credential-ordered management-session acquisition.
//!
//! These helpers open one connected device-management session without
//! compiling or executing a project programming operation. They deliberately
//! remain separate from the optional commissioning engine: diagnostics, unload recovery,
//! and sequence-number probes need raw access, while project programming must
//! go through the prepared Commissioner flow.

use zweidraehte_proto::address::IndividualAddress;

use crate::bus::{BusError as Error, BusResult as Result};
use crate::bus::{DeviceConnection, KnxBus};
use crate::security::{DeviceSecurityMode, SecurityEntry};

/// Borrowed management candidates, in Tool Key then FDSK order.
/// Application keys are intentionally outside this lower-layer interface.
#[derive(Clone, Copy)]
pub struct ManagementKeys<'a> {
    serial_number: Option<[u8; 6]>,
    tool_key: Option<&'a [u8; 16]>,
    fdsk: Option<&'a [u8; 16]>,
}

impl<'a> ManagementKeys<'a> {
    /// No secure credential: only plaintext access remains, where permitted.
    pub fn plaintext() -> Self {
        Self::from_parts(None, None, None)
    }

    /// Credentials for the device with this serial number. Secure session
    /// establishment needs it; add the device's keys with
    /// [`with_tool_key`](Self::with_tool_key) and [`with_fdsk`](Self::with_fdsk).
    ///
    /// ```
    /// # use zweidraehte_client::ManagementKeys;
    /// # let (serial_number, tool_key, factory_key) = ([0x00, 0xFA, 0, 0, 0, 1], [0x11; 16], [0x22; 16]);
    /// let credentials = ManagementKeys::for_serial(serial_number).with_tool_key(&tool_key).with_fdsk(&factory_key);
    /// ```
    pub fn for_serial(serial_number: [u8; 6]) -> Self {
        Self::from_parts(Some(serial_number), None, None)
    }

    /// The installed Tool Key, tried first.
    pub fn with_tool_key(self, tool_key: &'a [u8; 16]) -> Self {
        Self { tool_key: Some(tool_key), ..self }
    }

    /// The factory default setup key, tried when the Tool Key is absent or rejected.
    pub fn with_fdsk(self, fdsk: &'a [u8; 16]) -> Self {
        Self { fdsk: Some(fdsk), ..self }
    }

    /// Resolved key material, where each part may be missing.
    pub(crate) fn from_parts(
        serial_number: Option<[u8; 6]>,
        tool_key: Option<&'a [u8; 16]>,
        fdsk: Option<&'a [u8; 16]>,
    ) -> Self {
        Self { serial_number, tool_key, fdsk }
    }

    /// Sender probes must not fall back to a factory credential.
    pub fn tool_key_only(self) -> Self {
        Self { fdsk: None, ..self }
    }
}

impl std::fmt::Debug for ManagementKeys<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagementKeys")
            .field("serial_number", &self.serial_number)
            .field("tool_key", &self.tool_key.map(|_| "[REDACTED]"))
            .field("fdsk", &self.fdsk.map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Selected management credential epoch, without secret bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementCredential {
    Plaintext,
    ToolKey,
    Fdsk,
}

impl ManagementCredential {
    pub const fn is_secure(self) -> bool {
        !matches!(self, Self::Plaintext)
    }
}

/// Profile discovery performs its own descriptor validation; other callers
/// validate plaintext DD0 before accepting a session.
pub(crate) enum PlaintextAccess {
    Forbidden,
    Allowed { validate_descriptor: bool },
}

impl KnxBus {
    /// Try Tool Key, FDSK, then permitted plaintext validated by a readable DD0.
    pub async fn connect_management(
        &self,
        address: IndividualAddress,
        keys: ManagementKeys<'_>,
        allow_plaintext: bool,
    ) -> Result<(DeviceConnection, ManagementCredential)> {
        self.acquire_management(
            address,
            keys,
            if allow_plaintext {
                PlaintextAccess::Allowed { validate_descriptor: true }
            } else {
                PlaintextAccess::Forbidden
            },
            false,
        )
        .await
    }

    /// Force fresh secure synchronization, exposing authenticated remote sequence evidence.
    pub async fn connect_management_synchronized(
        &self,
        address: IndividualAddress,
        keys: ManagementKeys<'_>,
        allow_plaintext: bool,
    ) -> Result<(DeviceConnection, ManagementCredential)> {
        self.acquire_management(
            address,
            keys,
            if allow_plaintext {
                PlaintextAccess::Allowed { validate_descriptor: true }
            } else {
                PlaintextAccess::Forbidden
            },
            true,
        )
        .await
    }

    pub(crate) async fn acquire_management(
        &self,
        address: IndividualAddress,
        keys: ManagementKeys<'_>,
        plaintext: PlaintextAccess,
        force_sync: bool,
    ) -> Result<(DeviceConnection, ManagementCredential)> {
        for (credential, key) in
            [(ManagementCredential::ToolKey, keys.tool_key), (ManagementCredential::Fdsk, keys.fdsk)]
        {
            let Some(key) = key else { continue };
            let tool = credential == ManagementCredential::ToolKey;
            let entry = SecurityEntry::with_credentials(
                DeviceSecurityMode::Secure,
                tool.then_some(*key),
                keys.fdsk.copied(),
                keys.serial_number,
            )
            .expect("the selected credential is present");
            self.set_device_security(address, entry).await?;
            let opened = if force_sync {
                self.connect_device_synchronized(address).await
            } else {
                self.connect_device(address).await
            };
            match opened {
                Ok(connection) => return Ok((connection, credential)),
                // A failed durable sequence reservation must not become an
                // authentication miss and permit another credential or plain
                // access. Preserve the I/O failure for recovery callers too.
                Err(error @ Error::Io(_)) => return Err(error),
                Err(error) => log::debug!("{credential:?} management access failed: {error}"),
            }
        }

        if let PlaintextAccess::Allowed { validate_descriptor } = plaintext {
            self.remove_device_security(address).await?;
            if let Ok(mut connection) = self.connect_device(address).await {
                if !validate_descriptor
                    || connection
                        .device_descriptor_read(0)
                        .await
                        .is_ok_and(|descriptor| descriptor.len() >= 2 && descriptor[..2] != [0xff, 0xff])
                {
                    return Ok((connection, ManagementCredential::Plaintext));
                }
                let _ = connection.close().await;
            }
        }
        Err(Error::ManagementAccessUnavailable)
    }
}
