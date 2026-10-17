//! Session management services.

use super::{AuthorizationPolicy, ExecutionSession, mutating_request_may_have_reached_device};
use crate::bus::BusError as ClientError;
use crate::bus::DeviceConnection;
use crate::commissioning::compiler::secrets::CredentialTransition;
use crate::commissioning::error::{CleanupOperation, Diagnostic};
use crate::commissioning::procedure::OperationExtent;
use crate::commissioning::procedure::operands::{OperationTarget, PropertyAddress};
use crate::commissioning::procedure::{RestartKind, ToolState};
use crate::commissioning::runtime::credentials::ManagementAccess;
use std::time::Duration;
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::apdu::restart::EraseCode;
use zweidraehte_proto::pid;

impl ExecutionSession<'_> {
    pub(in crate::commissioning) fn bind_access(&mut self, authorization: AuthorizationPolicy, target_max_apdu: u16) {
        self.config.authorization = authorization;
        self.config.target_max_apdu = target_max_apdu;
    }

    /// Invalidate observed bytes before changing the device's security mode.
    pub(crate) async fn enable_data_security(&mut self) -> Result<(), Diagnostic> {
        self.images.forget_device();
        self.connection_mut()?.enable_security_mode().await.map_err(|error| self.mutating_client_error(error))?;
        self.record_mutation();
        Ok(())
    }

    pub(crate) async fn bootstrap_tool_key(&mut self) -> Result<(), Diagnostic> {
        let key = self
            .replacement_tool_key
            .as_ref()
            .ok_or_else(|| Diagnostic::new("security bootstrap has no Tool Key"))?
            .key16()
            .expect("replacement Tool Key width");
        self.images.forget_device();
        self.connection_mut()?.write_tool_key(key).await.map_err(|error| self.mutating_client_error(error))?;
        // Preserve the confirmed replacement if sequence advancement or a
        // subsequent restart fails. The connection commits its key likewise.
        self.access = ManagementAccess::ToolKey(key.into());
        self.record_mutation();
        self.effects.record_credentials([CredentialTransition::ToolKey]);
        Ok(())
    }

    pub(crate) async fn advance_sending_sequence(&mut self, serial: Option<[u8; 6]>) -> Result<(), Diagnostic> {
        let reported = self
            .connection_mut()?
            .property_ext_read(InterfaceObjectType::Security, 1, pid::security::SEQUENCE_NUMBER_SENDING, 1, 1)
            .await?;
        let reported: [u8; 6] = reported.try_into().map_err(|_| Diagnostic::new("PID 59 is not a six-octet value"))?;
        let reported = reported.into_iter().fold(0u64, |value, byte| value << 8 | u64::from(byte));
        let stored = match serial {
            Some(serial) => self.bus.device_sequence_floor(serial).await?,
            None => 1,
        };
        let selected = reported.max(stored).max(crate::security::knx_sequence_timestamp_floor()).max(1);
        if selected > 0xFFFF_FFFF_FFFF {
            return Err(Diagnostic::new("PID 59 exceeds the KNX 48-bit range"));
        }
        self.connection_mut()?
            .property_ext_write(
                InterfaceObjectType::Security,
                1,
                pid::security::SEQUENCE_NUMBER_SENDING,
                1,
                1,
                &selected.to_be_bytes()[2..],
            )
            .await
            .map_err(|error| self.mutating_client_error(error))?;
        self.record_mutation();
        Ok(())
    }

    pub(crate) async fn finish<T>(&mut self, result: Result<T, Diagnostic>) -> Result<T, Diagnostic> {
        CleanupOperation::Disconnect.combine(result, self.disconnect().await)
    }

    pub(crate) async fn connect_at(
        &mut self,
        target: zweidraehte_proto::address::IndividualAddress,
    ) -> Result<(), Diagnostic> {
        self.disconnect().await?;
        self.target = target;
        self.connect().await
    }

    pub(crate) fn connection_mut(&mut self) -> Result<&mut DeviceConnection, Diagnostic> {
        self.connection.as_mut().ok_or_else(|| Diagnostic::new("management connection is not open"))
    }

    pub(crate) async fn set_memory_verify_mode(&mut self, enabled: bool) -> Result<(), Diagnostic> {
        if !self.config.verify_mode {
            if enabled {
                return Err(Diagnostic::new("device profile does not advertise classic-memory Verify Mode"));
            }

            return Ok(());
        }

        let current = match self.current_device_control {
            Some(value) => value,
            _ => {
                let result = {
                    let connection = self.connection_mut()?;
                    connection.property_read(0, pid::DEVICE_CONTROL, 1, 1).await
                };
                let bytes = result?;
                let value = bytes
                    .first()
                    .copied()
                    .ok_or_else(|| Diagnostic::new("PID_DEVICE_CONTROL returned an empty value"))?;

                self.original_device_control.get_or_insert(value);
                self.current_device_control = Some(value);
                value
            }
        };

        let updated = if enabled {
            current | pid::device_control::VERIFY_MODE
        } else {
            current & !pid::device_control::VERIFY_MODE
        };

        if updated == current {
            return Ok(());
        }

        self.write_device_control(updated).await
    }

    async fn write_device_control(&mut self, value: u8) -> Result<(), Diagnostic> {
        self.images.invalidate_target(
            &OperationTarget::Property {
                address: PropertyAddress::Indexed { object_index: 0, property_id: pid::DEVICE_CONTROL as u8 },
                start_element: 1,
            },
            OperationExtent::property(1, 1),
        );
        let result = {
            let connection = self.connection_mut()?;
            connection.property_write(0, pid::DEVICE_CONTROL, 1, 1, &[value]).await
        };
        if let Err(error) = result {
            if mutating_request_may_have_reached_device(&error) {
                self.current_device_control = None;
            }

            return Err(self.mutating_client_error(error));
        }

        self.current_device_control = Some(value);
        self.record_mutation();
        Ok(())
    }

    pub(crate) async fn connect(&mut self) -> Result<(), Diagnostic> {
        let fresh_connection = self.connection.is_none();
        self.open_without_authorization().await?;
        if let Err(primary) = self.authorize().await {
            let connection = self.connection.take().expect("authorization follows opening");
            return match connection.close().await {
                Ok(()) | Err(ClientError::TransportClosed) => Err(primary),
                Err(error) => Err(primary.with_cleanup_failure(CleanupOperation::Disconnect, Diagnostic::from(error))),
            };
        }
        if fresh_connection {
            // Native fresh Connect identifies the mask again. This restores
            // authored mask metadata, never previously observed descriptors.
            self.activate_indexed_mask_seeds();
        }
        Ok(())
    }

    pub(crate) async fn connect_without_authorization_at(
        &mut self,
        target: zweidraehte_proto::address::IndividualAddress,
    ) -> Result<(), Diagnostic> {
        self.disconnect().await?;
        self.target = target;
        self.open_without_authorization().await
    }

    async fn open_without_authorization(&mut self) -> Result<(), Diagnostic> {
        if self.connection.is_some() {
            return Err(Diagnostic::new("management connection is already open"));
        }
        self.install_security().await?;
        self.connection = Some(self.bus.connect_device(self.target).await?);
        Ok(())
    }

    pub(crate) async fn authorize(&mut self) -> Result<(), Diagnostic> {
        if let AuthorizationPolicy::LegacyKey { key, required_level } = self.config.authorization.clone() {
            let granted =
                self.connection_mut()?.authorize(key.as_slice().try_into().expect("legacy key width")).await?;
            if granted > required_level {
                return Err(Diagnostic::new(format!(
                    "authorization granted level {granted}, but level {required_level} or stronger is required"
                )));
            }
        }
        Ok(())
    }

    pub(crate) async fn disconnect(&mut self) -> Result<(), Diagnostic> {
        if self.connection.is_none() {
            // Native Disconnect clears indexed state even when no transport
            // connection was opened. Type-addressed descriptors survive.
            self.forget_indexed_property_state();
            return Ok(());
        }

        let restore = self.mandatory_restore().await;
        let connection = self.connection.take().expect("connection was checked above");
        let close = connection.close().await.map_err(Diagnostic::from);
        self.original_device_control = None;
        self.current_device_control = None;
        // Disconnect discards indexed object state. Descriptors addressed by
        // object type survive, unlike an explicit clear-cache control.
        self.forget_indexed_property_state();

        CleanupOperation::Disconnect.combine(restore, close)
    }

    pub(crate) async fn apply_state(&mut self, previous: ToolState, next: ToolState) -> Result<(), Diagnostic> {
        if self.connection.is_some()
            && (previous.memory_auto_verify != next.memory_auto_verify
                || (self.original_device_control.is_some() && self.current_device_control.is_none()))
        {
            match next.memory_auto_verify {
                Some(true) => self.set_memory_verify_mode(true).await?,
                Some(false) | None => self.set_memory_verify_mode(false).await?,
            }
        }

        Ok(())
    }

    pub(crate) async fn restore_state(&mut self) -> Result<(), Diagnostic> {
        let Some(original) = self.original_device_control else {
            return Ok(());
        };
        if self.current_device_control == Some(original) {
            return Ok(());
        }

        self.write_device_control(original).await
    }

    async fn mandatory_restore(&mut self) -> Result<(), Diagnostic> {
        self.restore_state().await.map_err(|error| {
            Diagnostic::new("restoring device-wide state fails")
                .with_cleanup_failure(CleanupOperation::RestoreDeviceState, error)
        })
    }

    pub(crate) async fn restart_device(&mut self, kind: RestartKind) -> Result<(), Diagnostic> {
        if kind == RestartKind::Confirmed {
            return self.reset_device(EraseCode::Confirmed.into(), 0).await;
        }
        self.mandatory_restore().await?;
        let programmed = self.images.take_programmed_image();
        self.images.forget_device();
        match self.connection_mut()?.restart().await {
            Ok(()) | Err(ClientError::TransportClosed) => self.record_mutation(),
            Err(error) => return Err(self.mutating_client_error(error)),
        }
        self.close_after_restart(Duration::ZERO).await?;
        self.images.preserve_restart_snapshot(programmed);
        Ok(())
    }

    pub(crate) async fn reset_device(&mut self, erase_code: u8, channel: u8) -> Result<(), Diagnostic> {
        if erase_code > 7 {
            return Err(Diagnostic::new(format!("master-reset erase code {erase_code:#04x} is not defined")));
        }
        self.mandatory_restore().await?;
        self.connection_mut()?;
        let programmed = self.images.take_programmed_image();
        self.images.forget_device();

        let result = {
            let connection = self.connection_mut()?;
            connection.master_reset(EraseCode::from(erase_code), channel).await
        };
        let acknowledgement = result.map_err(|error| self.mutating_client_error(error))?;
        self.record_mutation();
        self.close_after_restart(acknowledgement.process_time).await?;
        self.effects.confirm_reset(EraseCode::from(erase_code), channel);
        if erase_code <= u8::from(EraseCode::Confirmed) {
            self.images.preserve_restart_snapshot(programmed);
        }
        Ok(())
    }

    pub(crate) async fn close_after_restart(&mut self, process_time: Duration) -> Result<(), Diagnostic> {
        self.images.forget_device();
        self.forget_indexed_property_state();
        if let Some(connection) = self.connection.take() {
            // The reset acknowledgement precedes the reset itself. Closing
            // the transport connection is the commit boundary on devices
            // that defer the reset until the session ends.
            match connection.close().await {
                Ok(()) | Err(ClientError::TransportClosed) => {}
                Err(error) => return Err(Diagnostic::from(error)),
            }
        }
        self.original_device_control = None;
        self.current_device_control = None;

        let restart_delay = process_time.max(self.config.minimum_restart_delay);
        if !restart_delay.is_zero() {
            tokio::time::sleep(restart_delay).await;
        }

        Ok(())
    }
}
