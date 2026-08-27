//! Connection-oriented (RCo) device management.

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::apdu::auth::{AuthorizeRequest, AuthorizeResponse};
use zweidraehte_proto::messages::apdu::device::{DeviceDescriptorRead, DeviceDescriptorResponse};
use zweidraehte_proto::messages::apdu::function_property::{FunctionPropertyHeader, FunctionPropertyResponse};
use zweidraehte_proto::messages::apdu::memory::{
    MemoryExtendedAccess, MemoryExtendedResponse, MemoryReadRequest, MemoryResponse, MemoryWriteRequest,
};
use zweidraehte_proto::messages::apdu::property::{
    PropertyDescriptionRead, PropertyValueHeader, PropertyValueResponse,
};
use zweidraehte_proto::messages::apdu::property_ext::{
    FunctionPropertyExtHeader, FunctionPropertyExtRequest, PropertyExtValueHeader, PropertyExtValueRequest,
    PropertyReturnCode,
};
use zweidraehte_proto::messages::apdu::restart::{EraseCode, RestartError, RestartParsed, RestartResponse};
use zweidraehte_proto::messages::knx::{ApciCode, Tpci, offsets};
use zweidraehte_proto::pid;

use crate::core::frames;
use crate::core::management::{self, FunctionPropertyResult, PropertyDescription};
use crate::driver::BusCommand;
use crate::error::{Error, Result};

/// A point-to-point transport connection to a KNX device
/// (`DMP_Connect_RCo`, 03/05/02 §3.2).
///
/// Created via [`KnxBus::connect_device`](crate::KnxBus::connect_device).
/// All management methods run as connected (numbered) transport data with
/// T_ACK handling, retransmission and connection supervision per 03/03/04
/// §5.4 Style 3. Close with [`close`](Self::close); a dropped handle
/// leaves the device to time the connection out (6 s).
pub struct DeviceConnection {
    addr: IndividualAddress,
    cmd_tx: mpsc::Sender<BusCommand>,
    last_security_sync_remote_sequence: Option<u64>,
}

/// Outcome of a master reset: how long the device says it needs before it
/// is reachable again.
#[derive(Debug, Clone, Copy)]
pub struct RestartAck {
    pub process_time: Duration,
}

impl DeviceConnection {
    pub(crate) fn new(
        addr: IndividualAddress,
        cmd_tx: mpsc::Sender<BusCommand>,
        last_security_sync_remote_sequence: Option<u64>,
    ) -> Self {
        Self { addr, cmd_tx, last_security_sync_remote_sequence }
    }

    /// The device this connection talks to.
    pub fn address(&self) -> IndividualAddress {
        self.addr
    }

    /// The exact `SeqNrremote` from this connection's latest authenticated
    /// `S-A_Sync_Res`, if a sync has occurred.
    ///
    /// This is the device's next sending sequence number. It is distinct from
    /// PID 59, which commissioning may read and replace, and from a live
    /// receiver's “last valid” state, which 03/03/07 represents as one less.
    pub fn last_security_sync_remote_sequence(&self) -> Option<u64> {
        self.last_security_sync_remote_sequence
    }

    // ========================================================================
    // Request plumbing
    // ========================================================================

    /// Send a connected request expecting the mapped response service.
    async fn request(
        &mut self,
        apci: ApciCode,
        msg_len: usize,
        data_writer: impl FnOnce(&mut [u8]),
    ) -> Result<Vec<u8>> {
        let expected_apci = management::expected_response_apci(apci);
        self.request_raw(apci, msg_len, data_writer, true, expected_apci).await
    }

    /// Send a connected request that resolves on the device's T_ACK.
    async fn request_no_response(
        &mut self,
        apci: ApciCode,
        msg_len: usize,
        data_writer: impl FnOnce(&mut [u8]),
    ) -> Result<()> {
        self.request_raw(apci, msg_len, data_writer, false, None).await.map(|_| ())
    }

    async fn request_raw(
        &mut self,
        apci: ApciCode,
        msg_len: usize,
        data_writer: impl FnOnce(&mut [u8]),
        expects_response: bool,
        expected_apci: Option<ApciCode>,
    ) -> Result<Vec<u8>> {
        // Sequence number 0 and the zero source address are placeholders;
        // the bus task stamps the live sequence number and the connector's
        // assigned address when the frame goes out.
        let frame = frames::build_individual_frame(
            IndividualAddress::new(0, 0, 0),
            self.addr,
            Tpci::DataConnected(0),
            apci,
            msg_len,
            data_writer,
        );
        self.send_request(frame, expects_response, expected_apci).await
    }

    async fn send_request(
        &self,
        frame: Vec<u8>,
        expects_response: bool,
        expected_apci: Option<ApciCode>,
    ) -> Result<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BusCommand::TlRequest { frame, expects_response, expected_apci, tx })
            .await
            .map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)?
    }

    // ========================================================================
    // Management services
    // ========================================================================

    /// Read a property value (`DMP_InterfaceObjectRead_R`).
    pub async fn property_read(&mut self, obj_idx: u8, prop_id: u16, start_idx: u16, count: u16) -> Result<Vec<u8>> {
        let buf = self
            .request(ApciCode::PropertyValueRead, PropertyValueHeader::MIN_MSG_LEN, |buf| {
                PropertyValueResponse::write(buf, obj_idx, prop_id, count, start_idx, &[])
            })
            .await?;
        let hdr = PropertyValueHeader::parse(&buf).ok_or(Error::Parse("PropertyValueResponse too short"))?;
        if hdr.count == 0 {
            return Err(Error::DeviceError(0));
        }
        Ok(hdr.data(&buf).to_vec())
    }

    /// Write a property value (`DMP_InterfaceObjectWrite_R`).
    pub async fn property_write(
        &mut self,
        obj_idx: u8,
        prop_id: u16,
        start_idx: u16,
        count: u16,
        data: &[u8],
    ) -> Result<()> {
        let buf = self
            .request(ApciCode::PropertyValueWrite, PropertyValueResponse::msg_len(data.len()), |buf| {
                PropertyValueResponse::write(buf, obj_idx, prop_id, count, start_idx, data)
            })
            .await?;
        let hdr = PropertyValueHeader::parse(&buf).ok_or(Error::Parse("PropertyValueResponse too short"))?;
        if hdr.count == 0 {
            return Err(Error::DeviceError(0));
        }
        Ok(())
    }

    /// Read a property through AN163 extended object addressing.
    pub async fn property_ext_read(
        &mut self,
        object_type: InterfaceObjectType,
        object_instance: u16,
        prop_id: u16,
        start_idx: u16,
        count: u16,
    ) -> Result<Vec<u8>> {
        let raw_object_type = u16::from(object_type);
        let count = u8::try_from(count).map_err(|_| Error::Parse("extended property count exceeds one octet"))?;
        let buf = self
            .request(ApciCode::PropertyExtValueRead, PropertyExtValueRequest::msg_len(0), |buf| {
                PropertyExtValueRequest::write(buf, raw_object_type, object_instance, prop_id, count, start_idx, &[])
            })
            .await?;
        let hdr = PropertyExtValueHeader::parse(&buf).ok_or(Error::Parse("PropertyExtValueResponse too short"))?;
        if (hdr.object_type, hdr.object_instance, hdr.prop_id, hdr.start_idx)
            != (raw_object_type, object_instance, prop_id, start_idx)
        {
            return Err(Error::UnexpectedResponse);
        }
        if hdr.count == 0 {
            let code = hdr.data(&buf).first().copied().unwrap_or(u8::from(PropertyReturnCode::Error));
            return Err(Error::DeviceError(code));
        }
        Ok(hdr.data(&buf).to_vec())
    }

    /// Write a property through AN163 extended object addressing and check
    /// the confirmed write's return code.
    pub async fn property_ext_write(
        &mut self,
        object_type: InterfaceObjectType,
        object_instance: u16,
        prop_id: u16,
        start_idx: u16,
        count: u16,
        data: &[u8],
    ) -> Result<()> {
        let raw_object_type = u16::from(object_type);
        let count = u8::try_from(count).map_err(|_| Error::Parse("extended property count exceeds one octet"))?;
        let buf = self
            .request(ApciCode::PropertyExtValueWriteCon, PropertyExtValueRequest::msg_len(data.len()), |buf| {
                PropertyExtValueRequest::write(buf, raw_object_type, object_instance, prop_id, count, start_idx, data)
            })
            .await?;
        let hdr = PropertyExtValueHeader::parse(&buf).ok_or(Error::Parse("PropertyExtValueWriteConRes too short"))?;
        if (hdr.object_type, hdr.object_instance, hdr.prop_id, hdr.start_idx)
            != (raw_object_type, object_instance, prop_id, start_idx)
        {
            return Err(Error::UnexpectedResponse);
        }
        let code = hdr.data(&buf).first().copied().ok_or(Error::Parse("PropertyExtValueWriteConRes has no code"))?;
        if code != u8::from(PropertyReturnCode::Success) {
            return Err(Error::DeviceError(code));
        }
        Ok(())
    }

    /// Replace the active security tool key.
    ///
    /// Unlike an ordinary extended-property write, the confirmed response is
    /// encrypted with `new_key`. The dedicated bus command changes the live
    /// channel only after sending the old-key request and commits the keyring
    /// entry only after the new-key response authenticates.
    pub async fn write_tool_key(&mut self, new_key: [u8; 16]) -> Result<()> {
        const SECURITY_OBJECT_INSTANCE: u16 = 1;
        let security_object_type = u16::from(InterfaceObjectType::Security);

        let frame = frames::build_individual_frame(
            IndividualAddress::new(0, 0, 0),
            self.addr,
            Tpci::DataConnected(0),
            ApciCode::PropertyExtValueWriteCon,
            PropertyExtValueRequest::msg_len(new_key.len()),
            |buf| {
                PropertyExtValueRequest::write(
                    buf,
                    security_object_type,
                    SECURITY_OBJECT_INSTANCE,
                    zweidraehte_proto::pid::security::TOOL_KEY,
                    1,
                    1,
                    &new_key,
                )
            },
        );
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BusCommand::TlToolKeyWrite {
                frame,
                expected_apci: ApciCode::PropertyExtValueWriteConRes,
                new_key,
                tx,
            })
            .await
            .map_err(|_| Error::WorkerGone)?;
        let buf = rx.await.map_err(|_| Error::WorkerGone)??;
        let hdr = PropertyExtValueHeader::parse(&buf).ok_or(Error::Parse("PropertyExtValueWriteConRes too short"))?;
        if (hdr.object_type, hdr.object_instance, hdr.prop_id, hdr.start_idx)
            != (security_object_type, SECURITY_OBJECT_INSTANCE, zweidraehte_proto::pid::security::TOOL_KEY, 1)
        {
            return Err(Error::UnexpectedResponse);
        }
        let code = hdr.data(&buf).first().copied().ok_or(Error::Parse("PropertyExtValueWriteConRes has no code"))?;
        if code != u8::from(PropertyReturnCode::Success) {
            return Err(Error::DeviceError(code));
        }
        Ok(())
    }

    /// Read a property description.
    pub async fn property_description_read(
        &mut self,
        obj_idx: u8,
        prop_id: u16,
        prop_idx: u8,
    ) -> Result<PropertyDescription> {
        let buf = self
            .request(ApciCode::PropertyDescriptionRead, PropertyDescriptionRead::MIN_MSG_LEN, |buf| {
                PropertyDescriptionRead::write(buf, obj_idx, prop_id, prop_idx)
            })
            .await?;
        PropertyDescription::parse(&buf).ok_or(Error::Parse("PropertyDescriptionResponse too short"))
    }

    /// Execute a function property command.
    pub async fn function_property_command(
        &mut self,
        obj_idx: u8,
        prop_id: u16,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        let buf = self
            .request(ApciCode::FunctionPropertyCommand, FunctionPropertyHeader::msg_len(service_data.len()), |buf| {
                FunctionPropertyHeader::write(buf, obj_idx, prop_id, service_data)
            })
            .await?;
        let resp = FunctionPropertyResponse::parse(&buf).ok_or(Error::Parse("FunctionPropertyResponse too short"))?;
        Ok(FunctionPropertyResult { return_code: resp.return_code, data: resp.data(&buf).to_vec() })
    }

    /// Read the state of a function property.
    pub async fn function_property_state_read(
        &mut self,
        obj_idx: u8,
        prop_id: u16,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        let buf = self
            .request(ApciCode::FunctionPropertyStateRead, FunctionPropertyHeader::msg_len(service_data.len()), |buf| {
                FunctionPropertyHeader::write(buf, obj_idx, prop_id, service_data)
            })
            .await?;
        let resp = FunctionPropertyResponse::parse(&buf).ok_or(Error::Parse("FunctionPropertyResponse too short"))?;
        Ok(FunctionPropertyResult { return_code: resp.return_code, data: resp.data(&buf).to_vec() })
    }

    /// Execute a function property command through AN163 extended object
    /// addressing.
    pub async fn function_property_ext_command(
        &mut self,
        object_type: InterfaceObjectType,
        object_instance: u16,
        prop_id: u16,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        let raw_object_type = u16::from(object_type);
        let buf = self
            .request(
                ApciCode::FunctionPropertyExtCommand,
                FunctionPropertyExtRequest::msg_len(service_data.len()),
                |buf| FunctionPropertyExtRequest::write(buf, raw_object_type, object_instance, prop_id, service_data),
            )
            .await?;
        let hdr =
            FunctionPropertyExtHeader::parse(&buf).ok_or(Error::Parse("FunctionPropertyExtStateResponse too short"))?;
        if (hdr.object_type, hdr.object_instance, hdr.prop_id) != (raw_object_type, object_instance, prop_id) {
            return Err(Error::UnexpectedResponse);
        }
        let (return_code, data) =
            hdr.data(&buf).split_first().ok_or(Error::Parse("FunctionPropertyExtStateResponse has no return code"))?;
        Ok(FunctionPropertyResult { return_code: *return_code, data: data.to_vec() })
    }

    /// Read function-property state through AN163 extended addressing.
    pub async fn function_property_ext_state_read(
        &mut self,
        object_type: InterfaceObjectType,
        object_instance: u16,
        prop_id: u16,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        let raw_object_type = u16::from(object_type);
        let buf = self
            .request(
                ApciCode::FunctionPropertyExtStateRead,
                FunctionPropertyExtRequest::msg_len(service_data.len()),
                |buf| FunctionPropertyExtRequest::write(buf, raw_object_type, object_instance, prop_id, service_data),
            )
            .await?;
        let hdr =
            FunctionPropertyExtHeader::parse(&buf).ok_or(Error::Parse("FunctionPropertyExtStateResponse too short"))?;
        if (hdr.object_type, hdr.object_instance, hdr.prop_id) != (raw_object_type, object_instance, prop_id) {
            return Err(Error::UnexpectedResponse);
        }
        let (return_code, data) =
            hdr.data(&buf).split_first().ok_or(Error::Parse("FunctionPropertyExtStateResponse has no return code"))?;
        Ok(FunctionPropertyResult { return_code: *return_code, data: data.to_vec() })
    }

    /// Enable KNX Data Secure management through Security IO.
    ///
    /// This is the policy transition required before replacing an FDSK with a
    /// commissioned Tool Key or loading secure application tables. Keeping
    /// the object identity and function-property payload here prevents each
    /// programming entry point from spelling the protocol record itself.
    pub async fn enable_security_mode(&mut self) -> Result<()> {
        let result = self
            .function_property_ext_command(InterfaceObjectType::Security, 1, pid::security::SECURITY_MODE, &[0, 0, 1])
            .await?;
        if result.return_code != 0 {
            return Err(Error::DeviceError(result.return_code));
        }
        Ok(())
    }

    /// Read device memory (`DMP_MemRead_RCo`).
    pub async fn memory_read(&mut self, address: u16, count: u8) -> Result<Vec<u8>> {
        let buf = self
            .request(ApciCode::MemoryRead, MemoryReadRequest::MSG_LEN, |buf| {
                MemoryReadRequest::write(buf, count, address)
            })
            .await?;
        let acc = MemoryResponse::parse(&buf).ok_or(Error::Parse("MemoryResponse too short"))?;
        if acc.count == 0 && count != 0 {
            return Err(Error::DeviceError(0));
        }
        Ok(acc.data.to_vec())
    }

    /// Write device memory (`DMP_MemWrite_RCo`).
    ///
    /// Resolves on the device's T_ACK. Note that per 03/05/02 §3.16 the
    /// plain variant carries no application-level confirmation — use
    /// [`memory_write_verify`](Self::memory_write_verify) when the outcome
    /// matters.
    pub async fn memory_write(&mut self, address: u16, data: &[u8]) -> Result<()> {
        self.request_no_response(ApciCode::MemoryWrite, MemoryWriteRequest::msg_len(data.len()), |buf| {
            MemoryWriteRequest::write(buf, address, data)
        })
        .await
    }

    /// Write device memory and read it back (`DMP_MemWrite_RCoV`,
    /// 03/05/02 §3.16.3).
    pub async fn memory_write_verify(&mut self, address: u16, data: &[u8]) -> Result<()> {
        self.memory_write(address, data).await?;
        let read_back = self.memory_read(address, data.len() as u8).await?;
        if read_back != data {
            return Err(Error::VerifyMismatch { address });
        }
        Ok(())
    }

    /// Read through `A_MemoryExtended_Read` (24-bit address, explicit return
    /// code).
    pub async fn memory_extended_read(&mut self, address: u32, count: u8) -> Result<Vec<u8>> {
        let buf = self
            .request(ApciCode::MemoryExtendedRead, MemoryExtendedAccess::msg_len(0), |buf| {
                MemoryExtendedAccess::write(buf, count, address, &[])
            })
            .await?;
        let response =
            MemoryExtendedResponse::parse(&buf).ok_or(Error::Parse("MemoryExtendedReadResponse too short"))?;
        if response.address != address {
            return Err(Error::UnexpectedResponse);
        }
        if response.return_code != PropertyReturnCode::Success {
            return Err(Error::DeviceError(response.return_code.into()));
        }
        if response.data.len() != usize::from(count) {
            return Err(Error::Parse("MemoryExtendedReadResponse count mismatch"));
        }
        Ok(response.data.to_vec())
    }

    /// Write through `A_MemoryExtended_Write` and check its explicit return
    /// code.
    pub async fn memory_extended_write(&mut self, address: u32, data: &[u8]) -> Result<()> {
        let count = u8::try_from(data.len()).map_err(|_| Error::Parse("extended memory write exceeds one octet"))?;
        let buf = self
            .request(ApciCode::MemoryExtendedWrite, MemoryExtendedAccess::msg_len(data.len()), |buf| {
                MemoryExtendedAccess::write(buf, count, address, data)
            })
            .await?;
        let response =
            MemoryExtendedResponse::parse(&buf).ok_or(Error::Parse("MemoryExtendedWriteResponse too short"))?;
        if response.address != address {
            return Err(Error::UnexpectedResponse);
        }
        if response.return_code != PropertyReturnCode::Success {
            return Err(Error::DeviceError(response.return_code.into()));
        }
        Ok(())
    }

    /// Authorize with a key (`DMP_Authorize_RCo`). Returns the granted
    /// access level.
    pub async fn authorize(&mut self, key: &[u8; 4]) -> Result<u8> {
        let buf = self
            .request(ApciCode::AuthorizeRequest, AuthorizeRequest::MIN_MSG_LEN, |buf| AuthorizeRequest::write(buf, key))
            .await?;
        AuthorizeResponse::parse(&buf).ok_or(Error::Parse("AuthorizeResponse too short"))
    }

    /// Read the device descriptor.
    pub async fn device_descriptor_read(&mut self, descriptor_type: u8) -> Result<Vec<u8>> {
        let buf = self
            .request(ApciCode::DeviceDescriptorRead, DeviceDescriptorRead::MIN_MSG_LEN, |buf| {
                DeviceDescriptorRead::write(buf, descriptor_type)
            })
            .await?;
        if DeviceDescriptorResponse::descriptor_type(&buf) == Some(DeviceDescriptorResponse::ERROR_DESCRIPTOR_TYPE) {
            return Err(Error::DeviceError(DeviceDescriptorResponse::ERROR_DESCRIPTOR_TYPE));
        }
        if buf.len() < offsets::MSG_APCI + 2 {
            return Err(Error::Parse("DeviceDescriptorResponse too short"));
        }
        Ok(buf[offsets::MSG_APCI + 2..].to_vec())
    }

    /// Basic restart (`DM_Restart_RCo`). Resolves on the device's T_ACK;
    /// the device then reboots, taking its transport connection with it —
    /// [`close`](Self::close) afterwards succeeds locally regardless.
    pub async fn restart(&mut self) -> Result<()> {
        self.request_no_response(ApciCode::Restart, RestartParsed::BASIC_MIN_MSG_LEN, |_| {}).await
    }

    /// Master reset with an erase code (03/05/02 §3.7.1.2). Returns the
    /// process time the device announced; wait that long before
    /// reconnecting.
    pub async fn master_reset(&mut self, erase_code: EraseCode, channel: u8) -> Result<RestartAck> {
        // A_Restart_Response has no ApciCode mapping (escaped APCI 0x03A1),
        // so match on the peer only and check the payload shape ourselves.
        let buf = self
            .request_raw(
                ApciCode::Restart,
                RestartParsed::MASTER_MIN_MSG_LEN,
                |buf| RestartParsed::write_master_reset(buf, erase_code, channel),
                true,
                None,
            )
            .await?;
        let (error, process_time_100ms) =
            RestartResponse::parse(&buf).ok_or(Error::Parse("A_Restart_Response malformed"))?;
        if error != RestartError::NoError {
            return Err(Error::RestartRefused(error));
        }
        Ok(RestartAck { process_time: Duration::from_millis(u64::from(process_time_100ms) * 100) })
    }

    /// Close the transport connection (`DMP_Disconnect_RCo`).
    pub async fn close(self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(BusCommand::TlClose { tx }).await.map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)?
    }
}
