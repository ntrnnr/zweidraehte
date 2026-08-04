//! Connection-oriented (RCo) device management.

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::apdu::auth::{AuthorizeRequest, AuthorizeResponse};
use zweidraehte_proto::messages::apdu::device::{DeviceDescriptorRead, DeviceDescriptorResponse};
use zweidraehte_proto::messages::apdu::function_property::{FunctionPropertyHeader, FunctionPropertyResponse};
use zweidraehte_proto::messages::apdu::memory::{MemoryReadRequest, MemoryResponse, MemoryWriteRequest};
use zweidraehte_proto::messages::apdu::property::{
    PropertyDescriptionRead, PropertyValueHeader, PropertyValueResponse,
};
use zweidraehte_proto::messages::apdu::restart::{EraseCode, RestartError, RestartParsed, RestartResponse};
use zweidraehte_proto::messages::knx::{ApciCode, Tpci, offsets};

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
}

/// Outcome of a master reset: how long the device says it needs before it
/// is reachable again.
#[derive(Debug, Clone, Copy)]
pub struct RestartAck {
    pub process_time: Duration,
}

impl DeviceConnection {
    pub(crate) fn new(addr: IndividualAddress, cmd_tx: mpsc::Sender<BusCommand>) -> Self {
        Self { addr, cmd_tx }
    }

    /// The device this connection talks to.
    pub fn address(&self) -> IndividualAddress {
        self.addr
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
