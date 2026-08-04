//! Network management (NM_*) and connectionless (RCl) device management.

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::apdu::device::{
    APCI_ONLY_MSG_LEN, DeviceDescriptorRead, DeviceDescriptorResponse, IndividualAddressSerialNumberRead,
    IndividualAddressSerialNumberResponse, IndividualAddressSerialNumberWrite, IndividualAddressWrite,
};
use zweidraehte_proto::messages::apdu::function_property::{FunctionPropertyHeader, FunctionPropertyResponse};
use zweidraehte_proto::messages::apdu::property::{PropertyValueHeader, PropertyValueResponse};
use zweidraehte_proto::messages::knx::{ApciCode, KnxMessageBuffer, Tpci, offsets};

use crate::core::frames;
use crate::core::management::{self, FunctionPropertyResult, ResponseMatcher};
use crate::driver::BusCommand;
use crate::error::{Error, Result};

/// Network-management surface, obtained from
/// [`KnxBus::network_management`](crate::KnxBus::network_management).
///
/// Covers the broadcast NM_* procedures of 03/05/02 ch. 2 (programming-mode
/// addressing, serial-number addressing, scanning) plus connectionless
/// (RCl) point-to-point management.
pub struct NetworkManagement<'bus> {
    cmd_tx: &'bus mpsc::Sender<BusCommand>,
    source: IndividualAddress,
}

impl<'bus> NetworkManagement<'bus> {
    pub(crate) fn new(cmd_tx: &'bus mpsc::Sender<BusCommand>, source: IndividualAddress) -> Self {
        Self { cmd_tx, source }
    }

    // ========================================================================
    // Programming-mode addressing (NM_IndividualAddress_*)
    // ========================================================================

    /// `NM_IndividualAddress_Write` (03/05/02 §2.3): assign an individual
    /// address to the device in programming mode.
    ///
    /// The write is a broadcast with no confirmation; every device in
    /// programming mode accepts it, so the caller must ensure exactly one
    /// is. Verify with [`read_individual_addresses`]
    /// (Self::read_individual_addresses) afterwards.
    pub async fn write_individual_address(&self, new_addr: IndividualAddress) -> Result<()> {
        let frame = frames::build_broadcast_frame(
            self.source,
            ApciCode::IndividualAddressWrite,
            IndividualAddressWrite::MSG_LEN,
            |buf| IndividualAddressWrite::write(buf, new_addr),
        );
        self.send_only(frame).await
    }

    /// `NM_IndividualAddress_Read` (03/05/02 §2.2): collect the addresses
    /// of all devices currently in programming mode, listening for
    /// `scan_window`.
    pub async fn read_individual_addresses(&self, scan_window: Duration) -> Result<Vec<IndividualAddress>> {
        let frame =
            frames::build_broadcast_frame(self.source, ApciCode::IndividualAddressRead, APCI_ONLY_MSG_LEN, |_| {});
        let matcher = ResponseMatcher { source: None, apci: Some(ApciCode::IndividualAddressResponse) };
        let responses = self.scan(frame, matcher, scan_window).await?;

        // The responding device's address is the response frame's source;
        // the APDU itself is empty.
        Ok(responses
            .iter()
            .map(|internal| KnxMessageBuffer::from_buffer(internal.as_slice()).get_source_addr())
            .collect())
    }

    // ========================================================================
    // Serial-number addressing (NM_IndividualAddress_SerialNumber_*)
    // ========================================================================

    /// `NM_IndividualAddress_SerialNumber_Read` (03/05/02 §2.4): find the
    /// individual address of the device with the given KNX serial number.
    pub async fn read_individual_address_by_serial(&self, serial: &[u8; 6]) -> Result<IndividualAddress> {
        let frame = frames::build_broadcast_frame(
            self.source,
            ApciCode::IndividualAddressSerialNumberRead,
            IndividualAddressSerialNumberRead::MSG_LEN,
            |buf| IndividualAddressSerialNumberRead::write(buf, serial),
        );
        let matcher = ResponseMatcher { source: None, apci: Some(ApciCode::IndividualAddressSerialNumberResponse) };
        let internal = self.unconnected_raw(frame, matcher).await?;

        let responded = IndividualAddressSerialNumberResponse::serial_number(&internal)
            .ok_or(Error::Parse("IndividualAddressSerialNumberResponse too short"))?;
        if responded != serial {
            return Err(Error::UnexpectedResponse);
        }
        Ok(KnxMessageBuffer::from_buffer(internal.as_slice()).get_source_addr())
    }

    /// `NM_IndividualAddress_SerialNumber_Write` (03/05/02 §2.5): assign an
    /// individual address to the device with the given serial number.
    /// Broadcast without confirmation — verify by reading it back.
    pub async fn write_individual_address_by_serial(
        &self,
        serial: &[u8; 6],
        new_addr: IndividualAddress,
    ) -> Result<()> {
        let frame = frames::build_broadcast_frame(
            self.source,
            ApciCode::IndividualAddressSerialNumberWrite,
            IndividualAddressSerialNumberWrite::MSG_LEN,
            |buf| IndividualAddressSerialNumberWrite::write(buf, serial, new_addr),
        );
        self.send_only(frame).await
    }

    // ========================================================================
    // Connectionless (RCl) device management
    // ========================================================================

    /// Read a device descriptor without opening a transport connection.
    pub async fn device_descriptor_read(&self, addr: IndividualAddress, descriptor_type: u8) -> Result<Vec<u8>> {
        let buf = self
            .unconnected(addr, ApciCode::DeviceDescriptorRead, DeviceDescriptorRead::MIN_MSG_LEN, |buf| {
                DeviceDescriptorRead::write(buf, descriptor_type)
            })
            .await?;
        if DeviceDescriptorResponse::descriptor_type(&buf) == Some(DeviceDescriptorResponse::ERROR_DESCRIPTOR_TYPE) {
            return Err(Error::DeviceError(DeviceDescriptorResponse::ERROR_DESCRIPTOR_TYPE));
        }
        Ok(buf[offsets::MSG_APCI + 2..].to_vec())
    }

    /// Read a property value without opening a transport connection.
    pub async fn property_read(
        &self,
        addr: IndividualAddress,
        obj_idx: u8,
        prop_id: u16,
        start_idx: u16,
        count: u16,
    ) -> Result<Vec<u8>> {
        let buf = self
            .unconnected(addr, ApciCode::PropertyValueRead, PropertyValueHeader::MIN_MSG_LEN, |buf| {
                PropertyValueResponse::write(buf, obj_idx, prop_id, count, start_idx, &[])
            })
            .await?;
        let hdr = PropertyValueHeader::parse(&buf).ok_or(Error::Parse("PropertyValueResponse too short"))?;
        if hdr.count == 0 {
            return Err(Error::DeviceError(0));
        }
        Ok(hdr.data(&buf).to_vec())
    }

    /// Execute a function property command without opening a transport
    /// connection.
    pub async fn function_property_command(
        &self,
        addr: IndividualAddress,
        obj_idx: u8,
        prop_id: u16,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        let buf = self
            .unconnected(
                addr,
                ApciCode::FunctionPropertyCommand,
                FunctionPropertyHeader::msg_len(service_data.len()),
                |buf| FunctionPropertyHeader::write(buf, obj_idx, prop_id, service_data),
            )
            .await?;
        let resp = FunctionPropertyResponse::parse(&buf).ok_or(Error::Parse("FunctionPropertyResponse too short"))?;
        Ok(FunctionPropertyResult { return_code: resp.return_code, data: resp.data(&buf).to_vec() })
    }

    /// Read the state of a function property without opening a transport
    /// connection.
    pub async fn function_property_state_read(
        &self,
        addr: IndividualAddress,
        obj_idx: u8,
        prop_id: u16,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        let buf = self
            .unconnected(
                addr,
                ApciCode::FunctionPropertyStateRead,
                FunctionPropertyHeader::msg_len(service_data.len()),
                |buf| FunctionPropertyHeader::write(buf, obj_idx, prop_id, service_data),
            )
            .await?;
        let resp = FunctionPropertyResponse::parse(&buf).ok_or(Error::Parse("FunctionPropertyResponse too short"))?;
        Ok(FunctionPropertyResult { return_code: resp.return_code, data: resp.data(&buf).to_vec() })
    }

    // ========================================================================
    // Internal plumbing
    // ========================================================================

    async fn unconnected(
        &self,
        dest: IndividualAddress,
        apci: ApciCode,
        msg_len: usize,
        data_writer: impl FnOnce(&mut [u8]),
    ) -> Result<Vec<u8>> {
        let frame = frames::build_individual_frame(self.source, dest, Tpci::DataIndividual, apci, msg_len, data_writer);
        let matcher = ResponseMatcher { source: Some(dest), apci: management::expected_response_apci(apci) };
        self.unconnected_raw(frame, matcher).await
    }

    async fn unconnected_raw(&self, frame: Vec<u8>, matcher: ResponseMatcher) -> Result<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(BusCommand::Unconnected { frame, matcher, tx }).await.map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)?
    }

    async fn scan(&self, frame: Vec<u8>, matcher: ResponseMatcher, window: Duration) -> Result<Vec<Vec<u8>>> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(BusCommand::Scan { frame, matcher, window, tx }).await.map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)?
    }

    async fn send_only(&self, frame: Vec<u8>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(BusCommand::SendOnly { frame, tx }).await.map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)?
    }
}
