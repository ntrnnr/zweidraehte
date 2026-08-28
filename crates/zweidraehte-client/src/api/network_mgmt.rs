//! Network management (NM_*) and connectionless (RCl) device management.

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::apdu::device::{
    APCI_ONLY_MSG_LEN, DeviceDescriptorRead, DeviceDescriptorResponse, IndividualAddressSerialNumberRead,
    IndividualAddressSerialNumberResponse, IndividualAddressSerialNumberWrite, IndividualAddressWrite,
};
use zweidraehte_proto::messages::apdu::function_property::{FunctionPropertyHeader, FunctionPropertyResponse};
use zweidraehte_proto::messages::apdu::property::{PropertyValueHeader, PropertyValueResponse};
use zweidraehte_proto::messages::apdu::system_network_parameter::{
    SystemNetworkParameterRead, SystemNetworkParameterResponse,
};
use zweidraehte_proto::messages::knx::{ApciCode, KnxMessageBuffer, Tpci, offsets};
use zweidraehte_proto::pid;

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

/// Verified result of serial-number individual-address assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialAddressAssignment {
    pub previous: IndividualAddress,
    pub current: IndividualAddress,
    pub changed: bool,
}

/// One device selected by physical programming mode, including the serial
/// number returned by the system-network-parameter procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgrammingModeDevice {
    pub address: IndividualAddress,
    pub serial_number: [u8; 6],
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

    /// Scan physical programming mode until at least one device responds.
    ///
    /// `wait_timeout = None` preserves the ordinary one-scan behavior.
    /// `Some(timeout)` repeats scans until a device responds or the overall
    /// timeout expires. An expired wait returns an empty list, just like a
    /// single scan without responses.
    pub async fn read_individual_addresses_with_wait(
        &self,
        scan_window: Duration,
        wait_timeout: Option<Duration>,
    ) -> Result<Vec<IndividualAddress>> {
        let Some(wait_timeout) = wait_timeout else { return self.read_individual_addresses(scan_window).await };

        tokio::time::timeout(wait_timeout, async {
            loop {
                let found = self.read_individual_addresses(scan_window).await?;
                if !found.is_empty() {
                    return Ok(found);
                }
            }
        })
        .await
        .unwrap_or_else(|_| Ok(Vec::new()))
    }

    /// `NM_Read_SerialNumber_By_ProgrammingMode` (03/05/02 §2.20.1.3).
    ///
    /// Unlike an individually addressed `PID_SERIAL_NUMBER` read, this
    /// system broadcast is answered only by devices whose physical
    /// programming mode is active. It therefore remains unambiguous while
    /// several uncommissioned devices still share the default IA.
    pub async fn read_programming_mode_devices(&self, scan_window: Duration) -> Result<Vec<ProgrammingModeDevice>> {
        const OPERAND_BY_PROGRAMMING_MODE: u8 = 0x01;

        let object_type: u16 = InterfaceObjectType::Device.into();
        let property_id = pid::SERIAL_NUMBER;
        let frame = frames::build_system_broadcast_frame(
            self.source,
            ApciCode::SystemNetworkParameterRead,
            SystemNetworkParameterRead::MIN_MSG_LEN,
            |buf| SystemNetworkParameterRead::write(buf, object_type, property_id, OPERAND_BY_PROGRAMMING_MODE, &[]),
        );
        let matcher = ResponseMatcher { source: None, apci: Some(ApciCode::SystemNetworkParameterResponse) };

        self.scan(frame, matcher, scan_window)
            .await?
            .into_iter()
            .map(|internal| {
                let response = SystemNetworkParameterResponse::parse(&internal)
                    .ok_or(Error::Parse("SystemNetworkParameterResponse too short"))?;
                if response.object_type != object_type
                    || response.pid != pid::SERIAL_NUMBER
                    || response.operand != OPERAND_BY_PROGRAMMING_MODE
                {
                    return Err(Error::UnexpectedResponse);
                }

                let serial_number: [u8; 6] = response
                    .tail(&internal)
                    .try_into()
                    .map_err(|_| Error::Parse("programming-mode serial response is not six octets"))?;
                let address = KnxMessageBuffer::from_buffer(internal.as_slice()).get_source_addr();

                Ok(ProgrammingModeDevice { address, serial_number })
            })
            .collect()
    }

    // ========================================================================
    // Serial-number addressing (NM_IndividualAddress_SerialNumber_*)
    // ========================================================================

    /// `NM_IndividualAddress_SerialNumber_Read` (03/05/02 §2.4): find the
    /// individual address of the device with the given KNX serial number.
    pub async fn read_individual_address_by_serial(&self, serial: &[u8; 6]) -> Result<IndividualAddress> {
        let found = self.read_individual_addresses_by_serial(serial, management::RESPONSE_TIMEOUT).await?;
        match found.as_slice() {
            [address] => Ok(*address),
            [] => Err(Error::SerialDeviceNotFound),
            _ => Err(Error::DuplicateSerialNumber(found.len())),
        }
    }

    /// Scanning variant of serial-number address discovery. Collecting
    /// every response lets commissioning reject duplicated factory
    /// identities instead of selecting whichever answer arrived first.
    pub async fn read_individual_addresses_by_serial(
        &self,
        serial: &[u8; 6],
        scan_window: Duration,
    ) -> Result<Vec<IndividualAddress>> {
        let frame = frames::build_broadcast_frame(
            self.source,
            ApciCode::IndividualAddressSerialNumberRead,
            IndividualAddressSerialNumberRead::MSG_LEN,
            |buf| IndividualAddressSerialNumberRead::write(buf, serial),
        );
        let matcher = ResponseMatcher { source: None, apci: Some(ApciCode::IndividualAddressSerialNumberResponse) };
        let responses = self.scan(frame, matcher, scan_window).await?;
        responses
            .into_iter()
            .map(|internal| {
                let responded = IndividualAddressSerialNumberResponse::serial_number(&internal)
                    .ok_or(Error::Parse("IndividualAddressSerialNumberResponse too short"))?;
                if responded != serial {
                    return Err(Error::UnexpectedResponse);
                }
                Ok(KnxMessageBuffer::from_buffer(internal.as_slice()).get_source_addr())
            })
            .collect()
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

    /// Secure form of `NM_IndividualAddress_SerialNumber_Write` used after
    /// the serial-addressed FDSK sync in initial commissioning. The inner
    /// service and the secure envelope are both system broadcasts; `current`
    /// names the security entry whose credential the preceding sync proved.
    pub async fn write_individual_address_by_serial_secure(
        &self,
        serial: &[u8; 6],
        current: IndividualAddress,
        new_addr: IndividualAddress,
        key: [u8; 16],
    ) -> Result<()> {
        let frame = frames::build_system_broadcast_frame(
            self.source,
            ApciCode::IndividualAddressSerialNumberWrite,
            IndividualAddressSerialNumberWrite::MSG_LEN,
            |buf| IndividualAddressSerialNumberWrite::write(buf, serial, new_addr),
        );
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BusCommand::SecureSystemBroadcast { frame, at: current, key, tx })
            .await
            .map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)?
    }

    /// ETS-style serial address assignment (03/05/02 §2.5): locate a
    /// unique target, prove the requested address is unused, write, and
    /// verify through another serial-number read. This service does not
    /// reset the device.
    pub async fn assign_individual_address_by_serial(
        &self,
        serial: &[u8; 6],
        new_address: IndividualAddress,
        scan_window: Duration,
    ) -> Result<SerialAddressAssignment> {
        self.assign_individual_address_by_serial_inner(serial, new_address, scan_window, None).await
    }

    /// Secure serial-number assignment. Discovery and collision checks remain
    /// plain NM services; only the state-changing write is protected, exactly
    /// as in the Data Secure bootstrap procedure.
    pub async fn assign_individual_address_by_serial_secure(
        &self,
        serial: &[u8; 6],
        new_address: IndividualAddress,
        scan_window: Duration,
        key: [u8; 16],
    ) -> Result<SerialAddressAssignment> {
        self.assign_individual_address_by_serial_inner(serial, new_address, scan_window, Some(key)).await
    }

    async fn assign_individual_address_by_serial_inner(
        &self,
        serial: &[u8; 6],
        new_address: IndividualAddress,
        scan_window: Duration,
        secure_key: Option<[u8; 16]>,
    ) -> Result<SerialAddressAssignment> {
        let found = self.read_individual_addresses_by_serial(serial, scan_window).await?;
        let previous = match found.as_slice() {
            [address] => *address,
            [] => return Err(Error::SerialDeviceNotFound),
            _ => return Err(Error::DuplicateSerialNumber(found.len())),
        };
        if previous == new_address {
            return Ok(SerialAddressAssignment { previous, current: previous, changed: false });
        }
        if self.is_device_present(new_address, scan_window).await? {
            return Err(Error::IndividualAddressOccupied(new_address));
        }

        match secure_key {
            Some(key) => self.write_individual_address_by_serial_secure(serial, previous, new_address, key).await?,
            None => self.write_individual_address_by_serial(serial, new_address).await?,
        }
        let verified = self.read_individual_addresses_by_serial(serial, scan_window).await?;
        match verified.as_slice() {
            [address] if *address == new_address => {
                Ok(SerialAddressAssignment { previous, current: *address, changed: true })
            }
            [address] => Err(Error::SerialAddressVerification { expected: new_address, actual: Some(*address) }),
            [] => Err(Error::SerialAddressVerification { expected: new_address, actual: None }),
            _ => Err(Error::DuplicateSerialNumber(verified.len())),
        }
    }

    // ========================================================================
    // Connectionless (RCl) device management
    // ========================================================================

    /// Probe whether a device answers at `addr`: a connectionless
    /// `A_DeviceDescriptor_Read` with a caller-chosen wait window
    /// instead of the standard 3 s response timeout.
    ///
    /// This is the line-scan primitive — sweeping 256 addresses at the
    /// full timeout costs minutes, and every KNX device must answer a
    /// connectionless descriptor read (it is how a management tool
    /// checks reachability before anything else). A window of a few
    /// hundred milliseconds comfortably covers a TP1 round trip.
    pub async fn is_device_present(&self, addr: IndividualAddress, window: Duration) -> Result<bool> {
        let frame = frames::build_individual_frame(
            self.source,
            addr,
            Tpci::DataIndividual,
            ApciCode::DeviceDescriptorRead,
            DeviceDescriptorRead::MIN_MSG_LEN,
            |buf| DeviceDescriptorRead::write(buf, 0),
        );
        let matcher = ResponseMatcher {
            source: Some(addr),
            apci: management::expected_response_apci(ApciCode::DeviceDescriptorRead),
        };
        match self.scan(frame, matcher, window).await {
            Ok(responses) => Ok(!responses.is_empty()),
            // An individually addressed TP1 frame to an absent device
            // draws no link-layer ACK, which the interface reports as
            // a negative confirmation. For a presence probe that *is*
            // the answer — and it arrives without waiting the window
            // out, so sweeping empty addresses is fast.
            Err(Error::NegativeConfirmation) => Ok(false),
            Err(e) => Err(e),
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    const SERIAL: [u8; 6] = [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78];

    fn source() -> IndividualAddress {
        IndividualAddress::new(15, 15, 250)
    }

    fn current() -> IndividualAddress {
        IndividualAddress::new(1, 1, 1)
    }

    fn desired() -> IndividualAddress {
        IndividualAddress::new(1, 1, 42)
    }

    fn serial_response(address: IndividualAddress) -> Vec<u8> {
        frames::build_individual_frame(
            address,
            source(),
            Tpci::DataIndividual,
            ApciCode::IndividualAddressSerialNumberResponse,
            IndividualAddressSerialNumberResponse::MSG_LEN,
            |buf| IndividualAddressSerialNumberResponse::write_serial(buf, &SERIAL),
        )
    }

    fn programming_mode_response(address: IndividualAddress) -> Vec<u8> {
        frames::build_system_broadcast_frame(
            address,
            ApciCode::SystemNetworkParameterResponse,
            SystemNetworkParameterResponse::msg_len(SERIAL.len()),
            |buf| {
                SystemNetworkParameterResponse::write(
                    buf,
                    InterfaceObjectType::Device.into(),
                    pid::SERIAL_NUMBER,
                    0x01,
                    &SERIAL,
                )
            },
        )
    }

    fn individual_address_response(address: IndividualAddress) -> Vec<u8> {
        frames::build_individual_frame(
            address,
            source(),
            Tpci::DataIndividual,
            ApciCode::IndividualAddressResponse,
            APCI_ONLY_MSG_LEN,
            |_| {},
        )
    }

    async fn answer_serial_scan(rx: &mut mpsc::Receiver<BusCommand>, addresses: &[IndividualAddress]) {
        let BusCommand::Scan { tx, .. } = rx.recv().await.expect("scan command") else {
            panic!("expected a scan command")
        };
        tx.send(Ok(addresses.iter().copied().map(serial_response).collect())).expect("scan receiver remains alive");
    }

    async fn answer_presence_scan(rx: &mut mpsc::Receiver<BusCommand>, occupied: bool) {
        let BusCommand::Scan { tx, .. } = rx.recv().await.expect("presence command") else {
            panic!("expected a presence scan")
        };
        tx.send(Ok(if occupied { vec![vec![0]] } else { Vec::new() })).expect("scan receiver remains alive");
    }

    #[tokio::test]
    async fn programming_mode_scan_uses_the_system_parameter_procedure() {
        let (tx, mut rx) = mpsc::channel(1);
        let management = NetworkManagement::new(&tx, source());
        let client = management.read_programming_mode_devices(Duration::from_millis(1));
        let device = async {
            let BusCommand::Scan { frame, tx, .. } = rx.recv().await.expect("scan command") else {
                panic!("expected a scan command")
            };
            let request = KnxMessageBuffer::from_buffer(frame);

            assert_eq!(request.get_dest_addr(), zweidraehte_proto::messages::knx::DestinationAddress::SystemBroadcast);
            assert_eq!(request.get_tpci(), Some(Tpci::DataSystemBroadcast));
            assert_eq!(request.get_apci_code(), ApciCode::SystemNetworkParameterRead);

            let header = SystemNetworkParameterRead::parse(request.buf()).expect("request has a parameter header");
            assert_eq!(header.object_type, u16::from(InterfaceObjectType::Device));
            assert_eq!(header.pid, pid::SERIAL_NUMBER);
            assert_eq!(header.operand, 0x01);

            tx.send(Ok(vec![programming_mode_response(current())])).expect("scan receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert_eq!(result.expect("programming-mode scan succeeds"), vec![ProgrammingModeDevice {
            address: current(),
            serial_number: SERIAL,
        }]);
    }

    #[tokio::test]
    async fn configured_programming_mode_wait_repeats_empty_scans() {
        let (tx, mut rx) = mpsc::channel(2);
        let management = NetworkManagement::new(&tx, source());
        let client =
            management.read_individual_addresses_with_wait(Duration::from_millis(1), Some(Duration::from_secs(1)));
        let device = async {
            let BusCommand::Scan { tx, .. } = rx.recv().await.expect("first scan command") else {
                panic!("expected a scan command")
            };
            tx.send(Ok(Vec::new())).expect("scan receiver remains alive");

            let BusCommand::Scan { tx, .. } = rx.recv().await.expect("second scan command") else {
                panic!("expected a scan command")
            };
            tx.send(Ok(vec![individual_address_response(current())])).expect("scan receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert_eq!(result.expect("programming-mode wait succeeds"), vec![current()]);
    }

    #[tokio::test]
    async fn serial_assignment_is_a_noop_at_the_desired_address() {
        let (tx, mut rx) = mpsc::channel(4);
        let management = NetworkManagement::new(&tx, source());
        let client = management.assign_individual_address_by_serial(&SERIAL, desired(), Duration::from_millis(1));
        let device = async { answer_serial_scan(&mut rx, &[desired()]).await };
        let (result, ()) = tokio::join!(client, device);

        assert_eq!(result.expect("no-op assignment succeeds"), SerialAddressAssignment {
            previous: desired(),
            current: desired(),
            changed: false
        });
        assert!(rx.try_recv().is_err(), "a no-op sends no write or occupancy probe");
    }

    #[tokio::test]
    async fn serial_assignment_rejects_missing_and_duplicate_devices() {
        for (answers, expected_duplicate) in [(Vec::new(), None), (vec![current(), desired()], Some(2))] {
            let (tx, mut rx) = mpsc::channel(4);
            let management = NetworkManagement::new(&tx, source());
            let client = management.assign_individual_address_by_serial(&SERIAL, desired(), Duration::from_millis(1));
            let device = async { answer_serial_scan(&mut rx, &answers).await };
            let (result, ()) = tokio::join!(client, device);
            assert!(match (result, expected_duplicate) {
                (Err(Error::SerialDeviceNotFound), None) => true,
                (Err(Error::DuplicateSerialNumber(actual)), Some(expected)) => actual == expected,
                _ => false,
            });
        }
    }

    #[tokio::test]
    async fn serial_assignment_refuses_an_occupied_address() {
        let (tx, mut rx) = mpsc::channel(4);
        let management = NetworkManagement::new(&tx, source());
        let client = management.assign_individual_address_by_serial(&SERIAL, desired(), Duration::from_millis(1));
        let device = async {
            answer_serial_scan(&mut rx, &[current()]).await;
            answer_presence_scan(&mut rx, true).await;
        };
        let (result, ()) = tokio::join!(client, device);
        assert!(matches!(result, Err(Error::IndividualAddressOccupied(address)) if address == desired()));
    }

    #[tokio::test]
    async fn serial_assignment_writes_and_verifies() {
        let (tx, mut rx) = mpsc::channel(4);
        let management = NetworkManagement::new(&tx, source());
        let client = management.assign_individual_address_by_serial(&SERIAL, desired(), Duration::from_millis(1));
        let device = async {
            answer_serial_scan(&mut rx, &[current()]).await;
            answer_presence_scan(&mut rx, false).await;
            let BusCommand::SendOnly { tx, .. } = rx.recv().await.expect("write command") else {
                panic!("expected the serial write")
            };
            tx.send(Ok(())).expect("write receiver remains alive");
            answer_serial_scan(&mut rx, &[desired()]).await;
        };
        let (result, ()) = tokio::join!(client, device);
        assert_eq!(result.expect("assignment succeeds"), SerialAddressAssignment {
            previous: current(),
            current: desired(),
            changed: true
        });
    }

    #[tokio::test]
    async fn secure_serial_assignment_uses_the_synchronized_system_broadcast_path() {
        const KEY: [u8; 16] = [0x42; 16];
        let (tx, mut rx) = mpsc::channel(4);
        let management = NetworkManagement::new(&tx, source());
        let client =
            management.assign_individual_address_by_serial_secure(&SERIAL, desired(), Duration::from_millis(1), KEY);
        let device = async {
            answer_serial_scan(&mut rx, &[current()]).await;
            answer_presence_scan(&mut rx, false).await;
            let BusCommand::SecureSystemBroadcast { frame, at, key, tx } = rx.recv().await.expect("write command")
            else {
                panic!("expected the secure serial write")
            };
            let message = KnxMessageBuffer::from_buffer(frame);
            assert_eq!(message.get_dest_addr(), zweidraehte_proto::messages::knx::DestinationAddress::SystemBroadcast);
            assert_eq!(message.get_tpci(), Some(Tpci::DataSystemBroadcast));
            assert_eq!(at, current());
            assert_eq!(key, KEY);
            tx.send(Ok(())).expect("write receiver remains alive");
            answer_serial_scan(&mut rx, &[desired()]).await;
        };
        let (result, ()) = tokio::join!(client, device);
        assert_eq!(result.expect("assignment succeeds").current, desired());
    }

    #[tokio::test]
    async fn serial_assignment_reports_failed_verification() {
        let (tx, mut rx) = mpsc::channel(4);
        let management = NetworkManagement::new(&tx, source());
        let client = management.assign_individual_address_by_serial(&SERIAL, desired(), Duration::from_millis(1));
        let device = async {
            answer_serial_scan(&mut rx, &[current()]).await;
            answer_presence_scan(&mut rx, false).await;
            let BusCommand::SendOnly { tx, .. } = rx.recv().await.expect("write command") else {
                panic!("expected the serial write")
            };
            tx.send(Ok(())).expect("write receiver remains alive");
            answer_serial_scan(&mut rx, &[]).await;
        };
        let (result, ()) = tokio::join!(client, device);
        assert!(matches!(
            result,
            Err(Error::SerialAddressVerification { expected, actual: None }) if expected == desired()
        ));
    }
}
