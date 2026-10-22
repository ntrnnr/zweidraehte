//! Network management (NM_*) and connectionless (RCl) device management.

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::apdu::device::{
    APCI_ONLY_MSG_LEN, DeviceDescriptorRead, DeviceDescriptorResponse, DomainAddressResponse,
    DomainAddressSerialNumberRead, DomainAddressSerialNumberResponse, DomainAddressSerialNumberWrite,
    DomainAddressWrite, IndividualAddressSerialNumberRead, IndividualAddressSerialNumberResponse,
    IndividualAddressSerialNumberWrite, IndividualAddressWrite, OpenMediumDomainAddress,
};
use zweidraehte_proto::messages::apdu::function_property::FunctionPropertyHeader;
use zweidraehte_proto::messages::apdu::property::{PropertyValueHeader, PropertyValueResponse};
use zweidraehte_proto::messages::apdu::system_network_parameter::{
    SystemNetworkParameterRead, SystemNetworkParameterResponse,
};
use zweidraehte_proto::messages::knx::{ApciCode, KnxMessageBuffer, Tpci, offsets};
use zweidraehte_proto::pid;

use crate::bus::driver::BusCommand;
use crate::bus::frames;
use crate::bus::management::{self, FunctionPropertyResult, PropertyAddress, ResponseMatcher};
use crate::bus::{BusError as Error, BusResult as Result};

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
#[non_exhaustive]
pub struct SerialAddressAssignment {
    pub previous: IndividualAddress,
    pub current: IndividualAddress,
    pub changed: bool,
}

/// One device selected by physical programming mode, including the serial
/// number returned by the system-network-parameter procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProgrammingModeDevice {
    pub address: IndividualAddress,
    pub serial_number: [u8; 6],
}

/// Which devices a network-management request selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressTarget {
    /// Every device whose physical programming mode is active, by ordinary
    /// broadcast (03/05/02 §2.2, §2.3).
    ProgrammingMode,
    /// Every device whose physical programming mode is active, by KNX system
    /// broadcast. The open-medium procedures (03/05/02 §2.9, §2.10) use this
    /// to stay independent of the interface's ordinary broadcast domain.
    OpenMediumProgrammingMode,
    /// The device with this KNX serial number (03/05/02 §2.4, §2.5).
    Serial([u8; 6]),
}

/// Protection of a state-changing network-management broadcast.
///
/// Only serial-number writes have a secure form; a secure write to a
/// programming-mode target is refused with [`BusError::Unsupported`]. Discovery
/// and verification reads are always plain.
///
/// [`BusError::Unsupported`]: crate::BusError::Unsupported
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Protection {
    Plain,
    /// KNX Data Secure, under the security entry at `current` whose key a
    /// preceding system-broadcast sync proved. The inner service and the
    /// secure envelope are both system broadcasts.
    Secure {
        current: IndividualAddress,
        key: [u8; 16],
    },
}

impl std::fmt::Debug for Protection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => f.write_str("Plain"),
            Self::Secure { current, .. } => f.debug_struct("Secure").field("current", current).finish_non_exhaustive(),
        }
    }
}

impl<'bus> NetworkManagement<'bus> {
    pub(crate) fn new(cmd_tx: &'bus mpsc::Sender<BusCommand>, source: IndividualAddress) -> Self {
        Self { cmd_tx, source }
    }

    // ========================================================================
    // Individual addresses (NM_IndividualAddress_*)
    // ========================================================================

    /// Collect the individual address of every device `target` selects,
    /// listening for `scan_window`.
    ///
    /// Every response is retained, including repeated source addresses,
    /// because two uncommissioned devices may still share one address and a
    /// serial number may be duplicated. A serial response for a different
    /// serial number is an error.
    pub async fn read_individual_addresses(
        &self,
        target: AddressTarget,
        scan_window: Duration,
    ) -> Result<Vec<IndividualAddress>> {
        let (frame, matcher) = match target {
            AddressTarget::ProgrammingMode => (
                frames::build_broadcast_frame(self.source, ApciCode::IndividualAddressRead, APCI_ONLY_MSG_LEN, |_| {}),
                ResponseMatcher { source: None, apci: Some(ApciCode::IndividualAddressResponse) },
            ),
            AddressTarget::OpenMediumProgrammingMode => (
                frames::build_system_broadcast_frame(
                    self.source,
                    ApciCode::IndividualAddressRead,
                    APCI_ONLY_MSG_LEN,
                    |_| {},
                ),
                ResponseMatcher { source: None, apci: Some(ApciCode::IndividualAddressResponse) },
            ),
            AddressTarget::Serial(serial) => (
                frames::build_broadcast_frame(
                    self.source,
                    ApciCode::IndividualAddressSerialNumberRead,
                    IndividualAddressSerialNumberRead::MSG_LEN,
                    |buf| IndividualAddressSerialNumberRead::write(buf, &serial),
                ),
                ResponseMatcher { source: None, apci: Some(ApciCode::IndividualAddressSerialNumberResponse) },
            ),
        };
        let responses = self.scan(frame, matcher, scan_window).await?;

        // The responding device's address is the response frame's source.
        responses
            .into_iter()
            .map(|internal| {
                if let AddressTarget::Serial(serial) = &target {
                    let responded = IndividualAddressSerialNumberResponse::serial_number(&internal)
                        .ok_or(Error::Parse("IndividualAddressSerialNumberResponse too short"))?;
                    if responded != serial {
                        return Err(Error::UnexpectedResponse);
                    }
                }
                Ok(KnxMessageBuffer::from_buffer(internal.as_slice()).get_source_addr())
            })
            .collect()
    }

    /// The individual address of exactly one device `target` selects.
    /// Cardinality is checked before examining the address value.
    pub async fn read_individual_address(
        &self,
        target: AddressTarget,
        scan_window: Duration,
    ) -> Result<IndividualAddress> {
        let found = self.read_individual_addresses(target, scan_window).await?;
        exactly_one(target, found)
    }

    /// Scan physical programming mode until at least one device responds or
    /// `timeout` expires. An expired wait returns an empty list, just like a
    /// single scan without responses.
    pub async fn await_programming_mode(
        &self,
        scan_window: Duration,
        timeout: Duration,
    ) -> Result<Vec<IndividualAddress>> {
        tokio::time::timeout(timeout, async {
            loop {
                let found = match self.read_individual_addresses(AddressTarget::ProgrammingMode, scan_window).await {
                    Ok(found) => found,

                    // A bus access can reject the request before the scan
                    // window is installed. A configured wait treats that as
                    // a failed attempt and retries, but retains the normal
                    // scan cadence so a faulty interface cannot turn this
                    // loop into a transmit flood.
                    Err(Error::NegativeConfirmation) => {
                        tokio::time::sleep(scan_window).await;
                        Vec::new()
                    }

                    Err(error) => return Err(error),
                };

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

    /// Assign `new_addr` to the devices `target` selects
    /// (`NM_IndividualAddress_Write`, `NM_IndividualAddress_SerialNumber_Write`).
    ///
    /// The write is a broadcast with no confirmation. A programming-mode write
    /// is accepted by every device in programming mode, so the caller must
    /// first prove that exactly one is. Verify with
    /// [`read_individual_address`](Self::read_individual_address) afterwards.
    pub async fn write_individual_address(
        &self,
        target: AddressTarget,
        new_addr: IndividualAddress,
        protection: Protection,
    ) -> Result<()> {
        match (target, protection) {
            (AddressTarget::ProgrammingMode, Protection::Plain) => {
                let frame = frames::build_broadcast_frame(
                    self.source,
                    ApciCode::IndividualAddressWrite,
                    IndividualAddressWrite::MSG_LEN,
                    |buf| IndividualAddressWrite::write(buf, new_addr),
                );
                self.send_only(frame).await
            }
            (AddressTarget::OpenMediumProgrammingMode, Protection::Plain) => {
                let frame = frames::build_system_broadcast_frame(
                    self.source,
                    ApciCode::IndividualAddressWrite,
                    IndividualAddressWrite::MSG_LEN,
                    |buf| IndividualAddressWrite::write(buf, new_addr),
                );
                self.send_only(frame).await
            }
            (AddressTarget::Serial(serial), Protection::Plain) => {
                let frame = frames::build_broadcast_frame(
                    self.source,
                    ApciCode::IndividualAddressSerialNumberWrite,
                    IndividualAddressSerialNumberWrite::MSG_LEN,
                    |buf| IndividualAddressSerialNumberWrite::write(buf, &serial, new_addr),
                );
                self.send_only(frame).await
            }
            (AddressTarget::Serial(serial), Protection::Secure { current, key }) => {
                let frame = frames::build_system_broadcast_frame(
                    self.source,
                    ApciCode::IndividualAddressSerialNumberWrite,
                    IndividualAddressSerialNumberWrite::MSG_LEN,
                    |buf| IndividualAddressSerialNumberWrite::write(buf, &serial, new_addr),
                );
                self.send_secure(frame, current, key).await
            }
            (AddressTarget::ProgrammingMode | AddressTarget::OpenMediumProgrammingMode, Protection::Secure { .. }) => {
                Err(Error::Unsupported("programming-mode address writes have no secure form"))
            }
        }
    }

    /// ETS-style serial address assignment (03/05/02 §2.5): locate a unique
    /// target, prove the requested address is unused, write, and verify
    /// through another serial-number read. This service does not reset the
    /// device.
    ///
    /// Discovery and collision checks remain plain NM services; only the
    /// state-changing write uses `protection`, exactly as in the Data Secure
    /// bootstrap procedure. A secure `current` must be the address the device
    /// is found at, since that is the security entry its sync proved.
    pub async fn assign_individual_address(
        &self,
        serial: &[u8; 6],
        new_address: IndividualAddress,
        scan_window: Duration,
        protection: Protection,
    ) -> Result<SerialAddressAssignment> {
        let target = AddressTarget::Serial(*serial);
        let previous = self.read_individual_address(target, scan_window).await?;
        if let Protection::Secure { current, .. } = protection
            && current != previous
        {
            return Err(Error::ProgrammingVerification(format!(
                "secure assignment was synchronized at {current}, but the device answers at {previous}"
            )));
        }
        if previous == new_address {
            return Ok(SerialAddressAssignment { previous, current: previous, changed: false });
        }
        if self.is_device_present(new_address, scan_window).await? {
            return Err(Error::IndividualAddressOccupied(new_address));
        }

        self.write_individual_address(target, new_address, protection).await?;
        let verified = self.read_individual_addresses(target, scan_window).await?;
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
    // Open-medium domain addresses (NM_DomainAddress_*)
    // ========================================================================

    /// Collect the PL110 or RF domain address of every device `target`
    /// selects (`NM_DomainAddress_Read`, `A_DomainAddressSerialNumber_Read`).
    ///
    /// Both procedures are system broadcasts, so the two programming-mode
    /// targets send the same request. Returning every response is what lets
    /// the caller distinguish no selected device, one selected device, and an
    /// unsafe multi-device selection or duplicated serial number.
    pub async fn read_domain_addresses(
        &self,
        target: AddressTarget,
        scan_window: Duration,
    ) -> Result<Vec<(IndividualAddress, OpenMediumDomainAddress)>> {
        let (frame, matcher) = match target {
            AddressTarget::ProgrammingMode | AddressTarget::OpenMediumProgrammingMode => (
                frames::build_system_broadcast_frame(
                    self.source,
                    ApciCode::DomainAddressRead,
                    APCI_ONLY_MSG_LEN,
                    |_| {},
                ),
                ResponseMatcher { source: None, apci: Some(ApciCode::DomainAddressResponse) },
            ),
            AddressTarget::Serial(serial) => (
                frames::build_system_broadcast_frame(
                    self.source,
                    ApciCode::DomainAddressSerialNumberRead,
                    DomainAddressSerialNumberRead::MSG_LEN,
                    |buf| DomainAddressSerialNumberRead::write(buf, &serial),
                ),
                ResponseMatcher { source: None, apci: Some(ApciCode::DomainAddressSerialNumberResponse) },
            ),
        };

        self.scan(frame, matcher, scan_window)
            .await?
            .into_iter()
            .map(|internal| {
                let domain_address = match &target {
                    AddressTarget::Serial(serial) => {
                        let response_serial = DomainAddressSerialNumberResponse::serial_number(&internal)
                            .ok_or(Error::Parse("DomainAddressSerialNumberResponse is too short"))?;
                        if response_serial != serial {
                            return Err(Error::UnexpectedResponse);
                        }
                        DomainAddressSerialNumberResponse::domain_address(&internal)
                            .ok_or(Error::Parse("serial domain response has neither the PL nor RF width"))?
                    }
                    _ => DomainAddressResponse::domain_address(&internal)
                        .ok_or(Error::Parse("DomainAddressResponse has neither the PL nor RF width"))?,
                };
                let address = KnxMessageBuffer::from_buffer(internal.as_slice()).get_source_addr();

                Ok((address, domain_address))
            })
            .collect()
    }

    /// The domain address of exactly one device `target` selects.
    pub async fn read_domain_address(
        &self,
        target: AddressTarget,
        scan_window: Duration,
    ) -> Result<(IndividualAddress, OpenMediumDomainAddress)> {
        let found = self.read_domain_addresses(target, scan_window).await?;
        exactly_one(target, found)
    }

    /// Write a PL110 or RF domain address to the devices `target` selects
    /// (`A_DomainAddress_Write`, `NM_DomainAddressSerialNumber_Write` and its
    /// secure form, 03/05/02 §2.12, §2.13).
    ///
    /// The programming-mode service contains no device identity; callers
    /// requiring authenticated commissioning must address the device by
    /// serial number.
    pub async fn write_domain_address(
        &self,
        target: AddressTarget,
        domain_address: OpenMediumDomainAddress,
        protection: Protection,
    ) -> Result<()> {
        match (target, protection) {
            (AddressTarget::ProgrammingMode | AddressTarget::OpenMediumProgrammingMode, Protection::Plain) => {
                let frame = frames::build_system_broadcast_frame(
                    self.source,
                    ApciCode::DomainAddressWrite,
                    DomainAddressWrite::msg_len(domain_address),
                    |buf| DomainAddressWrite::write(buf, domain_address),
                );
                self.send_only(frame).await
            }
            (AddressTarget::Serial(serial), protection) => {
                let frame = frames::build_system_broadcast_frame(
                    self.source,
                    ApciCode::DomainAddressSerialNumberWrite,
                    DomainAddressSerialNumberWrite::msg_len(domain_address),
                    |buf| DomainAddressSerialNumberWrite::write(buf, &serial, domain_address),
                );
                match protection {
                    Protection::Plain => self.send_only(frame).await,
                    Protection::Secure { current, key } => self.send_secure(frame, current, key).await,
                }
            }
            (AddressTarget::ProgrammingMode | AddressTarget::OpenMediumProgrammingMode, Protection::Secure { .. }) => {
                Err(Error::Unsupported("programming-mode domain writes have no secure form"))
            }
        }
    }

    /// Verify that exactly one device `target` selects reports the expected
    /// domain address, and return its current individual address.
    ///
    /// For a serial target this is a stronger diagnostic than the
    /// standardized §2.12 check, which only proves reachability through
    /// [`read_individual_address`](Self::read_individual_address); it needs
    /// the newly selected domain to remain reachable from this client.
    pub async fn verify_domain_address(
        &self,
        target: AddressTarget,
        expected: OpenMediumDomainAddress,
        scan_window: Duration,
    ) -> Result<IndividualAddress> {
        let (address, actual) = self.read_domain_address(target, scan_window).await?;
        if actual != expected {
            return Err(Error::ProgrammingVerification(format!(
                "domain write returned {actual:?}, expected {expected:?}"
            )));
        }

        Ok(address)
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
    // TODO: connectionless extended property reads, should a caller need
    // them; only standard addressing is implemented here.
    pub async fn property_read(
        &self,
        addr: IndividualAddress,
        property: PropertyAddress,
        start_idx: u16,
        count: u16,
    ) -> Result<Vec<u8>> {
        let (object_index, property_id) = indexed(property)?;
        let property = management::ClassicProperty::new(object_index, property_id, start_idx, count)?;

        let buf = self
            .unconnected(addr, ApciCode::PropertyValueRead, PropertyValueHeader::MIN_MSG_LEN, |buf| {
                PropertyValueResponse::write(buf, object_index, property_id, count, start_idx, &[])
            })
            .await?;
        Ok(property.response(&buf)?.to_vec())
    }

    async fn function_property_request(
        &self,
        apci: ApciCode,
        addr: IndividualAddress,
        property: PropertyAddress,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        let (object_index, property_id) = indexed(property)?;

        let buf = self
            .unconnected(addr, apci, FunctionPropertyHeader::msg_len(service_data.len()), |buf| {
                FunctionPropertyHeader::write(buf, object_index, property_id, service_data)
            })
            .await?;
        FunctionPropertyResult::parse(&buf, object_index, property_id)
    }

    /// Execute a function property command without opening a transport
    /// connection. Only standard addressing is implemented connectionless.
    pub async fn function_property_command(
        &self,
        addr: IndividualAddress,
        property: PropertyAddress,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        self.function_property_request(ApciCode::FunctionPropertyCommand, addr, property, service_data).await
    }

    /// Read the state of a function property without opening a transport
    /// connection. Only standard addressing is implemented connectionless.
    pub async fn function_property_state_read(
        &self,
        addr: IndividualAddress,
        property: PropertyAddress,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        self.function_property_request(ApciCode::FunctionPropertyStateRead, addr, property, service_data).await
    }

    // ========================================================================
    // Internal plumbing
    // ========================================================================

    async fn send_secure(&self, frame: Vec<u8>, current: IndividualAddress, key: [u8; 16]) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BusCommand::SecureSystemBroadcast { frame, at: current, key, tx })
            .await
            .map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)?
    }

    async fn unconnected(
        &self,
        dest: IndividualAddress,
        apci: ApciCode,
        msg_len: usize,
        data_writer: impl FnOnce(&mut [u8]),
    ) -> Result<Vec<u8>> {
        management::validate_apdu_length(msg_len, false)?;

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

/// The one response a singular read requires, with the cardinality error
/// that fits how the target selected devices.
fn exactly_one<T: Copy>(target: AddressTarget, found: Vec<T>) -> Result<T> {
    match (found.as_slice(), target) {
        ([device], _) => Ok(*device),
        ([], AddressTarget::Serial(_)) => Err(Error::SerialDeviceNotFound),
        ([], _) => Err(Error::ProgrammingDeviceNotFound),
        (_, AddressTarget::Serial(_)) => Err(Error::DuplicateSerialNumber(found.len())),
        (_, _) => Err(Error::MultipleProgrammingDevices(found.len())),
    }
}

/// The standard addressing the connectionless services implement.
fn indexed(property: PropertyAddress) -> Result<(u8, u16)> {
    match property {
        PropertyAddress::Indexed { object_index, property_id } => Ok((object_index, u16::from(property_id))),
        PropertyAddress::Extended { .. } => {
            Err(Error::Unsupported("connectionless property services use standard addressing"))
        }
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

    fn open_medium_individual_address_response(address: IndividualAddress) -> Vec<u8> {
        frames::build_system_broadcast_frame(address, ApciCode::IndividualAddressResponse, APCI_ONLY_MSG_LEN, |_| {})
    }

    fn domain_response(address: IndividualAddress, domain: OpenMediumDomainAddress) -> Vec<u8> {
        frames::build_system_broadcast_frame(
            address,
            ApciCode::DomainAddressResponse,
            DomainAddressResponse::MSG_LEN_NO_DOA + domain.encoded_len(),
            |buf| {
                let start = offsets::MSG_APCI + 2;
                domain.write(&mut buf[start..]);
            },
        )
    }

    fn serial_domain_response(address: IndividualAddress, domain: OpenMediumDomainAddress) -> Vec<u8> {
        frames::build_system_broadcast_frame(
            address,
            ApciCode::DomainAddressSerialNumberResponse,
            DomainAddressSerialNumberResponse::MSG_LEN_NO_DOA + domain.encoded_len(),
            |buf| {
                DomainAddressSerialNumberResponse::write_serial(buf, &SERIAL);

                let start = offsets::MSG_APCI + 8;
                domain.write(&mut buf[start..]);
            },
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
    async fn connectionless_property_rejects_invalid_fields_and_stale_reply() {
        let (tx, mut rx) = mpsc::channel(1);
        let management = NetworkManagement::new(&tx, source());
        assert!(matches!(PropertyAddress::indexed(0, 256), Err(Error::Parse(_))));
        for (property, start, count) in [(1, 4096, 1), (1, 1, 16)] {
            assert!(matches!(
                management
                    .property_read(
                        current(),
                        PropertyAddress::indexed(0, property).expect("PID fits one octet"),
                        start,
                        count
                    )
                    .await,
                Err(Error::Parse(_))
            ));
        }
        assert!(rx.try_recv().is_err());
        let client =
            management.property_read(current(), PropertyAddress::indexed(0, 1).expect("PID fits one octet"), 7, 1);
        let peer = async {
            let BusCommand::Unconnected { tx, .. } = rx.recv().await.expect("request") else {
                panic!("unconnected request")
            };
            let response = frames::build_individual_frame(
                current(),
                source(),
                Tpci::DataIndividual,
                ApciCode::PropertyValueResponse,
                PropertyValueResponse::msg_len(1),
                |buf| PropertyValueResponse::write(buf, 0, 1, 1, 6, &[1]),
            );
            tx.send(Ok(response)).expect("request receiver");
        };
        let (result, ()) = tokio::join!(client, peer);
        assert!(matches!(result, Err(Error::UnexpectedResponse)));
    }

    #[tokio::test]
    async fn connectionless_property_read_reports_a_typed_negative_response() {
        let (tx, mut rx) = mpsc::channel(1);
        let management = NetworkManagement::new(&tx, source());
        let client = management.property_read(
            current(),
            PropertyAddress::indexed(5, pid::MCB_TABLE).expect("PID fits one octet"),
            1,
            1,
        );
        let device = async {
            let BusCommand::Unconnected { frame, matcher, tx } =
                rx.recv().await.expect("connectionless property-value read")
            else {
                panic!("expected an unconnected request")
            };
            let request = KnxMessageBuffer::from_buffer(frame);
            let header = PropertyValueHeader::parse(request.buf()).expect("complete property-value read");

            assert_eq!(request.get_apci_code(), ApciCode::PropertyValueRead);
            assert_eq!(matcher.source, Some(current()));
            assert_eq!(matcher.apci, Some(ApciCode::PropertyValueResponse));
            assert_eq!((header.object_idx, header.prop_id, header.start_idx, header.count), (5, pid::MCB_TABLE, 1, 1));

            let response = frames::build_individual_frame(
                current(),
                source(),
                Tpci::DataIndividual,
                ApciCode::PropertyValueResponse,
                PropertyValueResponse::ERROR_MSG_LEN,
                |buf| PropertyValueResponse::write_error(buf, 5, pid::MCB_TABLE, 1),
            );
            tx.send(Ok(response)).expect("request receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert!(matches!(
            result,
            Err(Error::PropertyValueUnavailable { object_index: 5, property_id })
                if property_id == pid::MCB_TABLE
        ));
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
        let client = management.await_programming_mode(Duration::from_millis(1), Duration::from_secs(1));
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
    async fn configured_programming_mode_wait_retries_a_rejected_scan() {
        let (tx, mut rx) = mpsc::channel(2);
        let management = NetworkManagement::new(&tx, source());
        let client = management.await_programming_mode(Duration::from_millis(1), Duration::from_secs(1));
        let device = async {
            let BusCommand::Scan { tx, .. } = rx.recv().await.expect("first scan command") else {
                panic!("expected a scan command")
            };
            tx.send(Err(Error::NegativeConfirmation)).expect("scan receiver remains alive");

            let BusCommand::Scan { tx, .. } = rx.recv().await.expect("second scan command") else {
                panic!("expected a scan command")
            };
            tx.send(Ok(vec![individual_address_response(current())])).expect("scan receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert_eq!(result.expect("programming-mode wait succeeds"), vec![current()]);
    }

    #[tokio::test]
    async fn open_medium_ia_scan_uses_system_broadcast_and_preserves_cardinality() {
        let (tx, mut rx) = mpsc::channel(1);
        let management = NetworkManagement::new(&tx, source());
        let client =
            management.read_individual_addresses(AddressTarget::OpenMediumProgrammingMode, Duration::from_millis(1));
        let device = async {
            let BusCommand::Scan { frame, tx, .. } = rx.recv().await.expect("scan command") else {
                panic!("expected a scan command")
            };
            let request = KnxMessageBuffer::from_buffer(frame);

            assert_eq!(request.get_dest_addr(), zweidraehte_proto::messages::knx::DestinationAddress::SystemBroadcast);
            assert_eq!(request.get_tpci(), Some(Tpci::DataSystemBroadcast));
            assert_eq!(request.get_apci_code(), ApciCode::IndividualAddressRead);

            tx.send(Ok(vec![
                open_medium_individual_address_response(current()),
                open_medium_individual_address_response(current()),
                open_medium_individual_address_response(desired()),
            ]))
            .expect("scan receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert_eq!(result.expect("open-medium IA scan succeeds"), vec![current(), current(), desired()]);
    }

    #[tokio::test]
    async fn singular_open_medium_ia_read_rejects_duplicate_responses() {
        let (tx, mut rx) = mpsc::channel(1);
        let management = NetworkManagement::new(&tx, source());
        let client =
            management.read_individual_address(AddressTarget::OpenMediumProgrammingMode, Duration::from_millis(1));
        let device = async {
            let BusCommand::Scan { tx, .. } = rx.recv().await.expect("scan command") else {
                panic!("expected a scan command")
            };

            tx.send(Ok(vec![
                open_medium_individual_address_response(current()),
                open_medium_individual_address_response(current()),
            ]))
            .expect("scan receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert!(matches!(result, Err(Error::MultipleProgrammingDevices(2))));
    }

    #[tokio::test]
    async fn open_medium_ia_write_uses_a_standard_system_broadcast() {
        use zweidraehte_proto::messages::knx::FrameType;

        let (tx, mut rx) = mpsc::channel(1);
        let management = NetworkManagement::new(&tx, source());
        let client =
            management.write_individual_address(AddressTarget::OpenMediumProgrammingMode, desired(), Protection::Plain);
        let device = async {
            let BusCommand::SendOnly { frame, tx } = rx.recv().await.expect("write command") else {
                panic!("expected a send-only command")
            };
            let request = KnxMessageBuffer::from_buffer(frame);

            assert_eq!(request.get_dest_addr(), zweidraehte_proto::messages::knx::DestinationAddress::SystemBroadcast);
            assert_eq!(request.get_tpci(), Some(Tpci::DataSystemBroadcast));
            assert_eq!(request.get_apci_code(), ApciCode::IndividualAddressWrite);
            assert_eq!(request.ctrl_field().ft(), FrameType::Standard);
            assert_eq!(IndividualAddressWrite::address_bytes(request.buf()), Some(desired().as_bytes()));

            tx.send(Ok(())).expect("write receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        result.expect("open-medium IA write succeeds");
    }

    #[tokio::test]
    async fn serial_assignment_is_a_noop_at_the_desired_address() {
        let (tx, mut rx) = mpsc::channel(4);
        let management = NetworkManagement::new(&tx, source());
        let client =
            management.assign_individual_address(&SERIAL, desired(), Duration::from_millis(1), Protection::Plain);
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
            let client =
                management.assign_individual_address(&SERIAL, desired(), Duration::from_millis(1), Protection::Plain);
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
        let client =
            management.assign_individual_address(&SERIAL, desired(), Duration::from_millis(1), Protection::Plain);
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
        let client =
            management.assign_individual_address(&SERIAL, desired(), Duration::from_millis(1), Protection::Plain);
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
            management.assign_individual_address(&SERIAL, desired(), Duration::from_millis(1), Protection::Secure {
                current: current(),
                key: KEY,
            });
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
        let client =
            management.assign_individual_address(&SERIAL, desired(), Duration::from_millis(1), Protection::Plain);
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

    #[tokio::test]
    async fn programming_mode_domain_scan_preserves_every_responder() {
        let pl = OpenMediumDomainAddress::Pl(0x42);
        let rf = OpenMediumDomainAddress::Rf([1, 2, 3, 4, 5, 6]);
        let (tx, mut rx) = mpsc::channel(1);
        let management = NetworkManagement::new(&tx, source());
        let client =
            management.read_domain_addresses(AddressTarget::OpenMediumProgrammingMode, Duration::from_millis(1));
        let device = async {
            let BusCommand::Scan { frame, tx, .. } = rx.recv().await.expect("scan command") else {
                panic!("expected a scan command")
            };
            let request = KnxMessageBuffer::from_buffer(frame);

            assert_eq!(request.get_dest_addr(), zweidraehte_proto::messages::knx::DestinationAddress::SystemBroadcast);
            assert_eq!(request.get_tpci(), Some(Tpci::DataSystemBroadcast));
            assert_eq!(request.get_apci_code(), ApciCode::DomainAddressRead);

            tx.send(Ok(vec![domain_response(current(), pl), domain_response(desired(), rf)]))
                .expect("scan receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert_eq!(result.expect("domain scan succeeds"), vec![(current(), pl), (desired(), rf)]);
    }

    #[tokio::test]
    async fn singular_programming_mode_domain_read_rejects_ambiguity() {
        let domain = OpenMediumDomainAddress::Pl(0x42);
        let (tx, mut rx) = mpsc::channel(1);
        let management = NetworkManagement::new(&tx, source());
        let client = management.read_domain_address(AddressTarget::OpenMediumProgrammingMode, Duration::from_millis(1));
        let device = async {
            let BusCommand::Scan { tx, .. } = rx.recv().await.expect("scan command") else {
                panic!("expected a scan command")
            };
            tx.send(Ok(vec![domain_response(current(), domain), domain_response(desired(), domain)]))
                .expect("scan receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert!(matches!(result, Err(Error::MultipleProgrammingDevices(2))));
    }

    #[tokio::test]
    async fn programming_mode_rf_domain_write_uses_a_standard_system_broadcast() {
        use zweidraehte_proto::messages::knx::FrameType;

        let domain = OpenMediumDomainAddress::Rf([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let (tx, mut rx) = mpsc::channel(1);
        let management = NetworkManagement::new(&tx, source());
        let client =
            management.write_domain_address(AddressTarget::OpenMediumProgrammingMode, domain, Protection::Plain);
        let device = async {
            let BusCommand::SendOnly { frame, tx } = rx.recv().await.expect("write command") else {
                panic!("expected a send-only command")
            };
            let request = KnxMessageBuffer::from_buffer(frame);

            assert_eq!(request.get_dest_addr(), zweidraehte_proto::messages::knx::DestinationAddress::SystemBroadcast);
            assert_eq!(request.get_tpci(), Some(Tpci::DataSystemBroadcast));
            assert_eq!(request.get_apci_code(), ApciCode::DomainAddressWrite);
            assert_eq!(request.ctrl_field().ft(), FrameType::Standard);
            assert_eq!(OpenMediumDomainAddress::parse(DomainAddressWrite::domain_address(request.buf())), Some(domain));

            tx.send(Ok(())).expect("write receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        result.expect("domain write succeeds");
    }

    #[tokio::test]
    async fn serial_domain_read_checks_the_echo_and_rejects_duplicates() {
        let domain = OpenMediumDomainAddress::Pl(0x7F);
        let (tx, mut rx) = mpsc::channel(1);
        let management = NetworkManagement::new(&tx, source());
        let client = management.verify_domain_address(AddressTarget::Serial(SERIAL), domain, Duration::from_millis(1));
        let device = async {
            let BusCommand::Scan { frame, tx, .. } = rx.recv().await.expect("scan command") else {
                panic!("expected a scan command")
            };
            let request = KnxMessageBuffer::from_buffer(frame);

            assert_eq!(request.get_dest_addr(), zweidraehte_proto::messages::knx::DestinationAddress::SystemBroadcast);
            assert_eq!(request.get_apci_code(), ApciCode::DomainAddressSerialNumberRead);
            assert_eq!(DomainAddressSerialNumberRead::serial_number(request.buf()), Some(SERIAL.as_slice()));

            tx.send(Ok(vec![serial_domain_response(current(), domain), serial_domain_response(desired(), domain)]))
                .expect("scan receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert!(matches!(result, Err(Error::DuplicateSerialNumber(2))));
    }

    #[tokio::test]
    async fn serial_domain_read_rejects_a_different_echoed_serial() {
        let domain = OpenMediumDomainAddress::Pl(0x7F);
        let (tx, mut rx) = mpsc::channel(1);
        let management = NetworkManagement::new(&tx, source());
        let client = management.read_domain_addresses(AddressTarget::Serial(SERIAL), Duration::from_millis(1));
        let device = async {
            let BusCommand::Scan { tx, .. } = rx.recv().await.expect("scan command") else {
                panic!("expected a scan command")
            };
            let mut response = serial_domain_response(current(), domain);
            response[offsets::MSG_APCI + 2] ^= 0x01;

            tx.send(Ok(vec![response])).expect("scan receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert!(matches!(result, Err(Error::UnexpectedResponse)));
    }

    #[tokio::test]
    async fn secure_serial_domain_write_uses_the_synchronized_system_broadcast_path() {
        use zweidraehte_proto::messages::knx::FrameType;

        const KEY: [u8; 16] = [0x5A; 16];

        let domain = OpenMediumDomainAddress::Rf([1, 3, 5, 7, 9, 11]);
        let (tx, mut rx) = mpsc::channel(1);
        let management = NetworkManagement::new(&tx, source());
        let client = management.write_domain_address(AddressTarget::Serial(SERIAL), domain, Protection::Secure {
            current: current(),
            key: KEY,
        });
        let device = async {
            let BusCommand::SecureSystemBroadcast { frame, at, key, tx } = rx.recv().await.expect("write command")
            else {
                panic!("expected a secure system-broadcast command")
            };
            let request = KnxMessageBuffer::from_buffer(frame);

            assert_eq!(at, current());
            assert_eq!(key, KEY);
            assert_eq!(request.get_dest_addr(), zweidraehte_proto::messages::knx::DestinationAddress::SystemBroadcast);
            assert_eq!(request.get_apci_code(), ApciCode::DomainAddressSerialNumberWrite);
            assert_eq!(request.ctrl_field().ft(), FrameType::Standard);
            assert_eq!(DomainAddressSerialNumberWrite::serial_number(request.buf()), Some(SERIAL.as_slice()));
            assert_eq!(
                OpenMediumDomainAddress::parse(DomainAddressSerialNumberWrite::domain_address(request.buf())),
                Some(domain)
            );

            tx.send(Ok(())).expect("write receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        result.expect("secure serial domain write succeeds");
    }
}
