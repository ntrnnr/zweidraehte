//! Connection-oriented (RCo) device management.

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::apdu::auth::{AuthorizeRequest, AuthorizeResponse};
use zweidraehte_proto::messages::apdu::coupler::{
    FilterTableOpenRequest, FilterTableReadRequest, FilterTableWriteRequest, RouterMemoryReadRequest,
    RouterMemoryWriteRequest,
};
use zweidraehte_proto::messages::apdu::device::{AdcRead, AdcResponse, DeviceDescriptorRead, DeviceDescriptorResponse};
use zweidraehte_proto::messages::apdu::function_property::FunctionPropertyHeader;
use zweidraehte_proto::messages::apdu::memory::{
    MemoryExtendedAccess, MemoryReadRequest, MemoryWriteRequest, UserMemoryReadRequest, UserMemoryWriteRequest,
};
use zweidraehte_proto::messages::apdu::property::{PropertyDescriptionRead, PropertyValueResponse};
use zweidraehte_proto::messages::apdu::property_ext::{
    FunctionPropertyExtRequest, PropertyExtDescription, PropertyExtDescriptionRead, PropertyExtValueRequest,
};
use zweidraehte_proto::messages::apdu::restart::{EraseCode, RestartError, RestartParsed, RestartResponse};
use zweidraehte_proto::messages::knx::{ApciCode, Tpci, offsets};
use zweidraehte_proto::pid;

use crate::bus::driver::{BusCommand, Completion, ConnectionId};
use crate::bus::frames;
use crate::bus::management::{self, FunctionPropertyResult, PropertyAddress, PropertyDescription};
use crate::bus::{BusError as Error, BusResult as Result};

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
    connection: ConnectionId,
    cmd_tx: mpsc::Sender<BusCommand>,
    secure_management: bool,
    last_security_sync_remote_sequence: Option<u64>,
    filter_table_open: bool,
}

/// Outcome of a master reset: how long the device says it needs before it
/// is reachable again.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RestartAck {
    pub process_time: Duration,
}

/// A device memory address space, and the service family that reaches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemorySpace {
    /// `A_Memory_*`: 16-bit memory.
    Standard,
    /// `A_MemoryExtended_*`: 24-bit memory whose writes return an explicit
    /// return code.
    Extended,
    /// `A_UserMemory_*`: the application's 20-bit logical user memory.
    User,
    /// `A_FilterTable_*`: legacy coupler Filter Table memory. Requires
    /// [`DeviceConnection::filter_table_open`] first.
    FilterTable,
    /// `A_RouterMemory_*`: legacy coupler Router memory.
    Router,
}

impl MemorySpace {
    fn family(self) -> management::MemoryFamily {
        match self {
            Self::Standard => management::MemoryFamily::Classic,
            Self::Extended => management::MemoryFamily::Extended,
            Self::User => management::MemoryFamily::User,
            Self::FilterTable => management::MemoryFamily::Filter,
            Self::Router => management::MemoryFamily::Router,
        }
    }
}

/// How a memory write is confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteCheck {
    /// The device acknowledges the transport frame; Verify Mode is off.
    /// Per 03/05/02 §3.16 this carries no application-level confirmation.
    Acknowledged,
    /// `PID_DEVICE_CONTROL.VerifyMode` is active, so the device answers the
    /// write with a response echoing the written bytes, which are compared.
    /// BCU2 download procedures confirm this way. This is not the same
    /// exchange as a write followed by a read.
    DeviceVerify,
    /// Write, then read the bytes back and compare (`DMP_MemWrite_RCoV`,
    /// 03/05/02 §3.16.3).
    ReadBack,
}

impl DeviceConnection {
    pub(crate) fn new(
        addr: IndividualAddress,
        cmd_tx: mpsc::Sender<BusCommand>,
        secure_management: bool,
        last_security_sync_remote_sequence: Option<u64>,
        connection: ConnectionId,
    ) -> Self {
        Self {
            addr,
            connection,
            cmd_tx,
            secure_management,
            last_security_sync_remote_sequence,
            filter_table_open: false,
        }
    }

    /// The device this connection talks to.
    pub fn address(&self) -> IndividualAddress {
        self.addr
    }

    /// Whether this transport connection is protected by authenticated KNX
    /// Data Secure management, including when it reused a recent sync.
    pub fn is_secure_management(&self) -> bool {
        self.secure_management
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
        self.request_raw(apci, msg_len, data_writer, Completion::Response(expected_apci)).await
    }

    /// Send a connected request that resolves on the device's T_ACK.
    async fn request_no_response(
        &mut self,
        apci: ApciCode,
        msg_len: usize,
        data_writer: impl FnOnce(&mut [u8]),
    ) -> Result<()> {
        self.request_raw(apci, msg_len, data_writer, Completion::Acknowledgement).await.map(|_| ())
    }

    async fn request_raw(
        &mut self,
        apci: ApciCode,
        msg_len: usize,
        data_writer: impl FnOnce(&mut [u8]),
        completion: Completion,
    ) -> Result<Vec<u8>> {
        management::validate_apdu_length(msg_len, self.secure_management)?;

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
        self.send_request(frame, completion).await
    }

    async fn send_request(&self, frame: Vec<u8>, completion: Completion) -> Result<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BusCommand::TlRequest { connection: self.connection, frame, completion, tx })
            .await
            .map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)?
    }

    // ========================================================================
    // Interface-object properties
    // ========================================================================
    //
    // Every property operation takes a [`PropertyAddress`]; its addressing
    // selects the standard service or the AN163 extended one.

    /// Read a property value (`DMP_InterfaceObjectRead_R`).
    pub async fn property_read(&mut self, property: PropertyAddress, start_idx: u16, count: u16) -> Result<Vec<u8>> {
        match property {
            PropertyAddress::Indexed { object_index, property_id } => {
                let property_id = u16::from(property_id);
                let property = management::ClassicProperty::new(object_index, property_id, start_idx, count)?;
                let buf = self
                    .request(ApciCode::PropertyValueRead, PropertyValueResponse::msg_len(0), |buf| {
                        PropertyValueResponse::write(buf, object_index, property_id, count, start_idx, &[])
                    })
                    .await?;
                Ok(property.response(&buf)?.to_vec())
            }
            PropertyAddress::Extended { object_type, object_instance, property_id } => {
                let raw_object_type = u16::from(object_type);
                let property =
                    management::ExtendedProperty::new(raw_object_type, object_instance, property_id, start_idx, count)?;
                let count = property.count();
                let buf = self
                    .request(ApciCode::PropertyExtValueRead, PropertyExtValueRequest::msg_len(0), |buf| {
                        PropertyExtValueRequest::write(
                            buf,
                            raw_object_type,
                            object_instance,
                            property_id,
                            count,
                            start_idx,
                            &[],
                        )
                    })
                    .await?;
                Ok(property.read_response(&buf)?.to_vec())
            }
        }
    }

    /// Write a property value (`DMP_InterfaceObjectWrite_R`) and check the
    /// device's response: the echoed value for standard addressing, the return
    /// code of the confirmed write for extended addressing.
    pub async fn property_write(
        &mut self,
        property: PropertyAddress,
        start_idx: u16,
        count: u16,
        data: &[u8],
    ) -> Result<()> {
        match property {
            PropertyAddress::Indexed { object_index, property_id } => {
                let property_id = u16::from(property_id);
                let property = management::ClassicProperty::new(object_index, property_id, start_idx, count)?;
                property.validate_write(data)?;
                let buf = self
                    .request(ApciCode::PropertyValueWrite, PropertyValueResponse::msg_len(data.len()), |buf| {
                        PropertyValueResponse::write(buf, object_index, property_id, count, start_idx, data)
                    })
                    .await?;
                property.response(&buf).map(|_| ())
            }
            PropertyAddress::Extended { object_type, object_instance, property_id } => {
                let raw_object_type = u16::from(object_type);
                let property =
                    management::ExtendedProperty::new(raw_object_type, object_instance, property_id, start_idx, count)?;
                property.validate_write(data)?;
                let count = property.count();
                let buf = self
                    .request(ApciCode::PropertyExtValueWriteCon, PropertyExtValueRequest::msg_len(data.len()), |buf| {
                        PropertyExtValueRequest::write(
                            buf,
                            raw_object_type,
                            object_instance,
                            property_id,
                            count,
                            start_idx,
                            data,
                        )
                    })
                    .await?;
                property.write_response(&buf)
            }
        }
    }

    /// Write an extended-addressed property without an application response.
    ///
    /// `A_PropertyExtValue_WriteUnCon` is acknowledged by the transport
    /// connection only. The remote application deliberately ignores invalid
    /// targets, so callers that need proof must choose
    /// [`property_write`](Self::property_write) or perform a separate
    /// read-back. Standard addressing has no unconfirmed write and is refused.
    pub async fn property_write_unconfirmed(
        &mut self,
        property: PropertyAddress,
        start_idx: u16,
        count: u16,
        data: &[u8],
    ) -> Result<()> {
        let PropertyAddress::Extended { object_type, object_instance, property_id } = property else {
            return Err(Error::Unsupported("an unconfirmed property write needs extended addressing"));
        };
        let raw_object_type = u16::from(object_type);
        let property =
            management::ExtendedProperty::new(raw_object_type, object_instance, property_id, start_idx, count)?;
        property.validate_write(data)?;
        let count = property.count();
        self.request_no_response(
            ApciCode::PropertyExtValueWriteUnCon,
            PropertyExtValueRequest::msg_len(data.len()),
            |buf| {
                PropertyExtValueRequest::write(
                    buf,
                    raw_object_type,
                    object_instance,
                    property_id,
                    count,
                    start_idx,
                    data,
                )
            },
        )
        .await
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
                connection: self.connection,
                frame,
                expected_apci: ApciCode::PropertyExtValueWriteConRes,
                new_key,
                tx,
            })
            .await
            .map_err(|_| Error::WorkerGone)?;
        let buf = rx.await.map_err(|_| Error::WorkerGone)??;
        management::ExtendedProperty::new(
            security_object_type,
            SECURITY_OBJECT_INSTANCE,
            pid::security::TOOL_KEY,
            1,
            1,
        )?
        .write_response(&buf)
    }

    /// Read a property's description by property ID.
    ///
    /// A negative response zeroes the type, element count and access levels;
    /// see [`PropertyDescription::is_absent`].
    ///
    /// There is deliberately no corresponding write API: 03/03/07 defines
    /// only `A_PropertyDescription_Read/Response`. Load-control descriptor
    /// declarations describe tool-side cached metadata rather than bus writes.
    // TODO: expose the lookup by property index (property ID 0) if a client
    // needs to enumerate an object's properties; only the device stacks'
    // tests exercise it today.
    pub async fn property_description_read(&mut self, property: PropertyAddress) -> Result<PropertyDescription> {
        match property {
            PropertyAddress::Indexed { object_index, property_id } => {
                let buf = self
                    .request(ApciCode::PropertyDescriptionRead, PropertyDescriptionRead::MIN_MSG_LEN, |buf| {
                        PropertyDescriptionRead::write(buf, object_index, u16::from(property_id), 0)
                    })
                    .await?;
                let description =
                    PropertyDescription::parse(&buf).ok_or(Error::Parse("PropertyDescriptionResponse too short"))?;
                if buf[offsets::MSG_APCI + 2] != object_index || description.prop_id != u16::from(property_id) {
                    return Err(Error::UnexpectedResponse);
                }
                Ok(description)
            }
            PropertyAddress::Extended { object_type, object_instance, property_id } => {
                let raw_object_type = u16::from(object_type);
                management::validate_extended_target(object_instance, property_id)?;

                let buf = self
                    .request(ApciCode::PropertyExtDescriptionRead, PropertyExtDescriptionRead::MSG_LEN, |buf| {
                        PropertyExtDescriptionRead::write(buf, raw_object_type, object_instance, property_id, 0, 0)
                    })
                    .await?;
                let description = PropertyExtDescription::parse(&buf)
                    .ok_or(Error::Parse("PropertyExtDescriptionResponse too short"))?;
                if description.object_type != raw_object_type
                    || description.object_instance != object_instance
                    || description.prop_id != property_id
                {
                    return Err(Error::UnexpectedResponse);
                }
                Ok(PropertyDescription::from_extended(description))
            }
        }
    }

    async fn function_property_request(
        &mut self,
        command: bool,
        property: PropertyAddress,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        match property {
            PropertyAddress::Indexed { object_index, property_id } => {
                let property_id = u16::from(property_id);
                let apci =
                    if command { ApciCode::FunctionPropertyCommand } else { ApciCode::FunctionPropertyStateRead };
                let buf = self
                    .request(apci, FunctionPropertyHeader::msg_len(service_data.len()), |buf| {
                        FunctionPropertyHeader::write(buf, object_index, property_id, service_data)
                    })
                    .await?;
                FunctionPropertyResult::parse(&buf, object_index, property_id)
            }
            PropertyAddress::Extended { object_type, object_instance, property_id } => {
                management::validate_extended_target(object_instance, property_id)?;

                let apci =
                    if command { ApciCode::FunctionPropertyExtCommand } else { ApciCode::FunctionPropertyExtStateRead };
                let raw_object_type = u16::from(object_type);
                let buf = self
                    .request(apci, FunctionPropertyExtRequest::msg_len(service_data.len()), |buf| {
                        FunctionPropertyExtRequest::write(
                            buf,
                            raw_object_type,
                            object_instance,
                            property_id,
                            service_data,
                        )
                    })
                    .await?;
                FunctionPropertyResult::parse_extended(&buf, raw_object_type, object_instance, property_id)
            }
        }
    }

    /// Execute a function property command.
    pub async fn function_property_command(
        &mut self,
        property: PropertyAddress,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        self.function_property_request(true, property, service_data).await
    }

    /// Read the state of a function property.
    pub async fn function_property_state_read(
        &mut self,
        property: PropertyAddress,
        service_data: &[u8],
    ) -> Result<FunctionPropertyResult> {
        self.function_property_request(false, property, service_data).await
    }

    /// Enable KNX Data Secure management through Security IO.
    ///
    /// This is the policy transition required before replacing an FDSK with a
    /// commissioned Tool Key or loading secure application tables. Keeping
    /// the object identity and function-property payload here prevents each
    /// programming entry point from spelling the protocol record itself.
    pub async fn enable_security_mode(&mut self) -> Result<()> {
        let security_mode = PropertyAddress::Extended {
            object_type: InterfaceObjectType::Security,
            object_instance: 1,
            property_id: pid::security::SECURITY_MODE,
        };
        let result = self.function_property_command(security_mode, &[0, 0, 1]).await?;
        if result.return_code != 0 {
            return Err(Error::DeviceError(result.return_code));
        }
        Ok(())
    }

    /// Read and sum one ADC channel over `count` consecutive conversions.
    pub async fn adc_read(&mut self, channel: u8, count: u8) -> Result<u16> {
        if channel > 0x3F {
            return Err(Error::Parse("ADC channel exceeds six bits"));
        }
        if count == 0 {
            return Err(Error::Parse("ADC read count is zero"));
        }

        let buf =
            self.request(ApciCode::AdcRead, AdcRead::MIN_MSG_LEN, |buf| AdcRead::write(buf, channel, count)).await?;
        let response = AdcResponse::parse(&buf).ok_or(Error::Parse("AdcResponse too short"))?;

        if response.count == 0 {
            return Err(Error::DeviceError(0));
        }
        if response.channel != channel || response.count != count || buf.len() != AdcResponse::MSG_LEN {
            return Err(Error::UnexpectedResponse);
        }

        Ok(response.sum)
    }

    // ========================================================================
    // Memory
    // ========================================================================

    /// Select the legacy Filter Table memory access procedure.
    ///
    /// The application-layer specification defines no close service. The
    /// selection remains valid for this transport connection, which is ended
    /// by [`close`](Self::close).
    pub async fn filter_table_open(&mut self) -> Result<()> {
        self.request_no_response(ApciCode::FilterTableOpen, FilterTableOpenRequest::MSG_LEN, |_| {}).await?;
        self.filter_table_open = true;

        Ok(())
    }

    /// Read `count` bytes at `address` in `space` (`DMP_MemRead_RCo` and its
    /// counterparts). The address must fit the space's width.
    pub async fn memory_read(&mut self, space: MemorySpace, address: u32, count: u8) -> Result<Vec<u8>> {
        let transfer = management::MemoryTransfer::new(space.family(), address, usize::from(count))?;
        if space == MemorySpace::FilterTable && !self.filter_table_open {
            return Err(Error::FilterTableNotOpen);
        }

        let buf = match space {
            MemorySpace::Standard => {
                let address = u16::try_from(address).expect("checked standard memory address");
                self.request(ApciCode::MemoryRead, MemoryReadRequest::MSG_LEN, |buf| {
                    MemoryReadRequest::write(buf, count, address)
                })
                .await?
            }
            MemorySpace::Extended => {
                self.request(ApciCode::MemoryExtendedRead, MemoryExtendedAccess::msg_len(0), |buf| {
                    MemoryExtendedAccess::write(buf, count, address, &[])
                })
                .await?
            }
            MemorySpace::User => {
                self.request(ApciCode::UserMemoryRead, UserMemoryReadRequest::MSG_LEN, |buf| {
                    UserMemoryReadRequest::write(buf, address, count)
                })
                .await?
            }
            MemorySpace::FilterTable => {
                let address = u16::try_from(address).expect("checked coupler address");
                self.request(ApciCode::FilterTableRead, FilterTableReadRequest::MSG_LEN, |buf| {
                    FilterTableReadRequest::write(buf, address, count)
                })
                .await?
            }
            MemorySpace::Router => {
                let address = u16::try_from(address).expect("checked coupler address");
                self.request(ApciCode::RouterMemoryRead, RouterMemoryReadRequest::MSG_LEN, |buf| {
                    RouterMemoryReadRequest::write(buf, address, count)
                })
                .await?
            }
        };
        Ok(transfer.read_response(&buf)?.to_vec())
    }

    /// Write `data` at `address` in `space`, confirming it as `check` says.
    ///
    /// The extended service always confirms with an explicit return code, so
    /// it accepts [`WriteCheck::Acknowledged`] and [`WriteCheck::ReadBack`]
    /// but refuses [`WriteCheck::DeviceVerify`]: it has no Verify Mode echo.
    pub async fn memory_write(
        &mut self,
        space: MemorySpace,
        address: u32,
        data: &[u8],
        check: WriteCheck,
    ) -> Result<()> {
        let transfer = management::MemoryTransfer::new(space.family(), address, data.len())?;
        if space == MemorySpace::FilterTable && !self.filter_table_open {
            return Err(Error::FilterTableNotOpen);
        }
        if space == MemorySpace::Extended && check == WriteCheck::DeviceVerify {
            return Err(Error::Unsupported("extended memory writes have no Verify Mode response"));
        }

        // Verify Mode turns each write into a response-bearing service that
        // echoes the written bytes; without it the write resolves on T_ACK.
        let completion = |response| {
            if check == WriteCheck::DeviceVerify {
                Completion::Response(Some(response))
            } else {
                Completion::Acknowledgement
            }
        };
        let response = match space {
            MemorySpace::Standard => {
                let address = u16::try_from(address).expect("checked standard memory address");
                self.request_raw(
                    ApciCode::MemoryWrite,
                    MemoryWriteRequest::msg_len(data.len()),
                    |buf| MemoryWriteRequest::write(buf, address, data),
                    completion(ApciCode::MemoryReadResponse),
                )
                .await?
            }
            MemorySpace::Extended => {
                let count =
                    u8::try_from(data.len()).map_err(|_| Error::Parse("extended memory write exceeds one octet"))?;
                let buf = self
                    .request(ApciCode::MemoryExtendedWrite, MemoryExtendedAccess::msg_len(data.len()), |buf| {
                        MemoryExtendedAccess::write(buf, count, address, data)
                    })
                    .await?;
                transfer.extended_write_response(&buf)?;
                Vec::new()
            }
            MemorySpace::User => {
                self.request_raw(
                    ApciCode::UserMemoryWrite,
                    UserMemoryWriteRequest::msg_len(data.len()),
                    |buf| UserMemoryWriteRequest::write(buf, address, data),
                    completion(ApciCode::UserMemoryResponse),
                )
                .await?
            }
            MemorySpace::FilterTable => {
                let address = u16::try_from(address).expect("checked coupler address");
                self.request_raw(
                    ApciCode::FilterTableWrite,
                    FilterTableWriteRequest::msg_len(data.len()),
                    |buf| FilterTableWriteRequest::write(buf, address, data),
                    completion(ApciCode::FilterTableResponse),
                )
                .await?
            }
            MemorySpace::Router => {
                let address = u16::try_from(address).expect("checked coupler address");
                self.request_raw(
                    ApciCode::RouterMemoryWrite,
                    RouterMemoryWriteRequest::msg_len(data.len()),
                    |buf| RouterMemoryWriteRequest::write(buf, address, data),
                    completion(ApciCode::RouterMemoryResponse),
                )
                .await?
            }
        };

        match check {
            WriteCheck::Acknowledged => Ok(()),
            WriteCheck::DeviceVerify => transfer.verify_response(&response, data),
            WriteCheck::ReadBack => {
                let count = u8::try_from(data.len()).map_err(|_| Error::Parse("read-back exceeds one octet"))?;
                if self.memory_read(space, address, count).await? != data {
                    return Err(Error::VerifyMismatch { address });
                }
                Ok(())
            }
        }
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
                Completion::Response(None),
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
        self.cmd_tx
            .send(BusCommand::TlClose { connection: self.connection, tx })
            .await
            .map_err(|_| Error::WorkerGone)?;
        rx.await.map_err(|_| Error::WorkerGone)?
    }
}

#[cfg(test)]
mod tests {
    use zweidraehte_proto::messages::apdu::coupler::CouplerMemoryAccess;
    use zweidraehte_proto::messages::apdu::memory::UserMemoryAccess;
    use zweidraehte_proto::messages::apdu::property::PropertyValueHeader;
    use zweidraehte_proto::messages::knx::KnxMessageBuffer;

    use super::*;
    use zweidraehte_proto::messages::apdu::coupler::{FilterTableResponse, RouterMemoryResponse};
    use zweidraehte_proto::messages::apdu::memory::{MemoryResponse, UserMemoryResponse};
    use zweidraehte_proto::messages::apdu::property_ext::PropertyExtValueHeader;

    fn target() -> IndividualAddress {
        IndividualAddress::new(1, 1, 10)
    }

    fn source() -> IndividualAddress {
        IndividualAddress::new(1, 1, 1)
    }

    #[tokio::test]
    async fn classic_property_read_reports_a_typed_negative_response() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        let mut connection = DeviceConnection::new(target(), cmd_tx, false, None, ConnectionId::TEST);
        let client =
            connection.property_read(PropertyAddress::indexed(5, pid::MCB_TABLE).expect("PID fits one octet"), 1, 1);
        let device = async {
            let BusCommand::TlRequest { frame, completion, tx, .. } = cmd_rx.recv().await.expect("property-value read")
            else {
                panic!("expected a connected request")
            };
            let request = KnxMessageBuffer::from_buffer(frame);
            let header = PropertyValueHeader::parse(request.buf()).expect("complete property-value read");

            assert_eq!(request.get_apci_code(), ApciCode::PropertyValueRead);
            assert_eq!(completion, Completion::Response(Some(ApciCode::PropertyValueResponse)));
            assert_eq!((header.object_idx, header.prop_id, header.start_idx, header.count), (5, pid::MCB_TABLE, 1, 1));

            let response = frames::build_individual_frame(
                target(),
                source(),
                Tpci::DataConnected(0),
                ApciCode::PropertyValueResponse,
                PropertyValueResponse::ERROR_MSG_LEN,
                |buf| PropertyValueResponse::write_error(buf, 5, pid::MCB_TABLE, 1),
            );
            tx.send(Ok(response)).expect("request receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        let error = result.expect_err("count-zero response is negative");
        assert!(matches!(
            &error,
            Error::PropertyValueUnavailable { object_index: 5, property_id } if *property_id == pid::MCB_TABLE
        ));
        assert_eq!(error.to_string(), "property 27 on interface object 5 is unavailable");
    }

    #[tokio::test]
    async fn classic_property_write_reports_a_typed_negative_response() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        let mut connection = DeviceConnection::new(target(), cmd_tx, false, None, ConnectionId::TEST);
        let client = connection.property_write(
            PropertyAddress::indexed(4, pid::PROGRAM_VERSION).expect("PID fits one octet"),
            1,
            1,
            &[0x12, 0x34],
        );
        let device = async {
            let BusCommand::TlRequest { frame, completion, tx, .. } =
                cmd_rx.recv().await.expect("property-value write")
            else {
                panic!("expected a connected request")
            };
            let request = KnxMessageBuffer::from_buffer(frame);
            let header = PropertyValueHeader::parse(request.buf()).expect("complete property-value write");

            assert_eq!(request.get_apci_code(), ApciCode::PropertyValueWrite);
            assert_eq!(completion, Completion::Response(Some(ApciCode::PropertyValueResponse)));
            assert_eq!(
                (header.object_idx, header.prop_id, header.start_idx, header.count),
                (4, pid::PROGRAM_VERSION, 1, 1)
            );
            assert_eq!(header.data(request.buf()), [0x12, 0x34]);

            let response = frames::build_individual_frame(
                target(),
                source(),
                Tpci::DataConnected(0),
                ApciCode::PropertyValueResponse,
                PropertyValueResponse::ERROR_MSG_LEN,
                |buf| PropertyValueResponse::write_error(buf, 4, pid::PROGRAM_VERSION, 1),
            );
            tx.send(Ok(response)).expect("request receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert!(matches!(
            result,
            Err(Error::PropertyValueUnavailable { object_index: 4, property_id })
                if property_id == pid::PROGRAM_VERSION
        ));
    }

    #[tokio::test]
    async fn adc_read_validates_echoed_channel_and_count() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        let mut connection = DeviceConnection::new(target(), cmd_tx, false, None, ConnectionId::TEST);
        let client = connection.adc_read(7, 3);
        let device = async {
            let BusCommand::TlRequest { frame, completion, tx, .. } = cmd_rx.recv().await.expect("ADC request") else {
                panic!("expected a connected request")
            };
            let request = KnxMessageBuffer::from_buffer(frame);
            let request_data = AdcRead::parse(request.buf()).expect("complete ADC request");

            assert_eq!(request.get_apci_code(), ApciCode::AdcRead);
            assert_eq!(completion, Completion::Response(Some(ApciCode::AdcResponse)));
            assert_eq!((request_data.channel, request_data.count), (7, 3));

            let response = frames::build_individual_frame(
                target(),
                source(),
                Tpci::DataConnected(0),
                ApciCode::AdcResponse,
                AdcResponse::MSG_LEN,
                |buf| AdcResponse::write(buf, 7, 3, 0x1234),
            );
            tx.send(Ok(response)).expect("request receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert_eq!(result.expect("ADC read succeeds"), 0x1234);
    }

    #[tokio::test]
    async fn user_memory_read_encodes_twenty_bit_address_and_checks_response() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        let mut connection = DeviceConnection::new(target(), cmd_tx, false, None, ConnectionId::TEST);
        let client = connection.memory_read(MemorySpace::User, 0xA_1234, 3);
        let device = async {
            let BusCommand::TlRequest { frame, completion, tx, .. } = cmd_rx.recv().await.expect("user-memory request")
            else {
                panic!("expected a connected request")
            };
            let request = KnxMessageBuffer::from_buffer(frame);
            let access = UserMemoryAccess::parse_read(request.buf()).expect("complete user-memory request");

            assert_eq!(request.get_apci_code(), ApciCode::UserMemoryRead);
            assert_eq!(completion, Completion::Response(Some(ApciCode::UserMemoryResponse)));
            assert_eq!(access.full_address(), 0xA_1234);
            assert_eq!(access.count, 3);

            let response = frames::build_individual_frame(
                target(),
                source(),
                Tpci::DataConnected(0),
                ApciCode::UserMemoryResponse,
                UserMemoryResponse::msg_len(3),
                |buf| UserMemoryResponse::write(buf, 0xA, 3, 0x1234, &[0x11, 0x22, 0x33]),
            );
            tx.send(Ok(response)).expect("request receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert_eq!(result.expect("user-memory read succeeds"), [0x11, 0x22, 0x33]);
    }

    #[tokio::test]
    async fn filter_table_requires_open_then_uses_acknowledged_writes() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(2);
        let mut connection = DeviceConnection::new(target(), cmd_tx, false, None, ConnectionId::TEST);
        let client = async {
            assert!(matches!(
                connection.memory_write(MemorySpace::FilterTable, 0x4000, &[0xAA], WriteCheck::Acknowledged).await,
                Err(Error::FilterTableNotOpen)
            ));

            connection.filter_table_open().await?;
            connection.memory_write(MemorySpace::FilterTable, 0x4000, &[0xAA, 0xBB], WriteCheck::Acknowledged).await
        };
        let device = async {
            let BusCommand::TlRequest { frame, completion, tx, .. } = cmd_rx.recv().await.expect("filter-table open")
            else {
                panic!("expected a connected request")
            };
            let request = KnxMessageBuffer::from_buffer(frame);
            assert_eq!(request.get_apci_code(), ApciCode::FilterTableOpen);
            assert_eq!(completion, Completion::Acknowledgement);
            tx.send(Ok(Vec::new())).expect("request receiver remains alive");

            let BusCommand::TlRequest { frame, completion, tx, .. } = cmd_rx.recv().await.expect("filter-table write")
            else {
                panic!("expected a connected request")
            };
            let request = KnxMessageBuffer::from_buffer(frame);
            let access = CouplerMemoryAccess::parse_data(request.buf()).expect("complete filter-table write");
            assert_eq!(request.get_apci_code(), ApciCode::FilterTableWrite);
            assert_eq!(completion, Completion::Acknowledgement);
            assert_eq!(access.address, 0x4000);
            assert_eq!(access.data, &[0xAA, 0xBB]);
            tx.send(Ok(Vec::new())).expect("request receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        result.expect("filter-table procedure succeeds");
    }

    #[tokio::test]
    async fn router_memory_read_uses_the_router_response_service() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        let mut connection = DeviceConnection::new(target(), cmd_tx, false, None, ConnectionId::TEST);
        let client = connection.memory_read(MemorySpace::Router, 0xFFFC, 4);
        let device = async {
            let BusCommand::TlRequest { frame, completion, tx, .. } = cmd_rx.recv().await.expect("router-memory read")
            else {
                panic!("expected a connected request")
            };
            let request = KnxMessageBuffer::from_buffer(frame);
            assert_eq!(request.get_apci_code(), ApciCode::RouterMemoryRead);
            assert_eq!(completion, Completion::Response(Some(ApciCode::RouterMemoryResponse)));

            let response = frames::build_individual_frame(
                target(),
                source(),
                Tpci::DataConnected(0),
                ApciCode::RouterMemoryResponse,
                RouterMemoryResponse::msg_len(4),
                |buf| RouterMemoryResponse::write(buf, 0xFFFC, &[1, 2, 3, 4]),
            );
            tx.send(Ok(response)).expect("request receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        assert_eq!(result.expect("router-memory read succeeds"), [1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn auto_verify_writes_wait_for_each_memory_response() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        let mut connection = DeviceConnection::new(target(), cmd_tx, false, None, ConnectionId::TEST);
        let client = async {
            connection.memory_write(MemorySpace::User, 0xA_1234, &[0x11, 0x22], WriteCheck::DeviceVerify).await?;
            connection.filter_table_open().await?;
            connection.memory_write(MemorySpace::FilterTable, 0x4000, &[0x33], WriteCheck::DeviceVerify).await?;
            connection.memory_write(MemorySpace::Router, 0x5000, &[0x44, 0x55], WriteCheck::DeviceVerify).await
        };
        let device = async {
            let BusCommand::TlRequest { completion, tx, .. } = cmd_rx.recv().await.expect("user-memory write") else {
                panic!("expected a connected request")
            };
            assert_eq!(completion, Completion::Response(Some(ApciCode::UserMemoryResponse)));
            let response = frames::build_individual_frame(
                target(),
                source(),
                Tpci::DataConnected(0),
                ApciCode::UserMemoryResponse,
                UserMemoryResponse::msg_len(2),
                |buf| UserMemoryResponse::write(buf, 0xA, 2, 0x1234, &[0x11, 0x22]),
            );
            tx.send(Ok(response)).expect("request receiver remains alive");

            let BusCommand::TlRequest { completion, tx, .. } = cmd_rx.recv().await.expect("filter-table open") else {
                panic!("expected a connected request")
            };
            assert_eq!(completion, Completion::Acknowledgement);
            tx.send(Ok(Vec::new())).expect("request receiver remains alive");

            let BusCommand::TlRequest { completion, tx, .. } = cmd_rx.recv().await.expect("filter-table write") else {
                panic!("expected a connected request")
            };
            assert_eq!(completion, Completion::Response(Some(ApciCode::FilterTableResponse)));
            let response = frames::build_individual_frame(
                target(),
                source(),
                Tpci::DataConnected(0),
                ApciCode::FilterTableResponse,
                FilterTableResponse::msg_len(1),
                |buf| FilterTableResponse::write(buf, 0x4000, &[0x33]),
            );
            tx.send(Ok(response)).expect("request receiver remains alive");

            let BusCommand::TlRequest { completion, tx, .. } = cmd_rx.recv().await.expect("router-memory write") else {
                panic!("expected a connected request")
            };
            assert_eq!(completion, Completion::Response(Some(ApciCode::RouterMemoryResponse)));
            let response = frames::build_individual_frame(
                target(),
                source(),
                Tpci::DataConnected(0),
                ApciCode::RouterMemoryResponse,
                RouterMemoryResponse::msg_len(2),
                |buf| RouterMemoryResponse::write(buf, 0x5000, &[0x44, 0x55]),
            );
            tx.send(Ok(response)).expect("request receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        result.expect("auto-verified memory writes succeed");
    }

    #[tokio::test]
    async fn unconfirmed_extended_property_write_resolves_on_transport_ack() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        let mut connection = DeviceConnection::new(target(), cmd_tx, false, None, ConnectionId::TEST);
        let client = connection.property_write_unconfirmed(
            PropertyAddress::Extended {
                object_type: InterfaceObjectType::ApplicationProgram,
                object_instance: 1,
                property_id: 0x123,
            },
            7,
            2,
            &[0xAA, 0xBB, 0xCC, 0xDD],
        );
        let device = async {
            let BusCommand::TlRequest { frame, completion, tx, .. } =
                cmd_rx.recv().await.expect("unconfirmed property write")
            else {
                panic!("expected a connected request")
            };
            let request = KnxMessageBuffer::from_buffer(frame);
            let header = PropertyExtValueHeader::parse(request.buf()).expect("complete extended-property write");

            assert_eq!(request.get_apci_code(), ApciCode::PropertyExtValueWriteUnCon);
            assert_eq!(completion, Completion::Acknowledgement);
            assert_eq!(header.object_instance, 1);
            assert_eq!(header.prop_id, 0x123);
            assert_eq!(header.count, 2);
            assert_eq!(header.start_idx, 7);
            assert_eq!(header.data(request.buf()), &[0xAA, 0xBB, 0xCC, 0xDD]);
            tx.send(Ok(Vec::new())).expect("request receiver remains alive");
        };
        let (result, ()) = tokio::join!(client, device);

        result.expect("unconfirmed property write succeeds");
    }

    #[tokio::test]
    async fn management_services_reject_out_of_range_fields_before_sending() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        let mut connection = DeviceConnection::new(target(), cmd_tx, false, None, ConnectionId::TEST);

        assert!(connection.adc_read(64, 1).await.is_err());
        assert!(connection.adc_read(1, 0).await.is_err());
        assert!(connection.memory_read(MemorySpace::User, 0x10_0000, 1).await.is_err());
        assert!(connection.memory_write(MemorySpace::User, 0xF_FFFF, &[1, 2], WriteCheck::Acknowledged).await.is_err());
        assert!(connection.memory_read(MemorySpace::Router, 0xFFFF, 2).await.is_err());
        assert!(connection.memory_write(MemorySpace::Router, 0, &[], WriteCheck::Acknowledged).await.is_err());
        assert!(
            connection
                .property_write_unconfirmed(
                    PropertyAddress::Extended {
                        object_type: InterfaceObjectType::Device,
                        object_instance: 0,
                        property_id: 1
                    },
                    1,
                    1,
                    &[1]
                )
                .await
                .is_err()
        );

        assert!(cmd_rx.try_recv().is_err(), "invalid operations send no traffic");
    }

    #[tokio::test]
    async fn narrow_management_fields_reject_truncation_without_traffic() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        let mut connection = DeviceConnection::new(target(), cmd_tx, false, None, ConnectionId::TEST);
        macro_rules! rejected {
            ($operation:expr) => {
                assert!(
                    matches!(
                        tokio::time::timeout(Duration::from_millis(50), $operation).await,
                        Ok(Err(Error::Parse(_)))
                    ),
                    "invalid request must fail locally: {}",
                    stringify!($operation)
                );
                assert!(cmd_rx.try_recv().is_err(), "invalid request sends no frame");
            };
        }
        // A classic PID beyond one octet cannot even be addressed.
        assert!(matches!(PropertyAddress::indexed(0, 256), Err(Error::Parse(_))));
        rejected!(connection.property_read(PropertyAddress::indexed(0, 1).expect("PID fits one octet"), 4096, 1));
        rejected!(connection.property_read(PropertyAddress::indexed(0, 1).expect("PID fits one octet"), 4095, 2));
        rejected!(connection.property_read(PropertyAddress::indexed(0, 1).expect("PID fits one octet"), 1, 16));
        rejected!(
            connection.property_write(PropertyAddress::indexed(0, 1).expect("PID fits one octet"), 1, 2, &[1, 2, 3])
        );
        rejected!(connection.property_read(
            PropertyAddress::Extended { object_type: InterfaceObjectType::Device, object_instance: 0, property_id: 1 },
            1,
            1
        ));
        rejected!(connection.property_read(
            PropertyAddress::Extended {
                object_type: InterfaceObjectType::Device,
                object_instance: 4096,
                property_id: 1
            },
            1,
            1
        ));
        rejected!(connection.property_read(
            PropertyAddress::Extended {
                object_type: InterfaceObjectType::Device,
                object_instance: 1,
                property_id: 4096
            },
            1,
            1
        ));
        rejected!(connection.property_read(
            PropertyAddress::Extended { object_type: InterfaceObjectType::Device, object_instance: 1, property_id: 1 },
            65535,
            2
        ));
        rejected!(connection.property_write(
            PropertyAddress::Extended { object_type: InterfaceObjectType::Device, object_instance: 1, property_id: 1 },
            1,
            2,
            &[1]
        ));
        rejected!(connection.function_property_state_read(
            PropertyAddress::Extended { object_type: InterfaceObjectType::Device, object_instance: 0, property_id: 1 },
            &[]
        ));
        rejected!(connection.memory_read(MemorySpace::Standard, 0, 64));
        rejected!(connection.memory_read(MemorySpace::Standard, 65535, 2));
        rejected!(connection.memory_write(MemorySpace::Standard, 0, &[0; 64], WriteCheck::Acknowledged));
        rejected!(connection.memory_write(MemorySpace::Standard, 65535, &[1, 2], WriteCheck::DeviceVerify));
        rejected!(connection.memory_read(MemorySpace::Extended, 0x1000000, 1));
        rejected!(connection.memory_write(MemorySpace::Extended, 0xffffff, &[1, 2], WriteCheck::Acknowledged));
    }

    #[tokio::test]
    async fn classic_property_response_checks_echo_and_complete_elements() {
        for (object, property, start, count, data) in [
            (2, 3, 7, 2, vec![1, 2]),
            (1, 4, 7, 2, vec![1, 2]),
            (1, 3, 8, 2, vec![1, 2]),
            (1, 3, 7, 1, vec![1]),
            (1, 3, 7, 2, vec![1]),
            (1, 3, 7, 2, vec![]),
            (2, 3, 7, 0, vec![]),
        ] {
            let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
            let mut connection = DeviceConnection::new(target(), cmd_tx, false, None, ConnectionId::TEST);
            let client = connection.property_read(PropertyAddress::indexed(1, 3).expect("PID fits one octet"), 7, 2);
            let peer = async {
                let BusCommand::TlRequest { tx, .. } = cmd_rx.recv().await.expect("request") else {
                    panic!("connected request")
                };
                let response = frames::build_individual_frame(
                    target(),
                    source(),
                    Tpci::DataConnected(0),
                    ApciCode::PropertyValueResponse,
                    PropertyValueResponse::msg_len(data.len()),
                    |buf| PropertyValueResponse::write(buf, object, property, count, start, &data),
                );
                tx.send(Ok(response)).expect("request receiver");
            };
            let (result, ()) = tokio::join!(client, peer);
            assert!(matches!(result, Err(Error::UnexpectedResponse)), "mismatched response: {result:?}");
        }
    }

    #[tokio::test]
    async fn classic_memory_response_checks_address_count_and_exact_length() {
        for (address, count, data, trailing) in [
            (0x101, 2, vec![1, 2], false),
            (0x100, 1, vec![1], false),
            (0x100, 2, vec![1], false),
            (0x100, 2, vec![1, 2], true),
        ] {
            let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
            let mut connection = DeviceConnection::new(target(), cmd_tx, false, None, ConnectionId::TEST);
            let client = connection.memory_read(MemorySpace::Standard, 0x100, 2);
            let peer = async {
                let BusCommand::TlRequest { tx, .. } = cmd_rx.recv().await.expect("request") else {
                    panic!("connected request")
                };
                let mut response = frames::build_individual_frame(
                    target(),
                    source(),
                    Tpci::DataConnected(0),
                    ApciCode::MemoryReadResponse,
                    MemoryResponse::msg_len(data.len()),
                    |buf| MemoryResponse::write(buf, count, address, &data),
                );
                if trailing {
                    response.push(99);
                }
                tx.send(Ok(response)).expect("request receiver");
            };
            let (result, ()) = tokio::join!(client, peer);
            assert!(matches!(result, Err(Error::UnexpectedResponse)), "mismatched response: {result:?}");
        }
    }
}
