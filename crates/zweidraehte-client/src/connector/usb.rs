//! KNX USB interface connector.
//!
//! Talks to a KNX USB interface (an HID device) using the shared framing
//! from [`zweidraehte_proto::usb_hid`]: 64-byte HID reports carrying the
//! KNX USB Transfer Protocol, with cEMI as the negotiated EMI format.
//!
//! Opening the connector runs the interface bring-up the device stack's
//! USB link layer uses too: query supported EMI types, activate cEMI,
//! switch the cEMI server into data-link-layer mode, then read the
//! interface's individual address and max APDU length via local device
//! management (M_PropRead). After that, `send_cemi`/`recv_cemi` exchange
//! plain L_Data frames.
//!
//! async-hid runs its own backend threads, so it composes with tokio
//! without a dedicated bridge; timeouts use `tokio::time`.

use std::time::Duration;

use async_hid::{AsyncHidRead, AsyncHidWrite, DeviceReader, DeviceReaderWriter, DeviceWriter, HidBackend};
use futures_lite::StreamExt;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::config::MAX_APDU_LENGTH_EXTENDED;
use zweidraehte_proto::usb_hid::bus_access::{BusAccessFrameBuilder, BusAccessResponse};
use zweidraehte_proto::usb_hid::hid::{HidReport, MAX_REPORT_SIZE, ReassemblyBuffer, fragment_frame};
use zweidraehte_proto::usb_hid::is_known_knx_device;
use zweidraehte_proto::usb_hid::protocol::{EmiId, TransferFrame, encode_cemi_frame};

use crate::connector::{ConnectorInfo, KnxConnector};
use crate::error::{Error, Result};

/// Timeout for Bus Access Server and local device management exchanges.
const LOCAL_MGMT_TIMEOUT: Duration = Duration::from_secs(1);

/// Transfer frame buffer size: 8-byte header + largest KNX frame (263).
const TRANSFER_BUF_SIZE: usize = 271;

// Local device management addresses on the interface (03/06/03; same
// values the device stack's USB link layer uses).
mod interface {
    /// Device Object (object index 0).
    pub const DEVICE_OBJECT: u8 = 0x00;
    /// cEMI Server Object (object index 8).
    pub const CEMI_SERVER_OBJECT: u8 = 0x08;
    /// Communication mode on the cEMI Server Object (PID 52).
    pub const PID_COMM_MODE: u8 = 0x34;
    /// Data-link-layer communication mode value.
    pub const COMM_MODE_DATA_LINK_LAYER: u8 = 0x00;
    /// Max APDU length on the Device Object (PID 56).
    pub const PID_MAX_APDU_LENGTH: u8 = 0x38;
    /// Subnetwork address octet of the interface IA (PID 57).
    pub const PID_SUBNET_ADDR: u8 = 0x39;
    /// Device address octet of the interface IA (PID 58).
    pub const PID_DEVICE_ADDR: u8 = 0x3A;
}

/// How to pick the KNX USB interface to open.
#[derive(Debug, Clone, Default)]
pub enum UsbSelector {
    /// First interface whose VID/PID is in the
    /// [`KNOWN_KNX_DEVICES`](zweidraehte_proto::usb_hid::KNOWN_KNX_DEVICES)
    /// table.
    #[default]
    AutoDiscover,
    /// Match by vendor and product ID.
    VidPid { vendor_id: u16, product_id: u16 },
}

pub struct UsbConnector {
    reader: DeviceReader,
    writer: DeviceWriter,
    reassembly: ReassemblyBuffer,
}

impl UsbConnector {
    /// Open and bring up a KNX USB interface.
    pub async fn connect(selector: &UsbSelector) -> Result<(Self, ConnectorInfo)> {
        let backend = HidBackend::default();
        let mut devices = backend.enumerate().await.map_err(|e| Error::Usb(format!("enumeration failed: {e:?}")))?;

        while let Some(device) = devices.next().await {
            let matches = match selector {
                UsbSelector::AutoDiscover => is_known_knx_device(device.vendor_id, device.product_id),
                UsbSelector::VidPid { vendor_id, product_id } => {
                    device.vendor_id == *vendor_id && device.product_id == *product_id
                }
            };
            if !matches {
                continue;
            }

            log::info!(
                "Opening KNX USB interface: {} ({:04X}:{:04X})",
                device.name,
                device.vendor_id,
                device.product_id
            );
            let (reader, writer): DeviceReaderWriter =
                device.open().await.map_err(|e| Error::Usb(format!("open failed: {e:?}")))?;

            let mut connector = Self { reader, writer, reassembly: ReassemblyBuffer::new() };
            let info = connector.bring_up().await?;
            return Ok((connector, info));
        }

        Err(Error::Usb("no matching KNX USB interface found".into()))
    }

    // ========================================================================
    // Interface bring-up
    // ========================================================================

    async fn bring_up(&mut self) -> Result<ConnectorInfo> {
        // EMI negotiation: the interface must speak cEMI.
        let supported = self.bus_access_get(BusAccessFrameBuilder::get_supported_emi_type).await?;
        let supported = supported.get_supported_emi_types().ok_or(Error::Parse("SupportedEmiType response"))?;
        if !supported.supports_cemi() {
            return Err(Error::Usb("interface does not support cEMI".into()));
        }

        let active = self.bus_access_get(BusAccessFrameBuilder::get_active_emi_type).await?;
        let active = active.get_active_emi_type().ok_or(Error::Parse("ActiveEmiType response"))?;
        if active != EmiId::CEmi {
            log::info!("Activating cEMI mode (was {:?})", active);
            let response =
                self.bus_access_get(|buf| BusAccessFrameBuilder::set_active_emi_type(EmiId::CEmi, buf)).await?;
            if response.get_active_emi_type() != Some(EmiId::CEmi) {
                return Err(Error::Usb("failed to activate cEMI mode".into()));
            }
        }

        // Data-link-layer mode on the cEMI server, so L_Data flows.
        self.prop_write(interface::CEMI_SERVER_OBJECT, interface::PID_COMM_MODE, &[
            interface::COMM_MODE_DATA_LINK_LAYER,
        ])
        .await?;

        // The interface's own individual address and APDU limit.
        let subnet = self.prop_read(interface::DEVICE_OBJECT, interface::PID_SUBNET_ADDR).await?;
        let device_addr = self.prop_read(interface::DEVICE_OBJECT, interface::PID_DEVICE_ADDR).await?;
        let (&subnet, &device_addr) = match (subnet.first(), device_addr.first()) {
            (Some(s), Some(d)) => (s, d),
            _ => return Err(Error::Parse("empty interface address property")),
        };
        let assigned_address = IndividualAddress::from_bytes(&[subnet, device_addr]);

        let max_apdu = match self.prop_read(interface::DEVICE_OBJECT, interface::PID_MAX_APDU_LENGTH).await {
            Ok(data) if data.len() >= 2 => u16::from_be_bytes([data[0], data[1]]),
            Ok(data) if data.len() == 1 => data[0] as u16,
            _ => {
                log::warn!("Interface did not report max APDU length; assuming {}", MAX_APDU_LENGTH_EXTENDED);
                MAX_APDU_LENGTH_EXTENDED
            }
        };

        log::info!("KNX USB interface ready: address {}, max APDU {}", assigned_address, max_apdu);
        Ok(ConnectorInfo { assigned_address, max_apdu })
    }

    // ========================================================================
    // Bus Access Server + local device management
    // ========================================================================

    /// Send a Bus Access Server request built by `build` and wait for the
    /// matching response body.
    async fn bus_access_get(
        &mut self,
        build: impl FnOnce(&mut [u8]) -> core::result::Result<usize, zweidraehte_proto::usb_hid::bus_access::BusAccessError>,
    ) -> Result<BusAccessResponseOwned> {
        let mut buf = [0u8; TRANSFER_BUF_SIZE];
        let len = build(&mut buf).map_err(|e| Error::Usb(format!("request build failed: {e:?}")))?;
        self.write_transfer(&buf[..len]).await?;

        let deadline = tokio::time::Instant::now() + LOCAL_MGMT_TIMEOUT;
        loop {
            let (kind, body) = self.read_transfer_frame(Some(deadline)).await?;
            if kind == FrameKind::BusAccess {
                return BusAccessResponseOwned::parse(body);
            }
            log::debug!("Ignoring non-BAS frame while waiting for feature response");
        }
    }

    /// Local M_PropRead on the interface. Returns the property data bytes.
    async fn prop_read(&mut self, object_type: u8, property_id: u8) -> Result<Vec<u8>> {
        // M_PropRead.req: msg_code, obj_type(2, BE), instance(1-based),
        // PID, count(4 bits) | start index (12 bits) = 1 element at 1.
        let request = [0xFC, 0x00, object_type, 0x01, property_id, 0x10, 0x01];
        let response = self.local_mgmt_request(&request, 0xFB).await?;
        // Response: 7-byte device management header, then the data.
        if response.len() < 7 {
            return Err(Error::Parse("M_PropRead.con too short"));
        }
        Ok(response[7..].to_vec())
    }

    /// Local M_PropWrite on the interface.
    async fn prop_write(&mut self, object_type: u8, property_id: u8, data: &[u8]) -> Result<()> {
        let mut request = vec![0xF6, 0x00, object_type, 0x01, property_id, 0x10, 0x01];
        request.extend_from_slice(data);
        self.local_mgmt_request(&request, 0xF5).await?;
        Ok(())
    }

    /// Send a local-management cEMI frame and wait for the confirmation
    /// with the given message code.
    async fn local_mgmt_request(&mut self, cemi: &[u8], expected_con: u8) -> Result<Vec<u8>> {
        let mut buf = [0u8; TRANSFER_BUF_SIZE];
        let len = encode_cemi_frame(cemi, &mut buf).map_err(|e| Error::Usb(format!("frame encode failed: {e:?}")))?;
        self.write_transfer(&buf[..len]).await?;

        let deadline = tokio::time::Instant::now() + LOCAL_MGMT_TIMEOUT;
        loop {
            let (kind, body) = self.read_transfer_frame(Some(deadline)).await?;
            if kind == FrameKind::Cemi && body.first() == Some(&expected_con) {
                return Ok(body);
            }
            log::debug!("Ignoring cEMI frame while waiting for local mgmt confirmation");
        }
    }

    // ========================================================================
    // Transfer-frame I/O
    // ========================================================================

    /// Fragment a transfer frame into HID reports and write them.
    async fn write_transfer(&mut self, frame: &[u8]) -> Result<()> {
        for report in fragment_frame(frame) {
            self.writer.write_output_report(&report).await.map_err(|e| Error::Usb(format!("write failed: {e:?}")))?;
        }
        Ok(())
    }

    /// Read HID reports until a complete transfer frame reassembles.
    ///
    /// With a deadline, times out with [`Error::Timeout`]; without one,
    /// waits indefinitely (the `recv_cemi` path).
    async fn read_transfer_frame(&mut self, deadline: Option<tokio::time::Instant>) -> Result<(FrameKind, Vec<u8>)> {
        let mut report_buf = [0u8; MAX_REPORT_SIZE];
        loop {
            let read = self.reader.read_input_report(&mut report_buf);
            let result = match deadline {
                Some(deadline) => match tokio::time::timeout_at(deadline, read).await {
                    Ok(result) => result,
                    Err(_) => return Err(Error::Timeout),
                },
                None => read.await,
            };
            let _len = result.map_err(|e| Error::Usb(format!("read failed: {e:?}")))?;

            let Ok(report) = HidReport::parse(&report_buf) else {
                log::warn!("Dropping malformed HID report");
                continue;
            };
            match self.reassembly.process(&report) {
                Ok(Some(data)) => {
                    let Ok(frame) = TransferFrame::parse(data) else {
                        log::warn!("Dropping malformed USB transfer frame");
                        continue;
                    };
                    let kind = if frame.is_cemi_tunnel() {
                        FrameKind::Cemi
                    } else if frame.is_bus_access_server() {
                        FrameKind::BusAccess
                    } else {
                        log::debug!("Ignoring transfer frame with protocol {:?}", frame.header.protocol_id);
                        continue;
                    };
                    return Ok((kind, frame.body.to_vec()));
                }
                Ok(None) => {} // partial, keep reading
                Err(e) => {
                    log::warn!("HID reassembly error: {:?}", e);
                    self.reassembly.reset();
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Cemi,
    BusAccess,
}

/// Owned copy of a Bus Access Server response body (the borrowed
/// [`BusAccessResponse`] can't outlive the read buffer).
struct BusAccessResponseOwned {
    body: Vec<u8>,
}

impl BusAccessResponseOwned {
    fn parse(body: Vec<u8>) -> Result<Self> {
        // Validate eagerly so callers get a parse error at the await point.
        BusAccessResponse::parse(&body).map_err(|_| Error::Parse("Bus Access Server response"))?;
        Ok(Self { body })
    }

    fn response(&self) -> BusAccessResponse<'_> {
        BusAccessResponse::parse(&self.body).expect("validated in parse()")
    }

    fn get_supported_emi_types(&self) -> Option<zweidraehte_proto::usb_hid::bus_access::SupportedEmiTypes> {
        self.response().get_supported_emi_types()
    }

    fn get_active_emi_type(&self) -> Option<EmiId> {
        self.response().get_active_emi_type()
    }
}

impl KnxConnector for UsbConnector {
    async fn send_cemi(&mut self, cemi: &[u8]) -> Result<()> {
        let mut buf = [0u8; TRANSFER_BUF_SIZE];
        let len = encode_cemi_frame(cemi, &mut buf).map_err(|e| Error::Usb(format!("frame encode failed: {e:?}")))?;
        self.write_transfer(&buf[..len]).await
    }

    async fn recv_cemi(&mut self) -> Result<Vec<u8>> {
        loop {
            let (kind, body) = self.read_transfer_frame(None).await?;
            match kind {
                FrameKind::Cemi => return Ok(body),
                // Unsolicited feature infos (e.g. bus status changes).
                FrameKind::BusAccess => log::debug!("Ignoring unsolicited Bus Access Server frame"),
            }
        }
    }

    async fn close(&mut self) -> Result<()> {
        // Nothing to negotiate on the way out; dropping the handles closes
        // the HID device.
        Ok(())
    }
}
