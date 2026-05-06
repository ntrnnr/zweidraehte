//! USB KNX Link Layer
//!
//! This module implements a proper KNX link layer on top of the USB cEMI transport.
//! It handles:
//! - Setting PID_COMM_MODE to enable data link layer mode
//! - Converting between internal KNX format and cEMI
//! - Processing L_Data.req/ind/con messages
//!
//! ## Usage
//!
//! ```ignore
//! use zweidraehte_device::layers::linklayers::usb::{UsbLinkLayerBuilder, UsbLinkLayerResources};
//!
//! let builder = UsbLinkLayerBuilder::new();
//! let resources = UsbLinkLayerResources::new();
//! // Use with LinkLayerBuilder trait
//! ```

extern crate alloc;

use embassy_futures::select::{Either3, select3};
use embassy_sync::channel::DynamicSender;
use embassy_time::{Duration, Instant, Timer};

use crate::config::MAX_APDU_LENGTH_TP1_STANDARD;
use crate::context::LinkLayerBufferContext;
use crate::layers::{Inbox, LinkLayerBuilder, LinkLayerBuilderBase, LinkLayerCapabilities};
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::encoding::cemi::CemiMessageCode; // Still needed for RX path
use zweidraehte_proto::messages::buffers::{Buffer, DynBufferManager, MessageBuffer};
use zweidraehte_proto::messages::builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage, RequestMessage};
use zweidraehte_proto::messages::knx::{CemiFormat, Confirm, KnxMessageBuffer, ServiceType};

use super::device::{DeviceSelector, UsbHidDevice};
use super::transport::{UsbCemiTransport, UsbCemiTransportResources, comm_mode, properties};

/// Timeout for KNX tunnel operations (per spec: 1 second)
const TUNNEL_TIMEOUT: Duration = Duration::from_millis(1000);

/// Resources for USB Link Layer
pub struct UsbLinkLayerResources {
    /// Transport resources
    transport: UsbCemiTransportResources,
}

impl UsbLinkLayerResources {
    pub const fn new() -> Self {
        Self { transport: UsbCemiTransportResources::new() }
    }
}

impl Default for UsbLinkLayerResources {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for USB Link Layer
pub struct UsbLinkLayerBuilder {
    selector: DeviceSelector,
    /// Optional individual address to set on the interface
    individual_address: Option<IndividualAddress>,
}

impl UsbLinkLayerBuilder {
    /// Create a new builder with auto-discovery
    pub fn new() -> Self {
        Self { selector: DeviceSelector::AutoDiscover, individual_address: None }
    }

    /// Create a new builder with specific device selector
    pub fn with_selector(selector: DeviceSelector) -> Self {
        Self { selector, individual_address: None }
    }

    /// Create a new builder for a specific VID:PID
    pub fn with_vid_pid(vendor_id: u16, product_id: u16) -> Self {
        Self { selector: DeviceSelector::VidPid { vendor_id, product_id }, individual_address: None }
    }

    /// Create a new builder for a specific device path
    #[cfg(feature = "std")]
    pub fn with_path(path: impl Into<alloc::string::String>) -> Self {
        Self { selector: DeviceSelector::Path(path.into()), individual_address: None }
    }

    /// Set the individual address to configure on the interface
    pub fn with_individual_address(mut self, address: IndividualAddress) -> Self {
        self.individual_address = Some(address);
        self
    }
}

impl Default for UsbLinkLayerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Default max APDU length if the interface doesn't report one
/// (standard TP1 without extended frame format)
const DEFAULT_MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_TP1_STANDARD;

impl UsbLinkLayerBuilder {
    /// Read the interface's individual address from the Device Object.
    async fn read_individual_address<'a, D: UsbHidDevice>(
        transport: &mut UsbCemiTransport<'a, D>,
    ) -> Result<IndividualAddress, super::device::UsbHidError> {
        let subnet = transport.read_property_value(properties::DEVICE_OBJECT, properties::PID_SUBNET_ADDR).await?;
        let device = transport.read_property_value(properties::DEVICE_OBJECT, properties::PID_DEVICE_ADDR).await?;

        if subnet.is_empty() || device.is_empty() {
            return Err(super::device::UsbHidError::InvalidReport);
        }

        Ok(IndividualAddress([subnet[0], device[0]]))
    }

    /// Set the interface's individual address via Device Object properties
    /// (PIDs 57/58 — subnet and device address).
    async fn write_individual_address<'a, D: UsbHidDevice>(
        transport: &mut UsbCemiTransport<'a, D>,
        address: IndividualAddress,
    ) -> Result<(), super::device::UsbHidError> {
        transport.prop_write(properties::DEVICE_OBJECT, properties::PID_SUBNET_ADDR, &[address.subnet()]).await?;
        transport.prop_write(properties::DEVICE_OBJECT, properties::PID_DEVICE_ADDR, &[address.device()]).await?;
        Ok(())
    }

    /// Read the maximum APDU length from the Device Object (PID 56).
    async fn read_max_apdu_length<'a, D: UsbHidDevice>(
        transport: &mut UsbCemiTransport<'a, D>,
    ) -> Result<u16, super::device::UsbHidError> {
        let data = transport.read_property_value(properties::DEVICE_OBJECT, properties::PID_MAX_APDU_LENGTH).await?;

        if data.len() < 2 {
            return Err(super::device::UsbHidError::InvalidReport);
        }

        Ok(u16::from_be_bytes([data[0], data[1]]))
    }

    /// Read the communication mode from the cEMI Server Object (PID 52).
    async fn read_comm_mode<'a, D: UsbHidDevice>(
        transport: &mut UsbCemiTransport<'a, D>,
    ) -> Result<u8, super::device::UsbHidError> {
        let data = transport.read_property_value(properties::CEMI_SERVER_OBJECT, properties::PID_COMM_MODE).await?;

        if data.is_empty() {
            return Err(super::device::UsbHidError::InvalidReport);
        }

        Ok(data[0])
    }
}

impl LinkLayerBuilderBase for UsbLinkLayerBuilder {
    type Resources = UsbLinkLayerResources;

    fn create_resources(&self) -> Self::Resources {
        UsbLinkLayerResources::new()
    }
}

impl LinkLayerCapabilities for UsbLinkLayerBuilder {}

impl UsbLinkLayerBuilder {
    /// Open the USB device and negotiate cEMI mode.
    async fn open_transport<'a>(
        selector: &DeviceSelector,
        resources: super::transport::InitializedResources<'a>,
    ) -> UsbCemiTransport<'a, super::device::AsyncHidDevice> {
        info!("USB Link Layer: Opening device...");
        let mut transport = UsbCemiTransport::open(selector, resources)
            .await
            .unwrap_or_else(|e| panic!("USB Link Layer: Failed to open device: {:?}", e));

        transport
            .initialize()
            .await
            .unwrap_or_else(|e| panic!("USB Link Layer: Failed to initialize transport: {:?}", e));

        transport
    }

    /// Configure the interface's individual address.
    ///
    /// Reads the current address (for logging), then writes the requested
    /// address if one was provided.
    async fn configure_address<'a, D: UsbHidDevice>(
        transport: &mut UsbCemiTransport<'a, D>,
        requested: Option<IndividualAddress>,
    ) {
        match Self::read_individual_address(transport).await {
            Ok(address) => info!("USB Link Layer: Current interface address: {}", address),
            Err(e) => warn!("USB Link Layer: Failed to read individual address: {:?}", e),
        }

        if let Some(address) = requested {
            info!("USB Link Layer: Setting interface address to {}...", address);
            if let Err(e) = Self::write_individual_address(transport, address).await {
                warn!("USB Link Layer: Failed to set individual address: {:?}", e);
            }
        }
    }

    /// Set the cEMI Server Object to Data Link Layer mode and verify.
    async fn configure_comm_mode<'a, D: UsbHidDevice>(transport: &mut UsbCemiTransport<'a, D>) {
        info!("USB Link Layer: Setting communication mode to Data Link Layer...");
        if let Err(e) = transport
            .prop_write(properties::CEMI_SERVER_OBJECT, properties::PID_COMM_MODE, &[comm_mode::DATA_LINK_LAYER])
            .await
        {
            panic!("USB Link Layer: Failed to set comm mode: {:?}", e);
        }

        match Self::read_comm_mode(transport).await {
            Ok(mode) if mode == comm_mode::DATA_LINK_LAYER => {
                info!("USB Link Layer: Communication mode verified as Data Link Layer");
            }
            Ok(mode) => {
                warn!("USB Link Layer: Unexpected comm mode after write: 0x{:02X}", mode);
            }
            Err(e) => {
                // Write succeeded (we got M_PropWrite.con), but read-back failed
                debug!("USB Link Layer: Failed to verify comm mode: {:?}", e);
                info!("USB Link Layer: Communication mode set (write confirmed)");
            }
        }
    }

    /// Query the interface's max APDU length, falling back to the default.
    async fn query_max_apdu_length<'a, D: UsbHidDevice>(transport: &mut UsbCemiTransport<'a, D>) -> u16 {
        match Self::read_max_apdu_length(transport).await {
            Ok(len) => {
                info!("USB Link Layer: Interface max APDU length: {} bytes", len);
                len
            }
            Err(e) => {
                warn!(
                    "USB Link Layer: Failed to read max APDU length: {:?}, using default {}",
                    e, DEFAULT_MAX_APDU_LENGTH
                );
                DEFAULT_MAX_APDU_LENGTH
            }
        }
    }

    /// Log the bus connection status (best-effort, non-fatal).
    async fn log_bus_status<'a, D: UsbHidDevice>(transport: &mut UsbCemiTransport<'a, D>) {
        match transport.get_bus_connection_status().await {
            Ok(true) => info!("USB Link Layer: Bus connected"),
            Ok(false) => warn!("USB Link Layer: Bus not connected!"),
            Err(e) => warn!("USB Link Layer: Failed to check bus status: {:?}", e),
        }
    }
}

impl<CTX: LinkLayerBufferContext> LinkLayerBuilder<CTX> for UsbLinkLayerBuilder {
    async fn build_and_run<'a>(
        self,
        resources: &'a mut Self::Resources,
        context: &'a CTX,
        _ll_endpoints: (),
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl Inbox<RequestMessage<Buffer<'static>>> + 'a,
    ) -> ! {
        let transport_resources = resources.transport.init();

        let mut transport = Self::open_transport(&self.selector, transport_resources).await;
        Self::configure_address(&mut transport, self.individual_address).await;
        Self::configure_comm_mode(&mut transport).await;

        let max_apdu_length = Self::query_max_apdu_length(&mut transport).await;
        // Update the stack state so PID 56 (MAX_APDU_LENGTH) in the Device Object
        // reports the actual hardware capability rather than the compile-time default.
        context.set_max_apdu_length(max_apdu_length);

        Self::log_bus_status(&mut transport).await;
        info!("USB Link Layer: Initialization complete");

        let mut link_layer = UsbLinkLayer {
            transport,
            buffer_manager: context.buffer_manager(),
            ind_tx,
            conf_tx,
            pending_tx: None,
            timeout_deadline: None,
            max_apdu_length,
        };

        link_layer.process(req_rx).await
    }
}

/// Pending transmission waiting for confirmation
struct PendingTransmission {
    buffer: Buffer<'static>,
    #[allow(dead_code)]
    sent_at: Instant,
}

/// USB Link Layer
struct UsbLinkLayer<'a, D: UsbHidDevice> {
    transport: UsbCemiTransport<'a, D>,
    buffer_manager: &'a DynBufferManager<'static>,
    /// Channel for sending indications (received frames) up to the network layer
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    /// Channel for sending confirmations (transmission results) up to the network layer
    conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
    pending_tx: Option<PendingTransmission>,
    timeout_deadline: Option<Instant>,
    /// Maximum APDU length supported by the USB interface
    max_apdu_length: u16,
}

impl<'a, D: UsbHidDevice> UsbLinkLayer<'a, D> {
    /// Handle an incoming cEMI frame
    async fn handle_incoming_cemi(&mut self, cemi_data: &[u8]) {
        if cemi_data.is_empty() {
            return;
        }

        let message_code = CemiMessageCode::from(cemi_data[0]);
        debug!("USB Link Layer: Incoming cEMI, message_code={:?}, len={}", message_code, cemi_data.len());

        // Check if this is a confirmation for our pending transmission
        if let Some(ref _pending) = self.pending_tx
            && message_code == CemiMessageCode::LDataCon
        {
            // This is a confirmation
            if let Some(pending) = self.pending_tx.take() {
                let mut msg = KnxMessageBuffer::new(pending.buffer, ServiceType::L_Data_Con);

                // Check positive/negative confirmation from cEMI
                // In cEMI L_Data.con, byte 2 contains the control field
                // The confirmation flag is in the message itself
                if cemi_data.len() > 2 && (cemi_data[2] & 0x01) == 0 {
                    // Positive confirmation (no error)
                    msg.ctrl_field_mut().set_c(Confirm::NoError);
                } else {
                    // Negative confirmation
                    msg.ctrl_field_mut().set_c(Confirm::Err);
                }

                self.conf_tx.send(ConfirmationMessage::confirmation(msg)).await;
            }
            self.timeout_deadline = None;
            return;
        }

        // This is an indication - forward to network layer
        if message_code == CemiMessageCode::LDataInd {
            // Allocate buffer and copy cEMI data
            let mut buffer = self.buffer_manager.alloc().await;
            buffer.push_slice(cemi_data);

            // Create typed cEMI message and convert to internal format
            let cemi_msg: KnxMessageBuffer<Buffer<'static>, CemiFormat> = KnxMessageBuffer::from_cemi(buffer);
            let internal_msg = cemi_msg.into_internal();

            let indication = IndicationMessage::indication(internal_msg);
            self.ind_tx.send(indication).await;
        }
    }

    /// Handle a request from the network layer
    async fn handle_request(&mut self, message: Buffer<'static>) {
        // Log internal KNX format before conversion
        debug!("USB Link Layer: TX internal KNX format: {:02X?}", &message[..]);

        // Convert to cEMI format in-place using headroom
        let internal_msg = KnxMessageBuffer::new(message, ServiceType::L_Data_Req);
        let cemi_buffer = internal_msg.into_cemi().into_inner();

        // Check APDU length against interface maximum
        // cEMI structure: msg_code(1) + add_info_len(1) + [add_info(N)] + ctrl1(1) + ctrl2(1) + src(2) + dst(2) + npdu_len(1) + apdu...
        // The NPDU length field (at offset 8 if no additional info) contains the APDU length
        // APDU length = npdu_len byte value (which counts TPCI/APCI + data bytes)
        let add_info_len = if cemi_buffer.len() > 1 { cemi_buffer[1] as usize } else { 0 };
        let npdu_len_offset = 2 + add_info_len + 6; // skip msg_code, add_info_len, add_info, ctrl1, ctrl2, src(2), dst(2)

        if cemi_buffer.len() > npdu_len_offset {
            let apdu_length = cemi_buffer[npdu_len_offset] as u16;

            if apdu_length > self.max_apdu_length {
                warn!(
                    "USB Link Layer: APDU length {} exceeds interface maximum {} - rejecting frame",
                    apdu_length, self.max_apdu_length
                );
                let mut msg = KnxMessageBuffer::new(cemi_buffer, ServiceType::L_Data_Con);
                msg.ctrl_field_mut().set_c(Confirm::Err);
                self.conf_tx.send(ConfirmationMessage::confirmation(msg)).await;
                return;
            }
        }

        // Log cEMI format after conversion
        info!("USB Link Layer: TX cEMI: {:02X?}", &cemi_buffer[..]);

        match self.transport.send_cemi_raw(&cemi_buffer[..]).await {
            Ok(()) => {
                // Store pending transmission, wait for confirmation
                self.pending_tx = Some(PendingTransmission { buffer: cemi_buffer, sent_at: Instant::now() });
                self.timeout_deadline = Some(Instant::now() + TUNNEL_TIMEOUT);
            }
            Err(e) => {
                error!("USB Link Layer: Failed to send frame: {:?}", e);
                let mut msg = KnxMessageBuffer::new(cemi_buffer, ServiceType::L_Data_Con);
                msg.ctrl_field_mut().set_c(Confirm::Err);
                self.conf_tx.send(ConfirmationMessage::confirmation(msg)).await;
            }
        }
    }

    /// Handle transmission timeout
    async fn handle_timeout(&mut self) {
        if let Some(pending) = self.pending_tx.take() {
            warn!("USB Link Layer: Transmission timeout");
            let mut msg = KnxMessageBuffer::new(pending.buffer, ServiceType::L_Data_Con);
            msg.ctrl_field_mut().set_c(Confirm::Err);
            self.conf_tx.send(ConfirmationMessage::confirmation(msg)).await;
        }
        self.timeout_deadline = None;
    }

    /// Main event loop: receives requests from the network layer, USB data
    /// from the transport, and handles transmission timeouts.
    async fn process<M>(&mut self, mut req_rx: M) -> !
    where
        M: Inbox<RequestMessage<Buffer<'static>>>,
    {
        loop {
            trace!("USB Link Layer: Main loop iteration, waiting for events...");

            // Create timeout future
            let timeout_fut = async {
                if let Some(deadline) = self.timeout_deadline {
                    Timer::at(deadline).await;
                    true
                } else {
                    core::future::pending::<bool>().await
                }
            };

            match select3(timeout_fut, self.transport.try_recv_cemi(), req_rx.next()).await {
                Either3::First(_) => {
                    // Timeout
                    self.handle_timeout().await;
                }
                Either3::Second(result) => {
                    // USB data received
                    match result {
                        Ok(Some(cemi_data)) => {
                            self.handle_incoming_cemi(&cemi_data).await;
                        }
                        Ok(None) => {
                            // No complete frame yet, continue
                        }
                        Err(e) => {
                            panic!("USB Link Layer: Device read error: {:?}", e);
                        }
                    }
                }
                Either3::Third(request) => {
                    // Request from network layer
                    match request.service_type() {
                        ServiceType::L_Data_Req => {
                            self.handle_request(request.into_inner().into_inner()).await;
                        }
                        _ => {
                            // Unsupported service type
                            warn!("USB Link Layer: Unsupported service type {:?}", request.service_type());
                            self.conf_tx.send(request.into_inner().error().build()).await;
                        }
                    }
                }
            }
        }
    }
}
