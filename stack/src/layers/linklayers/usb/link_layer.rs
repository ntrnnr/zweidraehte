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
//! use zweidraehte::layers::linklayers::usb::{UsbLinkLayerBuilder, UsbLinkLayerResources};
//!
//! let builder = UsbLinkLayerBuilder::new();
//! let resources = UsbLinkLayerResources::new();
//! // Use with LinkLayerBuilder trait
//! ```

// FIXME: The whole object property read/write stuff in here should be handled
//        by some kind of "component" that is generic, maybe? Might be useful for
//        other devices as well or management.

extern crate alloc;

use core::cell::RefCell;

use embassy_futures::select::{Either3, select3};
use embassy_sync::channel::DynamicSender;
use embassy_time::{Duration, Instant, Timer};

use crate::address::IndividualAddress;
use crate::context::BufferManagerContext;
use crate::encoding::cemi::CemiMessageCode; // Still needed for RX path
use crate::layers::{Inbox, Layer, LayerOp, LinkLayerBuilder, LinkLayerBuilderBase};
use crate::messages::buffers::{Buffer, DynBufferManager, MessageBuffer};
use crate::messages::builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage};
use crate::messages::knx::{CemiFormat, Confirm, KnxMessageBuffer, ServiceType};

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
const DEFAULT_MAX_APDU_LENGTH: u16 = crate::config::MAX_APDU_LENGTH_TP1_STANDARD;

impl UsbLinkLayerBuilder {
    /// Read the interface's individual address from the device
    async fn read_individual_address<'a, D: UsbHidDevice>(
        transport: &mut UsbCemiTransport<'a, D>,
    ) -> Result<IndividualAddress, super::device::UsbHidError> {
        // Read subnet address (area.line as single byte) from Device Object
        let subnet_data = transport.prop_read(properties::DEVICE_OBJECT, properties::PID_SUBNET_ADDR).await?;

        // Read device address from Device Object
        let device_data = transport.prop_read(properties::DEVICE_OBJECT, properties::PID_DEVICE_ADDR).await?;

        // Property response format: msg_code(1) + obj_type(2) + obj_instance(1) + pid(1) + count_idx(2) + data
        // The actual value is at offset 7 (first data byte)
        if subnet_data.len() < 8 || device_data.len() < 8 {
            return Err(super::device::UsbHidError::InvalidReport);
        }

        let subnet = subnet_data[7];
        let device = device_data[7];

        Ok(IndividualAddress([subnet, device]))
    }

    /// Attempt to set the interface's individual address via Device Object properties
    ///
    /// This writes to PIDs 57 (subnet) and 58 (device) on the Device Object (Object 0).
    async fn write_individual_address<'a, D: UsbHidDevice>(
        transport: &mut UsbCemiTransport<'a, D>,
        address: IndividualAddress,
    ) -> Result<(), super::device::UsbHidError> {
        // Write subnet address (area.line as single byte) to Device Object
        transport.prop_write(properties::DEVICE_OBJECT, properties::PID_SUBNET_ADDR, &[address.subnet()]).await?;

        // Write device address to Device Object
        transport.prop_write(properties::DEVICE_OBJECT, properties::PID_DEVICE_ADDR, &[address.device()]).await?;

        Ok(())
    }

    /// Read the maximum APDU length supported by the interface
    ///
    /// This reads PID 56 (MAX_APDU_LENGTH) from the Device Object (Object 0).
    /// The value is a 16-bit unsigned integer representing the maximum APDU size
    /// the interface can handle.
    async fn read_max_apdu_length<'a, D: UsbHidDevice>(
        transport: &mut UsbCemiTransport<'a, D>,
    ) -> Result<u16, super::device::UsbHidError> {
        let data = transport
            .prop_read(properties::DEVICE_OBJECT, properties::PID_MAX_APDU_LENGTH)
            .await?;

        // Property response format: msg_code(1) + obj_type(2) + obj_instance(1) + pid(1) + count_idx(2) + data
        // The actual value is at offset 7, and it's a 16-bit big-endian value
        if data.len() < 9 {
            return Err(super::device::UsbHidError::InvalidReport);
        }

        let max_apdu = u16::from_be_bytes([data[7], data[8]]);
        Ok(max_apdu)
    }
}

impl LinkLayerBuilderBase for UsbLinkLayerBuilder {
    type Resources = UsbLinkLayerResources;

    fn create_resources(&self) -> Self::Resources {
        UsbLinkLayerResources::new()
    }
}

impl<CTX: BufferManagerContext> LinkLayerBuilder<CTX> for UsbLinkLayerBuilder {
    fn build_and_run<'a>(
        self,
        resources: &'a mut Self::Resources,
        context: &'a CTX,
        network_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
        inbox: impl Inbox<LayerOp<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        async move {
            // Initialize transport resources
            let transport_resources = resources.transport.init();

            // Open USB device and create transport
            info!("USB Link Layer: Opening device...");
            let mut transport = match UsbCemiTransport::open(&self.selector, transport_resources).await {
                Ok(t) => t,
                Err(e) => {
                    panic!("USB Link Layer: Failed to open device: {:?}", e);
                }
            };

            // Initialize transport (negotiate cEMI)
            if let Err(e) = transport.initialize().await {
                panic!("USB Link Layer: Failed to initialize transport: {:?}", e);
            }

            // Read interface's current individual address (before any writes)
            match Self::read_individual_address(&mut transport).await {
                Ok(address) => {
                    info!("USB Link Layer: Current interface address: {}", address);
                }
                Err(e) => {
                    warn!("USB Link Layer: Failed to read individual address: {:?}", e);
                }
            }

            // Set individual address if configured
            if let Some(address) = self.individual_address {
                info!("USB Link Layer: Setting interface address to {}...", address);
                if let Err(e) = Self::write_individual_address(&mut transport, address).await {
                    warn!("USB Link Layer: Failed to set individual address: {:?}", e);
                }
            }

            // Set communication mode to Data Link Layer on cEMI Server Object (Object 8)
            info!("USB Link Layer: Setting communication mode to Data Link Layer...");
            if let Err(e) = transport
                .prop_write(properties::CEMI_SERVER_OBJECT, properties::PID_COMM_MODE, &[comm_mode::DATA_LINK_LAYER])
                .await
            {
                panic!("USB Link Layer: Failed to set comm mode: {:?}", e);
            }

            // Verify the write
            match transport.prop_read(properties::CEMI_SERVER_OBJECT, properties::PID_COMM_MODE).await {
                Ok(data) => {
                    // Response format: msg_code(1) + obj_type(2) + obj_instance(1) + pid(1) + count_idx(2) + data
                    // The actual value is at offset 7 (first data byte)
                    if data.len() >= 8 && data[7] == comm_mode::DATA_LINK_LAYER {
                        info!("USB Link Layer: Communication mode verified as Data Link Layer");
                    } else {
                        warn!("USB Link Layer: Unexpected comm mode response: {:02X?}", data);
                    }
                }
                Err(e) => {
                    // Write succeeded (we got M_PropWrite.con), but read failed
                    debug!("USB Link Layer: Failed to verify comm mode: {:?}", e);
                    info!("USB Link Layer: Communication mode set (write confirmed)");
                }
            }

            // Read max APDU length from interface and update the stack state
            let max_apdu_length = match Self::read_max_apdu_length(&mut transport).await {
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
            };

            // Update the stack state with the detected max APDU length
            // This ensures PID 56 (MAX_APDU_LENGTH) in the Device Object reports
            // the actual hardware capability rather than the compile-time default
            context.set_max_apdu_length(max_apdu_length);

            // Check bus connection
            match transport.get_bus_connection_status().await {
                Ok(connected) => {
                    if connected {
                        info!("USB Link Layer: Bus connected");
                    } else {
                        warn!("USB Link Layer: Bus not connected!");
                    }
                }
                Err(e) => {
                    warn!("USB Link Layer: Failed to check bus status: {:?}", e);
                }
            }

            info!("USB Link Layer: Initialization complete");

            let mut link_layer = UsbLinkLayer {
                transport,
                buffer_manager: context.buffer_manager(),
                network_layer,
                pending_tx: None,
                timeout_deadline: None,
                max_apdu_length,
            };

            link_layer.process(inbox).await
        }
    }
}

/// Pending transmission waiting for confirmation
struct PendingTransmission {
    buffer: Buffer<'static>,
    response_tx: DynamicSender<'static, ConfirmationMessage<Buffer<'static>>>,
    #[allow(dead_code)]
    sent_at: Instant,
}

/// USB Link Layer
struct UsbLinkLayer<'a, D: UsbHidDevice> {
    transport: UsbCemiTransport<'a, D>,
    buffer_manager: &'a RefCell<DynBufferManager<'static>>,
    network_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
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

        let message_code = CemiMessageCode::try_from(cemi_data[0]).unwrap_or(CemiMessageCode::Other(cemi_data[0]));
        debug!("USB Link Layer: Incoming cEMI, message_code={:?}, len={}", message_code, cemi_data.len());

        // Check if this is a confirmation for our pending transmission
        if let Some(ref _pending) = self.pending_tx {
            if message_code == CemiMessageCode::LDataCon {
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

                    pending.response_tx.send(ConfirmationMessage::confirmation(msg)).await;
                }
                self.timeout_deadline = None;
                return;
            }
        }

        // This is an indication - forward to network layer
        if message_code == CemiMessageCode::LDataInd {
            // Allocate buffer and copy cEMI data
            let mut buffer = self.buffer_manager.borrow().alloc().await;
            buffer.push_slice(cemi_data);

            // Create typed cEMI message and convert to internal format
            let cemi_msg: KnxMessageBuffer<Buffer<'static>, CemiFormat> =
                KnxMessageBuffer::from_cemi(buffer);
            let internal_msg = cemi_msg.into_internal();

            let indication = IndicationMessage::indication(internal_msg);
            self.network_layer.send(LayerOp::Indication(indication)).await;
        }
    }

    /// Handle a request from the network layer
    async fn handle_request(
        &mut self,
        message: Buffer<'static>,
        response_tx: DynamicSender<'static, ConfirmationMessage<Buffer<'static>>>,
    ) {
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
                response_tx.send(ConfirmationMessage::confirmation(msg)).await;
                return;
            }
        }

        // Log cEMI format after conversion
        info!("USB Link Layer: TX cEMI: {:02X?}", &cemi_buffer[..]);

        match self.transport.send_cemi_raw(&cemi_buffer[..]).await {
            Ok(()) => {
                // Store pending transmission, wait for confirmation
                self.pending_tx =
                    Some(PendingTransmission { buffer: cemi_buffer, response_tx, sent_at: Instant::now() });
                self.timeout_deadline = Some(Instant::now() + TUNNEL_TIMEOUT);
            }
            Err(e) => {
                error!("USB Link Layer: Failed to send frame: {:?}", e);
                let mut msg = KnxMessageBuffer::new(cemi_buffer, ServiceType::L_Data_Con);
                msg.ctrl_field_mut().set_c(Confirm::Err);
                response_tx.send(ConfirmationMessage::confirmation(msg)).await;
            }
        }
    }

    /// Handle transmission timeout
    async fn handle_timeout(&mut self) {
        if let Some(pending) = self.pending_tx.take() {
            warn!("USB Link Layer: Transmission timeout");
            let mut msg = KnxMessageBuffer::new(pending.buffer, ServiceType::L_Data_Con);
            msg.ctrl_field_mut().set_c(Confirm::Err);
            pending.response_tx.send(ConfirmationMessage::confirmation(msg)).await;
        }
        self.timeout_deadline = None;
    }
}

impl<'a, D: UsbHidDevice> Layer<'a> for UsbLinkLayer<'a, D> {
    type Buffer = Buffer<'static>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Buffer>>,
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

            match select3(timeout_fut, self.transport.try_recv_cemi(), inbox.next()).await {
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
                Either3::Third(layer_op) => {
                    // Request from network layer
                    match layer_op {
                        LayerOp::Indication(_) => {
                            error!("USB Link Layer: Unexpected indication from upper layer");
                        }
                        LayerOp::Request { message, response_tx } => {
                            // Link layer only handles L_Data.req
                            match message.service_type() {
                                ServiceType::L_Data_Req => {
                                    self.handle_request(message.into_inner().into_inner(), response_tx).await;
                                }
                                _ => {
                                    // Unsupported service type
                                    warn!("USB Link Layer: Unsupported service type {:?}", message.service_type());
                                    response_tx.send(message.into_inner().error().build()).await;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
