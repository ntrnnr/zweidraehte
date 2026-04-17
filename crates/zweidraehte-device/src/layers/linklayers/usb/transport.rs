//! USB cEMI Transport
//!
//! This module provides low-level cEMI frame transport over USB HID.
//! It handles:
//! - USB HID report framing and fragmentation
//! - EMI type negotiation (activating cEMI mode)
//! - Bus Access Server feature get/set
//! - Device management (M_PropRead/Write)
//! - Raw cEMI frame TX/RX
//!
//! This is NOT a link layer - it's a transport that can be used to build
//! a link layer or bus monitor on top.

extern crate alloc;

use alloc::vec::Vec;
use core::mem::MaybeUninit;

use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Instant, Timer};

use zweidraehte_proto::encoding::cemi::CemiBuffer;
use zweidraehte_proto::messages::buffers::MessageBuffer;

use super::bus_access::{BusAccessFrameBuilder, BusAccessResponse, SupportedEmiTypes};
use super::device::{AsyncHidDevice, DeviceSelector, UsbHidDevice, UsbHidError};
use super::hid::{HidReport, MAX_REPORT_SIZE, ReassemblyBuffer, fragment_frame};
use super::protocol::{EmiId, TransferFrame, encode_cemi_frame};

/// Timeout for Bus Access Server operations
const BUS_ACCESS_TIMEOUT: Duration = Duration::from_millis(1000);

/// Timeout for device management operations
const DEVICE_MGMT_TIMEOUT: Duration = Duration::from_millis(1000);

/// Resources for USB cEMI Transport
pub struct UsbCemiTransportResources {
    /// HID report receive buffer
    pub(crate) rx_report: MaybeUninit<[u8; MAX_REPORT_SIZE]>,
    /// HID report transmit buffer
    pub(crate) tx_report: MaybeUninit<[u8; MAX_REPORT_SIZE]>,
    /// Frame reassembly buffer
    pub(crate) reassembly: MaybeUninit<ReassemblyBuffer>,
    /// Transfer frame buffer (header + cEMI)
    pub(crate) transfer_buf: MaybeUninit<[u8; 271]>, // 8 header + 263 max frame
}

impl UsbCemiTransportResources {
    pub const fn new() -> Self {
        Self {
            rx_report: MaybeUninit::uninit(),
            tx_report: MaybeUninit::uninit(),
            reassembly: MaybeUninit::uninit(),
            transfer_buf: MaybeUninit::uninit(),
        }
    }

    /// Initialize resources and return mutable references
    pub fn init(&mut self) -> InitializedResources<'_> {
        InitializedResources {
            rx_report: self.rx_report.write([0u8; MAX_REPORT_SIZE]),
            tx_report: self.tx_report.write([0u8; MAX_REPORT_SIZE]),
            reassembly: self.reassembly.write(ReassemblyBuffer::new()),
            transfer_buf: self.transfer_buf.write([0u8; 271]),
        }
    }
}

impl Default for UsbCemiTransportResources {
    fn default() -> Self {
        Self::new()
    }
}

/// Borrowed view over initialised [`UsbCemiTransportResources`] buffers.
///
/// Returned by [`UsbCemiTransportResources::init`] and consumed by
/// [`UsbCemiTransport::open`]. This is **not** a link-layer `Resources`
/// in the
/// [`LinkLayerBuilderBase::Resources`](crate::layers::LinkLayerBuilderBase)
/// sense — it lives one level below, at the USB transport boundary, and
/// holds only `&mut` references into the owning `UsbCemiTransportResources`
/// struct.
pub struct InitializedResources<'a> {
    pub rx_report: &'a mut [u8; MAX_REPORT_SIZE],
    pub tx_report: &'a mut [u8; MAX_REPORT_SIZE],
    pub reassembly: &'a mut ReassemblyBuffer,
    pub transfer_buf: &'a mut [u8; 271],
}

/// USB cEMI Transport
///
/// Provides low-level cEMI frame transport over USB HID. This is the foundation
/// for building higher-level abstractions like link layers or bus monitors.
pub struct UsbCemiTransport<'a, D: UsbHidDevice> {
    device: D,
    rx_report: &'a mut [u8; MAX_REPORT_SIZE],
    tx_report: &'a mut [u8; MAX_REPORT_SIZE],
    reassembly: &'a mut ReassemblyBuffer,
    transfer_buf: &'a mut [u8; 271],
}

impl<'a> UsbCemiTransport<'a, AsyncHidDevice> {
    /// Open a USB cEMI transport with the given device selector
    pub async fn open(selector: &DeviceSelector, resources: InitializedResources<'a>) -> Result<Self, UsbHidError> {
        let device = AsyncHidDevice::open(selector).await?;

        info!(
            "USB Transport: Opened {} ({:04X}:{:04X})",
            device.device_name(),
            device.vendor_id(),
            device.product_id()
        );

        Ok(Self {
            device,
            rx_report: resources.rx_report,
            tx_report: resources.tx_report,
            reassembly: resources.reassembly,
            transfer_buf: resources.transfer_buf,
        })
    }
}

// The `.to_vec()` calls on `self.transfer_buf` slices are required because
// methods like `send_bus_access_request` and loop bodies borrow `self` mutably,
// which conflicts with the immutable borrow of `self.transfer_buf`. The copy
// breaks the borrow dependency.
#[allow(clippy::unnecessary_to_owned)]
impl<'a, D: UsbHidDevice> UsbCemiTransport<'a, D> {
    /// Create a transport from an existing device
    pub fn from_device(device: D, resources: InitializedResources<'a>) -> Self {
        Self {
            device,
            rx_report: resources.rx_report,
            tx_report: resources.tx_report,
            reassembly: resources.reassembly,
            transfer_buf: resources.transfer_buf,
        }
    }

    /// Initialize the transport (negotiate cEMI mode)
    ///
    /// This must be called before sending/receiving cEMI frames.
    pub async fn initialize(&mut self) -> Result<(), UsbHidError> {
        info!("USB Transport: Initializing...");

        // Query supported EMI types
        let supported = self.get_supported_emi_types().await?;

        if !supported.supports_cemi() {
            error!("USB Transport: Device does not support cEMI!");
            return Err(UsbHidError::OpenFailed("cEMI not supported".into()));
        }

        info!(
            "USB Transport: Supported EMI types: EMI1={}, EMI2={}, cEMI={}",
            supported.supports_emi1(),
            supported.supports_emi2(),
            supported.supports_cemi()
        );

        // Check current active EMI type
        let active = self.get_active_emi_type().await?;
        info!("USB Transport: Current active EMI type: {:?}", active);

        // Set cEMI if not already active
        if active != EmiId::CEmi {
            info!("USB Transport: Setting active EMI type to cEMI...");
            self.set_active_emi_type(EmiId::CEmi).await?;
            info!("USB Transport: cEMI mode activated");
        }

        info!("USB Transport: Initialization complete");
        Ok(())
    }

    // ========================================================================
    // Bus Access Server Operations
    // ========================================================================

    /// Query supported EMI types
    pub async fn get_supported_emi_types(&mut self) -> Result<SupportedEmiTypes, UsbHidError> {
        let len = BusAccessFrameBuilder::get_supported_emi_type(self.transfer_buf)
            .map_err(|_| UsbHidError::WriteError("Failed to build request".into()))?;

        let response = self.send_bus_access_request(&self.transfer_buf[..len].to_vec()).await?;

        let response = BusAccessResponse::parse(&response).map_err(|_| UsbHidError::InvalidReport)?;

        response.get_supported_emi_types().ok_or(UsbHidError::InvalidReport)
    }

    /// Get current active EMI type
    pub async fn get_active_emi_type(&mut self) -> Result<EmiId, UsbHidError> {
        let len = BusAccessFrameBuilder::get_active_emi_type(self.transfer_buf)
            .map_err(|_| UsbHidError::WriteError("Failed to build request".into()))?;

        let response = self.send_bus_access_request(&self.transfer_buf[..len].to_vec()).await?;

        let response = BusAccessResponse::parse(&response).map_err(|_| UsbHidError::InvalidReport)?;

        response.get_active_emi_type().ok_or(UsbHidError::InvalidReport)
    }

    /// Set active EMI type
    pub async fn set_active_emi_type(&mut self, emi_id: EmiId) -> Result<(), UsbHidError> {
        let len = BusAccessFrameBuilder::set_active_emi_type(emi_id, self.transfer_buf)
            .map_err(|_| UsbHidError::WriteError("Failed to build request".into()))?;

        let response = self.send_bus_access_request(&self.transfer_buf[..len].to_vec()).await?;

        // Per spec, a successful Set gets a Response with the same feature ID echoed back
        let response = BusAccessResponse::parse(&response).map_err(|_| UsbHidError::InvalidReport)?;

        // Verify the response contains the ActiveEmiType feature and matches what we set
        if let Some(active) = response.get_active_emi_type() {
            if active == emi_id {
                Ok(())
            } else {
                Err(UsbHidError::WriteError("Set EMI type returned wrong value".into()))
            }
        } else {
            Err(UsbHidError::WriteError("Set EMI type failed".into()))
        }
    }

    /// Get bus connection status
    pub async fn get_bus_connection_status(&mut self) -> Result<bool, UsbHidError> {
        let len = BusAccessFrameBuilder::get_bus_connection_status(self.transfer_buf)
            .map_err(|_| UsbHidError::WriteError("Failed to build request".into()))?;

        let response = self.send_bus_access_request(&self.transfer_buf[..len].to_vec()).await?;

        let response = BusAccessResponse::parse(&response).map_err(|_| UsbHidError::InvalidReport)?;

        response.get_bus_connection_status().ok_or(UsbHidError::InvalidReport)
    }

    /// Send a Bus Access Server request and wait for response
    async fn send_bus_access_request(&mut self, request: &[u8]) -> Result<Vec<u8>, UsbHidError> {
        // Fragment and send
        for report in fragment_frame(request) {
            *self.tx_report = report;
            self.device.write_report(self.tx_report).await?;
        }

        // Wait for response with timeout
        let deadline = Instant::now() + BUS_ACCESS_TIMEOUT;

        loop {
            let timeout_fut = Timer::at(deadline);
            let read_fut = self.device.read_report(self.rx_report);

            match select(timeout_fut, read_fut).await {
                Either::First(_) => {
                    return Err(UsbHidError::Timeout);
                }
                Either::Second(result) => {
                    let _len = result?;

                    let report = HidReport::parse(self.rx_report).map_err(|_| UsbHidError::InvalidReport)?;

                    match self.reassembly.process(&report) {
                        Ok(Some(data)) => {
                            // Complete frame received
                            let frame = TransferFrame::parse(data).map_err(|_| UsbHidError::InvalidReport)?;

                            if frame.is_bus_access_server() {
                                return Ok(frame.body.to_vec());
                            }
                            // Not a bus access response, continue waiting
                        }
                        Ok(None) => {
                            // Partial frame, continue reading
                        }
                        Err(_) => {
                            // Reassembly error, reset and continue
                            self.reassembly.reset();
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // Device Management (M_PropRead/Write)
    // ========================================================================

    /// Read a property from the USB interface
    ///
    /// This uses cEMI M_PropRead.req (0xFC) to read properties from the
    /// interface's internal objects.
    ///
    /// # Arguments
    /// * `object_index` - The object index (0x00 = Device Object)
    /// * `property_id` - The property ID to read
    ///
    /// # Returns
    /// The property value bytes on success
    pub async fn prop_read(&mut self, object_type: u8, property_id: u8) -> Result<Vec<u8>, UsbHidError> {
        // Build M_PropRead.req frame
        // Format per cEMI spec:
        // - Byte 0: Message Code (0xFC)
        // - Byte 1-2: Object Type (16-bit, big-endian)
        // - Byte 3: Object Instance (1-based, so use 0x01)
        // - Byte 4: Property ID
        // - Byte 5-6: Number of Elements (4 bits) + Start Index (12 bits)
        let request = [
            0xFC, // M_PropRead.req
            0x00,
            object_type, // Object Type (high byte always 0 for KNX)
            0x01,        // Object Instance (1-based!)
            property_id,
            0x10,
            0x01, // Count=1, Start=1
        ];

        self.send_device_mgmt_request(&request).await
    }

    /// Write a property to the USB interface
    ///
    /// This uses cEMI M_PropWrite.req (0xF6) to write properties to the
    /// interface's internal objects.
    ///
    /// # Arguments
    /// * `object_type` - The object type (0x00 = Device Object, 0x08 = cEMI Server Object)
    /// * `property_id` - The property ID to write
    /// * `data` - The property value to write
    pub async fn prop_write(&mut self, object_type: u8, property_id: u8, data: &[u8]) -> Result<(), UsbHidError> {
        // Build M_PropWrite.req frame
        // Format per cEMI spec:
        // - Byte 0: Message Code (0xF6)
        // - Byte 1-2: Object Type (16-bit, big-endian)
        // - Byte 3: Object Instance (1-based, so use 0x01)
        // - Byte 4: Property ID
        // - Byte 5-6: Number of Elements (4 bits) + Start Index (12 bits)
        // - Byte 7+: Data
        let mut request = Vec::with_capacity(7 + data.len());
        request.push(0xF6); // M_PropWrite.req
        request.push(0x00); // Object Type high byte
        request.push(object_type); // Object Type low byte
        request.push(0x01); // Object Instance (1-based!)
        request.push(property_id);
        request.push(0x10); // Count=1 (high nibble)
        request.push(0x01); // Start=1 (low byte of 12-bit index)
        request.extend_from_slice(data);

        let response = self.send_device_mgmt_request(&request).await?;

        // Check response - M_PropWrite.con (0xF5) should echo back with no error
        // The response format is similar but may include error info
        if response.is_empty() {
            return Err(UsbHidError::WriteError("Empty response".into()));
        }

        // A successful write echoes back the request with possibly different data
        // Error is indicated by specific error codes in the response
        Ok(())
    }

    /// Read a property and extract its data payload.
    ///
    /// Sends an `M_PropRead.req`, validates that the response contains the
    /// 7-byte device management header, and returns just the data bytes
    /// (everything after the header).
    ///
    /// The property response wire format is:
    /// ```text
    /// msg_code(1) + obj_type(2) + obj_instance(1) + pid(1) + count_idx(2) + data(N)
    /// ```
    pub async fn read_property_value(&mut self, object_type: u8, property_id: u8) -> Result<Vec<u8>, UsbHidError> {
        const HEADER_LEN: usize = 7;
        let response = self.prop_read(object_type, property_id).await?;
        if response.len() < HEADER_LEN {
            return Err(UsbHidError::InvalidReport);
        }
        Ok(response[HEADER_LEN..].to_vec())
    }

    /// Send a device management request and wait for response
    async fn send_device_mgmt_request(&mut self, request: &[u8]) -> Result<Vec<u8>, UsbHidError> {
        debug!("USB Transport: Device mgmt request: {:02X?}", request);

        // Encode as cEMI frame
        let len = encode_cemi_frame(request, self.transfer_buf)
            .map_err(|_| UsbHidError::WriteError("Failed to encode frame".into()))?;

        debug!("USB Transport: TX frame: {:02X?}", &self.transfer_buf[..len]);

        // Fragment and send
        for report in fragment_frame(&self.transfer_buf[..len].to_vec()) {
            *self.tx_report = report;
            self.device.write_report(self.tx_report).await?;
        }

        // Wait for response with timeout
        let deadline = Instant::now() + DEVICE_MGMT_TIMEOUT;

        loop {
            let timeout_fut = Timer::at(deadline);
            let read_fut = self.device.read_report(self.rx_report);

            match select(timeout_fut, read_fut).await {
                Either::First(_) => {
                    debug!("USB Transport: Device mgmt timeout waiting for response");
                    return Err(UsbHidError::Timeout);
                }
                Either::Second(result) => {
                    let len = result?;
                    trace!("USB Transport: RX raw ({} bytes): {:02X?}", len, &self.rx_report[..len.min(64)]);

                    let report = HidReport::parse(self.rx_report).map_err(|_| UsbHidError::InvalidReport)?;

                    match self.reassembly.process(&report) {
                        Ok(Some(data)) => {
                            let frame = TransferFrame::parse(data).map_err(|_| UsbHidError::InvalidReport)?;

                            debug!("USB Transport: RX frame body: {:02X?}", frame.body);

                            if frame.is_cemi_tunnel() {
                                // Check if this is a device management response
                                let body = frame.body;
                                if !body.is_empty() {
                                    let msg_code = body[0];
                                    // M_PropRead.con = 0xFB, M_PropWrite.con = 0xF5
                                    if msg_code == 0xFB || msg_code == 0xF5 {
                                        debug!("USB Transport: Device mgmt response: {:02X?}", body);
                                        return Ok(body.to_vec());
                                    }
                                    // Log other cEMI messages we're ignoring while waiting
                                    // (e.g., L_Data.ind from bus traffic after enabling DLL mode)
                                    debug!(
                                        "USB Transport: Ignoring cEMI msg_code=0x{:02X} while waiting for device mgmt response",
                                        msg_code
                                    );
                                }
                            } else {
                                debug!("USB Transport: RX non-cEMI tunnel frame");
                            }
                            // Not the expected response, continue waiting
                        }
                        Ok(None) => {
                            // Partial frame, continue reading
                        }
                        Err(_) => {
                            self.reassembly.reset();
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // cEMI Frame Operations
    // ========================================================================

    /// Send a cEMI frame
    pub async fn send_cemi<B: MessageBuffer>(&mut self, frame: &CemiBuffer<B>) -> Result<(), UsbHidError> {
        let len = encode_cemi_frame(frame.as_bytes(), self.transfer_buf)
            .map_err(|_| UsbHidError::WriteError("Failed to encode frame".into()))?;

        for report in fragment_frame(&self.transfer_buf[..len].to_vec()) {
            *self.tx_report = report;
            self.device.write_report(self.tx_report).await?;
        }

        Ok(())
    }

    /// Send raw cEMI bytes
    pub async fn send_cemi_raw(&mut self, cemi_data: &[u8]) -> Result<(), UsbHidError> {
        // Log the cEMI data being sent
        info!("USB Transport: TX cEMI raw: {:02X?}", cemi_data);

        let len = encode_cemi_frame(cemi_data, self.transfer_buf)
            .map_err(|_| UsbHidError::WriteError("Failed to encode frame".into()))?;

        // Log the full USB transfer frame (header + body)
        info!("USB Transport: TX USB frame: {:02X?}", &self.transfer_buf[..len]);

        for report in fragment_frame(&self.transfer_buf[..len].to_vec()) {
            *self.tx_report = report;
            self.device.write_report(self.tx_report).await?;
        }

        Ok(())
    }

    /// Try to receive a cEMI frame (non-blocking check)
    ///
    /// Returns `Some(cemi_data)` if a complete cEMI frame was received,
    /// `None` if no data available or frame is incomplete.
    pub async fn try_recv_cemi(&mut self) -> Result<Option<Vec<u8>>, UsbHidError> {
        // Non-blocking read
        match self.device.read_report(self.rx_report).await {
            Ok(len) => {
                trace!("USB Transport: RX {} bytes", len);
                let report = HidReport::parse(self.rx_report).map_err(|_| UsbHidError::InvalidReport)?;

                match self.reassembly.process(&report) {
                    Ok(Some(data)) => {
                        let frame = TransferFrame::parse(data).map_err(|_| UsbHidError::InvalidReport)?;

                        if frame.is_cemi_tunnel() { Ok(Some(frame.body.to_vec())) } else { Ok(None) }
                    }
                    Ok(None) => Ok(None),
                    Err(_) => {
                        self.reassembly.reset();
                        Ok(None)
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Receive a cEMI frame with timeout
    pub async fn recv_cemi_timeout(&mut self, timeout: Duration) -> Result<Vec<u8>, UsbHidError> {
        let deadline = Instant::now() + timeout;

        loop {
            let timeout_fut = Timer::at(deadline);
            let read_fut = self.device.read_report(self.rx_report);

            match select(timeout_fut, read_fut).await {
                Either::First(_) => {
                    return Err(UsbHidError::Timeout);
                }
                Either::Second(result) => {
                    let _len = result?;

                    let report = HidReport::parse(self.rx_report).map_err(|_| UsbHidError::InvalidReport)?;

                    match self.reassembly.process(&report) {
                        Ok(Some(data)) => {
                            let frame = TransferFrame::parse(data).map_err(|_| UsbHidError::InvalidReport)?;

                            if frame.is_cemi_tunnel() {
                                return Ok(frame.body.to_vec());
                            }
                            // Not a cEMI tunnel frame, continue waiting
                        }
                        Ok(None) => {
                            // Partial frame, continue reading
                        }
                        Err(_) => {
                            self.reassembly.reset();
                        }
                    }
                }
            }
        }
    }

    /// Get a reference to the underlying device
    pub fn device(&self) -> &D {
        &self.device
    }

    /// Get a mutable reference to the underlying device
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }
}

// ============================================================================
// Property IDs for USB Interface cEMI Server Object
// ============================================================================

/// Property IDs and Object Indexes for USB KNX Interface
///
/// Object layout:
/// - Object 0 (Device Object): PID 56 for max APDU length, PID 57/58 for individual address
/// - Object 8 (cEMI Server Object): PID 52 for communication mode
pub mod properties {
    /// Communication mode (0x00 = DLL, 0x01 = Bus Monitor)
    /// Located on cEMI Server Object (Object 8)
    pub const PID_COMM_MODE: u8 = 0x34; // PID 52

    /// Maximum APDU length supported by the interface
    /// Located on Device Object (Object 0)
    pub const PID_MAX_APDU_LENGTH: u8 = 0x38; // PID 56

    /// Client Subnetwork Address (area.line byte of individual address)
    /// Located on Device Object (Object 0)
    pub const PID_SUBNET_ADDR: u8 = 0x39; // PID 57

    /// Client Device Address (device byte of individual address)
    /// Located on Device Object (Object 0)
    pub const PID_DEVICE_ADDR: u8 = 0x3A; // PID 58

    /// cEMI Server Object (Object Index 8) - used for comm mode
    pub const CEMI_SERVER_OBJECT: u8 = 0x08;

    /// Device Object (Object Index 0) - used for individual address and device properties
    pub const DEVICE_OBJECT: u8 = 0x00;
}

/// Communication mode values
pub mod comm_mode {
    /// Data Link Layer mode (normal operation)
    pub const DATA_LINK_LAYER: u8 = 0x00;

    /// Bus Monitor mode
    pub const BUS_MONITOR: u8 = 0x01;
}
