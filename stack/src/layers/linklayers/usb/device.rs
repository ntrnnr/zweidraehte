//! USB HID device abstraction
//!
//! This module provides a trait for USB HID device access and an implementation
//! using the async-hid crate for Linux/macOS/Windows.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::hid::MAX_REPORT_SIZE;

/// Error type for USB HID operations
#[derive(Debug)]
pub enum UsbHidError {
    /// Device not found
    NotFound,
    /// Failed to open device
    OpenFailed(String),
    /// Read error
    ReadError(String),
    /// Write error
    WriteError(String),
    /// Device disconnected
    Disconnected,
    /// Invalid report received
    InvalidReport,
    /// Timeout
    Timeout,
}

impl core::fmt::Display for UsbHidError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "USB HID device not found"),
            Self::OpenFailed(msg) => write!(f, "Failed to open device: {}", msg),
            Self::ReadError(msg) => write!(f, "Read error: {}", msg),
            Self::WriteError(msg) => write!(f, "Write error: {}", msg),
            Self::Disconnected => write!(f, "Device disconnected"),
            Self::InvalidReport => write!(f, "Invalid HID report"),
            Self::Timeout => write!(f, "Operation timed out"),
        }
    }
}

/// Device selector for finding KNX USB interfaces
#[derive(Debug, Clone)]
pub enum DeviceSelector {
    /// Auto-discover first KNX USB interface from known devices
    AutoDiscover,
    /// Match by vendor ID and product ID
    VidPid { vendor_id: u16, product_id: u16 },
    /// Match by device path (platform-specific)
    Path(String),
}

impl Default for DeviceSelector {
    fn default() -> Self {
        Self::AutoDiscover
    }
}

/// Known KNX USB interface vendor/product IDs
///
/// Taken from the Calimero project.
/// Device names are retrieved from USB device descriptors at runtime.
pub const KNOWN_KNX_DEVICES: &[(u16, u16)] = &[
    // VID 0x0111 - Makel Elektrik
    (0x0111, 0x1022), // Makel Elektrik
    // VID 0x0403 - FTDI
    (0x0403, 0x6898), // Tokka
    // VID 0x04CC - b+b Automations- und Steuerungstechnik
    (0x04CC, 0x0301), // b+b Automations- und Steuerungstechnik
    // VID 0x0681 - Siemens OCI700 interface (Synco family)
    (0x0681, 0x0014), // Siemens HVAC
    // VID 0x0908 - Siemens Automation & Drives
    (0x0908, 0x02DC), // Siemens HVAC
    (0x0908, 0x02DD), // Siemens
    (0x0908, 0x02E6), // Schrack Technik GmbH
    // VID 0x0E77 - Weinzierl Engineering GmbH
    (0x0E77, 0x0102), // Weinzierl Engineering GmbH
    (0x0E77, 0x0103), // Weinzierl Engineering GmbH
    (0x0E77, 0x0104), // GEWISS / Somfy / Weinzierl
    (0x0E77, 0x0111), // Siemens
    (0x0E77, 0x0112), // Siemens
    (0x0E77, 0x0115), // CONTROLtronic
    (0x0E77, 0x0117), // tecget
    (0x0E77, 0x0121), // Gustav Hensel GmbH & Co. KG
    (0x0E77, 0x0141), // Schneider Electric (MG)
    (0x0E77, 0x2001), // Weinzierl Engineering GmbH
    (0x0E77, 0x2002), // Gira
    (0x0E77, 0x6910), // Busch-Jaeger Elektro
    // VID 0x135E - Insta
    (0x135E, 0x0020), // Insta GmbH
    (0x135E, 0x0021), // Berker
    (0x135E, 0x0022), // GIRA Giersiepen
    (0x135E, 0x0023), // Albrecht Jung
    (0x135E, 0x0024), // Merten
    (0x135E, 0x0025), // Hager Electro
    (0x135E, 0x0026), // Feller
    (0x135E, 0x0027), // Panasonic
    (0x135E, 0x0028), // Glamox AS
    (0x135E, 0x0122), // GIRA Giersiepen
    (0x135E, 0x0123), // Albrecht Jung
    (0x135E, 0x0252), // Insta
    (0x135E, 0x0253), // Insta
    (0x135E, 0x0320), // Insta GmbH
    (0x135E, 0x0322), // GIRA Giersiepen
    (0x135E, 0x0323), // Albrecht Jung
    (0x135E, 0x0325), // Hager Electro
    (0x135E, 0x0326), // Feller
    (0x135E, 0x0329), // B.E.G.
    // VID 0x145C - Busch-Jaeger
    (0x145C, 0x1330), // Busch-Jaeger Elektro
    (0x145C, 0x1490), // Busch-Jaeger Elektro
    // VID 0x147B - ABB STOTZ-KONTAKT GmbH
    (0x147B, 0x2200), // ABB
    (0x147B, 0x5120), // ABB
    // VID 0x16D0 - MCS Electronics (OBSOLETE)
    (0x16D0, 0x0490), // TAPKO Technologies
    (0x16D0, 0x0491), // MDT technologies
    (0x16D0, 0x0492), // preussen automation
    // VID 0x16DE - Schneider Electric
    (0x16DE, 0x008E), // Schneider Electric Industries SAS
    // VID 0x24D5 - SATEL Ltd.
    (0x24D5, 0x0106), // Satel sp. z o.o.
    // VID 0x28C2 - Tapko Technologies GmbH
    (0x28C2, 0x0002), // Zennio
    (0x28C2, 0x0003), // Ekinex S.p.A.
    (0x28C2, 0x0004), // TAPKO Technologies
    (0x28C2, 0x0005), // Philips Controls
    (0x28C2, 0x0006), // HDL
    (0x28C2, 0x0007), // Niko-Zublin
    (0x28C2, 0x0008), // TAPKO Technologies
    (0x28C2, 0x000B), // VIVO
    (0x28C2, 0x000C), // ESYLUX
    (0x28C2, 0x000D), // VIVO
    (0x28C2, 0x000E), // APRICUM
    (0x28C2, 0x000F), // APRICUM
    (0x28C2, 0x0010), // Video-Star
    (0x28C2, 0x0011), // Griesser AG
    (0x28C2, 0x0012), // Griesser AG
    (0x28C2, 0x0013), // MEAN WELL Enterprises Co. Ltd.
    (0x28C2, 0x0014), // Ergo3 Sarl
    (0x28C2, 0x0015), // Bes - Ingenium
    (0x28C2, 0x0017), // Interra
    (0x28C2, 0x001A), // VIMAR
    (0x28C2, 0x001C), // OSix
    (0x28C2, 0x001D), // Panasonic
    (0x28C2, 0x001E), // Shenzhen HeGuang
    (0x28C2, 0x001F), // Module Electronic
    // VID 0x2A07 - ise GmbH
    (0x2A07, 0x0001), // ise GmbH
    (0x2A07, 0x0002), // Elsner Elektronik GmbH
    (0x2A07, 0x0003), // ise GmbH
    // VID 0x2D72 - DOGAWIST - Investment GmbH
    (0x2D72, 0x0002), // PEAKnx a DOGAWIST company
    // VID 0x7660 - KNX Association
    (0x7660, 0x0002), // KNX Association
];

/// Check if a VID:PID pair is a known KNX USB interface
pub fn is_known_knx_device(vendor_id: u16, product_id: u16) -> bool {
    KNOWN_KNX_DEVICES.iter().any(|(vid, pid)| *vid == vendor_id && *pid == product_id)
}

/// Trait for USB HID device access
///
/// This trait abstracts the USB HID device operations so we can have
/// different implementations (async-hid, mock for testing, etc.)
pub trait UsbHidDevice: Send {
    /// Read an HID report from the device
    ///
    /// Returns the number of bytes read into the buffer.
    fn read_report(
        &mut self,
        buf: &mut [u8; MAX_REPORT_SIZE],
    ) -> impl core::future::Future<Output = Result<usize, UsbHidError>> + Send;

    /// Write an HID report to the device
    fn write_report(
        &mut self,
        buf: &[u8; MAX_REPORT_SIZE],
    ) -> impl core::future::Future<Output = Result<(), UsbHidError>> + Send;
}

// ============================================================================
// async-hid implementation
// ============================================================================

use async_hid::{AsyncHidRead, AsyncHidWrite, DeviceReader, DeviceReaderWriter, DeviceWriter, HidBackend, HidResult};
use futures_lite::StreamExt;

/// USB HID device implementation using async-hid
pub struct AsyncHidDevice {
    reader: DeviceReader,
    writer: DeviceWriter,
    vendor_id: u16,
    product_id: u16,
    name: String,
}

impl AsyncHidDevice {
    /// Open a device matching the selector
    pub async fn open(selector: &DeviceSelector) -> Result<Self, UsbHidError> {
        match selector {
            DeviceSelector::AutoDiscover => Self::open_first_known().await,
            DeviceSelector::VidPid { vendor_id, product_id } => Self::open_by_vid_pid(*vendor_id, *product_id).await,
            DeviceSelector::Path(path) => Self::open_by_path(path).await,
        }
    }

    /// Open the first known KNX USB interface found
    async fn open_first_known() -> Result<Self, UsbHidError> {
        let backend = HidBackend::default();
        let mut devices =
            backend.enumerate().await.map_err(|e| UsbHidError::OpenFailed(format!("Enumeration failed: {:?}", e)))?;

        while let Some(device) = devices.next().await {
            let vid = device.vendor_id;
            let pid = device.product_id;

            if is_known_knx_device(vid, pid) {
                let name = device.name.clone();
                info!("Found KNX USB interface: {} (VID:PID = {:04X}:{:04X})", name, vid, pid);

                let result: HidResult<DeviceReaderWriter> = device.open().await;
                let (reader, writer) = result.map_err(|e| UsbHidError::OpenFailed(format!("{:?}", e)))?;

                return Ok(Self { reader, writer, vendor_id: vid, product_id: pid, name });
            }
        }

        Err(UsbHidError::NotFound)
    }

    /// Open a device by VID:PID
    async fn open_by_vid_pid(vendor_id: u16, product_id: u16) -> Result<Self, UsbHidError> {
        let backend = HidBackend::default();
        let mut devices =
            backend.enumerate().await.map_err(|e| UsbHidError::OpenFailed(format!("Enumeration failed: {:?}", e)))?;

        while let Some(device) = devices.next().await {
            if device.vendor_id == vendor_id && device.product_id == product_id {
                let name = device.name.clone();
                let result: HidResult<DeviceReaderWriter> = device.open().await;
                let (reader, writer) = result.map_err(|e| UsbHidError::OpenFailed(format!("{:?}", e)))?;

                return Ok(Self { reader, writer, vendor_id, product_id, name });
            }
        }

        Err(UsbHidError::NotFound)
    }

    /// Open a device by path
    async fn open_by_path(path: &str) -> Result<Self, UsbHidError> {
        let backend = HidBackend::default();
        let mut devices =
            backend.enumerate().await.map_err(|e| UsbHidError::OpenFailed(format!("Enumeration failed: {:?}", e)))?;

        while let Some(device) = devices.next().await {
            // async-hid uses DeviceId which can be converted to string for comparison
            let device_path = format!("{:?}", device.id);
            if device_path.contains(path) {
                let vid = device.vendor_id;
                let pid = device.product_id;
                let name = device.name.clone();

                let result: HidResult<DeviceReaderWriter> = device.open().await;
                let (reader, writer) = result.map_err(|e| UsbHidError::OpenFailed(format!("{:?}", e)))?;

                return Ok(Self { reader, writer, vendor_id: vid, product_id: pid, name });
            }
        }

        Err(UsbHidError::NotFound)
    }

    /// Get the vendor ID
    pub fn vendor_id(&self) -> u16 {
        self.vendor_id
    }

    /// Get the product ID
    pub fn product_id(&self) -> u16 {
        self.product_id
    }

    /// Get the device name from USB descriptor
    pub fn device_name(&self) -> &str {
        &self.name
    }
}

impl UsbHidDevice for AsyncHidDevice {
    async fn read_report(&mut self, buf: &mut [u8; MAX_REPORT_SIZE]) -> Result<usize, UsbHidError> {
        self.reader.read_input_report(buf).await.map_err(|e| UsbHidError::ReadError(format!("{:?}", e)))
    }

    async fn write_report(&mut self, buf: &[u8; MAX_REPORT_SIZE]) -> Result<(), UsbHidError> {
        self.writer.write_output_report(buf).await.map_err(|e| UsbHidError::WriteError(format!("{:?}", e)))
    }
}

// ============================================================================
// Mock device for testing
// ============================================================================

#[cfg(test)]
pub mod mock {
    use super::*;
    use alloc::string::ToString;
    use core::cell::RefCell;
    use heapless::Deque;

    /// Mock USB HID device for testing
    pub struct MockUsbHidDevice {
        /// Queue of reports to be "received" by read_report
        rx_queue: RefCell<Deque<[u8; MAX_REPORT_SIZE], 16>>,
        /// Queue of reports "sent" by write_report
        tx_queue: RefCell<Deque<[u8; MAX_REPORT_SIZE], 16>>,
    }

    impl MockUsbHidDevice {
        pub fn new() -> Self {
            Self { rx_queue: RefCell::new(Deque::new()), tx_queue: RefCell::new(Deque::new()) }
        }

        /// Inject a report to be returned by the next read_report call
        pub fn inject_report(&self, report: [u8; MAX_REPORT_SIZE]) {
            self.rx_queue.borrow_mut().push_back(report).ok();
        }

        /// Get the next report that was written
        pub fn pop_written_report(&self) -> Option<[u8; MAX_REPORT_SIZE]> {
            self.tx_queue.borrow_mut().pop_front()
        }

        /// Check if there are pending reports to read
        pub fn has_pending_reports(&self) -> bool {
            !self.rx_queue.borrow().is_empty()
        }
    }

    impl Default for MockUsbHidDevice {
        fn default() -> Self {
            Self::new()
        }
    }

    impl UsbHidDevice for MockUsbHidDevice {
        async fn read_report(&mut self, buf: &mut [u8; MAX_REPORT_SIZE]) -> Result<usize, UsbHidError> {
            if let Some(report) = self.rx_queue.borrow_mut().pop_front() {
                buf.copy_from_slice(&report);
                // Find actual data length (non-zero bytes after header)
                let data_len = report[2] as usize;
                Ok(3 + data_len)
            } else {
                // In a real mock, we'd want to block or return pending
                // For now, just return an error
                Err(UsbHidError::Timeout)
            }
        }

        async fn write_report(&mut self, buf: &[u8; MAX_REPORT_SIZE]) -> Result<(), UsbHidError> {
            self.tx_queue
                .borrow_mut()
                .push_back(*buf)
                .map_err(|_| UsbHidError::WriteError("Queue full".to_string()))?;
            Ok(())
        }
    }
}

/// List all available KNX USB interfaces
pub async fn list_devices() -> Result<Vec<(u16, u16, String)>, UsbHidError> {
    let backend = HidBackend::default();
    let mut devices =
        backend.enumerate().await.map_err(|e| UsbHidError::OpenFailed(format!("Enumeration failed: {:?}", e)))?;

    let mut result = Vec::new();

    while let Some(device) = devices.next().await {
        let vid = device.vendor_id;
        let pid = device.product_id;

        if is_known_knx_device(vid, pid) {
            result.push((vid, pid, device.name.clone()));
        }
    }

    Ok(result)
}
