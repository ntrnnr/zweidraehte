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
#[derive(Debug, Clone, Default)]
pub enum DeviceSelector {
    /// Auto-discover first KNX USB interface from known devices
    #[default]
    AutoDiscover,
    /// Match by vendor ID and product ID
    VidPid { vendor_id: u16, product_id: u16 },
    /// Match by device path (platform-specific)
    Path(String),
}

pub use zweidraehte_proto::usb_hid::{KNOWN_KNX_DEVICES, is_known_knx_device};

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
#[allow(clippy::items_after_test_module)]
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
