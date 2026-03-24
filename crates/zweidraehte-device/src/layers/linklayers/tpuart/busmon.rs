//! TPUART Bus Monitor Mode
//!
//! This module provides an ergonomic interface for using TPUART chips in bus monitor mode.
//! In this mode, the chip passively captures all traffic on the KNX bus, including:
//!
//! - Raw frame bytes
//! - ACK/NACK/BUSY acknowledgment bytes
//! - Collisions and error conditions
//!
//! # Usage
//!
//! ```ignore
//! use zweidraehte_device::layers::linklayers::tpuart::busmon::BusMonitor;
//!
//! let mut monitor = BusMonitor::new(uart);
//!
//! // Initialize and enter bus monitor mode
//! monitor.start().await?;
//!
//! // Receive frames
//! loop {
//!     match monitor.receive_frame(&mut buffer).await {
//!         Ok(frame) => {
//!             println!("Frame: {:02X?}", frame.data());
//!             if let Some(ack) = frame.ack_status() {
//!                 println!("  ACK: {:?}", ack);
//!             }
//!         }
//!         Err(e) => eprintln!("Error: {:?}", e),
//!     }
//! }
//!
//! // Exit bus monitor mode (resets the chip)
//! monitor.stop().await?;
//! ```
//!
//! # Protocol Details
//!
//! When bus monitor mode is enabled (`U_BUSMON_REQ` = 0x05), the TPUART enters a
//! transparent mode where it forwards all bus bytes to the host:
//!
//! - **Data bytes**: Raw KNX frame bytes as they appear on the bus
//! - **ACK (0xCC)**: Positive acknowledgment after successful frame transmission
//! - **NACK (0x0C)**: Negative acknowledgment (checksum error or collision)
//! - **BUSY (0xC0)**: Receiver is busy
//!
//! Frame boundaries are detected by:
//! 1. Receiving an ACK/NACK/BUSY byte (marks end of acknowledged frame)
//! 2. Inter-byte timeout (~4ms without new bytes, marks end of unacknowledged frame)
//!
//! The only way to exit bus monitor mode is by sending `U_Reset.req` (0x01).

use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Instant, Timer};
use embedded_io_async::{Read, Write};

use super::state_machine::{
    BusMonitorAction, BusMonitorContext, BusMonitorEvent, BusMonitorByteType,
    process_busmon_event, TIMEOUT_RESET,
    U_BUSMON_REQ, U_RESET_IND, U_RESET_REQ,
};

/// Error type for bus monitor operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusMonitorError {
    /// UART I/O error
    IoError,
    /// Timeout waiting for response
    Timeout,
    /// Buffer too small for frame
    BufferTooSmall,
    /// Bus monitor not started
    NotStarted,
    /// Unexpected response from chip
    UnexpectedResponse(u8),
}

/// Acknowledgment status for a received frame
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckStatus {
    /// Frame was acknowledged (ACK = 0xCC)
    Ack,
    /// Frame was not acknowledged (NACK = 0x0C)
    Nack,
    /// Receiver was busy (BUSY = 0xC0)
    Busy,
    /// No acknowledgment received (timeout)
    None,
}

impl From<BusMonitorByteType> for Option<AckStatus> {
    fn from(bt: BusMonitorByteType) -> Self {
        match bt {
            BusMonitorByteType::Ack => Some(AckStatus::Ack),
            BusMonitorByteType::Nack => Some(AckStatus::Nack),
            BusMonitorByteType::Busy => Some(AckStatus::Busy),
            BusMonitorByteType::Data => None,
        }
    }
}

/// A captured bus frame
#[derive(Debug)]
pub struct CapturedFrame<'a> {
    /// Frame data (including ACK byte if present)
    data: &'a [u8],
    /// Acknowledgment status (if frame ended with ACK/NACK/BUSY)
    ack_status: Option<AckStatus>,
}

impl<'a> CapturedFrame<'a> {
    /// Get the raw frame data
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Get the acknowledgment status
    pub fn ack_status(&self) -> Option<AckStatus> {
        self.ack_status
    }

    /// Get frame data without the ACK byte (if present)
    pub fn data_without_ack(&self) -> &[u8] {
        if self.ack_status.is_some() && !self.data.is_empty() {
            &self.data[..self.data.len() - 1]
        } else {
            self.data
        }
    }

    /// Check if this frame was successfully acknowledged
    pub fn is_acked(&self) -> bool {
        self.ack_status == Some(AckStatus::Ack)
    }
}

/// TPUART Bus Monitor
///
/// Provides an async interface for capturing KNX bus traffic using a TPUART chip
/// in bus monitor mode.
pub struct BusMonitor<U> {
    uart: U,
    ctx: BusMonitorContext,
    timeout_deadline: Option<Instant>,
}

impl<U> BusMonitor<U>
where
    U: Read + Write,
{
    /// Create a new bus monitor
    pub fn new(uart: U) -> Self {
        Self {
            uart,
            ctx: BusMonitorContext::new(),
            timeout_deadline: None,
        }
    }

    /// Start bus monitor mode
    ///
    /// This resets the TPUART chip and enables bus monitor mode.
    pub async fn start(&mut self) -> Result<(), BusMonitorError> {
        // Reset the chip first
        self.reset_chip().await?;

        // Enable bus monitor mode
        let actions = process_busmon_event(&mut self.ctx, BusMonitorEvent::Enable);

        for action in actions.iter() {
            if let BusMonitorAction::SendBusMonitorEnable = action {
                self.uart.write_all(&[U_BUSMON_REQ]).await
                    .map_err(|_| BusMonitorError::IoError)?;
            }
        }

        Ok(())
    }

    /// Stop bus monitor mode
    ///
    /// This resets the TPUART chip to exit bus monitor mode.
    pub async fn stop(&mut self) -> Result<(), BusMonitorError> {
        let actions = process_busmon_event(&mut self.ctx, BusMonitorEvent::Disable);

        for action in actions.iter() {
            if let BusMonitorAction::SendReset = action {
                self.reset_chip().await?;
            }
        }

        Ok(())
    }

    /// Check if bus monitor mode is active
    pub fn is_active(&self) -> bool {
        self.ctx.is_active()
    }

    /// Receive the next frame from the bus
    ///
    /// Returns a `CapturedFrame` containing the raw frame data and acknowledgment status.
    /// The provided buffer must be large enough to hold the frame (typically 64 bytes
    /// for standard frames, 256 for extended frames).
    pub async fn receive_frame<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<CapturedFrame<'a>, BusMonitorError> {
        if !self.ctx.is_active() {
            return Err(BusMonitorError::NotStarted);
        }

        let mut write_idx = 0;
        let mut ack_status: Option<AckStatus> = None;

        loop {
            let mut byte_buf = [0u8; 1];

            // Calculate timeout
            let timeout_duration = if let Some(deadline) = self.timeout_deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.as_ticks() == 0 {
                    Duration::from_millis(0)
                } else {
                    remaining
                }
            } else {
                // No active timeout, wait indefinitely (well, 1 hour)
                Duration::from_secs(3600)
            };

            let timeout_future = Timer::after(timeout_duration);

            match select(timeout_future, self.uart.read(&mut byte_buf)).await {
                Either::First(_) => {
                    // Timeout
                    let actions = process_busmon_event(&mut self.ctx, BusMonitorEvent::Timer);

                    for action in actions.iter() {
                        if let BusMonitorAction::FrameComplete = action {
                            self.timeout_deadline = None;
                            return Ok(CapturedFrame {
                                data: &buffer[..write_idx],
                                ack_status,
                            });
                        }
                    }

                    self.timeout_deadline = None;
                }
                Either::Second(result) => {
                    let byte = match result {
                        Ok(_) => byte_buf[0],
                        Err(_) => {
                            let _ = process_busmon_event(&mut self.ctx, BusMonitorEvent::ReceiveError);
                            continue;
                        }
                    };

                    let actions = process_busmon_event(&mut self.ctx, BusMonitorEvent::ReceivedByte(byte));

                    for action in actions.iter() {
                        match action {
                            BusMonitorAction::StoreReceivedByte(b) => {
                                if write_idx >= buffer.len() {
                                    return Err(BusMonitorError::BufferTooSmall);
                                }
                                buffer[write_idx] = *b;
                                write_idx += 1;
                            }
                            BusMonitorAction::ReceivedByte { byte_type, .. } => {
                                if let Some(status) = (*byte_type).into() {
                                    ack_status = Some(status);
                                }
                            }
                            BusMonitorAction::StartTimer(duration) => {
                                self.timeout_deadline = Some(Instant::now() + *duration);
                            }
                            BusMonitorAction::FrameComplete => {
                                self.timeout_deadline = None;
                                return Ok(CapturedFrame {
                                    data: &buffer[..write_idx],
                                    ack_status,
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    /// Reset the TPUART chip
    async fn reset_chip(&mut self) -> Result<(), BusMonitorError> {
        self.uart.write_all(&[U_RESET_REQ]).await
            .map_err(|_| BusMonitorError::IoError)?;

        let mut buf = [0u8; 1];
        let timeout = Timer::after(Duration::from_millis(TIMEOUT_RESET.as_millis()));

        match select(timeout, self.uart.read(&mut buf)).await {
            Either::First(_) => Err(BusMonitorError::Timeout),
            Either::Second(result) => {
                match result {
                    Ok(_) if buf[0] == U_RESET_IND => Ok(()),
                    Ok(_) => Err(BusMonitorError::UnexpectedResponse(buf[0])),
                    Err(_) => Err(BusMonitorError::IoError),
                }
            }
        }
    }

    /// Consume the bus monitor and return the UART
    pub fn release(self) -> U {
        self.uart
    }
}

/// Bus monitor ACK byte value
pub const BUSMON_ACK: u8 = super::state_machine::BUSMON_ACK;
/// Bus monitor NACK byte value
pub const BUSMON_NACK: u8 = super::state_machine::BUSMON_NACK;
/// Bus monitor BUSY byte value
pub const BUSMON_BUSY: u8 = super::state_machine::BUSMON_BUSY;
