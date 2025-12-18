//! KNX Bus Monitor using TPUART
//!
//! This utility puts the TPUART chip into bus monitor mode and displays
//! all traffic seen on the KNX bus. In this mode, the chip transparently
//! forwards every byte from the bus, including ACK/NACK/BUSY bytes.
//!
//! # Usage
//!
//! ```sh
//! cargo run --bin busmon -- /dev/ttyUSB0
//! ```

use std::io::{self, Write as IoWrite};

use embassy_executor::Spawner;
use env_logger::Env;

use platform::{
    AsyncSerialPort,
    serialport::{Options, Parity},
};

use zweidraehte::layers::linklayers::tpuart::busmon::{
    AckStatus, BusMonitor, BusMonitorError, BUSMON_ACK, BUSMON_BUSY, BUSMON_NACK,
};

/// Print a captured frame with decoded information
fn print_frame(frame: &[u8], ack_status: Option<AckStatus>) {
    let timestamp = chrono::Local::now().format("%H:%M:%S%.3f");

    // Print raw bytes
    print!("[{}] ", timestamp);

    if frame.is_empty() {
        println!("<empty frame>");
        return;
    }

    // Print hex dump
    for byte in frame.iter().take(frame.len().saturating_sub(1)) {
        print!("{:02X} ", byte);
    }

    // Print last byte (might be ACK/NACK/BUSY)
    if let Some(&last) = frame.last() {
        match last {
            BUSMON_ACK => print!("[ACK]"),
            BUSMON_NACK => print!("[NACK]"),
            BUSMON_BUSY => print!("[BUSY]"),
            _ => print!("{:02X}", last),
        }
    }

    // Print ACK status
    if let Some(status) = ack_status {
        match status {
            AckStatus::Ack => print!(" -> ACK"),
            AckStatus::Nack => print!(" -> NACK"),
            AckStatus::Busy => print!(" -> BUSY"),
            AckStatus::None => {}
        }
    }

    println!();

    // Try to decode the frame if it looks valid
    if frame.len() >= 7 {
        decode_frame(frame);
    }

    io::stdout().flush().ok();
}

/// Decode and print frame details
fn decode_frame(frame: &[u8]) {
    let ctrl = frame[0];

    // Check if extended frame
    let is_extended = (ctrl & 0x80) != 0x80;

    // Frame type from control byte
    let frame_type = if is_extended { "Extended" } else { "Standard" };
    let repeated = if (ctrl & 0x20) == 0 { " (repeat)" } else { "" };
    let priority = match (ctrl >> 2) & 0x03 {
        0 => "System",
        1 => "Normal",
        2 => "Urgent",
        3 => "Low",
        _ => unreachable!(),
    };

    // Source address (bytes 1-2)
    let src_area = (frame[1] >> 4) & 0x0F;
    let src_line = frame[1] & 0x0F;
    let src_dev = frame[2];

    // Destination address (bytes 3-4)
    let dst_hi = frame[3];
    let dst_lo = frame[4];
    let is_group_addr = (frame[5] & 0x80) != 0;

    let dst_str = if is_group_addr {
        // Group address
        let main = (dst_hi >> 3) & 0x1F;
        let middle = dst_hi & 0x07;
        let sub = dst_lo;
        format!("{}/{}/{}", main, middle, sub)
    } else {
        // Individual address
        let area = (dst_hi >> 4) & 0x0F;
        let line = dst_hi & 0x0F;
        format!("{}.{}.{}", area, line, dst_lo)
    };

    // APCI (application layer control info)
    let apci_hi = frame[5] & 0x03;
    let apci_lo = if frame.len() > 6 { (frame[6] >> 6) & 0x03 } else { 0 };
    let apci = (apci_hi << 2) | apci_lo;

    let apci_name = match apci {
        0x00 => "GroupValueRead",
        0x01 => "GroupValueResponse",
        0x02 => "GroupValueWrite",
        0x03 => "IndividualAddrWrite",
        0x04 => "IndividualAddrRequest",
        0x05 => "IndividualAddrResponse",
        0x06 => "ADC_Read",
        0x07 => "ADC_Response",
        0x08 => "MemoryRead",
        0x09 => "MemoryResponse",
        0x0A => "MemoryWrite",
        0x0B => "UserMessage",
        0x0C => "DevDescriptorRead",
        0x0D => "DevDescriptorResponse",
        0x0E => "Restart",
        0x0F => "Escape",
        _ => "Unknown",
    };

    // Extract data if present
    let data_start = if is_extended { 8 } else { 7 };
    let data_len = if frame.len() > data_start {
        // Don't include checksum or ACK byte
        let end = frame.len();
        let end = if matches!(frame.last(), Some(&BUSMON_ACK) | Some(&BUSMON_NACK) | Some(&BUSMON_BUSY)) {
            end - 1
        } else {
            end
        };
        // Also exclude checksum (last byte before ACK)
        end.saturating_sub(data_start).saturating_sub(1)
    } else {
        0
    };

    println!(
        "       {} {}{}: {}.{}.{} -> {} {} {}",
        frame_type,
        priority,
        repeated,
        src_area,
        src_line,
        src_dev,
        dst_str,
        if is_group_addr { "GA" } else { "IA" },
        apci_name
    );

    // Print data bytes if present
    if data_len > 0 && frame.len() > data_start {
        let data_end = (data_start + data_len).min(frame.len());
        print!("       Data: ");

        // First data byte may contain 6 bits of data in APDU
        if frame.len() > 6 {
            let first_data = frame[6] & 0x3F;
            if data_len == 0 && first_data != 0 {
                print!("{:02X} ", first_data);
            }
        }

        for byte in &frame[data_start..data_end] {
            print!("{:02X} ", byte);
        }
        println!();
    }
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // Get serial port from command line args
    let args: Vec<String> = std::env::args().collect();
    let port = args.get(1).map(|s| s.as_str()).unwrap_or("/dev/ttyUSB0");

    println!("KNX Bus Monitor");
    println!("Opening serial port: {}", port);

    let uart = match AsyncSerialPort::open(Options {
        path: port.to_string(),
        baud_rate: 19200,
        parity: Parity::Even,
        ..Default::default()
    }) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open serial port: {:?}", e);
            return;
        }
    };

    // Create bus monitor
    let mut monitor = BusMonitor::new(uart);

    // Start bus monitor mode
    println!("Starting bus monitor mode...");
    if let Err(e) = monitor.start().await {
        eprintln!("Failed to start bus monitor: {:?}", e);
        return;
    }

    println!("Bus monitor mode enabled");
    println!("Press Ctrl+C to exit");
    println!("---");

    // Frame buffer
    let mut buffer = [0u8; 256];

    // Main receive loop
    loop {
        match monitor.receive_frame(&mut buffer).await {
            Ok(frame) => {
                print_frame(frame.data(), frame.ack_status());
            }
            Err(BusMonitorError::BufferTooSmall) => {
                eprintln!("Frame too large for buffer");
            }
            Err(e) => {
                log::warn!("Bus monitor error: {:?}", e);
            }
        }
    }
}
