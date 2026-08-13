//! MDT Bootloader (BSL) protocol client.
//!
//! Communicates with MDT device bootloaders via `A_FunctionPropertyCommand`
//! on object 0, property 242. Supports reading bootloader info structures
//! and controlling the bootloader state.
//!
//! Usage:
//!     cargo run -p zweidraehte-client --example mdt_bootloader -- \
//!         --server 192.168.1.100:3671 --device 1.0.101 <command>
//!
//! `--usb[=vid:pid]` connects through a KNX USB interface instead of
//! `--server`; see `--help` for the command list.

mod common;

use clap::{Parser, ValueEnum};
use common::TargetArgs;
use zweidraehte_client::{IndividualAddress, KnxBus};

// ============================================================================
// Protocol Constants
// ============================================================================

const BSL_OBJECT_IDX: u8 = 0;
const BSL_PROPERTY_ID: u16 = 242;

/// Response bit set in the command echo byte.
const RESPONSE_BIT: u8 = 0x80;

// ============================================================================
// BSL Commands
// ============================================================================

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum BslCmd {
    SwitchToBt = 0x01,
    SwitchToApp = 0x02,
    StateRequest = 0x05,
    ReadBslInfo = 0x11,
    ReadDevInfo = 0x12,
    ReadAppInfo = 0x13,
    ReadExchange = 0x14,
}

// ============================================================================
// BSL Device State
// ============================================================================

#[derive(Debug)]
enum BslState {
    AppError,
    AppReady,
    Bootloader,
    AppActive,
    Unknown(u8),
}

impl BslState {
    fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::AppError,
            1 => Self::AppReady,
            2 => Self::Bootloader,
            3 => Self::AppActive,
            x => Self::Unknown(x),
        }
    }
}

impl std::fmt::Display for BslState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AppError => write!(f, "Application Error"),
            Self::AppReady => write!(f, "Application Ready (for download)"),
            Self::Bootloader => write!(f, "Bootloader"),
            Self::AppActive => write!(f, "Application Active"),
            Self::Unknown(x) => write!(f, "Unknown ({:#04x})", x),
        }
    }
}

// ============================================================================
// Parsed Info Structures
// ============================================================================

#[derive(Debug)]
struct BslInfo {
    bsl_version: u16,
    crc_type: u8,
    max_telegram_len: u8,
    hwsw_key: [u8; 4],
    encryption_type: u8,
    app_info_addr: u32,
    bt_eeprom_stop_border: u32,
    exchange_info_addr: u32,
    dev_info_addr: u32,
}

#[derive(Debug)]
struct AppInfo {
    checksum: u32,
    checksum_len: u32,
    reset_vector_addr: u32,
    hwsw_key: [u8; 4],
    app_version: u16,
    checksum_blocks: Vec<ChecksumBlock>,
}

#[derive(Debug)]
struct ChecksumBlock {
    start_addr: u32,
    stop_addr: u32,
    checksum: u32,
}

// ============================================================================
// Protocol Operations
// ============================================================================

/// Send a single BSL command and return the BSL response data.
///
/// The command frame (service_data) is `[0x00, cmd, seq, extra_data...]`.
///
/// The KNX `FunctionPropertyStateResponse` has its own return_code at APDU
/// byte 4 (KNX-level success/failure). The BSL protocol's command echo and
/// payload live inside `result.data`:
///
/// ```text
/// result.return_code = KNX-level return code (not BSL)
/// result.data[0]     = cmd | 0x80 (BSL command echo with response bit)
/// result.data[1+]    = BSL response payload
/// ```
///
/// Returns the BSL response payload (everything after the command echo byte).
async fn bsl_command(
    client: &KnxBus,
    device: IndividualAddress,
    cmd: u8,
    seq: u8,
    extra_data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut service_data = vec![0x00, cmd, seq];
    service_data.extend_from_slice(extra_data);

    let result = client
        .network_management()
        .function_property_command(device, BSL_OBJECT_IDX, BSL_PROPERTY_ID, &service_data)
        .await?;

    log::debug!(
        "BSL cmd={:#04x} seq={}: return_code={:#04x}, data=[{}]",
        cmd,
        seq,
        result.return_code,
        hex_bytes(&result.data),
    );

    // The BSL protocol response is inside result.data.
    if result.data.is_empty() {
        return Err(format!("Empty BSL response for cmd {:#04x}", cmd).into());
    }

    let echo = result.data[0];

    // Error response: echo byte is 0xFF.
    if echo == 0xFF {
        return Err(format!("Device returned BSL error (cmd={:#04x})", cmd).into());
    }

    // Verify the echo matches our command with the response bit set.
    let expected_echo = cmd | RESPONSE_BIT;
    if echo != expected_echo {
        return Err(format!("BSL response mismatch: expected echo {:#04x}, got {:#04x}", expected_echo, echo,).into());
    }

    // Return everything after the echo byte.
    Ok(result.data[1..].to_vec())
}

/// Read a multipart info response by iterating through all sequence numbers.
///
/// Info commands (0x1x) return data split across multiple response fragments.
/// Each fragment's BSL payload (after the command echo byte) contains:
///
/// ```text
/// [0] max_seq      — total number of fragments minus one
/// [1] current_seq  — sequence number of this fragment
/// [2] data_len     — number of payload bytes in this fragment
/// [3..3+data_len]  — payload data
/// ```
///
/// Fragments are requested sequentially from seq=0 to seq=max_seq. The
/// payloads are concatenated to reassemble the full info structure.
async fn bsl_read_multipart(
    client: &KnxBus,
    device: IndividualAddress,
    cmd: u8,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut assembled = Vec::new();
    let mut seq: u8 = 0;

    loop {
        let data = bsl_command(client, device, cmd, seq, &[]).await?;

        if data.len() < 3 {
            return Err(format!("Info response too short ({} bytes, need at least 3 for header)", data.len()).into());
        }

        let max_seq = data[0];
        let current_seq = data[1];
        let data_len = data[2] as usize;

        if current_seq != seq {
            return Err(format!("Sequence mismatch: expected {}, got {}", seq, current_seq).into());
        }

        if data.len() < 3 + data_len {
            return Err(format!(
                "Fragment {} too short: data_len={} but only {} bytes available",
                seq,
                data_len,
                data.len() - 3,
            )
            .into());
        }

        let payload = &data[3..3 + data_len];
        log::debug!("Fragment {}/{}: {} bytes [{}]", current_seq, max_seq, data_len, hex_bytes(payload),);
        assembled.extend_from_slice(payload);

        if seq >= max_seq {
            break;
        }
        seq += 1;
    }

    Ok(assembled)
}

// ============================================================================
// Structure Parsers
// ============================================================================

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn parse_bsl_info(data: &[u8]) -> Result<BslInfo, Box<dyn std::error::Error>> {
    if data.len() < 28 {
        return Err(format!("BSL info too short: {} bytes (need 28)", data.len()).into());
    }

    Ok(BslInfo {
        bsl_version: read_u16(data, 0),
        crc_type: data[2],
        max_telegram_len: data[3],
        hwsw_key: [data[4], data[5], data[6], data[7]],
        encryption_type: data[8],
        app_info_addr: read_u32(data, 12),
        bt_eeprom_stop_border: read_u32(data, 16),
        exchange_info_addr: read_u32(data, 20),
        dev_info_addr: read_u32(data, 24),
    })
}

fn parse_app_info(data: &[u8]) -> Result<AppInfo, Box<dyn std::error::Error>> {
    if data.len() < 20 {
        return Err(format!("App info too short: {} bytes (need at least 20)", data.len()).into());
    }

    let num_blocks = data[19] as usize;
    let blocks_start = 20;
    let expected_len = blocks_start + num_blocks * 12;

    if data.len() < expected_len {
        return Err(format!(
            "App info too short for {} checksum blocks: {} bytes (need {})",
            num_blocks,
            data.len(),
            expected_len
        )
        .into());
    }

    let mut checksum_blocks = Vec::with_capacity(num_blocks);
    for i in 0..num_blocks {
        let offset = blocks_start + i * 12;
        checksum_blocks.push(ChecksumBlock {
            start_addr: read_u32(data, offset),
            stop_addr: read_u32(data, offset + 4),
            checksum: read_u32(data, offset + 8),
        });
    }

    Ok(AppInfo {
        checksum: read_u32(data, 0),
        checksum_len: read_u32(data, 4),
        reset_vector_addr: read_u32(data, 8),
        hwsw_key: [data[12], data[13], data[14], data[15]],
        app_version: read_u16(data, 16),
        checksum_blocks,
    })
}

// ============================================================================
// Display Helpers
// ============================================================================

fn format_version(v: u16) -> String {
    format!("{}.{:02}", v >> 8, v & 0xFF)
}

fn hex_bytes(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

fn print_bsl_info(info: &BslInfo) {
    println!("BSL Info:");
    println!("  Version:          {}", format_version(info.bsl_version));
    println!("  CRC type:         {:#04x}", info.crc_type);
    println!("  Max telegram len: {}", info.max_telegram_len);
    println!("  HWSW key:         {}", hex_bytes(&info.hwsw_key));
    println!("  Encryption:       {:#04x}", info.encryption_type);
    println!("  App info addr:    {:#010x}", info.app_info_addr);
    println!("  EEPROM border:    {:#010x}", info.bt_eeprom_stop_border);
    println!("  Exchange addr:    {:#010x}", info.exchange_info_addr);
    println!("  Dev info addr:    {:#010x}", info.dev_info_addr);
}

fn print_app_info(info: &AppInfo) {
    println!("App Info:");
    println!("  Checksum:         {:#010x}", info.checksum);
    println!("  Checksum length:  {:#010x}", info.checksum_len);
    println!("  Reset vector:     {:#010x}", info.reset_vector_addr);
    println!("  HWSW key:         {}", hex_bytes(&info.hwsw_key));
    println!("  App version:      {}", format_version(info.app_version));
    println!("  Checksum blocks:  {}", info.checksum_blocks.len());
    for (i, block) in info.checksum_blocks.iter().enumerate() {
        println!(
            "    [{}] {:#010x} - {:#010x}  checksum: {:#010x}",
            i, block.start_addr, block.stop_addr, block.checksum
        );
    }
}

fn print_hex_dump(label: &str, data: &[u8]) {
    println!("{} ({} bytes):", label, data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: String = chunk
            .iter()
            .enumerate()
            .map(|(j, b)| if j == 8 { format!(" {:02x}", b) } else { format!("{:02x}", b) })
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String =
            chunk.iter().map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }).collect();
        println!("  {:04x}  {:<49} {}", i * 16, hex, ascii);
    }
}

// ============================================================================
// CLI
// ============================================================================

/// Talk to an MDT device bootloader (BSL protocol).
#[derive(Parser)]
struct Config {
    #[command(flatten)]
    target: TargetArgs,

    /// Target device individual address, e.g. 1.0.101
    #[arg(short, long, value_parser = common::parse_ia)]
    device: IndividualAddress,

    /// What to do on the bootloader
    #[arg(value_enum)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Command {
    /// Read current bootloader state
    State,
    /// Read BSL info structure
    BslInfo,
    /// Read device info (raw hex dump)
    DevInfo,
    /// Read application info structure
    AppInfo,
    /// Read exchange data (raw hex dump)
    Exchange,
    /// Switch device to bootloader mode
    SwitchBt,
    /// Switch device to application mode
    SwitchApp,
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let config = Config::parse();

    // Connect to the bus.
    let bus = config.target.to_target().connect().await?;
    println!("Connected. Assigned address: {}, interface max APDU: {}", bus.assigned_address(), bus.max_apdu());

    // Dispatch the requested command.
    let result = run_command(&bus, config.device, config.command).await;

    // Always try to disconnect cleanly.
    let _ = bus.disconnect().await;

    result
}

async fn run_command(
    client: &KnxBus,
    device: IndividualAddress,
    command: Command,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::State => {
            let data = bsl_command(client, device, BslCmd::StateRequest as u8, 0, &[]).await?;
            if data.is_empty() {
                return Err("Empty state response".into());
            }
            let state = BslState::from_byte(data[0]);
            println!("Device state: {}", state);
        }

        Command::BslInfo => {
            let data = bsl_read_multipart(client, device, BslCmd::ReadBslInfo as u8).await?;
            print_hex_dump("BSL Info (raw)", &data);
            println!();
            match parse_bsl_info(&data) {
                Ok(info) => print_bsl_info(&info),
                Err(e) => eprintln!("Failed to parse BSL info: {}", e),
            }
        }

        Command::DevInfo => {
            let data = bsl_read_multipart(client, device, BslCmd::ReadDevInfo as u8).await?;
            print_hex_dump("Device Info", &data);
        }

        Command::AppInfo => {
            let data = bsl_read_multipart(client, device, BslCmd::ReadAppInfo as u8).await?;
            print_hex_dump("App Info (raw)", &data);
            println!();
            match parse_app_info(&data) {
                Ok(info) => print_app_info(&info),
                Err(e) => eprintln!("Failed to parse app info: {}", e),
            }
        }

        Command::Exchange => {
            let data = bsl_read_multipart(client, device, BslCmd::ReadExchange as u8).await?;
            print_hex_dump("Exchange Data", &data);
        }

        Command::SwitchBt => {
            // SwitchToBt only needs [0x00, 0x01] — no sequence number.
            let data = bsl_command(client, device, BslCmd::SwitchToBt as u8, 0, &[]).await?;
            println!("Switch to bootloader: OK");
            if !data.is_empty() {
                println!("  Response data: {}", hex_bytes(&data));
            }
        }

        Command::SwitchApp => {
            let data = bsl_command(client, device, BslCmd::SwitchToApp as u8, 0, &[]).await?;
            println!("Switch to application: OK");
            if !data.is_empty() {
                println!("  Response data: {}", hex_bytes(&data));
            }
        }
    }

    Ok(())
}
