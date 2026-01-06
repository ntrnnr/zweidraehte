//! Sequence number behavior test for malformed memory writes
//!
//! This utility tests how a real KNX device handles sequence numbers when
//! malformed memory write requests are rejected/ignored.
//!
//! Based on conformance test 2.32.3 which shows that sequence numbers do NOT
//! increment when frames are rejected due to inconsistent length.
//!
//! Usage: cargo run --bin seqno_test
//!
//! Communicates via USB link layer (1.0.250) with device at 1.0.100
//! Uses memory address 0x4040 for testing.

mod keyboard;

use std::cell::RefCell;

use embassy_executor::Spawner;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
use embassy_time::{Duration, Timer};
use env_logger::Env;

use zweidraehte::{
    address::IndividualAddress,
    context::BufferManagerContext,
    encoding::tp1::{tp1_to_knx_message, tp1_to_knx_message_no_checksum},
    layers::{
        ActorRequest, LayerOp, LinkLayerBuilder,
        linklayers::usb::{UsbLinkLayerBuilder, UsbLinkLayerResources},
    },
    messages::{
        buffers::{Buffer, BufferManager, MessageBuffer},
        builder::RequestMessage,
        knx::{KnxMessageBuffer, ServiceType},
    },
};

/// Our address as the tester
const TESTER_ADDR: IndividualAddress = IndividualAddress::new(1, 0, 250);
/// Device under test address
const DUT_ADDR: IndividualAddress = IndividualAddress::new(1, 0, 101);
/// Memory address for testing
const MEM_ADDR: u16 = 0x4040;

// Fake network layer that receives indications and stores them for later inspection
struct TestNetworkLayer {
    receiver: embassy_sync::channel::Receiver<'static, NoopRawMutex, LayerOp<Buffer<'static>>, 32>,
    received: &'static RefCell<Vec<Vec<u8>>>,
}

impl TestNetworkLayer {
    async fn process(&mut self) -> ! {
        loop {
            let layer_op = self.receiver.receive().await;
            match layer_op {
                LayerOp::Indication(msg) => {
                    let buf = msg.buf().to_vec();
                    print_frame("RX", &buf);
                    self.received.borrow_mut().push(buf);
                }
                LayerOp::Request { message: _msg, response_tx: _response_tx } => {
                    println!("Unexpected request from link layer");
                }
            }
        }
    }
}

/// Pretty print a KNX frame
fn print_frame(prefix: &str, buf: &[u8]) {
    if buf.len() < 6 {
        println!("{}: {:02X?} (too short)", prefix, buf);
        return;
    }

    let src = u16::from_be_bytes([buf[1], buf[2]]);
    let dst = u16::from_be_bytes([buf[3], buf[4]]);

    let src_str = format!("{}.{}.{}", (src >> 12) & 0xF, (src >> 8) & 0xF, src & 0xFF);
    let dst_str = format!("{}.{}.{}", (dst >> 12) & 0xF, (dst >> 8) & 0xF, dst & 0xFF);

    // Parse TPCI
    if buf.len() >= 7 {
        let tpci = buf[6];
        let is_control = (tpci & 0x80) != 0;

        if is_control {
            // Control frame - TPCI format: 1 CC SSSS XX
            // CC = control type: 00=T_Connect/Disconnect, 01=T_ACK/NAK, 10/11=reserved
            // SSSS = sequence number (for ACK/NAK)
            // XX = subtype bits
            let ctrl_type = (tpci >> 5) & 0x03; // Bits 6-5
            let seqno = (tpci >> 2) & 0x0F;
            let ctrl_str = match tpci {
                0x80 => "T_Connect",
                0x81 => "T_Disconnect",
                t if (t & 0xC3) == 0xC2 => "T_ACK",
                t if (t & 0xC3) == 0xC3 => "T_NAK",
                _ => "T_???",
            };
            if ctrl_str == "T_ACK" || ctrl_str == "T_NAK" {
                println!("{}: {} -> {} {} seqno={}", prefix, src_str, dst_str, ctrl_str, seqno);
            } else {
                println!("{}: {} -> {} {}", prefix, src_str, dst_str, ctrl_str);
            }
        } else {
            // Data frame
            let seqno = (tpci >> 2) & 0x0F;
            let apci_hi = tpci & 0x03;
            let apci_lo = if buf.len() > 7 { buf[7] } else { 0 };
            let apci = ((apci_hi as u16) << 8) | (apci_lo as u16);

            println!(
                "{}: {} -> {} T_Data seqno={} APCI={:03X} data={:02X?}",
                prefix,
                src_str,
                dst_str,
                seqno,
                apci,
                &buf[8..]
            );
        }
    } else {
        println!("{}: {} -> {} {:02X?}", prefix, src_str, dst_str, &buf[6..]);
    }
}

#[embassy_executor::task]
async fn run_network(mut layer: TestNetworkLayer) {
    layer.process().await;
}

// Simple context that just provides a buffer manager
struct SimpleContext {
    buffer_manager: &'static RefCell<zweidraehte::messages::buffers::DynBufferManager<'static>>,
}

impl BufferManagerContext for SimpleContext {
    fn buffer_manager(&self) -> &RefCell<zweidraehte::messages::buffers::DynBufferManager<'static>> {
        self.buffer_manager
    }
}

/// Build a raw KNX frame
fn build_raw_frame(
    mut buffer: Buffer<'static>,
    ctrl: u8,
    src: IndividualAddress,
    dst: IndividualAddress,
    at_hc_eff: u8,
    payload: &[u8],
) -> RequestMessage<Buffer<'static>> {
    let len = 6 + payload.len();
    buffer.resize(len, 0);
    buffer[0] = ctrl;
    let src_bytes = src.as_bytes();
    let dst_bytes = dst.as_bytes();
    buffer[1] = src_bytes[0];
    buffer[2] = src_bytes[1];
    buffer[3] = dst_bytes[0];
    buffer[4] = dst_bytes[1];
    buffer[5] = at_hc_eff;
    buffer[6..].copy_from_slice(payload);

    let msg = KnxMessageBuffer::new(tp1_to_knx_message_no_checksum(buffer), ServiceType::L_Data_Req);
    RequestMessage::request(msg)
}

/// Send a T_Connect
fn build_t_connect(
    buffer: Buffer<'static>,
    src: IndividualAddress,
    dst: IndividualAddress,
) -> RequestMessage<Buffer<'static>> {
    // T_Connect: TPCI = 0x80
    build_raw_frame(buffer, 0xB0, src, dst, 0x60, &[0x80])
}

/// Send a T_Disconnect
fn build_t_disconnect(
    buffer: Buffer<'static>,
    src: IndividualAddress,
    dst: IndividualAddress,
) -> RequestMessage<Buffer<'static>> {
    // T_Disconnect: TPCI = 0x81
    build_raw_frame(buffer, 0xB0, src, dst, 0x60, &[0x81])
}

/// Send a T_ACK with sequence number
fn build_t_ack(
    buffer: Buffer<'static>,
    src: IndividualAddress,
    dst: IndividualAddress,
    seqno: u8,
) -> RequestMessage<Buffer<'static>> {
    // T_ACK: TPCI = 0xC2 | (seqno << 2)
    let tpci = 0xC2 | ((seqno & 0x0F) << 2);
    build_raw_frame(buffer, 0xB0, src, dst, 0x60, &[tpci])
}

/// Build a Memory_Write request (A_Memory_Write = 0x0080, but in APCI it's 02 in the 10-bit APCI)
/// Wait, UserMemory uses 0x2C0-0x2C2, regular Memory uses 0x0200 (read), 0x0240 (response), 0x0280 (write)
///
/// For A_Memory_Write (APCI 0x0280):
/// TPCI/APCI byte format: TPCI[7:2] APCI[9:8] | APCI[7:0]
/// With numbered data: TPCI = 0x40 | (seqno << 2), then APCI = 02 80
///
/// Actually looking at the XML more carefully:
/// "BC #EDI #BDUT 66 42 C2 03 #MEM_ACCESSIBLE_START AA BB"
///   - 66 = length byte (6 data bytes after: TPCI, APCI_hi, count, addr_hi, addr_lo, data...)
///   - 42 = TPCI (0x40 = numbered data, seqno=0) + APCI_hi (0x02 = part of UserMemory APCI)
///   - C2 = APCI_lo (UserMemory_Write = 0x2C2)
///   - 03 = count
///   - Then address and data
///
/// Actually the TPCI byte structure is:
/// - Bits 7-6: Type (00=UCD, 01=NCD, 10=T_ACK, 11=T_Connect/Disconnect)
/// - For NCD (01): bits 5-2 are sequence number, bits 1-0 are upper APCI
/// - So 0x42 = 0100 0010 = NCD, seqno=0, APCI[9:8]=10
/// - Combined with C2: APCI = 0x2C2 = A_UserMemory_Write
fn build_user_memory_write(
    buffer: Buffer<'static>,
    src: IndividualAddress,
    dst: IndividualAddress,
    seqno: u8,
    mem_addr: u16,
    count: u8,
    data: &[u8],
) -> RequestMessage<Buffer<'static>> {
    // TPCI for numbered data packet with sequence number
    // 0x40 = NCD frame, seqno in bits 5-2, APCI[9:8] in bits 1-0
    // A_UserMemory_Write = 0x2C2, so APCI[9:8] = 0x02
    let tpci = 0x40 | ((seqno & 0x0F) << 2) | 0x02; // NCD + seqno + APCI_hi
    let apci_lo = 0xC2; // A_UserMemory_Write lower bits

    let mut payload = vec![tpci, apci_lo, count, (mem_addr >> 8) as u8, mem_addr as u8];
    payload.extend_from_slice(data);

    // Calculate length byte: payload length (without CTRL and addresses)
    // In the wire format, length byte encodes: 6 + NPDU length - 1 = 6 + (payload.len()) - 1
    // Actually for SFF: length field = (AT/HC/EFF byte to end) which is 1 + payload.len()
    // The 0x60 byte is AT/HC/EFF, then payload
    // Wait, let me look at the examples again...
    // "BC #EDI #BDUT 66 42 C2 03 #MEM_ACCESSIBLE_START AA BB"
    // BC = CTRL, EDI = src, BDUT = dst, then 66 is... the AT/HC/EFF + length?
    // Actually in internal format it's: CTRL, SRC_HI, SRC_LO, DST_HI, DST_LO, AT_HC_EFF, TPCI, APCI, ...
    // So 66 is AT/HC/EFF with length nibble
    // AT=0 (individual), HC=6, length nibble = 6 (meaning 6+1=7 bytes of NPDU)
    // Hmm, but that seems off. Let me check the actual format.

    // Looking at usb_test.rs line 151: buffer[5] = 0xE0; // AT=1 (group), HC=6
    // And that's for a short message. The format is:
    // [0] = CTRL
    // [1-2] = SRC
    // [3-4] = DST
    // [5] = AT(7) | HC(6-4) | EFF(3-0) where EFF encodes routing/length info
    // [6+] = TPCI, APCI, data

    // For SFF, the length field (NPDU length) is in byte 5 lower nibble
    // AT = 0 for individual addressing
    // HC = 6 (hop count)
    // EFF lower nibble = NPDU length - 1
    // NPDU = TPCI + APCI + data = payload.len()

    let npdu_len = payload.len();
    let at_hc_eff = 0x60 | ((npdu_len - 1) as u8 & 0x0F); // AT=0, HC=6, length=npdu_len-1

    build_raw_frame(buffer, 0xBC, src, dst, at_hc_eff, &payload)
}

/// Build a Memory_Read request
fn build_user_memory_read(
    buffer: Buffer<'static>,
    src: IndividualAddress,
    dst: IndividualAddress,
    seqno: u8,
    mem_addr: u16,
    count: u8,
) -> RequestMessage<Buffer<'static>> {
    // A_UserMemory_Read = 0x2C0
    let tpci = 0x40 | ((seqno & 0x0F) << 2) | 0x02; // NCD + seqno + APCI_hi
    let apci_lo = 0xC0; // A_UserMemory_Read lower bits

    let payload = vec![tpci, apci_lo, count, (mem_addr >> 8) as u8, mem_addr as u8];
    let npdu_len = payload.len();
    let at_hc_eff = 0x60 | ((npdu_len - 1) as u8 & 0x0F);

    build_raw_frame(buffer, 0xBC, src, dst, at_hc_eff, &payload)
}

async fn wait_for_response(received: &RefCell<Vec<Vec<u8>>>, timeout_ms: u64) -> Option<Vec<u8>> {
    let start = embassy_time::Instant::now();
    loop {
        {
            let mut r = received.borrow_mut();
            if !r.is_empty() {
                return Some(r.remove(0));
            }
        }
        if start.elapsed().as_millis() > timeout_ms {
            return None;
        }
        Timer::after(Duration::from_millis(10)).await;
    }
}

async fn clear_received(received: &RefCell<Vec<Vec<u8>>>) {
    received.borrow_mut().clear();
}

async fn run_seqno_test(
    bm: &'static RefCell<zweidraehte::messages::buffers::DynBufferManager<'static>>,
    link_sender: embassy_sync::channel::DynamicSender<'static, LayerOp<Buffer<'static>>>,
    received: &'static RefCell<Vec<Vec<u8>>>,
) {
    println!("\n=== Sequence Number Behavior Test ===");
    println!("Testing sequence number handling for malformed memory writes");
    println!("Tester: {}.{}.{}", TESTER_ADDR.area(), TESTER_ADDR.line(), TESTER_ADDR.device());
    println!("DUT:    {}.{}.{}", DUT_ADDR.area(), DUT_ADDR.line(), DUT_ADDR.device());
    println!("Memory: 0x{:04X}", MEM_ADDR);
    println!();

    // Step 1: T_Connect
    println!("--- Step 1: T_Connect ---");
    {
        let buffer = bm.borrow().alloc().await;
        let msg = build_t_connect(buffer, TESTER_ADDR, DUT_ADDR);
        print_frame("TX", msg.buf());
        let _conf = link_sender.request(msg).await;
    }
    Timer::after(Duration::from_millis(300)).await;
    clear_received(&received).await;

    // Step 2: Memory Write with count > data (malformed)
    println!("\n--- Step 2: Memory Write with count > data (malformed) ---");
    println!("Sending count=3 but only 2 data bytes - should be rejected");
    {
        let buffer = bm.borrow().alloc().await;
        // count=3, but only 2 bytes of data (AA BB)
        let msg = build_user_memory_write(buffer, TESTER_ADDR, DUT_ADDR, 0, MEM_ADDR, 3, &[0xAA, 0xBB]);
        print_frame("TX", msg.buf());
        let _conf = link_sender.request(msg).await;
    }

    // Wait for T_ACK
    if let Some(resp) = wait_for_response(&received, 1000).await {
        let tpci = resp.get(6).copied().unwrap_or(0);
        let ack_seqno = (tpci >> 2) & 0x0F;
        println!("  -> Got response, ACK seqno = {}", ack_seqno);
    } else {
        println!("  -> No response!");
    }
    Timer::after(Duration::from_millis(200)).await;

    // Step 3: Memory Write with count < data (malformed)
    println!("\n--- Step 3: Memory Write with count < data (malformed) ---");
    println!("Sending count=2 but 3 data bytes - should be rejected");
    println!("Question: Does seqno increment or stay at 0?");
    {
        let buffer = bm.borrow().alloc().await;
        // Try BOTH seqno=0 (as in XML) and seqno=1 (normal increment)
        // First try seqno=0 to see if device accepts it
        let msg = build_user_memory_write(buffer, TESTER_ADDR, DUT_ADDR, 0, MEM_ADDR, 2, &[0x01, 0x02, 0x03]);
        print_frame("TX (seqno=0)", msg.buf());
        let _conf = link_sender.request(msg).await;
    }

    if let Some(resp) = wait_for_response(&received, 1000).await {
        let tpci = resp.get(6).copied().unwrap_or(0);
        if (tpci & 0xC0) == 0xC0 {
            // Control frame (ACK/NAK)
            let ack_seqno = (tpci >> 2) & 0x0F;
            let is_ack = (tpci & 0x03) == 0x02;
            println!("  -> Got {}, seqno = {}", if is_ack { "ACK" } else { "NAK" }, ack_seqno);
            if is_ack {
                println!("  ** Device ACCEPTED seqno=0 for second write! **");
            }
        }
    } else {
        println!("  -> No response to seqno=0, trying seqno=1...");

        {
            let buffer = bm.borrow().alloc().await;
            let msg = build_user_memory_write(buffer, TESTER_ADDR, DUT_ADDR, 1, MEM_ADDR, 2, &[0x01, 0x02, 0x03]);
            print_frame("TX (seqno=1)", msg.buf());
            let _conf = link_sender.request(msg).await;
        }

        if let Some(resp) = wait_for_response(&received, 1000).await {
            let tpci = resp.get(6).copied().unwrap_or(0);
            if (tpci & 0xC0) == 0xC0 {
                let ack_seqno = (tpci >> 2) & 0x0F;
                let is_ack = (tpci & 0x03) == 0x02;
                println!("  -> Got {}, seqno = {}", if is_ack { "ACK" } else { "NAK" }, ack_seqno);
                if is_ack {
                    println!("  ** Device requires seqno=1 for second write **");
                }
            }
        } else {
            println!("  -> No response to seqno=1 either!");
        }
    }
    Timer::after(Duration::from_millis(200)).await;

    // Step 4: Read memory to verify nothing changed
    println!("\n--- Step 4: Read memory to verify data unchanged ---");
    {
        let buffer = bm.borrow().alloc().await;
        // Use seqno that matches expected state
        let msg = build_user_memory_read(buffer, TESTER_ADDR, DUT_ADDR, 1, MEM_ADDR, 3);
        print_frame("TX", msg.buf());
        let _conf = link_sender.request(msg).await;
    }

    // Should get ACK then Response
    while let Some(resp) = wait_for_response(&received, 1000).await {
        let tpci = resp.get(6).copied().unwrap_or(0);
        if (tpci & 0xC0) == 0xC0 {
            println!("  -> Got ACK");
        } else if (tpci & 0xC0) == 0x40 {
            // Data frame - this is the response
            let resp_seqno = (tpci >> 2) & 0x0F;
            println!("  -> Got Memory Response, seqno = {}", resp_seqno);
            if resp.len() > 11 {
                println!("     Data: {:02X?}", &resp[11..]);
            }
            break;
        }
    }

    // Step 5: ACK the response
    {
        let buffer = bm.borrow().alloc().await;
        let msg = build_t_ack(buffer, TESTER_ADDR, DUT_ADDR, 0);
        print_frame("TX", msg.buf());
        let _conf = link_sender.request(msg).await;
    }
    Timer::after(Duration::from_millis(100)).await;

    // Step 6: Disconnect
    println!("\n--- Step 6: Disconnect ---");
    {
        let buffer = bm.borrow().alloc().await;
        let msg = build_t_disconnect(buffer, TESTER_ADDR, DUT_ADDR);
        print_frame("TX", msg.buf());
        let _conf = link_sender.request(msg).await;
    }
    Timer::after(Duration::from_millis(200)).await;

    println!("\n=== Test Complete ===");
    println!("\nPress 'q' to quit, or any other key to run the test again...");
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    println!("=== KNX Sequence Number Behavior Test ===\n");

    // List available USB devices
    println!("Searching for KNX USB interfaces...");
    match zweidraehte::layers::linklayers::usb::list_devices().await {
        Ok(devices) => {
            if devices.is_empty() {
                println!("  No KNX USB interfaces found!");
                return;
            }
            for (vid, pid, name) in &devices {
                println!("  Found: {} (VID:PID = {:04X}:{:04X})", name, vid, pid);
            }
        }
        Err(e) => {
            println!("  Error enumerating devices: {:?}", e);
            return;
        }
    }
    println!();

    // Allocate resources
    let buffers: [[u8; 128]; 16] = [[0u8; 128]; 16];
    let buffers = Box::leak(Box::new(buffers));
    let buffer_manager = unsafe { BufferManager::new(buffers) };
    let buffer_manager = Box::leak(Box::new(buffer_manager));
    let bm = Box::leak(Box::new(RefCell::new(buffer_manager.dyn_buffer_manager())));

    let received: &'static RefCell<Vec<Vec<u8>>> = Box::leak(Box::new(RefCell::new(Vec::new())));

    // Create channels
    let network_channel = Box::leak(Box::new(Channel::<NoopRawMutex, LayerOp<Buffer<'static>>, 32>::new()));
    let network_sender = network_channel.sender().into();
    let network_receiver = network_channel.receiver();

    let link_channel = Box::leak(Box::new(Channel::<NoopRawMutex, LayerOp<Buffer<'static>>, 32>::new()));
    let link_sender: embassy_sync::channel::DynamicSender<'_, LayerOp<Buffer<'static>>> = link_channel.sender().into();
    let link_receiver = link_channel.receiver();

    // Create USB link layer with our tester address
    let ll_builder = UsbLinkLayerBuilder::new().with_individual_address(TESTER_ADDR);
    let ll_resources = Box::leak(Box::new(UsbLinkLayerResources::new()));
    let context = Box::leak(Box::new(SimpleContext { buffer_manager: bm }));

    // Spawn network layer
    let network = TestNetworkLayer { receiver: network_receiver, received };
    spawner.spawn(run_network(network)).unwrap();

    // Spawn link layer
    spawner.spawn(run_usb_link_layer(ll_builder, ll_resources, context, network_sender, link_receiver)).unwrap();

    // Wait for link layer to initialize
    Timer::after(Duration::from_millis(500)).await;

    // Main loop
    loop {
        run_seqno_test(bm, link_sender.clone(), received).await;

        // Wait for user input
        loop {
            if let Some(key) = keyboard::poll_key() {
                match key {
                    'q' | 'Q' => {
                        println!("\nQuitting...");
                        std::process::exit(0);
                    }
                    _ => break, // Run test again
                }
            }
            Timer::after(Duration::from_millis(10)).await;
        }
    }
}

#[embassy_executor::task]
async fn run_usb_link_layer(
    builder: UsbLinkLayerBuilder,
    resources: &'static mut UsbLinkLayerResources,
    context: &'static SimpleContext,
    network_sender: embassy_sync::channel::DynamicSender<'static, LayerOp<Buffer<'static>>>,
    link_receiver: embassy_sync::channel::Receiver<'static, NoopRawMutex, LayerOp<Buffer<'static>>, 32>,
) {
    builder.build_and_run(resources, context, network_sender, link_receiver).await;
}
