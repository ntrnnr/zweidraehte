//! USB KNX Interface test utility
//!
//! Connects to a KNX USB interface and monitors traffic using the stack's USB link layer.
//! Press '1' to send GroupValueWrite(1) to 2/0/3
//! Press '0' to send GroupValueWrite(0) to 2/0/3

mod keyboard;

use std::cell::RefCell;
use std::io::Write as IoWrite;

use embassy_executor::Spawner;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
use embassy_time::{Duration, Timer};
use env_logger::Env;

use zweidraehte::{
    address::{GroupAddress, IndividualAddress},
    context::BufferManagerContext,
    layers::{
        ActorRequest, LayerOp, LinkLayerBuilder,
        linklayers::usb::{UsbLinkLayerBuilder, UsbLinkLayerResources},
    },
    messages::buffers::{Buffer, BufferManager, MessageBuffer},
    messages::builder::RequestMessage,
    messages::knx::{KnxMessageBuffer, ServiceType},
};

/// Group address 2/0/3
const GROUP_ADDR: GroupAddress = GroupAddress::from_three_level(2, 0, 3);

// Fake network layer that just prints received messages
struct FakeNetworkLayer {
    receiver: embassy_sync::channel::Receiver<'static, NoopRawMutex, LayerOp<Buffer<'static>>, 32>,
}

impl FakeNetworkLayer {
    async fn process(&mut self) -> ! {
        loop {
            let layer_op = self.receiver.receive().await;
            match layer_op {
                LayerOp::Indication(msg) => {
                    let buf = msg.buf();
                    print_frame(buf);
                }
                LayerOp::Request { message: _msg, response_tx: _response_tx } => {
                    // Network layer doesn't typically receive requests from link layer
                    println!("Unexpected request from link layer");
                }
            }
        }
    }
}

/// Pretty print a KNX frame (internal format)
///
/// Internal KNX format:
/// - Byte 0: CTRL
/// - Byte 1-2: Source address
/// - Byte 3-4: Destination address
/// - Byte 5: AT/HC/EFF (AT=bit 7, HC=bits 6-4)
/// - Byte 6-7: TPCI/APCI
/// - Byte 8+: Data
fn print_frame(buf: &[u8]) {
    if buf.len() < 8 {
        println!("RX: {:02X?} (too short)", buf);
        return;
    }

    let src = u16::from_be_bytes([buf[1], buf[2]]);
    let dst = u16::from_be_bytes([buf[3], buf[4]]);
    let npdu = buf[5];
    let is_group = (npdu & 0x80) != 0; // AT bit

    let src_area = (src >> 12) & 0xF;
    let src_line = (src >> 8) & 0xF;
    let src_dev = src & 0xFF;

    let dst_str = if is_group {
        let main = (dst >> 11) & 0x1F;
        let middle = (dst >> 8) & 0x07;
        let sub = dst & 0xFF;
        format!("{}/{}/{}", main, middle, sub)
    } else {
        let area = (dst >> 12) & 0xF;
        let line = (dst >> 8) & 0xF;
        let dev = dst & 0xFF;
        format!("{}.{}.{}", area, line, dev)
    };

    // Get APCI from bytes 6-7
    let tpci_apci = u16::from_be_bytes([buf[6], buf[7]]);
    let apci = (tpci_apci & 0x03FF) >> 6; // Upper 4 bits of APCI

    let apci_str = match apci {
        0 => "GroupValueRead".to_string(),
        1 => "GroupValueResp".to_string(),
        2 => "GroupValueWrite".to_string(),
        _ => format!("APCI:{:03X}", tpci_apci & 0x03FF),
    };

    // Data bytes (short APCI data in lower 6 bits of byte 7, or extended data in byte 8+)
    let short_data = buf[7] & 0x3F;
    let data = if buf.len() > 8 { &buf[8..] } else { &[] };

    println!(
        "L_Data.ind {}.{}.{} -> {} {} data={:02X} {:02X?}",
        src_area, src_line, src_dev, dst_str, apci_str, short_data, data
    );
}

#[embassy_executor::task]
async fn run_fake_network(mut fake_network: FakeNetworkLayer) {
    fake_network.process().await;
}

// Simple context that just provides a buffer manager
struct SimpleContext {
    buffer_manager: &'static RefCell<zweidraehte::messages::buffers::DynBufferManager<'static>>,
}

impl BufferManagerContext for SimpleContext {
    fn buffer_manager(&self) -> &RefCell<zweidraehte::messages::buffers::DynBufferManager<'static>> {
        self.buffer_manager
    }

    fn max_apdu_length(&self) -> u16 {
        zweidraehte::config::MAX_APDU_LENGTH_EXTENDED
    }

    fn set_max_apdu_length(&self, _length: u16) {
        // No-op for this simple test context
    }
}

/// Build a GroupValueWrite request message for a 1-bit value
///
/// Hardcodes the internal KNX frame format directly since we're bypassing the full stack.
fn build_group_value_write(
    mut buffer: Buffer<'static>,
    group_addr: GroupAddress,
    value: bool,
) -> RequestMessage<Buffer<'static>> {
    // Internal KNX message format:
    // Byte 0: CTRL - FT(7) | -(6) | R(5) | SB(4) | PR(3-2) | A(1) | C(0)
    // Byte 1-2: Source address (0x0000, interface fills this in)
    // Byte 3-4: Destination address (group address)
    // Byte 5: AT/HC/EFF - AT(7) | HC(6-4) | EFF(3-0)
    // Byte 6-7: TPCI/APCI (GroupValueWrite = 0x00 0x80, with value in lower bits)
    let dest = group_addr.as_bytes();
    let apci_data = if value { 0x81 } else { 0x80 }; // GroupValueWrite with 1-bit value

    buffer.resize(8, 0);
    buffer[0] = 0xBC; // CTRL: standard frame, no repeat (first transmission), low priority
    buffer[1] = 0x00; // Source high (interface fills in)
    buffer[2] = 0x00; // Source low
    buffer[3] = dest[0]; // Dest high
    buffer[4] = dest[1]; // Dest low
    buffer[5] = 0xE0; // AT=1 (group), HC=6
    buffer[6] = 0x00; // TPCI/APCI high
    buffer[7] = apci_data; // APCI low + data

    let msg = KnxMessageBuffer::new(buffer, ServiceType::L_Data_Req);
    RequestMessage::request(msg)
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    println!("=== KNX USB Interface Test ===\n");

    // List available USB devices first
    println!("Searching for KNX USB interfaces...");
    match zweidraehte::layers::linklayers::usb::list_devices().await {
        Ok(devices) => {
            if devices.is_empty() {
                println!("  No KNX USB interfaces found!");
                println!("  Make sure your device is connected and you have permissions.");
                println!("  Known devices: ABB USB/S1.2 (147B:5120)");
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

    // Allocate buffers
    let buffers: [[u8; 128]; 8] = [[0u8; 128]; 8];
    let buffers = Box::leak(Box::new(buffers));
    let buffer_manager = unsafe { BufferManager::new(buffers) };
    let buffer_manager = Box::leak(Box::new(buffer_manager));
    let bm = Box::leak(Box::new(RefCell::new(buffer_manager.dyn_buffer_manager())));

    // Create channels for communication between link layer and fake network layer
    let network_channel = Box::leak(Box::new(Channel::<NoopRawMutex, LayerOp<Buffer<'static>>, 32>::new()));
    let network_sender = network_channel.sender().into();
    let network_receiver = network_channel.receiver();

    // Create channel for sending requests to the link layer
    let link_channel = Box::leak(Box::new(Channel::<NoopRawMutex, LayerOp<Buffer<'static>>, 32>::new()));
    let link_sender: embassy_sync::channel::DynamicSender<'_, LayerOp<Buffer<'static>>> = link_channel.sender().into();
    let link_receiver = link_channel.receiver();

    // Create USB link layer builder with individual address 1.0.253
    let ll_builder = UsbLinkLayerBuilder::new().with_individual_address(IndividualAddress::new(1, 0, 253));

    // Create link layer resources
    let ll_resources = Box::leak(Box::new(UsbLinkLayerResources::new()));

    // Create context
    let context = Box::leak(Box::new(SimpleContext { buffer_manager: bm }));

    // Spawn the fake network layer
    let fake_network = FakeNetworkLayer { receiver: network_receiver };
    spawner.spawn(run_fake_network(fake_network)).unwrap();

    // Spawn the link layer using the builder
    spawner.spawn(run_usb_link_layer(ll_builder, ll_resources, context, network_sender, link_receiver)).unwrap();

    // Wait for link layer to initialize
    Timer::after(Duration::from_millis(500)).await;

    println!("Monitoring KNX traffic...");
    println!("Press '1' to send GroupValueWrite(1) to 2/0/3");
    println!("Press '0' to send GroupValueWrite(0) to 2/0/3");
    println!("Press 'q' to quit\n");

    // Main loop - poll for keyboard input
    loop {
        // Poll for key press (non-blocking, 10ms timeout)
        if let Some(key) = keyboard::poll_key() {
            match key {
                '1' => {
                    print!("Sending GroupValueWrite(1) to 2/0/3... ");
                    std::io::stdout().flush().ok();

                    let buffer = bm.borrow().alloc().await;
                    let msg = build_group_value_write(buffer, GROUP_ADDR, true);

                    let confirmation = link_sender.request(msg).await;
                    println!("Confirmation: {:02X?}", confirmation.buf());
                }
                '0' => {
                    print!("Sending GroupValueWrite(0) to 2/0/3... ");
                    std::io::stdout().flush().ok();

                    let buffer = bm.borrow().alloc().await;
                    let msg = build_group_value_write(buffer, GROUP_ADDR, false);

                    let confirmation = link_sender.request(msg).await;
                    println!("Confirmation: {:02X?}", confirmation.buf());
                }
                'q' | 'Q' => {
                    println!("\nQuitting...");
                    std::process::exit(0);
                }
                _ => {}
            }
        }

        // Small yield to allow other tasks to run
        Timer::after(Duration::from_millis(1)).await;
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
