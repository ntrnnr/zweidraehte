use std::cell::RefCell;

use embassy_executor::Spawner;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
use embassy_time::{Duration, Ticker};
use env_logger::Env;

use platform::{
    AsyncSerialPort,
    serialport::{Options, Parity},
};

use zweidraehte::{
    address::IndividualAddress,
    context::KnxAddressContext,
    layers::{ActorRequest, Layer, LayerOp, linklayers::tpuart::TpUartLinkLayer},
    messages::{
        buffers::{Buffer, BufferManager},
        builder::RequestMessage,
        knx::{KnxMessageBuffer, ServiceType},
    },
};

/// Fixed address context for the test binary.
struct StaticAddress(IndividualAddress);

impl KnxAddressContext for StaticAddress {
    fn individual_address(&self) -> IndividualAddress {
        self.0
    }
}

// Fake network layer that just prints received messages
struct FakeNetworkLayer {
    receiver: embassy_sync::channel::Receiver<
        'static,
        NoopRawMutex,
        LayerOp<Buffer<'static>>,
        32,
    >,
}

impl FakeNetworkLayer {
    async fn process(&mut self) -> ! {
        loop {
            let layer_op = self.receiver.receive().await;
            match layer_op {
                LayerOp::Indication(msg) => {
                    println!("RX: {:x?}", msg.buf());
                }
                LayerOp::Request { message: _msg, response_tx: _response_tx } => {
                    // Network layer doesn't typically receive requests from link layer
                    println!("Unexpected request from link layer");
                }
            }
        }
    }
}

#[embassy_executor::task]
async fn run_fake_network(mut fake_network: FakeNetworkLayer) {
    fake_network.process().await;
}

#[embassy_executor::task]
async fn run_link_layer(
    mut ll: TpUartLinkLayer<'static, AsyncSerialPort>,
    link_receiver: embassy_sync::channel::Receiver<
        'static,
        NoopRawMutex,
        LayerOp<Buffer<'static>>,
        32,
    >,
) {
    ll.process(link_receiver).await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

    let buffers: [[u8; 128]; 4] = [[0u8; 128]; 4];
    let buffers = Box::leak(Box::new(buffers));
    let buffer_manager = unsafe { BufferManager::new(buffers) };
    let buffer_manager = Box::leak(Box::new(buffer_manager));
    let bm = Box::leak(Box::new(RefCell::new(buffer_manager.dyn_buffer_manager())));

    // Create channels for communication between link layer and fake network layer
    let network_channel =
        Box::leak(Box::new(Channel::<NoopRawMutex, LayerOp<Buffer<'static>>, 32>::new()));
    let network_sender = network_channel.sender().into();
    let network_receiver = network_channel.receiver();

    // Create channel for sending requests to the link layer
    let link_channel =
        Box::leak(Box::new(Channel::<NoopRawMutex, LayerOp<Buffer<'static>>, 32>::new()));
    let link_sender: embassy_sync::channel::DynamicSender<'_, LayerOp<Buffer<'static>>> =
        link_channel.sender().into();
    let link_receiver = link_channel.receiver();

    let s = AsyncSerialPort::open(Options { baud_rate: 19200, parity: Parity::Even, ..Default::default() }).unwrap();
    let addr_ctx: &'static StaticAddress =
        Box::leak(Box::new(StaticAddress(IndividualAddress::new(15, 15, 1))));
    let ll = TpUartLinkLayer::new(s, bm, network_sender, addr_ctx);

    // Spawn the fake network layer
    let fake_network = FakeNetworkLayer { receiver: network_receiver };
    spawner.spawn(run_fake_network(fake_network)).unwrap();

    // Spawn the link layer
    spawner.spawn(run_link_layer(ll, link_receiver)).unwrap();

    // Main test loop - send a test message every second
    let mut timer = Ticker::every(Duration::from_secs(1));

    loop {
        timer.next().await;

        let test_buffer = bm.borrow().alloc_from_slice(&[0xbc, 0x10, 0x64, 0x18, 0x00, 0xe1, 0x00, 0x80]).await;
        let test_msg = KnxMessageBuffer::new(test_buffer, ServiceType::L_Data_Req);

        println!("Transmitting test message: {:x?}", test_msg.buf());

        // Send the request to the link layer and wait for confirmation
        let confirmation = link_sender.request(RequestMessage::request(test_msg)).await;
        println!("TX confirmation: {:x?}", confirmation.buf());
    }
}
