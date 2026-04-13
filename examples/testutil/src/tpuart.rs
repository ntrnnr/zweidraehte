use embassy_executor::Spawner;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
use embassy_time::{Duration, Ticker};
use env_logger::Env;

use zweidraehte_platform::{
    AsyncSerialPort, AsyncSerialPortRx, AsyncSerialPortTx,
    serialport::{Options, Parity},
};

use zweidraehte_device::{
    layers::linklayers::tpuart::TpUartLinkLayer};
use zweidraehte_proto::messages::{
        buffers::{Buffer, BufferManager},
        builder::{ConfirmationMessage, IndicationMessage, RequestMessage},
        knx::{KnxMessageBuffer, ServiceType},
    };

// Fake network layer that just prints received indications
struct FakeNetworkLayer {
    ind_rx: embassy_sync::channel::Receiver<
        'static,
        NoopRawMutex,
        IndicationMessage<Buffer<'static>>,
        32,
    >,
}

impl FakeNetworkLayer {
    async fn process(&mut self) -> ! {
        loop {
            let msg = self.ind_rx.receive().await;
            println!("RX: {:x?}", msg.buf());
        }
    }
}

#[embassy_executor::task]
async fn run_fake_network(mut fake_network: FakeNetworkLayer) {
    fake_network.process().await;
}

#[embassy_executor::task]
async fn run_link_layer(
    mut ll: TpUartLinkLayer<'static, AsyncSerialPortTx, AsyncSerialPortRx>,
    req_rx: embassy_sync::channel::Receiver<
        'static,
        NoopRawMutex,
        RequestMessage<Buffer<'static>>,
        32,
    >,
) {
    ll.run(req_rx).await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

    let buffers: [[u8; 128]; 4] = [[0u8; 128]; 4];
    let buffers = Box::leak(Box::new(buffers));
    let buffer_manager = unsafe { BufferManager::new(buffers) };
    let buffer_manager = Box::leak(Box::new(buffer_manager));
    let bm = Box::leak(Box::new(buffer_manager.dyn_buffer_manager()));
    let ctx: &_ = Box::leak(Box::new(testutil::util::MockContext::new(*bm)));

    // Indication channel: link layer -> fake network layer
    let ind_channel =
        Box::leak(Box::new(Channel::<NoopRawMutex, IndicationMessage<Buffer<'static>>, 32>::new()));
    let ind_tx = ind_channel.sender().into();
    let ind_rx = ind_channel.receiver();

    // Confirmation channel: link layer -> main loop
    let conf_channel =
        Box::leak(Box::new(Channel::<NoopRawMutex, ConfirmationMessage<Buffer<'static>>, 32>::new()));
    let conf_tx = conf_channel.sender().into();
    let conf_rx = conf_channel.receiver();

    // Request channel: main loop -> link layer
    let req_channel =
        Box::leak(Box::new(Channel::<NoopRawMutex, RequestMessage<Buffer<'static>>, 32>::new()));
    let req_tx = req_channel.sender();
    let req_rx = req_channel.receiver();

    let s = AsyncSerialPort::open(Options { baud_rate: 19200, parity: Parity::Even, ..Default::default() }).unwrap();
    let (tx, rx) = s.split().unwrap();
    // NoAddressChecker — this test binary doesn't ACK any incoming frames.
    // TODO: Wire up a DeviceAddressChecker once this test needs to receive.
    let ll = TpUartLinkLayer::new(tx, rx, ctx, ind_tx, conf_tx);

    // Spawn the fake network layer
    let fake_network = FakeNetworkLayer { ind_rx };
    spawner.spawn(run_fake_network(fake_network)).unwrap();

    // Spawn the link layer
    spawner.spawn(run_link_layer(ll, req_rx)).unwrap();

    // Main test loop - send a test message every second
    let mut timer = Ticker::every(Duration::from_secs(1));

    loop {
        timer.next().await;

        let test_buffer = bm.alloc_from_slice(&[0xbc, 0x10, 0x64, 0x18, 0x00, 0xe1, 0x00, 0x80]).await;
        let test_msg = KnxMessageBuffer::new(test_buffer, ServiceType::L_Data_Req);

        println!("Transmitting test message: {:x?}", test_msg.buf());

        // Send the request to the link layer and wait for confirmation
        req_tx.send(RequestMessage::request(test_msg)).await;
        let confirmation = conf_rx.receive().await;
        println!("TX confirmation: {:x?}", confirmation.buf());
    }
}
