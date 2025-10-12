use std::cell::RefCell;

use embassy_executor::Spawner;
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicSender, Receiver},
};
use embassy_time::{Duration, Ticker};
use env_logger::Env;

use zweidraehte::{
    layers::{
        ActorRequest, Layer, LayerOp, LinkLayerBuilder,
        linklayers::knxip::{EndpointType, KnxNetIpBuilder, servers},
    },
    messages::{
        buffers::{Buffer, BufferManager},
        knx::{KnxMessageBuffer, ServiceType},
    },
    test_util::MockContext,
};

// Network layer that just prints received messages
struct FakeNetworkLayer {
    receiver: Receiver<'static, NoopRawMutex, LayerOp<KnxMessageBuffer<Buffer<'static>>>, 32>,
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

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

    // Setup buffer manager
    let buffers: [[u8; 128]; 4] = [[0u8; 128]; 4];
    let buffers = Box::leak(Box::new(buffers));
    let buffer_manager = unsafe { BufferManager::new(buffers) };
    let buffer_manager = Box::leak(Box::new(buffer_manager));
    let bm = Box::leak(Box::new(RefCell::new(buffer_manager.dyn_buffer_manager())));

    // Create mock context for testing
    let context = Box::leak(Box::new(MockContext::new(bm.borrow().clone())));

    // Create channels for communication between link layer and network layer
    let network_channel =
        Box::leak(Box::new(Channel::<NoopRawMutex, LayerOp<KnxMessageBuffer<Buffer<'static>>>, 32>::new()));
    let network_sender: DynamicSender<'_, LayerOp<KnxMessageBuffer<Buffer<'static>>>> = network_channel.sender().into();
    let network_receiver = network_channel.receiver();

    // Create channel for sending requests to the link layer
    let link_channel =
        Box::leak(Box::new(Channel::<NoopRawMutex, LayerOp<KnxMessageBuffer<Buffer<'static>>>, 32>::new()));
    let link_sender: DynamicSender<'_, LayerOp<KnxMessageBuffer<Buffer<'static>>>> = link_channel.sender().into();
    let link_receiver = link_channel.receiver();

    // Create the KNXnet/IP link layer builder and use the LinkLayerBuilder trait
    let local_hpai = EndpointType::new_udp_any(3671);
    let ds = servers::DiscoveryServer::new(local_hpai);
    let rs = servers::RoutingServer::new(local_hpai);
    let cs = servers::RemoteConfigurationServer::new(local_hpai);
    let kb = KnxNetIpBuilder::new("knxbridge"); // Bind to knxbridge interface
    let kb = kb.add_server(ds).add_server(rs).add_server(cs);

    println!("Starting KNXnet/IP link layer with 3 servers and 10 registrations");

    // Spawn the network layer
    let fake_network = FakeNetworkLayer { receiver: network_receiver };
    spawner.spawn(run_fake_network(fake_network)).unwrap();

    // Build and run the link layer using the LinkLayerBuilder trait
    let link_layer_future = kb.build_and_run(&context, network_sender, link_receiver);

    let test_loop = async {
        // Main test loop - send a test message every second
        let mut timer = Ticker::every(Duration::from_secs(1));

        loop {
            timer.next().await;

            let test_buffer = bm.borrow().alloc_from_slice(&[0xbc, 0x10, 0x64, 0x18, 0x00, 0xe1, 0x00, 0x80]).await;
            let test_msg = KnxMessageBuffer::new(test_buffer, ServiceType::L_Data_Req);

            println!("Transmitting test message: {:x?}", test_msg.buf());

            // Send the request to the link layer and wait for confirmation
            let confirmation = link_sender.request(test_msg).await;
            println!("TX confirmation: {:x?}", confirmation.buf());
        }
    };

    // Run both concurrently (link layer runs forever, test loop runs forever)
    embassy_futures::select::select(link_layer_future, test_loop).await;
}
