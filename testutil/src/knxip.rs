//! KNX/IP Link Layer Test Utility
//!
//! This test utility demonstrates a KNX/IP setup with Discovery and Routing Servers.
//! It creates a KNX/IP link layer that:
//! - Listens on the KNX multicast address (224.0.23.12:3671) for SearchRequest packets
//! - Listens on unicast (0.0.0.0:3671) for DescriptionRequest packets
//! - Listens on KNX multicast for RoutingIndication, RoutingBusy, and RoutingLostMessage
//! - Responds with device information to discovery queries
//! - Handles KNX routing with congestion control
//!
//! You can test this with the ETS software or knxd tools:
//! - `knxtool search` to trigger a SearchRequest
//! - The server will respond with device information

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
        LayerOp, LinkLayerBuilder,
        linklayers::knxip::KnxNetIpBuilder,
    },
    messages::{
        buffers::{Buffer, BufferManager},
        knxip::substructs::{DeviceInformation, HPAI},
    },
};

use testutil::util::MockContext;

// Network layer that just prints received messages
struct FakeNetworkLayer {
    receiver: Receiver<'static, NoopRawMutex, LayerOp<Buffer<'static>>, 32>,
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
        Box::leak(Box::new(Channel::<NoopRawMutex, LayerOp<Buffer<'static>>, 32>::new()));
    let network_sender: DynamicSender<'_, LayerOp<Buffer<'static>>> = network_channel.sender().into();
    let network_receiver = network_channel.receiver();

    // Create channel for sending requests to the link layer
    let link_channel =
        Box::leak(Box::new(Channel::<NoopRawMutex, LayerOp<Buffer<'static>>, 32>::new()));
    let _link_sender: DynamicSender<'_, LayerOp<Buffer<'static>>> = link_channel.sender().into();
    let link_receiver = link_channel.receiver();

    // Create the KNXnet/IP link layer builder
    use platform::address::EthernetAddress;
    use zweidraehte::address::IndividualAddress;
    use zweidraehte::messages::knxip::substructs::{DeviceStatus, KNXMedium};

    let control_endpoint = HPAI::Ipv4Udp { addr: "192.168.106.6".parse().unwrap(), port: 3671 };

    // Set device info on the mock context — discovery responses will
    // build DeviceInformation on demand from this.
    context.set_device_info(DeviceInformation {
        medium: KNXMedium::KNXIP,
        device_status: DeviceStatus::None,
        individual_address: IndividualAddress::new(1, 1, 0),
        project_installation_identifier: 0x1234,
        knx_serial_number: [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78],
        routing_multicast_address: core::net::Ipv4Addr::new(224, 0, 23, 12),
        mac_address: EthernetAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        friendly_name: *b"KNX Test Device\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    });

    let interface_addr = platform::get_interface_address("knxdevbridgeif").expect("Failed to get interface address");
    let kb =
        KnxNetIpBuilder::<platform::LinuxIpTransport, 2>::new("knxdevbridgeif", interface_addr, control_endpoint)
            .enable_routing_server();

    println!("Starting KNXnet/IP link layer with Discovery and Routing Servers");
    println!("  - Discovery: multicast 224.0.23.12:3671 for SearchRequest");
    println!("  - Discovery: unicast 0.0.0.0:3671 for DescriptionRequest");
    println!("  - Routing: multicast 224.0.23.12:3671 for RoutingIndication/Busy/Lost");
    println!("  - Control endpoint: {:?}", control_endpoint);

    // Spawn the network layer
    let fake_network = FakeNetworkLayer { receiver: network_receiver };
    spawner.spawn(run_fake_network(fake_network)).unwrap();

    // Create resources for the link layer (2 sockets max, 1 server)
    use zweidraehte::layers::linklayers::knxip::KnxNetIpResources;
    let ll_resources = Box::leak(Box::new(KnxNetIpResources::new()));

    // Build and run the link layer using the LinkLayerBuilder trait
    let link_layer_future = kb.build_and_run(ll_resources, &context, network_sender, link_receiver);

    let test_loop = async {
        // Main test loop - send a test message every second
        let mut timer = Ticker::every(Duration::from_secs(1));

        loop {
            timer.next().await;

            // let test_buffer = bm.borrow().alloc_from_slice(&[0xbc, 0x10, 0x64, 0x18, 0x00, 0xe1, 0x00, 0x80]).await;
            // let test_msg = KnxMessageBuffer::new(test_buffer, ServiceType::L_Data_Req);

            // println!("Transmitting test message: {:x?}", test_msg.buf());

            // // Send the request to the link layer and wait for confirmation
            // let confirmation = link_sender.request(test_msg).await;
            // println!("TX confirmation: {:x?}", confirmation.buf());
        }
    };

    // Run both concurrently (link layer runs forever, test loop runs forever)
    embassy_futures::select::select(link_layer_future, test_loop).await;
}
