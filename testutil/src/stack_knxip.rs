//! Full KNX Stack with KNX/IP Link Layer
//!
//! This test utility demonstrates the complete KNX stack with a real KNX/IP link layer.
//! It combines:
//! - Application Layer with communication objects
//! - Transport Layer
//! - Network Layer
//! - KNX/IP Link Layer with Discovery and Routing Servers
//!
//! The stack loads configuration from `stack_test_data.json` and provides:
//! - 8 communication objects (4 inputs, 4 outputs)
//! - KNX/IP discovery on multicast 224.0.23.12:3671
//! - KNX/IP routing with congestion control (RoutingIndication, RoutingBusy, RoutingLostMessage)
//! - Full bidirectional KNX message handling
//!
//! ## Comprehensive Test Configuration (stack_test_data.json)
//!
//! ### Address Table (8 group addresses)
//! - TSAP 1 → Group Address 1/0/1 (0x0801) - Controls CO1
//! - TSAP 2 → Group Address 1/0/2 (0x0802) - Controls CO2
//! - TSAP 3 → Group Address 1/0/3 (0x0803) - Controls CO3
//! - TSAP 4 → Group Address 1/0/4 (0x0804) - Controls CO4
//! - TSAP 5 → Group Address 1/1/1 (0x0901) - Controls CO5
//! - TSAP 6 → Group Address 1/1/2 (0x0902) - Controls CO6
//! - TSAP 7 → Group Address 1/1/3 (0x0903) - Controls CO3 and CO7 (multi-address)
//! - TSAP 8 → Group Address 1/1/4 (0x0904) - Broadcast to CO1, CO2, CO5, CO6
//!
//! ### Association Table (12 associations)
//! Maps Transport SAPs (TSAPs) to Application SAPs (ASAPs/Communication Objects):
//! - TSAP 1 → ASAP 1 (CO 1: co_in0)
//! - TSAP 2 → ASAP 2 (CO 2: co_in1)
//! - TSAP 3 → ASAP 3 (CO 3: co_in2)
//! - TSAP 4 → ASAP 4 (CO 4: co_in3)
//! - TSAP 5 → ASAP 5 (CO 5: co_out0)
//! - TSAP 6 → ASAP 6 (CO 6: co_out1)
//! - TSAP 7 → ASAP 3 (CO 3: co_in2) - 1/1/3 also controls CO3
//! - TSAP 7 → ASAP 7 (CO 7: co_out2)
//! - TSAP 8 → ASAP 1 (CO 1: co_in0) - Broadcast
//! - TSAP 8 → ASAP 2 (CO 2: co_in1) - Broadcast
//! - TSAP 8 → ASAP 5 (CO 5: co_out0) - Broadcast
//! - TSAP 8 → ASAP 6 (CO 6: co_out1) - Broadcast
//!
//! ### Communication Object Table (8 configured objects)
//! Flag legend: CE=Communication Enable, TE=Transmit Enable, RE=Read Enable,
//!              WE=Write Enable, UE=Update Enable, Priority=Low (bits 3-2 = 0b11)
//!
//! - CO 1: Type Uint1, Flags 0xDF (CE|TE|RE|WE|UE) - Full bidirectional
//! - CO 2: Type Uint1, Flags 0xDF (CE|TE|RE|WE|UE) - Full bidirectional
//! - CO 3: Type Uint1, Flags 0x5F (CE|TE|RE|WE) - No UE, won't auto-transmit on update
//! - CO 4: Type Uint1, Flags 0x4F (CE|TE|RE) - Read-only from bus (no WE)
//! - CO 5: Type Uint1, Flags 0xCF (CE|TE|RE|WE) - Can write to bus, no UE
//! - CO 6: Type Uint1, Flags 0xCF (CE|TE|RE|WE) - Can write to bus, no UE
//! - CO 7: Type Uint1, Flags 0x4F (CE|TE|RE) - Read-only from bus (no WE)
//! - CO 8: Type Uint1, Flags 0x00 - Disabled, application-local only
//!
//! ## Comprehensive Test Cases
//!
//! ### Test 1: Basic Input Control
//! - **Action**: Send `1` to address 1/0/1
//! - **Expected**: CO1 (co_in0) updates to `1`, triggers output CO5 to toggle
//!
//! ### Test 2: Independent Input Control
//! - **Action**: Send `0` to address 1/0/2
//! - **Expected**: CO2 (co_in1) updates to `0`, triggers output CO6 to toggle
//!
//! ### Test 3: Multi-Address Control (same object, different addresses)
//! - **Action**: Send `1` to address 1/0/3
//! - **Expected**: CO3 (co_in2) updates to `1`
//! - **Action**: Send `0` to address 1/1/3
//! - **Expected**: CO3 (co_in2) updates to `0` (same object controlled by two addresses)
//! - Also updates CO7 (co_out2) since 1/1/3 is also mapped to it
//!
//! ### Test 4: Broadcast Address
//! - **Action**: Send `1` to address 1/1/4
//! - **Expected**: CO1, CO2, CO5, CO6 all update to `1` simultaneously
//!
//! ### Test 5: Output Object Control
//! - **Action**: Send `1` to address 1/1/1
//! - **Expected**: CO5 (co_out0) updates to `1`
//! - **Action**: Send `0` to address 1/1/2
//! - **Expected**: CO6 (co_out1) updates to `0`
//!
//! ### Test 6: Read Request
//! - **Action**: Send GroupValueRead to address 1/0/1
//! - **Expected**: CO1 responds with GroupValueResponse containing current value
//! - All objects with RE flag set should respond to read requests on their addresses
//!
//! ### Test 7: Write to Read-Only Object (should be rejected)
//! - **Action**: Send `1` to address 1/0/4
//! - **Expected**: CO4 should NOT update (WE flag not set, read-only from bus)
//!
//! ### Test 8: Update Flag Behavior
//! - **Action**: Application updates CO3 locally
//! - **Expected**: NO automatic transmission (UE flag not set)
//! - **Action**: Application updates CO1 locally
//! - **Expected**: Automatic GroupValueWrite transmitted to 1/0/1 (UE flag is set)
//!
//! ### Test 9: Application-Local Object
//! - **Action**: Application updates CO8 (co_out3)
//! - **Expected**: No KNX bus activity (flags 0x00, not connected to any group address)
//!
//! ### Test 10: Stress Test - Rapid Updates
//! - **Action**: Send rapid alternating `0`/`1` to address 1/1/4 (broadcast)
//! - **Expected**: All 4 mapped objects (CO1, CO2, CO5, CO6) track changes
//! - May trigger RoutingBusy if congestion occurs

#![feature(adt_const_params)]

use std::fs::File;

use const_default::ConstDefault;
use embassy_executor::Spawner;
use embassy_sync::pubsub::WaitResult;
use embassy_time::Duration;
use env_logger::Env;
use platform::address::EthernetAddress;
use serde::{Deserialize, Serialize};
use static_cell::StaticCell;
use zweidraehte::{
    Runner, StackDefinition, StackResources,
    address::IndividualAddress,
    define_com_objects,
    dpt::DPT_Switch,
    layers::linklayers::knxip::{EndpointType, KnxNetIpBuilder, KnxNetIpResources, servers},
    messages::knxip::KNXnetIPServiceType,
    messages::knxip::substructs::{DeviceInformation, DeviceStatus, HPAI, KNXMedium, ServiceFamily, SupportedService},
    objects::{
        comm::{ComObjectIndex, ComObjects},
        tables::{addr7::AddrTab7, asso6::AssoTab6, co7::CoTab7},
    },
};

#[derive(Debug, ConstDefault)]
pub struct AppParameters {
    _delay_time: u16,
}

define_com_objects! {
    pub mod comm_objs {
        pub struct AppComObjects {
            1 => pub co_in0: DPT_Switch = DPT_Switch::from(false),
            2 => pub co_in1: DPT_Switch = DPT_Switch::from(false),
            3 => pub co_in2: DPT_Switch = DPT_Switch::from(false),
            4 => pub co_in3: DPT_Switch = DPT_Switch::from(false),
            5 => pub co_out0: DPT_Switch = DPT_Switch::from(false),
            6 => pub co_out1: DPT_Switch = DPT_Switch::from(false),
            7 => pub co_out2: DPT_Switch = DPT_Switch::from(false),
            8 => pub co_out3: DPT_Switch = DPT_Switch::from(false),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MyKnxStackStoredData {
    addr_tab: AddrTab7<30>,
    asso_tab: AssoTab6<30>,
    co_tab: CoTab7<30>,
}

#[derive(Debug, Clone, Copy)]
pub struct MyKnxStackWithKnxIp;
impl StackDefinition for MyKnxStackWithKnxIp {
    type ADT = AddrTab7<30>;
    type AST = AssoTab6<30>;
    type COT = CoTab7<30>;
    type P = AppParameters;
    type CO = comm_objs::AppComObjects;
    type LLB = KnxNetIpBuilder<2, 2>; // 2 sockets, 2 servers
}

#[embassy_executor::task]
async fn run_stack(
    runner: Runner<'static, MyKnxStackWithKnxIp>,
    link_layer_resources: &'static mut KnxNetIpResources<2>,
) {
    println!("Running KNX stack with KNX/IP link layer...");
    runner.run(link_layer_resources).await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    println!("=== KNX Stack with KNX/IP Link Layer ===");

    // Load or create stack configuration
    let stored_data = File::open("stack_test_data.json")
        .map_err(|_| ())
        .and_then(|f| serde_json::from_reader::<File, MyKnxStackStoredData>(f).map_err(|_| ()))
        .unwrap_or_else(|_| {
            println!("No stack_test_data.json found, creating default configuration");
            MyKnxStackStoredData {
                addr_tab: AddrTab7::<30>::new(),
                asso_tab: AssoTab6::<30>::new(),
                co_tab: CoTab7::<30>::new(),
            }
        });

    // Create KNX/IP Discovery Server configuration
    const SUPPORTED_SERVICES: &[SupportedService] = &[
        SupportedService { family: ServiceFamily::Core, version: 1 },
        //SupportedService { family: ServiceFamily::DeviceManagement, version: 1 },
        //SupportedService { family: ServiceFamily::Tunneling, version: 1 },
        SupportedService { family: ServiceFamily::Routing, version: 1 },
    ];

    let control_endpoint = HPAI::Ipv4Udp { addr: "192.168.106.6".parse().unwrap(), port: 3671 };

    let device_info = DeviceInformation {
        medium: KNXMedium::KNXIP,
        device_status: DeviceStatus::None,
        individual_address: IndividualAddress::new(1, 1, 0),
        project_installation_identifier: 0x1234,
        knx_serial_number: [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78],
        routing_multicast_address: core::net::Ipv4Addr::new(224, 0, 23, 12),
        mac_address: EthernetAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        friendly_name: *b"KNX Stack Test\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    };

    let discovery_server = servers::DiscoveryServer::new(control_endpoint, device_info, SUPPORTED_SERVICES);

    // Create routing server for KNX/IP routing
    let routing_server = servers::RoutingServer::new(core::net::Ipv4Addr::new(224, 0, 23, 12), 3671);

    // Create KNX/IP link layer builder with both discovery and routing servers
    let link_layer_builder = KnxNetIpBuilder::<2, 2>::new("knxdevbridgeif")
        .add_server(
            discovery_server,
            &[KNXnetIPServiceType::SearchRequest, KNXnetIPServiceType::DescriptionRequest],
            &[
                EndpointType::new_udp(core::net::Ipv4Addr::new(224, 0, 23, 12), 3671), // KNX multicast
                EndpointType::new_udp_any(3671),                                       // Unicast on 3671
            ],
        )
        .add_server(
            routing_server,
            &[
                KNXnetIPServiceType::RoutingIndication,
                KNXnetIPServiceType::RoutingBusy,
                KNXnetIPServiceType::RoutingLostMessage,
            ],
            &[
                EndpointType::new_udp(core::net::Ipv4Addr::new(224, 0, 23, 12), 3671), // KNX multicast
            ],
        );

    println!("KNX/IP Configuration:");
    println!("  - Interface: knxdevbridgeif");
    println!("  - Multicast: 224.0.23.12:3671");
    println!("  - Unicast: 0.0.0.0:3671");
    println!("  - Individual Address: 1.1.0");
    println!("  - Control Endpoint: {:?}", control_endpoint);
    println!("  - Discovery Server: SearchRequest, DescriptionRequest");
    println!("  - Routing Server: RoutingIndication, RoutingBusy, RoutingLostMessage");

    // Create stack resources
    static RESOURCES: StaticCell<StackResources<MyKnxStackWithKnxIp>> = StaticCell::new();
    let (stack, runner) = zweidraehte::new(
        RESOURCES.init(StackResources::new()),
        stored_data.addr_tab,
        stored_data.asso_tab,
        stored_data.co_tab,
        comm_objs::AppComObjects::new(),
        link_layer_builder,
    );

    // Create link layer resources
    let ll_resources = Box::leak(Box::new(KnxNetIpResources::<2>::new()));

    // Spawn the stack runner
    spawner.spawn(run_stack(runner, ll_resources)).unwrap();

    println!("\n=== Stack Running ===");
    println!("Communication Objects:");
    println!("  CO 1-4: Inputs  (co_in0-3)");
    println!("  CO 5-8: Outputs (co_out0-3)");
    println!("\nListening for KNX/IP discovery requests...");
    println!("Test with: knxtool search\n");

    // Main application loop - monitor and control communication objects
    let mut events = stack.events();
    let mut last_print = embassy_time::Instant::now();

    loop {
        // Print stack status every 5 seconds
        if embassy_time::Instant::now().duration_since(last_print) > Duration::from_secs(5) {
            let objects = stack.objects();
            let co_borrow = objects.borrow();

            println!("\n--- Stack Status ---");
            println!("Inputs:");
            for i in 1..=4 {
                let value = co_borrow.value(i);
                let status = co_borrow.status(i);
                println!("  CO {}: {:?} (status: {:?})", i, value, status);
            }
            println!("Outputs:");
            for i in 5..=8 {
                let value = co_borrow.value(i);
                let status = co_borrow.status(i);
                println!("  CO {}: {:?} (status: {:?})", i, value, status);
            }
            println!("--------------------\n");

            last_print = embassy_time::Instant::now();
        }

        // Process events with a timeout
        match embassy_time::with_timeout(Duration::from_millis(100), events.next_message()).await {
            Ok(WaitResult::Message((index, event))) => {
                println!("Event: {:?} on CO {:?}", event, index);

                // Example: Toggle output when input changes
                use zweidraehte::objects::comm::ComObjectEvent;
                if let ComObjectEvent::Updated = event {
                    let idx = index.index();
                    if idx >= 1 && idx <= 4 {
                        // Input updated - toggle corresponding output
                        let output_idx = comm_objs::Index::from_index(idx + 4).unwrap();
                        let current = {
                            let objects = stack.objects();
                            let co_borrow = objects.borrow();
                            let value_bytes = co_borrow.value(idx + 4);
                            // DPT_Switch is stored as a single byte, bit 0 is the value
                            value_bytes.len() > 0 && (value_bytes[0] & 0x01) != 0
                        };
                        stack.update_object(output_idx, DPT_Switch::from(!current)).await;
                        println!("Toggled output CO {} in response to input CO {}", idx + 4, idx);
                    }
                }
            }
            Ok(WaitResult::Lagged(count)) => {
                println!("Warning: Missed {} events (processing too slow)", count);
            }
            Err(_) => {
                // Timeout - continue
            }
        }
    }
}
