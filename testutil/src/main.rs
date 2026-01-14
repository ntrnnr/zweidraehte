#![feature(adt_const_params)]

use std::fs::File;

use const_default::ConstDefault;
use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel, pubsub::WaitResult};
use embassy_time::{Duration, Timer};
use env_logger::Env;
use knx_conformance::harness::mock::{MockLinkLayerBuilder, MockLinkLayerResources};
use serde::{Deserialize, Serialize};
use static_cell::StaticCell;
use core::cell::RefCell;
use zweidraehte::{
    Runner, StackDefinition, StackResources, StackState, define_com_objects,
    address::IndividualAddress,
    dpt::DPT_Switch,
    memory::{HasAddressTable, HasAssociationTable, HasCommunicationObjectTable},
    messages::{buffers::Buffer, knx::KnxMessageBuffer},
    objects::{
        comm::ComObjects,
        interface::PropertyServiceHandler,
        tables::{
            AddressTable, AssociationTable, CommunicationObjectTable, addr7::AddrTab7, asso6::AssoTab6, co7::CoTab7,
        },
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
pub struct MyKnxStackStoredData {
    addr_tab: AddrTab7<30>,
    asso_tab: AssoTab6<15>, // 15 entries = 64 bytes (old JSON has 62 bytes, serde should handle)
    co_tab: CoTab7<30>,
}

/// Unified device state for MyKnxStack
pub struct MyState {
    // Runtime state
    individual_address: core::cell::Cell<IndividualAddress>,
    // Tables
    pub adt: RefCell<AddrTab7<30>>,
    pub ast: RefCell<AssoTab6<15>>,
    pub cot: RefCell<CoTab7<30>>,
}

impl MyState {
    pub fn new(adt: AddrTab7<30>, ast: AssoTab6<15>, cot: CoTab7<30>) -> Self {
        Self {
            individual_address: core::cell::Cell::new(IndividualAddress::new(1, 0, 1)),
            adt: RefCell::new(adt),
            ast: RefCell::new(ast),
            cot: RefCell::new(cot),
        }
    }
}

impl Default for MyState {
    fn default() -> Self {
        Self {
            individual_address: core::cell::Cell::new(IndividualAddress::new(1, 0, 1)),
            adt: RefCell::new(AddrTab7::<30>::new()),
            ast: RefCell::new(AssoTab6::<15>::new()),
            cot: RefCell::new(CoTab7::<30>::new()),
        }
    }
}

impl StackState for MyState {
    fn individual_address(&self) -> IndividualAddress {
        self.individual_address.get()
    }

    fn set_individual_address(&self, addr: IndividualAddress) {
        self.individual_address.set(addr);
    }

    fn serial_number(&self) -> &[u8; 6] {
        &[0x00, 0xFA, 0x00, 0x00, 0x00, 0x01]
    }
}

impl HasAddressTable for MyState {
    type ADT = AddrTab7<30>;
    fn adt(&self) -> &RefCell<Self::ADT> {
        &self.adt
    }
}

impl HasAssociationTable for MyState {
    type AST = AssoTab6<15>;
    fn ast(&self) -> &RefCell<Self::AST> {
        &self.ast
    }
}

impl HasCommunicationObjectTable for MyState {
    type COT = CoTab7<30>;
    fn cot(&self) -> &RefCell<Self::COT> {
        &self.cot
    }
}

/// Device descriptor for test utility
const TEST_DEVICE_DESCRIPTOR: zweidraehte::ets::DeviceDescriptor = zweidraehte::ets::DeviceDescriptor {
    mask_version: 0x07B0,
    manufacturer_id: 0x00FA,
    hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    application_id: 0x0100,
    application_version: 0x01,
    max_address_table_entries: 30,
    max_association_table_entries: 15,
    max_com_objects: 30,
};

#[derive(Debug, Clone, Copy)]
pub struct MyKnxStack;
impl StackDefinition for MyKnxStack {
    const DEVICE: &'static zweidraehte::ets::DeviceDescriptor = &TEST_DEVICE_DESCRIPTOR;
    type P = AppParameters;
    type CO = comm_objs::AppComObjects;
    type LLB = MockLinkLayerBuilder<8>;
    type State = MyState;
    type Mem = zweidraehte::memory::NoMemoryMap;

    // Empty interface objects - this stack doesn't have interface objects
    type InterfaceObjects<'a> = ();

    fn create_interface_objects<'a>(_state: &'a Self::State) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
    {
        ()
    }
}

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, MyKnxStack>, link_layer_resources: &'static mut MockLinkLayerResources) {
    println!("Running stack...");
    runner.run(link_layer_resources).await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // Note: The JSON was created with old buffer sizes. Association table now uses 4 bytes per entry.
    // Old AssoTab6<30> = 62 bytes, New AssoTab6<30> = 124 bytes
    // To load old JSON with 62 bytes, we need AssoTab6<14> = 60 bytes (will pad to 62 with serde)
    let stored_data = File::open("stack_data.json")
        .map_err(|e| {
            eprintln!("Failed to open stack_data.json: {}", e);
        })
        .and_then(|f| {
            serde_json::from_reader::<File, MyKnxStackStoredData>(f).map_err(|e| {
                eprintln!("Failed to deserialize stack_data.json: {}", e);
            })
        })
        .unwrap_or_else(|_| {
            eprintln!("Using empty tables");
            MyKnxStackStoredData {
                addr_tab: AddrTab7::<30>::new(),
                asso_tab: AssoTab6::<15>::new(), // Changed from 30 to 15
                co_tab: CoTab7::<30>::new(),
            }
        });

    //serde_json::to_writer(File::create("stack_data.json").unwrap(), &stored_data).unwrap();

    println!("Address table contents:");
    for i in 1..=stored_data.addr_tab.entry_count() {
        println!("{i}: {:?}", stored_data.addr_tab.get_address(i));
    }

    println!("Association table contents:");
    println!("TSAP -> ASAP");
    for i in 1..=stored_data.asso_tab.entry_count() {
        println!("{i}: {:?} -> {:?}", stored_data.asso_tab.tsap(i), stored_data.asso_tab.asap(i));
    }

    println!("Communication table contents:");
    for i in 1..=stored_data.co_tab.entry_count() {
        println!("{i}: {:?}", stored_data.co_tab.get_object(i));
    }

    static RESOURCES: StaticCell<StackResources<MyKnxStack, { zweidraehte::config::buffer_size_for_apdu(MyKnxStack::MAX_APDU_LENGTH) }>> = StaticCell::new();

    // Create a channel for the mock link layer to receive injected messages
    static INJECTION_CHANNEL: StaticCell<Channel<NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, 8>> =
        StaticCell::new();
    let injection_channel = INJECTION_CHANNEL.init(Channel::new());

    // Create the mock link layer builder and handle
    // The builder is consumed when creating the stack, the handle is kept for injection
    let (link_layer_builder, mock_ll_handle) = MockLinkLayerBuilder::new(injection_channel);

    // Create the unified state (tables + runtime state)
    let state = MyState::new(
        stored_data.addr_tab,
        stored_data.asso_tab,
        stored_data.co_tab,
    );

    let (stack, runner) = zweidraehte::new(
        RESOURCES.init(StackResources::new()),
        comm_objs::AppComObjects::new(),
        (),  // hook_context
        link_layer_builder,
        state,
        zweidraehte::memory::NoMemoryMap,
    );

    // Create link layer resources
    let ll_resources = Box::leak(Box::new(MockLinkLayerResources::new()));

    spawner.spawn(run_stack(runner, ll_resources)).unwrap();

    // Inject messages using the mock link layer handle
    // GroupValueReadResponse for 1/0/4
    let msg1 = stack.alloc_message(&[0xbc, 0x10, 0x1, 0x8, 0x4, 0xe0, 0x0, 0x41]).await;
    mock_ll_handle.inject(msg1).await;

    // GroupValueWrite.Ind for 1/0/4
    let msg2 = stack.alloc_message(&[0xbc, 0x10, 0x1, 0x8, 0x4, 0xe0, 0x0, 0x81]).await;
    mock_ll_handle.inject(msg2).await;

    let objects = stack.objects();
    let mut events = stack.events();

    loop {
        match select(Timer::after_millis(1000), events.next_message()).await {
            Either::First(_) => {
                stack.update_object(comm_objs::Index::CoIn0, DPT_Switch::from(true)).await;

                // Test the new read_object_with_timeout functionality
                println!("Testing read_object_with_timeout...");

                // Start the read request in the background
                let read_future =
                    stack.read_object_with_timeout(comm_objs::Index::CoIn1, Some(Duration::from_millis(500)));

                // Simulate a device responding after a delay
                let inject_response = async {
                    Timer::after_millis(100).await;
                    // GroupValueResponse for 1/0/4 with value 0x01 (true)
                    let response = stack.alloc_message(&[0xbc, 0x10, 0x1, 0x8, 0x4, 0xe0, 0x0, 0x41]).await;
                    mock_ll_handle.inject(response).await;
                };

                // Run both concurrently: inject response while waiting for read to complete
                let (read_result, _) = embassy_futures::join::join(read_future, inject_response).await;

                match read_result {
                    Ok(()) => println!("Read object successful - response received!"),
                    Err(zweidraehte::ReadObjectError::Timeout) => {
                        println!("Read object timed out - no response received")
                    }
                }

                // Also test the regular read_object (fire-and-forget)
                stack.read_object(comm_objs::Index::CoIn0).await;

                println!("CoIn0: {:?}", objects.borrow().co_in0.value);
            }
            Either::Second(WaitResult::Message((index, event))) => {
                println!("Event received: {:?} for index {:?}", event, index);
            }
            Either::Second(WaitResult::Lagged(x)) => {
                println!("Event channel lagged by {} messages", x);
            }
        }

        // FIXME: stack needs to subscribe on objects and return events on subscribed object:
        //  - Update (GroupValueResponse)
        //  - Write (GroupValueWrite)

        //let a = stack.comm_obj_write_request(1).await;
        //println!("{:?}", a);
    }
}
