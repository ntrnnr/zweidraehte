#![feature(generic_arg_infer)]
#![feature(adt_const_params)]

use std::fs::File;

use const_default::ConstDefault;
use embassy_executor::Spawner;
use embassy_time::Timer;
use env_logger::Env;
use serde::{Deserialize, Serialize};
use static_cell::StaticCell;
use zweidraehte::{
    Runner, StackDefinition, StackResources, define_com_objects,
    dpt::DPT_Switch,
    messages::{buffers::Buffer, knx::KnxMessageBuffer},
    objects::{
        comm::ComObjects,
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
            0 => pub co_in0: DPT_Switch = DPT_Switch::from(false),
            1 => pub co_in1: DPT_Switch = DPT_Switch::from(false),
            2 => pub co_in2: DPT_Switch = DPT_Switch::from(false),
            3 => pub co_in3: DPT_Switch = DPT_Switch::from(false),
            4 => pub co_out0: DPT_Switch = DPT_Switch::from(false),
            5 => pub co_out1: DPT_Switch = DPT_Switch::from(false),
            6 => pub co_out2: DPT_Switch = DPT_Switch::from(false),
            7 => pub co_out3: DPT_Switch = DPT_Switch::from(false),
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
pub struct MyKnxStack;
impl StackDefinition for MyKnxStack {
    type ADT = AddrTab7<30>;
    type AST = AssoTab6<30>;
    type COT = CoTab7<30>;
    type P = AppParameters;
    type CO = comm_objs::AppComObjects;
}

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, MyKnxStack>) {
    println!("Running stack...");
    runner.run().await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // let mut buffers: [[u8; _]; _] = [[0u8; 32]; 10];
    // let buffer_manager = unsafe { BufferManager::new(&mut buffers) };

    let stored_data = File::open("stack_data.json")
        .map_err(|_| ())
        .and_then(|f| serde_json::from_reader::<File, MyKnxStackStoredData>(f).map_err(|_| ()))
        .unwrap_or_else(|_| MyKnxStackStoredData {
            addr_tab: AddrTab7::<30>::new(),
            asso_tab: AssoTab6::<30>::new(),
            co_tab: CoTab7::<30>::new(),
        });

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
    for i in 0..stored_data.co_tab.entry_count() {
        println!("{i}: {:?}", stored_data.co_tab.get_object(i));
    }

    //serde_json::to_writer(File::create("stack_data.json").unwrap(), &stored_data).unwrap();

    static RESOURCES: StaticCell<StackResources<MyKnxStack>> = StaticCell::new();

    let (stack, runner) = zweidraehte::new(
        RESOURCES.init(StackResources::new()),
        stored_data.addr_tab,
        stored_data.asso_tab,
        stored_data.co_tab,
        comm_objs::AppComObjects::new(),
    );

    spawner.spawn(run_stack(runner)).unwrap();

    stack.debug_inject_linklayer_message(&[0xbc, 0x10, 0x1, 0x8, 0x4, 0xe0, 0x0, 0x41][..]).await;
    stack.debug_inject_linklayer_message(&[0xbc, 0x10, 0x1, 0x8, 0x4, 0xe0, 0x0, 0x81][..]).await;

    loop {
        Timer::after_millis(1000).await;

        //stack.group_value_write_request(comm_objs::ComObjectIndex::CoIn0.index(), DPT_Switch::from(true)).await;
        //stack.group_value_read_request(comm_objs::ComObjectIndex::CoIn0.index()).await;

        // FIXME: stack needs to subscribe on objects and return events on subscribed object:
        //  - Update (GroupValueResponse)
        //  - Write (GroupValueWrite)

        //let a = stack.comm_obj_write_request(1).await;
        //println!("{:?}", a);
    }
}
