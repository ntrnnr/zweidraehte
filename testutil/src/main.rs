#![feature(adt_const_params)]

use std::fs::File;

use const_default::ConstDefault;
use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_sync::pubsub::WaitResult;
use embassy_time::{Timer, Duration};
use env_logger::Env;
use serde::{Deserialize, Serialize};
use static_cell::StaticCell;
use zweidraehte::{
    Runner, StackDefinition, StackResources, define_com_objects,
    dpt::DPT_Switch,
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

    let stored_data = File::open("stack_data.json")
        .map_err(|_| ())
        .and_then(|f| serde_json::from_reader::<File, MyKnxStackStoredData>(f).map_err(|_| ()))
        .unwrap_or_else(|_| MyKnxStackStoredData {
            addr_tab: AddrTab7::<30>::new(),
            asso_tab: AssoTab6::<30>::new(),
            co_tab: CoTab7::<30>::new(),
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

    static RESOURCES: StaticCell<StackResources<MyKnxStack>> = StaticCell::new();

    let (stack, runner) = zweidraehte::new(
        RESOURCES.init(StackResources::new()),
        stored_data.addr_tab,
        stored_data.asso_tab,
        stored_data.co_tab,
        comm_objs::AppComObjects::new(),
    );

    spawner.spawn(run_stack(runner)).unwrap();

    // GroupValueReadResponse for 1/0/4
    stack.debug_inject_linklayer_message(&[0xbc, 0x10, 0x1, 0x8, 0x4, 0xe0, 0x0, 0x41][..]).await;

    // GroupValueWrite.Ind for 1/0/4
    stack.debug_inject_linklayer_message(&[0xbc, 0x10, 0x1, 0x8, 0x4, 0xe0, 0x0, 0x81][..]).await;

    let objects = stack.objects();
    let mut events = stack.events();

    loop {
        match select(Timer::after_millis(1000), events.next_message()).await {
            Either::First(_) => {
                stack.update_object(comm_objs::Index::CoIn0, DPT_Switch::from(true)).await;
                
                // Test the new read_object_with_timeout functionality
                println!("Testing read_object_with_timeout...");
                match stack.read_object_with_timeout(comm_objs::Index::CoIn1, Some(Duration::from_millis(500))).await {
                    Ok(()) => println!("Read object successful - response received!"),
                    Err(zweidraehte::ReadObjectError::Timeout) => println!("Read object timed out - no response received"),
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
