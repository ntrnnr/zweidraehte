#![feature(generic_arg_infer)]

use const_default::ConstDefault;
use embassy_executor::Spawner;
use zweidraehte::{
    StackResources, StackRunner, define_com_objects,
    dpt::DPT_Switch,
    messages::buffers::BufferManager,
    objects::tables::{addr7::AddrTab7, app::Application, asso6::AssoTab6, co7::CoTab7},
};

#[derive(Debug, ConstDefault)]
struct AppParameters {
    _delay_time: u16,
}

// FIXME: reexport these from stack?
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use zweidraehte::objects::comm::{ComObject, ComObjects};
define_com_objects! {
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

#[embassy_executor::task]
async fn run_stack(runner: StackRunner) {
    println!("Running stack...");
    runner.run().await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut buffers: [[u8; _]; _] = [[0u8; 32]; 10];
    let buffer_manager = unsafe { BufferManager::new(&mut buffers) };

    let resources = StackResources {
        buffer_manager,
        ind_addr: zweidraehte::address::IndividualAddress::new(1, 0, 1),
        adt: AddrTab7::<30>::new(),
        ast: AssoTab6::<30>::new(),
        cot: CoTab7::<30>::new(),
        app: Application::<AppParameters>::new(),
        ram: AppComObjects::new(),
    };

    let (_stack, runner) = resources.bootstrap();

    spawner.spawn(run_stack(runner)).unwrap();
}
