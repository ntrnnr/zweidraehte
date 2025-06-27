use std::cell::RefCell;

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Ticker, Timer};
use env_logger::Env;

use platform::{
    AsyncSerialPort,
    serialport::{Options, Parity},
};

use zweidraehte::{
    address::IndividualAddress,
    layers::linklayers::tpuart::{LowerLinkLayer, TpUartLinkLayer},
    messages::{
        buffers::BufferManager,
        knx::{KnxMessageBuffer, ServiceType},
    },
};

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

    let mut buffers: [[u8; 128]; 4] = [[0u8; 128]; 4];
    let buffer_manager = unsafe { BufferManager::new(&mut buffers) };
    let bm = unsafe { core::mem::transmute(RefCell::new(buffer_manager.dyn_buffer_manager())) };

    let s = AsyncSerialPort::open(Options { baud_rate: 19200, parity: Parity::Even, ..Default::default() }).unwrap();
    let mut ll = TpUartLinkLayer::new(s, Some(IndividualAddress::new(15, 15, 1)), &bm);

    ll.initialize().await;

    let mut timer = Ticker::every(Duration::from_millis(1000));

    loop {
        match select(timer.next(), ll.receive()).await {
            Either::First(_) => {
                let mut test_buffer = bm.borrow().alloc().await;
                test_buffer.set_len(8);
                test_buffer.clone_from_slice(&[0xbc, 0x10, 0x64, 0x18, 0x00, 0xe1, 0x00, 0x80]);
                //test_buffer.clone_from_slice(&[0xbc, 0x11, 0x01, 0x09, 0x01, 0xe1, 0x00, 0x81]);
                let test_msg = KnxMessageBuffer::new(test_buffer, ServiceType::L_Data_Req);

                println!("Transmitting test message: {:x?}", test_msg.buf());
                let confirmation = ll.transmit(test_msg).await;
                println!("TX confirmation: {:x?}", confirmation);
            }
            Either::Second(msg) => {
                println!("RX: {:x?}", msg);
            }
        }
    }
}
