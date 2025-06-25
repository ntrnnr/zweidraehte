use std::cell::RefCell;

use embassy_executor::Spawner;
use env_logger::Env;

use platform::{
    AsyncSerialPort,
    serialport::{Options, Parity},
};

use zweidraehte::{
    address::IndividualAddress,
    layers::linklayers::tpuart::{LowerLinkLayer, TpUartLinkLayer},
    messages::buffers::BufferManager,
};

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

    let mut buffers: [[u8; 128]; 4] = [[0u8; 128]; 4];
    let buffer_manager = unsafe { BufferManager::new(&mut buffers) };
    let bm = unsafe { core::mem::transmute(RefCell::new(buffer_manager.dyn_buffer_manager())) };

    let s = AsyncSerialPort::open(Options { baud_rate: 19200, parity: Parity::Even, ..Default::default() }).unwrap();
    let mut ll = TpUartLinkLayer::new(s, Some(IndividualAddress::new(1, 0, 1)), &bm);

    // Create a test transmission message first
    let mut test_buffer = bm.borrow().alloc().await;
    test_buffer.set_len(8);
    // Simple KNX group value write frame: BC 11 22 11 01 80 00 80 (switch off light at 1/1/1)
    test_buffer.clone_from_slice(&[0xBC, 0x11, 0x22, 0x11, 0x01, 0x80, 0x00, 0x80]);
    let test_msg = zweidraehte::messages::knx::KnxMessageBuffer::new(
        test_buffer,
        zweidraehte::messages::knx::ServiceType::L_Data_Req,
    );

    //println!("Transmitting test message: {:x?}", test_msg.buf());
    //let confirmation = ll.transmit(test_msg).await;
    //println!("TX confirmation: {:x?}", confirmation);

    loop {
        let msg = ll.receive().await;
        println!("RX: {:x?}", msg);
    }

    //tpuart::TpUartLinkLayer::new(uart, individual_addr, buffer_manager)
}
