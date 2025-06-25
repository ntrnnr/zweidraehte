#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
#![feature(impl_trait_in_assoc_type)]

use defmt::*;
use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use embassy_stm32::peripherals::{USART1, USART2};
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::usart::{self, Config as UartConfig, Parity, BufferedUart, BufferedUartTx, BufferedUartRx};
use embassy_stm32::bind_interrupts;
use embassy_stm32::Config;
use embedded_io_async::{Read, Write};
use static_alloc::Bump;
use {defmt_rtt as _, panic_probe as _};

extern crate alloc;
use alloc::boxed::Box;

// 2048 bytes buffer
// Makes the TX and RX buffers fit exactly
#[global_allocator]
static A: Bump<[u8; 1 << 11]> = Bump::uninit();

bind_interrupts!(struct Irqs {
    USART2 => usart::BufferedInterruptHandler<USART2>;
    USART1 => usart::BufferedInterruptHandler<USART1>;
});

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    info!("Hello World!");

    let config = Config::default();
    // FIXME: do we need this?
    //config.rcc.sys_ck = Some(Hertz(36_000_000));
    let p = embassy_stm32::init(config);
    
    // GPIOs
    let _tpuart_res_n = Output::new(p.PA8, Level::High, Speed::Low);
    let mut led = Output::new(p.PB5, Level::High, Speed::Low);

    // UART
    let mut uart_config = UartConfig::default();
    uart_config.baudrate = 19200;
    uart_config.parity = Parity::ParityEven;
    let uart_tx_buf = Box::leak(Box::new([0u8; 256]));
    let uart_rx_buf = Box::leak(Box::new([0u8; 256]));
    let uart = BufferedUart::new(p.USART2, Irqs, p.PA3, p.PA2, uart_tx_buf.as_mut(), uart_rx_buf.as_mut(), uart_config).unwrap();

    // TPUART
    let mut tpuart_config = UartConfig::default();
    tpuart_config.baudrate = 19200;
    tpuart_config.parity = Parity::ParityEven;
    let tpuart_tx_buf = Box::leak(Box::new([0u8; 256]));
    let tpuart_rx_buf = Box::leak(Box::new([0u8; 256]));
    let mut tpuart = BufferedUart::new(p.USART1, Irqs, p.PA10, p.PA9, tpuart_tx_buf.as_mut(), tpuart_rx_buf.as_mut(), tpuart_config).unwrap();

    // Reset TPUART
    info!("Resetting TPUART");
    tpuart_reset(&mut tpuart).await;
    info!("Reset successful");

    // Read TPUART ID, just for shits and giggles
    info!("Reading ID");
    tpuart.write(&[0x20]).await.unwrap();
    let mut rdbuf = [0u8];
    tpuart.read(&mut rdbuf).await.unwrap();
    info!("ID: 0x{:02x}", rdbuf[0]);

    // Split the uarts and spawn bridge tasks
    let (uart_tx,   uart_rx  ) = uart.split();
    let (tpuart_tx, tpuart_rx) = tpuart.split();

    spawner.spawn(tpuart_to_uart(tpuart_rx, uart_tx)).unwrap();
    spawner.spawn(uart_to_tpuart(uart_rx, tpuart_tx)).unwrap();

    loop {
        led.set_high();
        Timer::after(Duration::from_millis(500)).await;

        led.set_low();
        Timer::after(Duration::from_millis(500)).await;
    }
}

#[embassy_executor::task]
async fn tpuart_to_uart(mut rx: BufferedUartRx<'static>, mut tx: BufferedUartTx<'static>) {
    loop {
        let mut buf = [0];
        rx.read_exact(&mut buf).await.unwrap();
        info!("TPUART -> UART: {:02x}", buf[0]);
        tx.write(&buf).await.unwrap();
    }
}

#[embassy_executor::task]
async fn uart_to_tpuart(mut rx: BufferedUartRx<'static>, mut tx: BufferedUartTx<'static>) {
    loop {
        let mut buf = [0];
        rx.read_exact(&mut buf).await.unwrap();
        info!("UART -> TPUART: {:02x}", buf[0]);
        tx.write(&buf).await.unwrap();
        //Timer::after(Duration::from_millis(1)).await;
    }
}

async fn tpuart_reset(uart: &mut BufferedUart<'_>) {
    uart.write(&[0x01]).await.unwrap();

    let mut rdbuf = [0u8];
    loop {
        uart.read_exact(&mut rdbuf).await.unwrap();
        
        if rdbuf[0] == 0x03 {
            break;
        }
    }
}
