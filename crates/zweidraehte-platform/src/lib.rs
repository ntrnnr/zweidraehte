#![cfg_attr(not(feature = "std"), no_std)]
#![feature(never_type)]
#![allow(async_fn_in_trait)]

pub mod address;
#[cfg(feature = "std")]
pub mod serialport;
pub mod traits;

pub use traits::{
    AsyncTcpListener, AsyncUdpSocket, IpConfig, IpTransport, NetworkConfig, NetworkInfo, NeverTcpError,
    NeverTcpListener, NeverTcpStream, SystemControl, TcpListenerOptions, UdpSocketOptions,
};

#[cfg(feature = "linux")]
mod linux;

#[cfg(feature = "linux")]
pub use linux::{
    AsyncLinuxTcpListener, AsyncSerialPort, AsyncSerialPortRx, AsyncSerialPortTx, AsyncTcpStream, Error as LinuxError,
    LinuxIpTransport, LinuxSystem, get_interface_address,
};

#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "linux")]
    LinuxPlatformError(LinuxError),

    Timeout,
    UnexpectedEof,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            #[cfg(feature = "linux")]
            Self::LinuxPlatformError(err) => write!(f, "Linux platform error: {:?}", &err),

            Self::Timeout => write!(f, "Timeout"),
            Self::UnexpectedEof => write!(f, "Unexpected EOF while reading"),
        }
    }
}

impl core::error::Error for Error {}

impl embedded_io_async::Error for Error {
    fn kind(&self) -> embedded_io_async::ErrorKind {
        embedded_io_async::ErrorKind::Other
    }
}

pub type Result<T> = core::result::Result<T, Error>;
