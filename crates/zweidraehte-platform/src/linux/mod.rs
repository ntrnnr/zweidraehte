mod error;
pub use error::{Error, Result};

mod serialport;
pub use self::serialport::{AsyncSerialPort, AsyncSerialPortRx, AsyncSerialPortTx};

mod multicast_socket;
pub use self::multicast_socket::AsyncUdpMulticastSocket;

mod tcp;
pub use self::tcp::{AsyncLinuxTcpListener, AsyncTcpStream};

mod interface;
pub use self::interface::get_interface_address;

mod system;
pub use self::system::LinuxSystem;

/// Linux IP transport implementation.
pub struct LinuxIpTransport;

impl crate::IpTransport for LinuxIpTransport {
    type UdpSocket = AsyncUdpMulticastSocket;
    type TcpListener = AsyncLinuxTcpListener;
    type TcpStream = AsyncTcpStream;
}
