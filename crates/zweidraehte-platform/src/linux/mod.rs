mod error;
pub use error::Error;

mod serialport;
pub use self::serialport::{AsyncSerialPort, AsyncSerialPortRx, AsyncSerialPortTx};

mod multicast_socket;
pub use self::multicast_socket::AsyncUdpMulticastSocket;

mod tcp;
pub use self::tcp::{AsyncLinuxTcpListener, AsyncTcpStream};

mod interface;
pub use self::interface::{
    InterfaceSelector, NetworkInterface, SelectInterfaceError, SelectionReason, ipv4_interfaces, route_source_address,
};

mod network;
pub use self::network::LinuxIpPlatform;

mod system;
pub use self::system::LinuxSystem;

/// Linux IP transport implementation.
pub struct LinuxIpTransport;

impl crate::IpTransport for LinuxIpTransport {
    type UdpSocket = AsyncUdpMulticastSocket;
    type TcpListener = AsyncLinuxTcpListener;
    type TcpStream = AsyncTcpStream;
}
