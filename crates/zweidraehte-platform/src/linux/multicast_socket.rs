use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as LinuxUdpSocket};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::io::{AsRawFd, RawFd};

use async_io::Async;
use embassy_time::{Duration, with_timeout};
use nix::libc;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrIn, recvmsg, setsockopt, sockopt::Ipv4PacketInfo};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::IoSliceMut;

use crate::Result;
use crate::traits::{AsyncUdpSocket, UdpSocketOptions};

#[derive(Debug)]
pub struct UdpMulticastSocket {
    s: LinuxUdpSocket,
}

impl UdpMulticastSocket {
    pub fn bind(options: UdpSocketOptions) -> Result<Self> {
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        s.set_reuse_address(true)?;
        s.set_multicast_ttl_v4(options.multicast_ttl)?;
        s.set_multicast_loop_v4(options.loopback)?;

        // Bind to specific interface using SO_BINDTODEVICE if specified
        if let Some(interface) = options.interface {
            #[cfg(target_os = "linux")]
            {
                use nix::sys::socket::{setsockopt, sockopt::BindToDevice};
                use std::ffi::OsString;

                let interface_os: OsString = interface.into();
                setsockopt(&s, BindToDevice, &interface_os).map_err(std::io::Error::other)?;
            }
        }

        // Enable IP_PKTINFO so recvmsg returns the destination IP address
        // of each incoming packet. This lets the stack distinguish unicast
        // from multicast traffic on shared sockets.
        setsockopt(&s, Ipv4PacketInfo, &true).map_err(std::io::Error::other)?;

        // To be able to receive unicast and multicast traffic on the same socket,
        // we need to bind to INADDR_ANY
        s.bind(&options.bind_addr.into())?;

        s.set_read_timeout(options.read_timeout.map(|x| core::time::Duration::from_micros(x.as_micros())))?;
        s.set_write_timeout(options.write_timeout.map(|x| core::time::Duration::from_micros(x.as_micros())))?;

        Ok(Self { s: s.into() })
    }

    pub fn join_multicast(&self, group: Ipv4Addr, interface: Ipv4Addr) -> Result<()> {
        self.s.join_multicast_v4(&group, &interface)?;
        Ok(())
    }

    pub fn leave_multicast(&self, group: Ipv4Addr, interface: Ipv4Addr) -> Result<()> {
        self.s.leave_multicast_v4(&group, &interface)?;
        Ok(())
    }

    pub fn set_broadcast(&self, broadcast: bool) -> Result<()> {
        self.s.set_broadcast(broadcast)?;
        Ok(())
    }

    pub fn local_endpoint(&self) -> SocketAddr {
        self.s.local_addr().unwrap()
    }
}

impl AsRawFd for UdpMulticastSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.s.as_raw_fd()
    }
}

impl AsFd for UdpMulticastSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.s.as_fd()
    }
}

#[derive(Debug)]
pub struct AsyncUdpMulticastSocket {
    watcher: Async<UdpMulticastSocket>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl AsyncUdpMulticastSocket {
    pub fn bind(mut options: UdpSocketOptions) -> Result<Self> {
        let read_timeout = options.read_timeout.take();
        let write_timeout = options.write_timeout.take();

        match UdpMulticastSocket::bind(options) {
            Ok(socket) => Ok(AsyncUdpMulticastSocket { watcher: Async::new(socket)?, read_timeout, write_timeout }),
            Err(err) => Err(err),
        }
    }

    pub fn join_multicast(&self, group: Ipv4Addr, interface: Ipv4Addr) -> Result<()> {
        self.watcher.get_ref().join_multicast(group, interface)
    }

    pub fn leave_multicast(&self, group: Ipv4Addr, interface: Ipv4Addr) -> Result<()> {
        self.watcher.get_ref().leave_multicast(group, interface)
    }

    pub fn set_broadcast(&self, broadcast: bool) -> Result<()> {
        self.watcher.get_ref().set_broadcast(broadcast)
    }

    pub fn local_endpoint(&self) -> SocketAddr {
        self.watcher.get_ref().local_endpoint()
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.write_timeout = timeout;
    }

    pub fn connect(&self, endpoint: SocketAddr) -> Result<()> {
        self.watcher.get_ref().s.connect(endpoint)?;
        Ok(())
    }

    pub async fn readable(&self) -> Result<()> {
        self.watcher.readable().await.map_err(|e| e.into())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let reader = self.watcher.read_with(|io| io.s.recv(buf));

        if let Some(read_timeout) = self.read_timeout {
            with_timeout(read_timeout, reader).await?
        } else {
            reader.await
        }
        .map_err(|e| e.into())
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV4, Option<Ipv4Addr>)> {
        // Use recvmsg with IP_PKTINFO to obtain the destination IP address
        // of the incoming packet, allowing unicast/multicast disambiguation.
        let reader = self.watcher.read_with(|io| {
            let fd = io.s.as_raw_fd();
            let mut iov = [IoSliceMut::new(buf)];

            // Ancillary data buffer sized for a single in_pktinfo control message.
            let mut cmsg_buf = nix::cmsg_space!(libc::in_pktinfo);

            let msg = recvmsg::<SockaddrIn>(fd, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
                .map_err(std::io::Error::from)?;

            let len = msg.bytes;

            // Extract source address from the msg header.
            let source = msg
                .address
                .map(|sa| SocketAddrV4::new(sa.ip(), sa.port()))
                .unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

            // Extract destination IP from IP_PKTINFO ancillary data.
            let mut local_addr = None;
            for cmsg in msg.cmsgs()? {
                if let ControlMessageOwned::Ipv4PacketInfo(pktinfo) = cmsg {
                    local_addr = Some(Ipv4Addr::from(u32::from_be(pktinfo.ipi_addr.s_addr)));
                }
            }

            Ok((len, source, local_addr))
        });

        if let Some(read_timeout) = self.read_timeout {
            with_timeout(read_timeout, reader).await?
        } else {
            reader.await
        }
        .map_err(|e| e.into())
    }

    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        let writer = self.watcher.write_with(|io| io.s.send(buf));

        if let Some(write_timeout) = self.write_timeout {
            with_timeout(write_timeout, writer).await?
        } else {
            writer.await
        }
        .map_err(|e| e.into())
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddrV4) -> Result<usize> {
        let writer = self.watcher.write_with(|io| io.s.send_to(buf, addr));

        if let Some(write_timeout) = self.write_timeout {
            with_timeout(write_timeout, writer).await?
        } else {
            writer.await
        }
        .map_err(|e| e.into())
    }
}

impl AsyncUdpSocket for AsyncUdpMulticastSocket {
    type Error = crate::Error;
    type Context = ();

    fn bind(_ctx: &(), options: UdpSocketOptions) -> core::result::Result<Self, crate::Error> {
        AsyncUdpMulticastSocket::bind(options)
    }

    fn join_multicast(&self, group: Ipv4Addr, interface: Ipv4Addr) -> core::result::Result<(), crate::Error> {
        self.watcher.get_ref().join_multicast(group, interface)
    }

    fn leave_multicast(&self, group: Ipv4Addr, interface: Ipv4Addr) -> core::result::Result<(), crate::Error> {
        self.watcher.get_ref().leave_multicast(group, interface)
    }

    fn set_broadcast(&self, broadcast: bool) -> core::result::Result<(), crate::Error> {
        self.watcher.get_ref().set_broadcast(broadcast)
    }

    fn local_endpoint(&self) -> SocketAddrV4 {
        match AsyncUdpMulticastSocket::local_endpoint(self) {
            SocketAddr::V4(addr) => addr,
            _ => panic!("UDP multicast socket doesn't support IPv6"),
        }
    }

    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> core::result::Result<(usize, SocketAddrV4, Option<Ipv4Addr>), crate::Error> {
        AsyncUdpMulticastSocket::recv_from(self, buf).await
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddrV4) -> core::result::Result<usize, crate::Error> {
        AsyncUdpMulticastSocket::send_to(self, buf, addr).await
    }
}
