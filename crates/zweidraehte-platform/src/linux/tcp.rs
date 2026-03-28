use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener as StdTcpListener, TcpStream as StdTcpStream};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::io::{AsRawFd, RawFd};

use async_io::Async;
use socket2::{Domain, Protocol, Socket, Type};

use crate::Result;
use crate::traits::{AsyncTcpListener, TcpListenerOptions};

// ============================================================================
// Synchronous TCP listener wrapper (socket2-based)
// ============================================================================

struct TcpListenerInner {
    s: StdTcpListener,
}

impl TcpListenerInner {
    fn bind(options: TcpListenerOptions) -> Result<Self> {
        let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;

        s.set_reuse_address(true)?;

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

        s.bind(&options.bind_addr.into())?;
        // Backlog of 4 — we only expect a handful of concurrent TCP
        // connections from ETS / KNX/IP Secure clients.
        s.listen(4)?;

        Ok(Self { s: s.into() })
    }
}

impl AsRawFd for TcpListenerInner {
    fn as_raw_fd(&self) -> RawFd {
        self.s.as_raw_fd()
    }
}

impl AsFd for TcpListenerInner {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.s.as_fd()
    }
}

// ============================================================================
// Synchronous TCP stream wrapper
// ============================================================================

struct TcpStreamInner {
    s: StdTcpStream,
}

impl Read for TcpStreamInner {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.s.read(buf)
    }
}

impl Write for TcpStreamInner {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.s.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.s.flush()
    }
}

impl AsRawFd for TcpStreamInner {
    fn as_raw_fd(&self) -> RawFd {
        self.s.as_raw_fd()
    }
}

impl AsFd for TcpStreamInner {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.s.as_fd()
    }
}

// ============================================================================
// Async TCP stream
// ============================================================================

/// Async TCP stream wrapping a standard `TcpStream` via `async_io`.
///
/// Implements `embedded_io_async::Read` and `Write` so it can be used
/// as the stream type for `AsyncTcpListener`.
pub struct AsyncTcpStream {
    watcher: Async<TcpStreamInner>,
}

impl embedded_io_async::ErrorType for AsyncTcpStream {
    type Error = crate::Error;
}

impl embedded_io_async::Read for AsyncTcpStream {
    async fn read(&mut self, buf: &mut [u8]) -> core::result::Result<usize, crate::Error> {
        // SAFETY: We don't move the Async wrapper while the I/O operation
        // is in progress — the borrow of `self` prevents that.
        unsafe { self.watcher.read_with_mut(|io| io.read(buf)).await.map_err(|e| e.into()) }
    }
}

impl embedded_io_async::Write for AsyncTcpStream {
    async fn write(&mut self, buf: &[u8]) -> core::result::Result<usize, crate::Error> {
        // SAFETY: We don't move the Async wrapper while the I/O operation
        // is in progress — the borrow of `self` prevents that.
        unsafe { self.watcher.write_with_mut(|io| io.write(buf)).await.map_err(|e| e.into()) }
    }

    async fn flush(&mut self) -> core::result::Result<(), crate::Error> {
        // SAFETY: We don't move the Async wrapper while the I/O operation
        // is in progress — the borrow of `self` prevents that.
        unsafe { self.watcher.write_with_mut(|io| io.flush()).await.map_err(|e| e.into()) }
    }
}

// ============================================================================
// Async TCP listener
// ============================================================================

/// Async TCP listener wrapping a standard `TcpListener` via `async_io`.
pub struct AsyncLinuxTcpListener {
    watcher: Async<TcpListenerInner>,
}

impl AsyncTcpListener for AsyncLinuxTcpListener {
    type Error = crate::Error;
    type Stream = AsyncTcpStream;

    fn bind(options: TcpListenerOptions) -> core::result::Result<Self, crate::Error> {
        let inner = TcpListenerInner::bind(options)?;
        let watcher = Async::new(inner)?;
        Ok(Self { watcher })
    }

    async fn accept(&self) -> core::result::Result<(AsyncTcpStream, SocketAddrV4), crate::Error> {
        let (stream, peer) = self
            .watcher
            .read_with(|io| {
                io.s.accept().map(|(s, addr)| {
                    // Set TCP_NODELAY to minimize latency for small KNX/IP frames.
                    let _ = s.set_nodelay(true);
                    (TcpStreamInner { s }, addr)
                })
            })
            .await
            .map_err(crate::Error::from)?;

        let peer_v4 = match peer {
            SocketAddr::V4(addr) => addr,
            _ => panic!("TCP listener on IPv4 socket accepted IPv6 connection"),
        };

        let watcher = Async::new(stream)?;
        Ok((AsyncTcpStream { watcher }, peer_v4))
    }

    fn local_endpoint(&self) -> SocketAddrV4 {
        match self.watcher.get_ref().s.local_addr().expect("bound listener has local addr") {
            SocketAddr::V4(addr) => addr,
            _ => panic!("TCP listener bound to IPv4 address returned IPv6"),
        }
    }
}
