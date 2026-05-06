use async_io::Async;
use nix::sys::termios::{FlushArg, tcflush};
use serialport::TTYPort;

use crate::serialport::*;
use crate::{Error, Result};

impl From<DataBits> for serialport::DataBits {
    fn from(d: DataBits) -> Self {
        match d {
            DataBits::Five => serialport::DataBits::Five,
            DataBits::Six => serialport::DataBits::Six,
            DataBits::Seven => serialport::DataBits::Seven,
            DataBits::Eight => serialport::DataBits::Eight,
        }
    }
}

impl From<StopBits> for serialport::StopBits {
    fn from(d: StopBits) -> Self {
        match d {
            StopBits::One => serialport::StopBits::One,
            StopBits::Two => serialport::StopBits::Two,
        }
    }
}

impl From<Parity> for serialport::Parity {
    fn from(d: Parity) -> Self {
        match d {
            Parity::Even => serialport::Parity::Even,
            Parity::Odd => serialport::Parity::Odd,
            Parity::None => serialport::Parity::None,
        }
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            path: "/dev/ttyUSB0".into(),
            baud_rate: 115200,
            data_bits: DataBits::Eight,
            stop_bits: StopBits::One,
            parity: Parity::None,
        }
    }
}

pub struct AsyncSerialPort {
    _t: TTYPort,
    s: Async<OwnedFd>,
}

/// Write half of a split [`AsyncSerialPort`].
pub struct AsyncSerialPortTx {
    s: Async<OwnedFd>,
}

/// Read half of a split [`AsyncSerialPort`].
pub struct AsyncSerialPortRx {
    s: Async<OwnedFd>,
}

use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

impl AsyncSerialPort {
    pub fn open(options: Options) -> Result<Self> {
        let mut t = serialport::new(options.path, options.baud_rate)
            .parity(options.parity.into())
            .stop_bits(options.stop_bits.into())
            .data_bits(options.data_bits.into())
            .open_native()?;

        #[cfg(target_os = "linux")]
        serialport_low_latency::enable_low_latency(&mut t).unwrap();

        // SAFETY: We keep the TTYPort around, so the OwnedFd doesn't get invalidated
        let fd = unsafe { OwnedFd::from_raw_fd(t.as_raw_fd()) };
        tcflush(&fd, FlushArg::TCIOFLUSH).unwrap();

        Ok(Self { _t: t, s: Async::new(fd)? })
    }

    /// Split into independent TX and RX halves.
    ///
    /// Each half owns a dup'd file descriptor, so reads and writes can proceed
    /// concurrently. The original `AsyncSerialPort` (and its `TTYPort`) is
    /// consumed to ensure the serial port settings remain valid for the
    /// lifetime of both halves.
    pub fn split(self) -> Result<(AsyncSerialPortTx, AsyncSerialPortRx)> {
        let dup_owned = nix::unistd::dup(self.s.as_fd()).map_err(std::io::Error::from)?;
        let tx = AsyncSerialPortTx { s: Async::new(dup_owned)? };
        // Consume self, keeping _t alive via the rx half's implicit lifetime.
        // The original fd is owned by self.s which we move into rx.
        let rx = AsyncSerialPortRx { s: self.s };
        // Leak _t so the TTYPort stays alive (its Drop would close the fd)
        core::mem::forget(self._t);
        Ok((tx, rx))
    }
}

impl embedded_io_async::ErrorType for AsyncSerialPort {
    type Error = Error;
}

impl embedded_io_async::Read for AsyncSerialPort {
    async fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, Self::Error> {
        // NOTE: can't use io.read() directly because serialport tries to poll
        // with a timeout by itself which doesn't work when using epoll
        unsafe {
            self.s
                .read_with_mut(|io| nix::unistd::read(io.as_fd(), buf).map_err(|e| e.into()))
                .await
                .map_err(|e| e.into())
        }
    }
}

impl embedded_io_async::Write for AsyncSerialPort {
    async fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, Self::Error> {
        // NOTE: can't use io.write() directly because serialport tries to poll
        // with a timeout by itself which doesn't work when using epoll
        unsafe {
            self.s
                .write_with_mut(|io| nix::unistd::write(io.as_fd(), buf).map_err(|e| e.into()))
                .await
                .map_err(|e| e.into())
        }
    }

    async fn flush(&mut self) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}

impl embedded_io_async::ErrorType for AsyncSerialPortTx {
    type Error = Error;
}

impl embedded_io_async::Write for AsyncSerialPortTx {
    async fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, Self::Error> {
        unsafe {
            self.s
                .write_with_mut(|io| nix::unistd::write(io.as_fd(), buf).map_err(|e| e.into()))
                .await
                .map_err(|e| e.into())
        }
    }

    async fn flush(&mut self) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}

impl embedded_io_async::ErrorType for AsyncSerialPortRx {
    type Error = Error;
}

impl embedded_io_async::Read for AsyncSerialPortRx {
    async fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, Self::Error> {
        unsafe {
            self.s
                .read_with_mut(|io| nix::unistd::read(io.as_fd(), buf).map_err(|e| e.into()))
                .await
                .map_err(|e| e.into())
        }
    }
}
