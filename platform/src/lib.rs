pub mod serialport;

#[cfg(feature = "linux")]
mod linux;

#[cfg(feature = "linux")]
pub use linux::{AsyncSerialPort, Error as LinuxError, Result as LinuxResult};

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
            #[cfg(target_os = "linux")]
            Self::LinuxPlatformError(err) => write!(f, "Linux platform error: {:?}", &err),

            Self::Timeout => write!(f, "Timeout"),
            Self::UnexpectedEof => write!(f, "Unexpected EOF while reading"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl embedded_io_async::Error for Error {
    fn kind(&self) -> embedded_io_async::ErrorKind {
        embedded_io_async::ErrorKind::Other
    }
}

pub type Result<T> = core::result::Result<T, Error>;
