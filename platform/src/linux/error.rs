#[derive(Debug)]
pub enum Error {
    IOError(std::io::Error),
    SerialportError(serialport::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::IOError(err) => write!(f, "IO Error: {:?}", &err),
            Self::SerialportError(err) => write!(f, "Serialport Error: {:?}", &err),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IOError(err)
    }
}

impl From<serialport::Error> for Error {
    fn from(err: serialport::Error) -> Self {
        Self::SerialportError(err)
    }
}

impl From<Error> for crate::Error {
    fn from(err: Error) -> Self {
        Self::LinuxPlatformError(err)
    }
}

impl From<std::io::Error> for crate::Error {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::WouldBlock => Self::Timeout,
            _ => Self::LinuxPlatformError(Error::IOError(err)),
        }
    }
}

impl From<serialport::Error> for crate::Error {
    fn from(err: serialport::Error) -> Self {
        Self::LinuxPlatformError(Error::SerialportError(err))
    }
}

//impl From<embassy_time::TimeoutError> for crate::Error {
//    fn from(_: embassy_time::TimeoutError) -> Self {
//        Self::Timeout
//    }
//}
