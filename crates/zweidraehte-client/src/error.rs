//! Client error types.

use core::net::SocketAddrV4;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::knxip::ConnectionStatus;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("tunnel connection to {addr} refused: {status}")]
    ConnectionRefused { addr: SocketAddrV4, status: ConnectionStatus },

    #[error("tunnel disconnected by server")]
    Disconnected,

    #[error("request timed out")]
    Timeout,

    #[error("tunnel ACK timeout after retransmission")]
    AckTimeout,

    #[error("negative L_Data confirmation from bus")]
    NegativeConfirmation,

    #[error("transport connection to {0} failed")]
    TransportConnectFailed(IndividualAddress),

    #[error("transport connection closed unexpectedly")]
    TransportClosed,

    #[error("transport NACK (expected seq {expected}, got {actual})")]
    TransportNack { expected: u8, actual: u8 },

    #[error("unexpected response")]
    UnexpectedResponse,

    #[error("device returned error (return code {0:#x})")]
    DeviceError(u8),

    #[error("parse error: {0}")]
    Parse(&'static str),

    #[error("worker task terminated")]
    WorkerGone,
}

pub type Result<T> = core::result::Result<T, Error>;
