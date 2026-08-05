//! Client error types.

use core::net::SocketAddrV4;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::apdu::restart::RestartError;
use zweidraehte_proto::messages::knxip::ConnectionStatus;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("tunnel connection to {addr} refused: {status}")]
    ConnectionRefused { addr: SocketAddrV4, status: ConnectionStatus },

    #[error("tunnel disconnected by server")]
    Disconnected,

    #[error("connection lost: heartbeat unanswered")]
    HeartbeatLost,

    #[error("request timed out")]
    Timeout,

    #[error("tunnel ACK timeout after retransmission")]
    AckTimeout,

    #[error("negative L_Data confirmation from bus")]
    NegativeConfirmation,

    #[error("transport connection to {0} failed")]
    TransportConnectFailed(IndividualAddress),

    #[error("transport connection closed by the device")]
    TransportClosed,

    #[error("a transport connection is already open (one at a time)")]
    ConnectionBusy,

    #[error("another request is already in flight")]
    RequestInFlight,

    #[error("unexpected response")]
    UnexpectedResponse,

    #[error("device returned error (return code {0:#x})")]
    DeviceError(u8),

    #[error("device rejected restart: {0}")]
    RestartRefused(RestartError),

    #[error("memory verify mismatch at address {address:#06x}")]
    VerifyMismatch { address: u16 },

    #[error("parse error: {0}")]
    Parse(&'static str),

    #[error("USB interface error: {0}")]
    Usb(String),

    #[error("secure MAC verification failed (wrong key or tampered frame)")]
    SecurityMacMismatch,

    #[error("S-A_Sync handshake timed out (no sync response from device)")]
    SecuritySyncTimeout,

    #[error("device is marked Secure in the keyring but has neither tool key nor FDSK")]
    SecurityMissingKey,

    #[error("bus task terminated")]
    WorkerGone,
}

pub type Result<T> = core::result::Result<T, Error>;
