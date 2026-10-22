//! Failures produced by connectors and management services.

use core::net::SocketAddrV4;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::apdu::restart::RestartError;
use zweidraehte_proto::messages::knxip::ConnectionStatus;

#[derive(Debug, thiserror::Error)]
pub enum BusError {
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

    #[error("filter-table memory access requires A_FilterTable_Open first")]
    FilterTableNotOpen,

    /// The request combines options no single service provides, such as a
    /// Verify Mode check on extended memory or a secure programming-mode write.
    #[error("unsupported request: {0}")]
    Unsupported(&'static str),

    #[error("no device answered for the requested serial number")]
    SerialDeviceNotFound,

    #[error("{0} devices answered for the same serial number")]
    DuplicateSerialNumber(usize),

    #[error("individual address {0} is already occupied")]
    IndividualAddressOccupied(IndividualAddress),

    #[error("serial address write did not verify as {expected} (observed {actual:?})")]
    SerialAddressVerification { expected: IndividualAddress, actual: Option<IndividualAddress> },

    #[error("no device is in programming mode")]
    ProgrammingDeviceNotFound,

    #[error("{0} devices are in programming mode")]
    MultipleProgrammingDevices(usize),

    #[error("programming-mode address write did not verify as {0}")]
    ProgrammingAddressVerification(IndividualAddress),

    #[error("no configured management credential can access the device")]
    ManagementAccessUnavailable,

    #[error("programming verification failed: {0}")]
    ProgrammingVerification(String),

    #[error("device returned error (return code {0:#x})")]
    DeviceError(u8),

    /// A classic `A_PropertyValue_Response` reported failure with count zero.
    ///
    /// Unlike extended property services, the classic response carries no
    /// return code that distinguishes a missing property, an access denial,
    /// or a value that does not fit in the response APDU.
    #[error("property {property_id} on interface object {object_index} is unavailable")]
    PropertyValueUnavailable { object_index: u8, property_id: u16 },

    #[error("device rejected restart: {0}")]
    RestartRefused(RestartError),

    #[error("memory verify mismatch at address {address:#x}")]
    VerifyMismatch { address: u32 },

    #[error("parse error: {0}")]
    Parse(&'static str),

    #[error("USB interface error: {0}")]
    Usb(String),

    #[error("secure MAC verification failed (wrong key or tampered frame)")]
    SecurityMacMismatch,

    #[error("S-A_Sync handshake timed out (no sync response from device)")]
    SecuritySyncTimeout,

    #[error("secure system-broadcast data requires a synchronized credential")]
    SecuritySyncRequired,

    #[error("device is marked Secure in the keyring but has neither tool key nor FDSK")]
    SecurityMissingKey,

    #[error("bus task terminated")]
    WorkerGone,
}

pub type BusResult<T> = core::result::Result<T, BusError>;
