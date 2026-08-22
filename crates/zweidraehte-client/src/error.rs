//! Client error types.

use core::net::SocketAddrV4;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::apdu::load_control::{LoadState, LsmMachine};
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

    #[error("{machine} load state still reads {state} after the procedure step (expected it to reach {expected})")]
    LoadState { machine: MachineRef, state: LoadState, expected: LoadState },

    #[error("device identity mismatch on object {obj_idx} property {prop_id}")]
    IdentityMismatch { obj_idx: u8, prop_id: u16 },

    #[error("property write verify mismatch on object {obj_idx} property {prop_id}")]
    PropertyVerifyMismatch { obj_idx: u8, prop_id: u16 },

    #[error("memory compare mismatch at address {address:#06x}")]
    CompareMismatch { address: u16 },

    #[error("download configuration invalid: {0}")]
    DownloadConfig(&'static str),

    #[error("master data: {0}")]
    MasterData(String),

    #[error("product data: {0}")]
    ProductData(String),

    #[error("cannot assemble the download procedure: {0}")]
    DownloadAssembly(String),

    #[error("unsupported download instruction: {0}")]
    UnsupportedInstruction(&'static str),

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

/// Which load state machine a [`Error::LoadState`] is about, in the
/// terms the failing path addressed it.
///
/// The two load-control paths identify machines differently, and the
/// error reports what the engine actually knows rather than guessing
/// a family-specific name: the memory path drives one of the four
/// mask-defined machines (a closed set proto names); the property
/// path drives whatever interface object the index selects, and since
/// the object roster is the device's, the index is the only
/// protocol-level identity there is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineRef {
    /// A machine of the memory-mapped System 7 path.
    Machine(LsmMachine),
    /// An interface object driven over `PID_LOAD_STATE_CONTROL`
    /// (System B).
    Object(u8),
    /// A profile-module object absent from the indexed roster.
    ObjectType { object_type: u16, occurrence: u16 },
}

impl core::fmt::Display for MachineRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Machine(machine) => write!(f, "the {machine}"),
            Self::Object(idx) => write!(f, "interface object {idx}"),
            Self::ObjectType { object_type, occurrence } => {
                write!(f, "interface object type {object_type:#06X}, occurrence {occurrence}")
            }
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
