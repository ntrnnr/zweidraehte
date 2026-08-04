//! Pluggable bus connectors.
//!
//! A connector is the client's access path onto a KNX network: KNX/IP
//! tunneling today, USB next, routing/TPUART/secure variants later. It
//! transports **raw cEMI frames** in both directions — all transport
//! framing (TunnelingRequest wrapping and acknowledgement, USB HID
//! transfer frames and fragmentation) is internal to the connector, as is
//! any local device management needed to bring the interface up (EMI-type
//! negotiation on USB, the MAX_APDU feature query on tunneling).
//!
//! A future IP Secure connector wraps the plain tunneling connector and
//! adds the session handshake + `SecureWrapper` around every packet —
//! same trait, same driver.

use zweidraehte_proto::address::IndividualAddress;

use crate::error::Result;

mod ip_tunnel;
mod usb;

pub use ip_tunnel::IpTunnelConnector;
pub use usb::{UsbConnector, UsbSelector};

/// What the driver learns from a connector once it is open.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorInfo {
    /// The individual address this bus access sends from (the tunnel's
    /// assigned additional IA, or the USB interface's own address).
    pub assigned_address: IndividualAddress,
    /// The interface-side maximum APDU length. The effective limit towards
    /// a target device is `min(this, device max APDU from PID 56)`.
    pub max_apdu: u16,
}

/// A bus access transporting raw cEMI frames.
///
/// `recv_cemi` doubles as the connector's service loop: connectors with
/// background protocol duties (tunnel heartbeat, ACK timers) run them
/// while the driver awaits the next frame, so the driver must keep a
/// `recv_cemi` call pending whenever it is otherwise idle. Both `send_cemi`
/// and `recv_cemi` service those duties, so no separate pump is needed.
/// The methods return explicit `impl Future + Send` (instead of `async
/// fn`) so the bus task driving a connector can itself be spawned on a
/// multi-threaded executor.
pub trait KnxConnector: Send + 'static {
    /// Send one cEMI frame to the bus. Resolves once the interface has
    /// accepted it (e.g. the TunnelingAck arrived), not when any bus-side
    /// confirmation does — those come back through `recv_cemi` as
    /// L_Data.con frames.
    fn send_cemi(&mut self, cemi: &[u8]) -> impl Future<Output = Result<()>> + Send;

    /// Receive the next cEMI frame from the bus (L_Data.ind / L_Data.con).
    ///
    /// Cancel-safe: dropping the future loses no frames.
    fn recv_cemi(&mut self) -> impl Future<Output = Result<Vec<u8>>> + Send;

    /// Close the bus access gracefully.
    fn close(&mut self) -> impl Future<Output = Result<()>> + Send;
}
