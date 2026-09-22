//! KNX/IP tunneling connector: a thin tokio I/O shell around the sans-io
//! [`TunnelSession`].
//!
//! The shell owns the UDP socket and executes the session's effects; every
//! protocol decision (sequence numbers, ACK retries, heartbeat, disconnect
//! handling) is made by the state machine in
//! [`crate::connector::ip_tunnel::session`]. Received cEMI frames and send completions are
//! buffered in queues, which keeps `recv_cemi` cancel-safe: a dropped
//! future leaves the frame in the inbox for the next call.

use std::collections::VecDeque;
use std::net::{SocketAddr, SocketAddrV4};
use std::time::Instant;

use tokio::net::UdpSocket;

use crate::bus::{BusError as Error, BusResult as Result};
use crate::connector::ip_tunnel::session::{Effect, SessionError, TunnelSession};
use crate::connector::{ConnectorInfo, KnxConnector};
use zweidraehte_proto::messages::knxip::substructs::HPAI;
use zweidraehte_proto::messages::knxip::{KNXnetIPServiceType, peek_service_type};

/// Maximum size of a KNXnet/IP packet we expect to receive.
const MAX_PACKET_SIZE: usize = 512;

pub struct IpTunnelConnector {
    socket: UdpSocket,
    server: SocketAddrV4,
    session: TunnelSession,
    /// UDP packets the session asked us to send, not yet on the wire.
    outbox: VecDeque<Vec<u8>>,
    /// Received cEMI frames awaiting a `recv_cemi` call.
    inbox: VecDeque<Vec<u8>>,
    /// FIFO completions for `send_cemi` calls in flight.
    completions: VecDeque<core::result::Result<(), SessionError>>,
    /// First fatal session error; sticky — every later call reports it.
    fatal: Option<SessionError>,
    closed: bool,
}

impl IpTunnelConnector {
    /// Open a tunneling connection to a KNX/IP interface.
    pub async fn connect(server: SocketAddrV4) -> Result<(Self, ConnectorInfo)> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let (session, effects) = TunnelSession::start(Instant::now());

        let mut connector = Self {
            socket,
            server,
            session,
            outbox: VecDeque::new(),
            inbox: VecDeque::new(),
            completions: VecDeque::new(),
            fatal: None,
            closed: false,
        };
        let mut opened = connector.process_effects(effects);

        // Drive the handshake until the session reports Opened (the
        // connect timeout inside the session bounds this loop).
        while opened.is_none() {
            if let Some(err) = connector.fatal {
                return Err(connector.map_error(err));
            }
            opened = connector.drive_once().await?;
        }

        let info = opened.expect("loop exits only with Some");
        Ok((connector, info))
    }

    /// Execute one batch of session effects. Returns the `Opened` info if
    /// this batch contained it.
    fn process_effects(&mut self, effects: Vec<Effect>) -> Option<ConnectorInfo> {
        let mut opened = None;
        for effect in effects {
            match effect {
                Effect::Send(packet) => self.outbox.push_back(packet),
                Effect::DeliverCemi(cemi) => self.inbox.push_back(cemi),
                Effect::SendComplete(result) => self.completions.push_back(result),
                Effect::Opened { assigned_address, max_apdu } => {
                    opened = Some(ConnectorInfo { assigned_address, max_apdu });
                }
                Effect::Fatal(err) => self.fatal = Some(err),
                Effect::Closed => self.closed = true,
            }
        }
        opened
    }

    /// One step of the I/O loop: flush pending packets, then wait for
    /// either a received packet or the session's next timer.
    ///
    /// Cancel-safe: packets stay queued until their `send_to` succeeded
    /// (at worst a cancelled step re-sends one packet, which the tunneling
    /// protocol tolerates as a repeat), and received frames land in queues
    /// before this returns.
    async fn drive_once(&mut self) -> Result<Option<ConnectorInfo>> {
        while let Some(packet) = self.outbox.front() {
            let endpoint = if is_tunnel_packet(packet) {
                data_endpoint(self.server, self.session.data_endpoint())
            } else {
                self.server
            };
            self.socket.send_to(packet, SocketAddr::V4(endpoint)).await?;
            self.outbox.pop_front();
        }

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let effects = match self.session.next_deadline() {
            Some(deadline) => {
                match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), self.socket.recv_from(&mut buf))
                    .await
                {
                    Ok(received) => {
                        let (len, source) = received?;
                        self.handle_datagram(source, &buf[..len])
                    }
                    Err(_) => self.session.poll(Instant::now()),
                }
            }
            None => {
                let (len, source) = self.socket.recv_from(&mut buf).await?;
                self.handle_datagram(source, &buf[..len])
            }
        };

        Ok(self.process_effects(effects))
    }

    fn map_error(&self, err: SessionError) -> Error {
        match err {
            SessionError::Refused(status) => Error::ConnectionRefused { addr: self.server, status },
            SessionError::ConnectTimeout => Error::Timeout,
            SessionError::Malformed => Error::Parse("malformed CONNECT_RESPONSE"),
            SessionError::AckTimeout => Error::AckTimeout,
            SessionError::NegativeAck(_) => Error::NegativeConfirmation,
            SessionError::HeartbeatLost => Error::HeartbeatLost,
            SessionError::Disconnected => Error::Disconnected,
        }
    }

    fn handle_datagram(&mut self, source: SocketAddr, data: &[u8]) -> Vec<Effect> {
        if !accepts_source(self.server, self.session.data_endpoint(), source, data) {
            return Vec::new();
        }
        self.session.handle_packet(data, Instant::now())
    }
}

fn data_endpoint(server: SocketAddrV4, advertised: Option<HPAI>) -> SocketAddrV4 {
    match advertised {
        Some(HPAI::Ipv4Udp { addr, port }) => SocketAddrV4::new(
            if addr.is_unspecified() { *server.ip() } else { addr },
            if port == 0 { server.port() } else { port },
        ),
        _ => server,
    }
}

fn is_tunnel_packet(packet: &[u8]) -> bool {
    matches!(
        peek_service_type(packet),
        Ok(KNXnetIPServiceType::TunnelingRequest
            | KNXnetIPServiceType::TunnelingAck
            | KNXnetIPServiceType::TunnelingFeatureGet
            | KNXnetIPServiceType::TunnelingFeatureResponse
            | KNXnetIPServiceType::TunnelingFeatureSet
            | KNXnetIPServiceType::TunnelingFeatureInfo)
    )
}

fn accepts_source(server: SocketAddrV4, advertised: Option<HPAI>, source: SocketAddr, packet: &[u8]) -> bool {
    // Control traffic must come from the configured server. Tunnel traffic
    // also accepts its negotiated data endpoint; NAT zeros inherit the server.
    source == SocketAddr::V4(server)
        || is_tunnel_packet(packet) && source == SocketAddr::V4(data_endpoint(server, advertised))
}

impl KnxConnector for IpTunnelConnector {
    async fn send_cemi(&mut self, cemi: &[u8]) -> Result<()> {
        if let Some(err) = self.fatal {
            return Err(self.map_error(err));
        }
        let effects = self.session.send_cemi(cemi.to_vec(), Instant::now());
        self.process_effects(effects);

        loop {
            if let Some(result) = self.completions.pop_front() {
                return result.map_err(|e| self.map_error(e));
            }
            if let Some(err) = self.fatal {
                return Err(self.map_error(err));
            }
            self.drive_once().await?;
        }
    }

    async fn recv_cemi(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some(cemi) = self.inbox.pop_front() {
                return Ok(cemi);
            }
            if let Some(err) = self.fatal {
                return Err(self.map_error(err));
            }
            self.drive_once().await?;
        }
    }

    async fn close(&mut self) -> Result<()> {
        if self.fatal.is_some() || self.closed {
            return Ok(());
        }
        let effects = self.session.close(Instant::now());
        self.process_effects(effects);

        while !self.closed && self.fatal.is_none() {
            self.drive_once().await?;
        }
        Ok(())
    }
}

mod session;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn provenance_preserves_negotiated_and_nat_endpoints() {
        let server = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3671);
        let data = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4000);
        let advertised = Some(HPAI::Ipv4Udp { addr: *data.ip(), port: data.port() });
        let tunnel = [6, 0x10, 4, 0x20, 0, 6];
        let disconnect = [6, 0x10, 2, 9, 0, 6];
        assert!(accepts_source(server, advertised, server.into(), &tunnel));
        assert!(accepts_source(server, advertised, data.into(), &tunnel));
        assert!(!accepts_source(server, advertised, data.into(), &disconnect));
        assert!(!accepts_source(server, advertised, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999).into(), &tunnel));
        assert_eq!(data_endpoint(server, Some(HPAI::Ipv4Udp { addr: Ipv4Addr::UNSPECIFIED, port: 0 })), server);
    }
}
