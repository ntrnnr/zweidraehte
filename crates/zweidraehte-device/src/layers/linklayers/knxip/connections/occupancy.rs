//! Live tunnel-slot occupancy counter.
//!
//! Published by [`TunnelConnectionHandler`](super::tunnel::TunnelConnectionHandler)
//! on every connect/disconnect; read by the composite IP-Interface
//! address checker to decide whether to over-ACK group frames.

use portable_atomic::{AtomicU8, Ordering::Relaxed};

/// Counts how many tunnel connections are currently open.
///
/// Storage lives in [`KnxNetIpResources`](super::super::KnxNetIpResources)
/// so it outlives both the tunnel handler (which mutates it) and the
/// address checker (which reads it).
///
/// `Relaxed` ordering is sufficient. The only consumer reads
/// [`any_open`](Self::any_open) on the TPUART hot path; a race that
/// straddles a connect/disconnect transition costs at most one
/// spurious or missed bus ACK, which TP1 tolerates.
pub struct TunnelOccupancy {
    count: AtomicU8,
}

impl TunnelOccupancy {
    pub const fn new() -> Self {
        Self { count: AtomicU8::new(0) }
    }

    /// `true` if at least one tunnel connection is currently open.
    pub fn any_open(&self) -> bool {
        self.count.load(Relaxed) > 0
    }

    pub(super) fn on_connect(&self) {
        self.count.fetch_add(1, Relaxed);
    }

    /// Saturating decrement — guards against double-close races where
    /// a slot is freed via two different teardown paths (e.g.
    /// DISCONNECT_REQUEST racing with TCP close).
    pub(super) fn on_disconnect(&self) {
        let _ = self.count.fetch_update(Relaxed, Relaxed, |v| (v > 0).then_some(v - 1));
    }
}

impl Default for TunnelOccupancy {
    fn default() -> Self {
        Self::new()
    }
}
