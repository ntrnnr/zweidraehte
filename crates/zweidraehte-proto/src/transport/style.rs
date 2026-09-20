//! Type-level selection of the profile's transport state machine.

use super::{ConnectionCore, ProcessResult, TlEvent, TlStyle, sm};

/// Compile-time transport-style selection shared by device stacks.
///
/// Each device selects one marker type. Transition dispatch then reaches only
/// that style's specialized entry point; no runtime style field is needed.
/// Storage, timers and I/O remain the embedder's responsibility.
///
/// This type-level policy is an architectural requirement: preserve it through
/// classification and table lookup so fixed-profile devices need only their
/// selected machine. Do not replace it with a stored [`TlStyle`] value when
/// sharing or simplifying the device path.
///
/// A runtime style value cannot satisfy a device's type-level selection:
///
/// ```compile_fail,E0277
/// use zweidraehte_proto::transport::{TransportStyle, TlStyle};
/// fn device_style<S: TransportStyle>() {}
/// device_style::<TlStyle>(); // the enum is not a concrete style implementation
/// ```
pub trait TransportStyle: 'static {
    /// Descriptive metadata, including support for outgoing connections.
    const STYLE: TlStyle;

    /// Process a transition, leaving state application deferred until after
    /// the embedder has executed the returned actions.
    fn process<C: ConnectionCore>(conn: &mut C, event: TlEvent) -> ProcessResult;
}

/// Style 1: strict recovery with NACK and retransmission (BCU2).
#[derive(Debug, Default, Clone, Copy)]
pub struct Style1;

/// Style 2: lenient recovery (BCU1).
#[derive(Debug, Default, Clone, Copy)]
pub struct Style2;

/// Style 3: also supports outgoing connections (System 7 and System B).
#[derive(Debug, Default, Clone, Copy)]
pub struct Style3;

/// Rationalised Style 1: no NACK or retransmission, only a connection timer.
#[derive(Debug, Default, Clone, Copy)]
pub struct Style1Rationalised;

impl TransportStyle for Style1 {
    const STYLE: TlStyle = TlStyle::Style1;

    fn process<C: ConnectionCore>(conn: &mut C, event: TlEvent) -> ProcessResult {
        sm::process_event_style1(conn, event)
    }
}

impl TransportStyle for Style2 {
    const STYLE: TlStyle = TlStyle::Style2;

    fn process<C: ConnectionCore>(conn: &mut C, event: TlEvent) -> ProcessResult {
        sm::process_event_style2(conn, event)
    }
}

impl TransportStyle for Style3 {
    const STYLE: TlStyle = TlStyle::Style3;

    fn process<C: ConnectionCore>(conn: &mut C, event: TlEvent) -> ProcessResult {
        sm::process_event_style3(conn, event)
    }
}

impl TransportStyle for Style1Rationalised {
    const STYLE: TlStyle = TlStyle::Style1Rationalised;

    fn process<C: ConnectionCore>(conn: &mut C, event: TlEvent) -> ProcessResult {
        sm::process_event_style1_rationalised(conn, event)
    }
}
