//! Connection-oriented transport layer state machine (KNX spec 03/03/04 §5.4)
//!
//! This module holds the *pure* part of the transport layer: the four
//! spec-defined state machine styles as static transition tables, the
//! event/action vocabulary, and [`process_event`] which drives one
//! connection through them. There is no I/O, no timers, and no clock in
//! here — timer handling is expressed as [`TlAction::StartAckTimer`]-style
//! actions that the embedding runtime executes.
//!
//! It lives in `zweidraehte-proto` (rather than the device stack) because
//! the state machine is symmetric: the same tables describe the server side
//! (a device accepting a connection from ETS) and the client side (a
//! management client opening a connection to a device, Style 3's
//! CONNECTING state). The device stack in `zweidraehte-device` and the
//! management client in `zweidraehte-client` both build on this module.
//!
//! # Architecture
//!
//! ```text
//! TlEvent ──→ classify_event() ──→ SpecEvent
//!                                      │
//!                          transition table lookup
//!                                      │
//!                                      ▼
//!                               (SpecAction, next_state)
//!                                      │
//!                          execute_action() maps to
//!                                      │
//!                                      ▼
//!                              ActionBuffer<TlAction>
//! ```
//!
//! Embedders provide the per-connection bookkeeping (sequence numbers,
//! remote address, state) through the [`ConnectionCore`] trait; the device
//! stack implements it on its richer `Connection` slot type, while
//! [`BasicConnection`] is a minimal ready-made implementation for clients
//! and tests.

mod connection_core;
mod events;
mod sm;

pub use connection_core::{BasicConnection, ConnectionCore, ConnectionState};
pub use events::{ActionBuffer, MAX_REPETITIONS, ProcessResult, TlAction, TlEvent, TlStyle};
pub use sm::process_event;
