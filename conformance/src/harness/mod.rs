//! The test harness: everything that runs in the *parent* process.
//!
//! The conformance harness is multi-process:
//!
//! - the parent (`conformance-runner`, `conformance-eitt`,
//!   `conformance-configuration`) owns the device state in shared memory
//!   and runs the test loop;
//! - the child (`conformance-dut-*`, [`crate::dut`]) runs the actual KNX
//!   stack;
//! - the two talk over a Unix socketpair plus that shared memory
//!   ([`crate::ipc`]).
//!
//! On restart the child exits and is respawned, destroying all volatile
//! state — transport connections, programming mode, and so on — while
//! persistent state survives in shared memory. That is the whole reason
//! for the process split: a restart the device stack cannot distinguish
//! from a real one.
//!
//! # What belongs here
//!
//! Driving the child, not being it. This module names no device-stack
//! type and starts no executor: [`ChildLifecycle`] spawns the DUT binary
//! by name, and its view of device state is the opaque byte region in
//! [`crate::ipc::shm`] — the DUT seeds its own factory defaults into a
//! blank one, so not even "what does a factory snapshot look like" is
//! known on this side.
//!
//! Keeping it that way is checked, not just intended: the DUT half is
//! behind the `dut` cargo feature, so under `cargo check -p
//! zweidraehte-conformance --no-default-features` the device stack is
//! not a direct dependency and `use zweidraehte_device::…` here stops
//! resolving. (It is still *in* the build graph — `zweidraehte-client`
//! pulls `zweidraehte-knxprod`, which uses the device crate's ETS
//! descriptor types. Transitive dependencies are not in the extern
//! prelude, so the boundary holds at the source level regardless.)
//!
//! The one concurrent construct on this side is `async-io`-backed, so
//! the parent stays runtime-agnostic; the runner binaries happen to be
//! `#[tokio::main]`, but nothing here requires that.

pub mod client_bridge;
pub mod frame_source;
pub mod lifecycle;

pub use frame_source::CapturedLinkLayerMessage;
pub use lifecycle::{ChildLifecycle, DutMode};
