//! Test harnesses for conformance testing
//!
//! The conformance harness uses a multi-process architecture:
//! - The parent (conformance-runner) owns device state in shared memory
//!   and runs the test loop
//! - The child (conformance-dut) runs the actual KNX stack, communicating
//!   with the parent over a Unix socketpair
//! - On restart, the child exits and is respawned, destroying all volatile
//!   state (transport connections, programming mode, etc.) while persistent
//!   state survives in shared memory

pub mod ipc;
pub mod mock;
pub mod multiprocess;
pub mod secure_stack;
pub mod stack;

pub use mock::CapturedLinkLayerMessage;
pub use multiprocess::MultiProcessHarness;
