//! Test harnesses for conformance testing
//!
//! The conformance harness uses a multi-process architecture:
//! - The parent (conformance-runner) owns device state in shared memory
//!   and runs the test loop
//! - The child (conformance-dut-systemb) runs the actual KNX stack, communicating
//!   with the parent over a Unix socketpair
//! - On restart, the child exits and is respawned, destroying all volatile
//!   state (transport connections, programming mode, etc.) while persistent
//!   state survives in shared memory

pub mod client_bridge;
pub mod fixture_common;
pub mod frame_source;
pub mod framing;
pub mod ip_secure_stack;
pub mod ipc;
pub mod lifecycle;
pub mod protocol;
pub mod shm;
pub mod system7_product;
pub mod system7_secure_stack;
pub mod system7_stack;
pub mod system_b_product;
pub mod systemb_secure_stack;
pub mod systemb_stack;

pub use frame_source::CapturedLinkLayerMessage;
pub use lifecycle::{ChildLifecycle, DutMode};
