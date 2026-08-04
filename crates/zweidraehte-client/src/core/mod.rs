//! Sans-io protocol cores.
//!
//! Nothing in here touches a socket, spawns a task, or reads a clock —
//! time comes in as parameters, I/O goes out as returned effects/frames.
//! The tokio side lives in [`connector`](crate::connector) and
//! [`driver`](crate::driver).

pub mod frames;
pub mod group;
pub mod management;
pub mod session;
pub mod tl_client;
