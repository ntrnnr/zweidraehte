//! The wire between the two processes.
//!
//! The conformance crate is split across a process boundary: the parent
//! runs the tests ([`crate::harness`]) and a child runs the actual KNX
//! stack ([`crate::dut`]). This module is everything that crosses that
//! boundary, and it is the *only* code both halves compile:
//!
//! - [`protocol`] — the message types, pure serde
//! - [`framing`] — length-prefixed postcard over a `UnixStream`
//! - [`shm`] — the mmap region that survives a DUT respawn
//! - [`ip_secure`] — the one DUT that uses none of the above, and the
//!   env vars and key material that stand in for them
//!
//! # What belongs here
//!
//! Nothing that names a device-stack type, and nothing that assumes an
//! executor. `crate::dut` is behind the `dut` cargo feature and pulls in
//! `zweidraehte-device` plus embassy; `crate::harness` and everything
//! above it compile without either. Anything added here has to stay in
//! the intersection, which in practice means serde, `std`, `async-io`
//! and `nix`.
//!
//! That constraint is what keeps the parent's view of the DUT opaque —
//! the SHM payload is a `T: Serialize` the parent never names, and the
//! DUT seeds its own factory defaults into a blank region. See
//! [`shm`]'s module docs.
//!
//! Note the name split with `dut::link`: this module is the parent↔child
//! transport, that one is the DUT's KNX *link layer*, which happens to
//! ride on it. (Not an intra-doc link — `dut` is cfg'd out under
//! `--no-default-features`, and a link that only resolves half the time
//! is worse than none.)

pub mod framing;
pub mod ip_secure;
pub mod protocol;
pub mod shm;
