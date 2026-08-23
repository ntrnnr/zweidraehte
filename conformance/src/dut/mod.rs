//! The device under test: everything that runs in the *child* process.
//!
//! A conformance DUT is not a mock — it is the real device stack, built
//! the way a firmware target builds it, over an IPC link layer instead
//! of a TPUART. That is the point of the multi-process design: the
//! parent cannot accidentally reach into device state and answer its own
//! questions, because the device lives in another address space and the
//! only channel is [`crate::ipc`].
//!
//! Behind the **`dut` cargo feature**, which is what makes that boundary
//! a compile error rather than a convention. This module is the crate's
//! only user of `zweidraehte-device`, `zweidraehte-knxprod` and embassy,
//! so `cargo check -p zweidraehte-conformance --no-default-features`
//! builds the parent half plus the `conformance-runner` and
//! `conformance-eitt` binaries with none of them as direct dependencies
//! — which is enough to make a parent-side `use zweidraehte_device::…`
//! fail to resolve. If that check starts failing, something on the
//! parent side has reached across.
//!
//! # Contents
//!
//! - [`common`] — the plumbing every TP1 DUT binary shares: argv, the
//!   IPC-forwarding logger, the SHM boot snapshot, erase-code dispatch,
//!   the exit sequence
//! - [`link`] — the DUT's KNX link layer over the IPC socket (a
//!   `LinkLayerBuilder`, so the stack sits on it unmodified)
//! - [`fixture_common`] — family-neutral fixture vocabulary: the
//!   conformance application's constants, the certification object, the
//!   shm sequence store shared by the secure DUTs
//! - one stack definition per family and security level —
//!   [`systemb_stack`], [`systemb_secure_stack`], [`system7_stack`],
//!   [`system7_secure_stack`], and [`ip_secure_stack`] for the KNX IP
//!   Secure DUT (which talks over real loopback sockets, not the IPC
//!   channel, and so uses none of `common` or `link`)
//! - [`system_b_product`] / [`system7_product`] — each DUT's `.knxprod`
//!   product data, generated in-process from the same constants that
//!   build its stack, for `conformance-configuration`'s download
//!   round-trip. They live on this side because they describe the
//!   device, which is why that one runner binary also carries
//!   `required-features = ["dut"]`.

pub mod bcu1_stack;
pub mod bcu2_light_switch_product;
pub mod bcu2_product;
pub mod bcu2_secure_stack;
pub mod bcu2_stack;
pub mod common;
pub mod fixture_common;
pub mod ip_secure_stack;
pub mod link;
pub mod micro_system7_product;
pub mod micro_system7_stack;
pub mod system7_product;
pub mod system7_secure_stack;
pub mod system7_stack;
pub mod system_b_product;
pub mod systemb_secure_stack;
pub mod systemb_stack;
