#![cfg_attr(not(any(test, feature = "knxprod")), no_std)]
#![feature(adt_const_params)]

#[cfg(feature = "full")]
pub mod ip_interface;
pub mod light_switch;

// Host-side demo devices (std): full device definitions with ETS page
// layouts, used by the demo/generator binaries. Gated because they pull
// in `zweidraehte-knxprod`, the Linux platform, and the shared support
// crate — none of which exist for the embedded firmware consumers.
#[cfg(feature = "demos")]
pub mod mdt_push_button_lite;
#[cfg(feature = "demos")]
pub mod module_test_device;
#[cfg(feature = "demos")]
pub mod system_b_demo;
