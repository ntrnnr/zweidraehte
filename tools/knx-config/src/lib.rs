//! Shared plumbing for the `knx-dump` / `knx-loader` binaries: loading
//! a product file (loose MTXML or `.knxprod`), resolving the mask
//! layer, and rendering a one-device project skeleton. Everything with
//! product *semantics* lives in the libraries
//! (`zweidraehte_ets_files::runtime::configuration` and
//! `zweidraehte_client::project`); these binaries stay glue.

pub mod dump;
pub mod load;
