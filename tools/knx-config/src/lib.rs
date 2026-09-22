//! Shared plumbing for the `knx-dump` / `knx-loader` binaries: loading
//! product data for inspection, resolving the mask layer, and rendering a
//! topology-only project guide. Actual project devices are always selected
//! from an imported `.knxprod` catalogue by `knx-loader` or the TUI. Everything
//! with product *semantics* lives in the libraries
//! (`zweidraehte_ets_files::runtime::configuration` and
//! `zweidraehte_client::project`); these binaries stay glue.

pub mod dump;
pub mod load;
