//! Shared plumbing for the `knx-dump` / `knx-loader` binaries: loading
//! a product file (loose MTXML or `.knxprod`), resolving the mask
//! layer, and rendering the mods-file skeleton. Everything with
//! product *semantics* lives in the libraries
//! (`zweidraehte_knxprod::runtime::mods`,
//! `zweidraehte_client::download::mods`); these binaries stay glue.

pub mod dump;
pub mod load;
