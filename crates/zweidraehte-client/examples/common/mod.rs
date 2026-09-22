//! The shared bus-target flags now live in the library's `cli`
//! module (select `--features cli` when running an example); this shim keeps every example's `mod
//! common;` include working unchanged.

#[allow(unused_imports)] // not every example uses every helper
pub use zweidraehte_client::cli::*;
