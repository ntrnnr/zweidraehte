//! Full-stack light-switch integration.
//!
//! The application adapter is shared by the full-stack firmware variants;
//! each firmware still owns its composable `StackDefinition`.

mod app;
pub mod easter_egg;

pub use app::*;
