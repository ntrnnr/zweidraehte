//! Application Program Equivalence Testing
//!
//! This module provides tools for comparing KNX ApplicationProgram definitions
//! to verify semantic and structural equivalence between:
//! - DSL-generated programs and manufacturer reference XML
//! - Two different XML files
//!
//! # Comparison Modes
//!
//! ## Semantic Equivalence (Default)
//! - Match entities by semantic keys (memory offset, object number)
//! - Ignore ID string differences
//! - Ignore element ordering within collections
//! - Focus on "does it behave the same?"
//!
//! ## Structural Equivalence (Optional)
//! - Additionally compare element ordering
//! - Compare ID correspondence structure
//! - Useful for verifying generator output matches manufacturer patterns
//!
//! # Example
//!
//! ```rust,ignore
//! use crate::equivalence::{EquivalenceChecker, ComparisonConfig};
//!
//! let checker = EquivalenceChecker::from_xml_files(
//!     "reference.xml",
//!     "generated.xml",
//! )?;
//!
//! let report = checker.compare(&ComparisonConfig::default());
//! if report.has_differences() {
//!     println!("{}", report);
//! }
//! ```

mod canonical;
mod comparison;
mod memory;
mod visibility;

// Only the driver surface is re-exported here; the modules reach each other
// through `super::`, so a glob re-export would just be dead weight.
pub use canonical::CanonicalProgram;
pub use comparison::{ComparisonConfig, EquivalenceChecker};
