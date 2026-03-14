// Re-export from the shared error module so existing `knxip::error::*` imports
// continue to work unchanged.
pub use crate::messages::error::{ParseError, ParseResult};

/// Error type for an unrecognized protocol code of type `T`.
#[derive(Debug, Eq, PartialEq)]
pub struct UnrecognizedProtocolCode<T>(pub T);
