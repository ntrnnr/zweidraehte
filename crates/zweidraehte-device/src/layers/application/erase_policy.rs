//! Erase-code availability is fixed by the application-layer composition.
//!
//! Security Mode and requester authorization are separate runtime checks.

use crate::restart::EraseCode;

mod private {
    pub trait Sealed {}
    impl Sealed for super::PlainEraseCodes {}
    impl Sealed for super::SecureEraseCodes {}
}

/// Compile-time erase-code availability for an application layer.
///
/// Sealed to the plain and Data Secure policies: the secure wrapper must
/// always enforce the profile's exclusions, regardless of Security Mode.
pub trait EraseCodePolicy: private::Sealed {
    /// Whether this composition implements the code, before access checks.
    fn supports(code: EraseCode) -> bool;
}

/// Base profiles allow every recognized erase code, subject to access checks.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlainEraseCodes;

/// Data Secure forbids ResetIA and ResetAP (06 Profiles §9.1.2.5.1).
#[derive(Debug, Default, Clone, Copy)]
pub struct SecureEraseCodes;

impl EraseCodePolicy for PlainEraseCodes {
    fn supports(code: EraseCode) -> bool {
        !matches!(code, EraseCode::Other(_))
    }
}

impl EraseCodePolicy for SecureEraseCodes {
    fn supports(code: EraseCode) -> bool {
        !matches!(code, EraseCode::Other(_) | EraseCode::ResetIA | EraseCode::ResetAP)
    }
}
