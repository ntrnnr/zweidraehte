//! Security intent, observed application state, and management access are
//! independent: a disabled application can still require secure management.

/// Exhaustive by design: an observation is unknown, disabled or enabled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ObservedDataSecurity {
    #[default]
    Unknown,
    Disabled,
    Enabled,
}

/// Requested application state, independently of management credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DesiredDataSecurity {
    Preserve,
    Disabled,
    Enabled,
}
