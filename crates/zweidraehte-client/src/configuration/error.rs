//! Errors from product lowering do not require project storage or live I/O.

/// Human-readable detail of a failure whose category is the enclosing variant.
///
/// Callers match on the variant and display the detail. The text has no
/// stable structure, and only this crate constructs one, so frontends report
/// their own failures with their own error types instead of borrowing ours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDetail(String);

impl ErrorDetail {
    pub(crate) fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }
}

impl std::fmt::Display for ErrorDetail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Product data that cannot be lowered into compiler inputs.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigurationError {
    #[error("product data: {0}")]
    ProductData(ErrorDetail),
}

/// Result of lowering product and installation data into compiler inputs.
pub type ConfigurationResult<T> = core::result::Result<T, ConfigurationError>;
