//! Errors from product lowering do not require project storage or live I/O.

/// Invalid installation values or product data encountered during lowering.
#[derive(Debug, thiserror::Error)]
pub enum ConfigurationError {
    #[error("device configuration invalid: {0}")]
    DeviceConfiguration(String),
    #[error("product data: {0}")]
    ProductData(String),
}

/// Result of lowering product and installation data into compiler inputs.
pub type ConfigurationResult<T> = core::result::Result<T, ConfigurationError>;
