use core::fmt::Debug;

/// System control operations.
///
/// Provides platform-specific system operations like restarting the
/// application process. On Linux this re-executes the current binary
/// via `exec()`, on embedded targets this triggers a system reset.
pub trait SystemControl {
    type Error: Debug;

    /// Perform an application restart.
    ///
    /// On Linux, this re-executes the current process, closing all file
    /// descriptors except stdin/stdout/stderr to avoid leaking resources.
    ///
    /// On embedded targets, this triggers a system reset (e.g. via SCB).
    ///
    /// This method should not return under normal circumstances.
    async fn restart(&mut self) -> Result<!, Self::Error>;
}
