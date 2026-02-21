//! System control for Cortex-M devices.
//!
//! Implements [`SystemControl`] by triggering a Cortex-M system reset.

use platform::SystemControl;

/// System control for Cortex-M based devices.
pub struct CortexMSystem;

#[derive(Debug, defmt::Format)]
pub struct SystemError;

impl SystemControl for CortexMSystem {
    type Error = SystemError;

    async fn restart(&mut self) -> Result<!, Self::Error> {
        defmt::info!("System restart requested, resetting...");
        // Brief delay to let any in-flight log output drain.
        embassy_time::Timer::after(embassy_time::Duration::from_millis(100)).await;
        cortex_m::peripheral::SCB::sys_reset();
    }
}
