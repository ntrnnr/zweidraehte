//! System control implementation for the Pico W.
//!
//! Implements [`SystemControl`] by triggering a Cortex-M system reset.

use platform::SystemControl;

/// System control for the Pico W (RP2040).
pub struct PicoWSystem;

#[derive(Debug, defmt::Format)]
pub struct SystemError;

impl SystemControl for PicoWSystem {
    type Error = SystemError;

    async fn restart(&mut self) -> Result<!, Self::Error> {
        defmt::info!("System restart requested, resetting...");
        // Brief delay to let any in-flight log output drain.
        embassy_time::Timer::after(embassy_time::Duration::from_millis(100)).await;
        cortex_m::peripheral::SCB::sys_reset();
    }
}
