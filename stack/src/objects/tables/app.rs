//! Application Program Object table implementation.
//!
//! The Application Program Object (Object Type 3) is unique among table objects
//! because it has both a Load State Machine and a Run State Machine:
//!
//! - **Load State Machine**: Controls loading/unloading of application data
//!   (same as Address Table, Association Table, etc.)
//! - **Run State Machine**: Controls execution state of the application
//!   (HALTED, RUNNING, READY, TERMINATED)
//!
//! # Type Structure
//!
//! The types compose as follows:
//! - `ApplicationImpl<D>` - Raw memory storage (implements `TableMemory`)
//! - `Table<ApplicationImpl<D>>` - Adds load state machine (implements `LoadableTable`)
//! - `RunnableApplication<Table<ApplicationImpl<D>>>` - Adds run state machine (implements `RunnableTable`)
//!
//! The type alias `Application<D>` provides the complete stack.

use const_default::ConstDefault;

use super::{RunnableApplication, Table, TableMemory};

/// Inner implementation for application data storage.
///
/// Generic over `D`, which is application-specific data that can be stored
/// alongside the application program object.
#[derive(Debug, ConstDefault)]
pub struct ApplicationImpl<D: ConstDefault> {
    _data: D,
}

impl<D: ConstDefault> TableMemory for ApplicationImpl<D> {
    fn data_ref(&self) -> &[u8] {
        &[]
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        &mut []
    }

    fn max_size() -> usize {
        core::mem::size_of::<D>()
    }

    fn read(&self, _offset: usize, _data: &mut [u8]) {}

    fn write(&mut self, _offset: usize, _data: &[u8]) {}
}

/// Application Program table with both Load and Run state machines.
///
/// This type composes:
/// - `ApplicationImpl<D>` for memory storage
/// - `Table<_>` wrapper for load state machine
/// - `RunnableApplication<_>` wrapper for run state machine
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte::objects::tables::app::Application;
///
/// // Create an application with no extra data
/// let mut app: Application<()> = Application::new();
///
/// // Load the application
/// app.write_lsm(&[LoadEvent::StartLoading.into()], None);
/// app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
/// assert!(app.is_loaded());
///
/// // Start running
/// app.write_rsm(&[RunEvent::Restart.into()]);
/// assert!(app.is_running());
/// ```
pub type Application<D> = RunnableApplication<Table<ApplicationImpl<D>>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::tables::{LoadEvent, LoadState, LoadableTable, RunEvent, RunState, RunnableTable};

    #[test]
    fn test_initial_state() {
        let app: Application<()> = Application::new();
        assert_eq!(app.read_lsm()[0], LoadState::Unloaded.into());
        assert_eq!(app.run_state(), RunState::Halted);
    }

    #[test]
    fn test_restart_when_not_loaded() {
        let mut app: Application<()> = Application::new();

        // RESTART when not loaded should stay HALTED
        app.write_rsm(&[RunEvent::Restart.into()]);
        assert_eq!(app.run_state(), RunState::Halted);
    }

    #[test]
    fn test_stop_transitions_to_terminated() {
        let mut app: Application<()> = Application::new();

        // STOP from HALTED should go to TERMINATED
        app.write_rsm(&[RunEvent::Stop.into()]);
        assert_eq!(app.run_state(), RunState::Terminated);
    }

    #[test]
    fn test_restart_after_load() {
        let mut app: Application<()> = Application::new();

        // Start loading
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        assert_eq!(app.read_lsm()[0], LoadState::Loading.into());

        // Complete loading
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        assert_eq!(app.read_lsm()[0], LoadState::Loaded.into());

        // RESTART when loaded should transition to RUNNING
        app.write_rsm(&[RunEvent::Restart.into()]);
        assert_eq!(app.run_state(), RunState::Running);
    }

    #[test]
    fn test_unload_resets_run_state() {
        let mut app: Application<()> = Application::new();

        // Load the application
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        // Start running
        app.write_rsm(&[RunEvent::Restart.into()]);
        assert_eq!(app.run_state(), RunState::Running);

        // Unload should reset run state to HALTED
        app.write_lsm(&[LoadEvent::Unload.into()], None);
        assert_eq!(app.read_lsm()[0], LoadState::Unloaded.into());
        assert_eq!(app.run_state(), RunState::Halted);
    }

    #[test]
    fn test_no_op_preserves_state() {
        let mut app: Application<()> = Application::new();

        // NO_OP should preserve HALTED
        app.write_rsm(&[RunEvent::NoOp.into()]);
        assert_eq!(app.run_state(), RunState::Halted);

        // Load and start running
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        app.write_rsm(&[RunEvent::Restart.into()]);
        assert_eq!(app.run_state(), RunState::Running);

        // NO_OP should preserve RUNNING
        app.write_rsm(&[RunEvent::NoOp.into()]);
        assert_eq!(app.run_state(), RunState::Running);
    }

    #[test]
    fn test_unknown_event_preserves_state() {
        let mut app: Application<()> = Application::new();

        // Unknown event (0xFF) should preserve state
        app.write_rsm(&[0xFF]);
        assert_eq!(app.run_state(), RunState::Halted);
    }

    #[test]
    fn test_restart_from_terminated_when_not_loaded() {
        let mut app: Application<()> = Application::new();

        // Go to TERMINATED
        app.write_rsm(&[RunEvent::Stop.into()]);
        assert_eq!(app.run_state(), RunState::Terminated);

        // RESTART from TERMINATED when not loaded should go to HALTED
        app.write_rsm(&[RunEvent::Restart.into()]);
        assert_eq!(app.run_state(), RunState::Halted);
    }
}
