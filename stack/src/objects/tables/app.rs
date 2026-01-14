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
//! - `Table<ApplicationImpl<D>>` - Adds load state machine (implements `HasLoadStateMachine`)
//! - `RunnableApplication<Table<ApplicationImpl<D>>>` - Adds run state machine (implements `HasRunStateMachine`)
//!
//! The type alias `Application<D>` provides the complete stack.

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};

use super::{RunnableApplication, Table, TableMemory};

/// Inner implementation for application data storage.
///
/// Generic over `D`, which is application-specific data that can be stored
/// alongside the application program object.
#[derive(Debug, Clone, ConstDefault, Serialize, Deserialize)]
pub struct ApplicationImpl<D: ConstDefault> {
    _data: D,
}

impl<D: ConstDefault> ApplicationImpl<D> {
    /// Get a type-safe reference to the application parameters.
    ///
    /// This provides direct access to the stored data without going through byte slices.
    pub fn params(&self) -> &D {
        &self._data
    }

    /// Get a type-safe mutable reference to the application parameters.
    ///
    /// This provides direct mutable access to the stored data.
    pub fn params_mut(&mut self) -> &mut D {
        &mut self._data
    }
}

impl<D: ConstDefault> TableMemory for ApplicationImpl<D> {
    fn data_ref(&self) -> &[u8] {
        // SAFETY: D is stored in memory as contiguous bytes, and we're creating
        // a read-only byte slice from it. The lifetime is tied to &self.
        unsafe { core::slice::from_raw_parts(&self._data as *const D as *const u8, core::mem::size_of::<D>()) }
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        // SAFETY: D is stored in memory as contiguous bytes, and we're creating
        // a mutable byte slice from it. The lifetime is tied to &mut self.
        unsafe { core::slice::from_raw_parts_mut(&mut self._data as *mut D as *mut u8, core::mem::size_of::<D>()) }
    }

    fn max_size() -> usize {
        core::mem::size_of::<D>()
    }

    fn read(&self, offset: usize, data: &mut [u8]) {
        let src = self.data_ref();
        let end = (offset + data.len()).min(src.len());
        if offset < src.len() {
            let copy_len = end - offset;
            data[..copy_len].copy_from_slice(&src[offset..end]);
        }
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        let dst = self.data_ref_mut();
        let end = (offset + data.len()).min(dst.len());
        if offset < dst.len() {
            let copy_len = end - offset;
            dst[offset..end].copy_from_slice(&data[..copy_len]);
        }
    }
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

impl<D: ConstDefault> Application<D> {
    /// Get a type-safe reference to the application parameters.
    ///
    /// This provides direct access to your application data struct without going through byte slices.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let app: Application<MyAppParams> = Application::new();
    /// let params: &MyAppParams = app.params();
    /// let value = params.some_field;
    /// ```
    pub fn params(&self) -> &D {
        self.inner().table.params()
    }

    /// Get a type-safe mutable reference to the application parameters.
    ///
    /// This allows you to modify your application data directly.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut app: Application<MyAppParams> = Application::new();
    /// let params: &mut MyAppParams = app.params_mut();
    /// params.some_field = 42;
    /// ```
    pub fn params_mut(&mut self) -> &mut D {
        self.inner_mut().table.params_mut()
    }
}

/// PEI (Platform Extension Interface) Program Object with Load and Run state machines.
///
/// For System B devices (mask 57B0), the PEI Program Object is Interface Object 5,
/// positioned between the Application Program Object (4) and IP Parameter Object (6).
///
/// This object provides proper state machine infrastructure for ETS compatibility,
/// even for devices that don't use platform-specific extensions. It is instantiated
/// with empty data `()` but still provides the required LOAD_STATE_CONTROL and
/// RUN_STATE_CONTROL properties that ETS expects.
///
/// # KNX Object Structure
///
/// ```text
/// Object 0: Device Object
/// Object 1: Address Table Object
/// Object 2: Association Table Object
/// Object 3: Group Object Table Object
/// Object 4: Application Program Object
/// Object 5: PEI Program Object (this type)
/// Object 6: IP Parameter Object
/// ```
pub type PeiApplication = RunnableApplication<Table<ApplicationImpl<()>>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::tables::{HasLoadStateMachine, HasRunStateMachine, LoadEvent, LoadState, RunEvent, RunState};

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
