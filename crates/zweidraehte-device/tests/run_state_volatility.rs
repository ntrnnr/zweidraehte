//! The Application Program run state must not survive a device reset.
//!
//! 03/05/01 §4.24.2.2 requires the run state to live in volatile memory, and
//! §4.24.2.3.3 note d) starts every reset in `Halted`. A persisted
//! `Terminated` would survive a restart and block the power-up cascade in
//! `SystemBDeviceModel::init`, which is what vendor conformance case 2.5.6
//! tests.
//!
//! This lives in its own integration test rather than beside the other run
//! state machine tests in `objects::tables::app`: naming a serde format
//! inside the lib test target makes `impl PartialEq<Value> for u8` visible,
//! which breaks `.into()` type inference in the neighbouring table tests.

use zweidraehte_device::objects::tables::{
    Application, HasLoadStateMachine, HasRunStateMachine, LoadEvent, RunEvent, RunState,
};

#[test]
fn run_state_does_not_survive_serialization() {
    let mut app: Application<()> = Application::new();

    // Load and start, then terminate — the one run state that would be
    // damaging to restore.
    app.write_lsm(&[LoadEvent::StartLoading.into()], None);
    app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
    app.handle_run_event(RunEvent::Loaded);
    app.handle_run_event(RunEvent::ReadyToRun);
    assert!(app.is_running());

    app.write_rsm(&[RunEvent::Stop.into()]);
    assert_eq!(app.run_state(), RunState::Terminated);

    let snapshot = serde_json::to_string(&app).expect("Application is Serialize");
    assert!(!snapshot.contains("run_state"), "run state leaked into the persisted snapshot: {snapshot}");

    let restored: Application<()> = serde_json::from_str(&snapshot).expect("snapshot round-trips");
    assert_eq!(restored.run_state(), RunState::Halted);

    // The load state is persistent, so the startup cascade still has an
    // application to start.
    assert!(restored.is_loaded());
}
