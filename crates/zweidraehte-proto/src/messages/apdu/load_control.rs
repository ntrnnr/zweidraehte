//! Load/Run State Machine wire enums.
//!
//! The pure protocol vocabulary of the load and run state machines:
//!
//! - [`LoadState`] / [`RunState`] — the state values read back from
//!   `PID_LOAD_STATE_CONTROL` / `PID_RUN_STATE_CONTROL`.
//! - [`LoadEvent`] / [`RunEvent`] — the control commands written to those
//!   properties (and the internal events the run machine reacts to).
//! - [`LoadSegment`] — the segment selector inside an `AdditionalLoadControls`
//!   load command.
//!
//! Only the wire encoding lives here. The state machines that consume and
//! transition these values (`Table<T>`, `RunnableApplication<T>`, the
//! `Has*StateMachine` traits, and the non-wire `LoadAction` / `RunAction` /
//! `LoadError` types) stay in the device crate's `objects::tables`.

use serde::{Deserialize, Serialize};

create_protocol_enum!(
    /// Load state of an interface object (`PID_LOAD_STATE_CONTROL` readback).
    #[derive(Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
    pub enum LoadState: u8 {
        Unloaded        , 0x00, "Unloaded";
        Loaded          , 0x01, "Loaded";
        Loading         , 0x02, "Loading";
        Err             , 0x03, "Error";
    }
);

create_protocol_enum!(
    /// Load control command written to `PID_LOAD_STATE_CONTROL`.
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum LoadEvent: u8 {
        NoOp                    , 0x00, "NoOp";
        StartLoading            , 0x01, "StartLoading";
        LoadCompleted           , 0x02, "LoadCompleted";
        AdditionalLoadControls  , 0x03, "AdditionalLoadControls";
        Unload                  , 0x04, "Unload";
        Err                     , 0x05, "Error";
        _,                              "Unknown Load Event 0x{:x}";
    }
);

create_protocol_enum!(
    /// Run state of the Application Program Object (`PID_RUN_STATE_CONTROL`
    /// readback). The application can only run once it is loaded.
    ///
    /// - `Halted` (0x00): not running; the default state when unloaded.
    /// - `Running` (0x01): running normally.
    /// - `Ready` (0x02): intermediate — conditions being checked before running.
    /// - `Terminated` (0x03): explicitly stopped via `RUNCONTROL_STOP`.
    #[derive(Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
    pub enum RunState: u8 {
        Halted          , 0x00, "Halted";
        Running         , 0x01, "Running";
        Ready           , 0x02, "Ready";
        Terminated      , 0x03, "Terminated";
    }
);

create_protocol_enum!(
    /// Event driving the run state machine of 03/05/01 §4.24.
    ///
    /// Only the first three are writable to `PID_RUN_STATE_CONTROL` (0x06);
    /// they are the whole of §4.24.2.3.2 Table 96:
    ///
    /// - `Ready` (0x00): no operation — state unchanged.
    /// - `Restart` (0x01): restart the application.
    /// - `Stop` (0x02): stop the application (→ `Terminated` if loaded).
    ///
    /// The rest are internal events raised by the device itself, and reuse
    /// the same byte space because nothing ever encodes them onto the wire:
    ///
    /// - `Loaded` (0x03): the load state machine finished loading.
    /// - `Unloaded` (0x04): the load state machine unloaded.
    /// - `ReadyToRun` (0x05): run conditions evaluated, the application may run.
    ///
    /// The overlap is why `HasRunStateMachine::write_rsm` decodes 0x00–0x02
    /// itself instead of handing the received byte to `RunEvent::from` — a
    /// management client must not be able to drive the internal events.
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum RunEvent: u8 {
        Ready           , 0x00, "Ready";
        Restart         , 0x01, "Restart";
        Stop            , 0x02, "Stop";
        Loaded          , 0x03, "Loaded";
        Unloaded        , 0x04, "Unloaded";
        ReadyToRun      , 0x05, "ReadyToRun";
        _,                      "Unknown Run Event 0x{:x}";
    }
);

create_protocol_enum!(
    /// Segment selector inside an `AdditionalLoadControls` load command.
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum LoadSegment: u8 {
        AbsoluteData            , 0x00, "AbsoluteData";
        AbsoluteStack           , 0x01, "AbsoluteStack";
        AbsoluteTask            , 0x02, "AbsoluteTask";
        AbsolutePointer         , 0x03, "AbsolutePointer";
        TaskCtrl1               , 0x04, "TaskCtrl1";
        TaskCtrl2               , 0x05, "TaskCtrl2";
        RelativeData            , 0x0b, "RelativeData";
        Err                     , 0x0c, "Error";
        _,                              "Unknown Load Segment 0x{:x}";
    }
);
