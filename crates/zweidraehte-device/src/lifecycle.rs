//! Stack-level lifecycle events.
//!
//! [`LifecycleEvent`] is published on
//! [`Stack::lifecycle_events()`](crate::Stack::lifecycle_events) when the
//! application or PEI run state machines transition into or out of the
//! RUNNING state, and when the application layer's read-on-init scan
//! settles. The events bridge AL run-state machinery and user code; they
//! do not belong to the communication-object layer.
//!
//! The actual `PubSubChannel` lives on
//! [`LayerContext`](crate::context::layer::LayerContext); the event is
//! emitted by [`DeviceModel`](crate::device_model::DeviceModel) for
//! Application/PEI run-state transitions and by the AL group-data
//! provider for `ReadOnInitComplete`.

/// Events emitted when a program lifecycle state changes.
///
/// These events are published through
/// [`Stack::lifecycle_events()`](crate::Stack::lifecycle_events) whenever a
/// run state machine transitions into or out of the RUNNING state, including
/// transitions caused by load state machine cascades (e.g., ETS programming
/// completing and automatically starting the application).
///
/// Both the Application Program Object and the PEI Program Object have run
/// state machines and emit their own pair of events. User code targeting
/// modern devices should typically only react to the `Application*` variants;
/// the `Pei*` variants are surfaced for completeness so that tools observing
/// the full ETS programming cascade can see both halves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecycleEvent {
    /// The application program transitioned to RUNNING.
    ///
    /// This is the appropriate time to:
    /// - Read ETS parameters and configure application behavior
    /// - Set initial output states
    /// - Send initial group value read requests for status objects
    /// - Start periodic timers
    ApplicationStarted,

    /// The application program transitioned out of RUNNING (to HALTED, READY, or TERMINATED).
    ///
    /// This is the appropriate time to:
    /// - Stop timers and periodic tasks
    /// - Set outputs to a safe state
    /// - Clean up application-level resources
    ApplicationStopped,

    /// The PEI (Physical External Interface) program transitioned to RUNNING.
    ///
    /// This stack currently supplies no Application Program 2, so the event is
    /// surfaced for observability but has no required user-side handling.
    PeiStarted,

    /// The PEI program transitioned out of RUNNING.
    PeiStopped,

    /// The application layer's read-on-init scan has settled — either it
    /// ran to completion (`ReadOnInitState::Done`) or the preconditions
    /// weren't met on this startup and the state machine stayed `Idle`.
    ///
    /// Fires exactly once per AL startup cycle, from
    /// `GroupDataProvider::poll`. The guard flag resets when the app
    /// transitions back out of the running state, so a subsequent
    /// startup re-fires the event.
    ///
    /// Observers:
    /// - The conformance IPC harness uses this to know when it can
    ///   transition from "draining startup ROI frames" to step-driven
    ///   mode. User code rarely needs to care — `ApplicationStarted`
    ///   and comm-object events cover the vast majority of startup
    ///   scenarios.
    ReadOnInitComplete,
}

/// Subscribe to the stack's lifecycle events and log each one, forever.
///
/// The shared body of the `lifecycle_task` every device firmware spawns —
/// embassy tasks cannot be generic, so each binary keeps a monomorphic
/// `#[embassy_executor::task]` wrapper that just awaits this:
///
/// ```ignore
/// #[embassy_executor::task]
/// async fn lifecycle_task(knx: Stack<'static, MyDevice>) -> ! {
///     zweidraehte_device::lifecycle::lifecycle_event_logger(knx).await
/// }
/// ```
///
/// A device that *reacts* to lifecycle transitions (rather than only logging
/// them) writes its own loop over
/// [`Stack::lifecycle_events()`](crate::Stack::lifecycle_events) instead.
pub async fn lifecycle_event_logger<D: crate::definition::StackDefinition>(knx: crate::Stack<'static, D>) -> ! {
    let mut events = knx.lifecycle_events();
    loop {
        match events.next_message_pure().await {
            LifecycleEvent::ApplicationStarted => crate::logging::info!("Application STARTED"),
            LifecycleEvent::ApplicationStopped => crate::logging::info!("Application STOPPED"),
            LifecycleEvent::PeiStarted => crate::logging::info!("PEI STARTED"),
            LifecycleEvent::PeiStopped => crate::logging::info!("PEI STOPPED"),
            _ => {}
        }
    }
}
