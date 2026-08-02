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
//!
//! # Soundness requirements for `D`
//!
//! `D` must implement [`zerocopy::IntoBytes`] (guaranteed no padding bytes and all
//! bit patterns are valid `u8` values), [`zerocopy::KnownLayout`], and
//! [`zerocopy::Immutable`]. These bounds are enforced at compile time on
//! [`ApplicationImpl`].
//!
//! ## Why `IntoBytes`?
//!
//! `data_ref` and `data_ref_mut` expose the raw bytes of `_data: D` as a `&[u8]`
//! slice. Reading padding bytes — bytes that `#[repr(C)]` inserts between fields to
//! satisfy alignment — as `u8` is undefined behaviour in the Rust abstract machine
//! because padding bytes are considered "uninitialised". `IntoBytes` requires that a
//! type has **no padding bytes**, eliminating this hazard entirely.
//!
//! ## Write-path validity (known limitation)
//!
//! The table-download write path (`TableMemory::write` → `data_ref_mut`) can install
//! arbitrary byte patterns into `_data`. For types that contain `#[repr(u8)]` or
//! `#[repr(u16)]` enums this means invalid discriminants could be loaded, which is
//! undefined behaviour the moment `params()` returns `&D`.
//!
//! A fully validated write path would require [`zerocopy::TryFromBytes`] on `D`. This
//! cannot currently be derived for the `#[repr(C, u8)]` data-carrying enums produced
//! by `#[derive(EtsUnion)]` — zerocopy's derive macro rejects `#[repr(C, u8)]`
//! outright. Therefore the write-path validity guarantee is documented as a **caller
//! responsibility**: device firmware should only allow ETS to load a well-formed
//! application image, and the conformance test harness only loads trusted byte images.
//!
//! The stack transition from `LoadState::Loading` → `LoadState::Loaded` (via
//! `LoadCompleted`) does NOT currently validate the downloaded bytes. A future
//! improvement could add a validation hook here once `TryFromBytes` support lands in
//! zerocopy for the affected repr forms.

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use zerocopy::{Immutable, IntoBytes, KnownLayout};

use super::{LoadControlPolicy, RelativeAlloc, RunnableApplication, Table, TableMemory};

/// Inner implementation for application data storage.
///
/// Generic over `D`, the application-specific parameter struct stored inside
/// the application program object. `D` must implement:
///
/// - [`zerocopy::IntoBytes`] — no padding bytes, all bytes are defined. This
///   ensures `data_ref` does not read uninitialized padding.
/// - [`zerocopy::KnownLayout`] — required by `IntoBytes`.
/// - [`zerocopy::Immutable`] — no interior mutability, required for safe shared
///   byte-level access.
///
/// Derive all three; never hand-write `unsafe impl IntoBytes`. Union fields
/// declared with `#[ets_union]` are padded and `IntoBytes`-checked by that
/// macro, so a param struct containing them derives cleanly. A hand-written
/// impl only asserts the invariant — and historically asserted it falsely,
/// putting uninitialized bytes on the bus through `data_ref`.
///
/// # Compile-fail example
///
/// A type with niche-carrying fields or interior mutability is rejected:
///
/// ```compile_fail
/// # use zweidraehte_device::objects::tables::app::ApplicationImpl;
/// # use const_default::ConstDefault;
/// use core::cell::Cell;
///
/// // Cell<u8> is not Immutable — ApplicationImpl<D> must reject it.
/// #[derive(ConstDefault)]
/// struct BadParams {
///     value: Cell<u8>,
/// }
///
/// // This must not compile: Cell<u8> violates the Immutable bound.
/// fn _check(_: ApplicationImpl<BadParams>) {}
/// ```
#[derive(Debug, Clone, ConstDefault, Serialize, Deserialize)]
pub struct ApplicationImpl<D: ConstDefault + IntoBytes + KnownLayout + Immutable> {
    _data: D,
}

impl<D: ConstDefault + IntoBytes + KnownLayout + Immutable> ApplicationImpl<D> {
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

impl<D: ConstDefault + IntoBytes + KnownLayout + Immutable> TableMemory for ApplicationImpl<D> {
    fn data_ref(&self) -> &[u8] {
        // Using zerocopy::IntoBytes::as_bytes avoids the padding-read UB that
        // the previous from_raw_parts approach had: IntoBytes guarantees no
        // padding bytes, so every byte in the slice is a defined value.
        self._data.as_bytes()
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        // SAFETY:
        // - `IntoBytes` guarantees no padding bytes, so every byte in the
        //   returned slice corresponds to a field byte (not an uninitialized gap).
        // - `as_mut_bytes()` is not available without `FromBytes` (which would
        //   require all bit patterns to be valid — too strong for enum fields).
        //   We use the raw pointer form instead: this is safe because IntoBytes
        //   already guarantees the absence of padding, and writing arbitrary byte
        //   patterns into individual field bytes (e.g. a single octet of a `u8`
        //   enum) does not produce UB by itself until the written value is
        //   interpreted as `D` via `params()`. See the module-level documentation
        //   for the write-path validity contract.
        unsafe {
            core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(self._data).cast::<u8>(), core::mem::size_of::<D>())
        }
    }

    const MAX_SIZE: usize = core::mem::size_of::<D>();

    /// The application program's load state machine owns every segment
    /// of the application — on System 7 that is the group object table
    /// *and* the parameter block, each larger than or unrelated to the
    /// params struct backing this table. The allocation records are
    /// acknowledgements of the product database's fixed layout; each
    /// region is bounds-checked by its own memory window when the
    /// bytes arrive.
    fn accepts_segment(_len: usize) -> bool {
        true
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
/// use zweidraehte_device::objects::tables::app::Application;
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
pub type Application<D, P = RelativeAlloc> = RunnableApplication<Table<ApplicationImpl<D>, P>>;

impl<D: ConstDefault + IntoBytes + KnownLayout + Immutable, P: LoadControlPolicy> Application<D, P> {
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

/// PEI (Physical External Interface) Program Object with Load and Run state machines.
///
/// PEI is a vestigial KNX specification artifact from older BCU designs where
/// external interface hardware (serial ports, etc.) had its own separately loadable
/// program. Modern System B devices (mask 07B0 and similar) don't use PEI programs,
/// but ETS still expects the interface object to be present and sends load/unload
/// commands to it during device programming.
///
/// This type is instantiated with empty data `()` because there is no actual PEI
/// program to store. The load and run state machines transition normally when ETS
/// writes to them, but **no stack behavior depends on PEI's state** — unlike the
/// application program object, whose run state gates access to group objects and
/// communication services.
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
/// Object 6: IP Parameter Object (if KNX/IP)
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

    /// STOP against an unloaded application leaves it HALTED.
    ///
    /// 03/05/01 §4.24.2.3.3 note c): the Stop event leads to Terminated, but
    /// "this shall only be possible if the corresponding Load State Machine is
    /// in the state Loaded". Vendor conformance case 2.2.4 tests this
    /// directly and expects HALTED back.
    #[test]
    fn test_stop_when_unloaded_stays_halted() {
        let mut app: Application<()> = Application::new();
        assert!(!app.is_loaded());

        app.write_rsm(&[RunEvent::Stop.into()]);
        assert_eq!(app.run_state(), RunState::Halted);
    }

    #[test]
    fn test_stop_when_loaded_transitions_to_terminated() {
        let mut app: Application<()> = Application::new();
        load_and_start(&mut app);

        app.write_rsm(&[RunEvent::Stop.into()]);
        assert_eq!(app.run_state(), RunState::Terminated);
    }

    /// Helper: load and start an application (simulates DeviceModel cascade).
    fn load_and_start(app: &mut Application<()>) {
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        app.handle_run_event(RunEvent::Loaded);
        app.handle_run_event(RunEvent::ReadyToRun);
    }

    #[test]
    fn test_load_completes_to_running() {
        let mut app: Application<()> = Application::new();

        // Start loading
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        assert_eq!(app.read_lsm()[0], LoadState::Loading.into());
        assert_eq!(app.run_state(), RunState::Halted);

        // Complete loading — LSM is now Loaded, RSM still Halted (no cascade)
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        assert_eq!(app.read_lsm()[0], LoadState::Loaded.into());
        assert_eq!(app.run_state(), RunState::Halted);

        // DeviceModel cascade: Loaded → Ready, ReadyToRun → Running
        app.handle_run_event(RunEvent::Loaded);
        assert_eq!(app.run_state(), RunState::Ready);
        app.handle_run_event(RunEvent::ReadyToRun);
        assert_eq!(app.run_state(), RunState::Running);
    }

    /// RESTART with the executable part loaded ends in RUNNING, from any state.
    ///
    /// 03/05/01 §4.24.2.3.3 Table 97 spells the transition
    /// `I:Halted → I:Ready → M:Running`; only the last is mandatory, and
    /// §4.24.2.4 notes the intermediates may never appear. Vendor conformance
    /// case 2.5.2 pins the write response to RUNNING with no wildcard.
    #[test]
    fn test_restart_when_loaded_goes_to_running() {
        let mut app: Application<()> = Application::new();
        load_and_start(&mut app);
        assert_eq!(app.run_state(), RunState::Running);

        app.write_rsm(&[RunEvent::Restart.into()]);
        assert_eq!(app.run_state(), RunState::Running);
    }

    /// The other of the two ways out of TERMINATED (03/05/01 Table 95): the
    /// vendor conformance 2.5.2 shape.
    #[test]
    fn test_restart_from_terminated_when_loaded() {
        let mut app: Application<()> = Application::new();
        load_and_start(&mut app);

        app.write_rsm(&[RunEvent::Stop.into()]);
        assert_eq!(app.run_state(), RunState::Terminated);

        app.write_rsm(&[RunEvent::Restart.into()]);
        assert_eq!(app.run_state(), RunState::Running);
    }

    #[test]
    fn test_unload_resets_run_state() {
        let mut app: Application<()> = Application::new();
        load_and_start(&mut app);
        assert_eq!(app.run_state(), RunState::Running);

        // DeviceModel signals Unloaded on LSM unload → RSM goes to HALTED
        app.handle_run_event(RunEvent::Unloaded);
        assert_eq!(app.run_state(), RunState::Halted);

        // LSM unload separately
        app.write_lsm(&[LoadEvent::Unload.into()], None);
        assert_eq!(app.read_lsm()[0], LoadState::Unloaded.into());
    }

    #[test]
    fn test_ready_preserves_state() {
        let mut app: Application<()> = Application::new();

        // Ready event should preserve HALTED
        app.write_rsm(&[RunEvent::Ready.into()]);
        assert_eq!(app.run_state(), RunState::Halted);

        // Load and start running
        load_and_start(&mut app);
        assert_eq!(app.run_state(), RunState::Running);

        // Ready event should preserve RUNNING
        app.write_rsm(&[RunEvent::Ready.into()]);
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

        // TERMINATED is only reachable while loaded (note c), so get there
        // first and then take the load state away underneath it. `write_lsm`
        // does not cascade, so the run state survives the unload here.
        load_and_start(&mut app);
        app.write_rsm(&[RunEvent::Stop.into()]);
        assert_eq!(app.run_state(), RunState::Terminated);

        app.write_lsm(&[LoadEvent::Unload.into()], None);
        assert!(!app.is_loaded());
        assert_eq!(app.run_state(), RunState::Terminated);

        // RESTART from TERMINATED when not loaded should go to HALTED
        app.write_rsm(&[RunEvent::Restart.into()]);
        assert_eq!(app.run_state(), RunState::Halted);
    }

    /// The internal run events share a byte space with the three writable
    /// ones (03/05/01 §4.24.2.3.2 Table 96 defines only 00h–02h), so a write
    /// of 03h/04h/05h to PID_RUN_STATE_CONTROL must be treated as an unknown
    /// event and ignored — not decoded as Loaded / Unloaded / ReadyToRun.
    #[test]
    fn test_internal_run_events_are_not_writable_from_the_bus() {
        let mut app: Application<()> = Application::new();
        load_and_start(&mut app);
        assert_eq!(app.run_state(), RunState::Running);

        // Would be `Unloaded` if the wire byte reached `RunEvent::from`,
        // which would drop a running application to HALTED.
        assert_eq!(app.write_rsm(&[0x04]), None);
        assert_eq!(app.run_state(), RunState::Running);

        for byte in [0x03u8, 0x05, 0x06, 0x7F, 0xFF] {
            assert_eq!(app.write_rsm(&[byte]), None, "0x{byte:02X} should be ignored");
            assert_eq!(app.run_state(), RunState::Running);
        }
    }

    // The matching assertion that the run state does not survive
    // serialization lives in `tests/run_state_volatility.rs`: naming a serde
    // format inside the lib test target makes `impl PartialEq<Value> for u8`
    // visible and breaks `.into()` inference across the other table tests.

    // ====================================================================
    // RunAction production tests
    // ====================================================================

    use crate::objects::tables::{LoadAction, RunAction};

    #[test]
    fn test_write_lsm_returns_load_action() {
        let mut app: Application<()> = Application::new();

        assert_eq!(app.write_lsm(&[LoadEvent::StartLoading.into()], None), LoadAction::LoadStart);
        assert_eq!(app.write_lsm(&[LoadEvent::LoadCompleted.into()], None), LoadAction::LoadEnd);
    }

    #[test]
    fn test_write_lsm_does_not_cascade_to_rsm() {
        let mut app: Application<()> = Application::new();

        // write_lsm no longer cascades into the RSM. After loading, the
        // RSM stays in Halted — the DeviceModel must orchestrate the cascade.
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        assert!(app.is_loaded());
        assert_eq!(app.run_state(), RunState::Halted); // Not Running!
    }

    #[test]
    fn test_handle_run_event_loaded_then_ready_to_run() {
        let mut app: Application<()> = Application::new();

        // Load the app (LSM side only)
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        assert!(app.is_loaded());
        assert_eq!(app.run_state(), RunState::Halted);

        // DeviceModel orchestrates the cascade:
        let ev = app.handle_run_event(RunEvent::Loaded);
        assert_eq!(app.run_state(), RunState::Ready);
        assert_eq!(ev, None); // Not running yet

        let ev = app.handle_run_event(RunEvent::ReadyToRun);
        assert_eq!(app.run_state(), RunState::Running);
        assert_eq!(ev, Some(RunAction::Started));
    }

    #[test]
    fn test_handle_run_event_unloaded() {
        let mut app: Application<()> = Application::new();

        // Load and start running (manual cascade)
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        app.handle_run_event(RunEvent::Loaded);
        app.handle_run_event(RunEvent::ReadyToRun);
        assert!(app.is_running());

        // Unload — RSM transitions Running → Halted
        let ev = app.handle_run_event(RunEvent::Unloaded);
        assert_eq!(app.run_state(), RunState::Halted);
        assert_eq!(ev, Some(RunAction::Stopped));
    }

    #[test]
    fn test_write_rsm_stop_produces_stopped() {
        let mut app: Application<()> = Application::new();

        // Load and start running (manual cascade)
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        app.handle_run_event(RunEvent::Loaded);
        app.handle_run_event(RunEvent::ReadyToRun);
        assert!(app.is_running());

        // Stop via PID 6 write
        let ev = app.write_rsm(&[RunEvent::Stop.into()]);
        assert_eq!(app.run_state(), RunState::Terminated);
        assert_eq!(ev, Some(RunAction::Stopped));
    }

    /// A restart of an already-running application crosses no observable
    /// boundary, but Table 97 routes it through the intermediate Halted and
    /// Ready states — it really did stop and start again. The device model
    /// needs to hear about it to reset the communication objects and re-arm
    /// read-on-init, which is how an ETS download ends.
    #[test]
    fn test_restart_of_running_app_still_produces_started() {
        let mut app: Application<()> = Application::new();
        load_and_start(&mut app);
        assert!(app.is_running());

        assert_eq!(app.write_rsm(&[RunEvent::Restart.into()]), Some(RunAction::Started));
        assert_eq!(app.run_state(), RunState::Running);
    }

    #[test]
    fn test_noop_transitions_produce_no_action() {
        let mut app: Application<()> = Application::new();

        // Unloaded throughout, so none of these reach RUNNING.
        assert_eq!(app.write_rsm(&[RunEvent::Ready.into()]), None);
        assert_eq!(app.write_rsm(&[RunEvent::Restart.into()]), None);
        assert_eq!(app.write_rsm(&[0xFF]), None);
    }

    #[test]
    fn test_startup_cascade_on_preloaded_app() {
        let mut app: Application<()> = Application::new();

        // Load app, start it, then stop (simulating a previous session)
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        app.handle_run_event(RunEvent::Loaded);
        app.handle_run_event(RunEvent::ReadyToRun);
        app.write_rsm(&[RunEvent::Stop.into()]);
        assert!(!app.is_running());
        assert!(app.is_loaded());

        // Simulate restart from persistent storage
        let mut app2 = RunnableApplication::from_table(app.inner().clone());
        assert!(!app2.is_running());
        assert!(app2.is_loaded());

        // DeviceModel startup cascade: Loaded → Ready → ReadyToRun → Running
        app2.handle_run_event(RunEvent::Loaded);
        let ev = app2.handle_run_event(RunEvent::ReadyToRun);
        assert!(app2.is_running());
        assert_eq!(ev, Some(RunAction::Started));
    }
}
