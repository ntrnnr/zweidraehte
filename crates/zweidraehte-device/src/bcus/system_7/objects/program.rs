//! Program objects for System 7 devices.
//!
//! Two program objects with the same property surface:
//!
//! - **Application Program** (Object Type 3, index 3)
//! - **Interface Program** (Object Type 4, index 4), optional for 0705.
//!
//! Differences from the System B objects they mirror:
//!
//! - Mask-specific access levels from Annex A.2.6/A.2.7's 0705h column:
//!   these management properties use controller level 3 for both reads and
//!   writes, despite the profile's unauthorised runtime level being 15.
//! - No allocation address: the absolute-segment records carry their own
//!   addresses, so `write_lsm` gets `None`.

use core::cell::{Cell, RefCell};

use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{
    InterfaceObjectType, PDT_Control, PDT_Generic05, PDT_Generic08, PDT_UnsignedChar, PDT_UnsignedLong,
};
use zweidraehte_proto::properties::PropertyError;

use crate::device_model::{DeviceModelEvent, DeviceModelNotifier, RunTarget};
use crate::objects::interface::{WriteResponse, interface_object, pid};
use crate::objects::tables::{HasLoadStateMachine, HasRunStateMachine, LoadAction, RunConditions, RunEvent};
use zweidraehte_proto::messages::apdu::load_control::{LoadState, TaskSegment};

/// One arm of the shared LSM/RSM write plumbing: apply the load event,
/// cascade the resulting run event, notify the device model.
///
/// An accepted absolute task segment also sets PID_PROGRAM_VERSION: System 7
/// downloads never write that property (03/05/03 §3.9.2), and the task
/// segment's application ID is the same five octets — manufacturer, software
/// ID, version (03/05/02 §3.31, 03/05/01 §4.2.13). The write is a property
/// write, so the state is marked dirty and persists it.
fn write_lsm_with_cascade<T: HasLoadStateMachine + HasRunStateMachine>(
    app: &RefCell<T>,
    program_version: &RefCell<[u8; 5]>,
    notifier: &impl DeviceModelNotifier,
    target: RunTarget,
    conditions: RunConditions,
    data: &[u8],
) -> Result<WriteResponse, PropertyError> {
    let action = app.borrow_mut().write_lsm(data, None);
    if action == LoadAction::Alloc
        && app.borrow().load_state() != LoadState::Err
        && let Some(task) = data.get(1..).and_then(TaskSegment::parse)
    {
        *program_version.borrow_mut() = task.application_id;
    }
    let run_action = match action {
        LoadAction::LoadEnd => app.borrow_mut().handle_run_event(RunEvent::Loaded, conditions),
        LoadAction::Unload => app.borrow_mut().handle_run_event(RunEvent::Unloaded, conditions),
        _ => None,
    };
    if let Some(run_action) = run_action {
        notifier.notify(DeviceModelEvent::RunAction(target, run_action));
    }
    Ok(WriteResponse::byte(app.borrow().read_lsm()[0]))
}

fn write_rsm_with_notify<T: HasLoadStateMachine + HasRunStateMachine>(
    app: &RefCell<T>,
    notifier: &impl DeviceModelNotifier,
    target: RunTarget,
    conditions: RunConditions,
    data: &[u8],
) -> Result<WriteResponse, PropertyError> {
    let run_action = app.borrow_mut().write_rsm(data, conditions);
    if let Some(run_action) = run_action {
        notifier.notify(DeviceModelEvent::RunAction(target, run_action));
    }
    Ok(WriteResponse::byte(app.borrow().read_rsm()[0]))
}

/// The property surface both program objects share. `$pei_type` adds the
/// object's PID_PEI_TYPE, which differs between them; each type therefore
/// writes its own constructor and its own `run_conditions()`.
macro_rules! system_7_program_object {
    ($(#[$doc:meta])* $name:ident, $object_type:ident, $run_target:ident, { $($pei_type:tt)* }) => {
        $(#[$doc])*
        #[interface_object(
            object_type = InterfaceObjectType::$object_type,
            levels = 16,
            object_type_rl = Controller
        )]
        pub struct $name<'a, T: HasLoadStateMachine + HasRunStateMachine, N: DeviceModelNotifier> {
            pub app: &'a RefCell<T>,
            /// Notifier for DeviceModel events (RSM lifecycle transitions).
            pub notifier: &'a N,

            /// PID_PROGRAM_VERSION (03/05/01 §4.2.13), persisted in the device
            /// state; the application's task segment sets it.
            pub program_version: &'a RefCell<[u8; 5]>,

            #[io(pid = pid::PROGRAM_VERSION, pdt = PDT_Generic05, access = RW,
                 policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = Controller,
                 read = |this: &Self| *this.program_version.borrow(),
                 write = |this: &mut Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
                     *this.program_version.borrow_mut() = data.try_into().map_err(|_| PropertyError::BufferTooSmall)?;
                     Ok(WriteResponse::Echo)
                 })]
            program_version_property: (),

            $($pei_type)*

            #[io(pid = pid::LOAD_STATE_CONTROL, pdt = PDT_Control, access = RW,
                 policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = Controller,
                 read = |this: &Self| this.app.borrow().read_lsm(),
                 write = |this: &mut Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
                     write_lsm_with_cascade(this.app, this.program_version, this.notifier, RunTarget::$run_target, this.run_conditions(), data)
                 })]
            load_state_control: (),

            #[io(pid = pid::RUN_STATE_CONTROL, pdt = PDT_Control, access = RW,
                 policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = Controller,
                 read = |this: &Self| this.app.borrow().read_rsm(),
                 write = |this: &mut Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
                     write_rsm_with_notify(this.app, this.notifier, RunTarget::$run_target, this.run_conditions(), data)
                 })]
            run_state_control: (),

            #[io(pid = pid::TABLE_REFERENCE, pdt = PDT_UnsignedLong, access = RO,
                 policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = SystemManufacturer,
                 read = |this: &Self| this.app.borrow().table_reference().to_be_bytes())]
            table_reference: (),

            #[io(pid = pid::MCB_TABLE, pdt = PDT_Generic08, access = RO,
                 policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = SystemManufacturer,
                 read = |this: &Self| -> [u8; 8] {
                     let app = this.app.borrow();
                     let src = app.mcb_bytes();
                     let mut out = [0u8; 8];
                     let n = src.len().min(8);
                     out[..n].copy_from_slice(&src[..n]);
                     out
                 })]
            mcb_table: (),

            #[io(pid = pid::ERROR_CODE, pdt = PDT_UnsignedChar, access = RO,
                 policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = SystemManufacturer,
                 read = |this: &Self| [this.app.borrow().last_error_code()])]
            error_code: (),
        }
    };
}

system_7_program_object!(
    /// Application Program Object (Object Type 3) for System 7.
    System7ApplicationProgramObject,
    ApplicationProgram,
    Application,
    {
        /// PID_PEI_TYPE, the PEI type the program requires
        /// (03/05/01 §4.20.2.2), persisted in the device state like on
        /// System B. 0705h makes writing optional (06 Profiles A.2.6).
        pub pei_type: &'a Cell<u8>,

        // A run condition (03/06/02 §2), re-evaluated on every write like
        // System B's; see `ApplicationProgramObject`.
        #[io(pid = pid::PEI_TYPE, pdt = PDT_UnsignedChar, access = RW,
             policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = Controller,
             read = |this: &Self| [this.pei_type.get()],
             write = |this: &mut Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
                 let [pei_type]: [u8; 1] = data.try_into().map_err(|_| PropertyError::BufferTooSmall)?;
                 this.pei_type.set(pei_type);
                 let run_action = this.app.borrow_mut().handle_run_event(RunEvent::ReadyToRun, this.run_conditions());
                 if let Some(action) = run_action {
                     this.notifier.notify(DeviceModelEvent::RunAction(RunTarget::Application, action));
                 }
                 Ok(WriteResponse::Echo)
             })]
        pei_type_property: (),
    }
);

impl<'a, T: HasLoadStateMachine + HasRunStateMachine, N: DeviceModelNotifier>
    System7ApplicationProgramObject<'a, T, N>
{
    /// Create the object over the persisted program version and PEI type
    /// cells.
    pub fn new(
        app: &'a RefCell<T>,
        program_version: &'a RefCell<[u8; 5]>,
        pei_type: &'a Cell<u8>,
        notifier: &'a N,
    ) -> Self {
        Self { app, notifier, program_version, pei_type }
    }

    /// The application's run conditions under its current required PEI type.
    fn run_conditions(&self) -> RunConditions {
        RunConditions::for_required_pei(self.pei_type.get())
    }
}

system_7_program_object!(
    /// Optional Interface Program Object (Object Type 4) for System 7.
    System7Program2Object,
    InterfaceProgram,
    Pei,
    {
        // No product of this stack loads an Interface Program, so it
        // requires no PEI. 06 Profiles A.2.7 makes the property optional
        // for 0705h; reporting it keeps the object's surface alike.
        #[io(pid = pid::PEI_TYPE, pdt = PDT_UnsignedChar, access = RO,
             policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = SystemManufacturer,
             read = |_this: &Self| [0u8])]
        pei_type: (),
    }
);

impl<'a, T: HasLoadStateMachine + HasRunStateMachine, N: DeviceModelNotifier> System7Program2Object<'a, T, N> {
    /// Create the object over the persisted program version cell.
    pub fn new(app: &'a RefCell<T>, program_version: &'a RefCell<[u8; 5]>, notifier: &'a N) -> Self {
        Self { app, notifier, program_version }
    }

    /// Always fulfilled: the program requires no PEI (PID_PEI_TYPE reads 0)
    /// and has no other condition this stack models.
    fn run_conditions(&self) -> RunConditions {
        RunConditions::Fulfilled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_model::DmNotificationSlot;
    use crate::objects::interface::{InterfaceObject, PropertyReadRequest, PropertyWriteRequest};
    use crate::objects::tables::{AbsoluteAlloc, Application};
    use zweidraehte_proto::messages::apdu::load_control::{LoadControlRecord, LoadEvent};

    const APPLICATION_ID: [u8; 5] = [0x00, 0x83, 0x00, 0x9B, 0x14];

    fn read_program_version<T: HasLoadStateMachine + HasRunStateMachine>(
        obj: &System7ApplicationProgramObject<'_, T, DmNotificationSlot>,
    ) -> [u8; 5] {
        let mut buf = [0u8; 8];
        let len = obj
            .read_property(PropertyReadRequest { pid: pid::PROGRAM_VERSION, start_idx: 1, count: 1 }, &mut buf)
            .expect("PID 13 is readable");
        buf[..len].try_into().expect("five octets")
    }

    fn write_lsm<T: HasLoadStateMachine + HasRunStateMachine>(
        obj: &mut System7ApplicationProgramObject<'_, T, DmNotificationSlot>,
        data: &[u8],
    ) {
        obj.write_property(PropertyWriteRequest { pid: pid::LOAD_STATE_CONTROL, start_idx: 1, data })
            .expect("load state control accepts the event");
    }

    #[test]
    fn the_task_segment_sets_the_program_version() {
        // System 7 downloads never write PID 13; the application ID arrives
        // in the absolute task segment (03/05/03 §3.9.2).
        let app = RefCell::new(Application::<(), AbsoluteAlloc>::new());
        let version = RefCell::new([0; 5]);
        let pei_type = Cell::new(0);
        let notifier = DmNotificationSlot::new();
        let mut obj = System7ApplicationProgramObject::new(&app, &version, &pei_type, &notifier);

        write_lsm(&mut obj, &[LoadEvent::StartLoading.into()]);
        write_lsm(&mut obj, &LoadControlRecord::task_segment(0x4000, 0, APPLICATION_ID));
        write_lsm(&mut obj, &[LoadEvent::LoadCompleted.into()]);

        assert_eq!(read_program_version(&obj), APPLICATION_ID);
        assert_eq!(*version.borrow(), APPLICATION_ID, "stored in the persisted cell");
    }

    #[test]
    fn a_rejected_task_segment_leaves_the_program_version() {
        let app = RefCell::new(Application::<(), AbsoluteAlloc>::new());
        let version = RefCell::new([0x00, 0xFA, 0x00, 0x01, 0x01]);
        let pei_type = Cell::new(0);
        let notifier = DmNotificationSlot::new();
        let mut obj = System7ApplicationProgramObject::new(&app, &version, &pei_type, &notifier);

        // Not loading: the record is not an accepted allocation.
        write_lsm(&mut obj, &LoadControlRecord::task_segment(0x4000, 0, APPLICATION_ID));
        assert_eq!(read_program_version(&obj), [0x00, 0xFA, 0x00, 0x01, 0x01]);

        // A truncated task record carries no application ID.
        write_lsm(&mut obj, &[LoadEvent::StartLoading.into()]);
        write_lsm(&mut obj, &LoadControlRecord::task_segment(0x4000, 0, APPLICATION_ID)[..6]);
        assert_eq!(read_program_version(&obj), [0x00, 0xFA, 0x00, 0x01, 0x01]);
    }

    /// The required PEI type is a run condition on System 7 as on System B
    /// (03/06/02 §2): a mismatch parks the application in Ready.
    #[test]
    fn required_pei_type_gates_the_run_state() {
        use crate::objects::tables::{RunAction, RunState};

        let app = RefCell::new(Application::<(), AbsoluteAlloc>::new());
        let version = RefCell::new([0; 5]);
        let pei_type = Cell::new(0x01);
        let notifier = DmNotificationSlot::new();
        let mut obj = System7ApplicationProgramObject::new(&app, &version, &pei_type, &notifier);

        write_lsm(&mut obj, &[LoadEvent::StartLoading.into()]);
        write_lsm(&mut obj, &LoadControlRecord::task_segment(0x4000, 0, APPLICATION_ID));
        write_lsm(&mut obj, &[LoadEvent::LoadCompleted.into()]);
        obj.write_property(PropertyWriteRequest {
            pid: pid::RUN_STATE_CONTROL,
            start_idx: 1,
            data: &[RunEvent::Restart.into()],
        })
        .expect("run state control accepts Restart");
        assert_eq!(app.borrow().run_state(), RunState::Ready);

        obj.write_property(PropertyWriteRequest { pid: pid::PEI_TYPE, start_idx: 1, data: &[0x00] })
            .expect("PID 16 is writable on 0705h");
        assert_eq!(app.borrow().run_state(), RunState::Running);
        assert!(matches!(
            notifier.take_event(),
            Some(DeviceModelEvent::RunAction(RunTarget::Application, RunAction::Started))
        ));
    }
}
