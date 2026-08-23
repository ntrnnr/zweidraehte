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

use core::cell::RefCell;

use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{
    InterfaceObjectType, PDT_Control, PDT_Generic05, PDT_Generic08, PDT_UnsignedChar, PDT_UnsignedLong,
};
use zweidraehte_proto::properties::PropertyError;

use crate::device_model::{DeviceModelEvent, DeviceModelNotifier, RunTarget};
use crate::objects::interface::{WriteResponse, interface_object, pid};
use crate::objects::tables::{HasLoadStateMachine, HasRunStateMachine, LoadAction, RunEvent};

/// One arm of the shared LSM/RSM write plumbing: apply the load event,
/// cascade the resulting run event, notify the device model.
fn write_lsm_with_cascade<T: HasLoadStateMachine + HasRunStateMachine>(
    app: &RefCell<T>,
    notifier: &dyn DeviceModelNotifier,
    target: RunTarget,
    data: &[u8],
) -> Result<WriteResponse, PropertyError> {
    let action = app.borrow_mut().write_lsm(data, None);
    let run_action = match action {
        LoadAction::LoadEnd => app.borrow_mut().handle_run_event(RunEvent::Loaded),
        LoadAction::Unload => app.borrow_mut().handle_run_event(RunEvent::Unloaded),
        _ => None,
    };
    if let Some(run_action) = run_action {
        notifier.notify(DeviceModelEvent::RunAction(target, run_action));
    }
    Ok(WriteResponse::byte(app.borrow().read_lsm()[0]))
}

fn write_rsm_with_notify<T: HasLoadStateMachine + HasRunStateMachine>(
    app: &RefCell<T>,
    notifier: &dyn DeviceModelNotifier,
    target: RunTarget,
    data: &[u8],
) -> Result<WriteResponse, PropertyError> {
    let run_action = app.borrow_mut().write_rsm(data);
    if let Some(run_action) = run_action {
        notifier.notify(DeviceModelEvent::RunAction(target, run_action));
    }
    Ok(WriteResponse::byte(app.borrow().read_rsm()[0]))
}

macro_rules! system_7_program_object {
    ($(#[$doc:meta])* $name:ident, $object_type:ident, $run_target:ident) => {
        $(#[$doc])*
        #[interface_object(
            object_type = InterfaceObjectType::$object_type,
            levels = 16,
            object_type_rl = Controller
        )]
        pub struct $name<'a, T: HasLoadStateMachine + HasRunStateMachine> {
            pub app: &'a RefCell<T>,
            /// Notifier for DeviceModel events (RSM lifecycle transitions).
            pub notifier: &'a dyn DeviceModelNotifier,

            #[io(pid = pid::PROGRAM_VERSION, pdt = PDT_Generic05, access = RW,
                 policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = Controller)]
            pub program_version: PDT_Generic05,

            #[io(pid = pid::PEI_TYPE, pdt = PDT_UnsignedChar, access = RW,
                 policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = Controller)]
            pub pei_type: PDT_UnsignedChar,

            #[io(pid = pid::LOAD_STATE_CONTROL, pdt = PDT_Control, access = RW,
                 policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = Controller,
                 read = |this: &Self| this.app.borrow().read_lsm(),
                 write = |this: &mut Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
                     write_lsm_with_cascade(this.app, this.notifier, RunTarget::$run_target, data)
                 })]
            load_state_control: (),

            #[io(pid = pid::RUN_STATE_CONTROL, pdt = PDT_Control, access = RW,
                 policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = Controller,
                 read = |this: &Self| this.app.borrow().read_rsm(),
                 write = |this: &mut Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
                     write_rsm_with_notify(this.app, this.notifier, RunTarget::$run_target, data)
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

        impl<'a, T: HasLoadStateMachine + HasRunStateMachine> $name<'a, T> {
            /// Create the object with program version and PEI type.
            pub fn with_info(
                app: &'a RefCell<T>,
                program_version: PDT_Generic05,
                pei_type: PDT_UnsignedChar,
                notifier: &'a dyn DeviceModelNotifier,
            ) -> Self {
                Self { app, notifier, program_version, pei_type }
            }
        }
    };
}

system_7_program_object!(
    /// Application Program Object (Object Type 3) for System 7.
    System7ApplicationProgramObject,
    ApplicationProgram,
    Application
);

system_7_program_object!(
    /// Optional Interface Program Object (Object Type 4) for System 7.
    System7Program2Object,
    InterfaceProgram,
    Pei
);
