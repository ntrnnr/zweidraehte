//! Access control of every standard preset, checked against the
//! specification property by property.
//!
//! For each preset this builds the interface objects exactly as firmware
//! does and walks them through the object dispatcher, the one place every
//! property service passes (standard and extended services, cEMI local
//! management). Three things are checked:
//!
//! 1. **The surface.** The served (object type, PID) pairs are exactly the
//!    expected ones — nothing missing, nothing extra — and each description
//!    reports the expected kind and access levels.
//! 2. **Enforcement.** Every property is read, written and described, and
//!    function properties are called, by every caller class: plain at each
//!    legacy level, and the Roles and the Tool with authentication only and
//!    with confidentiality, with Security Mode off and on. Each outcome is
//!    compared against what [`spec`] derives from the expected table — not
//!    against the served descriptor, so a wrong descriptor fails too.
//! 3. **No side effects of the probing itself.** Writes address an element
//!    far beyond any capacity, so an admitted write is refused by the bounds
//!    checks instead of changing the device; function calls name an invalid
//!    service.
//!
//! The memory maps are checked the same way, window by window, in
//! [`memory`].
//!
//! What this does not cover — service-level policies, role assignment by
//! the Secure Application Layer, the wire encoding of refusals — is covered
//! end to end by the conformance suite's access-control cases.

mod memory;
mod spec;
mod stacks;
mod tables;

use std::collections::BTreeMap;

use static_cell::StaticCell;

use zweidraehte_device::StackDefinition;
use zweidraehte_device::context::layer::LayerContext;
use zweidraehte_device::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, PropertyDescriptionResponse,
    PropertyError, PropertyServiceHandler,
};
use zweidraehte_proto::dpt::{PDT_Function, PropertyDataDefinition};
use zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode;
use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};

use spec::{Caller, Expected, Kind};

/// Build `$stack` as its runner would and bind its state and interface
/// objects for `$body`. Each expansion owns its buffer pool.
macro_rules! with_stack {
    ($stack:ty, $init:expr, $storage:expr, |$objects:ident, $state:ident| $body:block) => {{
        static BUFFERS: StaticCell<[[u8; 64]; 4]> = StaticCell::new();
        static BUF_MGR: StaticCell<BufferManager<4>> = StaticCell::new();

        let buffers = BUFFERS.init([[0u8; 64]; 4]);
        // SAFETY: single-threaded test; the buffers live in a StaticCell.
        let buffer_manager = BUF_MGR.init(unsafe { BufferManager::new(buffers) });
        let dyn_bm = buffer_manager.dyn_buffer_manager();
        // SAFETY: the buffer manager lives in a StaticCell ('static).
        let dyn_bm: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_bm) };

        let lctx = LayerContext::<$stack>::new(dyn_bm, $storage);
        let $state = <$stack>::create_state($init);
        let augments = <$stack>::create_augments(&$state, &(), &lctx);
        let $objects = <$stack>::create_interface_objects(&$state, &(), &lctx, &augments);
        $body
    }};
}

/// Secure storage backed by nothing, for the secure preset `$storage`.
macro_rules! secure_storage {
    ($storage:ty) => {{
        static STORAGE: StaticCell<$storage> = StaticCell::new();
        &*STORAGE.init(zweidraehte_device::storage::SecureStorage::new(
            stacks::NoConfigStore::new(),
            stacks::SequenceStore::boot(stacks::NoKv).expect("the empty backend cannot fail"),
        ))
    }};
}

// ============================================================================
// The checks
// ============================================================================

/// Every served property, keyed by (object type, PID).
fn served(objects: &impl PropertyServiceHandler) -> BTreeMap<(u16, u16), (u16, PropertyDescriptionResponse)> {
    let mut served = BTreeMap::new();
    for object_idx in 0..objects.object_count() {
        let object_type = u16::from(objects.object_type_at(object_idx).expect("object in range"));
        let mut prop_idx = 0;
        while let Ok(description) = objects.property_description_read(object_idx, 0, prop_idx) {
            served.insert((object_type, description.prop_id), (object_idx, description));
            prop_idx += 1;
        }
    }
    served
}

/// A write that no property can satisfy: element 4095 is past every
/// capacity, so an admitted write fails its bounds check and changes
/// nothing, while a refused one fails on access first.
const PROBE_START: u16 = 4095;

/// An invalid ServiceID: an admitted function call is rejected by the
/// function itself, a refused one on access first.
const PROBE_SERVICE: &[u8] = &[0x00, 0xFF];

fn check(
    name: &str,
    objects: &impl PropertyServiceHandler,
    expected: &[Expected],
    max_levels: u8,
    security_modes: &[bool],
    set_security_mode: &dyn Fn(bool),
) {
    let mut failures = Vec::new();
    let served = served(objects);

    // --- The surface ---------------------------------------------------
    let expected: BTreeMap<(u16, u16), Expected> = expected.iter().map(|e| ((e.object_type, e.pid), *e)).collect();
    for key in served.keys().filter(|key| !expected.contains_key(key)) {
        failures.push(format!("served but not expected: object type {} PID {}", key.0, key.1));
    }
    for (key, entry) in expected.iter().filter(|(key, _)| !served.contains_key(key)) {
        failures.push(format!("expected but not served: object type {} PID {} ({})", key.0, key.1, entry.source));
    }

    for (key, entry) in &expected {
        let Some((_, description)) = served.get(key) else { continue };
        let function = description.pdt == PDT_Function::ID;
        let writeable = !matches!(entry.kind, Kind::ReadOnly);
        let levels = (entry.read.level(max_levels), entry.write.level(max_levels));
        if function != matches!(entry.kind, Kind::Function)
            || description.writeable != writeable
            || (description.read_level, description.write_level) != levels
        {
            failures.push(format!(
                "object type {} PID {}: described {}{} {}/{}, expected {:?} {}/{} ({})",
                key.0,
                key.1,
                if function { "function " } else { "" },
                if description.writeable { "writeable" } else { "read-only" },
                description.read_level,
                description.write_level,
                entry.kind,
                levels.0,
                levels.1,
                entry.source
            ));
        }
    }

    // --- Enforcement ---------------------------------------------------
    for &security_mode in security_modes {
        set_security_mode(security_mode);
        for caller in Caller::all(max_levels) {
            let ctx = caller.context();
            for (key, entry) in &expected {
                let Some(&(object_idx, _)) = served.get(key) else { continue };
                let permissions = entry.permissions(&caller, security_mode, max_levels);
                let at = |what: &str| {
                    format!("object type {} PID {} {what}, {caller:?}, Security Mode {security_mode}", key.0, key.1)
                };

                let read = objects.property_value_read(
                    &FullPropertyReadRequest { object_idx, pid: entry.pid, start_idx: 1, count: 1, ctx },
                    &mut [0u8; 64],
                );
                let write = objects.property_value_write(&FullPropertyWriteRequest {
                    object_idx,
                    pid: entry.pid,
                    count: 1,
                    start_idx: PROBE_START,
                    data: &[0],
                    ctx,
                });
                let refused = |result: &Result<_, PropertyError>| {
                    matches!(result, Err(PropertyError::AccessDenied | PropertyError::WriteNotAllowed))
                };

                if matches!(entry.kind, Kind::Function) {
                    // No data-property service reaches a function.
                    if read.is_ok() {
                        failures.push(at("value read of a function property succeeded"));
                    }
                    if write.is_ok() {
                        failures.push(at("value write of a function property succeeded"));
                    }

                    let request =
                        FunctionPropertyRequest { object_idx, prop_id: entry.pid, service_data: PROBE_SERVICE, ctx };
                    let denied = u8::from(PropertyReturnCode::AccessDenied);
                    let command = objects.function_property_command(&request).return_code != denied;
                    let state_read = objects.function_property_state_read(&request).return_code != denied;
                    if command != permissions.write {
                        failures
                            .push(at(&format!("function command admitted={command}, expected {}", permissions.write)));
                    }
                    if state_read != permissions.read {
                        failures.push(at(&format!(
                            "function state read admitted={state_read}, expected {}",
                            permissions.read
                        )));
                    }
                } else {
                    let read_admitted =
                        !matches!(read, Err(PropertyError::AccessDenied | PropertyError::ReadNotAllowed));
                    if read_admitted != permissions.read {
                        failures.push(at(&format!(
                            "read admitted={read_admitted} ({read:?}), expected {}",
                            permissions.read
                        )));
                    }
                    if write.is_ok() {
                        failures.push(at("the probing write succeeded and may have changed the device"));
                    }
                    if refused(&write) == permissions.write {
                        failures.push(at(&format!(
                            "write refused={} ({write:?}), expected admitted={}",
                            refused(&write),
                            permissions.write
                        )));
                    }
                }

                let visible = objects.property_description_visible(object_idx, entry.pid, &ctx);
                let expected_visible = entry.description_visible(&caller, security_mode, max_levels);
                if visible != expected_visible {
                    failures.push(at(&format!("description visible={visible}, expected {expected_visible}")));
                }
            }
        }
    }
    set_security_mode(false);

    assert!(failures.is_empty(), "{name}: {} failure(s)\n  {}", failures.len(), failures.join("\n  "));
}

fn no_security_mode(_on: bool) {}

fn concat(parts: &[&[Expected]]) -> Vec<Expected> {
    parts.iter().flat_map(|part| part.iter().copied()).collect()
}

// ============================================================================
// System B
// ============================================================================

mod system_b {
    use super::tables::*;
    use super::*;
    use zweidraehte_device::bcus::system_b::{MemoryLayout, SystemBMemoryMap, SystemBStateInit};
    use zweidraehte_device::security::SecureResources;
    use zweidraehte_device::storage::StaticIdentity;

    fn base() -> Vec<Expected> {
        concat(&[
            &SYSTEM_B_ADDRESS_TABLE,
            &SYSTEM_B_ASSOCIATION_TABLE,
            &SYSTEM_B_GROUP_OBJECT_TABLE,
            SYSTEM_B_APPLICATION,
            SYSTEM_B_INTERFACE_PROGRAM,
        ])
    }

    /// The preset's memory map, with application memory: the test
    /// definitions have no parameters, so their own layout has none.
    fn memory_map<Stack: StackDefinition>() -> (SystemBMemoryMap, Vec<memory::Window>) {
        let layout = MemoryLayout::from_descriptor(SystemBMemoryMap::DEFAULT_BASE_ADDRESS, Stack::DEVICE, 16);
        (SystemBMemoryMap::new(layout), memory::system_b(&layout))
    }

    fn secure_init<C, R>(resources: R) -> SystemBStateInit<zweidraehte_device::storage::StaticSecureIdentity, C, R> {
        SystemBStateInit { identity: stacks::secure_identity(), loaded_config: None, resources }
    }

    #[test]
    fn tp1() {
        let expected = concat(&[SYSTEM_B_DEVICE, TP1_DEVICE, &base()]);
        with_stack!(
            stacks::system_b::Tp1Stack,
            SystemBStateInit::new(StaticIdentity::new([0; 6]), None),
            (),
            |objects, state| {
                check("System B TP1", &objects, &expected, 4, &[false], &no_security_mode);
                let (map, windows) = memory_map::<stacks::system_b::Tp1Stack>();
                memory::check("System B TP1", &map, &state, &windows, 4, &[false], &no_security_mode);
            }
        );
    }

    #[test]
    fn rf() {
        let expected = concat(&[SYSTEM_B_DEVICE, &base(), RF_MEDIUM_OBJECT]);
        with_stack!(
            stacks::system_b::RfStack,
            SystemBStateInit::new(StaticIdentity::new([0; 6]), None),
            (),
            |objects, state| {
                check("System B RF", &objects, &expected, 4, &[false], &no_security_mode);
                let (map, windows) = memory_map::<stacks::system_b::RfStack>();
                memory::check("System B RF", &map, &state, &windows, 4, &[false], &no_security_mode);
            }
        );
    }

    #[test]
    fn secure_tp1() {
        let device = secure_device(&concat(&[SYSTEM_B_DEVICE, TP1_DEVICE]));
        let expected = concat(&[&device, &base(), SECURITY_OBJECT, DIAGNOSTICS]);
        with_stack!(
            stacks::system_b::SecureTp1Stack,
            secure_init(SecureResources::simple(stacks::FDSK)),
            secure_storage!(stacks::system_b::SecureTp1Storage),
            |objects, state| {
                let set = |on| state.extension_state().security.set_security_mode_enabled(on);
                check("System B secure TP1", &objects, &expected, 4, &[false, true], &set);
                let (map, windows) = memory_map::<stacks::system_b::SecureTp1Stack>();
                memory::check("System B secure TP1", &map, &state, &windows, 4, &[false, true], &set);
            }
        );
    }

    #[test]
    fn secure_rf() {
        let device = secure_device(SYSTEM_B_DEVICE);
        let expected = concat(&[&device, &base(), RF_MEDIUM_OBJECT, SECURITY_OBJECT, DIAGNOSTICS]);
        with_stack!(
            stacks::system_b::SecureRfStack,
            secure_init(SecureResources::simple(stacks::FDSK)),
            secure_storage!(stacks::system_b::SecureRfStorage),
            |objects, state| {
                let set = |on| state.extension_state().security.set_security_mode_enabled(on);
                check("System B secure RF", &objects, &expected, 4, &[false, true], &set);
                let (map, windows) = memory_map::<stacks::system_b::SecureRfStack>();
                memory::check("System B secure RF", &map, &state, &windows, 4, &[false, true], &set);
            }
        );
    }

    #[test]
    fn secure_rf_retransmitter() {
        let device = secure_device(SYSTEM_B_DEVICE);
        let expected = concat(&[&device, &base(), RF_MEDIUM_OBJECT, RF_RETRANSMITTER, SECURITY_OBJECT, DIAGNOSTICS]);
        with_stack!(
            stacks::system_b::SecureRfRetransmitterStack,
            secure_init(SecureResources::simple(stacks::FDSK)),
            secure_storage!(stacks::system_b::SecureRfRetransmitterStorage),
            |objects, state| {
                let set = |on| state.extension_state().security.set_security_mode_enabled(on);
                check("System B secure RF retransmitter", &objects, &expected, 4, &[false, true], &set);
                let (map, windows) = memory_map::<stacks::system_b::SecureRfRetransmitterStack>();
                memory::check("System B secure RF retransmitter", &map, &state, &windows, 4, &[false, true], &set);
            }
        );
    }
}

// ============================================================================
// System 7
// ============================================================================

mod system_7 {
    use super::tables::*;
    use super::*;
    use zweidraehte_device::bcus::system_7::{System7MemoryMap, System7StateInit};
    use zweidraehte_device::security::SecureResources;
    use zweidraehte_device::storage::StaticIdentity;

    fn base() -> Vec<Expected> {
        concat(&[
            &SYSTEM_7_ADDRESS_TABLE,
            &SYSTEM_7_ASSOCIATION_TABLE,
            &SYSTEM_7_APPLICATION,
            &SYSTEM_7_INTERFACE_PROGRAM,
        ])
    }

    #[test]
    fn tp1() {
        let expected = concat(&[SYSTEM_7_DEVICE, TP1_DEVICE, &base()]);
        with_stack!(
            stacks::system_7::Tp1Stack,
            System7StateInit::new(StaticIdentity::new([0; 6]), None),
            (),
            |objects, state| {
                check("System 7 TP1", &objects, &expected, 16, &[false], &no_security_mode);
                let windows = memory::system_7(stacks::system_7::COT_ADDRESS);
                memory::check(
                    "System 7 TP1",
                    &System7MemoryMap::new(),
                    &state,
                    &windows,
                    16,
                    &[false],
                    &no_security_mode,
                );
            }
        );
    }

    #[test]
    fn secure_tp1() {
        let device = secure_device(&concat(&[SYSTEM_7_DEVICE, TP1_DEVICE]));
        let expected = concat(&[&device, &base(), SYSTEM_7_GROUP_OBJECT_TABLE, SECURITY_OBJECT, DIAGNOSTICS]);
        with_stack!(
            stacks::system_7::SecureTp1Stack,
            System7StateInit {
                identity: stacks::secure_identity(),
                loaded_config: None,
                resources: SecureResources::simple(stacks::FDSK),
            },
            secure_storage!(stacks::system_7::SecureTp1Storage),
            |objects, state| {
                let set = |on| state.extension_state().security.set_security_mode_enabled(on);
                check("System 7 secure TP1", &objects, &expected, 16, &[false, true], &set);
                let windows = memory::system_7(stacks::system_7::COT_ADDRESS);
                memory::check(
                    "System 7 secure TP1",
                    &System7MemoryMap::new(),
                    &state,
                    &windows,
                    16,
                    &[false, true],
                    &set,
                );
            }
        );
    }
}
