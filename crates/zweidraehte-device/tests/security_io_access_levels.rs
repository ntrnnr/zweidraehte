//! The Security Interface Object's access levels follow the base profile.
//!
//! 06 Profiles v02.02.01 §9.1.2.6.4 tabulates the Security IO's access
//! levels in the 4-level model: `3/X` on PID_OBJECT_TYPE(1),
//! PID_OBJECT_NAME(2), PID_SECURITY_FAILURES_LOG(55) and
//! PID_SECURITY_REPORT(57), `2/2` on the configuration PIDs, `X/2` on
//! PID_TOOL_KEY(56). But KNX Data Security is a profile *module* (§9.1)
//! composed onto a base profile, and the number of authorisation levels
//! belongs to that base profile — §4.2 row 12 gives System B four and
//! System 7 sixteen. Since the access check is `access_level <=
//! read_level`, a 16-level device whose unauthorised connections sit at
//! level 15 would be refused every "open" read if the literal 3 stayed.
//!
//! So the free level is the augment's `FREE` parameter, and the
//! privileged levels are not. This pins both halves.

use zweidraehte_device::objects::interface::pid;
use zweidraehte_device::security::SecurityAugment;
use zweidraehte_device::storage::kv::KeyValueStore;
use zweidraehte_device::storage::views::SiatStore;
use zweidraehte_proto::access::{AccessLevel, AccessLevelSpec};
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::properties::PropertyDescriptor;

/// The descriptor table does not depend on the sequence store, but the
/// augment is generic over one, so name the emptiest possible backend
/// rather than dragging a real flash or shm store into a table test.
struct NoKv;

impl KeyValueStore for NoKv {
    type Error = core::convert::Infallible;

    fn get(&self, _ns: u8, _key: &[u8], _buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Ok(None)
    }

    fn put(&mut self, _ns: u8, _key: &[u8], _val: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn remove(&mut self, _ns: u8, _key: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn for_each(&self, _ns: u8, _f: &mut dyn FnMut(&[u8], &[u8])) {}
}

type Seq = SiatStore<NoKv, 1, 0>;

/// Resolve one of the Security IO's specs the way a device with
/// `levels` authorisation levels would.
fn descriptor(prop_id: u16, levels: u8) -> PropertyDescriptor {
    SecurityAugment::<'static, Seq, 1, 0, 1>::DESCRIPTORS
        .iter()
        .find(|(t, d)| *t == InterfaceObjectType::Security && d.pid == prop_id)
        .map(|(_, d)| d.for_levels(levels))
        .unwrap_or_else(|| panic!("Security IO declares PID {prop_id}"))
}

/// The audience a spec names, before resolution.
fn spec(prop_id: u16) -> AccessLevelSpec {
    SecurityAugment::<'static, Seq, 1, 0, 1>::DESCRIPTORS
        .iter()
        .find(|(t, d)| *t == InterfaceObjectType::Security && d.pid == prop_id)
        .map(|(_, d)| d.read_level)
        .expect("Security IO declares this PID")
}

/// The four PIDs Profiles §9.1.2.6.4 gives an open read.
const OPEN_READ_PIDS: [u16; 4] =
    [pid::OBJECT_TYPE, pid::OBJECT_NAME, pid::security::SECURITY_FAILURES_LOG, pid::security::SECURITY_REPORT];

#[test]
fn open_reads_name_the_runtime_audience() {
    // The invariant is the audience, not the number: naming it is what
    // lets the same object be hosted by either profile.
    for prop_id in OPEN_READ_PIDS {
        assert_eq!(spec(prop_id), AccessLevelSpec::Audience(AccessLevel::Runtime), "PID {prop_id}");
    }
}

#[test]
fn open_reads_resolve_per_profile() {
    for prop_id in OPEN_READ_PIDS {
        assert_eq!(descriptor(prop_id, 4).read_level, 3, "4-level model, PID {prop_id}");
        assert_eq!(descriptor(prop_id, 16).read_level, 15, "16-level model, PID {prop_id}");
    }
}

#[test]
fn privileged_levels_are_absolute() {
    // `2/2` on the configuration PIDs, whichever model the device runs:
    // level 2 is a real level in both, not "the lowest one".
    for prop_id in [
        pid::LOAD_STATE_CONTROL,
        pid::security::SECURITY_MODE,
        pid::security::GROUP_KEY_TABLE,
        pid::security::GO_SECURITY_FLAGS,
    ] {
        for d in [descriptor(prop_id, 4), descriptor(prop_id, 16)] {
            assert_eq!(d.read_level, 2, "PID {prop_id}");
            assert_eq!(d.write_level, 2, "PID {prop_id}");
        }
    }

    // PID_TOOL_KEY is `X/2` — write-only, so its read level stays at the
    // most privileged 0 in both models rather than tracking the runtime
    // audience.
    for d in [descriptor(pid::security::TOOL_KEY, 4), descriptor(pid::security::TOOL_KEY, 16)] {
        assert_eq!(d.read_level, 0);
        assert_eq!(d.write_level, 2);
    }
}

/// The write half of the open-read PIDs: `X` on 1 and 2 (read-only),
/// `2` on 55 and 57. None of them names the runtime audience, so none
/// moves between models.
#[test]
fn write_levels_do_not_move_between_models() {
    for prop_id in OPEN_READ_PIDS {
        assert_eq!(descriptor(prop_id, 4).write_level, descriptor(prop_id, 16).write_level, "PID {prop_id}");
    }
}
