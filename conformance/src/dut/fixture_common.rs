//! Fixture vocabulary shared by every DUT family.
//!
//! These items are family-neutral: they describe *the conformance
//! test application* (its device descriptor, its parameters, the
//! certification object the data-security template checks) and the
//! multiprocess harness plumbing (the shared-memory sequence store,
//! the host RNG) — none of it is System B or System 7 specific. They
//! originally lived in the System B fixtures because System B was the
//! only family; the per-family stack modules now hold only what
//! genuinely differs per family.

use core::cell::{Cell, RefCell};

use std::io;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use const_default::ConstDefault;
use zerocopy::{Immutable, IntoBytes, KnownLayout};

use zweidraehte_device::prelude::*;
use zweidraehte_device::{
    Rng, SecureRng, StackDefinition,
    objects::interface::{
        FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult,
        PropertyError, PropertyRead, WriteResponse, interface_object_augment, pid,
    },
    restart::EraseCode,
    service::ServiceCtx,
};
use zweidraehte_proto::AccessContext;
use zweidraehte_proto::access::{AccessPolicy, ClientRole, SecurityMode};
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::apdu::load_control::LoadState;
use zweidraehte_proto::security::{SecurityConfig, SecurityState, SiatAccess};

// ============================================================================
// Polling DUT socket setup
// ============================================================================

/// Configure the command socket used by a host-side polling DUT.
///
/// Real-time runs block briefly between timer polls to avoid wasting a CPU.
/// Fast conformance runs cannot use `SO_RCVTIMEO`: an operating system may
/// round the millisecond timeout to a scheduler tick, which consumes the
/// narrow timing margin left after 50× compression. Those fixtures use a
/// nonblocking socket and yield explicitly after each timer pass instead.
///
/// Returns whether the caller should yield after each poll iteration.
pub fn configure_polling_socket(socket: &UnixStream, time_divisor: u32) -> io::Result<bool> {
    let fast_polling = time_divisor > 1;

    if fast_polling {
        socket.set_nonblocking(true)?;
    } else {
        socket.set_read_timeout(Some(Duration::from_millis(2)))?;
    }

    Ok(fast_polling)
}

// ============================================================================
// Test Parameters
// ============================================================================

/// The conformance application's (empty) ETS parameter block.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, IntoBytes, KnownLayout, Immutable)]
pub struct TestParameters;

impl ConstDefault for TestParameters {
    const DEFAULT: Self = TestParameters;
}

/// Device descriptor type 2 (DD2) data for conformance tests.
///
/// Deliberately placeholder content: these are the fourteen octets the
/// EITT management template declares as the default of its own
/// `DD2_RESPONSE` field, which is what 2.5.3 and 2.5.4 compare against.
/// A real DD2 would be filled in from the data sheet.
///
/// DD2 is Optional for System B — 06 Profiles §4.3 "Device
/// Identification", row "Device Descriptor Type 2", where it is M only
/// for RF unidirectional and bidirectional and "-" for System 1/2,
/// BCU 1 and System 7. We answer it so the read path is exercised.
///
/// Its fields are all defined in terms of an E-Mode device: 03/05/01
/// §4.1.3 describes octets 0-1 as "the manufacturer code of the
/// manufacturer of the E-Mode device", octet 5 as "the Management
/// Profile of the E-Mode device", and octets 6-13 as E-Mode Channel
/// information; §4.3.13.4 has an E-Mode Management Server deriving a
/// device's active Group Objects from DD2 plus the Channel database.
/// The spec does not go on to say DD2 is E-Mode only — §4.1.1 names a
/// mode for DD0 alone ("designed for use in S-Mode") — which is why an
/// S-Mode profile can still list it as Optional.
///
/// Format, against the octets below:
/// - Bytes 0-1: Application Manufacturer (0x0102)
/// - Bytes 2-3: Application Identification (0x0304)
/// - Byte 4: Application Version (0x05)
/// - Byte 5: Management Profile in bits 7-4, rest reserved (0x06)
/// - Bytes 6-13: Channel Info 1-4, two octets each
pub const CONFORMANCE_DD2: [u8; 14] =
    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E];

/// User Manufacturer Info for conformance tests.
///
/// This must match the expected response in the conformance test suite.
/// Format: Manufacturer ID (2 bytes) + Device Type (1 byte)
pub const CONFORMANCE_USER_MANUFACTURER_INFO: [u8; 3] = [0x00, 0x00, 0x00];

/// Security table sizes for const generics.
///
/// `GRP` and `GO` are not declared here — `SecureTp1DeviceState`
/// derives them as entry counts from the `ADT_SIZE`/`COT_SIZE` byte
/// sizes. `P2P` is the P2P Key Table capacity. `SIAT` is **not** a const
/// on the secure device state — it is the `N` of the `SiatStore` (the
/// SIAT lives in the sequence store, here [`ShmSiatStore`]); the value
/// below is passed as that `N` and must cover the union of P2P +
/// group-secure senders (03/03/07 §5.3).
pub mod sec_table_sizes {
    /// Max P2P Key Table entries.
    pub const P2P: usize = 8;
    /// Max SIAT entries — the `SiatStore` capacity (union of P2P +
    /// group-secure senders).
    pub const SIAT: usize = 8;
}

/// Factory Default Setup Key for the secure DUT.
///
/// Distinct from `TK1` (see `tests::security::variables::TK1`). The
/// default persisted SHM snapshot already carries `tool_key == TK1`
/// (the `knx_stack_config!` macro's `security.tool_key` field), so
/// tests that don't factory-reset the DUT see the pre-configured
/// TK1. Once a factory reset fires, the active tool key reverts to
/// this distinct FDSK, and each such test has to re-provision TK1
/// explicitly (sync + FDSK-encrypted `PID_TOOL_KEY` write) — the
/// pattern the reference XML uses for 3.8.13.1/8 etc.
pub const SECURE_FDSK: [u8; 16] = [0x11; 16];

/// Build a persisted security snapshot through the runtime state's public
/// mutation API.
///
/// Conformance fixtures need pre-provisioned boot images, but they must not
/// depend on the persisted config's table fields. Going through
/// [`SecurityState`] keeps fixture construction on the same boundary used by
/// property writes and snapshot persistence.
pub fn security_snapshot<const GRP: usize, const P2P: usize, const GO: usize>(
    tool_key: [u8; 16],
    load_state: LoadState,
    group_keys: &[u8],
    p2p_keys: &[u8],
    go_flags: &[u8],
) -> SecurityConfig<GRP, P2P, GO> {
    let state = SecurityState::from_config(SecurityConfig::default());
    state.set_tool_key(tool_key);
    state.set_load_state(load_state);

    state.grp_keys().borrow_mut().write_entries(0, group_keys).expect("group key fixture fits");
    state.p2p_keys().borrow_mut().write_entries(0, p2p_keys).expect("P2P key fixture fits");
    state.go_flags().borrow_mut().write_entries(0, go_flags).expect("GO flag fixture fits");

    state.to_config()
}

/// The SIAT/sequence store for the conformance DUT: the SIAT view over the
/// shared-memory key-value backend. `K = 0` persists the sending counter at its
/// exact value (no skip-ahead) so the value read back via PID 59 across
/// power-down / reset matches what the conformance suite asserts.
pub type ShmSiatStore = SiatStore<ShmSeqStorage, { sec_table_sizes::SIAT }, 0>;

pub struct GetrandomRng;

impl Rng for GetrandomRng {
    fn fill(buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom failed");
    }
}

impl SecureRng for GetrandomRng {}

// ============================================================================
// Certification Object Augment (Section 3.6 — KNX Secure Access Roles)
// ============================================================================

/// Object type for the KNX Certification Object (manufacturer-specific).
///
/// Active only during KNX certification testing. 0xC351 is 50001, the
/// value the EITT templates carry as `USER_OBJ_TYPE1` — their "User
/// Interface Object (IO1)", described there as being "used for testing
/// both Roles and Extended Interface Object addressing".
const CERTIFICATION_OBJECT_TYPE: InterfaceObjectType = InterfaceObjectType::Other(0xC351);

/// Property IDs on the Certification Object.
///
/// PID 51 serves the role-based access tests (data security 3.6). The
/// other four are the template's `ACCESSIBLE_PROP1`..`PROP4`, whose
/// required shapes come from its own field comments — a device is
/// expected to supply one property of each kind so the extended property
/// services have something manufacturer-specific to address.
mod cert_pid {
    /// Role-based access testing. UINT8, read/write.
    pub const ROLES: u16 = 51; // 0x33
    /// `ACCESSIBLE_PROP1` — PDT_GENERIC_02, restricted write level.
    pub const GENERIC_02: u16 = 52; // 0x34
    /// `ACCESSIBLE_PROP3` — PDT_FUNCTION.
    pub const FUNCTION: u16 = 54; // 0x36
    /// `ACCESSIBLE_PROP4` — PDT_GENERIC_01, long enough to fill an APDU.
    pub const LONG_ARRAY: u16 = 55; // 0x37
    /// `ACCESSIBLE_PROP2` — PDT_GENERIC_01 with a validated range.
    pub const RANGED: u16 = 201; // 0xC9
}

/// How many elements [`cert_pid::LONG_ARRAY`] holds.
///
/// The template reads `MAX_APDU_FIT_DATA` (F5h = 245) elements from it
/// and expects a response filling the whole 254-octet APDU, then reads
/// `MAX_APDU_LENGTH` (FEh = 254) and expects F4h. The property has to be
/// long enough that the first read is about the APDU rather than about
/// running out of property.
const CERT_LONG_ARRAY_LEN: usize = 245;

/// Accepted range for [`cert_pid::RANGED`].
///
/// Data security 4.2.12 writes each boundary and expects a distinct
/// return code: 00h is below the minimum (F6h), FFh above the maximum
/// (F7h), and 80h is a hole inside the range that must still be refused
/// (F8h). The three codes are the point of the case, so the property
/// needs all three conditions to be separable.
const CERT_RANGED_MIN: u8 = 0x01;
const CERT_RANGED_MAX: u8 = 0xFE;
const CERT_RANGED_VOID: u8 = 0x80;

/// Access policy for the Certification Object's PID 51.
///
/// `sec_off = 0x3FF`: all access types when security mode is off.
/// `sec_on = 0x0FF`: RoleX/A R+W, RoleX/A+C R+W, Tool/A+C R+W, Tool/A R+W,
/// Unlisted denied. The per-role R vs W granularity is enforced by the
/// augment's custom `can_read`/`can_write` checks (run before macro
/// dispatch via the `read_with_ctx` / `write_with_ctx` closures cannot
/// see `req.ctx`, so the bespoke logic lives in `handle_extra_pid_*`).
const CERT_PID51_POLICY: AccessPolicy = AccessPolicy::new(0x3FF, 0x0FF);

/// Augment that adds a Certification Object (IOT 0xC351) for Section 3.6
/// role-based access control conformance tests.
///
/// The object has a single read/write UINT8 property (PID 51) whose
/// access is governed by per-role permissions:
///
/// | Role | Required Security | Read | Write |
/// |------|-------------------|------|-------|
/// | 0    | A                 | yes  | yes   |
/// | 1    | A+C               | yes  | yes   |
/// | 2    | A                 | yes  | no    |
/// | 3    | A+C               | yes  | no    |
/// | 4    | A                 | no   | yes   |
/// | 5    | A+C               | no   | yes   |
/// | none | —                 | no   | no    |
/// | Tool | A or A+C          | yes  | yes   |
///
/// The access levels are written as audiences (03/04/01 §4.3.2.2
/// Table 1) rather than numbers: this augment is composed onto both
/// secure DUTs, and a literal `3` would be a *privileged* level on the
/// 16-level System 7 device rather than "free".
///
/// PID 1 (OBJECT_TYPE) is auto-emitted by the macro from the
/// `additional_objects` entry. PID 51 is marked `manual` because the
/// per-request access check needs `req.ctx`, which the macro's standard
/// `read = |this| ...` closure form doesn't expose. The bespoke logic
/// lives in `handle_extra_pid_read` / `handle_extra_pid_write` below.
#[interface_object_augment(
    additional_objects = [CERTIFICATION_OBJECT_TYPE],
)]
pub struct CertificationObjectAugment {
    // PID 1 OBJECT_TYPE — fixed `0xC351` read.
    #[io(
        pid = pid::OBJECT_TYPE,
        pdt = zweidraehte_proto::dpt::PDT_UnsignedInt,
        access = RO,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL, // 3FF/0CC
        rl = Runtime, wl = SystemManufacturer,
        read = |_this: &Self| -> [u8; 2] { 0xC351u16.to_be_bytes() },
    )]
    _object_type_io: (),

    // PID 51 ROLES — role-based access; bespoke logic in
    // `handle_extra_pid_*` below.
    #[io(
        pid = cert_pid::ROLES,
        pdt = zweidraehte_proto::dpt::PDT_UnsignedChar,
        access = RW,
        policy = CERT_PID51_POLICY,
        rl = Runtime, wl = Runtime,
        manual,
    )]
    _roles_io: (),

    // ------------------------------------------------------------------
    // The template's ACCESSIBLE_PROP1..PROP4.
    //
    // All four are `manual`: the macro's `read = |this| ...` closure form
    // cannot see the request, and each of these needs something from it —
    // a start index and count for the array, the written value for the
    // range check, the access context for the level check.
    // ------------------------------------------------------------------
    // PID 52 — PDT_GENERIC_02, restricted at both ends. 4.1.10 reads it
    // unauthorised and expects a refusal, and 4.2.11 / 4.3.11 / 4.4.11
    // authorise with the level-0 key, write, re-key, and expect the next
    // write refused. Level 0 for both means only a fully authorised
    // client gets through, which is the "higher access level" those
    // cases are named for.
    #[io(
        pid = cert_pid::GENERIC_02,
        pdt = zweidraehte_proto::dpt::PDT_Generic02,
        access = RW,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL, // 3FF/0CC
        rl = SystemManufacturer, wl = SystemManufacturer,
        manual,
    )]
    _generic02_io: (),

    // PID 201 — PDT_GENERIC_01 with the validated range above.
    #[io(
        pid = cert_pid::RANGED,
        pdt = zweidraehte_proto::dpt::PDT_Generic01,
        access = RW,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL,
        rl = Runtime, wl = Runtime,
        manual,
    )]
    _ranged_io: (),

    // PID 54 — PDT_FUNCTION. Reached through the function-property
    // services; a plain value write to it must fail with FEh, which the
    // value handlers below produce by declining it as a type mismatch.
    #[io(
        pid = cert_pid::FUNCTION,
        pdt = zweidraehte_proto::dpt::PDT_Function,
        access = RW,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL,
        rl = Runtime, wl = Runtime,
        manual,
    )]
    _function_io: (),

    // PID 55 — PDT_GENERIC_01, `CERT_LONG_ARRAY_LEN` elements.
    #[io(
        pid = cert_pid::LONG_ARRAY,
        pdt = zweidraehte_proto::dpt::PDT_Generic01,
        access = RW,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL,
        rl = Runtime, wl = Runtime,
        array(max = CERT_LONG_ARRAY_LEN as u16),
        manual,
    )]
    _long_array_io: (),

    /// The stored value for PID 51 (single byte).
    value: Cell<u8>,
    /// PID 52's two octets.
    generic02: Cell<[u8; 2]>,
    /// PID 201's single octet, seeded inside the accepted range.
    ranged: Cell<u8>,
    /// PID 55's elements. `RefCell` rather than `Cell` because reads
    /// slice it rather than copying the whole array out.
    long_array: RefCell<[u8; CERT_LONG_ARRAY_LEN]>,
}

impl CertificationObjectAugment {
    pub fn new() -> Self {
        Self {
            value: Cell::new(0),
            generic02: Cell::new([0, 0]),
            ranged: Cell::new(CERT_RANGED_MIN),
            long_array: RefCell::new([0u8; CERT_LONG_ARRAY_LEN]),
        }
    }

    /// Check whether the given access context permits reading PID 51.
    fn can_read(ctx: &AccessContext) -> bool {
        match ctx.role {
            ClientRole::Tool => true,
            ClientRole::Roles(mask) => {
                // Roles 0,1 (R+W), Roles 2,3 (R only) — all can read.
                // Roles 4,5 (W only) — cannot read.
                // Additionally, the security level must match the role's
                // requirement: even roles (0,2,4) require A, odd (1,3,5)
                // require A+C.
                Self::has_matching_read_role(mask, ctx.security)
            }
            ClientRole::Unlisted => false,
        }
    }

    /// Check whether the given access context permits writing PID 51.
    fn can_write(ctx: &AccessContext) -> bool {
        match ctx.role {
            ClientRole::Tool => true,
            ClientRole::Roles(mask) => {
                // Roles 0,1 (R+W), Roles 4,5 (W only) — can write.
                // Roles 2,3 (R only) — cannot write.
                Self::has_matching_write_role(mask, ctx.security)
            }
            ClientRole::Unlisted => false,
        }
    }

    /// Check whether the received security level satisfies a role's required
    /// security level. A+C satisfies both A+C and A requirements (superset).
    fn security_satisfies(received: SecurityMode, required: SecurityMode) -> bool {
        matches!(
            (received, required),
            (SecurityMode::AuthConf, SecurityMode::AuthConf)
                | (SecurityMode::AuthConf, SecurityMode::AuthOnly)
                | (SecurityMode::AuthOnly, SecurityMode::AuthOnly)
        )
    }

    /// Check if any role in the bitmask grants read access at the given
    /// security level. A role grants read if:
    /// 1. The role bit is set in the mask
    /// 2. The role is in the read-capable set (0,1,2,3)
    /// 3. The security level satisfies the role's requirement
    fn has_matching_read_role(mask: u16, security: SecurityMode) -> bool {
        // Read-capable roles: 0 (A), 1 (A+C), 2 (A), 3 (A+C)
        for role in 0..4u16 {
            if mask & (1 << role) == 0 {
                continue;
            }
            let required = if role % 2 == 0 { SecurityMode::AuthOnly } else { SecurityMode::AuthConf };
            if Self::security_satisfies(security, required) {
                return true;
            }
        }
        false
    }

    /// Check if any role in the bitmask grants write access at the given
    /// security level. A role grants write if:
    /// 1. The role bit is set in the mask
    /// 2. The role is in the write-capable set (0,1,4,5)
    /// 3. The security level satisfies the role's requirement
    fn has_matching_write_role(mask: u16, security: SecurityMode) -> bool {
        // Write-capable roles: 0 (A), 1 (A+C), 4 (A), 5 (A+C)
        for role in [0u16, 1, 4, 5] {
            if mask & (1 << role) == 0 {
                continue;
            }
            let required = if role % 2 == 0 { SecurityMode::AuthOnly } else { SecurityMode::AuthConf };
            if Self::security_satisfies(security, required) {
                return true;
            }
        }
        false
    }
}

impl Default for CertificationObjectAugment {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Manual fallback methods for PID 51 (role-based access checks).
//
// PIDs marked `manual` in the struct attributes route here. Unhandled
// PIDs return `None` so the augment chain falls through.
// ============================================================================

impl CertificationObjectAugment {
    /// All Certification PIDs are statically known — no runtime-conditional
    /// descriptors. Returns `None` to fall through to the macro's static
    /// descriptor table.
    pub fn handle_extra_pid_descriptor(
        &self,
        _object_type: InterfaceObjectType,
        _prop_id: u16,
    ) -> Option<zweidraehte_proto::properties::PropertyDescriptor> {
        None
    }

    pub fn handle_extra_pid_read<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        match req.pid {
            cert_pid::ROLES => {
                if !Self::can_read(&req.ctx) {
                    return Some(Err(PropertyError::AccessDenied));
                }
                let val = [self.value.get()];
                Some(val.read_property(req.start_idx, req.count, buf))
            }
            cert_pid::GENERIC_02 => Some(self.generic02.get().read_property(req.start_idx, req.count, buf)),
            cert_pid::RANGED => Some([self.ranged.get()].read_property(req.start_idx, req.count, buf)),
            cert_pid::LONG_ARRAY => Some(self.read_long_array(req.start_idx, req.count, buf)),
            // PID 54 is PDT_FUNCTION. A value read of a function
            // property is not a thing, so it falls through to the same
            // type-conflict answer as a value write.
            cert_pid::FUNCTION => Some(Err(PropertyError::TypeMismatch)),
            _ => None,
        }
    }

    pub fn handle_extra_pid_write<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        match req.pid {
            cert_pid::ROLES => {
                if !Self::can_write(&req.ctx) {
                    return Some(Err(PropertyError::AccessDenied));
                }
                if req.data.len() != 1 {
                    return Some(Err(PropertyError::TypeMismatch));
                }
                self.value.set(req.data[0]);
                Some(Ok(WriteResponse::Echo))
            }
            cert_pid::GENERIC_02 => {
                if req.data.len() != 2 {
                    return Some(Err(PropertyError::TypeMismatch));
                }
                self.generic02.set([req.data[0], req.data[1]]);
                Some(Ok(WriteResponse::Echo))
            }
            cert_pid::RANGED => {
                if req.data.len() != 1 {
                    return Some(Err(PropertyError::TypeMismatch));
                }
                // The three rejections 4.2.12 distinguishes. Order
                // matters only in that the void value sits inside the
                // range, so it has to be checked after the bounds rather
                // than folded into them.
                let value = req.data[0];
                if value < CERT_RANGED_MIN {
                    return Some(Err(PropertyError::ValueBelowMin));
                }
                if value > CERT_RANGED_MAX {
                    return Some(Err(PropertyError::ValueAboveMax));
                }
                if value == CERT_RANGED_VOID {
                    return Some(Err(PropertyError::ValueOutOfRange));
                }
                self.ranged.set(value);
                Some(Ok(WriteResponse::Echo))
            }
            cert_pid::LONG_ARRAY => {
                let start = req.start_idx as usize;
                let mut store = self.long_array.borrow_mut();
                // `start_idx` is 1-based, and element 0 is the element
                // count, which is not writable.
                if start == 0 || start - 1 + req.data.len() > store.len() {
                    return Some(Err(PropertyError::InvalidStartIndex));
                }
                store[start - 1..start - 1 + req.data.len()].copy_from_slice(req.data);
                Some(Ok(WriteResponse::Echo))
            }
            // A value write to a PDT_FUNCTION property: 4.2.13 and
            // 4.3.12 expect FEh, which is what TypeMismatch maps to.
            cert_pid::FUNCTION => Some(Err(PropertyError::TypeMismatch)),
            _ => None,
        }
    }

    /// Array read for [`cert_pid::LONG_ARRAY`].
    ///
    /// The blanket `PropertyRead` impl is single-element — it refuses
    /// anything but `start_idx == 1, count == 1` — so an array property
    /// has to do the slicing itself. Same convention the tunnelling
    /// augment follows: `start_idx == 0` answers the element count as a
    /// big-endian u16, and `start_idx >= 1` is a 1-based offset.
    fn read_long_array(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        let store = self.long_array.borrow();

        if start_idx == 0 {
            if buf.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            buf[..2].copy_from_slice(&(store.len() as u16).to_be_bytes());
            return Ok(2);
        }
        if count == 0 {
            return Err(PropertyError::InvalidElementCount);
        }

        let start = (start_idx - 1) as usize;
        if start >= store.len() {
            return Err(PropertyError::InvalidStartIndex);
        }
        // Clamped rather than refused: a read running off the end
        // returns what is there, and it is the APDU budget that decides
        // whether the answer fits — 4.1.8 wants F4h from that check, not
        // an address error from this one.
        let end = (start + count as usize).min(store.len());
        let needed = end - start;
        if buf.len() < needed {
            return Err(PropertyError::BufferTooSmall);
        }
        buf[..needed].copy_from_slice(&store[start..end]);
        Ok(needed)
    }

    /// The function-property body for PID 54.
    ///
    /// Three octets, so that with the return code in front the response
    /// carries the four the template expects: 4.2.13, 4.3.12 and 4.6.1
    /// all match `?? ?? ?? ??`, which is return code plus three. The
    /// contents are free — the wildcards say the template only cares
    /// that the property answers as a function property at all — so this
    /// echoes the service ID and the stored byte rather than a constant,
    /// which makes a wrong-PID answer visible in a trace.
    fn function_body(&self, req: &FunctionPropertyRequest<'_>) -> [u8; 3] {
        let service_id = req.service_data.get(1).copied().unwrap_or(0);
        [service_id, self.value.get(), 0x00]
    }

    pub fn handle_extra_pid_function_command<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        match req.prop_id {
            cert_pid::FUNCTION => Some(FunctionPropertyResult::with_code(
                zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode::Success,
                &self.function_body(req),
            )),
            _ => None,
        }
    }

    pub fn handle_extra_pid_function_state_read<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        match req.prop_id {
            cert_pid::FUNCTION => Some(FunctionPropertyResult::with_code(
                zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode::Success,
                &self.function_body(req),
            )),
            _ => None,
        }
    }
}

// ============================================================================
// Sequence Number Storage
// ============================================================================

use zweidraehte_device::storage::backends::{ByteIo, PackedSeqStore, region_len};
use zweidraehte_device::storage::region::FramSiatRegion;
use zweidraehte_device::storage::{HasConfigStore, HasSeqStore, SiatStore, seq};

use crate::dut::common::{ConformanceStack, DutConfigStore};

/// An [`ByteIo`] over the `mmap(MAP_SHARED)` seq region, addressed by a raw
/// pointer.
///
/// Reads and writes go directly to the mapping, so they are immediately visible
/// to the parent and survive child-process restarts (the parent holds the
/// memfd). The packed layout and all the offset/peer-table logic live in
/// [`PackedSeqStore`]; this is purely the medium, the host-side twin of the
/// embedded `FramRegion`.
pub struct ShmRegion {
    ptr: *mut u8,
}

// SAFETY: The embassy executor is single-threaded — no concurrent access.
unsafe impl Send for ShmRegion {}
unsafe impl Sync for ShmRegion {}

impl ShmRegion {
    /// # Safety
    /// `ptr` must be valid for the lifetime of this region and point to at
    /// least [`packed_seq::region_len(16)`](zweidraehte_device::storage::backends::region_len)
    /// writable bytes in a `MAP_SHARED` region.
    pub unsafe fn from_ptr(ptr: *mut u8) -> Self {
        Self { ptr }
    }
}

impl ByteIo for ShmRegion {
    type Error = core::convert::Infallible;

    fn read_at(&self, off: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        unsafe { core::ptr::copy_nonoverlapping(self.ptr.add(off as usize), buf.as_mut_ptr(), buf.len()) };
        Ok(())
    }

    fn write_at(&mut self, off: u32, data: &[u8]) -> Result<(), Self::Error> {
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(off as usize), data.len()) };
        Ok(())
    }
}

/// The SIAT region the shared-memory store binds: the same write-in-place
/// [`FramSiatRegion`] (`"KNXR"` magic) a FRAM device uses, sized to the
/// 256-byte tail `SharedMemory` carves out (`region_len(16)` = 146 fits). It
/// owns the whole tail at offset 0 (via `new()`), so it never appears in a
/// `REGIONS` array — and its `BATCH` parameter is moot (the harness builds
/// its `SiatStore` by hand with K = 0 for exact per-write persistence).
type ShmSiatRegion = FramSiatRegion<256, 16>;

/// Shared-memory sequence/SIAT store: [`PackedSeqStore`] over a [`ShmRegion`].
///
/// The mmap region is zero-filled by the kernel (and re-zeroed by the
/// parent's `SharedMemory::blank` between suites), which the layout relies
/// on: no magic yet means the store boots to defaults, and the peer-count
/// field reads 0 on first boot before any write.
pub type ShmSeqStorage = PackedSeqStore<ShmRegion, ShmSiatRegion, 16>;

// The bound region must cover the packed 16-slot layout within the shm tail.
const _: () = assert!(region_len(16) <= 256);

/// Static pointer to the seq region in shared memory.
/// Set by `dut_secure.rs` before stack creation.
static SEQ_PTR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Process-global pointer to the initialized store. Kept as an address so the
/// `OnceLock` remains `Sync`; access is single-threaded in every DUT child.
static SECURE_STORAGE_PTR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// The DUT's hand-written stores struct — the conformance twin of the
/// stores structs (`SecureStorage` etc.) on real devices. Holds only
/// the shared-memory SIAT store; the DUT's config persistence goes through
/// its own shm snapshot path, not the storage task.
pub struct ConformanceSecureStorage {
    pub seq: core::cell::RefCell<ShmSiatStore>,
}

impl HasSeqStore for ConformanceSecureStorage {
    type Seq = ShmSiatStore;
    fn seq_store(&self) -> &core::cell::RefCell<ShmSiatStore> {
        &self.seq
    }
}

// The storage-side half of a restart erase, exactly what the macro-emitted
// handle composes for a `seq:` store on real devices. The DUT runs the
// generic storage task, so this is driven through the same trait, from the
// same call site, as on a real device.
impl StorageHooks for ConformanceSecureStorage {
    fn erase(&self, code: EraseCode) {
        seq::erase_seq_on_factory_reset(&mut *self.seq.borrow_mut(), code);
    }
}

/// The secure DUT's complete stores handle: the shm config snapshot plus the
/// shm SIAT/sequence store.
///
/// The conformance twin of `SecureStorage<C, S>` on a real device, and split
/// the same way — a config half and a seq half — because the storage task
/// wants both behind one `D::Storage`. It exists as a wrapper rather than as
/// extra impls on [`ConformanceSecureStorage`] because that struct is shared
/// verbatim by the System B and System 7 secure DUTs, while the config half
/// is parameterised by which stack it is persisting.
pub struct DutSecureStorage<S: ConformanceStack> {
    config: DutConfigStore<S>,
    secure: &'static ConformanceSecureStorage,
}

impl<S: ConformanceStack> DutSecureStorage<S> {
    pub const fn new(config: DutConfigStore<S>, secure: &'static ConformanceSecureStorage) -> Self {
        Self { config, secure }
    }
}

impl<S: ConformanceStack> HasConfigStore for DutSecureStorage<S> {
    type State = <DutConfigStore<S> as HasConfigStore>::State;
    type Config = <DutConfigStore<S> as HasConfigStore>::Config;

    fn save_config(&self, state: &Self::State) {
        self.config.save_config(state);
    }

    fn load_config(&self) -> Option<Self::Config> {
        self.config.load_config()
    }
}

impl<S: ConformanceStack> HasSeqStore for DutSecureStorage<S> {
    type Seq = ShmSiatStore;
    fn seq_store(&self) -> &core::cell::RefCell<ShmSiatStore> {
        self.secure.seq_store()
    }
}

impl<S: ConformanceStack> StorageHooks for DutSecureStorage<S> {
    /// The sequence store's erase — the config half has nothing durable of
    /// its own beyond the snapshot the following save rewrites.
    fn erase(&self, code: EraseCode) {
        self.secure.erase(code);
    }

    async fn on_restart(&self, code: EraseCode) {
        self.config.on_restart(code).await;
    }
}

/// Boot the SIAT store from the shm mapping and place it in its static home.
/// Call once per DUT process, after [`set_seq_shm_ptr`], before
/// `zweidraehte_device::new()`.
pub fn init_secure_storage() -> &'static ConformanceSecureStorage {
    static STORAGE: static_cell::StaticCell<ConformanceSecureStorage> = static_cell::StaticCell::new();
    let seq = SiatStore::boot(create_seq_storage()).expect("shm seq store boot is infallible");
    let storage = &*STORAGE.init(ConformanceSecureStorage { seq: core::cell::RefCell::new(seq) });
    SECURE_STORAGE_PTR
        .set(storage as *const ConformanceSecureStorage as usize)
        .expect("secure storage initialized once");
    storage
}

/// The process-global sequence store installed by [`init_secure_storage`].
///
/// The full stack receives this store through its `HasSeqStore` handle. The
/// polling micro DUT has no resource graph, so its zero-sized adapter uses
/// this accessor instead. Both paths still exercise the same packed
/// shared-memory backend and the same full-reset tail clearing.
pub fn secure_seq_store() -> &'static core::cell::RefCell<ShmSiatStore> {
    let ptr = *SECURE_STORAGE_PTR.get().expect("init_secure_storage() must run before stack creation");
    // SAFETY: `init_secure_storage` places the value in a process-lifetime
    // `StaticCell`; the child process owns the SHM mapping for the same life.
    unsafe { &(*(ptr as *const ConformanceSecureStorage)).seq }
}

/// Seed the two tool addresses provisioned in every EITT secure boot image.
///
/// Call this only when [`load_or_seed_snapshot_with_status`](super::common::load_or_seed_snapshot_with_status)
/// reports a fresh image. Ordinary process restarts must preserve intentional
/// SIAT writes and erases performed by the conformance cases.
pub fn seed_eitt_boot_siat() {
    let mut store = secure_seq_store().borrow_mut();

    store.siat_write_entry(0, 0xAFFE, [0; 6]).expect("EDI SIAT entry fits");
    store.siat_write_entry(1, 0xAFFD, [0; 6]).expect("alternate EDI SIAT entry fits");
}

/// Build the shared-memory sequence storage from the pointer installed
/// by [`set_seq_shm_ptr`].
///
/// The conformance harness is the one place whose storage can be built
/// "from nothing" (a process-global shared-memory mapping); hardware
/// devices construct theirs in `main` from peripherals and thread it
/// through `StateInit` → `SecureResources`.
pub fn create_seq_storage() -> ShmSeqStorage {
    let ptr = *SEQ_PTR.get().expect("set_seq_shm_ptr() must be called before stack creation");
    ShmSeqStorage::new(unsafe { ShmRegion::from_ptr(ptr as *mut u8) })
}

/// Set the shared memory seq pointer. Must be called once before the
/// stack is created.
pub fn set_seq_shm_ptr(ptr: *mut u8) {
    SEQ_PTR.set(ptr as usize).expect("SEQ_PTR already set");
}
