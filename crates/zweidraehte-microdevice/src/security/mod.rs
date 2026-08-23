//! The seam a profile module plugs into.
//!
//! KNX Data Security is a *profile module* (06 Profiles v02.02.01 §9.1
//! "Profile Module S-AL") composed onto a base profile rather than a profile
//! of its own. On the families this crate carries that composition has an
//! unusual shape, and it is the shape the bench MV-0021 device demonstrates:
//! its Security Interface Object is reachable **only** by object type, as
//! `ObjectType=17 Instance=1`, while the indexed roster stays at the four
//! classic objects the mask has always had.
//!
//! So the seam is not "one more interface object". It is a second address
//! space — the type/occurrence one the extended services use — that a module
//! can occupy without touching the indexed roster a family publishes.
//!
//! [`NoSecurity`] is the default and is zero-sized: its object type is
//! `None`, so every route into it is a compile-time-known dead branch and a
//! plain BCU1/BCU2/System 7 image carries none of this.

use heapless::Vec;

use zweidraehte_proto::access::AccessContext;
use zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode;
use zweidraehte_proto::messages::apdu::restart::EraseCode;
use zweidraehte_proto::properties::PropertyDescriptor;
use zweidraehte_proto::security::{SequenceNumberStorage, SiatAccess};

use crate::frame::FrameBuf;
use crate::sal::RequestContext;

/// Durable counters, SIAT storage, and entropy required by a micro S-AL.
///
/// Keeping these operations on the profile module's resource avoids adding a
/// platform trait or RNG field to every plain `Microdevice`.
pub trait MicroSecurityResources: SequenceNumberStorage + SiatAccess {
    /// Fill the six-octet nonce used by an `S-A_Sync_Res`.
    fn fill_random(&mut self, random: &mut [u8; 6]);
}

/// Reset work completed after its response has been protected and queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledRestart {
    pub erase_code: u8,
    /// `None` for a confirmed restart; factory reset variants carry whether
    /// the individual address must be erased.
    pub wipe_individual_address: Option<bool>,
}

/// A profile module contributing an interface object reached by type.
///
/// Kept deliberately narrow: the module owns some state and answers property
/// reads and writes for one object type. Everything else — frame handling,
/// the transport layer, the classic management model — stays the base
/// stack's, which is what "composed onto a base profile" means.
pub trait SecurityModule: 'static {
    /// Per-device state this module owns, held inside [`Microdevice`].
    ///
    /// Deliberately not `Default`: a secure device's state carries its FDSK
    /// and its sequence store, and neither has a meaningful default —
    /// defaulting the FDSK would mean a device that ships with a known key.
    /// [`Microdevice::new`] stays available for modules whose state *is*
    /// `Default`, which is how [`NoSecurity`] keeps every plain call site
    /// unchanged.
    ///
    /// [`Microdevice`]: crate::device::Microdevice
    /// [`Microdevice::new`]: crate::device::Microdevice::new
    type State;

    /// Request-scoped metadata needed to protect a response.
    ///
    /// This is `()` for [`NoSecurity`], keeping the ordinary reply path free
    /// of Data Secure fields. A secure module can choose a richer value.
    type ReplyContext: Copy;

    /// Reply metadata for a plaintext request.
    fn plain_reply_context() -> Self::ReplyContext;

    /// Whether this module brings the Data Secure profile obligations.
    ///
    /// The core uses this constant for services that exist only on a secure
    /// profile (extended management and master reset). For [`NoSecurity`] the
    /// branches fold away, keeping those services out of a plain image.
    const ENABLED: bool = false;

    /// Extra APDU octets carried by this module's outer wire envelope.
    ///
    /// This affects buffer capacity, not `PID_MAX_APDULENGTH`: that property
    /// describes the plaintext APDU the application can process. A plain
    /// profile has no envelope; Data Secure adds the fixed S-A_Data overhead.
    const FRAME_OVERHEAD: usize = 0;

    /// The interface object type this module serves, if it serves one.
    ///
    /// `None` for a module that contributes no object, which is what makes
    /// [`NoSecurity`] cost nothing: the resolution branch folds away.
    ///
    /// The object is reachable by type and occurrence 1 only. A family that
    /// wants it in its *indexed* roster as well — micro System 7 secure will,
    /// since 06 Profiles §9.1.2.6.1 gives it index 5 there — publishes it
    /// through `MicroDeviceFamily::object_type` in the ordinary way; this is
    /// for the BCU2 case, where the indexed roster must not grow.
    const OBJECT_TYPE: Option<u16> = None;

    /// Descriptor lookup for the module object's property roster.
    fn property_descriptor(_prop_id: u16) -> Option<(u16, PropertyDescriptor)> {
        None
    }

    /// Descriptor lookup by the property's observable zero-based index.
    fn property_descriptor_at(_index: u16) -> Option<PropertyDescriptor> {
        None
    }

    /// Read a range of property elements from the module's object.
    ///
    /// One-based element addressing with the `start = 0` element-count probe,
    /// the same convention the interface-object property services use
    /// everywhere. `None` means "no such property", which the caller renders
    /// as the address error.
    fn property_read<const N: usize>(
        _state: &Self::State,
        _prop_id: u16,
        _count: u8,
        _start: u16,
    ) -> Option<Vec<u8, N>> {
        None
    }

    /// `A_FunctionPropertyExtCommand` against the module's object.
    ///
    /// `None` means the module has no such function property, which the
    /// caller renders as the empty response 03/03/07 §3.4.4 specifies.
    fn function_command<const N: usize>(
        _state: &mut Self::State,
        _prop_id: u16,
        _data: &[u8],
    ) -> Option<FunctionResult<N>> {
        None
    }

    /// `A_FunctionPropertyExtState_Read` against the module's object.
    fn function_state_read<const N: usize>(
        _state: &Self::State,
        _prop_id: u16,
        _data: &[u8],
    ) -> Option<FunctionResult<N>> {
        None
    }

    /// Try to unwrap a secure frame in place, returning how to proceed.
    ///
    /// `buf[..len]` is the canonical frame. On success the buffer holds the
    /// decrypted plaintext and `len` is shortened. `response_tpci` is the
    /// outgoing TPCI already selected by the core; sync responses need it
    /// before CCM authenticates their TPCI/APCI field. Default: not a secure
    /// module, every frame passes through.
    // These are the independent facts at the S-AL boundary. A request struct
    // would merely move the argument list and make the plain module heavier.
    #[allow(clippy::too_many_arguments)]
    fn process_incoming(
        _state: &mut Self::State,
        _buf: &mut [u8],
        _len: &mut usize,
        _now_ms: u32,
        _own_ia: u16,
        _serial_number: [u8; 6],
        _time_divisor: u32,
        _group_key_index: Option<u16>,
        _response_tpci: u8,
    ) -> SalResult<Self::ReplyContext> {
        SalResult::Passthrough
    }

    /// Protect an outgoing reply when its request requires it.
    ///
    /// Owning the resize here is what makes the plain implementation truly
    /// empty: callers do not carry an `Option<ReplySecurity>` or a secure
    /// capacity branch through every non-secure response.
    fn protect_reply<const N: usize>(
        _state: &mut Self::State,
        _reply: Self::ReplyContext,
        _frame: &mut FrameBuf<N>,
    ) -> bool {
        true
    }

    /// Whether the device's Security Mode is currently enabled.
    fn security_mode_enabled(_state: &Self::State) -> bool {
        false
    }

    /// Reset the module to its factory state (erase codes 02h/07h).
    ///
    /// Called from the device's master-reset handler. A `NoSecurity` module
    /// has nothing to reset; `DataSecure` clears its tables, reverts the
    /// tool key to the FDSK, and disables security mode.
    fn factory_reset(_state: &mut Self::State, _reply: &mut Self::ReplyContext, _code: EraseCode) -> bool {
        true
    }

    /// Schedule a restart after the current master-reset response is queued.
    fn schedule_restart(_state: &mut Self::State, _restart: ScheduledRestart) {}

    /// Consume a restart scheduled by the current management request.
    fn take_scheduled_restart(_state: &mut Self::State) -> Option<ScheduledRestart> {
        None
    }

    /// Whether a memory operation is allowed by the security profile.
    ///
    /// The legacy memory-region level remains a separate mandatory check.
    fn memory_access_allowed(state: &Self::State, access: AccessContext) -> bool {
        !Self::security_mode_enabled(state) || access.security == zweidraehte_proto::access::SecurityMode::AuthConf
    }

    /// Required security bits for a zero-based group-object slot.
    fn group_security_flags(_state: &Self::State, _go_index: u16) -> Option<u8> {
        None
    }

    /// Protect an outgoing group telegram with the key selected by the
    /// address table's one-based group index.
    fn wrap_group(
        _state: &mut Self::State,
        _group_key_index: u16,
        _security_flags: u8,
        _buf: &mut [u8],
        _len: &mut usize,
        _capacity: usize,
    ) -> bool {
        false
    }

    /// Record an access-policy rejection after successful authentication.
    fn log_access_failure(_state: &Self::State, _source: u16, _frame: &[u8]) {}

    /// Write a range of property elements and report the wire-level result.
    ///
    /// Access policy is checked by the service before this hook. Keeping the
    /// result code here prevents malformed data and persistence failures from
    /// being misreported as authorization failures.
    fn property_write(
        _state: &mut Self::State,
        _prop_id: u16,
        _count: u8,
        _start: u16,
        _data: &[u8],
    ) -> PropertyReturnCode {
        PropertyReturnCode::AddressVoid
    }
}

/// The absence of a profile module: no object, no state, no code.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSecurity;

impl SecurityModule for NoSecurity {
    type State = ();
    type ReplyContext = ();

    #[inline(always)]
    fn plain_reply_context() {}

    #[inline(always)]
    fn protect_reply<const N: usize>(
        _state: &mut Self::State,
        _reply: Self::ReplyContext,
        _frame: &mut FrameBuf<N>,
    ) -> bool {
        true
    }

    #[inline(always)]
    fn security_mode_enabled(_state: &Self::State) -> bool {
        false
    }

    #[inline(always)]
    fn memory_access_allowed(_state: &Self::State, _access: AccessContext) -> bool {
        true
    }

    #[inline(always)]
    fn group_security_flags(_state: &Self::State, _go_index: u16) -> Option<u8> {
        None
    }
}

/// Where a `(object_type, occurrence)` pair resolved to.
///
/// The two variants are the two address spaces a device can hold an object
/// in, and keeping them apart is the point: an object the profile module
/// contributes must not acquire an index, because on BCU2 the indexed roster
/// is exactly the four objects the mask has always published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectRoute {
    /// An object in the family's indexed roster.
    Indexed(u8),
    /// The profile module's object, which has no index.
    Module,
}

/// One function-property answer: a return code and the data after it.
pub struct FunctionResult<const N: usize> {
    pub code: PropertyReturnCode,
    pub data: Vec<u8, N>,
}

mod data_secure;

pub use data_secure::{DataSecure, DataSecureState, SECURITY_IO_TYPE};

/// What the S-AL decided about an incoming frame.
pub enum SalResult<R> {
    /// Not a secure frame, or this module has no security. Pass through to
    /// the existing dispatch with the given access context.
    Passthrough,
    /// Decrypted successfully. The buffer now holds the plaintext APDU and
    /// should be re-parsed and dispatched with the given access context.
    Decrypted(RequestContext<R>),
    /// Frame dropped (bad MAC, replay, policy, etc.).
    Dropped,
    /// A response was produced (sync response). The frame is in the buffer.
    Response { len: usize },
}
