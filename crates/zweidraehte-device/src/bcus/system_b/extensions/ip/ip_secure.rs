//! KNX IP Secure extension state and augment (03/08/09 §2.3.1).
//!
//! Persists the IP Secure secrets and policy of the KNXnet/IP Parameter
//! Object — PIDs 91–97 — and exposes them to the link layer through
//! [`IpSecureStateView`]. The session crypto itself lives in the KNX/IP
//! link layer ([`session_handler`](crate::layers::linklayers::knxip));
//! this module is pure storage + property dispatch.
//!
//! The `ExtensionState` impl is hand-written instead of derived because
//! the Device Authentication Code factory default is the FDSK
//! (§2.3.1.3.3) — a resource-dependent seed the field-mapping derive
//! cannot express. The pattern mirrors `SecureExtensionState`'s tool-key
//! seeding.

use core::cell::{Cell, RefCell};

use serde::{Deserialize, Serialize};

use crate::StackDefinition;
use crate::bcus::system_b::extensions::security::{SecurityTable, read_table_with_count_probe, write_security_table};
use crate::bcus::system_b::{Extension, ExtensionState};
use crate::ip::{HasIpSecureView, IpSecureStateView};
use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult, PropertyBuf,
    PropertyError, WriteResponse, interface_object_augment, pid,
};
use crate::restart::EraseCode;
use crate::service::ServiceCtx;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{
    InterfaceObjectType, PDT_Function, PDT_Generic02, PDT_Generic16, PDT_Scaling, PDT_UnsignedInt,
};
use zweidraehte_proto::messages::knxip::substructs::ServiceFamily;

/// PBKDF2 hash of the empty password (§2.3.1.4.3) — the ex-factory
/// value of every PID_PASSWORD_HASHES entry:
/// `PBKDF2(HMAC-SHA256, "", "user-password.1.secure.ip.knx.org", 65536, 128)`.
pub const EMPTY_PASSWORD_HASH: [u8; 16] =
    [0xE9, 0xC3, 0x04, 0xB9, 0x14, 0xA3, 0x51, 0x75, 0xFD, 0x7D, 0x1C, 0x67, 0x3A, 0xB5, 0x2F, 0xE1];

/// Factory default multicast latency tolerance in ms (§2.3.1.6.3).
const DEFAULT_MULTICAST_LATENCY_TOLERANCE_MS: u16 = 2000;
/// Factory default sync latency fraction, 10.2 % (§2.3.1.7.3).
const DEFAULT_SYNC_LATENCY_FRACTION: u8 = 0x1A;

// ============================================================================
// Config
// ============================================================================

/// Persisted KNX IP Secure configuration (PIDs 91–97).
///
/// `MAX_PW` is the password-hash slot count (= highest supported User
/// ID, 1..=127; minimum 1 for the management user). `MAX_TU` is the
/// tunnelling-users table capacity.
#[derive(Clone, Serialize, Deserialize)]
pub struct IpSecureExtensionConfig<const MAX_PW: usize, const MAX_TU: usize> {
    /// PID 91 — secure backbone key; all-zero = not provisioned.
    pub backbone_key: [u8; 16],
    /// PID 92 — device authentication code; all-zero = "seed FDSK on load".
    pub device_authentication_code: [u8; 16],
    /// PID 93 — password hashes, entry `i` = User ID `i + 1`.
    pub password_hashes: SecurityTable<MAX_PW, 16>,
    /// PID 94 — required security version per family (0 = plain allowed).
    pub secured_device_management: u8,
    pub secured_tunnelling: u8,
    pub secured_routing: u8,
    /// PID 95.
    pub multicast_latency_tolerance_ms: u16,
    /// PID 96.
    pub sync_latency_fraction: u8,
    /// PID 97 — `(user_id, tunnelling_address_index)` pairs.
    pub tunnelling_users: SecurityTable<MAX_TU, 2>,
    // The 03/08/09 §2.2.4.2 multicast-timer persistence watermark is
    // intentionally *not* in this blob. It advances far more often than the
    // ETS-written config (potentially per received frame under an
    // adversarial peer), so riding the whole-config save would erase+rewrite
    // the config sector on every advance. It lives in its own dedicated
    // store (`mc_timer:` in the device's stores block), which the KNX/IP
    // Secure link layer reads and writes directly through the storage
    // handle on its context — see the runtime state below.
}

impl<const MAX_PW: usize, const MAX_TU: usize> crate::bcus::system_b::ExtensionConfig
    for IpSecureExtensionConfig<MAX_PW, MAX_TU>
{
}

impl<const MAX_PW: usize, const MAX_TU: usize> Default for IpSecureExtensionConfig<MAX_PW, MAX_TU> {
    fn default() -> Self {
        // §2.3.1.4.3: ex-factory, every supported password is the empty
        // string (its fixed PBKDF2 hash). §2.3.1.5.3: no family requires
        // security. §2.3.1.8.4: the tunnelling users table is empty.
        let mut password_hashes = SecurityTable::new();
        for i in 0..MAX_PW {
            let _ = password_hashes.write_entries(i as u16, &EMPTY_PASSWORD_HASH);
        }
        Self {
            backbone_key: [0; 16],
            device_authentication_code: [0; 16],
            password_hashes,
            secured_device_management: 0,
            secured_tunnelling: 0,
            secured_routing: 0,
            multicast_latency_tolerance_ms: DEFAULT_MULTICAST_LATENCY_TOLERANCE_MS,
            sync_latency_fraction: DEFAULT_SYNC_LATENCY_FRACTION,
            tunnelling_users: SecurityTable::new(),
        }
    }
}

// ============================================================================
// Runtime state
// ============================================================================

/// Non-serializable construction inputs for [`IpSecureExtensionState`].
pub struct IpSecureResources {
    /// Factory Default Setup Key — the ex-factory Device Authentication
    /// Code (§2.3.1.3.3), kept for factory reset re-seeding.
    pub fdsk: [u8; 16],
}

/// Runtime state for the KNX IP Secure PIDs, interior-mutable so the
/// augment writes through `&self`.
pub struct IpSecureExtensionState<const MAX_PW: usize, const MAX_TU: usize> {
    backbone_key: Cell<[u8; 16]>,
    device_authentication_code: Cell<[u8; 16]>,
    password_hashes: RefCell<SecurityTable<MAX_PW, 16>>,
    secured_device_management: Cell<u8>,
    secured_tunnelling: Cell<u8>,
    secured_routing: Cell<u8>,
    multicast_latency_tolerance_ms: Cell<u16>,
    sync_latency_fraction: Cell<u8>,
    tunnelling_users: RefCell<SecurityTable<MAX_TU, 2>>,
    persisted_mc_timer: Cell<u64>,
    /// Runtime-only: FDSK for DAC factory-reset re-seeding.
    fdsk: [u8; 16],
    /// Runtime-only: wakes the link-layer runtime when the backbone
    /// key or the Routing security version changes (timer sync events
    /// E11 / start-stop, §2.2.2.3.2.8). Mirrors the routing-multicast
    /// rebind channel plumbing.
    mc_sync_events: embassy_sync::channel::Channel<
        embassy_sync::blocking_mutex::raw::NoopRawMutex,
        crate::ip::IpSecureSyncEvent,
        2,
    >,
}

impl<const MAX_PW: usize, const MAX_TU: usize> ExtensionState for IpSecureExtensionState<MAX_PW, MAX_TU> {
    type Config = IpSecureExtensionConfig<MAX_PW, MAX_TU>;
    type Resources = IpSecureResources;

    fn from_config(config: Self::Config, resources: Self::Resources) -> Self {
        // A factory-fresh device carries a zero DAC in its config; seed
        // the FDSK so SESSION_RESPONSE MACs work out of the box
        // (§2.3.1.3.3). A non-zero persisted DAC was written by ETS and
        // is kept.
        let dac = if config.device_authentication_code == [0u8; 16] {
            resources.fdsk
        } else {
            config.device_authentication_code
        };
        Self {
            backbone_key: Cell::new(config.backbone_key),
            device_authentication_code: Cell::new(dac),
            password_hashes: RefCell::new(config.password_hashes),
            secured_device_management: Cell::new(config.secured_device_management),
            secured_tunnelling: Cell::new(config.secured_tunnelling),
            secured_routing: Cell::new(config.secured_routing),
            multicast_latency_tolerance_ms: Cell::new(config.multicast_latency_tolerance_ms),
            sync_latency_fraction: Cell::new(config.sync_latency_fraction),
            tunnelling_users: RefCell::new(config.tunnelling_users),
            // Seeded to 0 here; the KNX/IP Secure link layer reads the
            // durable watermark from the mc_timer store (directly through
            // the storage handle) right before its first sync start. A
            // device without such a store (or a blank one) correctly starts
            // at 0 and re-acquires the timer from the multicast group
            // (03/08/09 §2.2.4.2).
            persisted_mc_timer: Cell::new(0),
            fdsk: resources.fdsk,
            mc_sync_events: embassy_sync::channel::Channel::new(),
        }
    }

    fn to_config(&self) -> Self::Config {
        IpSecureExtensionConfig {
            backbone_key: self.backbone_key.get(),
            device_authentication_code: self.device_authentication_code.get(),
            password_hashes: self.password_hashes.borrow().clone(),
            secured_device_management: self.secured_device_management.get(),
            secured_tunnelling: self.secured_tunnelling.get(),
            secured_routing: self.secured_routing.get(),
            multicast_latency_tolerance_ms: self.multicast_latency_tolerance_ms.get(),
            sync_latency_fraction: self.sync_latency_fraction.get(),
            tunnelling_users: self.tunnelling_users.borrow().clone(),
        }
    }

    fn on_erase(&self, code: EraseCode) {
        if matches!(code, EraseCode::FactoryReset | EraseCode::FactoryResetKeepIA) {
            let defaults = IpSecureExtensionConfig::<MAX_PW, MAX_TU>::default();
            self.backbone_key.set(defaults.backbone_key);
            // §2.3.1.3.3: after every factory reset the DAC is the FDSK.
            self.device_authentication_code.set(self.fdsk);
            *self.password_hashes.borrow_mut() = defaults.password_hashes;
            self.secured_device_management.set(defaults.secured_device_management);
            self.secured_tunnelling.set(defaults.secured_tunnelling);
            self.secured_routing.set(defaults.secured_routing);
            self.multicast_latency_tolerance_ms.set(defaults.multicast_latency_tolerance_ms);
            self.sync_latency_fraction.set(defaults.sync_latency_fraction);
            *self.tunnelling_users.borrow_mut() = defaults.tunnelling_users;
            // The watermark belongs to the wiped backbone key (§2.2.4.2).
            self.persisted_mc_timer.set(0);
        }
    }
}

impl<const MAX_PW: usize, const MAX_TU: usize> IpSecureExtensionState<MAX_PW, MAX_TU> {
    fn secured_version_cell(&self, family: ServiceFamily) -> Option<&Cell<u8>> {
        match family {
            ServiceFamily::DeviceManagement => Some(&self.secured_device_management),
            ServiceFamily::Tunneling => Some(&self.secured_tunnelling),
            ServiceFamily::Routing => Some(&self.secured_routing),
            _ => None,
        }
    }
}

// ============================================================================
// IpSecureStateView — the link layer's window into this state
// ============================================================================

impl<const MAX_PW: usize, const MAX_TU: usize> IpSecureStateView for IpSecureExtensionState<MAX_PW, MAX_TU> {
    fn backbone_key(&self) -> [u8; 16] {
        self.backbone_key.get()
    }

    fn device_authentication_code(&self) -> [u8; 16] {
        self.device_authentication_code.get()
    }

    fn password_hash(&self, user_id: u8) -> Option<[u8; 16]> {
        if user_id == 0 {
            return None;
        }
        let table = self.password_hashes.borrow();
        let index = (user_id - 1) as u16;
        if index >= table.count() {
            return None;
        }
        let mut hash = [0u8; 16];
        table.read_entries(index, 1, &mut hash).ok()?;
        // An all-zero entry marks a deliberately disabled user slot.
        (hash != [0u8; 16]).then_some(hash)
    }

    fn secured_service_family(&self, family: ServiceFamily) -> u8 {
        self.secured_version_cell(family).map(Cell::get).unwrap_or(0)
    }

    fn multicast_latency_tolerance_ms(&self) -> u16 {
        self.multicast_latency_tolerance_ms.get()
    }

    fn sync_latency_fraction(&self) -> u8 {
        self.sync_latency_fraction.get()
    }

    fn tunnelling_user_allowed(&self, user_id: u8, tunnelling_slot: u8) -> bool {
        // §2.3.1.8.3: the management user has implicit access to every
        // tunnelling address and never appears in the table.
        if user_id == crate::layers::linklayers::knxip::secure::user_id::MANAGEMENT {
            return true;
        }
        let table = self.tunnelling_users.borrow();
        (0..table.count()).any(|i| {
            let mut entry = [0u8; 2];
            table.read_entries(i, 1, &mut entry).is_ok() && entry == [user_id, tunnelling_slot]
        })
    }

    fn persisted_mc_timer(&self) -> u64 {
        self.persisted_mc_timer.get()
    }

    fn set_persisted_mc_timer(&self, value: u64) {
        // Only updates the in-memory mirror; the 03/08/09 §2.2.4.2
        // durability lives in the runtime's `drain_mc_persist`, which
        // writes the flagged value straight to the mc_timer store before
        // the frame goes out.
        self.persisted_mc_timer.set(value);
    }

    fn mc_sync_event_channel(
        &self,
    ) -> &embassy_sync::channel::Channel<embassy_sync::blocking_mutex::raw::NoopRawMutex, crate::ip::IpSecureSyncEvent, 2>
    {
        &self.mc_sync_events
    }
}

impl<const MAX_PW: usize, const MAX_TU: usize> HasIpSecureView for IpSecureExtensionState<MAX_PW, MAX_TU> {
    fn ip_secure_view(&self) -> Option<&dyn IpSecureStateView> {
        Some(self)
    }
}

// ============================================================================
// IpSecureAugment — PIDs 91–97 on the KNXnet/IP Parameter Object
// ============================================================================

/// Property dispatch for the IP Secure PIDs.
///
/// A peer of [`IpAugment`](super::IpAugment) / [`TunnellingAugment`](super::TunnellingAugment)
/// on Object Type 11 — the three own disjoint PID ranges, so chain
/// order is irrelevant for correctness.
///
/// Access policies follow §2.3.1: the key material (91–93) is
/// write-only with Tool-Key-secured confidential writes (`008/008`);
/// PIDs 94–96 read openly but write Tool-only (`15D/15D`); the
/// tunnelling-users table (97) is Tool-only both ways (`00C/00C`).
#[interface_object_augment(target_objects = [InterfaceObjectType::IPParameter])]
pub struct IpSecureAugment<'a, const MAX_PW: usize, const MAX_TU: usize> {
    /// Borrowed persisted IP Secure state.
    pub state: &'a IpSecureExtensionState<MAX_PW, MAX_TU>,

    // PID 91 BACKBONE_KEY — write-only 16-byte key.
    #[io(
        pid = pid::ip::BACKBONE_KEY,
        pdt = PDT_Generic16,
        access = WO,
        policy = AccessPolicy::TOOL_ONLY_CONFIDENTIAL, // 008/008
        rl = 0, wl = 2,
        write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
            if data.len() < 16 {
                return Err(PropertyError::BufferTooSmall);
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&data[..16]);
            // §2.2.2.2.2: writing a *different* key resets the
            // multicast timer and restarts the sync (event E11);
            // rewriting the identical key is event E12 — no action.
            // The reset itself runs in the link-layer task, woken
            // through the sync-event channel.
            let changed = this.state.backbone_key.replace(key) != key;
            if changed {
                let _ = this.state.mc_sync_events.try_send(crate::ip::IpSecureSyncEvent::BackboneKeyChanged);
            }
            Ok(WriteResponse::Echo)
        },
    )]
    _backbone_key_io: (),

    // PID 92 DEVICE_AUTHENTICATION_CODE — write-only 16-byte key.
    #[io(
        pid = pid::ip::DEVICE_AUTHENTICATION_CODE,
        pdt = PDT_Generic16,
        access = WO,
        policy = AccessPolicy::TOOL_ONLY_CONFIDENTIAL, // 008/008
        rl = 0, wl = 2,
        write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
            if data.len() < 16 {
                return Err(PropertyError::BufferTooSmall);
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&data[..16]);
            this.state.device_authentication_code.set(key);
            Ok(WriteResponse::Echo)
        },
    )]
    _device_authentication_code_io: (),

    // PID 93 PASSWORD_HASHES — write-only PDT_GENERIC_16 array,
    // indexed by User ID.
    #[io(
        pid = pid::ip::PASSWORD_HASHES,
        pdt = PDT_Generic16,
        access = WO,
        policy = AccessPolicy::TOOL_ONLY_CONFIDENTIAL, // 008/008
        rl = 0, wl = 2,
        array(max = MAX_PW as u16),
        manual,
    )]
    _password_hashes_io: (),

    // PID 94 SECURED_SERVICE_FAMILIES — PDT_FUNCTION, dispatched via
    // FunctionPropertyCommand / FunctionPropertyStateRead.
    #[io(
        pid = pid::ip::SECURED_SERVICE_FAMILIES,
        pdt = PDT_Function,
        access = RW,
        policy = AccessPolicy::new(0x15D, 0x15D),
        rl = 3, wl = 2,
        manual,
    )]
    _secured_service_families_io: (),

    // PID 95 MULTICAST_LATENCY_TOLERANCE — u16 milliseconds.
    #[io(
        pid = pid::ip::MULTICAST_LATENCY_TOLERANCE,
        pdt = PDT_UnsignedInt,
        access = RW,
        policy = AccessPolicy::new(0x15D, 0x15D),
        rl = 3, wl = 2,
        read = |this: &Self| -> [u8; 2] { this.state.multicast_latency_tolerance_ms.get().to_be_bytes() },
        write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
            if data.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            this.state.multicast_latency_tolerance_ms.set(u16::from_be_bytes([data[0], data[1]]));
            Ok(WriteResponse::Echo)
        },
    )]
    _multicast_latency_tolerance_io: (),

    // PID 96 SYNC_LATENCY_FRACTION — PDT_SCALING.
    #[io(
        pid = pid::ip::SYNC_LATENCY_FRACTION,
        pdt = PDT_Scaling,
        access = RW,
        policy = AccessPolicy::new(0x15D, 0x15D),
        rl = 3, wl = 2,
        read = |this: &Self| -> [u8; 1] { [this.state.sync_latency_fraction.get()] },
        write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
            if data.is_empty() {
                return Err(PropertyError::BufferTooSmall);
            }
            this.state.sync_latency_fraction.set(data[0]);
            Ok(WriteResponse::Echo)
        },
    )]
    _sync_latency_fraction_io: (),

    // PID 97 TUNNELING_USERS — PDT_GENERIC_02 array of
    // (user id, tunnelling address index) pairs.
    #[io(
        pid = pid::ip::TUNNELING_USERS,
        pdt = PDT_Generic02,
        access = RW,
        policy = AccessPolicy::TOOL_ONLY, // 00C/00C
        rl = 2, wl = 2,
        array(max = MAX_TU as u16),
        manual,
    )]
    _tunneling_users_io: (),
}

impl<'a, const MAX_PW: usize, const MAX_TU: usize> IpSecureAugment<'a, MAX_PW, MAX_TU> {
    pub fn new(state: &'a IpSecureExtensionState<MAX_PW, MAX_TU>) -> Self {
        Self { state }
    }
}

// ============================================================================
// Manual fallback methods invoked by the macro-generated dispatch arms.
// ============================================================================

impl<'a, const MAX_PW: usize, const MAX_TU: usize> IpSecureAugment<'a, MAX_PW, MAX_TU> {
    /// All IP Secure PIDs are statically known.
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
        Some(match req.pid {
            // PID 93 is write-only (§2.3.1.4.2); a count probe at
            // start_idx 0 is still answered so ETS can size its writes.
            pid::ip::PASSWORD_HASHES => {
                if req.start_idx == 0 {
                    if buf.len() < 2 {
                        return Some(Err(PropertyError::BufferTooSmall));
                    }
                    buf[..2].copy_from_slice(&self.state.password_hashes.borrow().count().to_be_bytes());
                    Ok(2)
                } else {
                    Err(PropertyError::AccessDenied)
                }
            }
            pid::ip::TUNNELING_USERS => read_table_with_count_probe(&self.state.tunnelling_users.borrow(), req, buf),
            // PID 94 is a function property — value-level reads are invalid.
            pid::ip::SECURED_SERVICE_FAMILIES => Err(PropertyError::InvalidPropertyId),
            _ => return None,
        })
    }

    pub fn handle_extra_pid_write<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        Some(match req.pid {
            pid::ip::PASSWORD_HASHES => {
                let mut table = self.state.password_hashes.borrow_mut();
                write_security_table(&mut table, req)
            }
            pid::ip::TUNNELING_USERS => {
                let mut table = self.state.tunnelling_users.borrow_mut();
                write_security_table(&mut table, req)
            }
            _ => return None,
        })
    }

    /// PID 94 WriteServiceID 00h (§2.3.1.5.4): set the required
    /// security version for one service family.
    pub fn handle_extra_pid_function_command<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        if req.prop_id != pid::ip::SECURED_SERVICE_FAMILIES {
            return None;
        }

        // §2.3.1.5.4.1 Figure 23 — octets 10..13, which is what `service_data`
        // spans here:
        //   [0] reserved (00h)   [1] ServiceID   [2] Service Family ID
        //   [3] Security Version
        //
        // The leading reserved octet is real on this property: ETS's
        // `Command=00000301` arrives as a 4-byte `service_data`. Note that the
        // Security object's function properties (e.g. PID 51, 03/05/01) have
        // no such octet and start at ServiceID — the layout is per-property,
        // not a shared framing rule, so the two handlers legitimately differ.
        let Some(&service_id) = req.service_data.get(1) else {
            return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[]) });
        };
        if service_id != 0x00 {
            return Some(FunctionPropertyResult { return_code: 0xF2, data: PropertyBuf::new(&[service_id]) });
        }
        let (Some(&family_id), Some(&version)) = (req.service_data.get(2), req.service_data.get(3)) else {
            return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[service_id]) });
        };

        let family = ServiceFamily::from(family_id);
        let Some(cell) = self.state.secured_version_cell(family) else {
            return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[service_id]) });
        };
        // Only versions 0 (plain allowed) and 1 (this spec) are defined.
        if version > 1 {
            return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[service_id]) });
        }
        let changed = cell.replace(version) != version;
        // Flipping the Routing family starts or stops the multicast
        // timer sync in the link layer (§2.2.2.3.2.8).
        if changed && family == ServiceFamily::Routing {
            let _ = self.state.mc_sync_events.try_send(crate::ip::IpSecureSyncEvent::RoutingConfigChanged);
        }
        Some(FunctionPropertyResult::success_with_data(&[service_id]))
    }

    /// PID 94 ReadServiceID 00h (§2.3.1.5.5): read the required
    /// security version for one service family.
    pub fn handle_extra_pid_function_state_read<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        if req.prop_id != pid::ip::SECURED_SERVICE_FAMILIES {
            return None;
        }

        // §2.3.1.5.5.1 Figure 26 — same leading reserved octet as the write:
        //   [0] reserved (00h)   [1] ServiceID   [2] Service Family ID
        let Some(&service_id) = req.service_data.get(1) else {
            return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[]) });
        };
        if service_id != 0x00 {
            return Some(FunctionPropertyResult { return_code: 0xF2, data: PropertyBuf::new(&[service_id]) });
        }
        let Some(&family_id) = req.service_data.get(2) else {
            return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[service_id]) });
        };

        let family = ServiceFamily::from(family_id);
        let Some(cell) = self.state.secured_version_cell(family) else {
            return Some(FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[service_id]) });
        };
        Some(FunctionPropertyResult::success_with_data(&[service_id, family_id, cell.get()]))
    }
}

// ============================================================================
// IpSecureInterfaceExtension — IP + tunnelling + IP Secure aggregator
// ============================================================================

use super::{IpInterfaceAugmentBundle, IpInterfaceExtension};
use crate::IpPlatform;
use crate::ip::HasIpExtensionState;
use crate::objects::comm::HasGoSecurityView;
use crate::objects::interface::HasDomainAddress;
use crate::{HasRoutingMulticastRebind, HasSecurityMode};
use zweidraehte_proto::address::IndividualAddress;

/// Extension state for KNX IP Secure tunnelling interfaces: the plain
/// [`IpInterfaceExtension`] (IP config + tunnelling slots) plus the IP
/// Secure secrets. Same composition pattern as `IpInterfaceExtension`
/// itself — *not* a `SecureExtensionState`-style wrapper, because PIDs
/// 91–97 live in the same KNXnet/IP Parameter Object as the other IP
/// PIDs. KNX Data Secure stacks on the outside:
/// `SecureExtensionState<IpSecureInterfaceExtension<...>, SEQ, ...>`.
pub struct IpSecureInterfaceExtension<const N: usize, const CAPS: u16, const MAX_PW: usize, const MAX_TU: usize> {
    /// IP config + tunnelling slots.
    pub ip: IpInterfaceExtension<N, CAPS>,
    /// IP Secure secrets and policy (PIDs 91–97).
    pub ip_secure: IpSecureExtensionState<MAX_PW, MAX_TU>,
}

impl<const N: usize, const CAPS: u16, const MAX_PW: usize, const MAX_TU: usize> ExtensionState
    for IpSecureInterfaceExtension<N, CAPS, MAX_PW, MAX_TU>
{
    type Config = (<IpInterfaceExtension<N, CAPS> as ExtensionState>::Config, IpSecureExtensionConfig<MAX_PW, MAX_TU>);
    type Resources = IpSecureResources;

    fn from_config((ip_cfg, secure_cfg): Self::Config, resources: Self::Resources) -> Self {
        Self {
            ip: IpInterfaceExtension::from_config(ip_cfg, ()),
            ip_secure: IpSecureExtensionState::from_config(secure_cfg, resources),
        }
    }

    fn to_config(&self) -> Self::Config {
        (self.ip.to_config(), self.ip_secure.to_config())
    }

    fn on_erase(&self, code: EraseCode) {
        self.ip.on_erase(code);
        self.ip_secure.on_erase(code);
    }
}

// Forwarding: the aggregator presents the same trait surface as
// `IpInterfaceExtension`, plus the IP Secure view.

forward_to_field! {
    impl<[const N: usize, const CAPS: u16, const MAX_PW: usize, const MAX_TU: usize]> HasGoSecurityView
        for IpSecureInterfaceExtension<N, CAPS, MAX_PW, MAX_TU>
    {
        get fn required_security_for_asap(&self, asap: u16) -> zweidraehte_proto::messages::knx::RequiredSecurity;
        get fn required_security_for_p2p(&self, peer_ia: u16) -> zweidraehte_proto::messages::knx::RequiredSecurity;
        get fn required_security_for_broadcast(&self) -> zweidraehte_proto::messages::knx::RequiredSecurity;
        get fn required_security_for_tool_access(&self) -> zweidraehte_proto::messages::knx::RequiredSecurity;
    } => self.ip
}

forward_to_field! {
    impl<[const N: usize, const CAPS: u16, const MAX_PW: usize, const MAX_TU: usize]> HasSecurityMode
        for IpSecureInterfaceExtension<N, CAPS, MAX_PW, MAX_TU>
    {
        get fn security_mode_enabled(&self) -> bool;
        out fn log_access_denied(&self, source_addr: u16);
        get fn has_group_key(&self, tsap: u16) -> bool;
    } => self.ip
}

forward_to_field! {
    impl<[
        const N: usize, const CAPS: u16, const MAX_PW: usize, const MAX_TU: usize,
    ]> HasRoutingMulticastRebind for IpSecureInterfaceExtension<N, CAPS, MAX_PW, MAX_TU> {
        ref fn routing_multicast_rebind_channel(&self) -> &super::RoutingMulticastRebindChannel;
    } => self.ip
}

impl<const N: usize, const CAPS: u16, const MAX_PW: usize, const MAX_TU: usize> HasIpExtensionState
    for IpSecureInterfaceExtension<N, CAPS, MAX_PW, MAX_TU>
{
    fn ip_state(&self) -> &dyn crate::ip::IpStateView {
        self.ip.ip_state()
    }
}

impl<const N: usize, const CAPS: u16, const MAX_PW: usize, const MAX_TU: usize> crate::ip::HasAdditionalIas
    for IpSecureInterfaceExtension<N, CAPS, MAX_PW, MAX_TU>
{
    fn write_additional_ias_into(&self, buf: &mut [IndividualAddress]) -> usize {
        crate::ip::HasAdditionalIas::write_additional_ias_into(&self.ip, buf)
    }

    fn additional_ia_is_assigned(&self, addr: IndividualAddress) -> bool {
        crate::ip::HasAdditionalIas::additional_ia_is_assigned(&self.ip, addr)
    }
}

impl<const N: usize, const CAPS: u16, const MAX_PW: usize, const MAX_TU: usize> HasIpSecureView
    for IpSecureInterfaceExtension<N, CAPS, MAX_PW, MAX_TU>
{
    fn ip_secure_view(&self) -> Option<&dyn IpSecureStateView> {
        Some(&self.ip_secure)
    }
}

forward_to_field! {
    impl<[
        const N: usize, const CAPS: u16, const MAX_PW: usize, const MAX_TU: usize,
    ]> HasDomainAddress for IpSecureInterfaceExtension<N, CAPS, MAX_PW, MAX_TU> {
        const DOMAIN_ADDRESS_LENGTH: usize = IpInterfaceExtension::<N, CAPS>::DOMAIN_ADDRESS_LENGTH;
        out fn domain_address(&self, buf: &mut [u8]);
        set fn set_domain_address(&self, addr: &[u8]);
    } => self.ip
}

/// `Augment<D>` bundle: the plain IP-interface bundle (tunnelling + IP
/// PIDs) chained with [`IpSecureAugment`] (PIDs 91–97). All three peers
/// target Object Type 11 with disjoint PIDs.
#[derive(crate::service::ServiceRegistry)]
pub struct IpSecureInterfaceAugmentBundle<
    'a,
    P: IpPlatform,
    const N: usize,
    const CAPS: u16,
    const MAX_PW: usize,
    const MAX_TU: usize,
> {
    #[service(flatten)]
    pub ip: IpInterfaceAugmentBundle<'a, P, N, CAPS>,
    #[service(augment)]
    pub ip_secure: IpSecureAugment<'a, MAX_PW, MAX_TU>,
}

impl<P: IpPlatform, const N: usize, const CAPS: u16, const MAX_PW: usize, const MAX_TU: usize> Extension<P>
    for IpSecureInterfaceExtension<N, CAPS, MAX_PW, MAX_TU>
{
    type Augment<'a, D: StackDefinition>
        = IpSecureInterfaceAugmentBundle<'a, P, N, CAPS, MAX_PW, MAX_TU>
    where
        Self: 'a,
        P: 'a;

    fn create_augment<'a, D: StackDefinition>(&'a self, platform: &'a P) -> Self::Augment<'a, D>
    where
        P: 'a,
    {
        IpSecureInterfaceAugmentBundle {
            ip: self.ip.create_augment::<D>(platform),
            ip_secure: IpSecureAugment::new(&self.ip_secure),
        }
    }
}

// ============================================================================
// FeatureSet-derived aliases
// ============================================================================

use crate::bcus::system_b::SystemBDeviceState;
use crate::layers::linklayers::knxip::features::{FeatureSet, TunnelingFeature};

/// [`IpSecureInterfaceExtension`] with `N` and `CAPS` derived from a
/// [`FeatureSet`] — mirror of
/// [`IpInterfaceExtensionFor`](super::IpInterfaceExtensionFor).
///
/// ```rust,ignore
/// type ES = IpSecureInterfaceExtensionFor<KnxIpSecureInterfaceTcp<4>, 2, 8>;
/// ```
pub type IpSecureInterfaceExtensionFor<F: FeatureSet, const MAX_PW: usize, const MAX_TU: usize> =
    IpSecureInterfaceExtension<
        { <<F as FeatureSet>::Tunneling as TunnelingFeature>::CAPACITY },
        { <F as FeatureSet>::KNXNETIP_DEVICE_CAPABILITIES },
        MAX_PW,
        MAX_TU,
    >;

/// Like [`IpInterfaceDeviceState`](super::IpInterfaceDeviceState), but
/// with the IP Secure extension state.
pub type IpSecureInterfaceDeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D: StackDefinition,
    F: FeatureSet,
    const MAX_PW: usize,
    const MAX_TU: usize,
> = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, IpSecureInterfaceExtensionFor<F, MAX_PW, MAX_TU>>;
