//! The BCU-era management surface: memory services over the flat
//! image, the family-defined property server, the property-path load
//! state machines, authorization, device descriptor, and restart.
//!
//! Everything here answers exactly the request sequence a management
//! client sends during a download — the shape is pinned by the MV-0020
//! `Load/all` procedure (the client's mask fixture) and the hardware
//! trace in `BCU2_PLAN.md`: connect, read the 0115h compatibility probe,
//! read DD0, drive the three load state machines through
//! `PID_LOAD_STATE_CONTROL`, then verify-mode memory writes over
//! 0100h–046Fh, RunError clear, restart.

use heapless::Vec;
use zweidraehte_proto::access::{AccessContext, SecurityMode};
use zweidraehte_proto::memory::{MemoryOperation, memory_access_allowed};
use zweidraehte_proto::messages::apdu::load_control::{
    AbsSegment, LoadAction, LoadSegment, LoadState, load_control_transition,
};
use zweidraehte_proto::messages::apdu::memory::{MemoryBitWrite, UserMemoryAccess};
use zweidraehte_proto::messages::apdu::property::{
    PropertyDescriptionRead, PropertyDescriptionResponse as PropertyDescriptionApduResponse, PropertyValueHeader,
};
use zweidraehte_proto::messages::apdu::restart::EraseCode;
use zweidraehte_proto::messages::knx::offsets;
use zweidraehte_proto::pid;
use zweidraehte_proto::properties::PropertyDescriptionResponse as PropertyDescription;

use crate::device::{MAX_AUTH_LEVELS, MAX_LSM, Microdevice, RAM_SIZE, SYSTEM_STATUS_ADDR};
use crate::family::{MicroDeviceFamily, PropertyBacking, PropertySpec};
use crate::frame::{ApciCode, MAX_FRAME, is_extended};
use crate::security::ScheduledRestart;
use crate::security::SecurityModule;

/// How many data octets one `A_Memory_Read` response can carry at a given
/// APDU ceiling: the APDU less its APCI octet and the two address octets.
///
/// Also clamped to the 6-bit count field the short-form service encodes it
/// in, which an extended-frame profile would otherwise overrun.
const fn max_memory_data_length(max_apdu: u16) -> u8 {
    let by_apdu = (max_apdu as usize).saturating_sub(3);
    if by_apdu > 0x3F { 0x3F } else { by_apdu as u8 }
}

/// User-memory services carry a packed extension/count octet ahead of the
/// 16-bit address, reducing a standard-frame response by one data octet.
const fn max_user_memory_data_length(max_apdu: u16) -> u8 {
    let by_apdu = (max_apdu as usize).saturating_sub(4);
    if by_apdu > 0x0F { 0x0F } else { by_apdu as u8 }
}

/// One reply APDU. `small6` rides in the APCI low octet for the short
/// services; the payload follows.
pub struct Reply<const N: usize = MAX_FRAME> {
    pub apci: ApciCode,
    pub small6: u8,
    /// Sized by the profile's frame capacity rather than its APDU ceiling:
    /// a reply payload is always a strict subset of the frame that carries
    /// it, and one width means one const to thread through the stack.
    pub payload: Vec<u8, N>,
    /// A short response which the service specification requires in EFF.
    pub force_extended: bool,
}

impl<const N: usize> Reply<N> {
    pub(crate) fn new(apci: ApciCode, small6: u8, payload: &[u8]) -> Self {
        let mut p = Vec::new();
        // Payloads are built in this module and never exceed the
        // Standard TP1 APDU (1 APCI octet + the remaining payload).
        p.extend_from_slice(payload).expect("management reply fits the TP1 APDU");
        Self { apci, small6, payload: p, force_extended: false }
    }

    fn in_extended_frame(mut self) -> Self {
        // A standard-only profile cannot honour this hint. Keeping it
        // compile-time false also lets LLVM erase both send-path branches
        // from the plain micro image.
        self.force_extended = is_extended(N);
        self
    }
}

pub enum ServiceResult<const N: usize = MAX_FRAME> {
    None,
    Reply(Reply<N>),
    /// Basic restart (erase code 0): the embedder restarts after flushing.
    Restart,
}

/// One load state machine: the state plus the segment address the last
/// `AllocAbsDataSeg` record announced (read back through
/// `PID_TABLE_REFERENCE`).
#[derive(Debug, Clone, Copy)]
pub struct Lsm {
    pub state: LoadState,
    pub table_ref: u16,
}

impl Lsm {
    const fn new() -> Self {
        Self { state: LoadState::Unloaded, table_ref: 0 }
    }
}

/// Management state that lives outside the EEPROM image — the pieces
/// real mask firmware keeps in system RAM / hidden EEPROM.
pub struct ManagementState {
    /// PID_DEVICE_CONTROL on the device object. Bit 2 is verify mode:
    /// while set, every A_Memory_Write is answered with an
    /// A_Memory_Response reading the bytes back.
    pub device_control: u8,
    /// Authorization level of the active connection (0 = most
    /// privileged). Reset to the default key's level when the connection
    /// closes.
    pub auth_level: u8,
    pub auth_keys: [[u8; 4]; MAX_AUTH_LEVELS],
    pub lsm: [Lsm; MAX_LSM],
    /// Per-machine "explicitly stopped" run-state flag (System 7's
    /// RUNCONTROL_STOP → Terminated). Volatile on purpose: a re-powered
    /// device starts a loaded application running again.
    pub run_stopped: [bool; MAX_LSM],
    /// The option register, for families that keep it outside the
    /// EEPROM image (System 7's cell at 0100h). Persistent.
    pub option_reg: u8,
}

impl ManagementState {
    const DEFAULT_KEY: [u8; 4] = [0xFF; 4];

    pub fn new() -> Self {
        Self {
            device_control: 0,
            // Placeholder until `Microdevice::new` resolves the default
            // key against the concrete family's authorization model; 15 is
            // the ceiling and safe for every family.
            auth_level: (MAX_AUTH_LEVELS - 1) as u8,
            // Factory state: every level keyed FFFFFFFFh, which is why
            // an A_Authorize with the FF key is granted level 0.
            auth_keys: [[0xFF; 4]; MAX_AUTH_LEVELS],
            lsm: [Lsm::new(); MAX_LSM],
            run_stopped: [false; MAX_LSM],
            option_reg: 0,
        }
    }

    const fn free_access_level<F: MicroDeviceFamily>() -> u8 {
        // BCU1 has no authorization model. Zero is harmless there and
        // avoids underflow; no BCU1 service consults this field.
        F::AUTH_LEVELS.saturating_sub(1) as u8
    }

    fn access_level_for_key<F: MicroDeviceFamily>(&self, key: &[u8; 4]) -> u8 {
        let free_level = Self::free_access_level::<F>();
        (0..free_level).find(|&level| self.auth_keys[usize::from(level)] == *key).unwrap_or(free_level)
    }

    pub(crate) fn default_access_level<F: MicroDeviceFamily>(&self) -> u8 {
        self.access_level_for_key::<F>(&Self::DEFAULT_KEY)
    }

    pub fn reset_connection_auth<F: MicroDeviceFamily>(&mut self) {
        self.auth_level = self.default_access_level::<F>();
        // Verify Mode is scoped to one transport connection. Resources
        // §4.2.14.7 requires it to clear immediately when that connection
        // closes; boot and factory reset use this same disconnected state.
        self.device_control &= !pid::device_control::VERIFY_MODE;
    }

    pub fn verify_mode(&self) -> bool {
        self.device_control & pid::device_control::VERIFY_MODE != 0
    }
}

impl Default for ManagementState {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: MicroDeviceFamily, const FRAME_CAP: usize, SEC: SecurityModule> Microdevice<F, FRAME_CAP, SEC> {
    /// Dispatch one connection-oriented management APDU.
    /// `frame` is the whole canonical frame. The classic services need only
    /// `payload`, but the extended ones are parsed by
    /// `zweidraehte_proto::messages::apdu::property_ext`, whose offsets are
    /// frame-relative — reproducing them against `payload` would be a second
    /// copy of a wire layout this crate deliberately does not own.
    // The dispatch needs each fact independently; wrapping them would add a
    // second request abstraction beside the S-AL context for no useful gain.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_service(
        &mut self,
        code: ApciCode,
        small6: u8,
        payload: &[u8],
        frame: &[u8],
        access: AccessContext,
        connection_oriented: bool,
        reply_context: &mut SEC::ReplyContext,
    ) -> ServiceResult<FRAME_CAP> {
        // A_Authorize/A_Key_Write and the property services are BCU2
        // additions; a family predating them (BCU1) ignores the APCIs
        // the way the mask firmware ignores anything it does not
        // decode — the TL ACK still goes out, no reply follows.
        let has_auth = F::AUTH_LEVELS > 0;
        let has_properties = F::OBJECT_COUNT > 0 || SEC::OBJECT_COUNT > 0;
        // The extended services come with the extended APDU, not separately.
        // 06 Profiles §9.1.2.3 makes both obligations of the same module, and
        // the wire agrees: `A_PropertyExtDescription_Response` is a fixed 23
        // canonical octets — a 16-octet APDU — so a standard-frame profile
        // could implement six of the seven mandatory services and not the
        // seventh. Deriving the choice from the frame capacity keeps a plain
        // BCU1/BCU2 image free of code it could not use anyway; measured at
        // ~1.7 KiB of .text on the G0 light switch.
        let has_ext_services = has_properties && Self::supports_extended_frames();
        match code {
            ApciCode::DeviceDescriptorRead => self.device_descriptor_read(small6, frame, access),
            ApciCode::MemoryRead if connection_oriented => self.memory_read(small6, payload, frame, access),
            ApciCode::MemoryWrite if connection_oriented => self.memory_write(small6, payload, frame, access),
            ApciCode::MemoryBitWrite if connection_oriented => self.memory_bit_write(frame, access),
            // 06 Profiles §4.2.2 requires DMA on user memory for every
            // BCU-era family. These services use the same physical address
            // space and access policy as A_Memory_*, but add a 4-bit logical
            // address extension on the wire.
            ApciCode::UserMemoryRead if connection_oriented => self.user_memory_read(frame, access),
            ApciCode::UserMemoryWrite if connection_oriented => self.user_memory_write(frame, access),
            // Authorization belongs to a transport connection. In
            // particular, a connectionless System 7 request must not
            // acquire or reuse another client's connection level.
            ApciCode::AuthorizeRequest if has_auth && connection_oriented => self.authorize(payload),
            ApciCode::KeyWrite if has_auth && connection_oriented => self.key_write(payload, frame, access),
            ApciCode::PropertyValueRead if has_properties => self.property_value_read(payload, frame, access),
            ApciCode::PropertyValueWrite if has_properties => self.property_value_write(payload, frame, access),
            ApciCode::PropertyDescriptionRead if has_properties => {
                self.property_description_read(payload, frame, access)
            }
            ApciCode::FunctionPropertyCommand if SEC::ENABLED => self.function_property(frame, true, access),
            ApciCode::FunctionPropertyStateRead if SEC::ENABLED => self.function_property(frame, false, access),
            // Extended property services (06 Profiles §9.1.2.3.2, all `M`
            // for the Data Secure profile module). They address an object by
            // type and one-based occurrence rather than by index.
            ApciCode::PropertyExtValueRead if has_ext_services => self.property_ext_value_read(frame, access),
            ApciCode::PropertyExtValueWriteCon if has_ext_services => {
                self.property_ext_value_write(frame, access, true)
            }
            ApciCode::PropertyExtValueWriteUnCon if has_ext_services => {
                self.property_ext_value_write(frame, access, false)
            }
            ApciCode::PropertyExtDescriptionRead if has_ext_services => {
                self.property_ext_description_read(frame, access)
            }
            // Extended memory services (§9.1.2.3.3, `M`). These are what an
            // ETS download to a secure device actually uses — the bench
            // MV-0021 trace carries 361 of the write and no classic memory
            // write at all.
            ApciCode::MemoryExtendedRead if has_ext_services => self.memory_ext_read(frame, access),
            ApciCode::MemoryExtendedWrite if has_ext_services => self.memory_ext_write(frame, access),
            // Extended function properties (§9.1.2.3.2 items 6-7, `M`).
            ApciCode::FunctionPropertyExtCommand if has_ext_services => self.function_property_ext(frame, true, access),
            ApciCode::FunctionPropertyExtStateRead if has_ext_services => {
                self.function_property_ext(frame, false, access)
            }
            ApciCode::Restart => self.handle_restart(small6, payload, frame, access, reply_context),
            _ => F::extra_service(code, small6, payload).unwrap_or(ServiceResult::None),
        }
    }

    /// Record an AIL permission failure.
    ///
    /// Error Type 04h explicitly includes attempts to access protected data
    /// with plain telegrams (03/05/01 §6.3.9.3.2). `NoSecurity` compiles
    /// this call to a no-op, so plain devices carry no log or branch.
    pub(crate) fn record_access_failure(&self, access: AccessContext, frame: &[u8]) {
        SEC::log_access_failure(&self.sec, access.source_addr, frame);
    }

    // ── Memory services ─────────────────────────────────────────────

    /// Map a KNX address to one byte of device memory.
    ///
    /// Reads of unmapped addresses yield 00h and writes to them are
    /// dropped — a management client probing outside the windows gets
    /// the same experience real silicon gives it (whatever the data
    /// bus floats to), just deterministic.
    pub(crate) fn mem_read_byte(&self, addr: u16) -> u8 {
        if let Some(value) = F::special_byte_read(addr, self.eeprom.as_ref(), &self.mgmt) {
            return value;
        }
        let a = usize::from(addr);
        if a < RAM_SIZE {
            self.ram[a]
        } else if let Some(off) = self.eeprom_offset(addr) {
            self.eeprom.as_ref()[off]
        } else if let Some(off) = ram2_offset::<F>(addr) {
            self.ram2[off]
        } else {
            0
        }
    }

    pub(crate) fn mem_write_byte(&mut self, addr: u16, value: u8) {
        if F::special_byte_write(addr, value, self.eeprom.as_mut(), &mut self.mgmt) {
            return;
        }
        let a = usize::from(addr);
        if a < RAM_SIZE {
            // The system status byte guards itself with even parity
            // over the whole octet (bit 7 is the parity bit); the mask
            // firmware drops writes that fail the check, so a corrupted
            // telegram cannot flip programming mode.
            if usize::from(addr) == SYSTEM_STATUS_ADDR && !value.count_ones().is_multiple_of(2) {
                return;
            }
            self.ram[a] = value;
        } else if let Some(off) = self.eeprom_offset(addr) {
            self.eeprom.as_mut()[off] = value;
        } else if let Some(off) = ram2_offset::<F>(addr) {
            self.ram2[off] = value;
        }
    }

    fn eeprom_offset(&self, addr: u16) -> Option<usize> {
        let off = usize::from(addr.checked_sub(F::EEPROM_BASE)?);
        (off < F::EEPROM_SIZE).then_some(off)
    }

    fn memory_response(address: &[u8], count: u8, bytes: &[u8]) -> ServiceResult<FRAME_CAP> {
        let mut data: Vec<u8, FRAME_CAP> = Vec::new();
        let _ = data.extend_from_slice(address);
        let _ = data.extend_from_slice(bytes);
        ServiceResult::Reply(Reply::new(ApciCode::MemoryReadResponse, count, &data))
    }

    fn extended_memory_error(address: &[u8]) -> ServiceResult<FRAME_CAP> {
        let mut data: Vec<u8, FRAME_CAP> = Vec::new();
        let _ = data.extend_from_slice(address);
        ServiceResult::Reply(Reply::new(ApciCode::MemoryReadResponse, 0, &data).in_extended_frame())
    }

    fn memory_read(
        &mut self,
        count: u8,
        payload: &[u8],
        frame: &[u8],
        access: AccessContext,
    ) -> ServiceResult<FRAME_CAP> {
        if payload.len() != 2 {
            return ServiceResult::None;
        }
        let addr = u16::from_be_bytes([payload[0], payload[1]]);
        // The profile's APDU caps the response — 12 data bytes at the
        // standard 15-octet ceiling. KNX error handling rejects an oversized
        // request with count zero; silently truncating would claim success
        // for a different operation.
        let operation = MemoryOperation::Read;
        if !SEC::memory_access_allowed(&self.sec, access, F::memory_access_policy(addr, usize::from(count)), operation)
        {
            self.record_access_failure(access, frame);
            return Self::memory_response(payload, 0, &[]);
        }
        let exceeds_apdu =
            count > max_memory_data_length(Self::max_plaintext_apdu_length(access.security != SecurityMode::Plain));
        if is_extended(FRAME_CAP) && exceeds_apdu {
            return Self::extended_memory_error(payload);
        }
        if exceeds_apdu
            || !memory_access_allowed(
                F::MEMORY_REGIONS,
                addr,
                usize::from(count),
                operation,
                access.access_level,
                F::AUTH_LEVELS as u8,
            )
        {
            return Self::memory_response(payload, 0, &[]);
        }
        let mut data: Vec<u8, FRAME_CAP> = Vec::new();
        for i in 0..count {
            let _ = data.push(self.mem_read_byte(addr.wrapping_add(u16::from(i))));
        }
        Self::memory_response(payload, count, &data)
    }

    fn memory_write(
        &mut self,
        count: u8,
        payload: &[u8],
        frame: &[u8],
        access: AccessContext,
    ) -> ServiceResult<FRAME_CAP> {
        if payload.len() < 2 {
            return ServiceResult::None;
        }
        let addr = u16::from_be_bytes([payload[0], payload[1]]);
        let data = &payload[2..];
        if data.len() != usize::from(count) {
            // 03/03/07 §3.5.3 uses the count-zero response as the write
            // error indication when Verify Mode is active. Without Verify
            // Mode, a malformed write remains silent like every other
            // rejected A_Memory_Write.
            return if self.mgmt.verify_mode() {
                Self::memory_response(&payload[..2], 0, &[])
            } else {
                ServiceResult::None
            };
        }
        let operation = MemoryOperation::Write;
        if !SEC::memory_access_allowed(&self.sec, access, F::memory_access_policy(addr, data.len()), operation) {
            self.record_access_failure(access, frame);
            return if self.mgmt.verify_mode() {
                Self::memory_response(&payload[..2], 0, &[])
            } else {
                ServiceResult::None
            };
        }
        if !memory_access_allowed(
            F::MEMORY_REGIONS,
            addr,
            data.len(),
            operation,
            access.access_level,
            F::AUTH_LEVELS as u8,
        ) {
            return if self.mgmt.verify_mode() {
                Self::memory_response(&payload[..2], 0, &[])
            } else {
                ServiceResult::None
            };
        }
        if !F::memory_write_intercept(addr, data, self.eeprom.as_mut(), &mut self.mgmt) {
            for (i, &byte) in data.iter().enumerate() {
                self.mem_write_byte(addr.wrapping_add(i as u16), byte);
            }
        }
        // A successful verify response echoes the accepted write, matching
        // the full stack and allowing a write-only region to confirm success.
        if self.mgmt.verify_mode() {
            return Self::memory_response(&payload[..2], count, data);
        }
        ServiceResult::None
    }

    // ── Bit-oriented memory access ──────────────────────────────────

    /// Apply the bit masks as one memory operation.
    ///
    /// A partial write would be worse than rejecting the request: the service
    /// promises that a range crossing an access boundary remains unchanged.
    /// We therefore validate both the read and write sides, calculate all new
    /// octets in RAM, and only then touch the backing image.
    fn memory_bit_write(&mut self, frame: &[u8], access: AccessContext) -> ServiceResult<FRAME_CAP> {
        // Count and address precede the masks, so they remain available for
        // the specified Verify-Mode error response even when the mask data is
        // truncated or the count is outside the legal 1..=5 range.
        const HEADER_LEN: usize = offsets::MSG_APCI + 5;
        if frame.len() < HEADER_LEN {
            return ServiceResult::None;
        }
        let count = frame[offsets::MSG_APCI + 2] & 0x0F;
        let address = u16::from_be_bytes([frame[offsets::MSG_APCI + 3], frame[offsets::MSG_APCI + 4]]);
        let address_bytes = address.to_be_bytes();
        let error = |this: &Self| {
            if this.mgmt.verify_mode() { Self::memory_response(&address_bytes, 0, &[]) } else { ServiceResult::None }
        };

        if !(1..=5).contains(&count) || frame.len() != MemoryBitWrite::expected_msg_len(usize::from(count)) {
            return error(self);
        }
        let request = MemoryBitWrite::parse(frame).expect("memory-bit length validated");
        let count = usize::from(request.count);

        // A_MemoryBit_Write necessarily reads before it writes. Keep the
        // two legacy permissions explicit so a future asymmetric memory map
        // cannot accidentally turn a write-only region into readable state.
        let legacy_read_allowed = memory_access_allowed(
            F::MEMORY_REGIONS,
            request.address,
            count,
            MemoryOperation::Read,
            access.access_level,
            F::AUTH_LEVELS as u8,
        );
        let legacy_write_allowed = memory_access_allowed(
            F::MEMORY_REGIONS,
            request.address,
            count,
            MemoryOperation::Write,
            access.access_level,
            F::AUTH_LEVELS as u8,
        );
        let secure_allowed = SEC::memory_access_allowed(
            &self.sec,
            access,
            F::memory_access_policy(request.address, count),
            MemoryOperation::Write,
        );
        if !secure_allowed {
            self.record_access_failure(access, frame);
        }
        if !legacy_read_allowed || !legacy_write_allowed || !secure_allowed {
            return error(self);
        }

        let mut new_data = [0u8; 5];
        for (i, result) in new_data[..count].iter_mut().enumerate() {
            let old = self.mem_read_byte(request.address.wrapping_add(i as u16));
            *result = (old & request.and_masks[i]) ^ request.xor_masks[i];
        }

        if !F::memory_write_intercept(request.address, &new_data[..count], self.eeprom.as_mut(), &mut self.mgmt) {
            for (i, &byte) in new_data[..count].iter().enumerate() {
                self.mem_write_byte(request.address.wrapping_add(i as u16), byte);
            }
        }

        if !self.mgmt.verify_mode() {
            return ServiceResult::None;
        }

        // Verify reports what the storage actually accepted. This matters
        // for special registers such as the parity-protected system status
        // byte, where a syntactically valid write may deliberately be lost.
        let mut readback = [0u8; 5];
        for (i, byte) in readback[..count].iter_mut().enumerate() {
            *byte = self.mem_read_byte(request.address.wrapping_add(i as u16));
        }
        Self::memory_response(&address_bytes, request.count, &readback[..count])
    }

    // ── Extended-address user memory access ─────────────────────────

    fn user_memory_response(addr_ext: u8, address: u16, count: u8, bytes: &[u8]) -> ServiceResult<FRAME_CAP> {
        let mut data: Vec<u8, FRAME_CAP> = Vec::new();
        let _ = data.push(((addr_ext & 0x0F) << 4) | (count & 0x0F));
        let _ = data.extend_from_slice(&address.to_be_bytes());
        let _ = data.extend_from_slice(bytes);
        ServiceResult::Reply(Reply::new(ApciCode::UserMemoryResponse, 0, &data))
    }

    fn user_memory_write_error(&self, addr_ext: u8, address: u16) -> ServiceResult<FRAME_CAP> {
        if self.mgmt.verify_mode() {
            Self::user_memory_response(addr_ext, address, 0, &[])
        } else {
            ServiceResult::None
        }
    }

    fn user_memory_read(&mut self, frame: &[u8], access: AccessContext) -> ServiceResult<FRAME_CAP> {
        let Some(request) = UserMemoryAccess::parse_read(frame) else {
            return ServiceResult::None;
        };
        // A read has no trailing data. Treat a malformed request like an
        // unsupported APDU rather than accepting hidden trailing octets.
        if frame.len() != UserMemoryAccess::MIN_MSG_LEN {
            return ServiceResult::None;
        }

        let operation = MemoryOperation::Read;
        let count = usize::from(request.count);
        if !SEC::memory_access_allowed(
            &self.sec,
            access,
            F::memory_access_policy(request.address_low, count),
            operation,
        ) {
            self.record_access_failure(access, frame);
            return Self::user_memory_response(request.addr_ext, request.address_low, 0, &[]);
        }

        // BCU1/BCU2/System 7 expose no memory above 64 KiB. The service is
        // still mandatory as the Application Device Management memory
        // service; a non-zero extension therefore receives the specified
        // count-zero error response rather than aliasing low memory.
        if request.addr_ext != 0
            || request.count == 0
            || request.count
                > max_user_memory_data_length(Self::max_plaintext_apdu_length(access.security != SecurityMode::Plain))
            || !memory_access_allowed(
                F::MEMORY_REGIONS,
                request.address_low,
                count,
                operation,
                access.access_level,
                F::AUTH_LEVELS as u8,
            )
        {
            return Self::user_memory_response(request.addr_ext, request.address_low, 0, &[]);
        }

        let mut data: Vec<u8, FRAME_CAP> = Vec::new();
        for i in 0..request.count {
            let _ = data.push(self.mem_read_byte(request.address_low.wrapping_add(u16::from(i))));
        }
        Self::user_memory_response(request.addr_ext, request.address_low, request.count, &data)
    }

    fn user_memory_write(&mut self, frame: &[u8], access: AccessContext) -> ServiceResult<FRAME_CAP> {
        let Some(request) = UserMemoryAccess::parse_write(frame) else {
            return ServiceResult::None;
        };
        if !request.is_length_consistent(frame.len()) || request.count == 0 {
            return self.user_memory_write_error(request.addr_ext, request.address_low);
        }

        let operation = MemoryOperation::Write;
        if !SEC::memory_access_allowed(
            &self.sec,
            access,
            F::memory_access_policy(request.address_low, request.data.len()),
            operation,
        ) {
            self.record_access_failure(access, frame);
            return self.user_memory_write_error(request.addr_ext, request.address_low);
        }
        if request.addr_ext != 0
            || !memory_access_allowed(
                F::MEMORY_REGIONS,
                request.address_low,
                request.data.len(),
                operation,
                access.access_level,
                F::AUTH_LEVELS as u8,
            )
        {
            return self.user_memory_write_error(request.addr_ext, request.address_low);
        }

        if !F::memory_write_intercept(request.address_low, request.data, self.eeprom.as_mut(), &mut self.mgmt) {
            for (i, &byte) in request.data.iter().enumerate() {
                self.mem_write_byte(request.address_low.wrapping_add(i as u16), byte);
            }
        }
        if self.mgmt.verify_mode() {
            Self::user_memory_response(request.addr_ext, request.address_low, request.count, request.data)
        } else {
            ServiceResult::None
        }
    }

    // ── Device descriptor ───────────────────────────────────────────

    /// 03/03/07 §3.4.2: an unsupported descriptor type is answered
    /// with type 3Fh and no data.
    const DD_TYPE_UNSUPPORTED: u8 = 0x3F;

    fn device_descriptor_read(
        &self,
        descriptor_type: u8,
        frame: &[u8],
        access: AccessContext,
    ) -> ServiceResult<FRAME_CAP> {
        let allowed = zweidraehte_proto::access::AccessPolicy::READ_OPEN_WRITE_TOOL
            .can_read(&access, SEC::security_mode_enabled(&self.sec));
        if !allowed {
            self.record_access_failure(access, frame);
        }
        if descriptor_type == 0 {
            // Security Mode deliberately hides the mask from an unsecured
            // probe. ETS treats FFFFh as the signal to install the Tool Key,
            // synchronize and repeat DD0 securely. Returning the real mask
            // here makes it continue down the plaintext download path.
            let dd0 = if allowed { F::DD0 } else { 0xFFFF };
            return ServiceResult::Reply(Reply::new(ApciCode::DeviceDescriptorResponse, 0, &dd0.to_be_bytes()));
        }
        if !allowed {
            return ServiceResult::Reply(Reply::new(ApciCode::DeviceDescriptorResponse, Self::DD_TYPE_UNSUPPORTED, &[]));
        }
        if descriptor_type == 2
            && let Some(dd2) = F::device_descriptor2(self.eeprom.as_ref(), &self.identity, &self.mgmt)
        {
            return ServiceResult::Reply(Reply::new(ApciCode::DeviceDescriptorResponse, 2, &dd2));
        }
        ServiceResult::Reply(Reply::new(ApciCode::DeviceDescriptorResponse, Self::DD_TYPE_UNSUPPORTED, &[]))
    }

    // ── Authorization ───────────────────────────────────────────────

    fn authorize(&mut self, payload: &[u8]) -> ServiceResult<FRAME_CAP> {
        if payload.len() != 5 {
            return ServiceResult::None;
        }
        let key: [u8; 4] = payload[1..5].try_into().expect("length checked above");
        let granted = self.mgmt.access_level_for_key::<F>(&key);
        self.mgmt.auth_level = granted;
        ServiceResult::Reply(Reply::new(ApciCode::AuthorizeResponse, 0, &[granted]))
    }

    fn key_write(&mut self, payload: &[u8], frame: &[u8], access: AccessContext) -> ServiceResult<FRAME_CAP> {
        if payload.len() != 5 {
            return ServiceResult::None;
        }
        if !zweidraehte_proto::access::AccessPolicy::READ_OPEN_WRITE_TOOL
            .can_write(&access, SEC::security_mode_enabled(&self.sec))
        {
            self.record_access_failure(access, frame);
            // Access Policies at service level reject silently; the TL ACK
            // has already been emitted (03/04/01 §6.2.2.1.4, TSSJ 3.7.2.10).
            return ServiceResult::None;
        }
        let level = payload[0];
        if !F::key_write_level_valid(level) || !access.has_level(level) {
            // Not privileged enough to set this level's key: answer
            // with FFh, the "not modified" convention.
            return ServiceResult::Reply(Reply::new(ApciCode::KeyResponse, 0, &[0xFF]));
        }
        self.mgmt.auth_keys[usize::from(level)] = payload[1..5].try_into().expect("length checked above");
        ServiceResult::Reply(Reply::new(ApciCode::KeyResponse, 0, &[level]))
    }

    // ── Restart services ────────────────────────────────────────────

    fn handle_restart(
        &mut self,
        small6: u8,
        _payload: &[u8],
        frame: &[u8],
        access: AccessContext,
        reply_context: &mut SEC::ReplyContext,
    ) -> ServiceResult<FRAME_CAP> {
        use zweidraehte_proto::messages::apdu::restart::RestartError;
        use zweidraehte_proto::messages::knx::offsets;

        // The plain profiles implement only the original basic restart. Keep
        // the complete access-policy and erase-code matrix out of those
        // images rather than asking the optimizer to rediscover that every
        // secure policy input is absent.
        if !SEC::ENABLED {
            return if small6 & 0x01 == 0 { ServiceResult::Restart } else { ServiceResult::None };
        }

        // Secure basic restart: no erase and no response, but it still has a
        // Data Secure access policy.
        if small6 & 0x01 == 0 {
            let allowed = zweidraehte_proto::security::restart_access_policy(0)
                .can_write(&access, SEC::security_mode_enabled(&self.sec));
            if !allowed {
                self.record_access_failure(access, frame);
                return ServiceResult::None;
            }
            return ServiceResult::Restart;
        }

        // Master reset: parse the erase code from the frame.
        if frame.len() < offsets::MSG_APCI + 4 {
            return ServiceResult::None;
        }
        let erase_code = frame[offsets::MSG_APCI + 2];
        let code = EraseCode::from(erase_code);

        // Unknown codes and ResetIA/ResetAP are unsupported by the Data
        // Secure profile itself (06 Profiles §9.1.2.5.1), so report that
        // before consulting an access policy which does not exist for the
        // request. TSSJ 3.7.2.9 deliberately sends FEh in plain while
        // Security Mode is on and requires UnsupportedEraseCode, matching the
        // full stack's ordering.
        if matches!(code, EraseCode::Other(_) | EraseCode::ResetIA | EraseCode::ResetAP) {
            let reply = Reply::new(ApciCode::Restart, 0x21, &[RestartError::UnsupportedEraseCode.into(), 0x00, 0x00]);
            return ServiceResult::Reply(reply);
        }

        if frame[offsets::MSG_APCI + 3] != 0 {
            let reply = Reply::new(ApciCode::Restart, 0x21, &[RestartError::InvalidChannel.into(), 0x00, 0x00]);
            return ServiceResult::Reply(reply);
        }

        let security_on = SEC::security_mode_enabled(&self.sec);
        let policy = zweidraehte_proto::security::restart_access_policy(erase_code);
        let required_level = zweidraehte_proto::security::restart_required_level(erase_code);
        if !policy.can_write(&access, security_on) {
            self.record_access_failure(access, frame);
            let reply = Reply::new(ApciCode::Restart, 0x21, &[RestartError::AccessDenied.into(), 0x00, 0x00]);
            return ServiceResult::Reply(reply);
        }
        if !access.has_level(required_level) {
            let reply = Reply::new(ApciCode::Restart, 0x21, &[RestartError::AccessDenied.into(), 0x00, 0x00]);
            return ServiceResult::Reply(reply);
        }

        let (error, restart) = match code {
            EraseCode::Confirmed => {
                (RestartError::NoError, Some(ScheduledRestart { erase_code, wipe_individual_address: None }))
            }
            EraseCode::FactoryReset => {
                if SEC::factory_reset(&mut self.sec, reply_context, code) {
                    (RestartError::NoError, Some(ScheduledRestart { erase_code, wipe_individual_address: Some(true) }))
                } else {
                    (RestartError::AccessDenied, None)
                }
            }
            EraseCode::FactoryResetKeepIA => {
                if SEC::factory_reset(&mut self.sec, reply_context, code) {
                    (RestartError::NoError, Some(ScheduledRestart { erase_code, wipe_individual_address: Some(false) }))
                } else {
                    (RestartError::AccessDenied, None)
                }
            }
            // Optional ResetParam/ResetLinks are not implemented by this
            // product; the mandatory and prohibited codes returned above.
            _ => (RestartError::UnsupportedEraseCode, None),
        };

        // A_Restart_Response: the APCI low octet is 0xA1, built by the
        // frame builder as Restart's base (0x80) | small6. 0x21 & 0x3F
        // gives 0x21, which ORed with 0x80 = 0xA1.
        let reply = Reply::new(ApciCode::Restart, 0x21, &[error.into(), 0x00, 0x00]);

        if let Some(restart) = restart {
            SEC::schedule_restart(&mut self.sec, restart);
        }
        ServiceResult::Reply(reply)
    }

    /// Apply application and identity side effects after the factory-reset
    /// response has been protected under the old address and Tool Key.
    pub(crate) fn apply_factory_reset(&mut self, wipe_ia: bool) {
        use zweidraehte_proto::messages::apdu::load_control::LoadState;

        for machine in 0..F::LSM_COUNT {
            F::unload_side_effect(machine, self.eeprom.as_mut(), &mut self.mgmt);
            self.mgmt.lsm[machine].state = LoadState::Unloaded;
            self.mgmt.lsm[machine].table_ref = 0;
        }

        if wipe_ia {
            let base = F::ia_eeprom_offset();
            self.eeprom.as_mut()[base..base + 2].copy_from_slice(&[0xFF, 0xFF]);
        }

        self.mgmt.reset_connection_auth::<F>();
    }

    // ── Property services ───────────────────────────────────────────

    /// Number of mask-defined properties on the Device Object.
    ///
    /// Profile-module properties follow this short fixed roster. The loop is
    /// compile-time-specialized for each family, and [`NoSecurity`](crate::security::NoSecurity)
    /// contributes no entries.
    fn family_device_property_count() -> u8 {
        for index in 0..=u8::MAX {
            if F::property_spec(0, index).is_none() {
                return index;
            }
        }
        u8::MAX
    }

    pub(crate) fn property_spec(object_index: u8, property_index: u8) -> Option<PropertySpec> {
        if let Some(spec) = F::property_spec(object_index, property_index) {
            return Some(SEC::adjust_family_property(object_index, spec));
        }
        if object_index != 0 {
            return None;
        }
        let module_index = property_index.checked_sub(Self::family_device_property_count())?;
        let mut spec = SEC::device_property_spec(module_index)?;
        if spec.backing == PropertyBacking::InterfaceObjectList {
            spec.descriptor.max_elements = u16::from(F::OBJECT_COUNT) + u16::from(SEC::OBJECT_COUNT);
        }
        Some(spec)
    }

    pub(crate) fn property_spec_by_id(object_index: u8, property_id: u16) -> Option<(u8, PropertySpec)> {
        if let Some((index, spec)) = F::property_spec_by_id(object_index, property_id) {
            return Some((index, SEC::adjust_family_property(object_index, spec)));
        }
        if object_index != 0 {
            return None;
        }
        let base = Self::family_device_property_count();
        for module_index in 0..=u8::MAX - base {
            let mut spec = SEC::device_property_spec(module_index)?;
            if spec.backing == PropertyBacking::InterfaceObjectList {
                spec.descriptor.max_elements = u16::from(F::OBJECT_COUNT) + u16::from(SEC::OBJECT_COUNT);
            }
            if spec.descriptor.pid == property_id {
                return Some((base + module_index, spec));
            }
        }
        None
    }

    pub(crate) fn module_object(object_index: u8) -> Option<u8> {
        let module_index = object_index.checked_sub(F::OBJECT_COUNT)?;
        SEC::object_type(module_index).map(|_| module_index)
    }

    fn property_value_read(&mut self, payload: &[u8], frame: &[u8], access: AccessContext) -> ServiceResult<FRAME_CAP> {
        let Some(header) = PropertyValueHeader::parse_payload(payload) else {
            return ServiceResult::None;
        };
        let obj = header.object_idx as u8;
        let prop_id = header.prop_id as u8;
        let count = header.count as u8;
        let security_on = SEC::security_mode_enabled(&self.sec);
        let module_object = Self::module_object(obj);
        let descriptor = if let Some(module_object) = module_object {
            SEC::property_descriptor(module_object, u16::from(prop_id)).map(|(_, descriptor)| descriptor)
        } else {
            Self::property_spec_by_id(obj, u16::from(prop_id)).map(|(_, spec)| spec.descriptor)
        };
        let denied =
            SEC::ENABLED && descriptor.is_some_and(|descriptor| !descriptor.can_read_secure(&access, security_on));
        let result = if let Some(module_object) = module_object {
            descriptor.filter(|descriptor| descriptor.can_read_secure(&access, security_on)).and_then(|_| {
                SEC::property_read::<FRAME_CAP>(&self.sec, module_object, u16::from(prop_id), count, header.start_idx)
            })
        } else {
            self.property_read(obj, prop_id, count, header.start_idx, access)
        };
        if denied {
            self.record_access_failure(access, frame);
        }
        match result {
            Some(data) => property_value_response(header, header.count, &data),
            // Unknown property / bad index: the negative response keeps the
            // requested start index but carries a zero element count.
            None => property_value_response(header, 0, &[]),
        }
    }

    fn property_value_write(
        &mut self,
        payload: &[u8],
        frame: &[u8],
        access: AccessContext,
    ) -> ServiceResult<FRAME_CAP> {
        let Some(header) = PropertyValueHeader::parse_payload(payload) else {
            return ServiceResult::None;
        };
        let obj = header.object_idx as u8;
        let prop_id = header.prop_id as u8;
        let count = header.count as u8;
        let security_on = SEC::security_mode_enabled(&self.sec);
        let module_object = Self::module_object(obj);
        let descriptor = if let Some(module_object) = module_object {
            SEC::property_descriptor(module_object, u16::from(prop_id)).map(|(_, descriptor)| descriptor)
        } else {
            Self::property_spec_by_id(obj, u16::from(prop_id)).map(|(_, spec)| spec.descriptor)
        };
        let denied =
            SEC::ENABLED && descriptor.is_some_and(|descriptor| !descriptor.can_write_secure(&access, security_on));
        let accepted = if let Some(module_object) = module_object {
            descriptor
                .filter(|descriptor| descriptor.can_write_secure(&access, security_on))
                .map(|_| {
                    SEC::property_write(
                        &mut self.sec,
                        module_object,
                        u16::from(prop_id),
                        count,
                        header.start_idx,
                        header.payload_data(payload),
                    ) == zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode::Success
                })
                .unwrap_or(false)
        } else {
            self.property_write(obj, prop_id, count, header.start_idx, header.payload_data(payload), access)
        };
        if denied {
            self.record_access_failure(access, frame);
        }
        let response_data = if accepted {
            // Positive confirmation carries the property's current
            // value — the read-back a client would get, which for the
            // load-state controls is the machine's new state.
            if let Some(module_object) = module_object {
                SEC::property_read::<FRAME_CAP>(&self.sec, module_object, u16::from(prop_id), count, header.start_idx)
            } else {
                self.property_read(obj, prop_id, count, header.start_idx, access)
            }
        } else {
            None
        };

        // 03/04/01 §6.2.2.2.2 requires the regular write service to read the
        // value back. A write-only property (notably PID_TOOL_KEY, 008/008)
        // may have accepted and persisted the write while that read-back is
        // forbidden; AN193 §2.2.2 says the MaS must then return the standard
        // property error, not a positive count with an empty payload.
        match (accepted, response_data) {
            (true, Some(data)) => property_value_response(header, header.count, &data),
            _ => property_value_response(header, 0, &[]),
        }
    }

    /// Read `count` elements from `start` of a property. Properties on
    /// these masks are all single-element, so anything beyond
    /// `start <= 1, count <= 1` is out of range. Reading element 0
    /// returns the element count (1) as a 16-bit value, per 03/03/07.
    pub(crate) fn property_read(
        &self,
        obj: u8,
        prop_id: u8,
        count: u8,
        start: u16,
        access: AccessContext,
    ) -> Option<Vec<u8, FRAME_CAP>> {
        let (_, spec) = Self::property_spec_by_id(obj, u16::from(prop_id))?;
        let allowed = if SEC::ENABLED {
            spec.descriptor.can_read_secure(&access, SEC::security_mode_enabled(&self.sec))
        } else {
            spec.descriptor.can_read(access)
        };
        if !allowed {
            return None;
        }
        if start == 0 {
            return (count != 0).then(|| {
                let mut v = Vec::new();
                let elements = if spec.backing == PropertyBacking::InterfaceObjectList {
                    u16::from(F::OBJECT_COUNT) + u16::from(SEC::OBJECT_COUNT)
                } else {
                    1
                };
                let _ = v.extend_from_slice(&elements.to_be_bytes());
                v
            });
        }
        if spec.backing != PropertyBacking::InterfaceObjectList && (count != 1 || start != 1) {
            return None;
        }
        let mut v: Vec<u8, FRAME_CAP> = Vec::new();
        match spec.backing {
            PropertyBacking::ObjectType => {
                let _ = v.extend_from_slice(&F::object_type(obj).to_be_bytes());
            }
            PropertyBacking::DeviceControl => {
                let _ = v.push(self.mgmt.device_control);
            }
            PropertyBacking::ProgrammingMode => {
                let _ = v.push(u8::from(self.is_programming_mode()));
            }
            PropertyBacking::FirmwareRevision => {
                let _ = v.push(1);
            }
            PropertyBacking::SerialNumber => {
                let _ = v.extend_from_slice(&self.identity.serial_number);
            }
            PropertyBacking::OrderInfo => {
                let _ = v.extend_from_slice(&self.identity.order_info);
            }
            PropertyBacking::HardwareType => {
                let _ = v.extend_from_slice(&self.identity.hardware_type);
            }
            PropertyBacking::IndividualAddressSubnet => {
                let _ = v.push(self.individual_address().0[0]);
            }
            PropertyBacking::IndividualAddressDevice => {
                let _ = v.push(self.individual_address().0[1]);
            }
            PropertyBacking::MaxApduLength => {
                // The profile's wire ceiling, not the family's: a secure BCU2
                // answers 40 here over the same family a plain one answers 15
                // with (03/05/01 §4.3.7 — this is a wire-level value, and a
                // management client sizes its writes by it).
                let _ = v.extend_from_slice(&Self::max_apdu_length().to_be_bytes());
            }
            PropertyBacking::LoadState => {
                let machine = self.lsm_index(obj)?;
                let _ = v.push(self.mgmt.lsm[machine].state.into());
            }
            PropertyBacking::TableReference => {
                let machine = self.lsm_index(obj)?;
                let _ = v.extend_from_slice(&u32::from(self.mgmt.lsm[machine].table_ref).to_be_bytes());
            }
            PropertyBacking::RunState => {
                let state = F::run_state_read(obj, self.eeprom.as_ref(), &self.mgmt)?;
                let _ = v.push(state);
            }
            PropertyBacking::FamilySpecific => {
                let value =
                    F::property_read_hook(obj, u16::from(prop_id), self.eeprom.as_ref(), &self.identity, &self.mgmt)?;
                v.extend_from_slice(&value).ok()?;
            }
            PropertyBacking::InterfaceObjectList => {
                let total = u16::from(F::OBJECT_COUNT) + u16::from(SEC::OBJECT_COUNT);
                let first = start.checked_sub(1)?;
                if first >= total || count == 0 {
                    return None;
                }
                let end = (first + u16::from(count)).min(total);
                for index in first..end {
                    let object_type = if index < u16::from(F::OBJECT_COUNT) {
                        F::object_type(index as u8)
                    } else {
                        SEC::object_type((index - u16::from(F::OBJECT_COUNT)) as u8)?
                    };
                    v.extend_from_slice(&object_type.to_be_bytes()).ok()?;
                }
            }
        }
        Some(v)
    }

    pub(crate) fn property_write(
        &mut self,
        obj: u8,
        prop_id: u8,
        count: u8,
        start: u16,
        data: &[u8],
        access: AccessContext,
    ) -> bool {
        if count != 1 || start != 1 {
            return false;
        }
        let Some((_, spec)) = Self::property_spec_by_id(obj, u16::from(prop_id)) else {
            return false;
        };
        let allowed = if SEC::ENABLED {
            spec.descriptor.can_write_secure(&access, SEC::security_mode_enabled(&self.sec))
        } else {
            spec.descriptor.can_write(access)
        };
        if !allowed {
            return false;
        }
        match spec.backing {
            PropertyBacking::DeviceControl if data.len() == 1 => {
                // Status bits are owned by the device. A client may clear
                // the complete temporary resource with zero, or control the
                // supported Verify bit without manufacturing status flags.
                self.mgmt.device_control = if data[0] == 0 {
                    0
                } else {
                    let status = pid::device_control::USER_STOPPED | pid::device_control::ADDRESS_DUPLICATION;
                    (self.mgmt.device_control & status) | (data[0] & pid::device_control::VERIFY_MODE)
                };
                true
            }
            PropertyBacking::ProgrammingMode if data.len() == 1 => {
                self.set_programming_mode(data[0] & 0x01 != 0);
                true
            }
            PropertyBacking::HardwareType if data.len() == self.identity.hardware_type.len() => {
                self.identity.hardware_type.copy_from_slice(data);
                true
            }
            PropertyBacking::LoadState => {
                let Some(machine) = self.lsm_index(obj) else { return false };
                dispatch_lsm_event::<F>(machine, data, self.eeprom.as_mut(), &mut self.mgmt);
                true
            }
            PropertyBacking::TableReference => {
                let Some(machine) = self.lsm_index(obj) else { return false };
                let [0, 0, high, low] = data else { return false };
                self.mgmt.lsm[machine].table_ref = u16::from_be_bytes([*high, *low]);
                true
            }
            // `PDT_CONTROL` writes may carry the ten-octet control record
            // used by the conformance procedure.  Run Control defines only
            // its first octet; the remaining control data is reserved and
            // must not turn an otherwise valid event into a failed write.
            PropertyBacking::RunState if !data.is_empty() => {
                F::run_state_write(obj, data[0], self.eeprom.as_mut(), &mut self.mgmt)
            }
            PropertyBacking::FamilySpecific => {
                F::property_write_hook(obj, u16::from(prop_id), data, self.eeprom.as_mut(), &mut self.mgmt)
                    .unwrap_or(false)
            }
            PropertyBacking::InterfaceObjectList => false,
            _ => false,
        }
    }

    /// Which load state machine an interface object index drives. The
    /// property path works on every family — even where the primary
    /// load-control path is a memory window, `PID_LOAD_STATE_CONTROL`
    /// on the table/application objects stays live (and is what ETS
    /// actually drives on real System 7 silicon).
    fn lsm_index(&self, obj: u8) -> Option<usize> {
        let idx = usize::from(obj.checked_sub(F::LSM_OBJ_BASE)?);
        (idx < F::LSM_COUNT).then_some(idx)
    }

    // ── Property descriptions ───────────────────────────────────────

    fn property_description_read(
        &self,
        payload: &[u8],
        frame: &[u8],
        access: AccessContext,
    ) -> ServiceResult<FRAME_CAP> {
        if payload.len() != PropertyDescriptionRead::PAYLOAD_LEN {
            return ServiceResult::None;
        }
        let Some(request) = PropertyDescriptionRead::parse_payload(payload) else {
            return ServiceResult::None;
        };
        let obj = request.object_idx as u8;
        let requested_pid = request.prop_id as u8;
        let requested_idx = request.prop_idx;
        let found = if let Some(module_object) = Self::module_object(obj) {
            if requested_pid == 0 {
                SEC::property_descriptor_at(module_object, u16::from(requested_idx))
                    .map(|descriptor| (requested_idx, descriptor))
            } else {
                SEC::property_descriptor(module_object, u16::from(requested_pid))
                    .and_then(|(index, descriptor)| u8::try_from(index).ok().map(|index| (index, descriptor)))
            }
        } else if requested_pid == 0 {
            Self::property_spec(obj, requested_idx).map(|spec| (requested_idx, spec.descriptor))
        } else {
            Self::property_spec_by_id(obj, u16::from(requested_pid)).map(|(index, spec)| (index, spec.descriptor))
        };
        let found = found.filter(|(_, descriptor)| {
            let allowed =
                !SEC::ENABLED || descriptor.can_describe_secure(&access, SEC::security_mode_enabled(&self.sec));
            if !allowed {
                self.record_access_failure(access, frame);
            }
            allowed
        });

        let reply = if let Some((property_index, descriptor)) = found {
            let mut reply = [0u8; PropertyDescriptionApduResponse::PAYLOAD_LEN];
            let response = PropertyDescription::from_descriptor(u16::from(obj), u16::from(property_index), &descriptor);
            let encoded = response.encode(&mut reply);
            debug_assert_eq!(encoded, reply.len());
            reply
        } else {
            // Unknown property / exhausted by-index scan: echo the lookup
            // key and zero the descriptor, per 03/03/07.
            PropertyDescriptionApduResponse::encode_error_payload(obj, request.prop_id, requested_idx)
        };
        ServiceResult::Reply(Reply::new(ApciCode::PropertyDescriptionResponse, 0, &reply))
    }
}

/// Consume one load-control record (03/05/02 §3.31): the event octet,
/// then for `AdditionalLoadControls` the segment record. This parses
/// exactly what `LoadControlRecord` in the proto crate builds — the
/// two sides share the vocabulary so they cannot drift apart.
///
/// A free function rather than a method so a family's memory-window
/// intercept (System 7's load-control window at 0104h) can drive the
/// same state machine the property path drives.
pub(crate) fn dispatch_lsm_event<F: MicroDeviceFamily>(
    machine: usize,
    record: &[u8],
    eeprom: &mut [u8],
    mgmt: &mut ManagementState,
) {
    if machine >= F::LSM_COUNT {
        return;
    }
    let Some(&event) = record.first() else { return };
    let (new_state, action) = load_control_transition(mgmt.lsm[machine].state, event.into());
    mgmt.lsm[machine].state = new_state;

    match action {
        LoadAction::LoadStart | LoadAction::None => {}
        LoadAction::LoadEnd => F::load_completed_side_effect(machine, eeprom, mgmt),
        LoadAction::Unload => {
            // Side effect first: a family that locates the resource
            // through `table_ref` (System 7's association table) still
            // needs the reference to reach the blob it is emptying.
            F::unload_side_effect(machine, eeprom, mgmt);
            mgmt.lsm[machine].table_ref = 0;
        }
        LoadAction::Alloc => {
            let Some(&segment_type) = record.get(1) else { return };
            match LoadSegment::from(segment_type) {
                LoadSegment::AbsoluteData => {
                    // AllocAbsDataSeg. The segment lives at a fixed or
                    // product-defined address on these families, so
                    // allocation is remembering the address for
                    // PID_TABLE_REFERENCE — after checking the segment
                    // actually fits the device's storage, which is how
                    // an oversized product surfaces as a load Error
                    // rather than a silently truncated table.
                    if let Some(segment) = AbsSegment::parse(&record[1..]) {
                        if F::abs_segment_fits(segment.start_address, segment.length) {
                            mgmt.lsm[machine].table_ref = segment.start_address;
                        } else {
                            mgmt.lsm[machine].state = LoadState::Err;
                        }
                    } else if record.len() >= 4 {
                        // A record truncated after the start address:
                        // too short for AbsSegment, but the address is
                        // still worth remembering (no length to check).
                        mgmt.lsm[machine].table_ref = u16::from_be_bytes([record[2], record[3]]);
                    }
                }
                // Task records (stack/task/pointer/control blobs)
                // announce the application's identity and entry
                // points. This stack runs no legacy machine code, so
                // they are accepted as informational.
                LoadSegment::AbsoluteStack
                | LoadSegment::AbsoluteTask
                | LoadSegment::AbsolutePointer
                | LoadSegment::TaskCtrl1
                | LoadSegment::TaskCtrl2 => {}
                _ => mgmt.lsm[machine].state = LoadState::Err,
            }
        }
    }
}

fn ram2_offset<F: MicroDeviceFamily>(addr: u16) -> Option<usize> {
    let off = usize::from(addr.checked_sub(F::RAM2_BASE)?);
    (off < F::RAM2_SIZE).then_some(off)
}

/// Build the APCI-stripped payload shared by positive and negative regular
/// property responses. `count == 0` is the standard negative response.
fn property_value_response<const N: usize>(header: PropertyValueHeader, count: u16, data: &[u8]) -> ServiceResult<N> {
    let mut payload: Vec<u8, N> = Vec::new();
    payload
        .extend_from_slice(&PropertyValueHeader::encode_payload(
            header.object_idx as u8,
            header.prop_id,
            count,
            header.start_idx,
        ))
        .expect("management reply fits the TP1 APDU");
    payload.extend_from_slice(data).expect("management reply fits the TP1 APDU");
    ServiceResult::Reply(Reply::new(ApciCode::PropertyValueResponse, 0, &payload))
}
