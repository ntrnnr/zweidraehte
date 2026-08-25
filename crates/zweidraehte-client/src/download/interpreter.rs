//! The download interpreter: executes [`Instruction`] streams against
//! a device.
//!
//! The engine drives both load-control paths behind one
//! [`LoadControlPath`] switch: the *memory-mapped* one
//! (`DM_LoadStateMachineWrite_RCo_Mem`, 03/05/02 §3.31.2) that the
//! System 7 masks use — records written to the window at
//! [`MemoryResources::load_control_addr`], state read back from the
//! per-machine status bytes — and the *property* one
//! (`DM_LoadStateMachineWrite_RCo_IO`, `PID_LOAD_STATE_CONTROL`) that
//! System B uses, where the interface object index is the machine
//! index and relative segments are allocated by the device.
//!
//! Everything the engine does to the device goes through the small
//! [`DownloadTarget`] trait, so the unit tests can script a device
//! and the real path is a trivial forwarding impl on
//! [`DeviceConnection`].

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use zweidraehte_proto::pid;

use zweidraehte_proto::messages::apdu::load_control::{
    AbsSegment, LoadControlRecord, LoadEvent, LoadState, LsmMachine, MemLoadControlRecord,
};

use super::image::DeviceImage;
use super::ir::{Instruction, LsmTarget};
use super::mask::MemoryResources;
use crate::api::DeviceConnection;
use crate::error::{Error, MachineRef, Result};

/// The management operations the download engine needs. Implemented
/// by [`DeviceConnection`]; test code scripts its own device.
pub trait DownloadTarget {
    async fn property_read(&mut self, obj_idx: u8, prop_id: u16, start_idx: u16, count: u16) -> Result<Vec<u8>>;
    async fn property_write(
        &mut self,
        obj_idx: u8,
        prop_id: u16,
        start_idx: u16,
        count: u16,
        data: &[u8],
    ) -> Result<()>;
    /// Extended-property read by interface-object type and occurrence.
    async fn property_ext_read(
        &mut self,
        _object_type: u16,
        _occurrence: u16,
        _prop_id: u16,
        _start_idx: u16,
        _count: u16,
    ) -> Result<Vec<u8>> {
        Err(Error::UnsupportedInstruction("target does not support extended property reads"))
    }
    /// Confirmed extended-property write by type and occurrence.
    async fn property_ext_write(
        &mut self,
        _object_type: u16,
        _occurrence: u16,
        _prop_id: u16,
        _start_idx: u16,
        _count: u16,
        _data: &[u8],
    ) -> Result<()> {
        Err(Error::UnsupportedInstruction("target does not support extended property writes"))
    }
    async fn function_property_ext_command(
        &mut self,
        _object_type: u16,
        _occurrence: u16,
        _prop_id: u16,
        _service_data: &[u8],
    ) -> Result<()> {
        Err(Error::UnsupportedInstruction("target does not support extended function properties"))
    }
    async fn memory_read(&mut self, address: u16, count: u8) -> Result<Vec<u8>>;
    async fn memory_write(&mut self, address: u16, data: &[u8]) -> Result<()>;
    async fn memory_extended_read(&mut self, _address: u32, _count: u8) -> Result<Vec<u8>> {
        Err(Error::UnsupportedInstruction("target does not support extended memory reads"))
    }
    async fn memory_extended_write(&mut self, _address: u32, _data: &[u8]) -> Result<()> {
        Err(Error::UnsupportedInstruction("target does not support extended memory writes"))
    }
    async fn restart(&mut self) -> Result<()>;
    /// Confirmed restart (master reset erase code 01h), returning how long
    /// the device requires before it is ready again.
    ///
    /// The default preserves lightweight scripted targets. Real management
    /// connections override it with the response-bearing service.
    async fn confirmed_restart(&mut self) -> Result<Duration> {
        self.restart().await?;
        Ok(Duration::ZERO)
    }
    /// `A_Authorize` (03/05/01 §3.5.5), returning the granted level.
    /// Defaulted so scripted test targets model an unprotected device
    /// without a bus exchange.
    async fn authorize(&mut self, _key: &[u8; 4]) -> Result<u8> {
        Ok(0)
    }
}

impl DownloadTarget for DeviceConnection {
    async fn property_read(&mut self, obj_idx: u8, prop_id: u16, start_idx: u16, count: u16) -> Result<Vec<u8>> {
        DeviceConnection::property_read(self, obj_idx, prop_id, start_idx, count).await
    }

    async fn property_write(
        &mut self,
        obj_idx: u8,
        prop_id: u16,
        start_idx: u16,
        count: u16,
        data: &[u8],
    ) -> Result<()> {
        DeviceConnection::property_write(self, obj_idx, prop_id, start_idx, count, data).await
    }

    async fn property_ext_read(
        &mut self,
        object_type: u16,
        occurrence: u16,
        prop_id: u16,
        start_idx: u16,
        count: u16,
    ) -> Result<Vec<u8>> {
        DeviceConnection::property_ext_read(self, object_type, occurrence, prop_id, start_idx, count).await
    }

    async fn property_ext_write(
        &mut self,
        object_type: u16,
        occurrence: u16,
        prop_id: u16,
        start_idx: u16,
        count: u16,
        data: &[u8],
    ) -> Result<()> {
        DeviceConnection::property_ext_write(self, object_type, occurrence, prop_id, start_idx, count, data).await
    }

    async fn function_property_ext_command(
        &mut self,
        object_type: u16,
        occurrence: u16,
        prop_id: u16,
        service_data: &[u8],
    ) -> Result<()> {
        let result =
            DeviceConnection::function_property_ext_command(self, object_type, occurrence, prop_id, service_data)
                .await?;
        if result.return_code != 0 {
            return Err(Error::DeviceError(result.return_code));
        }
        Ok(())
    }

    async fn memory_read(&mut self, address: u16, count: u8) -> Result<Vec<u8>> {
        DeviceConnection::memory_read(self, address, count).await
    }

    async fn memory_write(&mut self, address: u16, data: &[u8]) -> Result<()> {
        DeviceConnection::memory_write(self, address, data).await
    }

    async fn memory_extended_read(&mut self, address: u32, count: u8) -> Result<Vec<u8>> {
        DeviceConnection::memory_extended_read(self, address, count).await
    }

    async fn memory_extended_write(&mut self, address: u32, data: &[u8]) -> Result<()> {
        DeviceConnection::memory_extended_write(self, address, data).await
    }

    async fn authorize(&mut self, key: &[u8; 4]) -> Result<u8> {
        DeviceConnection::authorize(self, key).await
    }

    async fn restart(&mut self) -> Result<()> {
        DeviceConnection::restart(self).await
    }

    async fn confirmed_restart(&mut self) -> Result<Duration> {
        Ok(DeviceConnection::master_reset(self, zweidraehte_proto::messages::apdu::restart::EraseCode::Confirmed, 0)
            .await?
            .process_time)
    }
}

/// How often, and how patiently, a load-state read-back is retried.
///
/// Our own devices transition synchronously with the memory write's
/// T_ACK, so the first read already answers and the budget below is
/// never spent. Real silicon is another matter: an Unload erases the
/// machine's EEPROM tables before the state byte flips, and on the
/// bench an MDT push button held its address-table state at Loaded
/// for well past the 100 ms this poll used to allow. ETS-class tools
/// wait seconds here ("until loadstate is correct", 03/05/02
/// §3.31.2), so we do too: 25 × 200 ms ≈ 5 s before giving up. An
/// explicit Error state still aborts immediately — waiting does not
/// heal that.
const STATE_POLL_ATTEMPTS: u32 = 25;
const STATE_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Progress a running download reports through
/// [`Downloader::with_progress`] — enough for a UI to show what is
/// happening and how far along it is, without the UI knowing the IR.
#[derive(Debug, Clone)]
pub enum DownloadEvent {
    /// About to execute step `index` (0-based) of `total`.
    Step { index: usize, total: usize, description: String },
    /// Byte progress inside the current step's data phase (chunked
    /// memory writes).
    Data { done: usize, total: usize },
}

/// Where progress events go. Boxed and `Send` so a UI thread can hand
/// in one end of a channel.
pub type ProgressSink = Box<dyn FnMut(DownloadEvent) + Send>;

/// Side effects which outlive the instruction stream itself.
///
/// In particular, a confirmed restart only starts after the management
/// connection has been closed. Keeping its process time in the result lets
/// the programming orchestrator disconnect first and wait second, matching
/// the KNX management procedure used by ETS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DownloadOutcome {
    confirmed_restart_process_time: Option<Duration>,
    loaded_properties: Vec<LoadedProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoadedProperty {
    pub(crate) obj_idx: u8,
    pub(crate) prop_id: u16,
    pub(crate) start_idx: u16,
    pub(crate) count: u16,
    pub(crate) data: Vec<u8>,
}

impl DownloadOutcome {
    pub(crate) fn confirmed_restart_process_time(&self) -> Option<Duration> {
        self.confirmed_restart_process_time
    }

    pub(crate) fn loaded_properties(&self) -> &[LoadedProperty] {
        &self.loaded_properties
    }
}

/// How a mask drives its load state machines.
///
/// The two paths carry identical record payloads; they differ only in
/// where the record is written and where the resulting state is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadControlPath {
    /// System 7: records go to the memory-mapped window,
    /// state comes from the per-machine status bytes
    /// (`DM_LoadStateMachineWrite_RCo_Mem`, 03/05/02 §3.31.2).
    Memory(MemoryResources),
    /// System B: records go to `PID_LOAD_STATE_CONTROL` on the
    /// interface object whose index *is* the machine index, and the
    /// same property reads the state back
    /// (`DM_LoadStateMachineWrite_RCo_IO`).
    Property,
    /// BCU1: there are no load state machines at all — the download
    /// is a direct memory-write sequence, so there are no records to
    /// write and no states to poll. Any LSM instruction reaching a
    /// direct-path run is a compile bug and fails loudly.
    Direct,
}

/// Which application service carries ordinary image memory transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryService {
    /// `A_Memory_Read` / `A_Memory_Write`, used by plain profiles.
    Classic,
    /// `A_MemoryExtended_Read` / `_Write`, mandatory for KNX Data Secure
    /// profiles and confirmed by the BCU2 and System B bench traces as their
    /// secure download path.
    Extended,
}

/// Executes download procedures against one device.
pub struct Downloader<'a, T> {
    target: &'a mut T,
    path: LoadControlPath,
    memory_service: MemoryService,
    /// `A_Memory_Write` data bytes per chunk: the APCI/count octet and
    /// the two address octets share the APDU with the data, and the
    /// count field itself is 6 bits.
    chunk: usize,
    /// Data bytes available after the nine-octet
    /// `A_PropertyExtValue_WriteCon` header. Unlike memory transfers, a
    /// property range may only be split between complete array elements.
    property_ext_data_budget: usize,
    /// The `A_Authorize` key sent at the procedure's Connect step. ETS
    /// authorizes every configuration connection; the default is the
    /// free-access key.
    key: [u8; 4],
    /// Whether `Connect` authorizes at all. True everywhere except
    /// BCU1, which predates `A_Authorize` — see
    /// [`DownloadModel::authorize_on_connect`](super::model::DownloadModel::authorize_on_connect).
    authorize: bool,
    /// Whether memory writes are diffed against the device's current
    /// content (BCU-era EEPROM) — see
    /// [`DownloadModel::diff_writes`](super::model::DownloadModel::diff_writes).
    diff_writes: bool,
    /// Progress reporting, when a UI wants it.
    progress: Option<ProgressSink>,
    /// Base addresses the device reported for relative segments, by
    /// interface object index. Filled by `RelSegment` allocation and
    /// by `LoadImageProperty` on `PID_TABLE_REFERENCE`; consumed by
    /// `WriteRelImage`.
    bases: BTreeMap<LsmTarget, u32>,
    /// Property values captured by `LdCtrlLoadImageProp`.
    ///
    /// System B's partial procedures use an all-zero `InlineData` buffer on
    /// a later `LdCtrlCompareProp`; ETS compares against the value loaded
    /// into that buffer before the application machine was unloaded. Keeping
    /// the snapshot separate from `bases` preserves those load-image
    /// semantics for every property, not only `PID_TABLE_REFERENCE`.
    loaded_properties: BTreeMap<(u8, u16), Vec<u8>>,
    /// The exact ranges are retained separately for durable post-download
    /// evidence. A product can request several MCB elements in one control,
    /// while `CompareProperty` still refers to the property as a whole.
    loaded_property_ranges: BTreeMap<(u8, u16, u16, u16), Vec<u8>>,
    /// Absolute segment declarations seen in this procedure. BCU2 marks
    /// zero-page RAM, RAM and EEPROM explicitly; only the EEPROM class is a
    /// candidate for read-before-write wear reduction.
    absolute_segments: Vec<AbsSegment>,
    /// Error codes currently mapped to "success" by `MapError`
    /// (`mapped == 0` inserts, `mapped == original` removes). While
    /// non-empty, a failing instruction is tolerated instead of
    /// aborting the run — see [`Instruction::MapError`] for why the
    /// numeric code itself cannot be matched.
    tolerated_errors: BTreeSet<u32>,
    /// Delay reported by the final confirmed restart. The interpreter must
    /// not wait for it while it still borrows the open connection.
    confirmed_restart_process_time: Option<Duration>,
}

impl<'a, T: DownloadTarget> Downloader<'a, T> {
    /// A downloader driving the memory-mapped path (System 7).
    ///
    /// `max_apdu` is the plaintext management budget selected by the caller:
    /// the smaller device/interface capability, less an S-A_Data envelope
    /// when the connection is secure (15 for a plain standard-frame target
    /// means 12-byte chunks).
    pub fn new(target: &'a mut T, resources: MemoryResources, max_apdu: u16) -> Self {
        Self::with_path(target, LoadControlPath::Memory(resources), max_apdu)
    }

    /// A downloader on an explicit load-control path.
    pub fn with_path(target: &'a mut T, path: LoadControlPath, max_apdu: u16) -> Self {
        let chunk = usize::from(max_apdu.saturating_sub(3)).clamp(1, 63);
        Self {
            target,
            path,
            memory_service: MemoryService::Classic,
            chunk,
            property_ext_data_budget: usize::from(max_apdu.saturating_sub(9)),
            key: [0xFF; 4],
            authorize: true,
            diff_writes: false,
            progress: None,
            bases: BTreeMap::new(),
            loaded_properties: BTreeMap::new(),
            loaded_property_ranges: BTreeMap::new(),
            absolute_segments: Vec::new(),
            tolerated_errors: BTreeSet::new(),
            confirmed_restart_process_time: None,
        }
    }

    /// Skip the `A_Authorize` at `Connect` — for targets that do not
    /// speak the service (BCU1 masks).
    pub fn without_authorize(mut self) -> Self {
        self.authorize = false;
        self
    }

    /// Diff memory writes against the device's current content and
    /// write only the changed runs — the BCU-era EEPROM economy ETS
    /// practices (see [`DownloadModel::diff_writes`](super::model::DownloadModel::diff_writes)).
    pub fn with_diffed_writes(mut self) -> Self {
        self.diff_writes = true;
        self
    }

    /// Select the memory application service used by image transfers.
    pub fn with_memory_service(mut self, service: MemoryService, max_apdu: u16) -> Self {
        self.memory_service = service;
        self.property_ext_data_budget = usize::from(max_apdu.saturating_sub(9));
        self.chunk = match service {
            MemoryService::Classic => usize::from(max_apdu.saturating_sub(3)).clamp(1, 63),
            // One APDU octet is shared with the TPCI in KNX's length
            // convention. After that, extended memory carries the second APCI
            // octet, count/return code and a three-octet address: five octets
            // before data. A secure PID-56 value of 40 reaches here as a
            // 27-octet plaintext budget and therefore leaves 22 data octets.
            MemoryService::Extended => usize::from(max_apdu.saturating_sub(5)).clamp(1, u8::MAX as usize),
        };
        self
    }

    /// Report progress to `sink` while running.
    pub fn with_progress(mut self, sink: ProgressSink) -> Self {
        self.progress = Some(sink);
        self
    }

    fn emit(&mut self, event: DownloadEvent) {
        if let Some(sink) = &mut self.progress {
            sink(event);
        }
    }

    /// Use a device-specific authorization key instead of the
    /// free-access `FF FF FF FF`.
    pub fn with_key(mut self, key: [u8; 4]) -> Self {
        self.key = key;
        self
    }

    /// Run a procedure. Fails on the first instruction that cannot be
    /// completed — a download is a transaction in spirit: on error the
    /// caller re-runs it (the procedure starts by unloading) rather
    /// than resuming mid-stream.
    ///
    /// The one exception is a `MapError` window (`original → 0`):
    /// failures inside it are logged and skipped, which is what the
    /// mask templates use it for (a step that legitimately fails on
    /// devices lacking an optional machine).
    pub async fn run(&mut self, instructions: &[Instruction], image: &DeviceImage) -> Result<()> {
        self.run_with_outcome(instructions, image).await.map(|_| ())
    }

    /// Run a procedure and return restart timing needed by its owner.
    pub(crate) async fn run_with_outcome(
        &mut self,
        instructions: &[Instruction],
        image: &DeviceImage,
    ) -> Result<DownloadOutcome> {
        // The engine works on its own copy: `ReadIntoImage` fills the
        // image's gaps with device-read bytes mid-run, and that
        // working state must not leak into the caller's compiled
        // download (which may be executed again, against another
        // device).
        let mut image = image.clone();
        self.confirmed_restart_process_time = None;
        self.loaded_properties.clear();
        self.loaded_property_ranges.clear();
        let total = instructions.len();
        for (index, instruction) in instructions.iter().enumerate() {
            log::debug!("download step: {instruction:?}");
            self.emit(DownloadEvent::Step { index, total, description: instruction.describe() });
            match self.execute(instruction, &mut image).await {
                Ok(()) => {}
                Err(e) if !self.tolerated_errors.is_empty() && !matches!(instruction, Instruction::MapError { .. }) => {
                    log::warn!("tolerating {instruction:?} failure inside a MapError window: {e}");
                }
                Err(e) => {
                    // Which step failed is the whole diagnosis on real
                    // hardware — a device that disconnects does so in
                    // reaction to a specific record.
                    log::error!("download failed at step: {instruction:?}: {e}");
                    return Err(e);
                }
            }
        }
        let loaded_properties = self
            .loaded_property_ranges
            .iter()
            .map(|(&(obj_idx, prop_id, start_idx, count), data)| LoadedProperty {
                obj_idx,
                prop_id,
                start_idx,
                count,
                data: data.clone(),
            })
            .collect();
        Ok(DownloadOutcome { confirmed_restart_process_time: self.confirmed_restart_process_time, loaded_properties })
    }

    async fn execute(&mut self, instruction: &Instruction, image: &mut DeviceImage) -> Result<()> {
        match instruction {
            // The engine runs inside an open transport connection, so
            // the transport half of Connect is a marker — but ETS's
            // DMP_Connect_RCo pairs it with an A_Authorize, and real
            // silicon gates system-memory writes (the load-control
            // window included) behind the access level that grants:
            // an unauthorized write is T_ACKed and silently ignored,
            // leaving the machine's state unchanged. Our own devices
            // grant free access at the default level, which is why
            // the software DUTs never needed this. BCU1 predates the
            // service entirely, so its model skips the exchange.
            Instruction::Connect => {
                if !self.authorize {
                    log::debug!("connect without A_Authorize (this mask has no access levels)");
                    return Ok(());
                }
                let level = self.target.authorize(&self.key).await?;
                log::debug!("authorized at access level {level}");
                Ok(())
            }
            Instruction::Disconnect => Ok(()),

            Instruction::CompareProperty { obj_idx, prop_id, expected } => {
                let value = self.target.property_read(*obj_idx, *prop_id, 1, 1).await?;
                let expected = self.loaded_properties.get(&(*obj_idx, *prop_id)).unwrap_or(expected);
                if !identity_matches(&value, expected) {
                    return Err(Error::IdentityMismatch { obj_idx: *obj_idx, prop_id: *prop_id });
                }
                Ok(())
            }

            Instruction::LsmEvent { lsm, event } => {
                self.write_load_control(*lsm, &LoadControlRecord::event(*event), MemLoadControlRecord::event).await?;
                // The compiled procedure emits these events only in their
                // valid sequence. Poll for the final state; the poll also
                // tolerates the optional Unloading and LoadCompleting states
                // while a slower device finishes the transition.
                let expected = match event {
                    LoadEvent::StartLoading => LoadState::Loading,
                    LoadEvent::LoadCompleted => LoadState::Loaded,
                    LoadEvent::Unload => LoadState::Unloaded,
                    // NoOp/AdditionalLoadControls don't come through
                    // LsmEvent; treat anything else as "must not error".
                    _ => LoadState::Loading,
                };
                self.expect_load_state(*lsm, expected).await
            }

            Instruction::AbsSegment { lsm, segment } => {
                let property = LoadControlRecord::abs_segment(segment);
                let machine = |m, _e| MemLoadControlRecord::abs_segment(m, segment);
                self.write_load_control_with(*lsm, &property, machine).await?;
                // A rejected allocation (e.g. segment larger than the
                // table) throws the machine into Error.
                self.expect_load_state(*lsm, LoadState::Loading).await?;
                self.absolute_segments.push(*segment);
                Ok(())
            }

            Instruction::RelSegment { lsm, segment } => {
                // Relative allocation is the property path's business:
                // the device chooses the address, so there is no
                // memory-mapped form to write.
                if self.path != LoadControlPath::Property {
                    return Err(Error::UnsupportedInstruction(
                        "relative segment allocation needs the property load-control path",
                    ));
                }
                let record = LoadControlRecord::rel_segment(segment);
                self.property_write_at(*lsm, pid::LOAD_STATE_CONTROL, 1, 1, &record).await?;
                self.expect_load_state(*lsm, LoadState::Loading).await?;

                // Pick up the base the device just assigned, so the
                // matching WriteRelMem knows where to write.
                let base = self.read_table_reference(*lsm).await?;
                self.bases.insert(*lsm, base);
                Ok(())
            }

            Instruction::TaskSegment { lsm, address, pei_type, application_id } => {
                // The AbsoluteTask record announces the application's
                // identity at its entry address; System 7 devices
                // accept it without acting on it. Byte layout pinned
                // by a Falcon download trace (2026-08-13). No state
                // poll: the record is informational and transitions
                // nothing. BCU2's unrelated legacy LsmIdx=5 announcement
                // is removed during compile rather than reaching here.
                let property = LoadControlRecord::task_segment(*address, *pei_type, *application_id);
                self.write_load_control_with(*lsm, &property, |m, _e| {
                    MemLoadControlRecord::task_segment(m, *address, *pei_type, *application_id)
                })
                .await
            }

            Instruction::TaskPointers { lsm, init_ptr, save_ptr, serial_ptr } => {
                // Informational like TaskSegment: the BCU2 stores the
                // pointers, the machine's state does not move.
                let property = LoadControlRecord::task_ptr(*init_ptr, *save_ptr, *serial_ptr);
                self.write_load_control_with(*lsm, &property, |m, _e| {
                    MemLoadControlRecord::task_ptr(m, *init_ptr, *save_ptr, *serial_ptr)
                })
                .await
            }

            Instruction::TaskControl1 { lsm, address, count } => {
                let property = LoadControlRecord::task_ctrl1(*address, *count);
                self.write_load_control_with(*lsm, &property, |m, _e| {
                    MemLoadControlRecord::task_ctrl1(m, *address, *count)
                })
                .await
            }

            Instruction::TaskControl2 { lsm, callback, address, seg0, seg1 } => {
                let property = LoadControlRecord::task_ctrl2(*callback, *address, *seg0, *seg1);
                self.write_load_control_with(*lsm, &property, |m, _e| {
                    MemLoadControlRecord::task_ctrl2(m, *callback, *address, *seg0, *seg1)
                })
                .await
            }

            Instruction::WriteRelImage { obj_idx, offset, length, verify } => {
                let target = LsmTarget::Index(*obj_idx);
                let base = match self.bases.get(&target) {
                    Some(base) => *base,
                    // No allocation seen in this run — the tables are
                    // being rewritten in place, so ask the device.
                    None => {
                        let base = self.read_table_reference(target).await?;
                        self.bases.insert(target, base);
                        base
                    }
                };
                let parts = image
                    .relative_parts(*obj_idx, *offset, *length)
                    .ok_or(Error::DownloadConfig("the procedure writes an object the image has no content for"))?;
                for (part_offset, bytes) in parts {
                    // The base is device-reported; a garbage value must not
                    // wrap into a plausible address.
                    let address = base
                        .checked_add(part_offset)
                        .ok_or(Error::Parse("allocated base + offset exceeds the address space"))?;
                    if *verify {
                        self.write_verified(address, bytes).await?;
                    } else {
                        self.write_chunked(address, bytes).await?;
                    }
                }
                Ok(())
            }

            Instruction::LoadImageProperty { obj_idx, prop_id, start_idx, count } => {
                let value = self.target.property_read(*obj_idx, *prop_id, *start_idx, *count).await?;
                // The loaded value replaces the load procedure's placeholder
                // buffer. A later CompareProperty for this exact resource
                // verifies the live value against this snapshot.
                if *prop_id == pid::TABLE_REFERENCE {
                    self.bases.insert(LsmTarget::Index(*obj_idx), be_u32(&value));
                }
                self.loaded_properties.insert((*obj_idx, *prop_id), value.clone());
                self.loaded_property_ranges.insert((*obj_idx, *prop_id, *start_idx, *count), value);
                Ok(())
            }

            Instruction::WriteImage { address, length, verify } => {
                // The window is a span of device memory; the image may
                // cover it with several regions (BCU1's mask template
                // writes fixed EEPROM windows across whatever the
                // product declares), so each covered part is written
                // on its own. A window the image covers not at all is
                // legitimate and writes nothing: the BCU2 template
                // names the 0200h..046Fh user EEPROM, which a
                // downward-compatible BCU1 program (0100h..01FFh) has
                // no content for, and the ETS trace of exactly that
                // download skips the span too.
                let parts: Vec<(u16, Vec<u8>)> =
                    image.covered(*address, *length).map(|(addr, bytes)| (addr, bytes.to_vec())).collect();
                if parts.is_empty() {
                    log::debug!("nothing to write in {length} bytes at {address:#06X}: the image has no content there");
                    return Ok(());
                }
                for (part_address, bytes) in parts {
                    self.write_bytes(part_address, &bytes, *verify).await?;
                }
                Ok(())
            }

            Instruction::ReadIntoImage { address, length } => {
                // `LdCtrlLoadImageMem`: snapshot device bytes into the
                // image's gaps. Compiled content stays — the ETS-owned
                // bytes must win — so a span the compile step fully
                // covered reads back into nothing, on purpose.
                let mut read = Vec::with_capacity(usize::from(*length));
                for chunk_start in (0..usize::from(*length)).step_by(self.chunk) {
                    let len = self.chunk.min(usize::from(*length) - chunk_start);
                    read.extend(self.read_memory(u32::from(*address) + chunk_start as u32, len as u8).await?);
                }
                image.fill_holes(*address, &read);
                Ok(())
            }

            Instruction::WriteMemory { address, data, verify } => self.write_bytes(*address, data, *verify).await,

            Instruction::CompareMemory { address, expected } => {
                let mut read = Vec::with_capacity(expected.len());
                for chunk_start in (0..expected.len()).step_by(self.chunk) {
                    let len = self.chunk.min(expected.len() - chunk_start);
                    read.extend(self.read_memory(u32::from(*address) + chunk_start as u32, len as u8).await?);
                }
                if read != *expected {
                    return Err(Error::CompareMismatch { address: *address });
                }
                Ok(())
            }

            Instruction::WriteProperty { obj_idx, prop_id, start_idx, count, data, verify } => {
                self.target.property_write(*obj_idx, *prop_id, *start_idx, *count, data).await?;
                if *verify {
                    let value = self.target.property_read(*obj_idx, *prop_id, *start_idx, *count).await?;
                    if value != *data {
                        return Err(Error::PropertyVerifyMismatch { obj_idx: *obj_idx, prop_id: *prop_id });
                    }
                }
                Ok(())
            }

            Instruction::WritePropertyData { .. } => {
                Err(Error::UnsupportedInstruction("unresolved property parameter data"))
            }

            Instruction::WritePropertyExt { object_type, occurrence, prop_id, start_idx, count, data, verify } => {
                self.write_property_ext_range(*object_type, *occurrence, *prop_id, *start_idx, *count, data, *verify)
                    .await
            }

            Instruction::FunctionPropertyExt { object_type, occurrence, prop_id, service_id, service_info } => {
                self.target
                    .function_property_ext_command(*object_type, *occurrence, *prop_id, &[
                        0,
                        *service_id,
                        *service_info,
                    ])
                    .await
            }

            Instruction::Restart => match self.target.restart().await {
                // A restarting device kills the transport connection
                // before any acknowledgement can leave it — real
                // silicon answers A_Restart with silence and a
                // T_Disconnect (`TransportClosed`). ETS treats that as
                // the restart happening (Falcon: "Disconnect while
                // waiting for response to Restart_req", then
                // proceeds), and so do we; only our own software
                // devices are polite enough to T_ACK first.
                Ok(()) | Err(Error::TransportClosed) => Ok(()),
                Err(e) => Err(e),
            },

            Instruction::ConfirmedRestart => {
                // The response acknowledges the reset request and reports
                // its process time, but ETS closes the transport connection
                // before waiting. Some real System B devices use that
                // disconnect as the commit boundary, so waiting here while
                // the connection is still open leaves the application
                // halted after an otherwise successful download.
                self.confirmed_restart_process_time = Some(self.target.confirmed_restart().await?);
                Ok(())
            }

            Instruction::MapError { original, mapped } => {
                if mapped == original {
                    // Identity mapping restores normal failure
                    // handling for this code.
                    self.tolerated_errors.remove(original);
                    Ok(())
                } else if *mapped == 0 {
                    self.tolerated_errors.insert(*original);
                    Ok(())
                } else {
                    // Mapping one error code to a *different* one has
                    // no meaning for typed errors, and no published
                    // template does it.
                    Err(Error::UnsupportedInstruction("MapError to a code other than 0 or itself"))
                }
            }

            Instruction::Delay { milliseconds } => {
                tokio::time::sleep(Duration::from_millis(u64::from(*milliseconds))).await;
                Ok(())
            }
        }
    }

    // ========================================================================
    // Load-control plumbing
    // ========================================================================

    /// Write a bare-event load-control record on whichever path this
    /// mask uses.
    async fn write_load_control(
        &mut self,
        lsm: LsmTarget,
        property_record: &[u8],
        memory_record: impl Fn(LsmMachine, LoadEvent) -> [u8; MemLoadControlRecord::RECORD_LEN],
    ) -> Result<()> {
        let event = LoadEvent::from(property_record[0]);
        self.write_load_control_with(lsm, property_record, |m, _| memory_record(m, event)).await
    }

    /// The general form: the property path writes `property_record` to
    /// `PID_LOAD_STATE_CONTROL` on object `lsm`; the memory path builds
    /// the machine-tagged record instead and writes it to the window.
    async fn write_load_control_with<const N: usize>(
        &mut self,
        lsm: LsmTarget,
        property_record: &[u8],
        memory_record: impl Fn(LsmMachine, LoadEvent) -> [u8; N],
    ) -> Result<()> {
        match self.path {
            LoadControlPath::Property => {
                self.property_write_at(lsm, pid::LOAD_STATE_CONTROL, 1, 1, property_record).await
            }
            LoadControlPath::Memory(resources) => {
                let machine = memory_machine(lsm)?;
                let event = LoadEvent::from(property_record[0]);
                let record = memory_record(machine, event);
                self.target.memory_write(resources.load_control_addr, &record).await
            }
            // BCU1 procedures contain no LSM instructions; one showing
            // up means the compile step paired a procedure with the
            // wrong path.
            LoadControlPath::Direct => {
                Err(Error::UnsupportedInstruction("load-control records cannot be sent on the direct (no-LSM) path"))
            }
        }
    }

    /// Read `PID_TABLE_REFERENCE` — the base address the device
    /// allocated for an object's relative segment.
    async fn read_table_reference(&mut self, target: LsmTarget) -> Result<u32> {
        let value = self.property_read_at(target, pid::TABLE_REFERENCE, 1, 1).await?;
        if value.is_empty() {
            return Err(Error::Parse("empty pid::TABLE_REFERENCE response"));
        }
        Ok(be_u32(&value))
    }

    // ========================================================================
    // Primitives
    // ========================================================================

    /// A memory write, on this downloader's write policy: diffed
    /// against the device where the model asks for it, plain
    /// otherwise; read-back verified when the instruction says so.
    async fn write_bytes(&mut self, address: u16, data: &[u8], verify: bool) -> Result<()> {
        if self.diff_writes && self.should_diff(address, data.len()) {
            return self.write_diffed(address, data, verify).await;
        }
        if verify {
            self.write_verified(u32::from(address), data).await
        } else {
            self.write_chunked(u32::from(address), data).await
        }
    }

    /// Classic BCU windows are EEPROM by construction. Extended BCU2
    /// procedures also declare volatile segments: reading those merely to
    /// avoid a write is both pointless and not guaranteed to be implemented
    /// by the device (real 0021h hardware answers E_ADDRESS_VOID for its RAM
    /// segment). Restrict the optimization to an enclosing EEPROM allocation.
    fn should_diff(&self, address: u16, length: usize) -> bool {
        if self.memory_service == MemoryService::Classic {
            return true;
        }
        let start = u32::from(address);
        let end = start + length as u32;
        self.absolute_segments.iter().rev().any(|segment| {
            let segment_start = u32::from(segment.start_address);
            let segment_end = segment_start + u32::from(segment.length);
            segment.memory_type == 3 && start >= segment_start && end <= segment_end
        })
    }

    /// Read the span and write only the runs that differ — what ETS
    /// does to BCU-era EEPROM (BCU1.log: a re-download that changed a
    /// handful of bytes reads every window and writes 8 small runs).
    /// EEPROM bytes are wear-limited and slow to write; reading first
    /// costs one pass and typically saves most of the write pass.
    ///
    /// Nearby changes coalesce into one run: ETS writes
    /// `$0135 Count=7` for changed bytes at $0135/37/38/3A/3B — a
    /// couple of unchanged bytes rewritten with their own value cost
    /// less than another telegram.
    async fn write_diffed(&mut self, address: u16, data: &[u8], verify: bool) -> Result<()> {
        let mut current = Vec::with_capacity(data.len());
        for start in (0..data.len()).step_by(self.chunk) {
            let len = self.chunk.min(data.len() - start);
            current.extend(self.read_memory(u32::from(address + start as u16), len as u8).await?);
        }
        if current.len() < data.len() {
            return Err(Error::Parse("short memory read while diffing a write"));
        }

        // Coalesce differing bytes into runs, bridging gaps of up to
        // three equal bytes.
        const BRIDGE: usize = 3;
        let mut runs: Vec<(usize, usize)> = Vec::new();
        for (i, (new, old)) in data.iter().zip(&current).enumerate() {
            if new == old {
                continue;
            }
            match runs.last_mut() {
                Some((_, end)) if i - *end <= BRIDGE => *end = i + 1,
                _ => runs.push((i, i + 1)),
            }
        }

        for (start, end) in runs {
            let run_address = address + start as u16;
            let run = data[start..end].to_vec();
            if verify {
                self.write_verified(u32::from(run_address), &run).await?;
            } else {
                self.write_chunked(u32::from(run_address), &run).await?;
            }
        }
        Ok(())
    }

    /// Chunked `DMP_MemWrite_RCo` (no read-back).
    async fn write_chunked(&mut self, address: u32, data: &[u8]) -> Result<()> {
        for start in (0..data.len()).step_by(self.chunk) {
            let end = (start + self.chunk).min(data.len());
            let chunk_address = address
                .checked_add(u32::try_from(start).map_err(|_| Error::Parse("memory write exceeds the address space"))?)
                .ok_or(Error::Parse("memory write exceeds the address space"))?;
            self.write_memory(chunk_address, &data[start..end]).await?;
            self.emit(DownloadEvent::Data { done: end, total: data.len() });
        }
        Ok(())
    }

    /// Chunked `DMP_MemWrite_RCoV` (03/05/02 §3.16.3): every chunk is
    /// read back and compared before the next goes out, so a failure
    /// names the first bad address instead of a garbled table.
    async fn write_verified(&mut self, address: u32, data: &[u8]) -> Result<()> {
        // DMP_MemWrite_Extended_R (03/05/02 §3.22) is already an
        // application-confirmed write. Unlike classic A_Memory_Write, it does
        // not use Verify Mode or require a read-back; some BCU2 RAM ranges are
        // deliberately writeable without being readable through the extended
        // service.
        if self.memory_service == MemoryService::Extended {
            return self.write_chunked(address, data).await;
        }
        for start in (0..data.len()).step_by(self.chunk) {
            let end = (start + self.chunk).min(data.len());
            let chunk_addr = address
                .checked_add(u32::try_from(start).map_err(|_| Error::Parse("memory write exceeds the address space"))?)
                .and_then(|address| u16::try_from(address).ok())
                .ok_or(Error::Parse("classic memory access exceeds the 16-bit address space"))?;
            let chunk = &data[start..end];
            self.write_memory(u32::from(chunk_addr), chunk).await?;
            let read_back = self.read_memory(u32::from(chunk_addr), chunk.len() as u8).await?;
            if read_back != chunk {
                return Err(Error::VerifyMismatch { address: chunk_addr });
            }
            self.emit(DownloadEvent::Data { done: end, total: data.len() });
        }
        Ok(())
    }

    /// Poll a machine's load state until it reads `expected`.
    async fn expect_load_state(&mut self, lsm: LsmTarget, expected: LoadState) -> Result<()> {
        // Resolve the machine's identity in the terms of the path
        // driving it — which is also exactly what a failure should
        // name, so the diagnostic never has to hedge between the
        // families' readings of the same index.
        let machine = match self.path {
            LoadControlPath::Memory(_) => MachineRef::Machine(memory_machine(lsm)?),
            LoadControlPath::Property => match lsm {
                LsmTarget::Index(index) => MachineRef::Object(index),
                LsmTarget::ObjectType { object_type, occurrence } => MachineRef::ObjectType { object_type, occurrence },
            },
            LoadControlPath::Direct => {
                return Err(Error::UnsupportedInstruction("load states cannot be read on the direct (no-LSM) path"));
            }
        };

        let mut state = LoadState::Err;
        for attempt in 0..STATE_POLL_ATTEMPTS {
            let raw = match (self.path, machine) {
                (LoadControlPath::Memory(resources), MachineRef::Machine(m)) => {
                    self.target.memory_read(resources.load_status_of(m), 1).await?
                }
                _ => self.property_read_at(lsm, pid::LOAD_STATE_CONTROL, 1, 1).await?,
            };
            state = LoadState::try_from(*raw.first().ok_or(Error::Parse("empty load-state response"))?)
                .map_err(|_| Error::Parse("load-state byte outside the LoadState coding"))?;
            if state == expected {
                return Ok(());
            }
            // An explicit Error state will not heal by waiting.
            if state == LoadState::Err {
                break;
            }
            if attempt + 1 < STATE_POLL_ATTEMPTS {
                tokio::time::sleep(STATE_POLL_INTERVAL).await;
            }
        }
        Err(Error::LoadState { machine, state, expected })
    }

    /// Read a property through the address form the procedure retained.
    async fn property_read_at(
        &mut self,
        target: LsmTarget,
        prop_id: u16,
        start_idx: u16,
        count: u16,
    ) -> Result<Vec<u8>> {
        match target {
            LsmTarget::Index(index) => self.target.property_read(index, prop_id, start_idx, count).await,
            LsmTarget::ObjectType { object_type, occurrence } => {
                self.target.property_ext_read(object_type, occurrence, prop_id, start_idx, count).await
            }
        }
    }

    /// Write a property through the address form the procedure retained.
    async fn property_write_at(
        &mut self,
        target: LsmTarget,
        prop_id: u16,
        start_idx: u16,
        count: u16,
        data: &[u8],
    ) -> Result<()> {
        match target {
            LsmTarget::Index(index) => self.target.property_write(index, prop_id, start_idx, count, data).await,
            LsmTarget::ObjectType { object_type, occurrence } => {
                self.write_property_ext_range(object_type, occurrence, prop_id, start_idx, count, data, false).await
            }
        }
    }

    /// Split one logical extended-property range into confirmed writes that
    /// fit the negotiated plaintext APDU without ever splitting an element.
    ///
    /// Application Layer §3.4.5.2 defines `nr_of_elem` and `start_index` as
    /// a contiguous array range. Falcon uses nine APDU octets before the
    /// property data, and its loader fills the remaining space with complete
    /// elements. Keeping that policy here lets the compiler describe a table
    /// once while devices with different APDU limits receive different,
    /// valid wire chunks.
    async fn write_property_ext_range(
        &mut self,
        object_type: u16,
        occurrence: u16,
        prop_id: u16,
        start_idx: u16,
        count: u16,
        data: &[u8],
        verify: bool,
    ) -> Result<()> {
        let count = usize::from(count);
        if count == 0 || data.is_empty() || data.len() % count != 0 {
            return Err(Error::DownloadConfig(
                "extended property data does not contain an integral number of non-empty elements",
            ));
        }
        let last_offset =
            u16::try_from(count - 1).map_err(|_| Error::DownloadConfig("extended property range exceeds 16 bits"))?;
        start_idx.checked_add(last_offset).ok_or(Error::DownloadConfig("extended property range exceeds 16 bits"))?;
        let element_size = data.len() / count;
        let elements_per_request = (self.property_ext_data_budget / element_size).min(usize::from(u8::MAX));
        if elements_per_request == 0 {
            return Err(Error::DownloadConfig("one extended property element exceeds the negotiated APDU"));
        }

        let mut element_offset = 0usize;
        while element_offset < count {
            let chunk_count = elements_per_request.min(count - element_offset);
            let chunk_start = start_idx
                .checked_add(
                    u16::try_from(element_offset)
                        .map_err(|_| Error::DownloadConfig("extended property range exceeds 16 bits"))?,
                )
                .ok_or(Error::DownloadConfig("extended property range exceeds 16 bits"))?;
            let byte_start = element_offset * element_size;
            let byte_end = byte_start + chunk_count * element_size;
            let chunk_count = u16::try_from(chunk_count)
                .map_err(|_| Error::DownloadConfig("extended property request exceeds 255 elements"))?;

            self.target
                .property_ext_write(
                    object_type,
                    occurrence,
                    prop_id,
                    chunk_start,
                    chunk_count,
                    &data[byte_start..byte_end],
                )
                .await?;
            if verify {
                let value =
                    self.target.property_ext_read(object_type, occurrence, prop_id, chunk_start, chunk_count).await?;
                if value != data[byte_start..byte_end] {
                    return Err(Error::UnexpectedResponse);
                }
            }
            element_offset += usize::from(chunk_count);
        }
        Ok(())
    }

    async fn read_memory(&mut self, address: u32, count: u8) -> Result<Vec<u8>> {
        match self.memory_service {
            MemoryService::Classic => {
                let address = u16::try_from(address)
                    .map_err(|_| Error::Parse("classic memory access exceeds the 16-bit address space"))?;
                self.target.memory_read(address, count).await
            }
            MemoryService::Extended => self.target.memory_extended_read(address, count).await,
        }
    }

    async fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<()> {
        match self.memory_service {
            MemoryService::Classic => {
                let address = u16::try_from(address)
                    .map_err(|_| Error::Parse("classic memory access exceeds the 16-bit address space"))?;
                self.target.memory_write(address, data).await
            }
            MemoryService::Extended => self.target.memory_extended_write(address, data).await,
        }
    }
}

/// A `PID_TABLE_REFERENCE` value (up to four big-endian octets) as a
/// `u32` base address. Shorter responses are zero-extended from the
/// left; anything past four octets is ignored.
fn be_u32(bytes: &[u8]) -> u32 {
    bytes.iter().take(4).fold(0u32, |acc, &b| (acc << 8) | u32::from(b))
}

/// Narrow an LSM index to a machine of the memory-mapped model.
///
/// The limit is the mask's machine roster, not the record format (the
/// nibble could hold 15): the memory-mapped masks define exactly four
/// machines — MV-0705 has four status bytes, B6EAh..B6EDh, and no
/// group-object-table machine, because that table is application data
/// there. Machine 5 exists only where "machine" means "interface
/// object", and those masks have no memory-mapped load controls at
/// all — so an out-of-range index here means a property-path
/// procedure is running against a memory-path device.
fn memory_machine(lsm: LsmTarget) -> Result<LsmMachine> {
    match lsm {
        LsmTarget::Index(index) => LsmMachine::try_from(index).map_err(|_| {
            Error::UnsupportedInstruction(
                "load state machine index outside 1-4 has no memory-mapped load-control record",
            )
        }),
        LsmTarget::ObjectType { .. } => Err(Error::UnsupportedInstruction(
            "object-type load state machine has no memory-mapped load-control record",
        )),
    }
}

/// Does a property value satisfy an `LdCtrlCompareProp` guard?
///
/// Not plain equality: product files pad the expected value out to a
/// fixed field width with zeros, while the property itself is only as
/// long as its PDT. MDT's real System 7 procedures compare
/// `PID_HARDWARE_TYPE` — six octets — against twenty hex characters,
/// and our own generator reproduces that convention, so an exact
/// comparison would reject every genuine device.
///
/// The value must therefore match the leading bytes of `expected`, and
/// whatever follows must be padding (all zero). An `expected` shorter
/// than the property, or non-zero trailing bytes, is a real mismatch.
fn identity_matches(value: &[u8], expected: &[u8]) -> bool {
    if expected.len() < value.len() {
        return false;
    }
    let (head, padding) = expected.split_at(value.len());
    head == value && padding.iter().all(|&b| b == 0)
}

// ============================================================================
// Tests: the engine against a scripted System 7 memory surface
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::mask::MaskDb;
    use crate::download::{GroupLink, ProcedureKind, ProductData, ProjectConfig, assemble, compile};
    use zweidraehte_proto::device::MaskVersion;
    use zweidraehte_proto::messages::apdu::load_control::LoadSegment;

    /// Mask resources come from the master data even in unit tests —
    /// there is no constant to reach for.
    fn resources() -> MemoryResources {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture parses");
        db.mask(MaskVersion::System7Tp1).expect("0705").memory_resources().expect("0705 is memory-mapped")
    }
    use std::collections::{HashMap, VecDeque};
    use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

    /// A scripted mask-0705 memory surface: plain byte memory plus
    /// the load-control window / status bytes, transitioning like the
    /// real `System7MemoryMap` (which the conformance tier then
    /// exercises for real).
    struct ScriptedDevice {
        memory: HashMap<u16, u8>,
        /// ADT, AST, APP, PEI load states.
        states: [LoadState; 4],
        /// Optional intermediate states returned by successive status
        /// reads before falling back to `states`.
        pending_states: VecDeque<LoadState>,
        restarted: bool,
        writes: usize,
        /// What PID_SERIAL_NUMBER answers — the value the fixture's
        /// `LdCtrlCompareProp` identity guard checks.
        serial: Vec<u8>,
    }

    impl ScriptedDevice {
        fn new() -> Self {
            Self {
                memory: HashMap::new(),
                states: [LoadState::Unloaded; 4],
                pending_states: VecDeque::new(),
                restarted: false,
                writes: 0,
                // The serial the fixture's CompareProp expects.
                serial: vec![0x00, 0xFA, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00],
            }
        }

        fn apply_load_control(&mut self, data: &[u8]) {
            let machine = (data[0] >> 4) as usize;
            let event = LoadEvent::from(data[0] & 0x0F);
            let state = &mut self.states[machine - 1];
            *state = match (event, *state) {
                (LoadEvent::StartLoading, _) => LoadState::Loading,
                (LoadEvent::LoadCompleted, LoadState::Loading) => LoadState::Loaded,
                (LoadEvent::Unload, _) => LoadState::Unloaded,
                (LoadEvent::AdditionalLoadControls, LoadState::Loading) => LoadState::Loading,
                _ => LoadState::Err,
            };
        }
    }

    impl DownloadTarget for ScriptedDevice {
        async fn property_read(&mut self, _obj: u8, prop_id: u16, _s: u16, _c: u16) -> Result<Vec<u8>> {
            match prop_id {
                78 => Ok(self.serial.clone()),
                _ => Err(Error::DeviceError(0)),
            }
        }
        async fn property_write(&mut self, _o: u8, _p: u16, _s: u16, _c: u16, _d: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn memory_read(&mut self, address: u16, count: u8) -> Result<Vec<u8>> {
            if (0xB6EA..0xB6EE).contains(&address) {
                if let Some(state) = self.pending_states.pop_front() {
                    return Ok(vec![state.into()]);
                }
                return Ok(vec![self.states[(address - 0xB6EA) as usize].into()]);
            }
            Ok((0..count).map(|i| *self.memory.get(&(address + u16::from(i))).unwrap_or(&0)).collect())
        }
        async fn memory_write(&mut self, address: u16, data: &[u8]) -> Result<()> {
            self.writes += 1;
            if address == 0x0104 {
                self.apply_load_control(data);
                return Ok(());
            }
            for (i, byte) in data.iter().enumerate() {
                self.memory.insert(address + i as u16, *byte);
            }
            Ok(())
        }
        async fn restart(&mut self) -> Result<()> {
            self.restarted = true;
            Ok(())
        }
    }

    fn product() -> ProductData {
        ProductData::from_mtxml_str(crate::download::product::tests::SYSTEM7_MTXML).expect("fixture parses")
    }

    fn project() -> ProjectConfig {
        let mut project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        project.links = vec![GroupLink { group_address: GroupAddress::from_three_level(2, 0, 3), com_object: 1 }];
        project
    }

    /// Compile the three layers the way the public API does.
    fn compiled_download(product: &ProductData, project: &ProjectConfig) -> crate::download::CompiledDownload {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture parses");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        compile(&mask, product, project).expect("the three layers compile")
    }

    #[tokio::test(start_paused = true)]
    async fn full_download_lands_blobs_and_states() {
        let compiled = compiled_download(&product(), &project());
        let mut device = ScriptedDevice::new();
        let mut downloader = Downloader::new(&mut device, resources(), 15);
        downloader.run(&compiled.instructions, &compiled.image).await.expect("scripted download succeeds");

        // The fixture's ProductProcedure loads only the address-table
        // machine, so that is what must end up Loaded.
        assert_eq!(device.states[0], LoadState::Loaded);
        assert!(device.restarted);

        // The ADT blob landed byte-exactly: length 2 counts IA 1.1.42
        // and GA 2/0/3.
        for (offset, expected) in [2u8, 0x11, 0x2A, 0x10, 0x03].into_iter().enumerate() {
            assert_eq!(device.memory.get(&(0x4000 + offset as u16)), Some(&expected), "ADT byte {offset}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn identity_mismatch_stops_before_unloading() {
        // The fixture's CompareProp expects one serial; the scripted
        // device answers a different one.
        let compiled = compiled_download(&product(), &project());

        let mut device = ScriptedDevice::new();
        device.serial = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        device.states = [LoadState::Loaded; 4]; // pretend it's configured
        let mut downloader = Downloader::new(&mut device, resources(), 15);
        let result = downloader.run(&compiled.instructions, &compiled.image).await;

        assert!(matches!(result, Err(Error::IdentityMismatch { obj_idx: 0, prop_id: 78 })));
        assert_eq!(device.states, [LoadState::Loaded; 4], "nothing was unloaded");
    }

    #[tokio::test(start_paused = true)]
    async fn load_state_error_is_reported() {
        let mut device = ScriptedDevice::new();
        let mut downloader = Downloader::new(&mut device, resources(), 15);
        // LoadCompleted while Unloaded → Error state on the device.
        let result = downloader
            .run(&[Instruction::LsmEvent { lsm: 1.into(), event: LoadEvent::LoadCompleted }], &DeviceImage::new())
            .await;
        assert!(matches!(
            result,
            Err(Error::LoadState { machine: MachineRef::Machine(LsmMachine::AddressTable), state: LoadState::Err, .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn load_state_poll_accepts_optional_intermediate_states() {
        let mut device = ScriptedDevice::new();
        device.states[0] = LoadState::Loaded;
        device.pending_states =
            [LoadState::Unloading, LoadState::Unloaded, LoadState::LoadCompleting, LoadState::Loaded].into();

        let mut downloader = Downloader::new(&mut device, resources(), 15);
        downloader.expect_load_state(1.into(), LoadState::Unloaded).await.expect("Unloading completes to Unloaded");
        downloader.expect_load_state(1.into(), LoadState::Loaded).await.expect("LoadCompleting completes to Loaded");
    }

    #[test]
    fn identity_guard_tolerates_the_padding_product_files_carry() {
        // A six-octet PID_HARDWARE_TYPE against the twenty hex
        // characters MDT (and our generator) write.
        let value = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x0A];
        let padded = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00];
        assert!(identity_matches(&value, &padded));
        assert!(identity_matches(&value, &value), "unpadded still matches");

        // A different device is still a mismatch...
        let other = [0xDE, 0xAD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(!identity_matches(&value, &other));
        // ...and so is non-zero trailing data, which is not padding.
        let trailing = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x0A, 0x01, 0x00, 0x00, 0x00];
        assert!(!identity_matches(&value, &trailing));
        // An expectation shorter than the property cannot match.
        assert!(!identity_matches(&value, &value[..3]));
    }

    #[tokio::test(start_paused = true)]
    async fn unload_all_resets_every_machine() {
        let mut device = ScriptedDevice::new();
        device.states = [LoadState::Loaded; 4];
        let mut downloader = Downloader::new(&mut device, resources(), 15);
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture parses");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let unload = assemble(&mask, &ProductData::default(), ProcedureKind::UnloadAll).expect("mask carries Unload");
        downloader.run(&unload, &DeviceImage::new()).await.expect("unload succeeds");
        assert_eq!(device.states, [LoadState::Unloaded; 4]);
    }

    #[tokio::test(start_paused = true)]
    async fn writes_are_chunked_by_apdu() {
        let mut device = ScriptedDevice::new();
        // max_apdu 15 → 12-byte chunks; 30 bytes → 3 writes + 3 verify reads.
        let mut downloader = Downloader::new(&mut device, resources(), 15);
        let data: Vec<u8> = (0..30).collect();
        downloader
            .run(&[Instruction::WriteMemory { address: 0x7000, data: data.clone(), verify: true }], &DeviceImage::new())
            .await
            .expect("write succeeds");
        assert_eq!(device.writes, 3);
        for (i, byte) in data.iter().enumerate() {
            assert_eq!(device.memory.get(&(0x7000 + i as u16)), Some(byte));
        }
    }

    struct ExtendedRecorder {
        state: LoadState,
        ext_writes: Vec<(u16, u16, u16, u16, u16, Vec<u8>)>,
        function_calls: Vec<(u16, u16, u16, Vec<u8>)>,
        memory: HashMap<u32, u8>,
        relative_base: Option<u32>,
        extended_memory_reads: usize,
        extended_memory_writes: usize,
    }

    impl Default for ExtendedRecorder {
        fn default() -> Self {
            Self {
                state: LoadState::Unloaded,
                ext_writes: Vec::new(),
                function_calls: Vec::new(),
                memory: HashMap::new(),
                relative_base: None,
                extended_memory_reads: 0,
                extended_memory_writes: 0,
            }
        }
    }

    impl DownloadTarget for ExtendedRecorder {
        async fn property_read(&mut self, _o: u8, prop_id: u16, _s: u16, _c: u16) -> Result<Vec<u8>> {
            if prop_id == pid::TABLE_REFERENCE
                && let Some(base) = self.relative_base
            {
                return Ok(base.to_be_bytes().to_vec());
            }
            panic!("object-type procedure must not use indexed properties");
        }

        async fn property_write(&mut self, _o: u8, _p: u16, _s: u16, _c: u16, _data: &[u8]) -> Result<()> {
            panic!("object-type procedure must not use indexed properties");
        }

        async fn property_ext_read(
            &mut self,
            object_type: u16,
            occurrence: u16,
            prop_id: u16,
            _start: u16,
            _count: u16,
        ) -> Result<Vec<u8>> {
            assert_eq!((object_type, occurrence, prop_id), (0x0011, 1, pid::LOAD_STATE_CONTROL));
            Ok(vec![self.state.into()])
        }

        async fn property_ext_write(
            &mut self,
            object_type: u16,
            occurrence: u16,
            prop_id: u16,
            start: u16,
            count: u16,
            data: &[u8],
        ) -> Result<()> {
            self.ext_writes.push((object_type, occurrence, prop_id, start, count, data.to_vec()));
            if prop_id == pid::LOAD_STATE_CONTROL {
                self.state = match LoadEvent::from(data[0]) {
                    LoadEvent::Unload => LoadState::Unloaded,
                    LoadEvent::StartLoading => LoadState::Loading,
                    LoadEvent::LoadCompleted => LoadState::Loaded,
                    // Segment/task records leave the current load state
                    // unchanged.
                    _ => self.state,
                };
            }
            Ok(())
        }

        async fn function_property_ext_command(
            &mut self,
            object_type: u16,
            occurrence: u16,
            prop_id: u16,
            service_data: &[u8],
        ) -> Result<()> {
            self.function_calls.push((object_type, occurrence, prop_id, service_data.to_vec()));
            Ok(())
        }

        async fn memory_read(&mut self, _address: u16, _count: u8) -> Result<Vec<u8>> {
            panic!("extended-memory policy must not use classic reads");
        }

        async fn memory_write(&mut self, _address: u16, _data: &[u8]) -> Result<()> {
            panic!("extended-memory policy must not use classic writes");
        }

        async fn memory_extended_read(&mut self, address: u32, count: u8) -> Result<Vec<u8>> {
            self.extended_memory_reads += 1;
            Ok((0..count).map(|offset| self.memory.get(&(address + u32::from(offset))).copied().unwrap_or(0)).collect())
        }

        async fn memory_extended_write(&mut self, address: u32, data: &[u8]) -> Result<()> {
            self.extended_memory_writes += 1;
            for (offset, byte) in data.iter().enumerate() {
                self.memory.insert(address + offset as u32, *byte);
            }
            Ok(())
        }

        async fn restart(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn object_type_lsm_and_extended_instructions_stay_on_extended_services() {
        let target = LsmTarget::ObjectType { object_type: 0x0011, occurrence: 1 };
        let instructions = [
            Instruction::LsmEvent { lsm: target, event: LoadEvent::Unload },
            Instruction::LsmEvent { lsm: target, event: LoadEvent::StartLoading },
            Instruction::WritePropertyExt {
                object_type: 0x0011,
                occurrence: 1,
                prop_id: pid::security::GO_SECURITY_FLAGS,
                start_idx: 1,
                count: 1,
                data: vec![3],
                verify: false,
            },
            Instruction::LsmEvent { lsm: target, event: LoadEvent::LoadCompleted },
            Instruction::FunctionPropertyExt {
                object_type: 0x0011,
                occurrence: 1,
                prop_id: pid::security::SECURITY_MODE,
                service_id: 0,
                service_info: 1,
            },
        ];
        let mut device = ExtendedRecorder::default();
        Downloader::with_path(&mut device, LoadControlPath::Property, 40)
            .without_authorize()
            .run(&instructions, &DeviceImage::new())
            .await
            .expect("extended procedure runs");

        assert_eq!(device.state, LoadState::Loaded);
        assert_eq!(device.ext_writes.len(), 4);
        assert_eq!(device.ext_writes[2], (0x0011, 1, pid::security::GO_SECURITY_FLAGS, 1, 1, vec![3]));
        assert_eq!(device.function_calls, vec![(0x0011, 1, pid::security::SECURITY_MODE, vec![0, 0, 1])]);
    }

    #[tokio::test(start_paused = true)]
    async fn extended_property_ranges_are_split_on_element_boundaries() {
        let go_flags = (0..40).collect::<Vec<_>>();
        let siat = (0..5).flat_map(|element| [element, 0, 0, 0, 0, 0, 0, element]).collect::<Vec<_>>();
        let instructions = [
            Instruction::WritePropertyExt {
                object_type: 0x0011,
                occurrence: 1,
                prop_id: pid::security::GO_SECURITY_FLAGS,
                start_idx: 1,
                count: 40,
                data: go_flags,
                verify: false,
            },
            Instruction::WritePropertyExt {
                object_type: 0x0011,
                occurrence: 1,
                prop_id: pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
                start_idx: 1,
                count: 5,
                data: siat,
                verify: false,
            },
        ];
        let mut device = ExtendedRecorder::default();

        // A 27-octet plaintext APDU leaves 18 data octets after the
        // extended-property header: exactly the BCU2 chunk size in the ETS
        // trace. One-byte rows therefore batch 18 at a time; eight-byte SIAT
        // rows batch two at a time without splitting the third row.
        Downloader::with_path(&mut device, LoadControlPath::Property, 27)
            .without_authorize()
            .run(&instructions, &DeviceImage::new())
            .await
            .expect("extended ranges fit into element-aligned requests");

        let writes = device
            .ext_writes
            .iter()
            .map(|(_, _, prop_id, start, count, data)| (*prop_id, *start, *count, data.len()))
            .collect::<Vec<_>>();
        assert_eq!(writes, [
            (pid::security::GO_SECURITY_FLAGS, 1, 18, 18),
            (pid::security::GO_SECURITY_FLAGS, 19, 18, 18),
            (pid::security::GO_SECURITY_FLAGS, 37, 4, 4),
            (pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 1, 2, 16),
            (pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 3, 2, 16),
            (pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 5, 1, 8),
        ]);
    }

    #[tokio::test(start_paused = true)]
    async fn extended_property_write_rejects_an_element_larger_than_the_apdu() {
        let instruction = Instruction::WritePropertyExt {
            object_type: 0x0011,
            occurrence: 1,
            prop_id: pid::security::GROUP_KEY_TABLE,
            start_idx: 1,
            count: 1,
            data: vec![0; 18],
            verify: false,
        };
        let mut device = ExtendedRecorder::default();
        let error = Downloader::with_path(&mut device, LoadControlPath::Property, 15)
            .without_authorize()
            .run(&[instruction], &DeviceImage::new())
            .await
            .expect_err("a six-byte data budget cannot carry an 18-byte element");

        assert!(error.to_string().contains("element exceeds the negotiated APDU"));
        assert!(device.ext_writes.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn extended_memory_write_confirmation_replaces_classic_readback() {
        let mut device = ExtendedRecorder::default();
        Downloader::with_path(&mut device, LoadControlPath::Direct, 40)
            .without_authorize()
            .with_memory_service(MemoryService::Extended, 40)
            .run(
                &[Instruction::WriteMemory { address: 0x4000, data: (0..80).collect(), verify: true }],
                &DeviceImage::new(),
            )
            .await
            .expect("extended memory write is confirmed");

        assert_eq!(device.extended_memory_writes, 3, "40-byte APDU leaves 35 data bytes per request");
        assert_eq!(device.extended_memory_reads, 0, "the confirmed extended service needs no verification read");
        assert_eq!(device.memory.get(&0x404F), Some(&79));
    }

    #[tokio::test(start_paused = true)]
    async fn extended_relative_writes_keep_the_32_bit_allocated_base() {
        let mut image = DeviceImage::new();
        image.insert_relative(4, vec![0x11, 0x22, 0x33]);
        let mut device = ExtendedRecorder { relative_base: Some(0x1_0000), ..Default::default() };

        Downloader::with_path(&mut device, LoadControlPath::Property, 40)
            .without_authorize()
            .with_memory_service(MemoryService::Extended, 40)
            .run(&[Instruction::WriteRelImage { obj_idx: 4, offset: 0, length: 3, verify: true }], &image)
            .await
            .expect("relative image writes above the classic address range");

        assert_eq!(device.memory.get(&0x1_0000), Some(&0x11));
        assert_eq!(device.memory.get(&0x1_0002), Some(&0x33));
    }

    #[tokio::test(start_paused = true)]
    async fn extended_diffing_reads_eeprom_but_writes_ram_directly() {
        let target = LsmTarget::ObjectType { object_type: 0x0011, occurrence: 1 };
        let eeprom = AbsSegment::eeprom(0x4000, 2);
        let ram = AbsSegment {
            segment_type: LoadSegment::AbsoluteData,
            start_address: 0x5000,
            length: 2,
            access_attributes: 0x30,
            memory_type: 2,
            memory_attributes: 0,
        };
        let instructions = [
            Instruction::LsmEvent { lsm: target, event: LoadEvent::StartLoading },
            Instruction::AbsSegment { lsm: target, segment: eeprom },
            Instruction::AbsSegment { lsm: target, segment: ram },
            Instruction::WriteMemory { address: 0x4000, data: vec![0, 0], verify: true },
            Instruction::WriteMemory { address: 0x5000, data: vec![0, 0], verify: true },
        ];
        let mut device = ExtendedRecorder::default();
        Downloader::with_path(&mut device, LoadControlPath::Property, 40)
            .without_authorize()
            .with_memory_service(MemoryService::Extended, 40)
            .with_diffed_writes()
            .run(&instructions, &DeviceImage::new())
            .await
            .expect("volatile and nonvolatile segments download");

        assert_eq!(device.extended_memory_reads, 1, "only EEPROM is read for diffing");
        assert_eq!(device.extended_memory_writes, 1, "equal EEPROM is skipped while RAM is initialized");
        assert_eq!(device.memory.get(&0x5001), Some(&0));
    }
}

// ============================================================================
// Tests: the direct path against a scripted BCU1 memory surface
// ============================================================================

#[cfg(test)]
mod bcu1_tests {
    use super::*;
    use crate::download::mask::MaskDb;
    use crate::download::{GroupLink, ParameterValue, ProductData, ProjectConfig, compile};
    use std::collections::HashMap;
    use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
    use zweidraehte_proto::device::MaskVersion;

    /// A scripted BCU1: nothing but bytes. No properties, no load
    /// state machines — and `A_Authorize` is a hard failure, the way
    /// real silicon that predates the service would at best ignore it.
    struct ScriptedBcu1 {
        memory: HashMap<u16, u8>,
        restarted: bool,
        /// `memory_write` calls — the diff tests count telegrams.
        writes: usize,
    }

    impl ScriptedBcu1 {
        fn new() -> Self {
            Self { memory: HashMap::new(), restarted: false, writes: 0 }
        }
    }

    impl DownloadTarget for ScriptedBcu1 {
        async fn property_read(&mut self, _o: u8, _p: u16, _s: u16, _c: u16) -> Result<Vec<u8>> {
            panic!("a BCU1 has no properties to read");
        }
        async fn property_write(&mut self, _o: u8, _p: u16, _s: u16, _c: u16, _d: &[u8]) -> Result<()> {
            panic!("a BCU1 has no properties to write");
        }
        async fn memory_read(&mut self, address: u16, count: u8) -> Result<Vec<u8>> {
            Ok((0..count).map(|i| *self.memory.get(&(address + u16::from(i))).unwrap_or(&0)).collect())
        }
        async fn memory_write(&mut self, address: u16, data: &[u8]) -> Result<()> {
            self.writes += 1;
            for (i, byte) in data.iter().enumerate() {
                self.memory.insert(address + i as u16, *byte);
            }
            Ok(())
        }
        async fn restart(&mut self) -> Result<()> {
            self.restarted = true;
            Ok(())
        }
        async fn authorize(&mut self, _key: &[u8; 4]) -> Result<u8> {
            panic!("a BCU1 does not speak A_Authorize");
        }
    }

    fn compiled() -> crate::download::CompiledDownload {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0012).expect("mask fixture");
        let mask = db.mask(MaskVersion::Bcu1Tp1).expect("0012");
        let product =
            ProductData::from_mtxml_str(crate::download::product::tests::BCU1_MTXML).expect("product fixture");

        let mut project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        project.links =
            vec![GroupLink { group_address: GroupAddress::from_three_level(2, 0, 3), com_object: 1 }, GroupLink {
                group_address: GroupAddress::from_three_level(0, 0, 1),
                com_object: 0,
            }];
        project.parameters = vec![ParameterValue { id: "M-00FA_A-0310-01-0000_P-1".to_string(), value: vec![0xEE] }];
        compile(&mask, &product, &project).expect("compiles")
    }

    /// The full MV-0012 DefaultProcedure against a plain memory
    /// surface: memory writes only, no `A_Authorize` (the scripted
    /// device panics on it), and the finished EEPROM window carries
    /// the compiled bytes. The BCU1 model diffs its writes, so a byte
    /// the device already holds — this scripted one reads unwritten
    /// memory as 00 — is never written; assertions read through the
    /// same lens the device does.
    #[tokio::test(start_paused = true)]
    async fn full_bcu1_download_is_memory_writes_only() {
        let c = compiled();
        let mut device = ScriptedBcu1::new();
        c.execute(&mut device, 15).await.expect("the scripted download succeeds");
        assert!(device.restarted);

        let at = |device: &ScriptedBcu1, address: u16| device.memory.get(&address).copied().unwrap_or(0);

        // RunError (010Dh): halted at the start, cleared at the end.
        assert_eq!(at(&device, 0x010D), 0xFF);
        // The GA table: muted mid-procedure (0116h ← 01), then the
        // compiled length 3 (IA slot + 2 GAs). The template's write
        // windows deliberately skip 0117h–0118h — the device's own IA
        // is `A_PhysicalAddress_Write` business, never the download's
        // — and the 230-byte window at 0119h starts exactly at the
        // first group address.
        assert_eq!(at(&device, 0x0116), 3);
        assert!(!device.memory.contains_key(&0x0117), "the IA slot is never written by the download");
        assert!(!device.memory.contains_key(&0x0118), "the IA slot is never written by the download");
        for (offset, expected) in [0x00u8, 0x01, 0x10, 0x03].into_iter().enumerate() {
            assert_eq!(at(&device, 0x0119 + offset as u16), expected, "GA byte {offset}");
        }
        // The RAM-flags zeroing wrote nothing: the diff saw zeros
        // already there. (ETS's own trace writes only the two bytes
        // that differed.)
        for address in (0x00CE..0x00CE + 9).chain(0x00D7..0x00D7 + 9) {
            assert_eq!(at(&device, address), 0x00, "RAM flags at {address:#06X}");
            assert!(!device.memory.contains_key(&address), "already-zero RAM flags are not rewritten");
        }
        // The parameter patch reached its EEPROM address.
        assert_eq!(at(&device, 0x0100 + 200), 0xEE);
        // The vendor ramp went out where nothing overrode it (its 00
        // bytes diffed away against the blank device).
        assert_eq!(at(&device, 0x0100), 0x00);
        assert_eq!(at(&device, 0x01FE), 0xFE);
        // The fixup's routine address (U_GetTMx on MV-0012, 0D6Ch)
        // reached the device inside the 0119h window.
        assert_eq!(at(&device, 0x01EF), 0x0D);
        assert_eq!(at(&device, 0x01F0), 0x6C);
    }

    /// The diff economy itself: a device already holding most of a
    /// window gets only the changed runs, with nearby changes
    /// coalesced into one write — the shape of ETS's BCU1 re-download
    /// (BCU1.log writes `$0135 Count=7` for five changed bytes).
    #[tokio::test(start_paused = true)]
    async fn diffed_writes_touch_only_changed_runs() {
        let mut device = ScriptedBcu1::new();
        for i in 0..16u16 {
            device.memory.insert(0x0200 + i, i as u8);
        }

        // Change bytes 4, 6 and 7 (one bridged run) and byte 15.
        let mut data: Vec<u8> = (0..16).collect();
        data[4] = 0xA4;
        data[6] = 0xA6;
        data[7] = 0xA7;
        data[15] = 0xAF;

        let mut downloader = Downloader::with_path(&mut device, LoadControlPath::Direct, 15).with_diffed_writes();
        downloader
            .run(&[Instruction::WriteMemory { address: 0x0200, data: data.clone(), verify: true }], &DeviceImage::new())
            .await
            .expect("runs");

        // Two runs: [4..8) bridged across the unchanged byte 5, and
        // [15..16). Each verified write is one memory_write call.
        assert_eq!(device.writes, 2, "one write per changed run");
        for (i, byte) in data.iter().enumerate() {
            assert_eq!(device.memory[&(0x0200 + i as u16)], *byte, "byte {i}");
        }
    }

    /// `ReadIntoImage` snapshots device bytes into the image's gaps —
    /// and only the gaps: compiled content wins, and the caller's
    /// image is untouched (the engine works on a copy).
    #[tokio::test(start_paused = true)]
    async fn read_into_image_fills_only_the_gaps() {
        let mut device = ScriptedBcu1::new();
        device.memory.insert(0x0200, 0xAB);
        device.memory.insert(0x0201, 0xCD);

        let mut image = DeviceImage::new();
        image.insert(0x0201, vec![0x11]).expect("inserts");

        let mut downloader = Downloader::with_path(&mut device, LoadControlPath::Direct, 15);
        downloader
            .run(
                &[Instruction::ReadIntoImage { address: 0x0200, length: 2 }, Instruction::WriteImage {
                    address: 0x0200,
                    length: 2,
                    verify: true,
                }],
                &image,
            )
            .await
            .expect("runs");

        assert_eq!(device.memory[&0x0200], 0xAB, "the device byte round-tripped through the image");
        assert_eq!(device.memory[&0x0201], 0x11, "the compiled byte won over the device's");
        assert!(image.slice(0x0200, 1).is_none(), "the caller's image is untouched");
    }

    /// LSM instructions on the direct path are a compile bug, not a
    /// silent no-op.
    #[tokio::test(start_paused = true)]
    async fn lsm_instructions_are_rejected_on_the_direct_path() {
        let mut device = ScriptedBcu1::new();
        let mut downloader = Downloader::with_path(&mut device, LoadControlPath::Direct, 15);
        let result = downloader
            .run(&[Instruction::LsmEvent { lsm: 1.into(), event: LoadEvent::Unload }], &DeviceImage::new())
            .await;
        assert!(matches!(result, Err(Error::UnsupportedInstruction(_))));
    }
}

// ============================================================================
// Tests: the property path against a scripted System B device
// ============================================================================

#[cfg(test)]
mod system_b_tests {
    use super::*;
    use crate::download::{GroupLink, mask::MaskDb};
    use crate::download::{ProcedureKind, ProductData, ProjectConfig, assemble, compile};
    use std::collections::HashMap;
    use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
    use zweidraehte_proto::device::MaskVersion;

    /// A mask template in the System B shape: `LdCtrlMerge` splice
    /// points around the relative-allocation and write steps, which is
    /// how the published MV-07B0 Load-all is built.
    const MASK_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="1">
    <MaskVersions>
      <MaskVersion Id="MV-07B0" MaskVersion="1968" Name="System B" ManagementModel="SystemB">
        <HawkConfigurationData>
          <Resources>
            <Resource Name="GroupAddressTableLoadControl" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="1" PropertyID="5" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupAddressTableLoadStatus" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="1" PropertyID="5" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupAssociationTableLoadControl" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="2" PropertyID="5" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupAssociationTableLoadStatus" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="2" PropertyID="5" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupObjectTableLoadControl" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="5" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupObjectTableLoadStatus" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="5" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="ApplicationLoadControl" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="5" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="ApplicationLoadStatus" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="5" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
          </Resources>
          <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
              <LdCtrlConnect />
              <LdCtrlUnload LsmIdx="3" />
              <LdCtrlUnload LsmIdx="2" />
              <LdCtrlUnload LsmIdx="1" />
              <LdCtrlLoad LsmIdx="3" />
              <LdCtrlRelSegment LsmIdx="3" Size="2" Mode="0" Fill="0" />
              <LdCtrlLoad LsmIdx="1" />
              <LdCtrlRelSegment LsmIdx="1" Size="2" Mode="0" Fill="0" />
              <LdCtrlLoad LsmIdx="2" />
              <LdCtrlRelSegment LsmIdx="2" Size="2" Mode="0" Fill="0" />
              <LdCtrlWriteRelMem ObjIdx="3" Offset="0" Size="1048576" Verify="true" />
              <LdCtrlWriteRelMem ObjIdx="2" Offset="0" Size="1048576" Verify="true" />
              <LdCtrlWriteRelMem ObjIdx="1" Offset="0" Size="1048576" Verify="true" />
              <LdCtrlLoadCompleted LsmIdx="3" />
              <LdCtrlLoadCompleted LsmIdx="2" />
              <LdCtrlLoadCompleted LsmIdx="1" />
              <LdCtrlRestart />
            </Procedure>
            <Procedure ProcedureType="Unload" ProcedureSubType="all" Access="remote local2">
              <LdCtrlConnect />
              <LdCtrlUnload LsmIdx="1" />
              <LdCtrlUnload LsmIdx="2" />
              <LdCtrlUnload LsmIdx="3" />
              <LdCtrlUnload LsmIdx="4" />
              <LdCtrlMapError OriginalError="3221498632" MappedError="0" />
              <LdCtrlUnload LsmIdx="5" />
              <LdCtrlMapError OriginalError="3221498632" MappedError="3221498632" />
              <LdCtrlDisconnect />
            </Procedure>
          </Procedures>
        </HawkConfigurationData>
      </MaskVersion>
    </MaskVersions>
  </MasterData>
</KNX>"#;

    /// A System B product: relative segments (no addresses — the
    /// device allocates), `MergedProcedure` style, one group object.
    const PRODUCT_XML: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-0301-02-0000" ApplicationNumber="769" ApplicationVersion="2" ProgramType="ApplicationProgram" MaskVersion="MV-07B0" Name="SystemB Light Switch" LoadProcedureStyle="MergedProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="false" Linkable="false">
      <Static>
        <Code>
          <RelativeSegment Id="M-00FA_A-0301-02-0000_RS-4" Size="4" LoadStateMachine="4" Offset="0"><Data>CQgHBg==</Data></RelativeSegment>
        </Code>
        <Parameters>
          <Parameter Id="M-00FA_A-0301-02-0000_P-1" Name="Mode" ParameterType="M-00FA_A-0301-02-0000_PT-1" Text="Mode" Value="0">
            <Memory CodeSegment="M-00FA_A-0301-02-0000_RS-4" Offset="1" BitOffset="0" />
          </Parameter>
        </Parameters>
        <ComObjectTable>
          <ComObject Id="M-00FA_A-0301-02-0000_O-1" Name="Switch" Text="Switch" Number="1" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Enabled" ReadOnInitFlag="Disabled" />
        </ComObjectTable>
        <AddressTable MaxEntries="254" />
        <AssociationTable MaxEntries="254" />
        <LoadProcedures />
      </Static>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    #[test]
    fn system_b_compiler_accepts_tp_rf_and_ip_masks() {
        let project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        for (code, decimal) in [(0x07B0, 1968), (0x27B0, 10160), (0x57B0, 22448)] {
            let mask_xml = MASK_XML
                .replace("MV-07B0", &format!("MV-{code:04X}"))
                .replace("MaskVersion=\"1968\"", &format!("MaskVersion=\"{decimal}\""));
            let product_xml = PRODUCT_XML.replace("MV-07B0", &format!("MV-{code:04X}"));
            let db = MaskDb::from_str(&mask_xml).expect("derived System B fixture parses");
            let mask = db.mask(MaskVersion::from(code)).expect("derived mask is present");
            let product = ProductData::from_mtxml_str(&product_xml).expect("derived product parses");
            let compiled = compile(&mask, &product, &project).expect("System B product compiles");
            assert_eq!(compiled.path(), LoadControlPath::Property, "mask {code:04X}");
            assert!(compiled.image.relative(1).is_some(), "mask {code:04X} has an address table");
            assert_eq!(compiled.instructions.last(), Some(&Instruction::ConfirmedRestart), "mask {code:04X}");
        }
    }

    /// A scripted System B device: load state and table reference per
    /// interface object, plus plain memory.
    struct ScriptedSystemB {
        memory: HashMap<u16, u8>,
        /// Load state per interface object index.
        states: HashMap<u8, LoadState>,
        /// The base this device hands out for the next allocation.
        next_base: u32,
        /// Allocated base per interface object.
        bases: HashMap<u8, u32>,
        restarted: bool,
        confirmed_restarted: bool,
        /// Interface objects this device does *not* have — property
        /// access to them fails, the way a real device without the
        /// optional fifth machine refuses `LdCtrlUnload LsmIdx="5"`.
        absent_objects: Vec<u8>,
    }

    impl ScriptedSystemB {
        fn new() -> Self {
            Self {
                memory: HashMap::new(),
                states: HashMap::new(),
                next_base: 0x4000,
                bases: HashMap::new(),
                restarted: false,
                confirmed_restarted: false,
                absent_objects: Vec::new(),
            }
        }

        fn state(&self, obj: u8) -> LoadState {
            self.states.get(&obj).copied().unwrap_or(LoadState::Unloaded)
        }
    }

    impl DownloadTarget for ScriptedSystemB {
        async fn property_read(&mut self, obj_idx: u8, prop_id: u16, _s: u16, _c: u16) -> Result<Vec<u8>> {
            if self.absent_objects.contains(&obj_idx) {
                return Err(Error::DeviceError(0));
            }
            match prop_id {
                pid::LOAD_STATE_CONTROL => Ok(vec![self.state(obj_idx).into()]),
                pid::TABLE_REFERENCE => {
                    let base = self.bases.get(&obj_idx).copied().unwrap_or(0);
                    Ok(base.to_be_bytes().to_vec())
                }
                _ => Err(Error::DeviceError(0)),
            }
        }

        async fn property_write(&mut self, obj_idx: u8, prop_id: u16, _s: u16, _c: u16, data: &[u8]) -> Result<()> {
            if self.absent_objects.contains(&obj_idx) {
                return Err(Error::DeviceError(0));
            }
            if prop_id != pid::LOAD_STATE_CONTROL {
                return Err(Error::DeviceError(0));
            }
            let event = LoadEvent::from(data[0]);
            let state = self.state(obj_idx);
            let next = match (event, state) {
                (LoadEvent::StartLoading, _) => LoadState::Loading,
                (LoadEvent::LoadCompleted, LoadState::Loading) => LoadState::Loaded,
                (LoadEvent::Unload, _) => LoadState::Unloaded,
                (LoadEvent::AdditionalLoadControls, LoadState::Loading) => {
                    // A relative allocation: hand out a base and
                    // remember it, the way a real device does.
                    let size = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                    self.bases.insert(obj_idx, self.next_base);
                    self.next_base += size.max(1);
                    LoadState::Loading
                }
                _ => LoadState::Err,
            };
            self.states.insert(obj_idx, next);
            Ok(())
        }

        async fn memory_read(&mut self, address: u16, count: u8) -> Result<Vec<u8>> {
            Ok((0..count).map(|i| *self.memory.get(&(address + u16::from(i))).unwrap_or(&0)).collect())
        }

        async fn memory_write(&mut self, address: u16, data: &[u8]) -> Result<()> {
            for (i, byte) in data.iter().enumerate() {
                self.memory.insert(address + i as u16, *byte);
            }
            Ok(())
        }

        async fn restart(&mut self) -> Result<()> {
            self.restarted = true;
            Ok(())
        }

        async fn confirmed_restart(&mut self) -> Result<Duration> {
            self.confirmed_restarted = true;
            Ok(Duration::from_secs(1))
        }
    }

    fn compiled() -> crate::download::CompiledDownload {
        let db = MaskDb::from_str(MASK_XML).expect("mask fixture");
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let product = ProductData::from_mtxml_str(PRODUCT_XML).expect("product fixture");

        let mut project = ProjectConfig::new(IndividualAddress::new(1, 1, 5));
        project.links =
            vec![GroupLink { group_address: GroupAddress::from_three_level(2, 0, 1), com_object: 1 }, GroupLink {
                group_address: GroupAddress::from_three_level(1, 0, 1),
                com_object: 1,
            }];
        project.max_apdu = 254;

        compile(&mask, &product, &project).expect("the three layers compile")
    }

    #[test]
    fn compiles_relative_content_per_interface_object() {
        let c = compiled();

        // Address table (object 1): 16-bit count, sorted, no IA slot.
        assert_eq!(c.image.relative(1).expect("ADT"), &[0x00, 0x02, 0x08, 0x01, 0x10, 0x01]);
        // Association table (object 2): 16-bit TSAP/ASAP pairs.
        assert_eq!(c.image.relative(2).expect("AST"), &[0x00, 0x02, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01]);
        // Group object table (object 3): 1-based descriptors.
        assert_eq!(c.image.relative(3).expect("COT"), &[0x00, 0x01, 0b1001_0100 | 0b11, 0x00]);
        // Application parameters (object 4): the product's defaults.
        assert_eq!(c.image.relative(4).expect("params"), &[0x09, 0x08, 0x07, 0x06]);

        // Nothing absolute: System B has no fixed addresses.
        assert_eq!(c.image.regions().count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn full_system_b_download_over_the_property_path() {
        let c = compiled();
        let mut device = ScriptedSystemB::new();
        let started = tokio::time::Instant::now();
        let outcome =
            c.execute_with_progress_outcome(&mut device, 254, Box::new(|_| {})).await.expect("the download succeeds");

        // All three table machines ended Loaded, driven entirely
        // through pid::LOAD_STATE_CONTROL.
        for obj in [1u8, 2, 3] {
            assert_eq!(device.state(obj), LoadState::Loaded, "object {obj}");
        }
        assert!(!device.restarted, "System B must not use the legacy basic restart");
        assert!(device.confirmed_restarted);
        assert_eq!(outcome.confirmed_restart_process_time(), Some(Duration::from_secs(1)));
        assert_eq!(
            tokio::time::Instant::now(),
            started,
            "the connection owner, not the interpreter, waits for restart"
        );

        // Each table landed at the base the device allocated, not at
        // any address the client chose.
        let adt_base = device.bases[&1] as u16;
        let adt: Vec<u8> = (0..6).map(|i| device.memory[&(adt_base + i)]).collect();
        assert_eq!(adt, [0x00, 0x02, 0x08, 0x01, 0x10, 0x01]);

        let cot_base = device.bases[&3] as u16;
        let cot: Vec<u8> = (0..4).map(|i| device.memory[&(cot_base + i)]).collect();
        assert_eq!(cot, [0x00, 0x01, 0b1001_0100 | 0b11, 0x00]);

        // The three allocations got distinct bases.
        assert_ne!(device.bases[&1], device.bases[&2]);
        assert_ne!(device.bases[&2], device.bases[&3]);
    }

    #[tokio::test]
    async fn relative_write_preserves_device_owned_gaps() {
        let mut image = DeviceImage::new();
        image
            .insert_sparse_relative(4, vec![0, 1, 2, 3, 4, 5, 6], vec![false, true, true, false, true, false, true])
            .expect("matching ownership mask");
        let mut device = ScriptedSystemB::new();
        device.bases.insert(4, 0x4000);
        let instruction = Instruction::WriteRelImage { obj_idx: 4, offset: 0, length: 7, verify: true };

        Downloader::with_path(&mut device, LoadControlPath::Property, 254)
            .run(&[instruction], &image)
            .await
            .expect("sparse relative write succeeds");

        assert_eq!(device.memory.get(&0x4001), Some(&1));
        assert_eq!(device.memory.get(&0x4002), Some(&2));
        assert_eq!(device.memory.get(&0x4004), Some(&4));
        assert_eq!(device.memory.get(&0x4006), Some(&6));
        assert!(!device.memory.contains_key(&0x4000));
        assert!(!device.memory.contains_key(&0x4003));
        assert!(!device.memory.contains_key(&0x4005));
    }

    #[tokio::test(start_paused = true)]
    async fn relative_allocation_needs_the_property_path() {
        // Driving a relative allocation down the memory-mapped path is
        // a category error: the device picks the address there.
        let db = MaskDb::from_str(MASK_XML).expect("mask fixture");
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let product = ProductData::from_mtxml_str(PRODUCT_XML).expect("product fixture");
        let instructions = assemble(&mask, &product, ProcedureKind::LoadAll).expect("assembles");
        let rel = instructions
            .iter()
            .find(|i| matches!(i, Instruction::RelSegment { .. }))
            .expect("the System B template allocates relatively")
            .clone();

        let mut device = ScriptedSystemB::new();
        let resources = MemoryResources {
            programming_mode_addr: 0x0060,
            load_control_addr: 0x0104,
            load_status_addr: 0xB6EA,
            address_table_addr: 0x4000,
        };
        let mut downloader = Downloader::new(&mut device, resources, 254);
        let result = downloader.run(&[rel], &DeviceImage::new()).await;
        assert!(matches!(result, Err(Error::UnsupportedInstruction(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn load_image_property_picks_up_an_existing_allocation() {
        // A partial download rewrites tables in place: the base comes
        // from pid::TABLE_REFERENCE rather than a fresh allocation.
        let c = compiled();
        let mut device = ScriptedSystemB::new();
        device.bases.insert(1, 0x7000);
        device.states.insert(1, LoadState::Loading);

        let mut downloader = Downloader::with_path(&mut device, LoadControlPath::Property, 254);
        downloader
            .run(
                &[
                    Instruction::LoadImageProperty {
                        obj_idx: 1,
                        prop_id: pid::TABLE_REFERENCE,
                        start_idx: 1,
                        count: 1,
                    },
                    Instruction::WriteRelImage { obj_idx: 1, offset: 0, length: 1_048_576, verify: true },
                ],
                &c.image,
            )
            .await
            .expect("writes to the pre-existing allocation");

        assert_eq!(device.memory[&0x7000], 0x00, "wrote at the base the device already had");
        assert_eq!(device.memory[&0x7002], 0x08);
    }

    #[tokio::test]
    async fn loaded_property_replaces_the_partial_procedures_compare_placeholder() {
        // System B Load/par snapshots PID 7 before unloading the application
        // machine and later compares PID 7 against that snapshot. The zeroes
        // in master data are the tool-side buffer's initial value, not a
        // requirement that a real allocation live at address zero.
        let mut device = ScriptedSystemB::new();
        device.bases.insert(4, 0x7000);
        let instructions = [
            Instruction::LoadImageProperty { obj_idx: 4, prop_id: pid::TABLE_REFERENCE, start_idx: 1, count: 1 },
            Instruction::CompareProperty { obj_idx: 4, prop_id: pid::TABLE_REFERENCE, expected: vec![0, 0, 0, 0] },
        ];

        Downloader::with_path(&mut device, LoadControlPath::Property, 254)
            .run(&instructions, &DeviceImage::new())
            .await
            .expect("the live table reference matches its loaded snapshot");
    }

    #[test]
    fn a_product_without_group_objects_still_loads_an_empty_rt7_table() {
        // System B: the group object table machine loads either way,
        // so no objects means a zero-count table, not a missing one.
        let db = MaskDb::from_str(MASK_XML).expect("mask fixture");
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let xml = PRODUCT_XML.replace(
            r#"<ComObjectTable>
          <ComObject Id="M-00FA_A-0301-02-0000_O-1" Name="Switch" Text="Switch" Number="1" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Enabled" ReadOnInitFlag="Disabled" />
        </ComObjectTable>"#,
            "<ComObjectTable />",
        );
        let product = ProductData::from_mtxml_str(&xml).expect("product parses");
        let mut project = ProjectConfig::new(zweidraehte_proto::address::IndividualAddress::new(1, 1, 5));
        project.links = vec![GroupLink { group_address: GroupAddress::from_three_level(2, 0, 1), com_object: 1 }];
        let c = crate::download::compile(&mask, &product, &project).expect("compiles");
        assert_eq!(c.image.relative(3), Some(&[0x00, 0x00][..]), "a zero-count RT7 table");
    }

    #[test]
    fn system_b_now_honors_the_products_capacity_declarations() {
        // The capacity checks used to run only on the System 7 path.
        let db = MaskDb::from_str(MASK_XML).expect("mask fixture");
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let xml = PRODUCT_XML.replace(r#"<AddressTable MaxEntries="254" />"#, r#"<AddressTable MaxEntries="1" />"#);
        let product = ProductData::from_mtxml_str(&xml).expect("product parses");
        let mut project = ProjectConfig::new(zweidraehte_proto::address::IndividualAddress::new(1, 1, 5));
        project.links =
            vec![GroupLink { group_address: GroupAddress::from_three_level(2, 0, 1), com_object: 1 }, GroupLink {
                group_address: GroupAddress::from_three_level(2, 0, 2),
                com_object: 1,
            }];
        let result = crate::download::compile(&mask, &product, &project);
        assert!(matches!(result, Err(Error::DownloadConfig(_))));
    }

    /// Task records (TaskSegment and the BCU2 TaskPtr/TaskCtrl
    /// family) are informational: they are written and *not* followed
    /// by a state poll. The recorder errors on every property read, so
    /// any poll would abort the run — and the L&J BCU2 procedure even
    /// sends a TaskSegment for machine 5 without ever starting it.
    #[tokio::test(start_paused = true)]
    async fn task_records_are_sent_without_state_polls() {
        struct Recorder {
            writes: Vec<(u8, Vec<u8>)>,
        }
        impl DownloadTarget for Recorder {
            async fn property_read(&mut self, _o: u8, _p: u16, _s: u16, _c: u16) -> Result<Vec<u8>> {
                Err(Error::DeviceError(0))
            }
            async fn property_write(&mut self, obj_idx: u8, _p: u16, _s: u16, _c: u16, data: &[u8]) -> Result<()> {
                self.writes.push((obj_idx, data.to_vec()));
                Ok(())
            }
            async fn memory_read(&mut self, _a: u16, _c: u8) -> Result<Vec<u8>> {
                Err(Error::DeviceError(0))
            }
            async fn memory_write(&mut self, _a: u16, _d: &[u8]) -> Result<()> {
                Err(Error::DeviceError(0))
            }
            async fn restart(&mut self) -> Result<()> {
                Ok(())
            }
        }

        let mut device = Recorder { writes: Vec::new() };
        let mut downloader = Downloader::with_path(&mut device, LoadControlPath::Property, 254);
        downloader
            .run(
                &[
                    Instruction::TaskSegment {
                        lsm: 5.into(),
                        address: 0x011E,
                        pei_type: 17,
                        application_id: [0x00, 0xE1, 0xE0, 0x24, 0x30],
                    },
                    Instruction::TaskPointers { lsm: 3.into(), init_ptr: 284, save_ptr: 285, serial_ptr: 0 },
                    Instruction::TaskControl1 { lsm: 3.into(), address: 0, count: 0 },
                    Instruction::TaskControl2 { lsm: 3.into(), callback: 20609, address: 282, seg0: 208, seg1: 208 },
                ],
                &DeviceImage::new(),
            )
            .await
            .expect("informational records need no state to be right");

        // Each record went to its machine's object, tagged with its
        // §3.31.2 segment type.
        let types: Vec<(u8, u8)> = device.writes.iter().map(|(obj, data)| (*obj, data[1])).collect();
        assert_eq!(types, vec![(5, 0x02), (3, 0x03), (3, 0x04), (3, 0x05)]);
    }

    #[tokio::test(start_paused = true)]
    async fn map_error_window_tolerates_the_guarded_step_only() {
        // The published MV-07B0 Unload-all wraps `LdCtrlUnload
        // LsmIdx="5"` in a MapError window, because not every 07B0
        // device has a fifth machine. The fixture's Unload procedure
        // is that template verbatim; the scripted device is one of the
        // devices without object 5.
        let db = MaskDb::from_str(MASK_XML).expect("mask fixture");
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let unload = assemble(&mask, &ProductData::default(), ProcedureKind::UnloadAll)
            .expect("the MapError guards convert instead of failing assembly");

        let mut device = ScriptedSystemB::new();
        device.absent_objects = vec![5];
        for obj in 1..=4u8 {
            device.states.insert(obj, LoadState::Loaded);
        }

        let mut downloader = Downloader::with_path(&mut device, LoadControlPath::Property, 254);
        downloader.run(&unload, &DeviceImage::new()).await.expect("the guarded LSM-5 failure is tolerated");
        for obj in 1..=4u8 {
            assert_eq!(device.state(obj), LoadState::Unloaded, "machine {obj} unloaded");
        }

        // The window is scoped: the identity mapping after the guarded
        // step restores normal failure handling, so the same failing
        // step outside the window aborts the run.
        let unguarded = [Instruction::LsmEvent { lsm: 5.into(), event: LoadEvent::Unload }];
        let mut downloader = Downloader::with_path(&mut device, LoadControlPath::Property, 254);
        downloader
            .run(&unguarded, &DeviceImage::new())
            .await
            .expect_err("outside a MapError window the failure aborts");
    }
}
