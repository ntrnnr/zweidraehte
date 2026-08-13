//! The download interpreter: executes [`Instruction`] streams against
//! a device.
//!
//! The engine drives both load-control paths behind one
//! [`LoadControlPath`] switch: the *memory-mapped* one
//! (`DM_LoadStateMachineWrite_RCo_Mem`, 03/05/02 §3.31.2) that the
//! System 7 / BIM M112 masks use — records written to the window at
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
    LoadControlRecord, LoadEvent, LoadState, LsmMachine, MemLoadControlRecord,
};

use super::image::DeviceImage;
use super::ir::{Instruction, LsmIndex};
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
    async fn memory_read(&mut self, address: u16, count: u8) -> Result<Vec<u8>>;
    async fn memory_write(&mut self, address: u16, data: &[u8]) -> Result<()>;
    async fn restart(&mut self) -> Result<()>;
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

    async fn memory_read(&mut self, address: u16, count: u8) -> Result<Vec<u8>> {
        DeviceConnection::memory_read(self, address, count).await
    }

    async fn memory_write(&mut self, address: u16, data: &[u8]) -> Result<()> {
        DeviceConnection::memory_write(self, address, data).await
    }

    async fn authorize(&mut self, key: &[u8; 4]) -> Result<u8> {
        DeviceConnection::authorize(self, key).await
    }

    async fn restart(&mut self) -> Result<()> {
        DeviceConnection::restart(self).await
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

/// How a mask drives its load state machines.
///
/// The two paths carry identical record payloads; they differ only in
/// where the record is written and where the resulting state is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadControlPath {
    /// System 7 / BIM M112: records go to the memory-mapped window,
    /// state comes from the per-machine status bytes
    /// (`DM_LoadStateMachineWrite_RCo_Mem`, 03/05/02 §3.31.2).
    Memory(MemoryResources),
    /// System B: records go to `PID_LOAD_STATE_CONTROL` on the
    /// interface object whose index *is* the machine index, and the
    /// same property reads the state back
    /// (`DM_LoadStateMachineWrite_RCo_IO`).
    Property,
}

/// Executes download procedures against one device.
pub struct Downloader<'a, T> {
    target: &'a mut T,
    path: LoadControlPath,
    /// `A_Memory_Write` data bytes per chunk: the APCI/count octet and
    /// the two address octets share the APDU with the data, and the
    /// count field itself is 6 bits.
    chunk: usize,
    /// The `A_Authorize` key sent at the procedure's Connect step. ETS
    /// authorizes every configuration connection; the default is the
    /// free-access key.
    key: [u8; 4],
    /// Progress reporting, when a UI wants it.
    progress: Option<ProgressSink>,
    /// Base addresses the device reported for relative segments, by
    /// interface object index. Filled by `RelSegment` allocation and
    /// by `LoadImageProperty` on `PID_TABLE_REFERENCE`; consumed by
    /// `WriteRelImage`.
    bases: BTreeMap<LsmIndex, u32>,
    /// Error codes currently mapped to "success" by `MapError`
    /// (`mapped == 0` inserts, `mapped == original` removes). While
    /// non-empty, a failing instruction is tolerated instead of
    /// aborting the run — see [`Instruction::MapError`] for why the
    /// numeric code itself cannot be matched.
    tolerated_errors: BTreeSet<u32>,
}

impl<'a, T: DownloadTarget> Downloader<'a, T> {
    /// A downloader driving the memory-mapped path (System 7).
    ///
    /// `max_apdu` is the smaller of the device's and the bus
    /// interface's APDU capability (15 for a plain System 7 target on
    /// standard frames → 12-byte chunks).
    pub fn new(target: &'a mut T, resources: MemoryResources, max_apdu: u16) -> Self {
        Self::with_path(target, LoadControlPath::Memory(resources), max_apdu)
    }

    /// A downloader on an explicit load-control path.
    pub fn with_path(target: &'a mut T, path: LoadControlPath, max_apdu: u16) -> Self {
        let chunk = usize::from(max_apdu.saturating_sub(3)).clamp(1, 63);
        Self {
            target,
            path,
            chunk,
            key: [0xFF; 4],
            progress: None,
            bases: BTreeMap::new(),
            tolerated_errors: BTreeSet::new(),
        }
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
        let total = instructions.len();
        for (index, instruction) in instructions.iter().enumerate() {
            log::debug!("download step: {instruction:?}");
            self.emit(DownloadEvent::Step { index, total, description: instruction.describe() });
            match self.execute(instruction, image).await {
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
        Ok(())
    }

    async fn execute(&mut self, instruction: &Instruction, image: &DeviceImage) -> Result<()> {
        match instruction {
            // The engine runs inside an open transport connection, so
            // the transport half of Connect is a marker — but ETS's
            // DMP_Connect_RCo pairs it with an A_Authorize, and real
            // silicon gates system-memory writes (the load-control
            // window included) behind the access level that grants:
            // an unauthorized write is T_ACKed and silently ignored,
            // leaving the machine's state unchanged. Our own devices
            // grant free access at the default level, which is why
            // the software DUTs never needed this.
            Instruction::Connect => {
                let level = self.target.authorize(&self.key).await?;
                log::debug!("authorized at access level {level}");
                Ok(())
            }
            Instruction::Disconnect => Ok(()),

            Instruction::CompareProperty { obj_idx, prop_id, expected } => {
                let value = self.target.property_read(*obj_idx, *prop_id, 1, 1).await?;
                if !identity_matches(&value, expected) {
                    return Err(Error::IdentityMismatch { obj_idx: *obj_idx, prop_id: *prop_id });
                }
                Ok(())
            }

            Instruction::LsmEvent { lsm, event } => {
                self.write_load_control(*lsm, &LoadControlRecord::event(*event), MemLoadControlRecord::event).await?;
                // Each event has exactly one legal outcome state; §4.23's
                // other transitions (e.g. LoadCompleted while Unloaded)
                // land in Error, which the poll surfaces.
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
                self.expect_load_state(*lsm, LoadState::Loading).await
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
                self.target.property_write(*lsm, pid::LOAD_STATE_CONTROL, 1, 1, &record).await?;
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
                // by a Falcon download trace (2026-08-13).
                let property = LoadControlRecord::task_segment(*address, *pei_type, *application_id);
                self.write_load_control_with(*lsm, &property, |m, _e| {
                    MemLoadControlRecord::task_segment(m, *address, *pei_type, *application_id)
                })
                .await?;
                self.expect_load_state(*lsm, LoadState::Loading).await
            }

            Instruction::WriteRelImage { obj_idx, offset, verify } => {
                let base = match self.bases.get(obj_idx) {
                    Some(base) => *base,
                    // No allocation seen in this run — the tables are
                    // being rewritten in place, so ask the device.
                    None => {
                        let base = self.read_table_reference(*obj_idx).await?;
                        self.bases.insert(*obj_idx, base);
                        base
                    }
                };
                let bytes = image
                    .relative(*obj_idx)
                    .ok_or(Error::DownloadConfig("the procedure writes an object the image has no content for"))?;
                // The base is device-reported; a garbage value must not
                // wrap into a plausible address.
                let address = base
                    .checked_add(*offset)
                    .and_then(|a| u16::try_from(a).ok())
                    .ok_or(Error::Parse("allocated base + offset is beyond the 16-bit address space"))?;
                if *verify {
                    self.write_verified(address, bytes).await
                } else {
                    self.write_chunked(address, bytes).await
                }
            }

            Instruction::LoadImageProperty { obj_idx, prop_id } => {
                let value = self.target.property_read(*obj_idx, *prop_id, 1, 1).await?;
                // The one property whose image we act on: an existing
                // allocation's base. Anything else is read and
                // discarded — ETS caches it for comparisons we do not
                // make.
                if *prop_id == pid::TABLE_REFERENCE {
                    self.bases.insert(*obj_idx, be_u32(&value));
                }
                Ok(())
            }

            Instruction::WriteImage { address, length } => {
                let bytes = image
                    .slice(*address, *length)
                    .ok_or(Error::DownloadConfig("procedure writes an address the image does not cover"))?;
                self.write_verified(*address, bytes).await
            }

            Instruction::WriteMemory { address, data, verify } => {
                if *verify {
                    self.write_verified(*address, data).await
                } else {
                    self.write_chunked(*address, data).await
                }
            }

            Instruction::CompareMemory { address, expected } => {
                let mut read = Vec::with_capacity(expected.len());
                for chunk_start in (0..expected.len()).step_by(self.chunk) {
                    let len = self.chunk.min(expected.len() - chunk_start);
                    read.extend(self.target.memory_read(*address + chunk_start as u16, len as u8).await?);
                }
                if read != *expected {
                    return Err(Error::CompareMismatch { address: *address });
                }
                Ok(())
            }

            Instruction::WriteProperty { obj_idx, prop_id, data, verify } => {
                self.target.property_write(*obj_idx, *prop_id, 1, 1, data).await?;
                if *verify {
                    let value = self.target.property_read(*obj_idx, *prop_id, 1, 1).await?;
                    if value != *data {
                        return Err(Error::PropertyVerifyMismatch { obj_idx: *obj_idx, prop_id: *prop_id });
                    }
                }
                Ok(())
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
        lsm: LsmIndex,
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
        lsm: LsmIndex,
        property_record: &[u8],
        memory_record: impl Fn(LsmMachine, LoadEvent) -> [u8; N],
    ) -> Result<()> {
        match self.path {
            LoadControlPath::Property => {
                self.target.property_write(lsm, pid::LOAD_STATE_CONTROL, 1, 1, property_record).await
            }
            LoadControlPath::Memory(resources) => {
                let machine = memory_machine(lsm)?;
                let event = LoadEvent::from(property_record[0]);
                let record = memory_record(machine, event);
                self.target.memory_write(resources.load_control_addr, &record).await
            }
        }
    }

    /// Read `PID_TABLE_REFERENCE` — the base address the device
    /// allocated for an object's relative segment.
    async fn read_table_reference(&mut self, obj_idx: u8) -> Result<u32> {
        let value = self.target.property_read(obj_idx, pid::TABLE_REFERENCE, 1, 1).await?;
        if value.is_empty() {
            return Err(Error::Parse("empty pid::TABLE_REFERENCE response"));
        }
        Ok(be_u32(&value))
    }

    // ========================================================================
    // Primitives
    // ========================================================================

    /// Chunked `DMP_MemWrite_RCo` (no read-back).
    async fn write_chunked(&mut self, address: u16, data: &[u8]) -> Result<()> {
        for start in (0..data.len()).step_by(self.chunk) {
            let end = (start + self.chunk).min(data.len());
            self.target.memory_write(address + start as u16, &data[start..end]).await?;
            self.emit(DownloadEvent::Data { done: end, total: data.len() });
        }
        Ok(())
    }

    /// Chunked `DMP_MemWrite_RCoV` (03/05/02 §3.16.3): every chunk is
    /// read back and compared before the next goes out, so a failure
    /// names the first bad address instead of a garbled table.
    async fn write_verified(&mut self, address: u16, data: &[u8]) -> Result<()> {
        for start in (0..data.len()).step_by(self.chunk) {
            let end = (start + self.chunk).min(data.len());
            let chunk_addr = address + start as u16;
            let chunk = &data[start..end];
            self.target.memory_write(chunk_addr, chunk).await?;
            let read_back = self.target.memory_read(chunk_addr, chunk.len() as u8).await?;
            if read_back != chunk {
                return Err(Error::VerifyMismatch { address: chunk_addr });
            }
            self.emit(DownloadEvent::Data { done: end, total: data.len() });
        }
        Ok(())
    }

    /// Poll a machine's load state until it reads `expected`.
    async fn expect_load_state(&mut self, lsm: LsmIndex, expected: LoadState) -> Result<()> {
        // Resolve the machine's identity in the terms of the path
        // driving it — which is also exactly what a failure should
        // name, so the diagnostic never has to hedge between the
        // families' readings of the same index.
        let machine = match self.path {
            LoadControlPath::Memory(_) => MachineRef::Machine(memory_machine(lsm)?),
            LoadControlPath::Property => MachineRef::Object(lsm),
        };

        let mut state = LoadState::Err;
        for attempt in 0..STATE_POLL_ATTEMPTS {
            let raw = match (self.path, machine) {
                (LoadControlPath::Memory(resources), MachineRef::Machine(m)) => {
                    self.target.memory_read(resources.load_status_of(m), 1).await?
                }
                _ => self.target.property_read(lsm, pid::LOAD_STATE_CONTROL, 1, 1).await?,
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
fn memory_machine(lsm: LsmIndex) -> Result<LsmMachine> {
    LsmMachine::try_from(lsm).map_err(|_| {
        Error::UnsupportedInstruction("load state machine index outside 1-4 has no memory-mapped load-control record")
    })
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

    /// Mask resources come from the master data even in unit tests —
    /// there is no constant to reach for.
    fn resources() -> MemoryResources {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture parses");
        db.mask(MaskVersion::System7Tp1).expect("0705").memory_resources().expect("0705 is memory-mapped")
    }
    use std::collections::HashMap;
    use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

    /// A scripted mask-0705 memory surface: plain byte memory plus
    /// the load-control window / status bytes, transitioning like the
    /// real `System7MemoryMap` (which the conformance tier then
    /// exercises for real).
    struct ScriptedDevice {
        memory: HashMap<u16, u8>,
        /// ADT, AST, APP, PEI load states.
        states: [LoadState; 4],
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

        // The ADT blob landed byte-exactly: count 1, IA 1.1.42, GA 2/0/3.
        for (offset, expected) in [1u8, 0x11, 0x2A, 0x10, 0x03].into_iter().enumerate() {
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
            .run(&[Instruction::LsmEvent { lsm: 1, event: LoadEvent::LoadCompleted }], &DeviceImage::new())
            .await;
        assert!(matches!(
            result,
            Err(Error::LoadState { machine: MachineRef::Machine(LsmMachine::AddressTable), state: LoadState::Err, .. })
        ));
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
        assert_eq!(c.image.relative(2).expect("AST"), &[0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01]);
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
        c.execute(&mut device, 254).await.expect("the download succeeds");

        // All three table machines ended Loaded, driven entirely
        // through pid::LOAD_STATE_CONTROL.
        for obj in [1u8, 2, 3] {
            assert_eq!(device.state(obj), LoadState::Loaded, "object {obj}");
        }
        assert!(device.restarted);

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
                    Instruction::LoadImageProperty { obj_idx: 1, prop_id: pid::TABLE_REFERENCE },
                    Instruction::WriteRelImage { obj_idx: 1, offset: 0, verify: true },
                ],
                &c.image,
            )
            .await
            .expect("writes to the pre-existing allocation");

        assert_eq!(device.memory[&0x7000], 0x00, "wrote at the base the device already had");
        assert_eq!(device.memory[&0x7002], 0x08);
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
        let unguarded = [Instruction::LsmEvent { lsm: 5, event: LoadEvent::Unload }];
        let mut downloader = Downloader::with_path(&mut device, LoadControlPath::Property, 254);
        downloader
            .run(&unguarded, &DeviceImage::new())
            .await
            .expect_err("outside a MapError window the failure aborts");
    }
}
