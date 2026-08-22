//! The project layer: what *this installation* wants of a device, and
//! the compile step that turns all three layers into a runnable
//! download.
//!
//! [`ProjectConfig`] is the only layer a caller authors by hand — the
//! individual address, which group addresses reach which group
//! objects, and any parameter values that differ from the product's
//! defaults. Everything structural comes from the product file and the
//! master data.
//!
//! [`compile`] follows ETS's own order:
//!
//! 1. **Seed** each segment buffer with the product's default `Data`.
//! 2. **Overlay** the tables generated from the project: the System 7
//!    address table (with the device's IA in its own slot), the
//!    association table, and the group object table built from the
//!    product's object definitions.
//! 3. **Patch** parameter values at their declared offsets.
//! 4. **Assemble** the procedure from mask + product, then insert the
//!    data writes ETS performs implicitly — derived from the
//!    procedure's own segment declarations, not from a hand-written
//!    layout.

use std::collections::BTreeMap;

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};
use zweidraehte_proto::messages::apdu::load_control::LoadEvent;
use zweidraehte_proto::pid;
use zweidraehte_proto::security::{SEQ6_MAX, u64_to_seq6};

use zweidraehte_knxprod::schema::LoadControl;

use super::assemble::{ProcedureKind, assemble_controls};
use super::image::DeviceImage;
use super::interpreter::{DownloadTarget, Downloader, LoadControlPath, MemoryService};
use super::ir::{Instruction, LsmTarget, controls_to_instructions};
use super::mask::{LsmModel, MachineRole, MaskData};
use super::model::{DownloadModel, ImageLayout, Placement};
use super::product::{ParameterLocation, ProductData};
use crate::error::{Error, Result};

/// A group address ↔ group object link (one association).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupLink {
    pub group_address: GroupAddress,
    /// The group object number (ASAP) as the product database numbers
    /// it.
    pub com_object: u8,
}

/// A parameter value that differs from the product default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterValue {
    /// The parameter's MTXML id, matching
    /// [`ParameterLocation::id`](super::product::ParameterLocation::id).
    pub id: String,
    /// Raw bytes in device-memory order: ETS stores multi-byte
    /// parameters big-endian. A bit-packed parameter travels as the
    /// big-endian encoding of its (at most 64-bit) value.
    pub value: Vec<u8>,
}

/// Installation-specific KNX Data Secure tables.
///
/// Group-key addresses are resolved to the exact sorted address-table indices
/// produced for this download; SIAT rows and GO flags are positional on the
/// device, so the compiler sorts and validates them before emitting writes.
#[derive(Debug, Clone, Default)]
pub struct SecurityConfig {
    pub group_keys: Vec<(GroupAddress, [u8; 16])>,
    pub siat: Vec<(IndividualAddress, u64)>,
    /// One flag octet per zero-based group-object slot: 00 plain, 01
    /// authentication only, 03 authentication plus confidentiality.
    pub go_flags: Vec<u8>,
}

/// What this installation wants of one device.
#[derive(Debug, Clone)]
pub struct ProjectConfig {
    /// The project-assigned individual address. On System 7 it lives
    /// inside the address table blob (offset 1–2), the one place such
    /// a device stores its own address.
    pub individual_address: IndividualAddress,
    /// Group links; the distinct group addresses become the address
    /// table, the links themselves the association table.
    pub links: Vec<GroupLink>,
    /// Parameter values overriding the product defaults.
    pub parameters: Vec<ParameterValue>,
    /// Security tables to commission for a secure product.
    pub security: Option<SecurityConfig>,
    /// The *device's* maximum APDU length, bounding `A_Memory_Write`
    /// chunks. 15 (the TP1 standard frame) is right for every System 7
    /// device; raise it only for targets known to accept extended
    /// frames.
    pub max_apdu: u16,
}

impl ProjectConfig {
    pub fn new(individual_address: IndividualAddress) -> Self {
        Self { individual_address, links: Vec::new(), parameters: Vec::new(), security: None, max_apdu: 15 }
    }
}

/// A download ready to execute: the image, the procedure, and the
/// load-control path they were compiled for.
///
/// The path is decided once, here, from the mask — so no caller has to
/// re-derive "memory or property?" and none can derive it differently
/// from the image it goes with. Run it with
/// [`execute`](Self::execute).
#[derive(Debug, Clone)]
pub struct CompiledDownload {
    pub image: DeviceImage,
    pub instructions: Vec<Instruction>,
    path: LoadControlPath,
    memory_service: MemoryService,
    /// From the model row: whether `Connect` authorizes (everything
    /// but BCU1).
    authorize: bool,
    /// From the model row: whether memory writes are diffed against
    /// the device (the BCU-era EEPROM economy).
    diff_writes: bool,
}

impl CompiledDownload {
    /// The load-control path this download drives.
    pub fn path(&self) -> LoadControlPath {
        self.path
    }

    /// Execute the download against a device.
    ///
    /// `max_apdu` is the device's `A_Memory_Write` capacity, bounding
    /// the chunk size. The procedure ends in a restart, so the caller
    /// reconnects afterwards.
    pub async fn execute<T: DownloadTarget>(&self, target: &mut T, max_apdu: u16) -> Result<()> {
        let mut downloader =
            Downloader::with_path(target, self.path, max_apdu).with_memory_service(self.memory_service, max_apdu);
        if !self.authorize {
            downloader = downloader.without_authorize();
        }
        if self.diff_writes {
            downloader = downloader.with_diffed_writes();
        }
        downloader.run(&self.instructions, &self.image).await
    }
}

/// Compile the three layers into an image and a procedure.
///
/// Two decisions differ between masks, and they are *independent* —
/// both read from the mask's own declarations, never inferred from
/// the family:
///
/// - **The load-control path** comes from the mask's LSM model (its
///   `<Role>LoadControl` resources). This is per-mask data, not
///   family lore: MV-2705 is System 7 yet drives its machines
///   through properties, and a family-keyed choice would break it.
/// - **The image half** comes from the management model: System B
///   hands each interface object its bytes and lets the device place
///   them; System 7 places content at the product's fixed addresses.
///
/// The axes really are orthogonal — 2705 wants an absolute image
/// *and* property-driven machines, which the interpreter already
/// supports (absolute-segment records have a property-path form).
pub fn compile(mask: &MaskData<'_>, product: &ProductData, project: &ProjectConfig) -> Result<CompiledDownload> {
    let model = download_model(mask)?;
    let path = (model.load_control)(mask)?;
    let memory_service = (model.memory_service)(product);

    // The image half follows the (device-selected) mask too — even
    // for a BCU1 program carried by a downward-compatible BCU2. The
    // one byte where RT1 and RT2 genuinely differ, the group-object
    // config octet's bit 7 ("shall be 1" in RT1, UpdateEnable in
    // RT2), follows the *silicon reading the table*: ETS writes the
    // same program's descriptors as D3/93 (bit 7 forced) to a real
    // 0012 device and as 53/13 (plain RT2 flags) to a 0020 carrying
    // it, matching 03/05/01 §4.18.3 vs §4.18.4. The remaining BCU-era
    // codings are octet-identical between the families.
    // Dynamic table management (converted pre-ETS4 programs on BCU1
    // or BCU2 silicon): ETS relocates the association table to sit
    // right behind the actual-size address table and repoints the
    // mask's one-byte association-table pointer. `Some(ptr)` carries
    // the pointer's address so the placement code needs no mask
    // access; `None` keeps the vendor's static offsets.
    let dtm: Option<u16> = if product.dynamic_table_management && matches!(model.management_model, "Bcu1" | "Bcu2") {
        Some(mask.standard_memory_address("GroupAssociationTablePtr").ok_or(Error::DownloadConfig(
            "this program needs dynamic table management, but the mask locates no GroupAssociationTablePtr",
        ))?)
    } else {
        None
    };

    let mut image = DeviceImage::new();
    build_image(&mut image, &model.layout, &mask.lsm_model(), product, project, dtm)?;
    apply_fixups(&mut image, mask, product)?;

    let controls = assemble_controls(mask, product, ProcedureKind::LoadAll)?;
    // `SetControlVariable EnableSegmentWrite=false` switches off
    // ETS's implicit segment-content writes: the BCU2 templates
    // (MV-0020/0021 Load/all) open with it and carry their own
    // explicit `WriteMem` data phase after `LoadCompleted` instead. A
    // Hawk log of a real 0020 download confirms nothing is written
    // during the Loading window. Honoring the flag here — rather than
    // as an instruction — keeps the IR free of tool-state: the
    // procedures that disable it never rely on insertion, and the
    // ones that rely on insertion never carry the variable.
    let implicit_writes = !controls.iter().any(|control| {
        matches!(control, LoadControl::LdCtrlSetControlVariable(v)
            if v.name == "EnableSegmentWrite" && v.value == "false")
    });
    let assembled = controls_to_instructions(&controls, product.task_identity)?;
    let assembled = if model.management_model == "Bcu2" {
        omit_legacy_bcu2_object_table_announcement(assembled)
    } else {
        assembled
    };
    let instructions = resolve_relative_steps(assembled, &image);
    let instructions = if implicit_writes { insert_image_writes(instructions, &image) } else { instructions };
    let instructions = if model.halt_app_first { halt_application_first(instructions, mask)? } else { instructions };
    let instructions = inject_security_phase(instructions, product, project)?;

    Ok(CompiledDownload {
        image,
        instructions,
        path,
        memory_service,
        authorize: model.authorize_on_connect,
        diff_writes: model.diff_writes,
    })
}

/// BCU2's trailing `LdCtrlTaskSegment LsmIdx="5"` is not a PEI load
/// machine record. ETS 6.4 removes it as a legacy object-table address
/// announcement before executing the procedure (bench MV-0021 trace); sending
/// it to indexed object 5 invents an object the four-object BCU2 roster does
/// not have.
fn omit_legacy_bcu2_object_table_announcement(instructions: Vec<Instruction>) -> Vec<Instruction> {
    instructions
        .into_iter()
        .filter(|instruction| !matches!(instruction, Instruction::TaskSegment { lsm: LsmTarget::Index(5), .. }))
        .collect()
}

/// Append the family-neutral Security IO load phase before the procedure
/// disconnects or restarts. OT 17 is deliberately addressed by type: secure
/// BCU2 does not publish it in its four-object indexed roster.
fn inject_security_phase(
    instructions: Vec<Instruction>,
    product: &ProductData,
    project: &ProjectConfig,
) -> Result<Vec<Instruction>> {
    let security = match (&project.security, product.is_secure_enabled) {
        (None, false) => return Ok(instructions),
        (Some(_), false) => {
            return Err(Error::DownloadConfig("security configuration supplied for a non-secure product"));
        }
        (None, true) => return Err(Error::DownloadConfig("secure product has no security configuration")),
        (Some(security), true) => security,
    };

    let group_key_capacity = product
        .max_security_group_key_table_entries
        .ok_or_else(|| Error::ProductData("secure product declares no group-key table capacity".to_string()))?;
    let siat_capacity = product
        .max_security_individual_address_entries
        .ok_or_else(|| Error::ProductData("secure product declares no SIAT capacity".to_string()))?;
    if security.group_keys.len() > usize::from(group_key_capacity) {
        return Err(Error::DownloadConfig("security configuration exceeds the product's group-key capacity"));
    }
    if security.siat.len() > usize::from(siat_capacity) {
        return Err(Error::DownloadConfig("security configuration exceeds the product's SIAT capacity"));
    }
    if security.go_flags.iter().any(|flag| !matches!(flag, 0 | 1 | 3)) {
        return Err(Error::DownloadConfig("GO security flags contain an unsupported protection coding"));
    }

    let mut group_addresses: Vec<GroupAddress> = project.links.iter().map(|link| link.group_address).collect();
    group_addresses.sort_unstable();
    group_addresses.dedup();

    let mut group_rows = Vec::with_capacity(security.group_keys.len());
    for (address, key) in &security.group_keys {
        let index = group_addresses
            .binary_search(address)
            .map_err(|_| Error::DownloadConfig("a security group key has no address-table entry"))?
            + 1;
        let index = u16::try_from(index).map_err(|_| Error::DownloadConfig("group-key index exceeds 16 bits"))?;
        group_rows.push((index, *key));
    }
    group_rows.sort_unstable_by_key(|(index, _)| *index);
    if group_rows.windows(2).any(|rows| rows[0].0 == rows[1].0) {
        return Err(Error::DownloadConfig("security configuration repeats a group key"));
    }

    let mut siat = security.siat.clone();
    siat.sort_unstable_by_key(|(address, _)| *address);
    if siat.windows(2).any(|rows| rows[0].0 == rows[1].0) {
        return Err(Error::DownloadConfig("security configuration repeats a SIAT address"));
    }
    if siat.iter().any(|(_, sequence)| *sequence > SEQ6_MAX) {
        return Err(Error::DownloadConfig("SIAT sequence number exceeds 48 bits"));
    }

    const SECURITY_IO: u16 = 0x0011;
    const OCCURRENCE: u16 = 1;
    let target = LsmTarget::ObjectType { object_type: SECURITY_IO, occurrence: OCCURRENCE };
    let mut phase = Vec::new();
    phase.push(Instruction::LsmEvent { lsm: target, event: LoadEvent::Unload });
    phase.push(Instruction::LsmEvent { lsm: target, event: LoadEvent::StartLoading });

    push_table_count(&mut phase, pid::security::GROUP_KEY_TABLE, group_rows.len())?;
    for (element, (index, key)) in group_rows.into_iter().enumerate() {
        let mut data = Vec::with_capacity(18);
        data.extend_from_slice(&index.to_be_bytes());
        data.extend_from_slice(&key);
        phase.push(ext_write(pid::security::GROUP_KEY_TABLE, element + 1, data)?);
    }

    push_table_count(&mut phase, pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, siat.len())?;
    for (element, (address, sequence)) in siat.into_iter().enumerate() {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&u16::from_be_bytes(address.0).to_be_bytes());
        data.extend_from_slice(&u64_to_seq6(sequence));
        phase.push(ext_write(pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, element + 1, data)?);
    }

    push_table_count(&mut phase, pid::security::GO_SECURITY_FLAGS, security.go_flags.len())?;
    for (element, flag) in security.go_flags.iter().copied().enumerate() {
        phase.push(ext_write(pid::security::GO_SECURITY_FLAGS, element + 1, vec![flag])?);
    }

    phase.push(Instruction::LsmEvent { lsm: target, event: LoadEvent::LoadCompleted });
    // Enabling Security Mode after the tables are loaded matches our
    // conformance fixtures and avoids tightening application-memory policy
    // halfway through the download.
    phase.push(Instruction::FunctionPropertyExt {
        object_type: SECURITY_IO,
        occurrence: OCCURRENCE,
        prop_id: pid::security::SECURITY_MODE,
        service_id: 0,
        service_info: 1,
    });

    let insertion = instructions
        .iter()
        .position(|instruction| matches!(instruction, Instruction::Disconnect | Instruction::Restart))
        .unwrap_or(instructions.len());
    let mut result = Vec::with_capacity(instructions.len() + phase.len());
    result.extend_from_slice(&instructions[..insertion]);
    result.extend(phase);
    result.extend_from_slice(&instructions[insertion..]);
    Ok(result)
}

fn push_table_count(instructions: &mut Vec<Instruction>, prop_id: u16, count: usize) -> Result<()> {
    let count = u16::try_from(count).map_err(|_| Error::DownloadConfig("security table count exceeds 16 bits"))?;
    instructions.push(Instruction::WritePropertyExt {
        object_type: 0x0011,
        occurrence: 1,
        prop_id,
        start_idx: 0,
        count: 1,
        data: count.to_be_bytes().to_vec(),
        verify: false,
    });
    Ok(())
}

fn ext_write(prop_id: u16, element: usize, data: Vec<u8>) -> Result<Instruction> {
    let start_idx =
        u16::try_from(element).map_err(|_| Error::DownloadConfig("security table index exceeds 16 bits"))?;
    Ok(Instruction::WritePropertyExt {
        object_type: 0x0011,
        occurrence: 1,
        prop_id,
        start_idx,
        count: 1,
        data,
        verify: false,
    })
}

/// The [`DownloadModel`] row for a mask, or the error every
/// unimplemented management model gets.
fn download_model(mask: &MaskData<'_>) -> Result<&'static DownloadModel> {
    DownloadModel::for_management_model(mask.management_model())
        .ok_or(Error::DownloadConfig("downloads for this management model are not implemented"))
}

/// The load-control path a mask drives its machines through — the
/// mask's [`DownloadModel`] row applied to its own LSM declarations.
///
/// Public because procedures other than a full download need it too:
/// running the mask's Unload template, or ad-hoc instruction streams,
/// construct their [`Downloader`] with the same path `compile` would
/// have chosen.
pub fn load_control_path(mask: &MaskData<'_>) -> Result<LoadControlPath> {
    (download_model(mask)?.load_control)(mask)
}

/// Halt the application before anything else touches the device: a
/// `RunError` ← 00 write inserted right after `Connect`.
///
/// The BCU2 Load/all template only halts in its memory phase, *after*
/// the LSM cycle — an order that assumes the app is not running.
/// `LoadCompleted` on the application machine (re)starts the user
/// code mid-download, which wedged a real BCU2 that was running its
/// application until its programming button was pressed (prog mode
/// force-halts user code, which is also why downloads to a device in
/// prog mode never showed this). ETS's own BCU1 re-download trace
/// halts first — its third telegram is `$010D ← 00`. The address
/// comes from the mask's `RunError` resource; the template's own
/// later halt then rewrites the byte with its existing value (or
/// diff-skips), and its closing `RunError ← FF` + restart bring the
/// app back up cleanly.
fn halt_application_first(instructions: Vec<Instruction>, mask: &MaskData<'_>) -> Result<Vec<Instruction>> {
    let run_error = mask.standard_memory_address("RunError").ok_or(Error::DownloadConfig(
        "this mask's model halts the application first, but the mask locates no RunError in memory",
    ))?;

    let mut out = Vec::with_capacity(instructions.len() + 1);
    let mut inserted = false;
    for instruction in instructions {
        let is_connect = matches!(instruction, Instruction::Connect);
        out.push(instruction);
        if is_connect && !inserted {
            out.push(Instruction::WriteMemory { address: run_error, data: vec![0x00], verify: true });
            inserted = true;
        }
    }
    Ok(out)
}

/// Patch the program's fixups into the image: BCU-era native code
/// calls mask-ROM routines, and each mask puts those entry points
/// elsewhere — `U_GetTMx` is 0D6Ch on MV-0012 and 5063h on MV-0020.
/// The vendor `Data` ships with the *product* mask's addresses baked
/// in, so on the product's own mask this rewrites bytes with their
/// existing values; on a downward-compatible host it is what keeps
/// the code from calling into nowhere (a real BCU2 running a BCU1
/// program crashed on boot over exactly this, until its programming
/// button — the ETS trace patches these four spots and nothing else
/// in the code).
///
/// An unresolvable routine is a hard error: shipping the code anyway
/// guarantees that crash on the device.
fn apply_fixups(image: &mut DeviceImage, mask: &MaskData<'_>, product: &ProductData) -> Result<()> {
    for fixup in &product.fixups {
        let address = mask.mask_entry_address(&fixup.function).ok_or_else(|| {
            Error::ProductData(format!(
                "the program's fixup {} has no MaskEntry on mask {:?}",
                fixup.function,
                mask.version()
            ))
        })?;
        let address = u16::try_from(address)
            .map_err(|_| Error::MasterData(format!("MaskEntry {} lies beyond the 16-bit space", fixup.function)))?;

        let segment = product.segment(&fixup.code_segment).ok_or_else(|| {
            Error::ProductData(format!(
                "fixup {} names segment {}, which the product does not define",
                fixup.function, fixup.code_segment
            ))
        })?;
        let base = segment
            .address
            .ok_or(Error::DownloadConfig("a fixup points into a relative segment; fixups are BCU-era absolute"))?;

        for &offset in &fixup.offsets {
            let target = u16::try_from(u32::from(base) + offset)
                .map_err(|_| Error::ProductData(format!("fixup {} offset {offset} overflows", fixup.function)))?;
            image.patch(target, &address.to_be_bytes())?;
        }
    }
    Ok(())
}

/// Fit the relative steps to the content this download actually has.
///
/// Two adjustments, both of which ETS makes and neither of which a
/// per-mask template or a per-product fragment could:
///
/// - **Sizing.** The mask templates carry a placeholder size on their
///   `LdCtrlRelSegment` steps — MV-07B0 says `Size="2"` for the
///   address, association and group object tables — because a table's
///   real size depends on the *project*. The requested size becomes
///   the larger of the declared size and the content we will write.
/// - **Pruning.** A product may declare a segment and a write for
///   content this project produces none of: a device with no
///   parameters still emits `LdCtrlRelSegment`/`LdCtrlWriteRelMem` for
///   its (zero-length) parameter block. Allocating nothing and writing
///   nothing is the correct rendering, so those steps are dropped
///   here — leaving the interpreter free to treat a write with no
///   content as the bug it would otherwise be.
fn resolve_relative_steps(instructions: Vec<Instruction>, image: &DeviceImage) -> Vec<Instruction> {
    instructions
        .into_iter()
        .filter_map(|instruction| match instruction {
            Instruction::RelSegment { lsm, mut segment } => match lsm {
                LsmTarget::Index(index) if image.relative(index).is_some() => {
                    let bytes = image.relative(index).expect("checked above");
                    segment.requested_memory_size = segment.requested_memory_size.max(bytes.len() as u32);
                    Some(Instruction::RelSegment { lsm, segment })
                }
                LsmTarget::Index(_) if segment.requested_memory_size == 0 => None,
                LsmTarget::Index(_) | LsmTarget::ObjectType { .. } => Some(Instruction::RelSegment { lsm, segment }),
            },
            Instruction::WriteRelImage { obj_idx, .. } if image.relative(obj_idx).is_none() => None,
            other => Some(other),
        })
        .collect()
}

// ============================================================================
// The generic image pipeline
// ============================================================================

/// Build the download image: the shared steps once, the per-model
/// residue through the [`ImageLayout`] definition.
///
/// Shared regardless of model: the sorted, deduplicated group-address
/// list (association TSAPs are indices into it), the capacity checks
/// against what the product declares, and the gapless group-object
/// descriptor rows. What the layout decides: the table byte formats,
/// the ASAP numbering base, and whether content lands at absolute
/// product addresses or at the machines' interface objects.
fn build_image(
    image: &mut DeviceImage,
    layout: &ImageLayout,
    model: &LsmModel,
    product: &ProductData,
    project: &ProjectConfig,
    dtm: Option<u16>,
) -> Result<()> {
    // The distinct group addresses, ascending — the address-table
    // formats binary-search this order, and each link's TSAP is
    // 1 + its address's position (TSAP 0 is the device's own IA).
    let mut group_addresses: Vec<GroupAddress> = project.links.iter().map(|l| l.group_address).collect();
    group_addresses.sort_unstable();
    group_addresses.dedup();

    if let Some(max) = product.address_table_max_entries
        && group_addresses.len() > max as usize
    {
        return Err(Error::DownloadConfig("more group addresses than the product's address table holds"));
    }
    // Under dynamic table management the association table is packed
    // behind the actual-size address table, so the vendor gap the
    // `MaxEntries` attribute encodes no longer bounds it — the packed
    // fit before the group object table (checked in `place_absolute`)
    // is the real constraint. TSAP FEh is the unlinked-object
    // placeholder there, so a real index must never reach it.
    match dtm {
        Some(_) if group_addresses.len() >= 0xFE => {
            return Err(Error::DownloadConfig(
                "dynamic table management reserves TSAP FEh; fewer group addresses needed",
            ));
        }
        None => {}
        Some(_) => {}
    }

    let associations: Vec<(u16, u16)> = project
        .links
        .iter()
        .map(|link| {
            let tsap = group_addresses
                .binary_search(&link.group_address)
                .expect("every link's address is in the list built from the links")
                + 1;
            (tsap as u16, u16::from(link.com_object))
        })
        .collect();

    let address_table = (layout.address_table)(project.individual_address, &group_addresses)?;
    let association_table = (layout.association_table)(&associations, &product.com_object_numbers)?;
    if dtm.is_none()
        && let Some(max) = product.association_table_max_entries
        && layout.association_count.read(&association_table).is_some_and(|count| count > usize::from(max))
    {
        return Err(Error::DownloadConfig("more associations than the product's association table holds"));
    }
    let group_object_table = (layout.group_object_table)(&co_rows(product, layout.first_asap)?)?;

    match layout.placement {
        Placement::RelativeObjects => {
            place_relative(image, model, product, project, [address_table, association_table, group_object_table])
        }
        Placement::AbsoluteSegments => {
            place_absolute(image, layout, product, project, [address_table, association_table, group_object_table], dtm)
        }
    }
}

/// The gapless group-object descriptor rows: row `i` describes ASAP
/// `first_asap + i`, numbers the product does not define get zeroed
/// descriptors, and a number below the base is a product-data error —
/// RT7 cannot express ASAP 0.
fn co_rows(product: &ProductData, first_asap: u16) -> Result<Vec<(ComObjectFlags, ComObjectType)>> {
    let Some(max) = product.com_objects.iter().map(|o| o.number).max() else {
        return Ok(Vec::new());
    };
    let mut rows = vec![(ComObjectFlags::from_byte(0), ComObjectType::Uint1); (max - first_asap) as usize + 1];
    for obj in &product.com_objects {
        if obj.number < first_asap {
            return Err(Error::ProductData(format!(
                "this management model numbers group objects from {first_asap}, but the product declares object {}",
                obj.number
            )));
        }
        rows[(obj.number - first_asap) as usize] = (obj.flags, obj.object_type);
    }
    Ok(rows)
}

/// Place content for a relative-allocation model (System B): the
/// generated tables at the interface objects the mask's LSM model
/// declares for them, the product's own relative segments at the
/// machines the *product* assigns them to.
///
/// A table we always produce content for must have its machine
/// declared, or the matching `LdCtrlWriteRelMem` would be silently
/// pruned for lack of content — hence the hard errors.
fn place_relative(
    image: &mut DeviceImage,
    model: &LsmModel,
    product: &ProductData,
    project: &ProjectConfig,
    [address_table, association_table, group_object_table]: [Vec<u8>; 3],
) -> Result<()> {
    let object = |role: MachineRole, what: &'static str| -> Result<u8> {
        model.object_of(role).ok_or(Error::DownloadConfig(what))
    };

    image.insert_relative(
        object(MachineRole::GroupAddressTable, "the mask declares no group address table machine")?,
        address_table,
    );
    image.insert_relative(
        object(MachineRole::GroupAssociationTable, "the mask declares no association table machine")?,
        association_table,
    );
    image.insert_relative(
        object(MachineRole::GroupObjectTable, "the mask declares no group object table machine")?,
        group_object_table,
    );

    // The product's own relative segments (the parameter block) go to
    // the machines the *product* assigns them to — its merge fragments
    // write them back at those same objects. A product segment landing
    // on a table machine would stomp a generated table; that is a
    // product-data bug worth stopping on.
    for segment in &product.segments {
        if segment.address.is_some() {
            continue;
        }
        let Some(machine) = segment.load_state_machine else { continue };
        if image.relative(machine).is_some() {
            return Err(Error::ProductData(format!(
                "the product assigns a relative segment to machine {machine}, which already holds generated table content"
            )));
        }

        // Relative content is capacity-sized: the declared size is the
        // allocation request, and the whole block is written back.
        let mut bytes = vec![0u8; segment.size as usize];
        let take = segment.data.len().min(bytes.len());
        bytes[..take].copy_from_slice(&segment.data[..take]);
        patch_parameters(&mut bytes, segment.size as usize, &segment.id, product, project)?;

        image.insert_relative(machine, bytes);
    }

    Ok(())
}

/// Place content for an absolute-address model (System 7, BCU2,
/// BCU1): every addressed segment's content, with the generated
/// tables landing in the segments the product names for them.
///
/// The bytes are each segment's *content*, not its capacity: a table
/// segment holds exactly its generated blob, a data segment its
/// default `Data` (plus any parameter patches). Padding to the
/// allocated size is the device's business — the download writes only
/// the meaningful bytes, as ETS does, so a two-entry table on a
/// 254-entry segment costs a handful of writes rather than hundreds.
///
/// Where a table lands depends on its declared offset:
///
/// - **Offset 0** — a dedicated table segment (System 7, BCU2): the
///   generated blob *is* the content, replacing the default data
///   wholesale. An empty blob keeps the segment out of the image.
/// - **Offset > 0** — the table lives inside a shared segment (BCU1:
///   all three tables point into the one 256-byte EEPROM segment):
///   the blob is spliced over the default data at its offset, and the
///   rest of the segment's content survives. An empty blob leaves the
///   default bytes alone.
fn place_absolute(
    image: &mut DeviceImage,
    layout: &ImageLayout,
    product: &ProductData,
    project: &ProjectConfig,
    [address_table, association_table, group_object_table]: [Vec<u8>; 3],
    dtm: Option<u16>,
) -> Result<()> {
    // Dynamic table management (converted BCU-era programs): the
    // association table does not sit at its vendor offset but is
    // packed right behind the actual-size address table, so it is
    // withheld from the per-segment splicing (an empty blob
    // contributes nothing) and written by absolute address after the
    // buffers exist — the packed table may straddle declared segment
    // boundaries (a native BCU2 program declares contiguous dedicated
    // ADT and AST segments; a converted BCU1 one shares one EEPROM
    // segment). The vendor bytes at the old offset stay in place,
    // unread — ETS leaves them too.
    let spliced_ast: &[u8] = if dtm.is_some() { &[] } else { &association_table };

    // Each generated table names the segment (and offset) that holds
    // it. A table whose blob is empty (no group objects, say) or
    // whose product declares no segment simply contributes nothing.
    let generated: [(Option<&str>, u32, &[u8], &'static str); 3] = [
        (product.address_table_segment.as_deref(), product.address_table_offset, &address_table, "group address table"),
        (
            product.association_table_segment.as_deref(),
            product.association_table_offset,
            spliced_ast,
            "association table",
        ),
        (
            product.com_object_table_segment.as_deref(),
            product.com_object_table_offset,
            &group_object_table,
            "group object table",
        ),
    ];

    let mut buffers: BTreeMap<String, (u16, Vec<u8>)> = BTreeMap::new();
    for segment in &product.segments {
        let Some(address) = segment.address else { continue };
        let mut content = segment.data.clone();

        for (id, offset, blob, what) in &generated {
            if *id != Some(segment.id.as_str()) {
                continue;
            }
            let offset = *offset as usize;

            // A group object table the *product* ships as default data
            // (vendor System 7 programs) is overlaid per object instead of
            // replaced — its count and pointers are firmware facts a
            // synthesized table would zero.
            if *what == "group object table"
                && content.len() > offset
                && let Some(overlay) = layout.overlay_group_object_table
            {
                overlay(&mut content[offset..], &product.com_objects)?;
                continue;
            }

            if offset + blob.len() > segment.size as usize {
                return Err(Error::DownloadConfig(match *what {
                    "group address table" => "group address table exceeds its segment",
                    "association table" => "association table exceeds its segment",
                    _ => "group object table exceeds its segment",
                }));
            }

            if offset == 0 {
                content = blob.to_vec();
            } else if !blob.is_empty() {
                if content.len() < offset + blob.len() {
                    content.resize(offset + blob.len(), 0);
                }
                content[offset..offset + blob.len()].copy_from_slice(blob);
            }
        }

        if !content.is_empty() {
            buffers.insert(segment.id.clone(), (address, content));
        }
    }

    // Dynamic table management: place the packed association table
    // and repoint the mask's one-byte association-table pointer at it.
    if let Some(ptr_addr) = dtm {
        let segment_base = |id: &Option<String>| {
            id.as_deref().and_then(|id| product.segments.iter().find(|s| s.id == id)).and_then(|s| s.address)
        };
        let adt_base = segment_base(&product.address_table_segment)
            .ok_or(Error::DownloadConfig("dynamic table management needs the address table in an addressed segment"))?;
        let assoc_abs = u32::from(adt_base) + product.address_table_offset + address_table.len() as u32;

        // The packed pair must stop short of the group object table —
        // the constraint that replaces the vendor MaxEntries gap. On
        // the shared-segment layout the COT follows in the same
        // segment; on dedicated segments the COT segment starts right
        // after the AST area. Either way its absolute start is the
        // ceiling.
        if let Some(cot_base) = segment_base(&product.com_object_table_segment) {
            let cot_abs = u32::from(cot_base) + product.com_object_table_offset;
            if assoc_abs + association_table.len() as u32 > cot_abs {
                return Err(Error::DownloadConfig(
                    "packed address and association tables run into the group object table",
                ));
            }
        }

        // The pointer's `Ptr_StandardMemory100` flavour stores the
        // address minus 0100h, so the value must be one byte once this
        // range check passes. ETS writes the byte as its own telegram
        // (BCU2_partial.log: `$0111 ← 1F`); with `diff_writes` on the
        // BCU-era models, patching it into the image produces exactly
        // that single-byte write.
        if !(0x0100..=0x01FF).contains(&assoc_abs) {
            return Err(Error::DownloadConfig(
                "the packed association table falls outside the one-byte pointer's 0100h page",
            ));
        }

        write_absolute(&mut buffers, product, assoc_abs, &association_table, "the packed association table")?;
        write_absolute(
            &mut buffers,
            product,
            u32::from(ptr_addr),
            &[(assoc_abs - 0x0100) as u8],
            "the association table pointer",
        )?;
    }

    // A generated table must land in a segment the product defined.
    for (id, _, blob, what) in generated {
        if let Some(id) = id
            && !blob.is_empty()
            && !buffers.contains_key(id)
            && !product.segments.iter().any(|s| s.id == id)
        {
            return Err(Error::ProductData(format!(
                "the {what} names segment {id}, which the product does not define"
            )));
        }
    }

    // Parameter patches, content-length: a parameter can sit past a
    // segment's default data (or in a segment with none), so the
    // buffer grows exactly to the last meaningful byte.
    for value in &project.parameters {
        let location = product
            .parameters
            .iter()
            .find(|p| p.id == value.id)
            .ok_or_else(|| Error::ProductData(format!("the product defines no parameter {}", value.id)))?;
        let segment = product.segments.iter().find(|s| s.id == location.code_segment).ok_or_else(|| {
            Error::ProductData(format!(
                "parameter {} names segment {}, which the product does not define",
                value.id, location.code_segment
            ))
        })?;
        let (_, bytes) = buffers
            .entry(location.code_segment.clone())
            .or_insert_with(|| (segment.address.unwrap_or_default(), Vec::new()));
        let end = location.offset as usize + patch_span(location, value)?;
        if end > bytes.len() {
            if end > segment.size as usize {
                return Err(Error::DownloadConfig("a parameter value runs past the end of its segment"));
            }
            bytes.resize(end, 0);
        }
        patch_one_parameter(bytes, location, value)?;
    }

    for (address, bytes) in buffers.values() {
        image.insert(*address, bytes.clone())?;
    }
    Ok(())
}

/// Write bytes at an absolute device address into the per-segment
/// content buffers, growing them (zero-filled) where the vendor's
/// default data stops short of the target.
///
/// Dynamic table management needs this because the packed association
/// table's home is an *address*, not a segment offset: a native BCU2
/// program declares contiguous dedicated ADT and AST segments, and the
/// packed table starts inside the first and may run into the second.
/// Every byte must land inside some addressed segment's declared
/// capacity — a byte falling into a gap means the product's layout
/// cannot hold the packed tables, which is worth stopping on.
fn write_absolute(
    buffers: &mut BTreeMap<String, (u16, Vec<u8>)>,
    product: &ProductData,
    address: u32,
    bytes: &[u8],
    what: &'static str,
) -> Result<()> {
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let position = address + cursor as u32;
        let segment = product
            .segments
            .iter()
            .find(|s| s.address.is_some_and(|base| (u32::from(base)..u32::from(base) + s.size).contains(&position)))
            .ok_or(Error::DownloadConfig(match () {
                _ if what.contains("pointer") => "the association table pointer lies outside the product's segments",
                _ => "the packed association table runs outside the product's segments",
            }))?;

        let base = segment.address.expect("the segment was selected for having an address");
        let offset = (position - u32::from(base)) as usize;
        let take = bytes.len() - cursor;
        let capacity_left = segment.size as usize - offset;
        let run = take.min(capacity_left);

        let (_, content) = buffers.entry(segment.id.clone()).or_insert_with(|| (base, Vec::new()));
        if content.len() < offset + run {
            content.resize(offset + run, 0);
        }
        content[offset..offset + run].copy_from_slice(&bytes[cursor..cursor + run]);
        cursor += run;
    }
    Ok(())
}

/// Patch the project's values for one segment into its content buffer.
///
/// Used by the relative placement, whose buffers are already
/// capacity-sized — a value past `capacity` is an error, never a
/// growth. (The absolute placement grows its content-length buffers
/// inline instead, because growth needs the segment lookup it already
/// holds.)
fn patch_parameters(
    bytes: &mut Vec<u8>,
    capacity: usize,
    segment_id: &str,
    product: &ProductData,
    project: &ProjectConfig,
) -> Result<()> {
    for value in &project.parameters {
        let location = product
            .parameters
            .iter()
            .find(|p| p.id == value.id)
            .ok_or_else(|| Error::ProductData(format!("the product defines no parameter {}", value.id)))?;
        if location.code_segment != segment_id {
            continue;
        }
        if location.offset as usize + patch_span(location, value)? > capacity {
            return Err(Error::DownloadConfig("a parameter value runs past the end of its segment"));
        }
        patch_one_parameter(bytes, location, value)?;
    }
    Ok(())
}

/// How many bytes a patch touches from its location's offset on.
///
/// Byte-aligned parameters are written verbatim, so the value's own
/// length is the span (a type-declared width only bounds it). A
/// bit-packed parameter's span covers every byte its bits reach —
/// including the partial first and last bytes it shares with its
/// neighbours.
fn patch_span(location: &ParameterLocation, value: &ParameterValue) -> Result<usize> {
    if location.bit_offset == 0 && location.size_bits % 8 == 0 {
        if location.size_bits != 0 && value.value.len() > (location.size_bits / 8) as usize {
            return Err(Error::DownloadConfig("a parameter value is wider than its declared type"));
        }
        Ok(value.value.len())
    } else {
        // Bit-packed values travel as a big-endian integer, so the
        // read-modify-write below can hold them in a u64.
        if value.value.len() > 8 {
            return Err(Error::DownloadConfig("a bit-packed parameter value is wider than 64 bits"));
        }
        Ok((usize::from(location.bit_offset) + usize::from(location.size_bits)).div_ceil(8))
    }
}

/// The one write every parameter patch ends in.
///
/// Both offsets follow ETS's memory conventions, which the TUI's
/// memory view already renders and compare-programs verifies against
/// vendor images: multi-byte values are big-endian, and `bit_offset`
/// counts from the MSB of the byte at `offset`.
fn patch_one_parameter(bytes: &mut [u8], location: &ParameterLocation, value: &ParameterValue) -> Result<()> {
    let start = location.offset as usize;
    if start + patch_span(location, value)? > bytes.len() {
        return Err(Error::DownloadConfig("a parameter value runs past the end of its segment"));
    }

    if location.bit_offset == 0 && location.size_bits % 8 == 0 {
        bytes[start..start + value.value.len()].copy_from_slice(&value.value);
        return Ok(());
    }

    // Sub-byte or unaligned: read-modify-write only the bits that
    // belong to this parameter, preserving its neighbours in the
    // shared octets.
    let raw = value.value.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    for bit in 0..location.size_bits {
        let global = start * 8 + usize::from(location.bit_offset) + usize::from(bit);
        let mask = 1u8 << (7 - global % 8);
        // The value's bits go out MSB-first, mirroring how they sit in
        // memory.
        let set = (raw >> (location.size_bits - 1 - bit)) & 1 == 1;
        if set {
            bytes[global / 8] |= mask;
        } else {
            bytes[global / 8] &= !mask;
        }
    }
    Ok(())
}

// ============================================================================
// The implicit data phase
// ============================================================================

/// Insert the data writes ETS performs implicitly.
///
/// A System 7 `ProductProcedure` declares its segments but contains no
/// write instructions — ETS writes each segment's content itself while
/// the owning machine is `Loading`. We make that explicit: every
/// segment allocated on a machine is written just before that
/// machine's `LoadCompleted`, in declaration order.
///
/// Procedures that *do* carry their own writes (`LdCtrlWriteMem` with
/// no inline data, System B's `LdCtrlWriteRelMem`) are untouched —
/// those already became `WriteImage` instructions during conversion.
fn insert_image_writes(instructions: Vec<Instruction>, image: &DeviceImage) -> Vec<Instruction> {
    let mut pending: Vec<(LsmTarget, u16, u16)> = Vec::new();
    let mut out = Vec::with_capacity(instructions.len());

    for instruction in instructions {
        match &instruction {
            Instruction::AbsSegment { lsm, segment } => {
                pending.push((*lsm, segment.start_address, segment.length));
                out.push(instruction);
            }
            Instruction::LsmEvent { lsm, event: LoadEvent::LoadCompleted } => {
                for (seg_lsm, address, capacity) in pending.iter() {
                    // Write only the segment's meaningful content, not
                    // its full allocated capacity — the image region is
                    // content-length, so its slice bounds the write.
                    if seg_lsm == lsm
                        && let Some(content) = image.slice(*address, *capacity)
                    {
                        out.push(Instruction::WriteImage {
                            address: *address,
                            length: content.len() as u16,
                            verify: true,
                        });
                    }
                }
                pending.retain(|(seg_lsm, _, _)| seg_lsm != lsm);
                out.push(instruction);
            }
            _ => out.push(instruction),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::mask::MaskDb;
    use crate::download::product::tests::SYSTEM7_MTXML;
    use zweidraehte_proto::device::MaskVersion;

    fn product() -> ProductData {
        ProductData::from_mtxml_str(SYSTEM7_MTXML).expect("fixture parses")
    }

    fn project() -> ProjectConfig {
        let mut project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        project.links =
            vec![GroupLink { group_address: GroupAddress::from_three_level(0, 0, 2), com_object: 1 }, GroupLink {
                group_address: GroupAddress::from_three_level(0, 0, 1),
                com_object: 1,
            }];
        project
    }

    fn compiled() -> CompiledDownload {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        compile(&mask, &product(), &project()).expect("compiles")
    }

    #[test]
    fn seeds_segments_with_product_defaults() {
        let c = compiled();
        // The parameter segment's <Data> base64 seeded the image, and
        // the segment is padded to its declared size.
        let params = c.image.slice(0x4300, 4).expect("param segment in image");
        assert_eq!(params, [1, 2, 3, 4]);
    }

    #[test]
    fn overlays_tables_built_from_the_project() {
        let c = compiled();
        // ADT: length 3 (IA + two GAs), then the encoded entries.
        let adt = c.image.slice(0x4000, 7).expect("ADT in image");
        assert_eq!(adt, [3, 0x11, 0x2A, 0x00, 0x01, 0x00, 0x02]);

        // AST: both links point at object 1; TSAPs follow the sorted
        // address order.
        let ast = c.image.slice(0x4100, 5).expect("AST in image");
        assert_eq!(ast, [2, 1, 1, 2, 1]);

        // COT: one object, number 1, so the table covers ASAPs 0..=1
        // with a zeroed row 0. "1 Bit" is type 0.
        let cot = c.image.slice(0x4200, 11).expect("COT in image");
        assert_eq!(cot[0], 2, "count covers ASAP 0 and 1");
        assert_eq!(&cot[3..7], &[0, 0, 0, 0], "unused ASAP 0");
        assert_eq!(cot[9], 0b1001_0100 | 0b11, "object 1 flags from the product");
        assert_eq!(cot[10], 0, "1 Bit is type code 0");
    }

    #[test]
    fn applies_parameter_values_over_the_defaults() {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let mut project = project();
        project.parameters = vec![ParameterValue { id: "M-00FA_A-0306-02-0000_P-1".to_string(), value: vec![0xEE] }];

        let c = compile(&mask, &product(), &project).expect("compiles");
        // Default data was 01 02 03 04; the parameter sits at offset 2.
        assert_eq!(c.image.slice(0x4300, 4).expect("param segment"), [1, 2, 0xEE, 4]);
    }

    /// A location shorthand for the bit-patching tests.
    fn at(offset: u32, bit_offset: u8, size_bits: u16) -> ParameterLocation {
        ParameterLocation {
            id: "p".to_string(),
            code_segment: "s".to_string(),
            offset,
            bit_offset,
            size_bits,
            legacy_patch_always: false,
        }
    }

    fn value(bytes: &[u8]) -> ParameterValue {
        ParameterValue { id: "p".to_string(), value: bytes.to_vec() }
    }

    #[test]
    fn a_sub_byte_patch_preserves_its_neighbours() {
        // One bit at MSB-first position 6 of byte 1: mask 0b0000_0010.
        let mut bytes = [0u8; 4];
        patch_one_parameter(&mut bytes, &at(1, 6, 1), &value(&[1])).expect("patches");
        assert_eq!(bytes, [0x00, 0x02, 0x00, 0x00]);

        // Clearing the same bit leaves everything else set.
        let mut bytes = [0xFFu8; 4];
        patch_one_parameter(&mut bytes, &at(1, 6, 1), &value(&[0])).expect("patches");
        assert_eq!(bytes, [0xFF, 0xFD, 0xFF, 0xFF]);
    }

    #[test]
    fn a_nibble_lands_msb_first() {
        // ETS packs from the MSB down: a 4-bit value at BitOffset 0 is
        // the byte's high nibble.
        let mut bytes = [0x0Fu8];
        patch_one_parameter(&mut bytes, &at(0, 0, 4), &value(&[0x05])).expect("patches");
        assert_eq!(bytes, [0x5F]);
    }

    #[test]
    fn a_bit_field_may_straddle_a_byte_boundary() {
        // 4 bits from bit 6 of byte 0: the low two bits of byte 0 and
        // the high two of byte 1.
        let mut bytes = [0u8; 2];
        patch_one_parameter(&mut bytes, &at(0, 6, 4), &value(&[0x0F])).expect("patches");
        assert_eq!(bytes, [0x03, 0xC0]);
    }

    #[test]
    fn a_value_wider_than_its_type_is_rejected() {
        let mut bytes = [0u8; 4];
        let result = patch_one_parameter(&mut bytes, &at(0, 0, 8), &value(&[0, 1]));
        assert!(matches!(result, Err(Error::DownloadConfig(_))));
    }

    #[test]
    fn a_straddling_patch_grows_its_buffer_to_the_last_touched_byte() {
        // Through the compile path: a 4-bit parameter at bit 6 of
        // offset 2 touches bytes 2 and 3, so the span math must claim
        // both — a value.len()-based bound would only claim one.
        assert_eq!(patch_span(&at(2, 6, 4), &value(&[0x0F])).expect("spans"), 2);
    }

    #[test]
    fn an_unknown_parameter_is_rejected() {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let mut project = project();
        project.parameters = vec![ParameterValue { id: "no-such-parameter".to_string(), value: vec![0] }];

        assert!(matches!(compile(&mask, &product(), &project), Err(Error::ProductData(_))));
    }

    #[test]
    fn inserts_image_writes_before_load_completed() {
        let c = compiled();

        // The fixture's ProductProcedure allocates one segment on the
        // address-table machine; the write must land between the
        // segment record and LoadCompleted.
        let seg_at =
            c.instructions.iter().position(|i| matches!(i, Instruction::AbsSegment { .. })).expect("segment record");
        let write_at = c
            .instructions
            .iter()
            .position(|i| matches!(i, Instruction::WriteImage { address: 0x4000, .. }))
            .expect("image write for the allocated segment");
        let completed_at = c
            .instructions
            .iter()
            .position(|i| matches!(i, Instruction::LsmEvent { event: LoadEvent::LoadCompleted, .. }))
            .expect("LoadCompleted");

        assert!(seg_at < write_at && write_at < completed_at, "the write happens inside the Loading window");
    }

    #[test]
    fn writes_cover_content_not_allocated_capacity() {
        // The fixture's ADT segment is sized for 7 entries (17 bytes),
        // but this project links only two group addresses. The write
        // must cover the blob (count + IA + 2 GAs = 7 bytes), not the
        // full 17-byte capacity — ETS writes content, not the segment.
        let c = compiled();
        let adt_write = c
            .instructions
            .iter()
            .find_map(|i| match i {
                Instruction::WriteImage { address: 0x4000, length, .. } => Some(*length),
                _ => None,
            })
            .expect("an ADT write");
        assert_eq!(adt_write, 7, "count + IA + two group addresses, not the 17-byte capacity");
        // And the image region is that length, not padded to capacity.
        assert_eq!(c.image.slice(0x4000, 64).expect("ADT region").len(), 7);
    }

    #[test]
    fn rejects_more_links_than_the_product_holds() {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let mut project = project();
        // The fixture's tables hold 7 entries.
        project.links = (0..9)
            .map(|i| GroupLink { group_address: GroupAddress::from_three_level(1, 0, i), com_object: 1 })
            .collect();

        assert!(matches!(compile(&mask, &product(), &project), Err(Error::DownloadConfig(_))));
    }

    /// Relative segments carry no address, so they contribute nothing
    /// to an absolute image — System B writes them through its own
    #[test]
    fn a_product_without_group_objects_contributes_no_system7_table() {
        // System 7: an empty COT blob keeps the COT segment out of the
        // image entirely — no placeholder table is written.
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let mut product = product();
        product.com_objects.clear();
        let mut project = project();
        project.links = vec![GroupLink { group_address: GroupAddress::from_three_level(0, 0, 2), com_object: 1 }];
        let c = compile(&mask, &product, &project).expect("compiles");
        assert!(c.image.slice(0x4200, 1).is_none(), "no COT content in the image");
    }

    #[test]
    fn a_vendor_supplied_cot_is_overlaid_not_replaced() {
        // Vendor System 7 products ship their group object table as the
        // COT segment's default data, whose count and pointers are
        // firmware facts. Only the per-object flags/type octets may
        // change; a synthesized table would zero the pointers.
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let mut product = product();
        let cot = product.segments.iter_mut().find(|s| s.id.ends_with("AS-4200")).expect("COT segment");
        // count 3, ram_flags_ptr 0700h, three rows with live pointers.
        cot.data = vec![
            3, 0x07, 0x00, // header
            0x07, 0x5A, 0xDF, 0x03, // object 0
            0x07, 0x6E, 0xDF, 0x03, // object 1 (the product defines it)
            0x07, 0x82, 0xDF, 0x00, // object 2
        ];

        let c = compile(&mask, &product, &project()).expect("compiles");
        let table = c.image.slice(0x4200, 15).expect("COT in image");
        assert_eq!(&table[..3], &[3, 0x07, 0x00], "count and RAM flags pointer survive");
        assert_eq!(&table[3..7], &[0x07, 0x5A, 0xDF, 0x03], "object 0 keeps its vendor row");
        assert_eq!(&table[7..9], &[0x07, 0x6E], "object 1 keeps its data pointer");
        assert_eq!(table[9], 0b1001_0100 | 0b11, "object 1 gets the configured flags");
        assert_eq!(table[10], 0x00, "object 1 gets the configured type (1 Bit = 00h, as ETS writes it)");
        assert_eq!(&table[11..], &[0x07, 0x82, 0xDF, 0x00], "object 2 keeps its vendor row");
    }

    #[test]
    fn an_object_outside_the_vendor_cot_is_an_error() {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let mut product = product();
        let cot = product.segments.iter_mut().find(|s| s.id.ends_with("AS-4200")).expect("COT segment");
        cot.data = vec![1, 0, 0, 0, 0, 0, 0]; // one row; the product's object is number 1
        assert!(matches!(compile(&mask, &product, &project()), Err(Error::ProductData(_))));
    }

    #[test]
    fn too_many_group_objects_error_instead_of_an_empty_table() {
        // Pins the fix of the old `.unwrap_or_default()`, which
        // swallowed the >255-object coding error into an empty table.
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let mut product = product();
        product.com_objects = (0..256u16)
            .map(|number| crate::download::product::ComObjectDef {
                number,
                object_type: zweidraehte_proto::com_object::ComObjectType::Uint1,
                flags: ComObjectFlags::from_byte(0x47),
            })
            .collect();
        let result = compile(&mask, &product, &project());
        assert!(matches!(result, Err(Error::DownloadConfig(_))));
    }

    /// A BCU1 compile end to end: direct path, the mask's
    /// DefaultProcedure template, and the tables spliced into the one
    /// EEPROM segment at their declared offsets — everything around
    /// them (the vendor's 00..FF ramp) survives.
    #[test]
    fn bcu1_compiles_direct_with_spliced_tables() {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0012).expect("fixture");
        let mask = db.mask(MaskVersion::Bcu1Tp1).expect("0012");
        let product = ProductData::from_mtxml_str(crate::download::product::tests::BCU1_MTXML).expect("fixture parses");

        let mut project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        project.links =
            vec![GroupLink { group_address: GroupAddress::from_three_level(2, 0, 3), com_object: 0 }, GroupLink {
                group_address: GroupAddress::from_three_level(0, 0, 1),
                com_object: 1,
            }];
        project.parameters = vec![ParameterValue { id: "M-00FA_A-0310-01-0000_P-1".to_string(), value: vec![0xEE] }];

        let c = compile(&mask, &product, &project).expect("compiles");
        assert_eq!(c.path(), LoadControlPath::Direct);

        // One region: the whole 256-byte EEPROM window at 0100h.
        let (address, bytes) = c.image.regions().next().expect("the EEPROM segment");
        assert_eq!((address, bytes.len()), (0x0100, 256));

        // ADT spliced at offset 22 (0116h): length counts the IA slot,
        // then the IA, then the sorted group addresses — and the ramp
        // survives on both sides of the splice.
        assert_eq!(&bytes[22..29], &[3, 0x11, 0x2A, 0x00, 0x01, 0x10, 0x03]);
        assert_eq!(bytes[21], 21, "the byte before the ADT keeps its vendor value");
        assert_eq!(bytes[29], 29, "the byte after the ADT keeps its vendor value");

        // AST spliced at offset 60: row n is ASAP n's sending
        // association. This deliberately opposes TSAP sort order.
        assert_eq!(&bytes[60..65], &[2, 2, 0, 1, 1]);

        // COT at offset 80: the vendor data there is a table the
        // firmware owns, so it is overlaid, not replaced — count and
        // data pointers keep their vendor bytes, each object's config
        // (with RT1's forced bit 7) and type are ours.
        assert_eq!(bytes[80], 80, "vendor count byte survives");
        assert_eq!(bytes[82], 82, "object 0 keeps its vendor data pointer");
        assert_eq!(bytes[83], 0x17 | 0x80, "object 0 config, bit 7 forced");
        assert_eq!(bytes[84], 0x00, "object 0 type (1 Bit)");
        assert_eq!(bytes[86], 0x4F | 0x80, "object 1 config, bit 7 forced");

        // The parameter patch landed over the ramp.
        assert_eq!(bytes[200], 0xEE);

        // The fixup resolved U_GetTMx against MV-0012: 3436 = 0D6Ch,
        // big-endian at offset 239 — on the program's own mask this
        // rewrites the vendor bytes with the same routine's address.
        assert_eq!(&bytes[239..241], &[0x0D, 0x6C]);

        // The procedure is the mask template: no LSM instructions,
        // the GA-len snapshot present, image writes with verify.
        assert!(!c.instructions.iter().any(|i| matches!(i, Instruction::LsmEvent { .. })));
        assert!(c.instructions.contains(&Instruction::ReadIntoImage { address: 0x0116, length: 1 }));
        assert!(c.instructions.contains(&Instruction::WriteImage { address: 0x0119, length: 230, verify: true }));
    }

    #[test]
    fn bcu1_capacity_counts_required_unused_sending_slots() {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0012).expect("fixture");
        let mask = db.mask(MaskVersion::Bcu1Tp1).expect("0012");
        let mut product =
            ProductData::from_mtxml_str(crate::download::product::tests::BCU1_MTXML).expect("fixture parses");
        product.association_table_max_entries = Some(1);

        // The product declares ASAPs 0 and 1. Even with no links, RT1
        // requires two indexed FEh placeholder rows, so a one-row table
        // cannot hold the application.
        let project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        assert!(matches!(compile(&mask, &product, &project), Err(Error::DownloadConfig(_))));
    }

    /// A BCU1 program compiled for a BCU2 device (the DD0-selected
    /// mask): the *procedure* is MV-0020's — property path, LSM
    /// cycling, task records, and **no** implicit segment writes
    /// (`EnableSegmentWrite=false`: the template carries its own data
    /// phase after LoadCompleted, and the ETS trace of this download
    /// writes nothing during Loading) — while the *tables* keep the
    /// product's RT1 realization (config bit 7 forced).
    #[test]
    fn bcu1_program_compiles_for_a_bcu2_device() {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0020).expect("fixture");
        let mask = db.mask(MaskVersion::Other(0x0020)).expect("0020");
        let product = ProductData::from_mtxml_str(crate::download::product::tests::BCU1_MTXML).expect("fixture parses");

        let mut project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        project.links = vec![GroupLink { group_address: GroupAddress::from_three_level(2, 0, 3), com_object: 1 }];

        let c = compile(&mask, &product, &project).expect("compiles");
        assert_eq!(c.path(), LoadControlPath::Property);

        // The application is halted (RunError 010Dh ← 00) right after
        // Connect, *before* the LSM cycle — LoadCompleted (re)starts
        // the user code, and doing that to a running device mid-
        // download wedges it.
        assert!(matches!(c.instructions[0], Instruction::Connect));
        assert_eq!(c.instructions[1], Instruction::WriteMemory { address: 0x010D, data: vec![0x00], verify: true });
        let first_lsm = c
            .instructions
            .iter()
            .position(|i| matches!(i, Instruction::LsmEvent { .. }))
            .expect("the template cycles machines");
        assert!(first_lsm > 1, "the halt precedes every LSM event");

        // The MV-0020 template's machinery is all there…
        assert!(c.instructions.iter().any(|i| matches!(i, Instruction::LsmEvent { .. })));
        assert!(c.instructions.iter().any(|i| matches!(i, Instruction::TaskPointers { lsm: LsmTarget::Index(3), .. })));
        assert!(c.instructions.iter().any(|i| matches!(i, Instruction::TaskControl2 { callback: 20609, .. })));

        // …and no implicit write landed inside the Loading window: the
        // first WriteImage comes after machine 3's LoadCompleted.
        let completed = c
            .instructions
            .iter()
            .position(|i| {
                matches!(i, Instruction::LsmEvent { lsm: LsmTarget::Index(3), event: LoadEvent::LoadCompleted })
            })
            .expect("LoadCompleted 3");
        let first_write = c
            .instructions
            .iter()
            .position(|i| matches!(i, Instruction::WriteImage { .. }))
            .expect("the template's data phase");
        assert!(first_write > completed, "EnableSegmentWrite=false suppresses the implicit data phase");

        // The tables follow the *device's* realization: on the BCU2
        // the config octet is plain RT2 flags — no forced bit 7. ETS
        // writes exactly this asymmetry (D3/93 to a real 0012, 53/13
        // to a 0020 carrying the same program).
        let (address, bytes) = c.image.regions().next().expect("the EEPROM segment");
        assert_eq!(address, 0x0100);
        assert_eq!(bytes[83], 0x17, "object 0 config is plain RT2 flags on the BCU2");

        // The fixup resolved U_GetTMx against the *device's* mask:
        // MV-0020's 20579 = 5063h — the code would call MV-0012's
        // 0D6Ch into nowhere otherwise (the crash the ETS trace's
        // ApplyFixupsTask exists to prevent).
        assert_eq!(&bytes[239..241], &[0x50, 0x63]);
    }

    #[test]
    fn secure_bcu2_uses_extended_memory_and_loads_security_by_type() {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0020).expect("fixture");
        let mask = db.mask(MaskVersion::Other(0x0020)).expect("0020");
        let mut product =
            ProductData::from_mtxml_str(crate::download::product::tests::BCU1_MTXML).expect("fixture parses");
        product.is_secure_enabled = true;
        product.max_security_group_key_table_entries = Some(2);
        product.max_security_individual_address_entries = Some(2);
        product.max_security_p2p_key_table_entries = Some(0);

        let ga_low = GroupAddress::from_three_level(0, 0, 1);
        let ga_high = GroupAddress::from_three_level(2, 0, 3);
        let mut project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        // Deliberately unsorted: the key table must use the compiled ADT's
        // sorted, one-based indices rather than declaration order.
        project.links = vec![GroupLink { group_address: ga_high, com_object: 1 }, GroupLink {
            group_address: ga_low,
            com_object: 0,
        }];
        project.max_apdu = 40;
        project.security = Some(SecurityConfig {
            group_keys: vec![(ga_high, [0xA5; 16]), (ga_low, [0x5A; 16])],
            siat: vec![(IndividualAddress::new(1, 2, 3), 0x0102_0304_0506)],
            go_flags: vec![3, 1],
        });

        let compiled = compile(&mask, &product, &project).expect("secure download compiles");
        assert_eq!(compiled.memory_service, MemoryService::Extended);
        assert!(
            !compiled.instructions.iter().any(|instruction| {
                matches!(instruction, Instruction::TaskSegment { lsm: LsmTarget::Index(5), .. })
            })
        );

        let target = LsmTarget::ObjectType { object_type: 0x0011, occurrence: 1 };
        let security_start = compiled
            .instructions
            .iter()
            .position(|instruction| {
                matches!(instruction, Instruction::LsmEvent { lsm, event: LoadEvent::Unload } if *lsm == target)
            })
            .expect("Security IO unload");
        let restart = compiled
            .instructions
            .iter()
            .position(|instruction| matches!(instruction, Instruction::Restart))
            .expect("restart");
        assert!(security_start < restart);

        let phase = &compiled.instructions[security_start..restart];
        assert!(matches!(phase[0], Instruction::LsmEvent { lsm, event: LoadEvent::Unload } if lsm == target));
        assert!(matches!(phase[1], Instruction::LsmEvent { lsm, event: LoadEvent::StartLoading } if lsm == target));
        let key_rows: Vec<&Vec<u8>> = phase
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::WritePropertyExt {
                    prop_id: pid::security::GROUP_KEY_TABLE, start_idx: 1.., data, ..
                } => Some(data),
                _ => None,
            })
            .collect();
        assert_eq!(key_rows.len(), 2);
        assert_eq!(&key_rows[0][..2], &[0, 1], "lower GA has ADT index 1");
        assert_eq!(&key_rows[0][2..], &[0x5A; 16]);
        assert_eq!(&key_rows[1][..2], &[0, 2], "higher GA has ADT index 2");
        assert_eq!(&key_rows[1][2..], &[0xA5; 16]);

        assert!(phase.iter().any(|instruction| {
            matches!(instruction, Instruction::WritePropertyExt {
                prop_id: pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
                start_idx: 1,
                data,
                ..
            } if data == &[0x12, 0x03, 1, 2, 3, 4, 5, 6])
        }));
        assert!(matches!(
            phase[phase.len() - 2],
            Instruction::LsmEvent { lsm, event: LoadEvent::LoadCompleted } if lsm == target
        ));
        assert!(matches!(
            phase.last(),
            Some(Instruction::FunctionPropertyExt {
                object_type: 0x0011,
                occurrence: 1,
                prop_id: pid::security::SECURITY_MODE,
                service_id: 0,
                service_info: 1,
            })
        ));
    }

    #[test]
    fn secure_table_capacities_are_enforced_before_assembly() {
        let mut product = product();
        product.is_secure_enabled = true;
        product.max_security_group_key_table_entries = Some(0);
        product.max_security_individual_address_entries = Some(0);
        let mut project = project();
        project.security = Some(SecurityConfig {
            group_keys: vec![(project.links[0].group_address, [0x11; 16])],
            ..Default::default()
        });

        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        assert!(matches!(compile(&mask, &product, &project), Err(Error::DownloadConfig(_))));
    }

    /// The BCU1 fixture with `DynamicTableManagement="true"` — the
    /// converted-program shape ETS lays tables out dynamically for.
    fn dtm_product() -> ProductData {
        let xml = crate::download::product::tests::BCU1_MTXML
            .replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"");
        ProductData::from_mtxml_str(&xml).expect("the converted fixture parses")
    }

    fn compile_dtm(project: &ProjectConfig) -> CompiledDownload {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0012).expect("fixture");
        let mask = db.mask(MaskVersion::Bcu1Tp1).expect("0012");
        compile(&mask, &dtm_product(), project).expect("compiles")
    }

    /// Dynamic table management, nothing linked: the association table
    /// is packed right behind the one-entry ADT and carries a TSAP FEh
    /// placeholder per group object — the exact bytes ETS wrote to the
    /// bench device (BCU1.log: ADT `01 00 00` at 0116h, AST
    /// `03 FE 00 FE 01 FE 02` at 0119h, `$0111 ← 19`; our fixture has
    /// two objects instead of three).
    #[test]
    fn dtm_packs_placeholder_associations_behind_the_adt() {
        let project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        let c = compile_dtm(&project);

        let (address, bytes) = c.image.regions().next().expect("the EEPROM segment");
        assert_eq!(address, 0x0100);

        // ADT at offset 22: just the IA slot.
        assert_eq!(&bytes[22..25], &[1, 0x11, 0x2A]);
        // AST packed at 25 (0119h): both objects unlinked.
        assert_eq!(&bytes[25..30], &[2, 0xFE, 0, 0xFE, 1]);
        // AssocTabPtr at 0111h repointed (Ptr_StandardMemory100).
        assert_eq!(bytes[17], 0x19);
        // The vendor AST offset keeps its ramp bytes, unread through
        // the repointed table.
        assert_eq!(&bytes[60..65], &[60, 61, 62, 63, 64]);
    }

    /// Dynamic table management with a link: the ADT grows, the packed
    /// AST moves with it, and the pointer follows — the linked object
    /// keeps its real TSAP while the other still gets the placeholder.
    #[test]
    fn dtm_relocation_follows_the_grown_adt() {
        let mut project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        project.links = vec![GroupLink { group_address: GroupAddress::from_three_level(0, 0, 1), com_object: 0 }];
        let c = compile_dtm(&project);

        let (_, bytes) = c.image.regions().next().expect("the EEPROM segment");
        assert_eq!(&bytes[22..27], &[2, 0x11, 0x2A, 0x00, 0x01]);
        assert_eq!(&bytes[27..32], &[2, 1, 0, 0xFE, 1]);
        assert_eq!(bytes[17], 0x1B);
    }

    /// The slot rule of 03/05/01 §4.17.3.4.1: association `i` carries
    /// ASAP `i`'s sending TSAP — RT2 devices index that slot on a
    /// transmission request, so the table must NOT be re-sorted by
    /// TSAP. Objects linked "in reverse" (object 0 on the higher
    /// group address) and an object with a second, non-sending link
    /// pin both halves of the rule.
    #[test]
    fn dtm_association_slots_follow_the_asap_not_the_tsap_order() {
        let mut project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        project.links = vec![
            // Object 0's first link is its sending association — the
            // higher GA, so its TSAP (2) sorts *after* object 1's.
            GroupLink { group_address: GroupAddress::from_three_level(0, 0, 2), com_object: 0 },
            GroupLink { group_address: GroupAddress::from_three_level(0, 0, 1), com_object: 1 },
            // A second link on object 0: a non-sending association,
            // placed after the slot range.
            GroupLink { group_address: GroupAddress::from_three_level(0, 0, 1), com_object: 0 },
        ];
        let c = compile_dtm(&project);

        let (_, bytes) = c.image.regions().next().expect("the EEPROM segment");
        // ADT: two GAs. AST packed behind it at 0119h + 4 = offset 29.
        assert_eq!(&bytes[22..29], &[3, 0x11, 0x2A, 0x00, 0x01, 0x00, 0x02]);
        assert_eq!(&bytes[29..36], &[
            3, // slots for ASAP 0..=1, one extra
            2, 0, // slot 0: ASAP 0 sends through TSAP 2 (GA 0/0/2)
            1, 1, // slot 1: ASAP 1 sends through TSAP 1 (GA 0/0/1)
            1, 0, // non-sending: ASAP 0 also listens on TSAP 1
        ]);
        assert_eq!(bytes[17], 0x1D, "AssocTabPtr follows the three-entry ADT");
    }

    /// A native-BCU2-shaped converted program: dedicated, contiguous
    /// table segments (the L&J MV-0021 reference declares ADT 0116h,
    /// AST 01C6h, COT 0274h back to back). The packed association
    /// table starts inside the ADT segment and, when long enough, runs
    /// across the declared boundary into the AST segment — the
    /// relocation arithmetic is absolute addresses, not segment
    /// offsets.
    #[test]
    fn dtm_packed_ast_straddles_dedicated_segments() {
        let xml = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-0311-01-0000" ApplicationNumber="785" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0020" Name="BCU2 Switch" LoadProcedureStyle="DefaultProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="true" Linkable="false">
      <Static>
        <Code>
          <AbsoluteSegment Id="M-00FA_A-0311-01-0000_AS-0100" Address="256" Size="22" MemoryType="EEPROM" />
          <AbsoluteSegment Id="M-00FA_A-0311-01-0000_AS-ADT" Address="278" Size="9" MemoryType="EEPROM" />
          <AbsoluteSegment Id="M-00FA_A-0311-01-0000_AS-AST" Address="287" Size="7" MemoryType="EEPROM" />
          <AbsoluteSegment Id="M-00FA_A-0311-01-0000_AS-COT" Address="294" Size="8" MemoryType="EEPROM" />
        </Code>
        <ComObjectTable CodeSegment="M-00FA_A-0311-01-0000_AS-COT" Offset="0">
          <ComObject Id="M-00FA_A-0311-01-0000_O-0" Name="Switch" Text="Switch" Number="0" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
          <ComObject Id="M-00FA_A-0311-01-0000_O-1" Name="Status" Text="Status" Number="1" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Enabled" WriteFlag="Disabled" CommunicationFlag="Enabled" TransmitFlag="Enabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
        </ComObjectTable>
        <AddressTable CodeSegment="M-00FA_A-0311-01-0000_AS-ADT" Offset="0" MaxEntries="3" />
        <AssociationTable CodeSegment="M-00FA_A-0311-01-0000_AS-AST" Offset="0" MaxEntries="3" />
        <LoadProcedures />
      </Static>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;
        let product = ProductData::from_mtxml_str(xml).expect("the fixture parses");
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0020).expect("fixture");
        let mask = db.mask(MaskVersion::Other(0x0020)).expect("0020");

        let mut project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        project.links = vec![GroupLink { group_address: GroupAddress::from_three_level(0, 0, 1), com_object: 0 }];
        let c = compile(&mask, &product, &project).expect("compiles");

        // ADT fills 5 of its segment's 9 bytes; the packed AST needs
        // another 5, so its last byte crosses into the AST segment.
        assert_eq!(c.image.slice(0x0116, 9).expect("the ADT segment region"), [
            2, 0x11, 0x2A, 0x00, 0x01, // ADT: len 2, IA, GA 0/0/1
            2, 1, 0, 0xFE, // AST head: count 2, (1, 0), placeholder…
        ]);
        assert_eq!(
            c.image.slice(0x011F, 1).expect("the AST segment region"),
            [1],
            "…(FE, 1) completes across the boundary"
        );
        // AssocTabPtr repointed at the packed table's start.
        assert_eq!(c.image.slice(0x0111, 1).expect("the pointer block region"), [0x1B]);
    }

    /// The packed pair must stop short of the group object table: a
    /// converted program whose COT leaves no room fails to compile
    /// rather than silently overlapping.
    #[test]
    fn dtm_rejects_tables_running_into_the_group_object_table() {
        let xml = crate::download::product::tests::BCU1_MTXML
            .replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"")
            .replace(
                "<ComObjectTable CodeSegment=\"M-00FA_A-0310-01-0000_AS-0100\" Offset=\"80\">",
                "<ComObjectTable CodeSegment=\"M-00FA_A-0310-01-0000_AS-0100\" Offset=\"27\">",
            );
        let product = ProductData::from_mtxml_str(&xml).expect("the fixture parses");
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0012).expect("fixture");
        let mask = db.mask(MaskVersion::Bcu1Tp1).expect("0012");

        let project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        // ADT ends at 25, the packed AST needs 25..30, the COT starts
        // at 27.
        let err = compile(&mask, &product, &project).expect_err("the packed tables overlap the COT");
        assert!(matches!(err, Error::DownloadConfig(_)));
    }

    /// device-assigned base instead.
    #[test]
    fn relative_segments_are_skipped_in_the_absolute_image() {
        use crate::download::product::Segment;
        let mut product = product();
        product.segments.push(Segment {
            id: "rel".to_string(),
            address: None,
            size: 16,
            memory_type: None,
            load_state_machine: Some(3),
            data: vec![9; 16],
        });
        let mut project = project();
        project.links = vec![GroupLink { group_address: GroupAddress::from_three_level(0, 0, 2), com_object: 1 }];
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let c = compile(&mask, &product, &project).expect("compiles");
        // No absolute region carries the relative segment's 0x09 fill.
        assert!(
            c.image.regions().all(|(_, bytes)| bytes != vec![9u8; 16].as_slice()),
            "the address-less segment must not land in the absolute image"
        );
        assert_eq!(c.image.relative_objects().count(), 0, "an absolute-model image has no relative half");
    }
}
