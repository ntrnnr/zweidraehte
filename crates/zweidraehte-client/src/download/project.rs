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

use std::collections::{BTreeMap, BTreeSet};

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::apdu::load_control::LoadEvent;
use zweidraehte_proto::pid;
use zweidraehte_proto::security::{SEQ6_MAX, u64_to_seq6};

use zweidraehte_knxprod::schema::LoadControl;
use zweidraehte_project::SecretBytes;

use super::assemble::{DownloadScope, assemble_controls, procedure_kind_for_scope};
use super::image::DeviceImage;
use super::interpreter::{DownloadOutcome, DownloadTarget, Downloader, LoadControlPath, MemoryService, ProgressSink};
use super::ir::{Instruction, LsmTarget, controls_to_instructions};
use super::mask::{LsmModel, MachineRole, MaskData};
use super::model::{DownloadModel, ImageLayout, Placement};
use super::product::{ParameterLocation, ProductData, PropertyObject};
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
#[derive(Clone, Default)]
pub struct SecurityConfig {
    group_keys: Vec<(GroupAddress, SecretBytes)>,
    siat: Vec<(IndividualAddress, u64)>,
    /// Protection by semantic communication-object number. The mask
    /// backend materializes the dense table using its own ASAP base.
    group_objects: Vec<GroupObjectSecurity>,
}

impl SecurityConfig {
    pub fn new(
        group_keys: Vec<(GroupAddress, [u8; 16])>,
        siat: Vec<(IndividualAddress, u64)>,
        group_objects: Vec<GroupObjectSecurity>,
    ) -> Self {
        Self {
            group_keys: group_keys.into_iter().map(|(address, key)| (address, key.into())).collect(),
            siat,
            group_objects,
        }
    }

    pub fn group_keys(&self) -> impl ExactSizeIterator<Item = (GroupAddress, &[u8; 16])> {
        self.group_keys.iter().map(|(address, key)| (*address, key.key16_ref().expect("group keys have fixed width")))
    }

    pub fn siat(&self) -> &[(IndividualAddress, u64)] {
        &self.siat
    }

    pub fn group_objects(&self) -> &[GroupObjectSecurity] {
        &self.group_objects
    }

    pub(crate) fn replace_siat(&mut self, siat: Vec<(IndividualAddress, u64)>) {
        self.siat = siat;
    }
}

impl core::fmt::Debug for SecurityConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SecurityConfig")
            .field("group_keys", &format_args!("[REDACTED; {} entries]", self.group_keys.len()))
            .field("siat", &self.siat)
            .field("group_objects", &self.group_objects)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupObjectSecurity {
    pub com_object: u16,
    pub protection: GroupObjectProtection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GroupObjectProtection {
    Plain,
    Authentication,
    AuthenticationConfidentiality,
}

impl GroupObjectProtection {
    fn code(self) -> u8 {
        match self {
            Self::Plain => 0,
            Self::Authentication => 1,
            Self::AuthenticationConfidentiality => 3,
        }
    }
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
    /// Property reporting Application Program 1's runtime state. Kept with
    /// the compiled mask facts so verification cannot re-derive a different
    /// object index from the product family.
    application_run_state_property: Option<(u8, u16)>,
    /// The procedure actually selected. A requested partial scope may become
    /// full when the mask has no compatible remote procedure.
    scope: DownloadScope,
}

impl CompiledDownload {
    /// The load-control path this download drives.
    pub fn path(&self) -> LoadControlPath {
        self.path
    }

    pub fn scope(&self) -> DownloadScope {
        self.scope
    }

    pub(crate) fn application_run_state_property(&self) -> Option<(u8, u16)> {
        self.application_run_state_property
    }

    /// Execute the download against a device.
    ///
    /// `max_apdu` is the plaintext management-APDU budget available to this
    /// procedure. For plain access that is PID 56 directly; a caller using
    /// Data Secure subtracts the S-A_Data envelope first. Some procedures
    /// restart the device themselves while later management models commonly
    /// end with a disconnect marker and leave the final confirmed restart to
    /// the programming orchestrator.
    pub async fn execute<T: DownloadTarget>(&self, target: &mut T, max_apdu: u16) -> Result<()> {
        self.execute_inner(target, max_apdu, None).await.map(|_| ())
    }

    /// Execute the download while reporting interpreter progress.
    pub async fn execute_with_progress<T: DownloadTarget>(
        &self,
        target: &mut T,
        max_apdu: u16,
        progress: ProgressSink<'_>,
    ) -> Result<()> {
        self.execute_inner(target, max_apdu, Some(progress)).await.map(|_| ())
    }

    /// Execute while retaining the process time from a confirmed restart.
    /// The programming layer closes the connection before waiting for it.
    pub(crate) async fn execute_with_progress_outcome<T: DownloadTarget>(
        &self,
        target: &mut T,
        max_apdu: u16,
        progress: ProgressSink<'_>,
    ) -> Result<DownloadOutcome> {
        self.execute_inner(target, max_apdu, Some(progress)).await
    }

    async fn execute_inner<'a, T: DownloadTarget>(
        &self,
        target: &'a mut T,
        max_apdu: u16,
        progress: Option<ProgressSink<'a>>,
    ) -> Result<DownloadOutcome> {
        let mut downloader =
            Downloader::with_path(target, self.path, max_apdu).with_memory_service(self.memory_service, max_apdu);
        if !self.authorize {
            downloader = downloader.without_authorize();
        }
        if self.diff_writes {
            downloader = downloader.with_diffed_writes();
        }
        if let Some(progress) = progress {
            downloader = downloader.with_progress(progress);
        }
        downloader.run_with_outcome(&self.instructions, &self.image).await
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
    compile_scoped(mask, product, project, DownloadScope::Full)
}

/// Compile the smallest safe procedure for an already-deployed application.
///
/// Partial support is optional mask data. If a mask has no suitable remote
/// procedure, or its partial procedure cannot be assembled with this product,
/// compilation returns the ordinary full flow. The fallback happens before
/// any bus access, preserving the caller's preflight guarantee.
pub fn compile_scoped(
    mask: &MaskData<'_>,
    product: &ProductData,
    project: &ProjectConfig,
    requested_scope: DownloadScope,
) -> Result<CompiledDownload> {
    match compile_selected(mask, product, project, requested_scope) {
        Ok(compiled) => Ok(compiled),
        Err(partial_error) if requested_scope != DownloadScope::Full => {
            log::warn!(
                "cannot compile {:?} download for mask {}: {}; falling back to full",
                requested_scope,
                mask.version(),
                partial_error
            );
            compile_selected(mask, product, project, DownloadScope::Full)
        }
        Err(error) => Err(error),
    }
}

fn compile_selected(
    mask: &MaskData<'_>,
    product: &ProductData,
    project: &ProjectConfig,
    requested_scope: DownloadScope,
) -> Result<CompiledDownload> {
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
    let dtm: Option<DynamicTableOptions> = if product.dynamic_table_management
        && matches!(model.management_model, "Bcu1" | "Bcu2")
    {
        Some(DynamicTableOptions {
            pointer_address: mask.standard_memory_address("GroupAssociationTablePtr").ok_or(Error::DownloadConfig(
                "this program needs dynamic table management, but the mask locates no GroupAssociationTablePtr",
            ))?,
            // BCU2 allocates absolute segments on word boundaries. BCU1's
            // direct-memory layout does not: ETS places an empty program's
            // three-byte ADT at 0116h and its AST immediately at 0119h.
            association_alignment: if model.management_model == "Bcu2" { 2 } else { 1 },
        })
    } else {
        None
    };

    let mut image = DeviceImage::new();
    build_image(&mut image, &model.layout, &mask.lsm_model(), product, project, dtm)?;
    patch_standard_image_resources(&mut image, mask, product)?;
    apply_fixups(&mut image, mask, product)?;

    // System B can carry a second application (historically called the PEI
    // program). Its merge-3/merge-5 fragments are the product-side evidence
    // that `Load/all` has actual AP2 data to allocate and write. Without
    // those fragments ETS selects `Load/ap1`. Object index 5 alone cannot
    // make that decision: 03/05/03 §3.9.3.3 requires the fixed AP2 object
    // to remain present, in state Unloaded, when the product does not use it.
    let procedure_kind = procedure_kind_for_scope(mask, product, requested_scope);
    let actual_scope = procedure_kind.scope();
    log::debug!("assembling {:?} for product {}", procedure_kind, product.id);
    let controls = assemble_controls(mask, product, procedure_kind)?;
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
    let assembled = if let Some(options) = dtm {
        finalize_dynamic_table_controls(
            assembled,
            &mask.lsm_model(),
            dynamic_table_layout(product, project, options.association_alignment)?,
        )?
    } else {
        assembled
    };
    let assembled = resolve_property_steps(assembled, product, project)?;
    let assembled = patch_application_identity_property(assembled, mask, product);
    let assembled = constrain_property_write_widths(assembled, mask)?;
    let assembled = if model.management_model == "Bcu2" {
        omit_legacy_bcu2_object_table_announcement(assembled)
    } else {
        assembled
    };
    let instructions = resolve_relative_steps(assembled, &image);
    let instructions = if implicit_writes { insert_image_writes(instructions, &image) } else { instructions };
    let instructions = if model.halt_app_first && actual_scope == DownloadScope::Full {
        halt_application_first(instructions, mask)?
    } else {
        instructions
    };
    let instructions = if model.confirmed_procedure_restart {
        instructions
            .into_iter()
            .map(
                |instruction| {
                    if instruction == Instruction::Restart { Instruction::ConfirmedRestart } else { instruction }
                },
            )
            .collect()
    } else {
        instructions
    };
    let instructions = if actual_scope.includes_group_communication() {
        inject_security_phase(instructions, product, project, model.layout.first_asap)?
    } else {
        instructions
    };

    Ok(CompiledDownload {
        image,
        instructions,
        path,
        memory_service,
        authorize: model.authorize_on_connect,
        diff_writes: model.diff_writes,
        application_run_state_property: mask.application_run_state_property(),
        scope: actual_scope,
    })
}

/// Resolve the all-zero `ApplicationId` placeholder in mask-owned load
/// procedures. ETS performs the same device-image substitution before it
/// executes the controls; sending the literal placeholder leaves PID 13 at
/// zero and makes every later differential compatibility check fail.
fn patch_application_identity_property(
    instructions: Vec<Instruction>,
    mask: &MaskData<'_>,
    product: &ProductData,
) -> Vec<Instruction> {
    let Some((application_object, application_property)) = mask.application_id_property() else {
        return instructions;
    };
    instructions
        .into_iter()
        .map(|instruction| match instruction {
            Instruction::WriteProperty { obj_idx, prop_id, start_idx, count, verify, .. }
                if obj_idx == application_object && prop_id == application_property =>
            {
                Instruction::WriteProperty {
                    obj_idx,
                    prop_id,
                    start_idx,
                    count,
                    data: product.task_identity.application_id.to_vec().into(),
                    verify,
                }
            }
            other => other,
        })
        .collect()
}

/// `LdCtrlWriteProp/@InlineData` is a tool-side buffer, not necessarily the
/// exact wire value. ETS constrains it using the property's PDT from master
/// data. Real System B products rely on this: their PID_MCB_TABLE rows carry
/// ten padded bytes in MTXML although PDT_GENERIC_08 permits exactly eight.
fn constrain_property_write_widths(instructions: Vec<Instruction>, mask: &MaskData<'_>) -> Result<Vec<Instruction>> {
    instructions
        .into_iter()
        .map(|mut instruction| {
            let (element_size, count, data, description) = match &mut instruction {
                Instruction::WriteProperty { obj_idx, prop_id, count, data, .. } => (
                    mask.indexed_property_element_size(*obj_idx, *prop_id),
                    *count,
                    data,
                    format!("object {obj_idx} property {prop_id}"),
                ),
                Instruction::WritePropertyExt { object_type, prop_id, count, data, .. } => (
                    mask.typed_property_element_size(*object_type, *prop_id),
                    *count,
                    data,
                    format!("{object_type} property {prop_id}"),
                ),
                _ => return Ok(instruction),
            };
            let Some(element_size) = element_size else { return Ok(instruction) };
            let expected = element_size
                .checked_mul(usize::from(count))
                .ok_or(Error::DownloadConfig("property write size overflows the host address space"))?;
            if data.len() < expected {
                return Err(Error::ProductData(format!(
                    "{description} provides {} data bytes for {count} element(s) of {element_size} bytes",
                    data.len()
                )));
            }
            data.truncate(expected);
            Ok(instruction)
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DynamicTableLayout {
    pub(super) address_start: u16,
    pub(super) association_start: u16,
    pub(super) object_start: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DynamicTableOptions {
    pointer_address: u16,
    association_alignment: u32,
}

/// Calculate the compact BCU table allocation ETS derives from the actual
/// project links. The address and association allocations meet at a
/// word-aligned boundary; the association allocation then extends to the
/// fixed group-object table.
pub(super) fn dynamic_table_layout(
    product: &ProductData,
    project: &ProjectConfig,
    association_alignment: u32,
) -> Result<DynamicTableLayout> {
    let segment_start = |id: &Option<String>, offset: u32, what: &'static str| -> Result<u32> {
        let base = id
            .as_deref()
            .and_then(|id| product.segments.iter().find(|segment| segment.id == id))
            .and_then(|segment| segment.address)
            .ok_or(Error::DownloadConfig(what))?;
        Ok(u32::from(base) + offset)
    };
    let address_start = segment_start(
        &product.address_table_segment,
        product.address_table_offset,
        "dynamic table management needs an addressed group address table",
    )?;
    let object_start = segment_start(
        &product.com_object_table_segment,
        product.com_object_table_offset,
        "dynamic table management needs an addressed group object table",
    )?;
    let group_count = project.links.iter().map(|link| link.group_address).collect::<BTreeSet<_>>().len();
    let address_len = 3usize
        .checked_add(group_count.checked_mul(2).ok_or(Error::DownloadConfig("group address table is too large"))?)
        .ok_or(Error::DownloadConfig("group address table is too large"))?;
    let association_start = (address_start + address_len as u32).next_multiple_of(association_alignment);
    if association_start >= object_start {
        return Err(Error::DownloadConfig("dynamic address table leaves no room for the association table"));
    }
    Ok(DynamicTableLayout {
        address_start: u16::try_from(address_start)
            .map_err(|_| Error::DownloadConfig("dynamic address table lies outside the 16-bit address space"))?,
        association_start: u16::try_from(association_start)
            .map_err(|_| Error::DownloadConfig("dynamic association table lies outside the 16-bit address space"))?,
        object_start: u16::try_from(object_start)
            .map_err(|_| Error::DownloadConfig("group object table lies outside the 16-bit address space"))?,
    })
}

/// Rewrite the product procedure's maximum-size ADT/AST allocations to the
/// compact dynamic layout. ETS changes both allocation records and their task
/// records; changing only the image bytes assigns the relocated association
/// table to the wrong load-state machine on real BCU2 hardware.
fn finalize_dynamic_table_controls(
    instructions: Vec<Instruction>,
    model: &LsmModel,
    layout: DynamicTableLayout,
) -> Result<Vec<Instruction>> {
    let address_lsm = model.object_of(MachineRole::GroupAddressTable).map(LsmTarget::Index);
    let association_lsm = model.object_of(MachineRole::GroupAssociationTable).map(LsmTarget::Index);
    if address_lsm.is_none() && association_lsm.is_none() {
        return Ok(instructions);
    }
    let address_len = layout.association_start - layout.address_start;
    let association_len = layout.object_start - layout.association_start;

    Ok(instructions
        .into_iter()
        .map(|instruction| match instruction {
            Instruction::AbsSegment { lsm, mut segment } if Some(lsm) == address_lsm => {
                segment.start_address = layout.address_start;
                segment.length = address_len;
                Instruction::AbsSegment { lsm, segment }
            }
            Instruction::AbsSegment { lsm, mut segment } if Some(lsm) == association_lsm => {
                segment.start_address = layout.association_start;
                segment.length = association_len;
                Instruction::AbsSegment { lsm, segment }
            }
            Instruction::TaskSegment { lsm, pei_type, application_id, .. } if Some(lsm) == address_lsm => {
                Instruction::TaskSegment { lsm, address: layout.address_start, pei_type, application_id }
            }
            Instruction::TaskSegment { lsm, pei_type, application_id, .. } if Some(lsm) == association_lsm => {
                Instruction::TaskSegment { lsm, address: layout.association_start, pei_type, application_id }
            }
            other => other,
        })
        .collect())
}

/// Fill mask-owned application identity resources after the sparse product
/// image exists. Master data locates these fields; hard-coding BCU2's 0103h
/// and 0109h would break compatibility-mode and other mask layouts.
fn patch_standard_image_resources(image: &mut DeviceImage, mask: &MaskData<'_>, product: &ProductData) -> Result<()> {
    for (name, bytes) in [
        ("ApplicationId", product.task_identity.application_id.as_slice()),
        ("ApplicationPeiType", core::slice::from_ref(&product.task_identity.pei_type)),
    ] {
        let Some(address) = mask.standard_memory_address(name) else { continue };
        let start = u32::from(address);
        let end = start + bytes.len() as u32;
        let belongs_to_product = product.segments.iter().any(|segment| {
            segment.address.is_some_and(|base| {
                let base = u32::from(base);
                start >= base && end <= base + segment.size
            })
        });
        if belongs_to_product {
            image.overwrite(address, bytes)?;
        }
    }
    Ok(())
}

/// Materialize the data block of each non-inline `LdCtrlWriteProp` from
/// property-backed parameters. ETS keeps these values outside every memory
/// segment; resolving them here preserves the same preflight-before-bus-write
/// guarantee as ordinary parameter image construction.
fn resolve_property_steps(
    instructions: Vec<Instruction>,
    product: &ProductData,
    project: &ProjectConfig,
) -> Result<Vec<Instruction>> {
    instructions
        .into_iter()
        .map(|instruction| {
            let Instruction::WritePropertyData { target, prop_id, start_idx, count, verify } = instruction else {
                return Ok(instruction);
            };
            let object = match target {
                LsmTarget::Index(index) => PropertyObject::Index(index),
                LsmTarget::ObjectType { object_type, occurrence } => PropertyObject::Type { object_type, occurrence },
            };
            let locations: Vec<_> = product
                .property_parameters
                .iter()
                .filter(|location| location.object == object && location.property_id == prop_id)
                .collect();
            if locations.is_empty() {
                return Err(Error::ProductData(format!(
                    "WriteProp for property {prop_id} has no matching property-backed parameter"
                )));
            }

            let mut data = Vec::new();
            for location in locations {
                let value = project
                    .parameters
                    .iter()
                    .find(|value| value.id == location.id)
                    .ok_or(Error::DownloadConfig("a property-backed parameter has no effective value"))?;
                let patch_location = ParameterLocation {
                    id: location.id.clone(),
                    code_segment: String::new(),
                    offset: location.offset,
                    bit_offset: location.bit_offset,
                    size_bits: location.size_bits,
                    legacy_patch_always: location.legacy_patch_always,
                    seeds_default: false,
                };
                let end = location.offset as usize + patch_span(&patch_location, value)?;
                if end > data.len() {
                    data.resize(end, 0);
                }
                patch_one_parameter(&mut data, &patch_location, value)?;
            }

            match target {
                LsmTarget::Index(obj_idx) => {
                    Ok(Instruction::WriteProperty { obj_idx, prop_id, start_idx, count, data: data.into(), verify })
                }
                LsmTarget::ObjectType { object_type, occurrence } => Ok(Instruction::WritePropertyExt {
                    object_type,
                    occurrence,
                    prop_id,
                    start_idx,
                    count,
                    data: data.into(),
                    verify,
                }),
            }
        })
        .collect()
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

/// Interleave the Security IO load with the ordinary application procedure.
///
/// ETS unloads Security IO after the ordinary unloads, then loads its tables
/// before completing any application/table machine. Keeping that dependency
/// ordering matters on devices whose application run conditions include the
/// Security IO load state. [`InterfaceObjectType::Security`] is deliberately
/// addressed by type: secure BCU2 does not publish it in its four-object
/// indexed roster.
fn inject_security_phase(
    instructions: Vec<Instruction>,
    product: &ProductData,
    project: &ProjectConfig,
    first_asap: u16,
) -> Result<Vec<Instruction>> {
    let Some(security) = &project.security else {
        return Ok(instructions);
    };
    if !product.supports_data_secure {
        return Err(Error::DownloadConfig("security configuration supplied for a product without Data Secure support"));
    }

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
    let go_flags = materialize_go_flags(security, product, first_asap)?;

    let mut group_addresses: Vec<GroupAddress> = project.links.iter().map(|link| link.group_address).collect();
    group_addresses.sort_unstable();
    group_addresses.dedup();

    let mut group_rows = Vec::with_capacity(security.group_keys.len());
    for (address, key) in security.group_keys() {
        let index = group_addresses
            .binary_search(&address)
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

    const OCCURRENCE: u16 = 1;
    let target = LsmTarget::ObjectType { object_type: InterfaceObjectType::Security, occurrence: OCCURRENCE };
    let security_unload = Instruction::LsmEvent { lsm: target, event: LoadEvent::Unload };
    let mut load_phase = vec![Instruction::LsmEvent { lsm: target, event: LoadEvent::StartLoading }];

    push_table_count(&mut load_phase, pid::security::GROUP_KEY_TABLE, group_rows.len())?;
    if !group_rows.is_empty() {
        let mut data = Vec::with_capacity(group_rows.len() * 18);
        for (index, key) in group_rows {
            data.extend_from_slice(&index.to_be_bytes());
            data.extend_from_slice(&key);
        }
        load_phase.push(ext_write(pid::security::GROUP_KEY_TABLE, 1, data.len() / 18, data)?);
    }

    push_table_count(&mut load_phase, pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, siat.len())?;
    if !siat.is_empty() {
        let mut data = Vec::with_capacity(siat.len() * 8);
        for (address, sequence) in siat {
            data.extend_from_slice(&u16::from_be_bytes(address.0).to_be_bytes());
            data.extend_from_slice(&u64_to_seq6(sequence));
        }
        load_phase.push(ext_write(pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 1, data.len() / 8, data)?);
    }

    // PID 61 is not a variable-length table. Its element count is fixed by
    // the Group Object Table and each element has the same index as its GO
    // (03/05/01 §6.3.15). Consequently ETS writes elements 1..N directly;
    // writing element zero asks the device to resize the property and real
    // BCU2 devices reject that with E_DATA_TYPE_CONFLICT. Keep the complete
    // range in one instruction: the interpreter splits it on element
    // boundaries according to the negotiated plaintext APDU, just as ETS
    // does (18 flags per request on the captured secure MV-0021 download).
    if !go_flags.is_empty() {
        load_phase.push(ext_write(pid::security::GO_SECURITY_FLAGS, 1, go_flags.len(), go_flags)?);
    }

    load_phase.push(Instruction::LsmEvent { lsm: target, event: LoadEvent::LoadCompleted });

    let termination = instructions
        .iter()
        .position(|instruction| {
            matches!(instruction, Instruction::Disconnect | Instruction::Restart | Instruction::ConfirmedRestart)
        })
        .unwrap_or(instructions.len());
    let unload_insertion = instructions
        .iter()
        .position(|instruction| matches!(instruction, Instruction::LsmEvent { event: LoadEvent::StartLoading, .. }))
        .unwrap_or(termination);
    let load_insertion = instructions
        .iter()
        .enumerate()
        .skip(unload_insertion)
        .find_map(|(index, instruction)| {
            matches!(instruction, Instruction::LsmEvent { event: LoadEvent::LoadCompleted, .. }).then_some(index)
        })
        .unwrap_or(termination);

    let mut result = Vec::with_capacity(instructions.len() + load_phase.len() + 1);
    result.extend_from_slice(&instructions[..unload_insertion]);
    result.push(security_unload);
    result.extend_from_slice(&instructions[unload_insertion..load_insertion]);
    result.extend(load_phase);
    result.extend_from_slice(&instructions[load_insertion..]);
    Ok(result)
}

/// Convert semantic object numbers into the dense PID 61 rows used by
/// this management model. BCU2/System 7 start at ASAP 0; System B starts
/// at ASAP 1. Callers never need to reproduce that distinction.
fn materialize_go_flags(security: &SecurityConfig, product: &ProductData, first_asap: u16) -> Result<Vec<u8>> {
    let Some(max_asap) = product.com_object_numbers.iter().copied().max() else {
        if security.group_objects.is_empty() {
            return Ok(Vec::new());
        }
        return Err(Error::DownloadConfig("GO security names an object absent from the product"));
    };
    if max_asap < first_asap {
        return Err(Error::DownloadConfig("the product's group objects start below this management model's ASAP base"));
    }

    let mut flags = vec![0; usize::from(max_asap - first_asap) + 1];
    let mut seen = std::collections::BTreeSet::new();
    for object in &security.group_objects {
        if !seen.insert(object.com_object) {
            return Err(Error::DownloadConfig("security configuration repeats a group object"));
        }
        if object.com_object < first_asap
            || !product.effective_com_objects().iter().any(|candidate| candidate.number == object.com_object)
        {
            return Err(Error::DownloadConfig("GO security names an object absent from the product"));
        }
        flags[usize::from(object.com_object - first_asap)] = object.protection.code();
    }
    Ok(flags)
}

fn push_table_count(instructions: &mut Vec<Instruction>, prop_id: u16, count: usize) -> Result<()> {
    let count = u16::try_from(count).map_err(|_| Error::DownloadConfig("security table count exceeds 16 bits"))?;
    instructions.push(Instruction::WritePropertyExt {
        object_type: InterfaceObjectType::Security,
        occurrence: 1,
        prop_id,
        start_idx: 0,
        count: 1,
        data: count.to_be_bytes().to_vec().into(),
        verify: false,
    });
    Ok(())
}

fn ext_write(prop_id: u16, start_idx: usize, count: usize, data: Vec<u8>) -> Result<Instruction> {
    let start_idx =
        u16::try_from(start_idx).map_err(|_| Error::DownloadConfig("security table index exceeds 16 bits"))?;
    let count = u16::try_from(count).map_err(|_| Error::DownloadConfig("security table count exceeds 16 bits"))?;
    Ok(Instruction::WritePropertyExt {
        object_type: InterfaceObjectType::Security,
        occurrence: 1,
        prop_id,
        start_idx,
        count,
        data: data.into(),
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
            out.push(Instruction::WriteMemory { address: run_error, data: vec![0x00].into(), verify: true });
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
    dtm: Option<DynamicTableOptions>,
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
pub(super) fn co_rows(product: &ProductData, first_asap: u16) -> Result<Vec<(ComObjectFlags, ComObjectType)>> {
    let Some(max) = product.com_object_numbers.iter().copied().max() else {
        return Ok(Vec::new());
    };
    if max < first_asap {
        return Err(Error::ProductData(format!(
            "this management model numbers group objects from {first_asap}, but the product roster ends at {max}"
        )));
    }
    let mut rows = vec![(ComObjectFlags::from_byte(0), ComObjectType::Uint1); (max - first_asap) as usize + 1];
    for obj in product.effective_com_objects() {
        if obj.number < first_asap {
            return Err(Error::ProductData(format!(
                "this management model numbers group objects from {first_asap}, but the product declares object {}",
                obj.number
            )));
        }
        let row = usize::from(obj.number - first_asap);
        if row >= rows.len() {
            return Err(Error::ProductData(format!(
                "configured object {} is absent from the product's declared object roster",
                obj.number
            )));
        }
        rows[row] = (obj.flags, obj.object_type);
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

        // `Data` and `Mask` are the same value/membership pair used by
        // absolute segments: every non-zero mask byte belongs to the product
        // image. A relative segment is not necessarily a parameter-only
        // backing store. System B products commonly put a complete
        // manufacturer configuration image here and use PID_MCB_TABLE to
        // divide it into CRC/access-control subsegments.
        let mut bytes = vec![0u8; segment.size as usize];
        let take = segment.data.len().min(bytes.len());
        bytes[..take].copy_from_slice(&segment.data[..take]);
        let mut owned = vec![false; segment.size as usize];
        if let Some(mask) = &segment.mask {
            if mask.len() != segment.data.len() {
                return Err(Error::ProductData(format!(
                    "segment {} has {} data bytes but {} mask bytes",
                    segment.id,
                    segment.data.len(),
                    mask.len()
                )));
            }
            for (owned, &mask) in owned[..take].iter_mut().zip(mask) {
                *owned = mask != 0;
            }
        } else {
            owned[..take].fill(true);
        }
        patch_parameters(&mut bytes, segment.size as usize, &segment.id, product, project)?;

        // Explicit project values own their bytes even when the product mask
        // leaves the default location open. This mirrors absolute placement:
        // the mask controls default image membership, while a configured
        // parameter is itself new image content.
        for value in &project.parameters {
            let Some(location) = product
                .parameters
                .iter()
                .find(|location| location.id == value.id && location.code_segment == segment.id)
            else {
                continue;
            };
            let start = location.offset as usize;
            let end = start
                .checked_add(patch_span(location, value)?)
                .ok_or(Error::DownloadConfig("a parameter value runs past the end of its segment"))?;
            if end > owned.len() {
                return Err(Error::DownloadConfig("a parameter value runs past the end of its segment"));
            }
            owned[start..end].fill(true);
        }

        image.insert_sparse_relative(machine, bytes, owned)?;
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
    dtm: Option<DynamicTableOptions>,
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

    let mut buffers: BTreeMap<String, AbsoluteBuffer> = BTreeMap::new();
    for segment in &product.segments {
        let Some(address) = segment.address else { continue };
        let mut buffer = AbsoluteBuffer::from_segment(address, segment)?;

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
                && buffer.bytes.len() > offset
                && let Some(overlay) = layout.overlay_group_object_table
            {
                overlay(&mut buffer.bytes[offset..], &product.com_objects, product.effective_com_objects())?;
                let remaining = buffer.bytes.len() - offset;
                buffer.claim_from_segment_mask(segment, offset, remaining);
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
                buffer.replace(blob);
                buffer.claim_from_segment_mask(segment, 0, blob.len());
            } else if !blob.is_empty() {
                buffer.write(offset, blob, false);
                buffer.claim_from_segment_mask(segment, offset, blob.len());
            }
        }

        buffers.insert(segment.id.clone(), buffer);
    }

    // Dynamic table management: place the packed association table
    // and repoint the mask's one-byte association-table pointer at it.
    if let Some(options) = dtm {
        let segment_base = |id: &Option<String>| {
            id.as_deref().and_then(|id| product.segments.iter().find(|s| s.id == id)).and_then(|s| s.address)
        };
        let adt_base = segment_base(&product.address_table_segment)
            .ok_or(Error::DownloadConfig("dynamic table management needs the address table in an addressed segment"))?;
        // ETS word-aligns the relocated table. The address table has an odd
        // length whenever it contains whole two-octet addresses, so omitting
        // this padding moved every BCU2 association and its pointer one byte
        // early (`011Dh` instead of the trace's `011Eh`).
        let after_adt = u32::from(adt_base) + product.address_table_offset + address_table.len() as u32;
        let assoc_abs = after_adt.next_multiple_of(options.association_alignment);

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
            u32::from(options.pointer_address),
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
        let Some(location) = product.parameters.iter().find(|p| p.id == value.id) else {
            if product.property_parameters.iter().any(|parameter| parameter.id == value.id) {
                continue;
            }
            return Err(Error::ProductData(format!("the product defines no parameter {}", value.id)));
        };
        let segment = product.segments.iter().find(|s| s.id == location.code_segment).ok_or_else(|| {
            Error::ProductData(format!(
                "parameter {} names segment {}, which the product does not define",
                value.id, location.code_segment
            ))
        })?;
        let buffer = buffers
            .entry(location.code_segment.clone())
            .or_insert_with(|| AbsoluteBuffer::empty(segment.address.unwrap_or_default()));
        let end = location.offset as usize + patch_span(location, value)?;
        if end > buffer.bytes.len() {
            if end > segment.size as usize {
                return Err(Error::DownloadConfig("a parameter value runs past the end of its segment"));
            }
            buffer.resize(end);
        }
        patch_one_parameter(&mut buffer.bytes, location, value)?;
        buffer.claim(location.offset as usize, patch_span(location, value)?);
    }

    for buffer in buffers.values() {
        buffer.insert_owned(image)?;
    }
    Ok(())
}

/// One absolute segment while the ETS-style sparse image is assembled.
///
/// MTXML `Data` and `Mask` are a value/membership pair: zero mask bytes are
/// holes, later filled by parameters, table formatters, or resource patches.
/// Treating `Data` as one dense write overwrote BCU2's live IA and wrote
/// vendor placeholders that ETS deliberately leaves untouched.
#[derive(Debug)]
struct AbsoluteBuffer {
    base: u16,
    bytes: Vec<u8>,
    owned: Vec<bool>,
}

impl AbsoluteBuffer {
    fn empty(base: u16) -> Self {
        Self { base, bytes: Vec::new(), owned: Vec::new() }
    }

    fn from_segment(base: u16, segment: &super::product::Segment) -> Result<Self> {
        if let Some(mask) = &segment.mask
            && mask.len() != segment.data.len()
        {
            return Err(Error::ProductData(format!(
                "segment {} has {} data bytes but {} mask bytes",
                segment.id,
                segment.data.len(),
                mask.len()
            )));
        }
        let owned = segment
            .mask
            .as_ref()
            .map_or_else(|| vec![true; segment.data.len()], |mask| mask.iter().map(|&byte| byte != 0).collect());
        Ok(Self { base, bytes: segment.data.clone(), owned })
    }

    fn resize(&mut self, len: usize) {
        self.bytes.resize(len, 0);
        self.owned.resize(len, false);
    }

    fn replace(&mut self, bytes: &[u8]) {
        self.bytes.clear();
        self.bytes.extend_from_slice(bytes);
        self.owned.clear();
        self.owned.resize(bytes.len(), false);
    }

    fn write(&mut self, offset: usize, bytes: &[u8], claim: bool) {
        if self.bytes.len() < offset + bytes.len() {
            self.resize(offset + bytes.len());
        }
        self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        if claim {
            self.claim(offset, bytes.len());
        }
    }

    fn claim(&mut self, offset: usize, len: usize) {
        if self.owned.len() < offset + len {
            self.resize(offset + len);
        }
        self.owned[offset..offset + len].fill(true);
    }

    fn claim_from_segment_mask(&mut self, segment: &super::product::Segment, offset: usize, len: usize) {
        if let Some(mask) = &segment.mask {
            for index in offset..offset + len {
                if mask.get(index).is_some_and(|&byte| byte != 0) {
                    self.owned[index] = true;
                }
            }
        } else {
            self.claim(offset, len);
        }
    }

    fn insert_owned(&self, image: &mut DeviceImage) -> Result<()> {
        let mut start = 0usize;
        while start < self.owned.len() {
            let Some(run_start) = self.owned[start..].iter().position(|owned| *owned).map(|offset| start + offset)
            else {
                break;
            };
            let run_end = self.owned[run_start..]
                .iter()
                .position(|owned| !*owned)
                .map_or(self.owned.len(), |offset| run_start + offset);
            let address =
                self.base
                    .checked_add(u16::try_from(run_start).map_err(|_| {
                        Error::DownloadConfig("absolute segment offset exceeds the 16-bit address space")
                    })?)
                    .ok_or(Error::DownloadConfig("absolute segment extends past the 16-bit address space"))?;
            image.insert(address, self.bytes[run_start..run_end].to_vec())?;
            start = run_end;
        }
        Ok(())
    }
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
    buffers: &mut BTreeMap<String, AbsoluteBuffer>,
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

        let buffer = buffers.entry(segment.id.clone()).or_insert_with(|| AbsoluteBuffer::empty(base));
        buffer.write(offset, &bytes[cursor..cursor + run], true);
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
pub(super) fn patch_parameters(
    bytes: &mut [u8],
    capacity: usize,
    segment_id: &str,
    product: &ProductData,
    project: &ProjectConfig,
) -> Result<()> {
    for value in &project.parameters {
        let Some(location) = product.parameters.iter().find(|p| p.id == value.id) else {
            if product.property_parameters.iter().any(|parameter| parameter.id == value.id) {
                continue;
            }
            return Err(Error::ProductData(format!("the product defines no parameter {}", value.id)));
        };
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
    if location.bit_offset == 0 && location.size_bits.is_multiple_of(8) {
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

    if location.bit_offset == 0 && location.size_bits.is_multiple_of(8) {
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
    use crate::download::ProcedureKind;
    use crate::download::mask::MaskDb;
    use crate::download::product::{ComObjectDef, tests::SYSTEM7_MTXML};
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
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        compile(&mask, &product(), &project()).expect("compiles")
    }

    #[test]
    fn unsupported_partial_request_compiles_the_full_flow() {
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let compiled = compile_scoped(&mask, &product(), &project(), DownloadScope::Parameters).expect("compiles");

        assert_eq!(compiled.scope(), DownloadScope::Full);
        assert_eq!(compiled.instructions, compile(&mask, &product(), &project()).expect("full compiles").instructions);
    }

    #[test]
    fn application_program_2_fragments_select_the_complete_procedure() {
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_07B0_RESOURCES).expect("fixture");
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let mut product = ProductData {
            load_procedure_style: super::super::product::LoadProcedureStyle::Merged,
            ..Default::default()
        };

        assert_eq!(procedure_kind_for_scope(&mask, &product, DownloadScope::Full), ProcedureKind::LoadApplication);

        product
            .load_procedures
            .push(zweidraehte_knxprod::schema::LoadProcedure { merge_id: Some(3), controls: Vec::new() });
        assert_eq!(procedure_kind_for_scope(&mask, &product, DownloadScope::Full), ProcedureKind::LoadAll);
    }

    #[test]
    fn property_inline_data_is_constrained_by_the_masks_pdt() {
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_07B0_RESOURCES).expect("fixture");
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let instructions = vec![Instruction::WriteProperty {
            obj_idx: 4,
            prop_id: 27,
            start_idx: 1,
            count: 1,
            data: vec![0, 0, 0, 20, 0, 50, 0, 0, 0, 0].into(),
            verify: false,
        }];

        let constrained = constrain_property_write_widths(instructions, &mask).expect("PDT fixes the wire width");
        assert!(matches!(
            &constrained[0],
            Instruction::WriteProperty { data, .. } if data == &[0, 0, 0, 20, 0, 50, 0, 0]
        ));
    }

    #[test]
    fn application_id_placeholder_is_resolved_from_the_product() {
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_07B0_RESOURCES).expect("fixture");
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let product = ProductData {
            task_identity: super::super::ir::TaskIdentity {
                application_id: [0x00, 0xC5, 0x04, 0x0D, 0x12],
                pei_type: 0,
            },
            ..Default::default()
        };
        let instructions = vec![
            Instruction::WriteProperty {
                obj_idx: 4,
                prop_id: pid::PROGRAM_VERSION,
                start_idx: 1,
                count: 1,
                data: vec![0; 5].into(),
                verify: true,
            },
            Instruction::WriteProperty {
                obj_idx: 5,
                prop_id: pid::PROGRAM_VERSION,
                start_idx: 1,
                count: 1,
                data: vec![0; 5].into(),
                verify: true,
            },
        ];

        let patched = patch_application_identity_property(instructions, &mask, &product);
        assert!(matches!(
            &patched[0],
            Instruction::WriteProperty { data, .. } if data == &[0x00, 0xC5, 0x04, 0x0D, 0x12]
        ));
        assert!(matches!(
            &patched[1],
            Instruction::WriteProperty { data, .. } if data == &[0, 0, 0, 0, 0]
        ));
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
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let mut project = project();
        project.parameters = vec![ParameterValue { id: "M-00FA_A-0306-02-0000_P-1".to_string(), value: vec![0xEE] }];

        let c = compile(&mask, &product(), &project).expect("compiles");
        // Default data was 01 02 03 04; the parameter sits at offset 2.
        assert_eq!(c.image.slice(0x4300, 4).expect("param segment"), [1, 2, 0xEE, 4]);
    }

    #[test]
    fn masked_relative_segments_follow_mask_membership() {
        use crate::download::product::Segment;

        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_07B0_RESOURCES).expect("fixture");
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let product = ProductData {
            segments: vec![Segment {
                id: "s".into(),
                address: None,
                size: 6,
                memory_type: None,
                load_state_machine: Some(4),
                data: vec![10, 11, 12, 13, 14, 15],
                mask: Some(vec![0xFF, 0, 0xFF, 0xFF, 0, 0xFF]),
            }],
            parameters: vec![ParameterLocation {
                id: "p".into(),
                code_segment: "s".into(),
                offset: 2,
                bit_offset: 0,
                size_bits: 16,
                legacy_patch_always: false,
                seeds_default: true,
            }],
            ..Default::default()
        };
        let mut image = DeviceImage::new();

        place_relative(
            &mut image,
            &mask.lsm_model(),
            &product,
            &ProjectConfig::new(IndividualAddress::new(1, 1, 1)),
            [Vec::new(), Vec::new(), Vec::new()],
        )
        .expect("relative image assembles");

        assert_eq!(image.relative(4), Some(&[10, 11, 12, 13, 14, 15][..]));
        assert_eq!(image.relative_parts(4, 0, 6), Some(vec![(0, &[10][..]), (2, &[12, 13][..]), (5, &[15][..])]));
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
            seeds_default: false,
        }
    }

    fn value(bytes: &[u8]) -> ParameterValue {
        ParameterValue { id: "p".to_string(), value: bytes.to_vec() }
    }

    #[test]
    fn property_parameter_data_resolves_before_execution() {
        let product = ProductData {
            property_parameters: vec![super::super::product::PropertyParameterLocation {
                id: "p".to_string(),
                object: PropertyObject::Index(0),
                property_id: 86,
                offset: 0,
                bit_offset: 0,
                size_bits: 8,
                legacy_patch_always: false,
            }],
            ..Default::default()
        };
        let mut project = ProjectConfig::new(IndividualAddress::new(1, 1, 1));
        project.parameters.push(value(&[42]));

        let resolved = resolve_property_steps(
            vec![Instruction::WritePropertyData {
                target: LsmTarget::Index(0),
                prop_id: 86,
                start_idx: 1,
                count: 1,
                verify: false,
            }],
            &product,
            &project,
        )
        .expect("property data resolves");
        assert_eq!(resolved, vec![Instruction::WriteProperty {
            obj_idx: 0,
            prop_id: 86,
            start_idx: 1,
            count: 1,
            data: vec![42].into(),
            verify: false,
        }]);
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
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
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
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
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
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let mut product = product();
        product.com_objects.clear();
        product.com_object_numbers.clear();
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
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
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
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
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
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let mut product = product();
        product.com_objects = (0..256u16)
            .map(|number| crate::download::product::ComObjectDef {
                number,
                object_type: zweidraehte_proto::com_object::ComObjectType::Uint1,
                flags: ComObjectFlags::from_byte(0x47),
            })
            .collect();
        product.com_object_numbers = (0..256u16).collect();
        let result = compile(&mask, &product, &project());
        assert!(matches!(result, Err(Error::DownloadConfig(_))));
    }

    /// A BCU1 compile end to end: direct path, the mask's
    /// DefaultProcedure template, and the tables spliced into the one
    /// EEPROM segment at their declared offsets — everything around
    /// them (the vendor's 00..FF ramp) survives.
    #[test]
    fn bcu1_compiles_direct_with_spliced_tables() {
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0012).expect("fixture");
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
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0012).expect("fixture");
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
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0020).expect("fixture");
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
        assert_eq!(c.instructions[1], Instruction::WriteMemory {
            address: 0x010D,
            data: vec![0x00].into(),
            verify: true
        });
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
    fn bcu2_compiler_accepts_0020_0021_and_0025_masks() {
        let product =
            ProductData::from_mtxml_str(crate::download::product::tests::BCU1_MTXML).expect("BCU1 fixture parses");
        let project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));

        for (code, decimal) in [(0x0020, 32), (0x0021, 33), (0x0025, 37)] {
            let xml = crate::download::mask::fixtures::MV_0020
                .replace("MV-0020", &format!("MV-{code:04X}"))
                .replace("MaskVersion=\"32\"", &format!("MaskVersion=\"{decimal}\""));
            let db = MaskDb::from_xml_str(&xml).expect("derived BCU2 fixture parses");
            let mask = db.mask(MaskVersion::from(code)).expect("derived mask is present");
            let compiled = compile(&mask, &product, &project).expect("BCU1-compatible program compiles");
            assert_eq!(compiled.path(), LoadControlPath::Property, "mask {code:04X}");
        }
    }

    #[test]
    fn secure_bcu2_uses_extended_memory_and_loads_security_by_type() {
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0020).expect("fixture");
        let mask = db.mask(MaskVersion::Other(0x0020)).expect("0020");
        let mut product =
            ProductData::from_mtxml_str(crate::download::product::tests::BCU1_MTXML).expect("fixture parses");
        product.com_objects = (0..=2)
            .map(|number| ComObjectDef {
                number,
                object_type: ComObjectType::Uint1,
                flags: ComObjectFlags::from_byte(0),
            })
            .collect();
        product.com_object_numbers = vec![0, 1, 2];
        product.supports_data_secure = true;
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
        project.security = Some(SecurityConfig::new(
            vec![(ga_high, [0xA5; 16]), (ga_low, [0x5A; 16])],
            vec![(IndividualAddress::new(1, 2, 3), 0x0102_0304_0506)],
            vec![
                GroupObjectSecurity { com_object: 1, protection: GroupObjectProtection::AuthenticationConfidentiality },
                GroupObjectSecurity { com_object: 2, protection: GroupObjectProtection::Authentication },
            ],
        ));

        let compiled = compile(&mask, &product, &project).expect("secure download compiles");
        assert_eq!(compiled.memory_service, MemoryService::Extended);
        assert!(
            !compiled.instructions.iter().any(|instruction| {
                matches!(instruction, Instruction::TaskSegment { lsm: LsmTarget::Index(5), .. })
            })
        );

        let target = LsmTarget::ObjectType { object_type: InterfaceObjectType::Security, occurrence: 1 };
        let security_start = compiled
            .instructions
            .iter()
            .position(|instruction| {
                matches!(instruction, Instruction::LsmEvent { lsm, event: LoadEvent::Unload } if *lsm == target)
            })
            .expect("Security IO unload");
        let first_standard_start = compiled
            .instructions
            .iter()
            .position(|instruction| {
                matches!(instruction, Instruction::LsmEvent {
                    lsm: LsmTarget::Index(_),
                    event: LoadEvent::StartLoading,
                })
            })
            .expect("standard load starts");
        let first_standard_completed = compiled
            .instructions
            .iter()
            .position(|instruction| {
                matches!(instruction, Instruction::LsmEvent {
                    lsm: LsmTarget::Index(_),
                    event: LoadEvent::LoadCompleted,
                })
            })
            .expect("standard load completes");
        let restart = compiled
            .instructions
            .iter()
            .position(|instruction| matches!(instruction, Instruction::Restart))
            .expect("restart");
        assert!(security_start < first_standard_start, "Security IO unload accompanies the ordinary unloads");

        let security_loading = compiled
            .instructions
            .iter()
            .position(|instruction| {
                matches!(instruction, Instruction::LsmEvent { lsm, event: LoadEvent::StartLoading } if *lsm == target)
            })
            .expect("Security IO load starts");
        let security_completed = compiled
            .instructions
            .iter()
            .position(|instruction| {
                matches!(instruction, Instruction::LsmEvent { lsm, event: LoadEvent::LoadCompleted } if *lsm == target)
            })
            .expect("Security IO load completes");
        assert!(first_standard_start < security_loading);
        assert!(security_completed < first_standard_completed);
        assert!(first_standard_completed < restart);

        let phase = &compiled.instructions[security_loading..=security_completed];
        assert!(matches!(phase[0], Instruction::LsmEvent { lsm, event: LoadEvent::StartLoading } if lsm == target));
        let key_rows = phase
            .iter()
            .find_map(|instruction| match instruction {
                Instruction::WritePropertyExt {
                    prop_id: pid::security::GROUP_KEY_TABLE,
                    start_idx: 1,
                    count,
                    data,
                    ..
                } => Some((*count, data)),
                _ => None,
            })
            .expect("group-key range");
        assert_eq!(key_rows.0, 2);
        assert_eq!(&key_rows.1[..2], &[0, 1], "lower GA has ADT index 1");
        assert_eq!(&key_rows.1[2..18], &[0x5A; 16]);
        assert_eq!(&key_rows.1[18..20], &[0, 2], "higher GA has ADT index 2");
        assert_eq!(&key_rows.1[20..], &[0xA5; 16]);

        assert!(phase.iter().any(|instruction| {
            matches!(instruction, Instruction::WritePropertyExt {
                prop_id: pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
                start_idx: 1,
                data,
                ..
            } if data == &[0x12, 0x03, 1, 2, 3, 4, 5, 6])
        }));
        assert!(phase.iter().any(|instruction| {
            matches!(instruction, Instruction::WritePropertyExt {
                prop_id: pid::security::GROUP_KEY_TABLE,
                start_idx: 0,
                data,
                ..
            } if data == &[0, 2])
        }));
        assert!(phase.iter().any(|instruction| {
            matches!(instruction, Instruction::WritePropertyExt {
                prop_id: pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
                start_idx: 0,
                data,
                ..
            } if data == &[0, 1])
        }));
        assert!(!phase.iter().any(|instruction| {
            matches!(instruction, Instruction::WritePropertyExt {
                prop_id: pid::security::GO_SECURITY_FLAGS,
                start_idx: 0,
                ..
            })
        }));
        let go_flags = phase
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::WritePropertyExt {
                    prop_id: pid::security::GO_SECURITY_FLAGS,
                    start_idx,
                    count,
                    data,
                    ..
                } => Some((*start_idx, *count, data.as_slice())),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(go_flags, [(1, 3, &[0, 3, 1][..])]);
        assert!(matches!(
            phase.last(),
            Some(Instruction::LsmEvent { lsm, event: LoadEvent::LoadCompleted }) if *lsm == target
        ));
        assert!(!compiled.instructions.iter().any(|instruction| {
            matches!(instruction, Instruction::FunctionPropertyExt {
                object_type: InterfaceObjectType::Security,
                prop_id: pid::security::SECURITY_MODE,
                ..
            })
        }));
    }

    #[test]
    fn data_secure_capability_does_not_enable_security_io() {
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0020).expect("fixture");
        let mask = db.mask(MaskVersion::Other(0x0020)).expect("0020");
        let mut product =
            ProductData::from_mtxml_str(crate::download::product::tests::BCU1_MTXML).expect("fixture parses");
        product.supports_data_secure = true;
        let project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));

        let compiled = compile(&mask, &product, &project).expect("capable product compiles in plain mode");
        assert_eq!(compiled.memory_service, MemoryService::Extended);
        assert!(!compiled.instructions.iter().any(|instruction| {
            matches!(instruction, Instruction::LsmEvent {
                lsm: LsmTarget::ObjectType { object_type: InterfaceObjectType::Security, .. },
                ..
            })
        }));
    }

    #[test]
    fn security_io_requires_product_capability() {
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0020).expect("fixture");
        let mask = db.mask(MaskVersion::Other(0x0020)).expect("0020");
        let product = ProductData::from_mtxml_str(crate::download::product::tests::BCU1_MTXML).expect("fixture parses");
        let mut project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        project.security = Some(SecurityConfig::default());

        let error = compile(&mask, &product, &project).expect_err("unsupported Security IO is rejected");
        assert!(error.to_string().contains("without Data Secure support"));
    }

    #[test]
    fn secure_table_capacities_are_enforced_before_assembly() {
        let mut product = product();
        product.supports_data_secure = true;
        product.max_security_group_key_table_entries = Some(0);
        product.max_security_individual_address_entries = Some(0);
        let mut project = project();
        project.security =
            Some(SecurityConfig::new(vec![(project.links[0].group_address, [0x11; 16])], Vec::new(), Vec::new()));

        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        assert!(matches!(compile(&mask, &product, &project), Err(Error::DownloadConfig(_))));
    }

    #[test]
    fn go_security_rows_follow_each_management_model_asap_origin() {
        let product = ProductData {
            com_objects: vec![
                ComObjectDef { number: 0, object_type: ComObjectType::Uint1, flags: ComObjectFlags::from_byte(0) },
                ComObjectDef { number: 1, object_type: ComObjectType::Uint1, flags: ComObjectFlags::from_byte(0) },
                ComObjectDef { number: 2, object_type: ComObjectType::Uint1, flags: ComObjectFlags::from_byte(0) },
            ],
            com_object_numbers: vec![0, 1, 2],
            ..Default::default()
        };
        let security = SecurityConfig::new(Vec::new(), Vec::new(), vec![
            GroupObjectSecurity { com_object: 1, protection: GroupObjectProtection::Authentication },
            GroupObjectSecurity { com_object: 2, protection: GroupObjectProtection::AuthenticationConfidentiality },
        ]);

        // RT2 and RT8 include ASAP 0, even when it is unused by this
        // particular product. RT7 starts its physical table at ASAP 1.
        assert_eq!(materialize_go_flags(&security, &product, 0).expect("BCU2/System 7 rows"), [0, 1, 3]);
        assert_eq!(materialize_go_flags(&security, &product, 1).expect("System B rows"), [1, 3]);

        let invalid = SecurityConfig::new(Vec::new(), Vec::new(), vec![GroupObjectSecurity {
            com_object: 0,
            protection: GroupObjectProtection::Authentication,
        }]);
        assert!(matches!(materialize_go_flags(&invalid, &product, 1), Err(Error::DownloadConfig(_))));
    }

    /// The BCU1 fixture with `DynamicTableManagement="true"` — the
    /// converted-program shape ETS lays tables out dynamically for.
    fn dtm_product() -> ProductData {
        let xml = crate::download::product::tests::BCU1_MTXML
            .replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"");
        ProductData::from_mtxml_str(&xml).expect("the converted fixture parses")
    }

    fn compile_dtm(project: &ProjectConfig) -> CompiledDownload {
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0012).expect("fixture");
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
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0020).expect("fixture");
        let mask = db.mask(MaskVersion::Other(0x0020)).expect("0020");

        let mut project = ProjectConfig::new(IndividualAddress::new(1, 1, 42));
        project.links = vec![GroupLink { group_address: GroupAddress::from_three_level(0, 0, 1), com_object: 0 }];
        let c = compile(&mask, &product, &project).expect("compiles");

        // ADT fills 5 of its segment's 9 bytes. BCU2 then leaves one
        // alignment byte and starts the packed AST at the next word.
        assert_eq!(c.image.slice(0x0116, 9).expect("the ADT segment region"), [2, 0x11, 0x2A, 0x00, 0x01]);
        assert!(c.image.slice(0x011B, 1).is_none(), "the alignment byte remains device-owned");
        assert_eq!(c.image.slice(0x011C, 3).expect("the AST head"), [2, 1, 0]);
        assert_eq!(
            c.image.slice(0x011F, 2).expect("the AST segment region"),
            [0xFE, 1],
            "the placeholder row completes across the boundary"
        );
        // AssocTabPtr repointed at the packed table's start.
        assert_eq!(c.image.slice(0x0111, 1).expect("the pointer block region"), [0x1C]);
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
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0012).expect("fixture");
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
            mask: None,
        });
        let mut project = project();
        project.links = vec![GroupLink { group_address: GroupAddress::from_three_level(0, 0, 2), com_object: 1 }];
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
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
