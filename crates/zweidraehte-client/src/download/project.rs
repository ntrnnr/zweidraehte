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
//! 2. **Overlay** the tables generated from the project: the RT8
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

use super::assemble::{ProcedureKind, assemble};
use super::image::DeviceImage;
use super::image_layout::{ImageLayout, Placement};
use super::interpreter::{DownloadTarget, Downloader, LoadControlPath};
use super::ir::Instruction;
use super::mask::{LsmModel, LsmRealization, MachineRole, MaskData};
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
    /// The *device's* maximum APDU length, bounding `A_Memory_Write`
    /// chunks. 15 (the TP1 standard frame) is right for every System 7
    /// device; raise it only for targets known to accept extended
    /// frames.
    pub max_apdu: u16,
}

impl ProjectConfig {
    pub fn new(individual_address: IndividualAddress) -> Self {
        Self { individual_address, links: Vec::new(), parameters: Vec::new(), max_apdu: 15 }
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
        Downloader::with_path(target, self.path, max_apdu).run(&self.instructions, &self.image).await
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
///   family lore: MV-2705 is BimM112-managed yet drives its machines
///   through properties, and a family-keyed choice would break it.
/// - **The image half** comes from the management model: System B
///   hands each interface object its bytes and lets the device place
///   them; BIM M112 places content at the product's fixed addresses.
///
/// The axes really are orthogonal — 2705 wants an absolute image
/// *and* property-driven machines, which the interpreter already
/// supports (absolute-segment records have a property-path form).
pub fn compile(mask: &MaskData<'_>, product: &ProductData, project: &ProjectConfig) -> Result<CompiledDownload> {
    let path = load_control_path(mask)?;

    let layout = ImageLayout::for_management_model(mask.management_model())
        .ok_or(Error::DownloadConfig("downloads for this management model are not implemented"))?;
    let mut image = DeviceImage::new();
    build_image(&mut image, layout, &mask.lsm_model(), product, project)?;

    let assembled = assemble(mask, product, ProcedureKind::LoadAll)?;
    let instructions = insert_image_writes(resolve_relative_steps(assembled, &image), &image);

    Ok(CompiledDownload { image, instructions, path })
}

/// The load-control path a mask drives its machines through — read
/// from the mask's own LSM declarations, never inferred from the
/// family (MV-2705 is BimM112-managed yet property-driven).
///
/// Public because procedures other than a full download need it too:
/// running the mask's Unload template, or ad-hoc instruction streams,
/// construct their [`Downloader`] with the same path `compile` would
/// have chosen.
pub fn load_control_path(mask: &MaskData<'_>) -> Result<LoadControlPath> {
    // BIM M112 first: the master data still declares the legacy
    // memory-mapped window at 0104h for these masks, but that is not
    // what ETS does — a Falcon trace of a real MDT 0705 device
    // (ETS.log, 2026-08-13) unloads through PropertyValue_Write on
    // interface objects 1..4, PID_LOAD_STATE_CONTROL, and the device
    // never reacted to spec-shaped window writes at all. 03/05/02
    // §3.31.2 marks the memory procedure "shall not be used for
    // further developments", the certification templates only ever
    // exercise the property realization, and the machine index *is*
    // the object index — so the property path is what real System 7
    // silicon actually speaks.
    if mask.management_model() == "BimM112" {
        return Ok(LoadControlPath::Property);
    }

    let model = mask.lsm_model();
    match model.realization() {
        Some(LsmRealization::Property) => Ok(LoadControlPath::Property),
        Some(LsmRealization::Memory) => {
            let resources = mask.memory_resources().ok_or(Error::DownloadConfig(
                "this mask drives its machines through memory but does not locate all of \
                 ProgrammingMode / load control / load status / address table there",
            ))?;
            Ok(LoadControlPath::Memory(resources))
        }
        None if model.is_empty() => {
            Err(Error::DownloadConfig("this mask declares no load state machines; its downloads are not implemented"))
        }
        None => Err(Error::DownloadConfig(
            "this mask mixes memory-mapped and property-driven machines; no published mask does",
        )),
    }
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
            Instruction::RelSegment { lsm, mut segment } => match image.relative(lsm) {
                Some(bytes) => {
                    segment.requested_memory_size = segment.requested_memory_size.max(bytes.len() as u32);
                    Some(Instruction::RelSegment { lsm, segment })
                }
                // Nothing to hold: drop a zero-size request, but honour
                // one the product sized deliberately.
                None if segment.requested_memory_size == 0 => None,
                None => Some(Instruction::RelSegment { lsm, segment }),
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
    if let Some(max) = product.association_table_max_entries
        && project.links.len() > max as usize
    {
        return Err(Error::DownloadConfig("more associations than the product's association table holds"));
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
    let association_table = (layout.association_table)(&associations)?;
    let group_object_table = (layout.group_object_table)(&co_rows(product, layout.first_asap)?)?;

    match layout.placement {
        Placement::RelativeObjects => {
            place_relative(image, model, product, project, [address_table, association_table, group_object_table])
        }
        Placement::AbsoluteSegments => {
            place_absolute(image, layout, product, project, [address_table, association_table, group_object_table])
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

/// Place content for an absolute-address model (BIM M112): every
/// addressed segment's content, with the generated tables replacing
/// the content of the segments the product names for them.
///
/// The bytes are each segment's *content*, not its capacity: a table
/// segment holds exactly its generated blob, a data segment its
/// default `Data` (plus any parameter patches). Padding to the
/// allocated size is the device's business — the download writes only
/// the meaningful bytes, as ETS does, so a two-entry table on a
/// 254-entry segment costs a handful of writes rather than hundreds.
fn place_absolute(
    image: &mut DeviceImage,
    layout: &ImageLayout,
    product: &ProductData,
    project: &ProjectConfig,
    [address_table, association_table, group_object_table]: [Vec<u8>; 3],
) -> Result<()> {
    // Each generated table names the segment that holds it. A table
    // whose blob is empty (no group objects, say) or whose product
    // declares no segment simply contributes nothing.
    let generated: [(Option<&str>, &[u8], &'static str); 3] = [
        (product.address_table_segment.as_deref(), &address_table, "group address table"),
        (product.association_table_segment.as_deref(), &association_table, "association table"),
        (product.com_object_table_segment.as_deref(), &group_object_table, "group object table"),
    ];

    let mut buffers: BTreeMap<String, (u16, Vec<u8>)> = BTreeMap::new();
    for segment in &product.segments {
        let Some(address) = segment.address else { continue };

        // A generated table replaces the segment's content wholesale;
        // otherwise the content is the product's default data. One
        // exception: a group object table the *product* ships as
        // default data (vendor M112 programs) is overlaid per object
        // instead — its count and pointers are firmware facts a
        // synthesized table would zero.
        let content = match generated.iter().find(|(id, _, _)| *id == Some(segment.id.as_str())) {
            Some((_, _, "group object table"))
                if !segment.data.is_empty() && layout.overlay_group_object_table.is_some() =>
            {
                let overlay = layout.overlay_group_object_table.expect("guard checked it is Some");
                let mut bytes = segment.data.clone();
                overlay(&mut bytes, &product.com_objects)?;
                bytes
            }
            Some((_, blob, what)) => {
                if blob.len() > segment.size as usize {
                    return Err(Error::DownloadConfig(match *what {
                        "group address table" => "group address table exceeds its segment",
                        "association table" => "association table exceeds its segment",
                        _ => "group object table exceeds its segment",
                    }));
                }
                blob.to_vec()
            }
            None => segment.data.clone(),
        };

        if !content.is_empty() {
            buffers.insert(segment.id.clone(), (address, content));
        }
    }

    // A generated table must land in a segment the product defined.
    for (id, blob, what) in generated {
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
    let mut pending: Vec<(u8, u16, u16)> = Vec::new();
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
                        out.push(Instruction::WriteImage { address: *address, length: content.len() as u16 });
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
        // ADT: count 2, IA 1.1.42, then 0/0/1 and 0/0/2 ascending.
        let adt = c.image.slice(0x4000, 7).expect("ADT in image");
        assert_eq!(adt, [2, 0x11, 0x2A, 0x00, 0x01, 0x00, 0x02]);

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
                Instruction::WriteImage { address: 0x4000, length } => Some(*length),
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
    fn a_product_without_group_objects_contributes_no_m112_table() {
        // M112: an empty COT blob keeps the COT segment out of the
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
        // Vendor M112 products ship their group object table as the
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
