//! Present the compiled download procedure of the edited device.
//!
//! The rows describe the same offline compile a project download starts
//! from. Live preparation still binds image operands, revalidates stamps and
//! may narrow sections, so the executed procedure can differ in detail.

use super::memory::{image_requirements_label, image_space_label};
use crate::status::DownloadPreview;
use zweidraehte_client::bus::PropertyAddress;
use zweidraehte_client::commissioning::inspection::{
    Comparison, ControlPath, DescribedPropertyAction, DescribedPropertyOperation, ErrorHandler,
    FunctionPropertyOperation, LoadEffect, LoadRecord, MemoryAddress, MemoryTransfer, NormalizedProcedure,
    OperationData, OperationExtent, OperationTarget, ProcedureOperation, ProcedureSourceId, ProcedureStep, ServiceRead,
};
use zweidraehte_client::commissioning::{CompiledProgram, ImageLocation, ProgramSections};
use zweidraehte_client::project::ProjectDownloadPreview;
use zweidraehte_project::ProgrammingSection;

/// The procedure tab's rows, or why none could be compiled.
#[derive(Debug, Default)]
pub struct ProcedureView {
    /// Facts about the compiled download shown above the step list.
    pub header: Vec<String>,
    pub rows: Vec<ProcedureRow>,
    /// Compilation failure or missing target observation, shown in place of rows.
    pub message: Option<String>,
}

/// One executable step, summarized for the list and expanded for details.
#[derive(Debug, Clone)]
pub struct ProcedureRow {
    pub operation: &'static str,
    pub summary: String,
    pub sections: String,
    pub secure_only: bool,
    /// Every field of the step as labelled values. A value may span lines.
    pub detail: Vec<DetailField>,
}

/// One labelled value in the step detail pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailField {
    pub label: String,
    pub value: String,
}

impl ProcedureView {
    /// Present the status worker's download preview of the edited device.
    pub(crate) fn from_preview(preview: Result<DownloadPreview, String>) -> Self {
        let message = |message: String| Self { message: Some(message), ..Self::default() };
        match preview {
            Ok(DownloadPreview { preview: ProjectDownloadPreview::Compiled(compiled), deployed }) => {
                procedure_view(&compiled, deployed)
            }
            Ok(DownloadPreview { preview: ProjectDownloadPreview::NeedsObservations(requirements), .. }) => message(
                format!("The download needs target observations first: {}", image_requirements_label(&requirements)),
            ),
            // The preview enum is non-exhaustive; an unknown outcome has no
            // procedure to show.
            Ok(DownloadPreview { preview, .. }) => message(format!("No procedure preview: {preview:?}")),
            Err(error) => message(error),
        }
    }
}

fn procedure_view(compiled: &CompiledProgram, deployed: bool) -> ProcedureView {
    let summary = compiled.summary();
    let baseline = if deployed { "changed since the last deployment" } else { "no deployment recorded" };
    let mut header = vec![
        format!("Profile: {}", compiled.profile().mask()),
        format!(
            "Sections: {} ({baseline})",
            summary.sections.map_or_else(|| "none".to_owned(), program_sections_label)
        ),
        format!("Image: {} bytes, {} controls", summary.image_bytes, summary.controls),
    ];
    let Some(procedure) = compiled.procedure() else {
        header.push("Procedure: none".to_owned());
        return ProcedureView { header, ..ProcedureView::default() };
    };
    header.insert(0, format!("Procedure: {}", source_label(&procedure.id)));
    ProcedureView { header, rows: rows(procedure), message: None }
}

fn rows(procedure: &NormalizedProcedure) -> Vec<ProcedureRow> {
    procedure
        .steps
        .iter()
        .map(|step| {
            let (operation, summary) = describe(&step.operation);
            ProcedureRow {
                operation,
                summary,
                sections: sections_label(step),
                secure_only: step.secure_only,
                detail: detail(step),
            }
        })
        .collect()
}

fn source_label(source: &ProcedureSourceId) -> String {
    match source {
        ProcedureSourceId::MasterData(id) => {
            let subtype = id.subtype.as_deref().map_or_else(String::new, |subtype| format!(" {subtype}"));
            let style = id.management_style.map_or_else(String::new, |style| format!(", {style:?}"));
            format!("Master Data {}{subtype} #{}{style}", id.procedure_type, id.source_index)
        }
        ProcedureSourceId::Module { definition_id, instance_id, .. } => {
            format!("module {definition_id} ({instance_id})")
        }
        ProcedureSourceId::Product { product_id, .. } => format!("product {product_id}"),
        ProcedureSourceId::Generated { name } => format!("generated {name}"),
    }
}

fn program_sections_label(sections: ProgramSections) -> String {
    [
        (ProgramSections::APPLICATION_PROGRAM_1, "AP1"),
        (ProgramSections::APPLICATION_PROGRAM_2, "AP2"),
        (ProgramSections::PARAMETERS, "Par"),
        (ProgramSections::GROUP_COMMUNICATION, "GC"),
        (ProgramSections::CONFIGURATION, "Cfg"),
    ]
    .into_iter()
    .filter(|(section, _)| sections.contains(*section))
    .map(|(_, label)| label)
    .collect::<Vec<_>>()
    .join(",")
}

fn sections_label(step: &ProcedureStep) -> String {
    step.sections
        .iter()
        .map(|section| match section {
            ProgrammingSection::Address => "IA",
            ProgrammingSection::ApplicationProgram1 => "AP1",
            ProgrammingSection::ApplicationProgram2 => "AP2",
            ProgrammingSection::Parameters => "Par",
            ProgrammingSection::GroupCommunication => "GC",
            ProgrammingSection::Configuration => "Cfg",
        })
        .collect::<Vec<_>>()
        .join(",")
}

// ================================================================================
// Operation summaries
// ================================================================================

// Each summary names the operation's target and payload in one line. The
// detail pane carries the full representation, so these favour brevity over
// completeness: retry timing, cache policies and error mappings stay there.

fn describe(operation: &ProcedureOperation) -> (&'static str, String) {
    match operation {
        ProcedureOperation::Connect => ("Connect", String::new()),
        ProcedureOperation::Disconnect => ("Disconnect", String::new()),
        ProcedureOperation::Delay { milliseconds } => ("Delay", format!("{milliseconds} ms")),
        ProcedureOperation::Restart { kind } => ("Restart", format!("{kind:?}")),
        ProcedureOperation::MasterReset { erase_code, channel } => {
            ("MasterReset", format!("erase code {erase_code}, channel {channel}"))
        }
        ProcedureOperation::SetControlVariable { variable, value } => {
            ("SetVariable", format!("{variable:?} = {value}"))
        }
        ProcedureOperation::MapError { filter, original, mapped } => (
            "MapError",
            format!(
                "{original:#X} -> {mapped:#X}{}",
                filter.map_or_else(String::new, |filter| format!(" for control {filter:#04X}"))
            ),
        ),
        ProcedureOperation::ClearCache => ("ClearCache", String::new()),
        ProcedureOperation::ProgressText(text) => ("Progress", text.clone()),
        ProcedureOperation::LoadRecord(record) => ("LoadRecord", load_record(record)),
        ProcedureOperation::AbsoluteSegment { record, transfers } => {
            let bytes: u64 = transfers.iter().map(|transfer| u64::from(transfer.extent.byte_length)).sum();
            ("AbsSegment", format!("{} transfers, {bytes} bytes; {}", transfers.len(), load_record(record)))
        }
        ProcedureOperation::ReadIntoImage { target: source, image_location, extent: size, capture_as, .. } => (
            "Read",
            format!(
                "{} ({}) into {}{}",
                target(source),
                extent(size),
                location(image_location),
                capture_as.as_ref().map_or_else(String::new, |stamp| format!(", captures stamp {stamp}"))
            ),
        ),
        ProcedureOperation::LoadImage { target: source, image_location, extent: size, .. } => {
            ("LoadImage", format!("{} ({}) into {}", target(source), extent(size), location(image_location)))
        }
        ProcedureOperation::Write { target: destination, data: payload, extent: size, policy } => {
            ("Write", format!("{} ({}) <- {}; {policy:?}", target(destination), extent(size), data(payload)))
        }
        ProcedureOperation::Compare { target: source, comparison, extent: size, invert, .. } => (
            "Compare",
            format!(
                "{} ({}) {} {}",
                target(source),
                extent(size),
                if *invert { "!=" } else { "==" },
                compared(comparison)
            ),
        ),
        ProcedureOperation::FunctionProperty(FunctionPropertyOperation::Invoke { address, data: payload, effect }) => {
            ("FuncProp", format!("invoke {} with {}{}", property(address), hex(payload), load_effect(effect)))
        }
        ProcedureOperation::FunctionProperty(FunctionPropertyOperation::ReadResult { address }) => {
            ("FuncProp", format!("read result of {}", property(address)))
        }
        ProcedureOperation::DescribedProperty(described) => (
            "DescProp",
            format!(
                "{} ({} elements): {}",
                target(&described.target),
                described.elements,
                described_action(&described.action)
            ),
        ),
        ProcedureOperation::DeclarePropertyDescriptor {
            address,
            property_data_type,
            maximum_elements,
            writable,
            ..
        } => (
            "DeclProp",
            format!(
                "{} as {property_data_type}, up to {maximum_elements} elements{}",
                property(address),
                if *writable { ", writable" } else { "" }
            ),
        ),
        ProcedureOperation::ClearLineCouplerFilter { address } => {
            ("ClearFilter", address.as_ref().map_or_else(|| "coupler filter table".to_owned(), property))
        }
        // The operation set is non-exhaustive; a newer variant still shows
        // its complete representation in the detail pane.
        other => ("Other", debug_variant(other)),
    }
}

fn load_record(record: &LoadRecord) -> String {
    format!(
        "{} <- {}{}{}",
        target(&record.write.target),
        hex(&record.bytes),
        record
            .poll
            .as_ref()
            .map_or_else(String::new, |(poll, state)| format!(", poll {} for {state:?}", target(&poll.target))),
        load_effect(&record.effect)
    )
}

fn load_effect(effect: &LoadEffect) -> String {
    match effect {
        LoadEffect::None => String::new(),
        LoadEffect::Invalidate { location: start, length } => {
            format!(", invalidates {length} bytes at {}", location(start))
        }
        LoadEffect::InvalidateAll => ", invalidates the image".to_owned(),
        LoadEffect::Fill { location: start, length, filled, value } => {
            format!(", invalidates {length} bytes at {}, fills {filled} with {value:02X}", location(start))
        }
    }
}

fn target(target: &OperationTarget) -> String {
    match target {
        OperationTarget::ImageMemory(image) => format!("memory for {}", location(image)),
        OperationTarget::Memory { service, address: MemoryAddress::Fixed(address) } => {
            format!("{service:?} memory 0x{address:04X}")
        }
        OperationTarget::Memory { service, address: MemoryAddress::Pointer { space, offset, .. } } => {
            format!("{service:?} memory at pointer to {} +0x{offset:04X}", image_space_label(space))
        }
        OperationTarget::Property { address, start_element } => format!("{}[{start_element}]", property(address)),
        OperationTarget::Adc { channel } => format!("ADC channel {channel}"),
        OperationTarget::Constant(bytes) => format!("constant {}", hex(bytes)),
    }
}

fn property(address: &PropertyAddress) -> String {
    match address {
        PropertyAddress::Indexed { object_index, property_id } => format!("object {object_index} PID {property_id}"),
        PropertyAddress::Extended { object_type, object_instance, property_id } => {
            format!("object {object_type:?} #{object_instance} PID {property_id}")
        }
    }
}

fn extent(extent: &OperationExtent) -> String {
    match extent.property_elements {
        Some(elements) => format!("{elements} elements, {} bytes", extent.byte_length),
        None => format!("{} bytes", extent.byte_length),
    }
}

fn data(data: &OperationData) -> String {
    match data {
        OperationData::Inline(bytes) => hex(bytes),
        OperationData::Buffer { location: source, length, .. } => {
            format!("buffer {length} bytes at {}", location(source))
        }
        OperationData::ImageOverlay { location: source, length, .. } => {
            format!("authored bytes overlaid by image {length} bytes at {}", location(source))
        }
        OperationData::Credential { location: source, length, .. } => {
            format!("credential {length} bytes at {}", location(source))
        }
        OperationData::Image { location: source, length } => format!("image {length} bytes at {}", location(source)),
        OperationData::ImageWindow { location: source, maximum } => {
            format!("image window up to {maximum} bytes at {}", location(source))
        }
    }
}

fn compared(comparison: &Comparison) -> String {
    match comparison {
        Comparison::Exact { data: expected, .. } => data(expected),
        Comparison::ImageExact { location: expected, length, .. } => {
            format!("image {length} bytes at {}", location(expected))
        }
        other => debug_variant(other),
    }
}

fn described_action(action: &DescribedPropertyAction) -> String {
    match action {
        DescribedPropertyAction::Write { payload, .. } => format!("write {}", hex(payload)),
        DescribedPropertyAction::WriteImage { location: source, length, .. } => {
            format!("write image {length} bytes at {}", location(source))
        }
        DescribedPropertyAction::WriteImageWindow { location: source, length, .. } => {
            format!("write image window {length} bytes at {}", location(source))
        }
        DescribedPropertyAction::LoadImage { location: destination, .. } => {
            format!("load into {}", location(destination))
        }
        other => debug_variant(other),
    }
}

fn location(location: &ImageLocation) -> String {
    format!("{} +0x{:04X}", image_space_label(&location.space), location.offset)
}

/// Hexadecimal payload, truncated so one step stays on one line.
fn hex(bytes: &[u8]) -> String {
    const SHOWN: usize = 16;
    let mut text = bytes.iter().take(SHOWN).map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(" ");
    if bytes.is_empty() {
        text.push_str("(empty)");
    } else if bytes.len() > SHOWN {
        text.push_str(&format!(" … ({} bytes)", bytes.len()));
    }
    text
}

/// The variant name of a value's `Debug` representation.
fn debug_variant(value: &impl std::fmt::Debug) -> String {
    let debug = format!("{value:?}");
    debug.split([' ', '(', '{']).next().unwrap_or_default().to_owned()
}

// ================================================================================
// Step details
// ================================================================================

// The detail pane lists every field of the step, so nothing the compiler
// decided is hidden behind the one-line summary. Payloads are shown in full,
// sixteen bytes per line. Leaf policies (cache, verification, causes) keep
// their compact `Debug` form: their variant names already read as prose.

/// Labelled fields under construction; nested operands prefix their labels.
#[derive(Default)]
struct Fields(Vec<DetailField>);

impl Fields {
    fn push(&mut self, label: impl Into<String>, value: impl Into<String>) {
        self.0.push(DetailField { label: label.into(), value: value.into() });
    }

    fn debug(&mut self, label: impl Into<String>, value: &impl std::fmt::Debug) {
        self.push(label, format!("{value:?}"));
    }
}

fn detail(step: &ProcedureStep) -> Vec<DetailField> {
    let mut fields = Fields::default();
    let (operation, _) = describe(&step.operation);
    fields.push("Operation", operation);
    fields.push("Sections", if step.sections.is_empty() { "none".to_owned() } else { sections_label(step) });
    fields.push("Secure only", if step.secure_only { "yes" } else { "no" });
    fields.push("Source", control_path(&step.path));
    fields
        .push("Record code", step.source_control_code.map_or_else(|| "none".to_owned(), |code| format!("{code:#04X}")));
    fields.push("On error", error_handlers(&step.on_error));
    operation_detail(&mut fields, &step.operation);
    fields.0
}

fn control_path(path: &ControlPath) -> String {
    let controls = path.control_indices.iter().map(usize::to_string).collect::<Vec<_>>().join(" › ");
    let mut text = format!("{}, {} variant {}", source_label(&path.procedure), path.mask_id, path.variant_index);
    if !controls.is_empty() {
        text.push_str(&format!(", control {controls}"));
    }
    if let Some(contribution) = path.contribution {
        text.push_str(&format!(", built-in {contribution}"));
    }
    text
}

fn error_handlers(handlers: &[ErrorHandler]) -> String {
    if handlers.is_empty() {
        return "propagate".to_owned();
    }
    handlers.iter().map(|handler| format!("{:?} on {:?}", handler.action, handler.cause)).collect::<Vec<_>>().join("\n")
}

fn operation_detail(fields: &mut Fields, operation: &ProcedureOperation) {
    match operation {
        ProcedureOperation::Connect
        | ProcedureOperation::Disconnect
        | ProcedureOperation::ClearCache
        | ProcedureOperation::ProgressText(_)
        | ProcedureOperation::Delay { .. }
        | ProcedureOperation::Restart { .. }
        | ProcedureOperation::MasterReset { .. }
        | ProcedureOperation::SetControlVariable { .. }
        | ProcedureOperation::MapError { .. } => {
            // These operations carry only scalars, all named by the summary.
            let arguments = describe(operation).1;
            if !arguments.is_empty() {
                fields.push("Arguments", arguments);
            }
        }
        ProcedureOperation::LoadRecord(record) => load_record_detail(fields, "", record),
        ProcedureOperation::AbsoluteSegment { record, transfers } => {
            load_record_detail(fields, "", record);
            for (index, transfer) in transfers.iter().enumerate() {
                transfer_detail(fields, &format!("Transfer {} ", index + 1), transfer);
            }
        }
        ProcedureOperation::ReadIntoImage { target: source, image_location, extent: size, cache, capture_as } => {
            fields.push("Target", target(source));
            fields.push("Extent", extent(size));
            fields.push("Into", location(image_location));
            fields.debug("Cache", cache);
            fields.push("Captures", capture_as.as_ref().map_or_else(|| "nothing".to_owned(), ToString::to_string));
        }
        ProcedureOperation::LoadImage { target: source, image_location, extent: size, alignment } => {
            fields.push("Target", target(source));
            fields.push("Extent", extent(size));
            fields.push("Into", location(image_location));
            fields.push("Alignment", format!("{alignment} bytes"));
        }
        ProcedureOperation::Write { target: destination, data: payload, extent: size, policy } => {
            fields.push("Target", target(destination));
            fields.push("Extent", extent(size));
            data_detail(fields, "", payload);
            fields.debug("Policy", policy);
        }
        ProcedureOperation::Compare {
            target: source,
            comparison,
            extent: size,
            cache,
            invert,
            retry_interval_milliseconds,
            timeout_milliseconds,
        } => {
            fields.push("Target", target(source));
            fields.push("Extent", extent(size));
            comparison_detail(fields, comparison);
            fields.push("Expect", if *invert { "different" } else { "equal" });
            fields.debug("Cache", cache);
            retry_detail(fields, *retry_interval_milliseconds, *timeout_milliseconds);
        }
        ProcedureOperation::FunctionProperty(FunctionPropertyOperation::Invoke { address, data: payload, effect }) => {
            fields.push("Function", "invoke");
            fields.push("Property", property(address));
            fields.push("Data", hex_full(payload));
            fields.push("Effect", load_effect(effect).trim_start_matches(", ").to_owned());
        }
        ProcedureOperation::FunctionProperty(FunctionPropertyOperation::ReadResult { address }) => {
            fields.push("Function", "read result");
            fields.push("Property", property(address));
        }
        ProcedureOperation::DescribedProperty(described) => described_detail(fields, described),
        ProcedureOperation::DeclarePropertyDescriptor {
            address,
            property_data_type,
            maximum_elements,
            read_access,
            write_access,
            writable,
        } => {
            fields.push("Property", property(address));
            fields.push("Type", property_data_type.clone());
            fields.push("Max elements", maximum_elements.to_string());
            fields.push("Access", format!("read {read_access}, write {write_access}"));
            fields.push("Writable", if *writable { "yes" } else { "no" });
        }
        ProcedureOperation::ClearLineCouplerFilter { address } => {
            fields.push("Property", address.as_ref().map_or_else(|| "coupler filter table".to_owned(), property));
        }
        // A newer operation keeps its complete compiler representation.
        other => fields.push("Operation data", format!("{other:#?}")),
    }
}

fn load_record_detail(fields: &mut Fields, prefix: &str, record: &LoadRecord) {
    service_detail(fields, &format!("{prefix}Load target"), &record.write);
    fields.push(format!("{prefix}Load bytes"), hex_full(&record.bytes));
    match &record.poll {
        Some((poll, state)) => {
            service_detail(fields, &format!("{prefix}Poll"), poll);
            fields.debug(format!("{prefix}Poll until"), state);
        }
        None => fields.push(format!("{prefix}Poll"), "none"),
    }
    let effect = load_effect(&record.effect);
    fields.push(format!("{prefix}Effect"), if effect.is_empty() { "none".to_owned() } else { effect[2..].to_owned() });
}

fn service_detail(fields: &mut Fields, label: &str, service: &ServiceRead) {
    fields.push(label, format!("{} ({})", target(&service.target), extent(&service.extent)));
    pointer_detail(fields, label, &service.target);
}

/// A pointer-addressed target first reads its base; show that read too.
fn pointer_detail(fields: &mut Fields, label: &str, operand: &OperationTarget) {
    if let OperationTarget::Memory { address: MemoryAddress::Pointer { read, encoding, .. }, .. } = operand {
        fields.push(
            format!("{label} pointer"),
            format!("{} ({}), {encoding:?}", target(&read.target), extent(&read.extent)),
        );
    }
}

fn transfer_detail(fields: &mut Fields, prefix: &str, transfer: &MemoryTransfer) {
    fields.push(format!("{prefix}target"), format!("{} ({})", target(&transfer.target), extent(&transfer.extent)));
    pointer_detail(fields, &format!("{prefix}target"), &transfer.target);
    data_detail(fields, prefix, &transfer.data);
    fields.debug(format!("{prefix}policy"), &transfer.policy);
}

fn data_detail(fields: &mut Fields, prefix: &str, payload: &OperationData) {
    let label = if prefix.is_empty() { "Data".to_owned() } else { format!("{prefix}data") };
    match payload {
        OperationData::Inline(bytes) => fields.push(label, hex_full(bytes)),
        OperationData::Buffer { location: source, length, fallback } => {
            fields.push(&label, format!("buffer {length} bytes at {}", location(source)));
            fields.push(format!("{label} fallback"), fallback.as_deref().map_or_else(|| "none".to_owned(), hex_full));
        }
        OperationData::ImageOverlay { location: source, length, inline } => {
            fields.push(&label, format!("image-owned bits of {length} bytes at {} over", location(source)));
            fields.push(format!("{label} authored"), hex_full(inline));
        }
        OperationData::Credential { location: source, length, effects } => {
            fields.push(&label, format!("credential {length} bytes at {}", location(source)));
            fields.debug(format!("{label} effects"), effects);
        }
        OperationData::Image { .. } | OperationData::ImageWindow { .. } => fields.push(label, data(payload)),
    }
}

fn comparison_detail(fields: &mut Fields, comparison: &Comparison) {
    match comparison {
        Comparison::Exact { data: expected, mask, padding } => {
            data_detail(fields, "Expected ", expected);
            fields.push("Mask", mask.as_deref().map_or_else(|| "none".to_owned(), hex_full));
            fields.debug("Padding", padding);
        }
        Comparison::ImageExact { location: expected, length, mask } => {
            fields.push("Expected", format!("image {length} bytes at {}", location(expected)));
            fields.push("Mask", mask.as_deref().map_or_else(|| "none".to_owned(), hex_full));
        }
        Comparison::NumericRange { range, encoding } => {
            fields.debug("Range", range);
            fields.debug("Encoding", encoding);
        }
    }
}

fn described_detail(fields: &mut Fields, described: &DescribedPropertyOperation) {
    let DescribedPropertyOperation { target: source, elements, extended_description, widths, action } = described;
    fields.push("Target", target(source));
    fields.push("Elements", elements.to_string());
    fields.push("Description", if *extended_description { "by object type" } else { "by object index" });
    fields.push(
        "PDT widths",
        widths.iter().map(|(pdt, width)| format!("{pdt:#04X}={width}")).collect::<Vec<_>>().join(" "),
    );
    match action {
        DescribedPropertyAction::LoadImage { location: destination, lookup } => {
            fields.push("Action", format!("load into {}", location(destination)));
            fields.debug("Type lookup", lookup);
        }
        DescribedPropertyAction::Write { payload, policy } => {
            fields.push("Action", "write");
            fields.push("Data", hex_full(payload));
            fields.debug("Policy", policy);
        }
        DescribedPropertyAction::WriteImage { location: source, length, policy } => {
            fields.push("Action", format!("write image {length} bytes at {}", location(source)));
            fields.debug("Policy", policy);
        }
        DescribedPropertyAction::WriteImageWindow { location: source, length, inline, policy } => {
            fields.push("Action", format!("write image window {length} bytes at {}", location(source)));
            fields.push("Authored", inline.as_deref().map_or_else(|| "none".to_owned(), hex_full));
            fields.debug("Policy", policy);
        }
        DescribedPropertyAction::Compare {
            reference,
            mask,
            cache,
            invert,
            retry_interval_milliseconds,
            timeout_milliseconds,
        } => {
            fields.push("Action", if *invert { "compare, expect different" } else { "compare, expect equal" });
            fields.push("Reference", hex_full(reference));
            fields.push("Mask", mask.as_deref().map_or_else(|| "none".to_owned(), hex_full));
            fields.debug("Cache", cache);
            retry_detail(fields, *retry_interval_milliseconds, *timeout_milliseconds);
        }
        DescribedPropertyAction::CompareRange {
            range,
            lookup,
            cache,
            invert,
            retry_interval_milliseconds,
            timeout_milliseconds,
        } => {
            fields.push("Action", if *invert { "range, expect outside" } else { "range, expect inside" });
            fields.debug("Range", range);
            fields.push("Type lookup", lookup.as_ref().map_or_else(|| "descriptor".to_owned(), |l| format!("{l:?}")));
            fields.debug("Cache", cache);
            retry_detail(fields, *retry_interval_milliseconds, *timeout_milliseconds);
        }
    }
}

fn retry_detail(fields: &mut Fields, interval: Option<u16>, timeout: Option<u32>) {
    let text = match (interval, timeout) {
        (None, None) => "once".to_owned(),
        (interval, timeout) => format!(
            "every {} until {}",
            interval.map_or_else(|| "default interval".to_owned(), |ms| format!("{ms} ms")),
            timeout.map_or_else(|| "default timeout".to_owned(), |ms| format!("{ms} ms")),
        ),
    };
    fields.push("Retry", text);
}

/// The whole payload, sixteen bytes per line.
fn hex_full(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(empty)".to_owned();
    }
    let lines = bytes
        .chunks(16)
        .map(|chunk| chunk.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>();
    format!("{} ({} bytes)", lines.join("\n"), bytes.len())
}
