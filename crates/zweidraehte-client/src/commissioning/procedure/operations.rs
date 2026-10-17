//! Operations in the executable procedure model.

use std::collections::BTreeMap;

use super::*;

/// All executable and stateful operations required by project-20 through
/// project-23 classic profiles.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcedureOperation {
    Connect,
    Disconnect,
    Delay {
        milliseconds: u32,
    },
    Restart {
        kind: RestartKind,
    },
    MasterReset {
        erase_code: u8,
        channel: u8,
    },

    SetControlVariable {
        variable: ControlVariable,
        value: bool,
    },
    MapError {
        filter: Option<u8>,
        original: u32,
        mapped: u32,
    },
    ClearCache,
    ProgressText(String),

    LoadRecord(LoadRecord),
    AbsoluteSegment {
        record: LoadRecord,
        transfers: Vec<MemoryTransfer>,
    },

    ReadIntoImage {
        target: OperationTarget,
        image_location: ImageLocation,
        extent: OperationExtent,
        cache: CachePolicy,
        /// Retain this read as durable device evidence after the procedure.
        ///
        /// Ordinary working-image reads stay private to the interpreter. The
        /// compiler sets this only for Master-Data download-stamp controls,
        /// whose value would otherwise be lost when the final reset closes
        /// the management session.
        capture_as: Option<ResourceId>,
    },
    /// Read the unowned window of one working-image segment and merge the
    /// returned bits, preserving owned bits and marking the read range owned.
    ///
    /// This operation bypasses the value cache. Selection follows the load
    /// control's leading/trailing ownership scan and independently aligns its
    /// offset and size. The compiler emits it for absolute standard/user
    /// memory controls with byte granularity, and resolved System B stamp
    /// properties with their element granularity.
    LoadImage {
        target: OperationTarget,
        image_location: ImageLocation,
        extent: OperationExtent,
        alignment: u32,
    },
    Write {
        target: OperationTarget,
        data: OperationData,
        extent: OperationExtent,
        policy: WriteIntent,
    },
    Compare {
        target: OperationTarget,
        comparison: Comparison,
        extent: OperationExtent,
        cache: CachePolicy,
        invert: bool,
        retry_interval_milliseconds: Option<u16>,
        timeout_milliseconds: Option<u32>,
    },
    FunctionProperty(FunctionPropertyOperation),
    /// A property write or comparison whose element type is selected when
    /// the control executes.
    ///
    /// For ordinary described controls, neither the mask profile, Master Data, a procedure declaration nor an
    /// observation types the property, so its byte extent is unknown until
    /// the control executes. The reference then asks the device for the
    /// property's description, sizes the transfer as `elements` times the
    /// reported type's width, and uses the authored bytes only when they are
    /// at least that long. Numeric controls can instead carry an explicit
    /// lookup policy so cache updates and clears retain their native ordering.
    DescribedProperty(DescribedPropertyOperation),
    DeclarePropertyDescriptor {
        address: crate::commissioning::procedure::operands::PropertyAddress,
        property_data_type: String,
        maximum_elements: u16,
        read_access: u8,
        write_access: u8,
        writable: bool,
    },

    ClearLineCouplerFilter {
        address: Option<crate::commissioning::procedure::operands::PropertyAddress>,
    },
}

impl ProcedureOperation {
    /// Module services join a session established by the authored recipe.
    /// Tool state and progress operations can also run at outer boundaries.
    pub(crate) const fn requires_management_session(&self) -> bool {
        match self {
            Self::Delay { .. }
            | Self::SetControlVariable { .. }
            | Self::MapError { .. }
            | Self::ClearCache
            | Self::ProgressText(_) => false,
            Self::Connect
            | Self::Disconnect
            | Self::Restart { .. }
            | Self::MasterReset { .. }
            | Self::LoadRecord(_)
            | Self::AbsoluteSegment { .. }
            | Self::ReadIntoImage { .. }
            | Self::LoadImage { .. }
            | Self::Write { .. }
            | Self::Compare { .. }
            | Self::FunctionProperty(_)
            | Self::DescribedProperty(_)
            | Self::DeclarePropertyDescriptor { .. }
            | Self::ClearLineCouplerFilter { .. } => true,
        }
    }

    pub(crate) const fn mutates_device(&self) -> bool {
        matches!(
            self,
            Self::Restart { .. }
                | Self::MasterReset { .. }
                | Self::LoadRecord(_)
                | Self::AbsoluteSegment { .. }
                | Self::Write { .. }
                | Self::DescribedProperty(DescribedPropertyOperation {
                    action: DescribedPropertyAction::Write { .. }
                        | DescribedPropertyAction::WriteImage { .. }
                        | DescribedPropertyAction::WriteImageWindow { .. },
                    ..
                })
                | Self::FunctionProperty(_)
                | Self::DeclarePropertyDescriptor { .. }
                | Self::ClearLineCouplerFilter { .. }
        )
    }
}

/// One property control sized by an execution-time selected property type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescribedPropertyOperation {
    /// A property address. Numeric count comparisons may select element zero;
    /// other actions start at element one or later.
    pub target: OperationTarget,
    pub elements: u16,
    /// Whether a type-addressed description may be read by object type.
    /// The reference does so only when the product admits extended
    /// property services and the connection carries more than 15 octets;
    /// otherwise it locates the object and reads by index.
    pub extended_description: bool,
    /// Element width in this control's direction for every fixed-size
    /// property data type, keyed by its wire number. A reported type absent
    /// here has no fixed width and fails the control.
    pub widths: BTreeMap<u8, u32>,
    pub action: DescribedPropertyAction,
}

/// Immutable inputs to a property's execution-time PDT lookup.
///
/// These are lookup rules, not assertions that a descriptor is currently
/// cached. Executed declarations and discoveries replace live descriptors;
/// cache clears and disconnects invalidate the applicable initial seeds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PropertyDataTypeLookup {
    /// Identification's indexed seeds for this PID. All known indices are
    /// retained because classic type-addressed discovery locates an index and
    /// then uses the full indexed lookup, including its mask PDT cache.
    pub indexed: BTreeMap<u8, IndexedPropertyDataTypeSeed>,
    /// A type-addressed descriptor observed before the procedure, superseded
    /// by executed declarations or subsequent discovery. It survives disconnect.
    pub initial_descriptor: Option<u8>,
    /// Well-known PDTs keyed by object type, with `None` denoting unscoped
    /// metadata. A present entry containing `None` has ambiguous or missing
    /// PDT metadata and requires discovery rather than an unscoped fallback.
    pub well_known: BTreeMap<Option<u16>, Option<u8>>,
    /// Master Data's token-to-wire-number table, used only when an executed
    /// declaration supplies a token. Like the operation's width table, this
    /// resolves types without making source declarations into cached facts.
    pub declaration_types: BTreeMap<String, u8>,
}

/// Initial indexed state for one property's runtime lookup. Cache clearing or
/// disconnect disables these seeds. A fresh connection identifies mask OT/PDT
/// metadata again, but cannot restore an old observed descriptor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexedPropertyDataTypeSeed {
    pub object_type: Option<u16>,
    /// A mask PDT seed precedes both cached descriptors and well-known metadata.
    pub property_data_type: Option<u8>,
    /// A previously observed descriptor, replaced by an executed declaration.
    pub descriptor: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescribedPropertyAction {
    /// Resolve the read geometry before testing working-image ownership.
    /// `location` denotes the property's first element. The live PDT selects
    /// both the requested element offset and the aligned unowned read window.
    LoadImage { location: ImageLocation, lookup: PropertyDataTypeLookup },
    /// Send the first `elements * width` authored bytes. Shorter authored
    /// data sends nothing: the reference finds no image segment to supply
    /// the value and skips the control without an error.
    Write { payload: Vec<u8>, policy: WriteIntent },
    /// Send the image segment that starts at the property's first element,
    /// clipped to `elements * width`. Parameters stored in a property that
    /// no metadata types lay out a segment that spans exactly their bytes
    /// from the property's start, so the segment rather than the property
    /// type bounds the write. `length` is the segment's length, resolved
    /// from the final image; a zero length sends nothing, as the reference
    /// does when no segment exists.
    WriteImage { location: ImageLocation, length: u32, policy: WriteIntent },
    /// Resolve the image offset from the target's element width. `location`
    /// denotes the property's first element and `length` its represented
    /// segment extent. A complete inline source supplies all requested bytes,
    /// overlaid by current image-owned bits. A short or absent inline source
    /// instead sends the available image suffix, retaining its ownership.
    WriteImageWindow { location: ImageLocation, length: u32, inline: Option<Vec<u8>>, policy: WriteIntent },
    /// Compare the first `elements * width` authored bytes with the value
    /// read from the target. Shorter authored data compares nothing and
    /// reads nothing. An authored mask clears bits of the leading bytes it
    /// covers; bytes beyond it stay fully compared.
    Compare {
        reference: Vec<u8>,
        mask: Option<Vec<u8>>,
        cache: CachePolicy,
        invert: bool,
        retry_interval_milliseconds: Option<u16>,
        timeout_milliseconds: Option<u32>,
    },
    /// Read the described extent and compare its numeric value, without an
    /// image reference. The reported PDT selects both width and sign extension.
    CompareRange {
        range: NumericRange,
        /// `None` requests ordinary descriptor discovery. A compiled lookup
        /// preserves native cache and well-known-metadata priorities at runtime.
        lookup: Option<PropertyDataTypeLookup>,
        cache: CachePolicy,
        invert: bool,
        retry_interval_milliseconds: Option<u16>,
        timeout_milliseconds: Option<u32>,
    },
}

impl DescribedPropertyOperation {
    /// The concrete operation for a selected property data type, or `None`
    /// when neither the authored bytes nor the selected image segment supply
    /// a payload. Image-overlay operands retain ownership selection for runtime.
    pub fn resolve(&self, property_data_type: u8) -> Result<Option<ProcedureOperation>, CompileError> {
        let numeric_count = matches!(&self.action, DescribedPropertyAction::CompareRange { .. })
            && matches!(&self.target, OperationTarget::Property { start_element: 0, .. });
        if numeric_count && self.elements != 1 {
            return Err(CompileError::invalid("numeric property count requires exactly one element"));
        }
        let width = if numeric_count {
            2
        } else {
            *self.widths.get(&property_data_type).ok_or_else(|| {
                CompileError::invalid(format!(
                    "target describes the property with PDT {property_data_type:#04x}, which has no fixed element size"
                ))
            })?
        };
        let length = u32::from(self.elements)
            .checked_mul(width)
            .ok_or_else(|| CompileError::invalid("described property length exceeds 32 bits"))?;

        let target = self.target.clone();
        Ok(match &self.action {
            DescribedPropertyAction::LoadImage { location, .. } => {
                let OperationTarget::Property { start_element: start @ 1.., .. } = target else {
                    return Err(CompileError::invalid("described image read requires an ordinary property element"));
                };
                if width == 0 || length == 0 {
                    return Err(CompileError::invalid(
                        "described image read requires a positive element width and count",
                    ));
                }
                let displacement = u32::from(start - 1)
                    .checked_mul(width)
                    .ok_or_else(|| CompileError::invalid("described image read offset exceeds 32 bits"))?;
                let image_location = ImageLocation {
                    space: location.space.clone(),
                    offset: location
                        .offset
                        .checked_add(displacement)
                        .ok_or_else(|| CompileError::invalid("described image read offset exceeds 32 bits"))?,
                };
                Some(ProcedureOperation::LoadImage {
                    target,
                    image_location,
                    extent: OperationExtent::property(length, self.elements),
                    alignment: width,
                })
            }
            DescribedPropertyAction::CompareRange {
                range,
                cache,
                invert,
                retry_interval_milliseconds,
                timeout_milliseconds,
                ..
            } => {
                // Element zero is the two-byte array count, regardless of the
                // ordinary element width. Its numeric converter still uses PDT.
                let length =
                    if matches!(target, OperationTarget::Property { start_element: 0, .. }) { 2 } else { length };
                Some(ProcedureOperation::Compare {
                    target,
                    comparison: Comparison::NumericRange {
                        range: range.clone(),
                        encoding: NumericEncoding::Property {
                            sign_extension: NumericSignExtension::for_property_data_type(property_data_type),
                        },
                    },
                    extent: OperationExtent::property(length, self.elements),
                    cache: *cache,
                    invert: *invert,
                    retry_interval_milliseconds: *retry_interval_milliseconds,
                    timeout_milliseconds: *timeout_milliseconds,
                })
            }
            DescribedPropertyAction::Write { payload, policy } => {
                let Some(bytes) = payload.get(..length as usize) else { return Ok(None) };

                Some(ProcedureOperation::Write {
                    target,
                    data: OperationData::Inline(bytes.to_vec()),
                    extent: OperationExtent::property(length, self.elements),
                    policy: *policy,
                })
            }

            // The reference clips the described size to the segment and
            // sends only the segment's bytes. Its wire count covers that
            // clipped payload, including a partially supplied final element.
            DescribedPropertyAction::WriteImage { location, length: segment, policy } => {
                let sent = length.min(*segment);
                if sent == 0 {
                    return Ok(None);
                }

                Some(ProcedureOperation::Write {
                    target,
                    data: OperationData::Buffer { location: location.clone(), length: sent, fallback: None },
                    extent: OperationExtent::property_window(sent, width)?,
                    policy: *policy,
                })
            }

            DescribedPropertyAction::WriteImageWindow { location, length: segment, inline, policy } => {
                let OperationTarget::Property { start_element: start @ 1.., .. } = target else {
                    return Err(CompileError::invalid("described image window requires an ordinary property element"));
                };
                if width == 0 {
                    return Err(CompileError::invalid("described image window has zero-byte elements"));
                }
                if length == 0 {
                    return Ok(None);
                }
                let displacement = u32::from(start - 1)
                    .checked_mul(width)
                    .ok_or_else(|| CompileError::invalid("described image offset exceeds 32 bits"))?;
                let location = ImageLocation {
                    space: location.space.clone(),
                    offset: location
                        .offset
                        .checked_add(displacement)
                        .ok_or_else(|| CompileError::invalid("described image offset exceeds 32 bits"))?,
                };
                let (data, sent) = if let Some(payload) = inline.as_ref().filter(|bytes| bytes.len() >= length as usize)
                {
                    // A fallback-first Buffer would bypass the desired image.
                    // Keep the overlay explicit until the current working image
                    // is available, after the target description is resolved.
                    (
                        OperationData::ImageOverlay { location, length, inline: payload[..length as usize].to_vec() },
                        length,
                    )
                } else {
                    let sent = length.min(segment.saturating_sub(displacement));
                    if sent == 0 {
                        return Ok(None);
                    }
                    (OperationData::Buffer { location, length: sent, fallback: None }, sent)
                };
                Some(ProcedureOperation::Write {
                    target,
                    data,
                    extent: OperationExtent::property_window(sent, width)?,
                    policy: *policy,
                })
            }

            DescribedPropertyAction::Compare {
                reference,
                mask,
                cache,
                invert,
                retry_interval_milliseconds,
                timeout_milliseconds,
            } => {
                let Some(bytes) = reference.get(..length as usize) else { return Ok(None) };

                // The reference starts from a full mask over the compared
                // bytes and ANDs the authored mask into its common prefix.
                let mask = mask.as_ref().map(|authored| {
                    let mut effective = vec![u8::MAX; bytes.len()];
                    for (bits, authored) in effective.iter_mut().zip(authored) {
                        *bits &= authored;
                    }
                    effective
                });

                Some(ProcedureOperation::Compare {
                    target,
                    comparison: Comparison::Exact {
                        data: OperationData::Inline(bytes.to_vec()),
                        mask,
                        padding: ComparisonPadding::None,
                    },
                    extent: OperationExtent::property(length, self.elements),
                    cache: *cache,
                    invert: *invert,
                    retry_interval_milliseconds: *retry_interval_milliseconds,
                    timeout_milliseconds: *timeout_milliseconds,
                })
            }
        })
    }
}

/// Verification strategy selected for one concrete write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritePolicy {
    NoVerification,
    ReadBack,
    Optimistic,
    DeviceAutoVerify,
}

/// Authored verification intent. Ordered tool variables remain runtime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteIntent {
    Explicit(WritePolicy),
    Memory { verify: bool },
    Relative { verify: bool },
    AbsoluteSegment,
    Property { verify: bool },
}

impl WriteIntent {
    /// Verified memory writes and absolute-segment transfers prefer device
    /// auto-verification, then optimistic writes, then read-back. Relative
    /// memory writes skip the optimistic policy; property writes use read-back.
    /// The direct-write verification flag does not promote unverified writes.
    /// `verify_mode` is the resolved profile's VerifyMode feature; an ordered
    /// tool-state override takes precedence over that initial capability.
    pub fn resolve(self, state: ToolState, verify_mode: bool) -> WritePolicy {
        let auto_verify = state.memory_auto_verify.unwrap_or(verify_mode);
        match self {
            Self::Explicit(policy) => policy,
            Self::Property { verify: true } => WritePolicy::ReadBack,
            Self::Property { verify: false } | Self::Relative { verify: false } | Self::Memory { verify: false } => {
                WritePolicy::NoVerification
            }
            Self::Relative { verify: true } if auto_verify => WritePolicy::DeviceAutoVerify,
            Self::Relative { verify: true } => WritePolicy::ReadBack,
            Self::Memory { verify: true } | Self::AbsoluteSegment => {
                if auto_verify {
                    WritePolicy::DeviceAutoVerify
                } else if state.optimistic_writes {
                    WritePolicy::Optimistic
                } else {
                    WritePolicy::ReadBack
                }
            }
        }
    }
}

pub use crate::commissioning::procedure::operands::{OperationTarget, ServiceRead};

/// Bytes supplied to a write or comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationData {
    Inline(Vec<u8>),
    /// A runtime buffer value, optionally with an authored default.
    Buffer {
        location: ImageLocation,
        length: u32,
        fallback: Option<Vec<u8>>,
    },
    /// Overlay current image-owned bits on a complete authored source. Unlike
    /// `Buffer`, the inline source never bypasses partially owned image data.
    ImageOverlay {
        location: ImageLocation,
        length: u32,
        inline: Vec<u8>,
    },
    /// Opaque reference into the private payload owned by a prepared
    /// commissioning operation. The public plan exposes length and ordering,
    /// never the referenced key bytes.
    Secret(SecretPayloadReference),
    Image {
        location: ImageLocation,
        length: u32,
    },
    /// One authored transfer window. The executor skips unowned gaps while
    /// retaining the original control's single error boundary.
    ImageWindow {
        location: ImageLocation,
        maximum: u32,
    },
}

/// Wire-service extent for one operation.
///
/// Property services encode an element count independently from the number of
/// value octets. Keeping both prevents the device-management layer from
/// guessing a property data type from the payload length. Byte-addressed
/// services leave `property_elements` unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationExtent {
    pub byte_length: u32,
    pub property_elements: Option<u16>,
    /// Resolved property width when the selected image ends inside an element.
    /// Complete transfers infer their width from bytes and count as before.
    pub property_element_width: Option<u32>,
}

impl OperationExtent {
    pub const fn bytes(byte_length: u32) -> Self {
        Self { byte_length, property_elements: None, property_element_width: None }
    }

    pub const fn property(byte_length: u32, elements: u16) -> Self {
        Self { byte_length, property_elements: Some(elements), property_element_width: None }
    }

    /// A clipped window retains its resolved PDT width without inventing source bytes.
    pub(crate) fn property_window(byte_length: u32, width: u32) -> Result<Self, CompileError> {
        if byte_length == 0 || width == 0 {
            return Err(CompileError::invalid("property window requires positive bytes and width"));
        }
        let count = u16::try_from(byte_length.div_ceil(width))
            .map_err(|_| CompileError::invalid("property window exceeds the element count field"))?;
        Ok(Self {
            byte_length,
            property_elements: Some(count),
            property_element_width: (!byte_length.is_multiple_of(width)).then_some(width),
        })
    }

    /// A clipped window may select only the prefix of its final element.
    pub(crate) fn element_width(self) -> Result<u32, CompileError> {
        let Some(count) = self.property_elements else {
            return if self.property_element_width.is_none() {
                Ok(1)
            } else {
                Err(CompileError::invalid("memory transfer carries a property element width"))
            };
        };
        if count == 0 {
            return Err(CompileError::invalid("property transfer has no element count"));
        }
        if let Some(width) = self.property_element_width {
            if width == 0 || self.byte_length == 0 || self.byte_length.div_ceil(width) != u32::from(count) {
                return Err(CompileError::invalid("property window has inconsistent element geometry"));
            }
            return Ok(width);
        }
        if self.byte_length == 0 || self.byte_length % u32::from(count) != 0 {
            return Err(CompileError::invalid("property bytes do not contain complete elements"));
        }
        Ok(self.byte_length / u32::from(count))
    }
}

/// Comparison performed by one load control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Comparison {
    Exact {
        data: OperationData,
        mask: Option<Vec<u8>>,
        padding: ComparisonPadding,
    },
    /// Compare against image reference bytes using the image's current
    /// ownership intersected with the authored mask. This is read-only: it
    /// never fills unowned reference bits by reading the device. A successful
    /// LoadImage can change both the reference and its ownership.
    ImageExact {
        location: ImageLocation,
        length: u32,
        mask: Option<Vec<u8>>,
    },
    NumericRange {
        range: NumericRange,
        encoding: NumericEncoding,
    },
}

/// Inclusive numeric interval, independent of source byte encoding.
/// Native endpoint normalization wraps exclusive extrema. A lower endpoint
/// above the upper endpoint represents an empty interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NumericRange {
    Unsigned { lower: u64, upper: u64 },
    Signed { lower: i64, upper: i64 },
}

/// Source-specific conversion before the numeric interval is evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericEncoding {
    /// Tool-selected memory byte order, with zero extension of short values.
    Memory,
    /// Properties are always big-endian. PDT signedness controls extension,
    /// independently of whether the interval itself is signed or unsigned.
    Property { sign_extension: NumericSignExtension },
}

/// How a short property value fills the remaining bits of a 64-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericSignExtension {
    Zero,
    Sign,
}

impl NumericSignExtension {
    pub(crate) fn for_property_data_type(pdt: u8) -> Self {
        if matches!(pdt, 1 | 3 | 8) { Self::Sign } else { Self::Zero }
    }
}

/// Length semantics of an exact load-control comparison.
///
/// Property identity values in published product procedures may occupy a
/// fixed-width XML field whose unused suffix is zero-filled. That suffix is
/// not part of the property element returned by the device. Memory controls,
/// by contrast, always compare an exact byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonPadding {
    None,
    ExpectedTrailingZeros,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    Bypass,
    UseAndPopulate,
    Populate,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn described_image_windows_resolve_offsets_before_selecting_the_source() {
        let location = ImageLocation {
            space: ImageSpace::Property { object: ObjectSelector::Index { index: 4 }, property_id: 238 },
            offset: 0,
        };
        let mut operation = DescribedPropertyOperation {
            target: OperationTarget::Property {
                address: operands::PropertyAddress::Indexed { object_index: 4, property_id: 238 },
                start_element: 2,
            },
            elements: 2,
            extended_description: false,
            widths: BTreeMap::from([(2, 1), (4, 2), (20, 4), (24, 8)]),
            action: DescribedPropertyAction::WriteImageWindow {
                location: location.clone(),
                length: 6,
                inline: Some(vec![0xa5; 10]),
                policy: WriteIntent::Property { verify: true },
            },
        };
        for (pdt, offset, length) in [(2, 1, 2), (4, 2, 4), (20, 4, 8)] {
            let Some(ProcedureOperation::Write { target, data, extent, policy }) =
                operation.resolve(pdt).expect("known description selects a window")
            else {
                panic!("described write")
            };
            assert_eq!(target, operation.target);
            assert_eq!(policy, WriteIntent::Property { verify: true });
            assert_eq!(extent, OperationExtent::property(length, 2));
            assert_eq!(data, OperationData::ImageOverlay {
                location: ImageLocation { offset, ..location.clone() },
                length,
                inline: vec![0xa5; length as usize],
            });
        }
        assert!(operation.resolve(24).expect("short inline and missing suffix skip").is_none());
        for inline in [None, Some(vec![]), Some(vec![0x99])] {
            operation.action = DescribedPropertyAction::WriteImageWindow {
                location: location.clone(),
                length: 5,
                inline,
                policy: WriteIntent::Property { verify: true },
            };
            let Some(ProcedureOperation::Write { data, extent, .. }) =
                operation.resolve(4).expect("short source selects the image suffix")
            else {
                panic!("clipped image write")
            };
            assert_eq!(extent, OperationExtent::property_window(3, 2).expect("partial last element"));
            assert_eq!(data, OperationData::Buffer {
                location: ImageLocation { offset: 2, ..location.clone() },
                length: 3,
                fallback: None,
            });
        }
        operation.widths.insert(4, u32::MAX);
        operation.elements = 1;
        operation.target = OperationTarget::Property {
            address: operands::PropertyAddress::Indexed { object_index: 4, property_id: 238 },
            start_element: 3,
        };
        assert!(operation.resolve(4).is_err(), "runtime offset arithmetic stays checked");
    }

    #[test]
    fn described_image_writes_count_the_clipped_payload_and_retain_its_width() {
        let location = ImageLocation {
            space: ImageSpace::Property { object: ObjectSelector::Index { index: 4 }, property_id: 52 },
            offset: 0,
        };
        for (segment, sent, elements) in [(0, 0, 0), (1, 1, 1), (3, 3, 2), (59, 59, 30), (160, 160, 80), (161, 160, 80)]
        {
            let operation = DescribedPropertyOperation {
                target: OperationTarget::Property {
                    address: operands::PropertyAddress::Indexed { object_index: 4, property_id: 52 },
                    start_element: 1,
                },
                elements: 80,
                extended_description: false,
                widths: BTreeMap::from([(4, 2)]),
                action: DescribedPropertyAction::WriteImage {
                    location: location.clone(),
                    length: segment,
                    policy: WriteIntent::Property { verify: false },
                },
            };
            let resolved = operation.resolve(4).expect("known two-byte PDT");
            if sent == 0 {
                assert!(resolved.is_none());
                continue;
            }
            let Some(ProcedureOperation::Write { extent, data, .. }) = resolved else { panic!("resolved image write") };
            assert_eq!(extent.byte_length, sent);
            assert_eq!(extent.property_elements, Some(elements));
            assert_eq!(extent.element_width().expect("resolved width"), 2);
            assert_eq!(extent.property_element_width, (!sent.is_multiple_of(2)).then_some(2));
            assert_eq!(data, OperationData::Buffer { location: location.clone(), length: sent, fallback: None });
        }
        assert!(OperationExtent::property_window(1, 0).is_err());
        assert!(OperationExtent::property_window(0, 2).is_err());
        assert!(OperationExtent::property_window(65536, 1).is_err());
        assert!(OperationExtent::property(59, 30).element_width().is_err(), "ordinary extents stay strict");
    }

    #[test]
    fn write_policies_follow_ets_get_write_options() {
        use WriteIntent::*;
        use WritePolicy::*;
        let state = |optimistic_writes, memory_auto_verify, verify_direct_writes| ToolState {
            optimistic_writes,
            memory_auto_verify,
            verify_direct_writes,
            ..ToolState::default()
        };
        // Verified memory writes and absolute-segment transfers share the
        // same precedence for device verification and optimistic writes.
        for intent in [Memory { verify: true }, AbsoluteSegment] {
            assert_eq!(intent.resolve(state(true, None, false), false), Optimistic);
            assert_eq!(intent.resolve(state(false, None, false), false), ReadBack);
            assert_eq!(intent.resolve(state(true, None, false), true), DeviceAutoVerify);
            assert_eq!(intent.resolve(state(true, Some(false), false), true), Optimistic);
        }
        // Relative memory never writes optimistically.
        assert_eq!(Relative { verify: true }.resolve(state(true, None, false), false), ReadBack);
        assert_eq!(Relative { verify: true }.resolve(state(true, Some(true), false), false), DeviceAutoVerify);
        // The direct-write verification flag leaves unverified writes unchanged.
        for intent in [Memory { verify: false }, Relative { verify: false }, Property { verify: false }] {
            assert_eq!(intent.resolve(state(true, Some(true), true), true), NoVerification);
        }
        assert_eq!(Property { verify: true }.resolve(state(true, Some(true), false), true), ReadBack);
    }
}
