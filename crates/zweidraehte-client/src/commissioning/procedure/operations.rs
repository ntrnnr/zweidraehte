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
    /// A property write or comparison whose element type only the target's
    /// property description supplies.
    ///
    /// Neither the mask profile, Master Data, a procedure declaration nor an
    /// observation types the property, so its byte extent is unknown until
    /// the control executes. The reference then asks the device for the
    /// property's description, sizes the transfer as `elements` times the
    /// reported type's width, and uses the authored bytes only when they are
    /// at least that long. The executor resolves the same way.
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
                    action: DescribedPropertyAction::Write { .. } | DescribedPropertyAction::WriteImage { .. },
                    ..
                })
                | Self::FunctionProperty(_)
                | Self::DeclarePropertyDescriptor { .. }
                | Self::ClearLineCouplerFilter { .. }
        )
    }
}

/// One indexed property control sized by the target's property description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescribedPropertyOperation {
    /// Always an indexed property address with a start element of at least
    /// one. Type-addressed lookups locate the object first and are not
    /// modelled.
    pub target: OperationTarget,
    pub elements: u16,
    /// Element width in this control's direction for every fixed-size
    /// property data type, keyed by its wire number. A reported type absent
    /// here has no fixed width and fails the control.
    pub widths: BTreeMap<u8, u32>,
    pub action: DescribedPropertyAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescribedPropertyAction {
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
    /// Compare the first `elements * width` authored bytes with the value
    /// read from the target. Shorter authored data compares nothing and
    /// reads nothing.
    Compare {
        reference: Vec<u8>,
        cache: CachePolicy,
        invert: bool,
        retry_interval_milliseconds: Option<u16>,
        timeout_milliseconds: Option<u32>,
    },
}

impl DescribedPropertyOperation {
    /// The concrete operation for a reported property data type, or `None`
    /// when the authored bytes are shorter than the described extent or no
    /// image segment exists.
    pub fn resolve(&self, property_data_type: u8) -> Result<Option<ProcedureOperation>, CompileError> {
        let width = *self.widths.get(&property_data_type).ok_or_else(|| {
            CompileError::invalid(format!(
                "target describes the property with PDT {property_data_type:#04x}, which has no fixed element size"
            ))
        })?;
        let length = u32::from(self.elements)
            .checked_mul(width)
            .ok_or_else(|| CompileError::invalid("described property length exceeds 32 bits"))?;

        let target = self.target.clone();
        Ok(match &self.action {
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
            // sends the segment's bytes. The element count stays the authored
            // one even when the segment is shorter than the described
            // elements.
            DescribedPropertyAction::WriteImage { location, length: segment, policy } => {
                let sent = length.min(*segment);
                if sent == 0 {
                    return Ok(None);
                }

                Some(ProcedureOperation::Write {
                    target,
                    data: OperationData::Buffer { location: location.clone(), length: sent, fallback: None },
                    extent: OperationExtent::property(sent, self.elements),
                    policy: *policy,
                })
            }

            DescribedPropertyAction::Compare {
                reference,
                cache,
                invert,
                retry_interval_milliseconds,
                timeout_milliseconds,
            } => {
                let Some(bytes) = reference.get(..length as usize) else { return Ok(None) };

                Some(ProcedureOperation::Compare {
                    target,
                    comparison: Comparison::Exact {
                        data: OperationData::Inline(bytes.to_vec()),
                        mask: None,
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
}

impl OperationExtent {
    pub const fn bytes(byte_length: u32) -> Self {
        Self { byte_length, property_elements: None }
    }

    pub const fn property(byte_length: u32, elements: u16) -> Self {
        Self { byte_length, property_elements: Some(elements) }
    }

    /// Transfer comparisons and wire chunks share complete-element geometry.
    pub(crate) fn element_width(self) -> Result<u32, CompileError> {
        let Some(count) = self.property_elements else { return Ok(1) };
        if count == 0 {
            return Err(CompileError::invalid("property transfer has no element count"));
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
    UnsignedRange {
        lower: RangeBound<u64>,
        upper: RangeBound<u64>,
    },
    SignedRange {
        lower: RangeBound<i64>,
        upper: RangeBound<i64>,
    },
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

/// One endpoint of an XML comparison range. Open and exclusive endpoints are
/// meaningful in the load-control DSL and cannot be normalized away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeBound<T> {
    Unbounded,
    Inclusive(T),
    Exclusive(T),
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
