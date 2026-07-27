//! Canonical form types for semantic comparison.
//!
//! This module defines canonical representations of KNX ApplicationProgram elements
//! that allow comparison by semantic keys rather than arbitrary IDs.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use zweidraehte_knxprod::schema::{
    ApplicationProgram, ComObject, EnableFlag, ParameterItem, ParameterType, ParameterTypeDef,
};

use super::visibility::{CanonicalVisibilityMap, RefKey, VisibilityMap};

// ============================================================================
// Semantic Keys
// ============================================================================

/// Semantic key for a parameter based on its memory location.
///
/// This key uniquely identifies a parameter independent of its ID string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParameterKey {
    /// Memory offset in bytes from segment start.
    pub memory_offset: u32,
    /// Bit offset within the byte (0-7).
    pub bit_offset: u8,
    /// Size in bits.
    pub size_bits: u32,
}

impl ParameterKey {
    /// Create a new parameter key.
    pub fn new(memory_offset: u32, bit_offset: u8, size_bits: u32) -> Self {
        Self { memory_offset, bit_offset, size_bits }
    }
}

impl std::fmt::Display for ParameterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:X}:{}:{}", self.memory_offset, self.bit_offset, self.size_bits)
    }
}

// ============================================================================
// Type Signatures
// ============================================================================

/// Type signature for semantic comparison of parameter types.
///
/// Two types with the same signature are considered semantically equivalent,
/// regardless of their IDs or names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypeSignature {
    /// Numeric type with range.
    Number { signed: bool, min: i64, max: i64, size_bits: u32 },
    /// Enumeration type with named values.
    Enum {
        /// Sorted map of value -> display text.
        variants: BTreeMap<i64, String>,
        size_bits: u32,
    },
    /// Text type.
    Text { max_chars: usize, pattern: Option<String> },
    /// Raw bytes (no type).
    None { size_bits: u32 },
}

impl TypeSignature {
    /// Extract type signature from a parsed ParameterType.
    // FIXME: should we derive this from the DPT definitions in the master data?
    pub fn from_param_type(pt: &ParameterType) -> Self {
        match &pt.type_def {
            ParameterTypeDef::TypeNumber(tn) => TypeSignature::Number {
                signed: tn.num_type == "signedInt",
                min: tn.min_inclusive,
                max: tn.max_inclusive,
                size_bits: tn.size_in_bit as u32,
            },
            ParameterTypeDef::TypeFloat(tf) => {
                // Treat float as a number with the encoding in the pattern
                TypeSignature::Number {
                    signed: true,
                    min: tf.min_inclusive as i64,
                    max: tf.max_inclusive as i64,
                    size_bits: 16, // DPT 9 is 16 bits
                }
            }
            ParameterTypeDef::TypeRestriction(tr) => {
                let variants: BTreeMap<i64, String> =
                    tr.enumerations.iter().map(|e| (e.value as i64, normalize_text(&e.text))).collect();
                TypeSignature::Enum { variants, size_bits: tr.size_in_bit }
            }
            ParameterTypeDef::TypeText(tt) => {
                TypeSignature::Text { max_chars: (tt.size_in_bit / 8) as usize, pattern: tt.pattern.clone() }
            }
            ParameterTypeDef::TypeNone(_) => TypeSignature::None { size_bits: 0 },
            ParameterTypeDef::TypePicture(_) => TypeSignature::None { size_bits: 0 },
            ParameterTypeDef::TypeIpAddress(_) => TypeSignature::None { size_bits: 32 },
        }
    }

    /// Get the size in bits for this type.
    pub fn size_bits(&self) -> u32 {
        match self {
            TypeSignature::Number { size_bits, .. } => *size_bits,
            TypeSignature::Enum { size_bits, .. } => *size_bits,
            TypeSignature::Text { max_chars, .. } => (*max_chars * 8) as u32,
            TypeSignature::None { size_bits } => *size_bits,
        }
    }
}

// ============================================================================
// Canonical Parameter
// ============================================================================

/// Canonical representation of a parameter.
///
/// The semantic key is deliberately not repeated here: parameters are only ever
/// reached through [`CanonicalProgram::parameters`], which is keyed by it.
#[derive(Debug, Clone)]
pub struct CanonicalParameter {
    /// Original ID, for pointing at the element in the source XML.
    pub original_id: String,
    /// Display name.
    pub name: String,
    /// Display text (normalized).
    pub text: String,
    /// Type signature.
    pub type_signature: TypeSignature,
    /// Default value as string.
    pub default_value: String,
    /// Whether this parameter is hidden (Access="None").
    pub hidden: bool,
    /// Suffix text if any.
    pub suffix_text: Option<String>,
}

// ============================================================================
// Canonical Communication Object
// ============================================================================

/// Canonical representation of a communication object.
///
/// As with [`CanonicalParameter`], the object number lives in the key of
/// [`CanonicalProgram::com_objects`] rather than being duplicated here.
#[derive(Debug, Clone)]
pub struct CanonicalComObject {
    /// Original ID, for pointing at the element in the source XML.
    pub original_id: String,
    /// Object name.
    pub name: String,
    /// Display text (normalized).
    pub text: String,
    /// Function text.
    pub function_text: String,
    /// Object size string (e.g., "1 Bit", "2 Bytes").
    pub object_size: String,
    /// Default datapoint type if specified.
    pub datapoint_type: Option<String>,
    /// Communication object flags.
    pub flags: ComObjectFlags,
}

/// Communication object flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ComObjectFlags {
    pub read: bool,
    pub write: bool,
    pub communicate: bool,
    pub transmit: bool,
    pub update: bool,
    pub read_on_init: bool,
}

impl ComObjectFlags {
    /// Create from a parsed ComObject.
    pub fn from_com_object(obj: &ComObject) -> Self {
        Self {
            read: obj.read_flag == EnableFlag::Enabled,
            write: obj.write_flag == EnableFlag::Enabled,
            communicate: obj.communication_flag == EnableFlag::Enabled,
            transmit: obj.transmit_flag == EnableFlag::Enabled,
            update: obj.update_flag == EnableFlag::Enabled,
            read_on_init: obj.read_on_init_flag == EnableFlag::Enabled,
        }
    }
}

// ============================================================================
// Canonical Parameter Reference
// ============================================================================

/// Canonical representation of a parameter reference.
#[derive(Debug, Clone)]
pub struct CanonicalParamRef {
    /// Original ref ID.
    pub original_id: String,
    /// Key of the referenced parameter.
    pub param_key: ParameterKey,
    /// Text override if any (normalized).
    pub text_override: Option<String>,
    /// Value override if any.
    pub value_override: Option<String>,
    /// Whether hidden via Access="None".
    pub hidden: bool,
    /// Index of this ref among refs for the same parameter.
    pub ref_index: usize,
}

impl CanonicalParamRef {
    /// The semantic identity of this reference.
    pub fn ref_key(&self) -> RefKey {
        RefKey::Param { key: self.param_key, ref_index: self.ref_index }
    }
}

// ============================================================================
// Canonical ComObject Reference
// ============================================================================

/// Canonical representation of a communication object reference.
#[derive(Debug, Clone)]
pub struct CanonicalComObjectRef {
    /// Original ref ID.
    pub original_id: String,
    /// Number of the referenced object.
    pub object_number: u16,
    /// Text override if any (normalized).
    pub text_override: Option<String>,
    /// Function text override if any.
    pub function_text_override: Option<String>,
    /// Datapoint type override if any.
    pub datapoint_type: Option<String>,
    /// Flag overrides if any.
    pub flag_overrides: Option<ComObjectFlags>,
    /// Index of this ref among refs for the same object.
    pub ref_index: usize,
}

impl CanonicalComObjectRef {
    /// The semantic identity of this reference.
    pub fn ref_key(&self) -> RefKey {
        RefKey::ComObject { number: self.object_number, ref_index: self.ref_index }
    }
}

// ============================================================================
// Canonical Program
// ============================================================================

/// Canonical representation of an application program.
///
/// This struct contains all program elements indexed by semantic keys,
/// enabling comparison without relying on ID strings.
#[derive(Debug, Clone)]
pub struct CanonicalProgram {
    /// Program metadata.
    pub metadata: ProgramMetadata,
    /// Parameters keyed by memory location.
    pub parameters: BTreeMap<ParameterKey, CanonicalParameter>,
    /// Type signatures (deduplicated).
    pub type_signatures: BTreeSet<TypeSignature>,
    /// Communication objects keyed by number.
    pub com_objects: BTreeMap<u16, CanonicalComObject>,
    /// Parameter references with their visibility constraints.
    pub param_refs: Vec<CanonicalParamRef>,
    /// ComObject references with their visibility constraints.
    pub com_object_refs: Vec<CanonicalComObjectRef>,
    /// ID to parameter key mapping (for resolving references).
    pub id_to_param_key: HashMap<String, ParameterKey>,
    /// ID to object number mapping (for resolving references).
    pub id_to_object_number: HashMap<String, u16>,
    /// Parameter ref ID to index mapping.
    pub param_ref_id_to_index: HashMap<String, usize>,
    /// ComObject ref ID to index mapping.
    pub com_object_ref_id_to_index: HashMap<String, usize>,
    /// Code segments that parameters store their values in, with the declared
    /// size of each. Used to size the memory image for the layout comparison.
    pub param_segments: BTreeMap<String, u32>,
    /// Visibility constraints from the Dynamic section, reduced to semantic keys.
    pub visibility: CanonicalVisibilityMap,

    // For strict mode: preserve ordering
    /// Parameters in original order (for ordering comparison).
    pub parameter_order: Vec<ParameterKey>,
    /// Parameter refs in original order.
    pub param_ref_order: Vec<String>,
    /// ComObject refs in original order.
    pub com_object_ref_order: Vec<String>,
}

/// Program metadata.
#[derive(Debug, Clone, Default)]
pub struct ProgramMetadata {
    pub id: String,
    pub name: String,
    pub application_number: u16,
    pub application_version: u8,
    pub mask_version: String,
}

impl CanonicalProgram {
    /// Create a canonical program from a parsed ApplicationProgram.
    pub fn from_parsed(program: &ApplicationProgram) -> Self {
        let mut canonical = Self {
            metadata: ProgramMetadata {
                id: program.id.clone(),
                name: program.name.clone(),
                application_number: program.application_number,
                application_version: program.application_version,
                mask_version: program.mask_version.clone(),
            },
            parameters: BTreeMap::new(),
            type_signatures: BTreeSet::new(),
            com_objects: BTreeMap::new(),
            param_refs: Vec::new(),
            com_object_refs: Vec::new(),
            id_to_param_key: HashMap::new(),
            id_to_object_number: HashMap::new(),
            param_ref_id_to_index: HashMap::new(),
            com_object_ref_id_to_index: HashMap::new(),
            param_segments: BTreeMap::new(),
            visibility: CanonicalVisibilityMap::default(),
            parameter_order: Vec::new(),
            param_ref_order: Vec::new(),
            com_object_ref_order: Vec::new(),
        };

        // Build type signature lookup
        let mut type_id_to_sig: HashMap<String, TypeSignature> = HashMap::new();
        if let Some(ref param_types) = program.static_section.parameter_types {
            for pt in &param_types.types {
                let sig = TypeSignature::from_param_type(pt);
                canonical.type_signatures.insert(sig.clone());
                type_id_to_sig.insert(pt.id.clone(), sig);
            }
        }

        // Declared sizes of every code segment, keyed by segment ID. System 7
        // programs use absolute segments and System B ones relative segments;
        // for sizing a memory image only the declared size matters, not where
        // the segment lives, so both kinds go into the same lookup.
        let mut segment_sizes: HashMap<&str, u32> = HashMap::new();
        if let Some(ref code) = program.static_section.code {
            for segment in &code.absolute_segments {
                segment_sizes.insert(&segment.id, segment.size);
            }
            for segment in &code.relative_segments {
                segment_sizes.insert(&segment.id, segment.size);
            }
        }

        // Process parameters
        if let Some(ref params) = program.static_section.parameters {
            for item in &params.items {
                match item {
                    ParameterItem::Parameter(p) => {
                        if let Some(ref mem) = p.memory {
                            if let Some(&size) = segment_sizes.get(mem.code_segment.as_str()) {
                                canonical.param_segments.insert(mem.code_segment.clone(), size);
                            }
                            let type_sig = type_id_to_sig
                                .get(&p.parameter_type)
                                .cloned()
                                .unwrap_or(TypeSignature::None { size_bits: 0 });
                            let key = ParameterKey::new(mem.offset, mem.bit_offset, type_sig.size_bits());
                            let cp = CanonicalParameter {
                                original_id: p.id.clone(),
                                name: p.name.clone(),
                                text: normalize_text(&p.text),
                                type_signature: type_sig,
                                default_value: p.value.clone(),
                                hidden: p.access.as_deref() == Some("None"),
                                suffix_text: normalize_optional_text(&p.suffix_text),
                            };
                            canonical.id_to_param_key.insert(p.id.clone(), key);
                            canonical.parameter_order.push(key);
                            canonical.parameters.insert(key, cp);
                        }
                    }
                    ParameterItem::Union(u) => {
                        if let Some(&size) = segment_sizes.get(u.memory.code_segment.as_str()) {
                            canonical.param_segments.insert(u.memory.code_segment.clone(), size);
                        }

                        // Process union parameters
                        for up in &u.parameters {
                            let type_sig = type_id_to_sig
                                .get(&up.parameter_type)
                                .cloned()
                                .unwrap_or(TypeSignature::None { size_bits: 0 });
                            let key = ParameterKey::new(
                                u.memory.offset + up.offset as u32,
                                up.bit_offset,
                                type_sig.size_bits(),
                            );
                            let cp = CanonicalParameter {
                                original_id: up.id.clone(),
                                name: up.name.clone(),
                                text: normalize_text(&up.text),
                                type_signature: type_sig,
                                default_value: up.value.clone(),
                                hidden: false, // Union params don't have access attr
                                suffix_text: normalize_optional_text(&up.suffix_text),
                            };
                            canonical.id_to_param_key.insert(up.id.clone(), key);
                            canonical.parameter_order.push(key);
                            canonical.parameters.insert(key, cp);
                        }
                    }
                }
            }
        }

        // Process communication objects
        if let Some(ref com_table) = program.static_section.com_object_table {
            for obj in &com_table.objects {
                let co = CanonicalComObject {
                    original_id: obj.id.clone(),
                    name: obj.name.clone(),
                    text: normalize_text(&obj.text),
                    function_text: obj.function_text.clone(),
                    object_size: obj.object_size.clone(),
                    datapoint_type: normalize_optional_text(&obj.datapoint_type),
                    flags: ComObjectFlags::from_com_object(obj),
                };
                canonical.id_to_object_number.insert(obj.id.clone(), obj.number);
                canonical.com_objects.insert(obj.number, co);
            }
        }

        // Process parameter references
        if let Some(ref param_refs) = program.static_section.parameter_refs {
            // Count refs per parameter to assign indices
            let mut ref_counts: HashMap<ParameterKey, usize> = HashMap::new();

            for pr in &param_refs.refs {
                // Resolve the parameter this ref points to
                if let Some(&param_key) = canonical.id_to_param_key.get(&pr.ref_id) {
                    let ref_index = *ref_counts.get(&param_key).unwrap_or(&0);
                    ref_counts.insert(param_key, ref_index + 1);

                    let cpr = CanonicalParamRef {
                        original_id: pr.id.clone(),
                        param_key,
                        text_override: normalize_optional_text(&pr.text),
                        value_override: pr.value.clone(),
                        hidden: pr.access.as_deref() == Some("None"),
                        ref_index,
                    };
                    let idx = canonical.param_refs.len();
                    canonical.param_ref_id_to_index.insert(pr.id.clone(), idx);
                    canonical.param_ref_order.push(pr.id.clone());
                    canonical.param_refs.push(cpr);
                }
            }
        }

        // Process communication object references
        if let Some(ref com_refs) = program.static_section.com_object_refs {
            // Count refs per object to assign indices
            let mut ref_counts: HashMap<u16, usize> = HashMap::new();

            for cr in &com_refs.refs {
                // Resolve the object this ref points to
                if let Some(&obj_num) = canonical.id_to_object_number.get(&cr.ref_id) {
                    let ref_index = *ref_counts.get(&obj_num).unwrap_or(&0);
                    ref_counts.insert(obj_num, ref_index + 1);

                    let flag_overrides = if cr.read_flag.is_some()
                        || cr.write_flag.is_some()
                        || cr.communication_flag.is_some()
                        || cr.transmit_flag.is_some()
                        || cr.update_flag.is_some()
                        || cr.read_on_init_flag.is_some()
                    {
                        Some(ComObjectFlags {
                            read: cr.read_flag.map(|f| f == EnableFlag::Enabled).unwrap_or(false),
                            write: cr.write_flag.map(|f| f == EnableFlag::Enabled).unwrap_or(false),
                            communicate: cr.communication_flag.map(|f| f == EnableFlag::Enabled).unwrap_or(false),
                            transmit: cr.transmit_flag.map(|f| f == EnableFlag::Enabled).unwrap_or(false),
                            update: cr.update_flag.map(|f| f == EnableFlag::Enabled).unwrap_or(false),
                            read_on_init: cr.read_on_init_flag.map(|f| f == EnableFlag::Enabled).unwrap_or(false),
                        })
                    } else {
                        None
                    };

                    let cor = CanonicalComObjectRef {
                        original_id: cr.id.clone(),
                        object_number: obj_num,
                        text_override: normalize_optional_text(&cr.text),
                        function_text_override: normalize_optional_text(&cr.function_text),
                        datapoint_type: normalize_optional_text(&cr.datapoint_type),
                        flag_overrides,
                        ref_index,
                    };
                    let idx = canonical.com_object_refs.len();
                    canonical.com_object_ref_id_to_index.insert(cr.id.clone(), idx);
                    canonical.com_object_ref_order.push(cr.id.clone());
                    canonical.com_object_refs.push(cor);
                }
            }
        }

        // Visibility comes last: canonicalizing it needs the ref lookups built above.
        canonical.visibility = VisibilityMap::from_program(program).canonicalize(&canonical);

        canonical
    }

    /// Size of the memory image spanned by this program's parameters.
    ///
    /// `Err` carries the reason no single image applies. Parameters are keyed by
    /// offset alone ([`ParameterKey`] deliberately ignores the segment, so that
    /// two programs naming their segments differently still match up), which
    /// only holds while every parameter lives in one segment. A program that
    /// spreads parameters over several segments would alias offsets between
    /// them, so we refuse rather than compare nonsense.
    pub fn memory_image_size(&self) -> Result<u32, String> {
        match self.param_segments.len() {
            0 => Err("no code segment carries parameters".to_string()),
            1 => Ok(*self.param_segments.values().next().expect("length checked to be 1")),
            n => Err(format!("parameters span {} code segments, which offset-keyed comparison cannot separate", n)),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Normalize text for comparison by trimming and collapsing whitespace.
pub fn normalize_text(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Normalize an optional text attribute.
///
/// An attribute written as `SuffixText=""` and an absent one mean the same
/// thing, so both collapse to `None` — otherwise every parameter that spells the
/// default one way while the other program spells it the other way reads as a
/// difference.
pub fn normalize_optional_text(value: &Option<String>) -> Option<String> {
    value.as_deref().map(normalize_text).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_text() {
        assert_eq!(normalize_text("  hello   world  "), "hello world");
        assert_eq!(normalize_text("single"), "single");
        assert_eq!(normalize_text("  "), "");
    }

    #[test]
    fn test_parameter_key_display() {
        let key = ParameterKey::new(0x100, 3, 8);
        assert_eq!(format!("{}", key), "0x100:3:8");
    }
}
