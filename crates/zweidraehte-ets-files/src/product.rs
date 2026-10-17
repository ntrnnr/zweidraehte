//! The product layer: what a `.knxprod` / MTXML application program
//! says about one product.
//!
//! Sits between a device mask and a configured project device. It carries what
//! only the manufacturer knows: where the loadable segments live, what
//! the load procedure looks like, which group objects exist, and where
//! parameters are stored.
//!
//! Extracted directly from the shared schema types, including segment bytes,
//! table declarations, and load controls. Presentation-oriented summaries are
//! derived by consumers and do not form a second product model.
//!
//! [`ProductData`] is an immutable owned value. Tests that need synthetic
//! product facts can opt into the `test-fixtures` feature and use its owned
//! fixture setters without exposing mutation in production builds.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "archives")]
use crate::archive::KnxprodArchive;
use crate::runtime::Device;
use crate::runtime::model::{ExpandedModule, ModuleArgValue};
use crate::runtime::parser::{ParseError, parse_application_program};
use crate::schema::{
    ApplicationProgram, ApplicationProgramAttributes, BusInterface, Extension, Knx, LoadControl, LoadProcedure, Options,
};
use crate::schema::{KnxSchemaVersion, schema_version_from_namespace};
use zweidraehte_proto::com_object::{ComObjectFlagFields, ComObjectFlags, ComObjectType};
use zweidraehte_proto::device::MaskVersion;
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::knx::Priority;

mod identity;
mod selection;
#[cfg(feature = "archives")]
pub(crate) use selection::extract_product;
pub use selection::{ApplicationProgramRelation, SelectedProduct};
#[cfg(test)]
mod module_geometry_tests;

/// Product extraction failures retain their underlying parser or I/O cause.
#[derive(Debug, thiserror::Error)]
pub enum ProductError {
    #[error("product Master Data is invalid: {0}")]
    MasterData(#[from] crate::schema::master_data::MasterDataError),
    #[error("product already has a different Master Data document")]
    MasterDataAlreadyBound,
    #[error("cannot read product XML")]
    Io(#[from] std::io::Error),
    #[error("cannot parse product XML")]
    Parse(#[from] ParseError),
    #[error("the document defines no application program")]
    MissingApplicationProgram,
    #[error("the document defines {count} application programs; select one explicitly")]
    AmbiguousApplicationProgram { count: usize },
    #[error("the archive has no application program {0}")]
    UnknownApplicationProgram(String),
    #[error("catalogue product {product:?} has no exact Hardware2Program relation for application {application:?}")]
    MissingCatalogueProgramRelation { product: String, application: String },
    #[error("catalogue product {product:?} and application {application:?} match {count} Hardware2Program relations")]
    AmbiguousCatalogueProgramRelation { product: String, application: String, count: usize },
    #[error("application {application:?} is exposed by {count} catalogue products; select one explicitly")]
    AmbiguousCatalogueApplication { application: String, count: usize },
    #[error(
        "product schema provenance {namespace:?} ({declared_version:?}) conflicts with explicitly selected project schema {selected_version}"
    )]
    SchemaProvenanceConflict { namespace: Option<String>, declared_version: Option<u16>, selected_version: u16 },
    #[error("application program has unknown load procedure style {0:?}")]
    InvalidLoadProcedureStyle(String),
    #[error("communication object {number} has unrecognized size {size:?}")]
    InvalidObjectSize { number: u16, size: String },
    #[error("segment {segment_id} has invalid base64 in {field}")]
    InvalidSegmentBase64 {
        segment_id: String,
        field: &'static str,
        #[source]
        source: base64::DecodeError,
    },
    #[error("segment {segment_id} has {data_length} data bytes but {mask_length} mask bytes")]
    SegmentMaskLength { segment_id: String, data_length: usize, mask_length: usize },
    #[error("property parameter {parameter_id} declares neither ObjectIndex nor ObjectType")]
    MissingPropertyObject { parameter_id: String },
    #[error("property parameter {parameter_id} declares both ObjectIndex and ObjectType")]
    ConflictingPropertyObject { parameter_id: String },
    #[error("module {module_id} parameter {parameter_id} references unresolved BaseOffset argument {argument_id}")]
    UnresolvedModuleBaseOffset { module_id: String, parameter_id: String, argument_id: String },
    #[error("module {module_id} references unknown definition {definition_id}")]
    UnknownModuleDefinition { module_id: String, definition_id: String },
    #[error("module instance {0} occurs more than once")]
    DuplicateModuleInstance(String),
    #[error("module {module_id} parameter {parameter_id} resolves outside the segment offset range")]
    InvalidModuleParameterOffset { module_id: String, parameter_id: String },
    #[error("cannot parse manufacturer Hardware.xml")]
    HardwareXml(#[source] quick_xml::DeError),
    #[error("cannot parse manufacturer Catalog.xml")]
    CatalogueXml(#[source] quick_xml::DeError),
    #[error(transparent)]
    HardwareApplicationProgram(#[from] crate::schema::HardwareApplicationProgramError),
    // Keep both authoritative relations for diagnosis without making every
    // product/archive/client result carry two large bindings inline.
    #[error("secondary application {actual:?} is not the PEI Program {expected:?} the selected relation binds")]
    SecondaryApplicationMismatch { expected: Option<String>, actual: String },
    #[error("secondary application {application_program_id:?} is unsupported: {reason}")]
    UnsupportedSecondaryApplication { application_program_id: String, reason: String },
    #[error("application-program-2 binding {selected:?} conflicts with the existing binding {current:?}")]
    ApplicationProgram2BindingConflict {
        current: Box<ApplicationProgram2Binding>,
        selected: Box<ApplicationProgram2Binding>,
    },
    #[error(
        "application-program relation selects {relation_application_program_id:?}, not extracted product {product_application_program_id:?}"
    )]
    ApplicationProgramRelationMismatch {
        product_application_program_id: String,
        relation_application_program_id: String,
    },
}

pub type Result<T> = std::result::Result<T, ProductError>;

/// Identity encoded in an application task-segment record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplicationIdentity {
    pub application_id: [u8; 5],
    pub pei_type: u8,
}

/// Authoritative hardware-package declaration for a second application.
///
/// An application-program MTXML document does not own this fact. It is
/// declared by the product's `Hardware.xml` relation, so parsing a lone MTXML
/// deliberately produces [`Unbound`](Self::Unbound). Consumers must not turn
/// the fixed PEI Program object or product-side merge fragments into a fourth,
/// inferred state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationProgramRelationIdentity {
    /// Selected saleable product, when the caller selected one from a
    /// `.knxprod` catalogue rather than selecting only an application.
    pub catalog_product_id: Option<String>,
    /// Exact catalogue item which selected the product/relation, when one was
    /// available in the package.
    pub catalog_item_id: Option<String>,
    pub hardware_id: String,
    pub hardware2program_id: String,
    pub application_program_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ApplicationProgram2Binding {
    /// No matching `Hardware.xml` relation was available.
    #[default]
    Unbound,
    /// The selected hardware relation explicitly has no second application.
    Absent { relation: ApplicationProgramRelationIdentity },
    /// The relation declares a second application-program definition.
    Present { relation: ApplicationProgramRelationIdentity, application_program_id: String },
}

/// One manufacturer's complete, package-ready ETS content.
///
/// Both generated definitions and imported archives lower to this value. The
/// project builder therefore refers to stable ETS IDs, never to generator-local
/// handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManufacturerContent {
    pub manufacturer_id: String,
    pub application_programs: Vec<(String, String)>,
    pub hardware: String,
    pub catalogue: String,
    /// Auxiliary members relative to the manufacturer directory, including
    /// `Baggages.xml` when baggage is present.
    pub auxiliary_files: Vec<(String, Vec<u8>)>,
}

/// One saleable catalogue product and the application relation it selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogueProduct {
    pub catalogue_item_id: String,
    pub product_id: String,
    pub hardware_id: String,
    pub hardware2program_id: String,
    pub application_program_id: String,
    pub name: String,
    pub order_number: String,
    pub medium_types: String,
}

impl ManufacturerContent {
    pub fn new(
        manufacturer_id: impl Into<String>,
        application_programs: Vec<(String, String)>,
        hardware: String,
        catalogue: String,
    ) -> Self {
        Self {
            manufacturer_id: manufacturer_id.into(),
            application_programs,
            hardware,
            catalogue,
            auxiliary_files: Vec::new(),
        }
    }

    pub fn with_auxiliary_files(mut self, files: Vec<(String, Vec<u8>)>) -> Self {
        self.auxiliary_files = files;
        self
    }

    pub fn directory_name(&self) -> String {
        let id = self.manufacturer_id.strip_prefix("M-").unwrap_or(&self.manufacturer_id);
        format!("M-{id}")
    }

    /// Resolve catalogue items through Hardware2Program relations.
    pub fn catalogue_products(&self) -> Result<Vec<CatalogueProduct>> {
        let hardware: crate::schema::HardwareKnx =
            quick_xml::de::from_str(&self.hardware).map_err(ProductError::HardwareXml)?;
        let catalogue: crate::schema::CatalogKnx =
            quick_xml::de::from_str(&self.catalogue).map_err(ProductError::CatalogueXml)?;

        let mut products = BTreeMap::new();
        let mut relations = BTreeMap::new();
        for hardware in &hardware.manufacturer_data.manufacturer.hardware.hardware {
            for product in &hardware.products.products {
                products.insert(product.id.as_str(), (hardware.id.as_str(), product));
            }
            for relation in &hardware.hardware2programs.hardware2programs {
                relations.insert(relation.id.as_str(), (hardware.id.as_str(), relation));
            }
        }

        let mut items = Vec::new();
        collect_catalogue_items(&catalogue.manufacturer_data.manufacturer.catalog.catalog_sections, &mut items);
        Ok(items
            .into_iter()
            .filter_map(|item| {
                let (product_hardware, product) = products.get(item.product_ref_id.as_str())?;
                let (relation_hardware, relation) = relations.get(item.hardware2program_ref_id.as_str())?;
                let application_program = relation.application_program_refs.first()?;
                (product_hardware == relation_hardware).then(|| CatalogueProduct {
                    catalogue_item_id: item.id.clone(),
                    product_id: product.id.clone(),
                    hardware_id: (*product_hardware).to_owned(),
                    hardware2program_id: relation.id.clone(),
                    application_program_id: application_program.ref_id.clone(),
                    name: item.name.clone(),
                    order_number: product.order_number.clone(),
                    medium_types: relation.medium_types.clone(),
                })
            })
            .collect())
    }
}

fn collect_catalogue_items<'a>(
    sections: &'a [crate::schema::CatalogSection],
    output: &mut Vec<&'a crate::schema::CatalogItem>,
) {
    for section in sections {
        output.extend(&section.catalog_items);
        collect_catalogue_items(&section.subsections, output);
    }
}

/// One loadable memory segment of a product.
///
/// System 7 products place segments at absolute addresses; System B
/// declares sizes and lets the device allocate, so `address` is `None`
/// there until the device reports one back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The segment's MTXML id, e.g. `M-00FA_A-0306-02-0000_AS-4000`.
    /// Load-control records reference segments by this id.
    pub id: String,
    /// Absolute address (System 7), or `None` for relative segments.
    pub address: Option<u32>,
    /// Allocated size in bytes.
    pub size: u32,
    /// `"EEPROM"`, `"RAM"`, or absent.
    pub memory_type: Option<String>,
    /// Whether the XML explicitly classifies an absolute segment as user
    /// memory. `None` means the attribute was omitted and keeps that distinct
    /// from an explicit `false`.
    pub user_memory: Option<bool>,
    /// Load state machine index, for relative (System B) segments.
    pub load_state_machine: Option<u8>,
    /// The segment's default contents, decoded from the MTXML's
    /// base64. This is what ETS seeds the download image with before
    /// applying project data.
    pub data: Vec<u8>,
    /// Which bits of `data` belong to the product image. Each mask byte applies
    /// to the data byte at the same index: set bits come from `data`, while
    /// clear bits retain their existing device value. MTXML without a mask
    /// owns all supplied data bits.
    pub mask: Option<Vec<u8>>,
}

/// One group object the product defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComObjectDef {
    /// Object number — the ASAP the association table references.
    pub number: u16,
    /// Value field type, resolved from MTXML's `ObjectSize` spelling
    /// at extraction time so an unknown size fails there rather than
    /// silently becoming `Uint1` in a table.
    pub object_type: ComObjectType,
    /// Product DPT references exactly as declared by MTXML.
    ///
    /// The value is an `xs:IDREFS` list such as `DPT-1 DPST-1-1`.
    /// Property-based group-object tables need the numeric DPT identity in
    /// addition to the payload width, so discarding this annotation would
    /// make those tables impossible to compile faithfully.
    pub datapoint_type: Option<String>,
    /// The configuration flags, in the group object table's coding.
    pub flags: ComObjectFlags,
}

/// Where one parameter lives in device memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterLocation {
    pub id: String,
    /// Segment id the offset is relative to.
    pub code_segment: String,
    pub offset: u32,
    /// Bit position within the byte at `offset`, counted from the MSB —
    /// the convention ETS uses when packing sub-byte parameters.
    pub bit_offset: u8,
    /// Storage width in bits, from the parameter's type or its DPT float
    /// encoding. 0 means the type declares no usable width (or there is no
    /// `ParameterTypes` section); patching then falls back to a whole-byte
    /// copy sized by the value.
    pub size_bits: u16,
    /// ETS writes this parameter on every download even when its value
    /// equals the product default; a diff-based project must include it.
    pub legacy_patch_always: bool,
    /// Whether the declared base value initializes this location before
    /// active references and project edits are applied. Ordinary parameters
    /// always do; a union contributes only its `DefaultUnionParameter`.
    pub seeds_default: bool,
    /// Whether the product's `ParameterByteOrder` reorders the value's
    /// bytes: true for numeric types and for an unknown type.
    pub byte_ordered: bool,
}

/// Interface-object identity used by a property-backed parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PropertyObject {
    Index(u8),
    /// Absence and explicit zero select different resource declarations.
    Type {
        object_type: InterfaceObjectType,
        occurrence: Option<u16>,
    },
}

/// Where one parameter contributes bits to an interface-object property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyParameterLocation {
    pub id: String,
    pub object: PropertyObject,
    pub property_id: u16,
    pub offset: u32,
    pub bit_offset: u8,
    pub size_bits: u16,
    pub legacy_patch_always: bool,
    /// Whether the product's `ParameterByteOrder` reorders the value's
    /// bytes: true for numeric types and for an unknown type.
    pub byte_ordered: bool,
}

/// How a product's load procedures compose with the mask.
///
/// From MTXML's `ApplicationProgram/@LoadProcedureStyle`; decides
/// whether the product supplies a whole procedure or fragments the
/// mask template merges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadProcedureStyle {
    /// BCU-era application: use the mask's default procedure.
    #[default]
    Default,
    /// System 7: the product carries one complete procedure that
    /// replaces the mask's Load template.
    Product,
    /// System B: the product carries `MergeId`-tagged fragments the
    /// mask template splices in.
    Merged,
}

impl LoadProcedureStyle {
    fn from_mtxml(value: &str) -> Result<Self> {
        match value {
            "DefaultProcedure" => Ok(Self::Default),
            "ProductProcedure" => Ok(Self::Product),
            "MergedProcedure" => Ok(Self::Merged),
            _ => Err(ProductError::InvalidLoadProcedureStyle(value.to_owned())),
        }
    }
}

// ============================================================================
// Programming Metadata
// ============================================================================

/// The XML document that supplied an application program.
///
/// Converted legacy product-store documents legitimately omit their namespace.
/// Keeping the raw namespace and parsed version separate lets profile selection
/// report that uncertainty instead of silently choosing the newest master data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProductSchemaProvenance {
    namespace: Option<String>,
    schema_version: Option<u16>,
    schema_version_source: Option<ProductSchemaVersionSource>,
    created_by: Option<String>,
    tool_version: Option<String>,
}

/// Authority which established a product's project-schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProductSchemaVersionSource {
    /// The product XML root carried a versioned KNX namespace.
    DocumentNamespace,
    /// A caller explicitly bound a namespace-free converted product.
    ExplicitBinding,
}

impl ProductSchemaProvenance {
    fn from_knx(knx: &Knx) -> Self {
        let namespace = non_empty(&knx.xmlns).map(str::to_owned);
        let schema_version = namespace.as_deref().and_then(schema_version_from_namespace);

        Self {
            namespace,
            schema_version,
            schema_version_source: schema_version.map(|_| ProductSchemaVersionSource::DocumentNamespace),
            created_by: non_empty(&knx.created_by).map(str::to_owned),
            tool_version: non_empty(&knx.tool_version).map(str::to_owned),
        }
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    pub fn schema_version(&self) -> Option<u16> {
        self.schema_version
    }

    pub fn schema_version_source(&self) -> Option<ProductSchemaVersionSource> {
        self.schema_version_source
    }

    pub fn created_by(&self) -> Option<&str> {
        self.created_by.as_deref()
    }

    pub fn tool_version(&self) -> Option<&str> {
        self.tool_version.as_deref()
    }
}

fn non_empty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

/// Where an effective product option came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductValueSource {
    /// The manufacturer wrote the attribute in the product XML.
    Explicit,
    /// The attribute was absent and the XSD default was applied deliberately.
    SchemaDefault {
        /// The version parsed from the document namespace, if it had one.
        schema_version: Option<u16>,
    },
}

/// An effective product value together with its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveProductValue<T> {
    pub value: T,
    pub source: ProductValueSource,
}

impl<T> EffectiveProductValue<T> {
    pub fn is_explicit(&self) -> bool {
        matches!(self.source, ProductValueSource::Explicit)
    }
}

/// Byte order used while applying parameter values to the program image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterByteOrder {
    BigEndian,
    LittleEndian,
    Unknown(String),
}

impl From<&str> for ParameterByteOrder {
    fn from(value: &str) -> Self {
        match value {
            "BigEndian" => Self::BigEndian,
            "LittleEndian" => Self::LittleEndian,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// Source used to select a text parameter's code page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextParameterEncodingSelector {
    WindowsAnsiCodePage,
    ProjectCodePage,
    TextParameterEncodingCodePage,
    Unknown(String),
}

impl From<&str> for TextParameterEncodingSelector {
    fn from(value: &str) -> Self {
        match value {
            "UseWindowsAnsiCodePage" => Self::WindowsAnsiCodePage,
            "UseProjectCodePage" => Self::ProjectCodePage,
            "UseTextParameterEncodingCodePage" => Self::TextParameterEncodingCodePage,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// How invisible parameters participate in a download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadBehavior {
    None,
    Background,
    DefaultValue,
    Unknown(String),
}

impl From<&str> for DownloadBehavior {
    fn from(value: &str) -> Self {
        match value {
            "None" => Self::None,
            "Background" => Self::Background,
            "DefaultValue" => Self::DefaultValue,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// What commissioning should do with an application marked as not loadable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotLoadableBehavior {
    SkipSilently,
    DisplayError,
    Unknown(String),
}

impl From<&str> for NotLoadableBehavior {
    fn from(value: &str) -> Self {
        match value {
            "SkipSilently" => Self::SkipSilently,
            "DisplayError" => Self::DisplayError,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// Operation offered for customer-adjustable parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomerAdjustableParameterBehavior {
    Write,
    Sync,
    Unknown(String),
}

impl From<&str> for CustomerAdjustableParameterBehavior {
    fn from(value: &str) -> Self {
        match value {
            "Write" => Self::Write,
            "Sync" => Self::Sync,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// Whether IP configuration is supplied by the tool or product-specific code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpConfigurationMode {
    Tool,
    Custom,
    Unknown(String),
}

impl From<&str> for IpConfigurationMode {
    fn from(value: &str) -> Self {
        match value {
            "Tool" => Self::Tool,
            "Custom" => Self::Custom,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// Product attributes that change image compilation or commissioning policy.
///
/// The raw schema records are retained so callers can audit whether an
/// attribute existed. Convenience getters apply XSD defaults explicitly and
/// return [`EffectiveProductValue`] rather than erasing that distinction.
#[derive(Debug, Clone, Default)]
pub struct ProductProgrammingOptions {
    schema_version: Option<u16>,
    application_attributes: ApplicationProgramAttributes,
    program_type: String,
    min_ets_version: Option<String>,
    replaces_versions: Option<String>,
    application_hash: Option<String>,
    dynamic_table_management: bool,
    linkable: bool,
    ip_config: Option<String>,
    additional_addresses_count: Option<u32>,
    is_secure_enabled: Option<bool>,
    max_user_entries: Option<u16>,
    max_tunneling_user_entries: Option<u16>,
    max_security_individual_address_entries: Option<u16>,
    max_security_group_key_table_entries: Option<u16>,
    max_security_p2p_key_table_entries: Option<u16>,
    non_reg_relevant_data_version: Option<u32>,
    options: Option<Options>,
    extension: Option<Extension>,
}

impl ProductProgrammingOptions {
    fn from_program(program: &ApplicationProgram, provenance: &ProductSchemaProvenance) -> Self {
        Self {
            schema_version: provenance.schema_version(),
            application_attributes: program.attributes.clone(),
            program_type: program.program_type.clone(),
            min_ets_version: program.min_ets_version.clone(),
            replaces_versions: program.replaces_versions.clone(),
            application_hash: program.hash.clone(),
            dynamic_table_management: program.dynamic_table_management,
            linkable: program.linkable,
            ip_config: program.ip_config.clone(),
            additional_addresses_count: program.additional_addresses_count,
            is_secure_enabled: program.is_secure_enabled,
            max_user_entries: program.max_user_entries,
            max_tunneling_user_entries: program.max_tunneling_user_entries,
            max_security_individual_address_entries: program.max_security_individual_address_entries,
            max_security_group_key_table_entries: program.max_security_group_key_table_entries,
            max_security_p2p_key_table_entries: program.max_security_p2p_key_table_entries,
            non_reg_relevant_data_version: program.non_reg_relevant_data_version,
            options: program.static_section.options.clone(),
            extension: program.static_section.extension.clone(),
        }
    }

    /// The exact optional application attributes, before XSD defaults.
    pub fn application_attributes(&self) -> &ApplicationProgramAttributes {
        &self.application_attributes
    }

    /// The exact `<Static><Options>` element, or `None` when it was absent.
    pub fn raw_options(&self) -> Option<&Options> {
        self.options.as_ref()
    }

    /// The exact `<Static><Extension>` element, including plugin declarations.
    pub fn extension(&self) -> Option<&Extension> {
        self.extension.as_ref()
    }

    pub fn program_type(&self) -> &str {
        &self.program_type
    }

    pub fn min_ets_version(&self) -> Option<&str> {
        self.min_ets_version.as_deref()
    }

    pub fn replaces_versions(&self) -> Option<&str> {
        self.replaces_versions.as_deref()
    }

    pub fn application_hash(&self) -> Option<&str> {
        self.application_hash.as_deref()
    }

    pub fn dynamic_table_management(&self) -> bool {
        self.dynamic_table_management
    }

    pub fn linkable(&self) -> bool {
        self.linkable
    }

    pub fn original_manufacturer(&self) -> Option<&str> {
        self.application_attributes.original_manufacturer.as_deref()
    }

    pub fn tunneling_address_indices(&self) -> Option<&str> {
        self.application_attributes.tunneling_address_indices.as_deref()
    }

    fn effective<T>(&self, explicit: Option<T>, default: T) -> EffectiveProductValue<T> {
        match explicit {
            Some(value) => EffectiveProductValue { value, source: ProductValueSource::Explicit },
            None => EffectiveProductValue {
                value: default,
                source: ProductValueSource::SchemaDefault { schema_version: self.schema_version },
            },
        }
    }

    fn option_bool(&self, get: impl FnOnce(&Options) -> Option<bool>) -> EffectiveProductValue<bool> {
        self.effective(self.options.as_ref().and_then(get), false)
    }

    pub fn pre_ets4_style(&self) -> EffectiveProductValue<bool> {
        self.effective(self.application_attributes.pre_ets4_style, false)
    }

    pub fn converted_from_pre_ets4_data(&self) -> EffectiveProductValue<bool> {
        self.effective(self.application_attributes.converted_from_pre_ets4_data, false)
    }

    pub fn created_from_legacy_schema_version(&self) -> EffectiveProductValue<bool> {
        self.effective(self.application_attributes.created_from_legacy_schema_version, false)
    }

    pub fn ip_configuration(&self) -> EffectiveProductValue<IpConfigurationMode> {
        self.effective(self.ip_config.as_deref().map(IpConfigurationMode::from), IpConfigurationMode::Tool)
    }

    pub fn additional_addresses_count(&self) -> EffectiveProductValue<u32> {
        self.effective(self.additional_addresses_count, 0)
    }

    pub fn is_secure_enabled(&self) -> EffectiveProductValue<bool> {
        self.effective(self.is_secure_enabled, false)
    }

    pub fn max_user_entries(&self) -> EffectiveProductValue<u16> {
        self.effective(self.max_user_entries, 0)
    }

    pub fn max_tunneling_user_entries(&self) -> EffectiveProductValue<u16> {
        self.effective(self.max_tunneling_user_entries, 0)
    }

    pub fn max_security_individual_address_entries(&self) -> EffectiveProductValue<u16> {
        self.effective(self.max_security_individual_address_entries, 0)
    }

    pub fn max_security_group_key_table_entries(&self) -> EffectiveProductValue<u16> {
        self.effective(self.max_security_group_key_table_entries, 0)
    }

    pub fn max_security_p2p_key_table_entries(&self) -> EffectiveProductValue<u16> {
        self.effective(self.max_security_p2p_key_table_entries, 0)
    }

    pub fn max_security_proxy_group_key_table_entries(&self) -> EffectiveProductValue<u16> {
        self.effective(self.application_attributes.max_security_proxy_group_key_table_entries, 0)
    }

    pub fn max_security_proxy_individual_address_table_entries(&self) -> EffectiveProductValue<u16> {
        self.effective(self.application_attributes.max_security_proxy_individual_address_table_entries, 0)
    }

    pub fn non_reg_relevant_data_version(&self) -> EffectiveProductValue<u32> {
        self.effective(self.non_reg_relevant_data_version, 0)
    }

    pub fn broken(&self) -> EffectiveProductValue<bool> {
        self.effective(self.application_attributes.broken, false)
    }

    pub fn download_info_incomplete(&self) -> EffectiveProductValue<bool> {
        self.effective(self.application_attributes.download_info_incomplete, false)
    }

    pub fn prefer_partial_download_if_application_loaded(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.prefer_partial_download_if_application_loaded)
    }

    pub fn easy_ctrl_mode_style_empty_group_com_tables(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.easy_ctrl_mode_style_empty_group_com_tables)
    }

    pub fn set_object_table_length_always_to_one(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.set_object_table_length_always_to_one)
    }

    pub fn text_parameter_encoding(&self) -> Option<&str> {
        self.options.as_ref()?.text_parameter_encoding.as_deref()
    }

    pub fn text_parameter_encoding_selector(&self) -> EffectiveProductValue<TextParameterEncodingSelector> {
        let explicit = self
            .options
            .as_ref()
            .and_then(|options| options.text_parameter_encoding_selector.as_deref())
            .map(TextParameterEncodingSelector::from);

        self.effective(explicit, TextParameterEncodingSelector::TextParameterEncodingCodePage)
    }

    pub fn text_parameter_zero_terminate(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.text_parameter_zero_terminate)
    }

    pub fn parameter_byte_order(&self) -> EffectiveProductValue<ParameterByteOrder> {
        let explicit = self
            .options
            .as_ref()
            .and_then(|options| options.parameter_byte_order.as_deref())
            .map(ParameterByteOrder::from);

        self.effective(explicit, ParameterByteOrder::BigEndian)
    }

    pub fn partial_download_only_visible_parameters(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.partial_download_only_visible_parameters)
    }

    pub fn legacy_no_partial_download(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.legacy_no_partial_download)
    }

    pub fn legacy_no_memory_verify_mode(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.legacy_no_memory_verify_mode)
    }

    pub fn legacy_no_optimistic_write(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.legacy_no_optimistic_write)
    }

    pub fn legacy_do_not_report_property_write_errors(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.legacy_do_not_report_property_write_errors)
    }

    pub fn legacy_no_background_download(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.legacy_no_background_download)
    }

    pub fn legacy_do_not_check_manufacturer_id(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.legacy_do_not_check_manufacturer_id)
    }

    pub fn legacy_always_reload_app_if_co_visibility_changed(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.legacy_always_reload_app_if_co_visibility_changed)
    }

    pub fn legacy_never_reload_app_if_co_visibility_changed(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.legacy_never_reload_app_if_co_visibility_changed)
    }

    pub fn legacy_do_not_support_undo_delete(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.legacy_do_not_support_undo_delete)
    }

    pub fn legacy_allow_partial_download_if_ap2_mismatch(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.legacy_allow_partial_download_if_ap2_mismatch)
    }

    pub fn legacy_keep_object_table_gaps(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.legacy_keep_object_table_gaps)
    }

    pub fn legacy_proxy_communication_objects(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.legacy_proxy_communication_objects)
    }

    pub fn device_info_ignore_run_state(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.device_info_ignore_run_state)
    }

    pub fn device_info_ignore_loaded_state(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.device_info_ignore_loaded_state)
    }

    pub fn device_compare_allow_compatible_manufacturer_id(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.device_compare_allow_compatible_manufacturer_id)
    }

    pub fn line_coupler_0912_new_programming_style(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.line_coupler_0912_new_programming_style)
    }

    pub fn max_routing_apdu_length(&self) -> Option<u32> {
        self.options.as_ref()?.max_routing_apdu_length
    }

    pub fn comparable(&self) -> Option<bool> {
        self.options.as_ref()?.comparable
    }

    pub fn reconstructable(&self) -> Option<bool> {
        self.options.as_ref()?.reconstructable
    }

    pub fn download_invisible_parameters(&self) -> EffectiveProductValue<DownloadBehavior> {
        let explicit = self
            .options
            .as_ref()
            .and_then(|options| options.download_invisible_parameters.as_deref())
            .map(DownloadBehavior::from);

        self.effective(explicit, DownloadBehavior::DefaultValue)
    }

    pub fn supports_extended_memory_services(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.supports_extended_memory_services)
    }

    pub fn supports_extended_property_services(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.supports_extended_property_services)
    }

    pub fn supports_ip_system_broadcast(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.supports_ip_system_broadcast)
    }

    pub fn not_loadable(&self) -> Option<NotLoadableBehavior> {
        self.options.as_ref()?.not_loadable.as_deref().map(NotLoadableBehavior::from)
    }

    pub fn not_loadable_message_ref(&self) -> Option<&str> {
        self.options.as_ref()?.not_loadable_message_ref.as_deref()
    }

    pub fn customer_adjustable_parameters(&self) -> Option<CustomerAdjustableParameterBehavior> {
        self.options.as_ref()?.customer_adjustable_parameters.as_deref().map(CustomerAdjustableParameterBehavior::from)
    }

    pub fn master_reset_on_crc_mismatch(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.master_reset_on_crc_mismatch)
    }

    pub fn prompt_before_full_download(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.prompt_before_full_download)
    }

    pub fn legacy_patch_manufacturer_id_in_task_segment(&self) -> EffectiveProductValue<bool> {
        self.option_bool(|options| options.legacy_patch_manufacturer_id_in_task_segment)
    }

    pub fn requires_external_software(&self) -> EffectiveProductValue<bool> {
        self.effective(self.extension.as_ref().and_then(|extension| extension.requires_external_software), false)
    }
}

/// Everything the product file says that a download needs.
///
/// Parsed product facts cannot be edited after extraction. Project-specific
/// choices belong in a lowered device configuration instead.
///
/// ```compile_fail
/// use zweidraehte_ets_files::product::ProductData;
///
/// let mut product = ProductData::default();
/// product.supports_data_secure = true;
/// ```
#[derive(Debug, Clone, Default)]
pub struct ProductData {
    /// Application program id, e.g. `M-00FA_A-0306-02-0000`.
    id: String,
    /// Exact master-data reference from `ApplicationProgram/@MaskVersion`.
    /// Numeric DD0 alone cannot distinguish descriptor-qualified profiles.
    mask_version_id: String,
    /// The mask this product runs on, from `@MaskVersion` (`MV-0705`).
    mask_version: Option<MaskVersion>,
    /// Source document identity used to select matching versioned master data.
    schema_provenance: ProductSchemaProvenance,
    /// The exact package document, or one explicitly associated with loose XML.
    master_data: Option<std::sync::Arc<crate::MasterData>>,
    /// Product-level switches that influence compilation and commissioning.
    programming_options: ProductProgrammingOptions,
    /// AP2 belongs to the hardware-to-program relation, not this application
    /// document. Project-aware loading binds it after extracting the program.
    application_program_2: ApplicationProgram2Binding,
    /// Content of the relation's secondary PEI Program once a package loader
    /// has extracted it. Compilation of a present AP2 needs this content.
    secondary_application: Option<std::sync::Arc<ProductData>>,
    /// Whether the product supplies a whole procedure (System 7) or
    /// fragments the mask template merges (System B).
    load_procedure_style: LoadProcedureStyle,
    /// The application identity task-segment records announce, from
    /// the program element's own attributes (the load-procedure XML
    /// does not repeat them).
    application_identity: ApplicationIdentity,
    /// Whether the application declares KNX Data Secure capability.
    ///
    /// The project separately decides whether to enable that capability for
    /// a device instance. Keeping the two values separate prevents a capable
    /// product from silently turning a plain installation into a secure one.
    supports_data_secure: bool,
    /// Product-declared Security IO capacities. The compile step checks the
    /// project configuration against these before emitting table writes.
    max_security_individual_address_entries: Option<u16>,
    max_security_group_key_table_entries: Option<u16>,
    max_security_p2p_key_table_entries: Option<u16>,
    /// Exact ETS bus-interface declarations. These map the product's
    /// additional-address slots to tunneling, USB, or routing endpoints.
    bus_interfaces: Vec<BusInterface>,
    /// Untranslated texts of the application's `Static/Messages`, keyed by
    /// message id. Load controls name them by `MessageRef`.
    messages: BTreeMap<String, String>,
    segments: Vec<Segment>,
    /// Relative segment positions inside the allocation owned by their load
    /// state machine, keyed by segment id. Kept beside [`Segment`] to avoid
    /// breaking callers that construct that public record directly.
    relative_segment_offsets: BTreeMap<String, u32>,
    /// The product's load procedures: one complete `ProductProcedure`
    /// for System 7, or `MergeId`-tagged fragments for System B.
    load_procedures: Vec<LoadProcedure>,
    /// Communication objects declared by the application's root static
    /// section. Concrete objects from allocator-backed module instances are
    /// configuration-dependent and arrive in the lowered configuration.
    com_objects: Vec<ComObjectDef>,
    /// Every root object number the program declares, visible or not.
    /// A lowered project configuration carries the effective visible subset,
    /// but the BCU-era group object table keeps a
    /// row per declared object regardless —
    /// dynamic table management sizes its association slots off this
    /// roster (ETS emits TSAP FEh placeholders for objects the
    /// configuration hides: BCU1.log writes three slots with one
    /// object visible).
    com_object_numbers: Vec<u16>,
    parameters: Vec<ParameterLocation>,
    // Keep only static geometry facts. A compiler receiving an evaluated
    // roster must not run dynamic pages again to recover instance locations.
    module_definitions: BTreeMap<String, ModuleGeometryDefinition>,
    parameter_widths: BTreeMap<String, u16>,
    /// Parameter types whose bytes the product byte order leaves alone,
    /// for locations resolved later inside module instances.
    byte_unordered_types: BTreeSet<String>,
    /// Authored parameter ids whose raw payload needs storage-specific framing.
    /// Keep capacities in bytes: `MaxSize` may exceed the fixed-width bit field.
    raw_data_parameter_max_sizes: BTreeMap<String, u32>,
    resolved_module_parameter_ids: BTreeSet<String>,
    /// Parameters written through `LdCtrlWriteProp` rather than into a
    /// memory segment. Their values form a property-local data block.
    property_parameters: Vec<PropertyParameterLocation>,
    /// Segment id holding the group address table, if the product
    /// says (`Static/AddressTable/@CodeSegment`).
    address_table_segment: Option<String>,
    /// Offset of the table inside its segment
    /// (`Static/AddressTable/@Offset`). Zero on the families with
    /// dedicated table segments (System 7, BCU2); non-zero on BCU1,
    /// whose tables live inside the one EEPROM segment (the MDT
    /// MV-0012 reference points all three tables into it).
    address_table_offset: u32,
    address_table_max_entries: Option<u16>,
    association_table_segment: Option<String>,
    association_table_offset: u32,
    association_table_max_entries: Option<u16>,
    /// Segment id holding the group object table.
    com_object_table_segment: Option<String>,
    com_object_table_offset: u32,
    /// The program's fixups (BCU-era native code): mask-ROM routine
    /// addresses to patch into the code segments, resolved against
    /// the mask the download is compiled for.
    fixups: Vec<FixupDef>,
    /// Whether ETS lays the tables out dynamically for this program
    /// (`@DynamicTableManagement`, true on converted pre-ETS4 BCU-era
    /// programs). ETS's CommunicationTableFormatter then packs the
    /// association table immediately after the actual-size address
    /// table, repoints AssocTabPtr, and pads the association table
    /// with a TSAP FEh placeholder per unlinked group object — instead
    /// of honoring the vendor's static table offsets (bench traces
    /// BCU1.log and BCU2_partial.log at the repo root).
    dynamic_table_management: bool,
}

/// One resolved allocator or literal argument, keyed by its declared name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializedModuleArgument {
    Numeric(i64),
    Text(String),
}

/// Post-evaluation module instance. Its arguments already include allocation
/// and base-argument arithmetic; geometry resolution must not repeat either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedModule {
    pub instance_id: String,
    pub definition_id: String,
    pub arguments: BTreeMap<String, MaterializedModuleArgument>,
}

impl From<&ExpandedModule> for MaterializedModule {
    fn from(module: &ExpandedModule) -> Self {
        Self {
            instance_id: module.instance_id.clone(),
            definition_id: module.module_def_id.clone(),
            arguments: module
                .args
                .iter()
                .map(|(name, value)| {
                    let value = match value {
                        ModuleArgValue::Numeric(value) => MaterializedModuleArgument::Numeric(*value),
                        ModuleArgValue::Text(value) => MaterializedModuleArgument::Text(value.clone()),
                    };
                    (name.clone(), value)
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
struct ModuleGeometryDefinition {
    parameters: Vec<crate::schema::ParameterItem>,
    argument_names: BTreeMap<String, String>,
}

/// One fixup, extraction-side: which routine, which segment, where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixupDef {
    /// The `_ME-…` id suffix naming the routine
    /// (`Fixup/@FunctionRef` minus its product-mask prefix).
    pub function: String,
    /// The code segment the offsets index into.
    pub code_segment: String,
    pub offsets: Vec<u32>,
}

impl ProductData {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn mask_version(&self) -> Option<MaskVersion> {
        self.mask_version
    }

    /// Exact mask-profile ID, including descriptor suffixes such as those on
    /// the two real `MV-0300` variants.
    pub fn mask_version_id(&self) -> &str {
        &self.mask_version_id
    }

    /// Effective application profile used for programming metadata.
    ///
    /// Plain `MV-0300` applications select the executable System 300 profile.
    /// This is an application-data alias, not a device observation: the
    /// authored identifier remains available through [`Self::mask_version_id`],
    /// and physical discovery still needs its own management descriptor.
    pub fn programming_profile_id(&self) -> &str {
        match self.mask_version_id.as_str() {
            "MV-0300" => "MV-0300-01000001000000000000",
            authored => authored,
        }
    }

    pub fn schema_provenance(&self) -> &ProductSchemaProvenance {
        &self.schema_provenance
    }

    pub fn master_data(&self) -> Option<&std::sync::Arc<crate::MasterData>> {
        self.master_data.as_ref()
    }

    /// Associate a document once. Rebinding the same content is harmless;
    /// replacing package-owned Master Data is an error.
    pub fn bind_master_data(mut self, document: std::sync::Arc<crate::MasterData>) -> Result<Self> {
        if let Some(current) = &self.master_data {
            if current.source_xml() != document.source_xml() {
                return Err(ProductError::MasterDataAlreadyBound);
            }
        } else {
            self.master_data = Some(document.clone());
        }

        // A secondary PEI Program compiles against the same exact catalogue.
        if let Some(secondary) = self.secondary_application.take() {
            let secondary = std::sync::Arc::unwrap_or_clone(secondary).bind_master_data(document)?;
            self.secondary_application = Some(std::sync::Arc::new(secondary));
        }

        Ok(self)
    }

    /// Bind a namespace-free converted product to an explicitly selected KNX
    /// project schema.
    ///
    /// Normal MTXML and archive inputs already carry their schema in the root
    /// namespace. For those products this method is an idempotent check: a
    /// matching selection preserves the document provenance byte-for-byte and
    /// a different selection is rejected. For a product with no namespace,
    /// the explicit binding is recorded separately; the raw namespace remains
    /// absent so downstream diagnostics do not misrepresent operator input as
    /// XML provenance.
    ///
    /// This is an explicit trust boundary, not schema inference. In
    /// particular, `CreatedBy`, `ToolVersion`, and the mask version do not
    /// identify which project schema supplied the product.
    pub fn bind_schema_version(mut self, version: KnxSchemaVersion) -> Result<Self> {
        let selected_version = version.as_u16();

        match self.schema_provenance.schema_version {
            Some(declared_version) if declared_version != selected_version => {
                return Err(ProductError::SchemaProvenanceConflict {
                    namespace: self.schema_provenance.namespace.clone(),
                    declared_version: Some(declared_version),
                    selected_version,
                });
            }
            Some(_) => {
                // The parsed product and its effective XSD defaults already
                // carry the same version. Preserve the original namespace,
                // including harmless spelling details such as a trailing `/`.
                return Ok(self);
            }
            None if self.schema_provenance.namespace.is_some() => {
                return Err(ProductError::SchemaProvenanceConflict {
                    namespace: self.schema_provenance.namespace.clone(),
                    declared_version: None,
                    selected_version,
                });
            }
            None => {}
        }

        self.schema_provenance.schema_version = Some(selected_version);
        self.schema_provenance.schema_version_source = Some(ProductSchemaVersionSource::ExplicitBinding);
        self.programming_options.schema_version = Some(selected_version);

        Ok(self)
    }

    pub fn programming_options(&self) -> &ProductProgrammingOptions {
        &self.programming_options
    }

    /// Return the package-level AP2 declaration bound to this product.
    pub fn application_program_2(&self) -> &ApplicationProgram2Binding {
        &self.application_program_2
    }

    /// Bind the selected `Hardware.xml` relation to an extracted application.
    ///
    /// This consumes the value because relation metadata is immutable product
    /// provenance once selected. Repeating the same binding is idempotent;
    /// replacing one authoritative relation with a contradictory one fails.
    pub fn bind_application_program_2(mut self, selected: ApplicationProgram2Binding) -> Result<Self> {
        let relation = match &selected {
            ApplicationProgram2Binding::Unbound => None,
            ApplicationProgram2Binding::Absent { relation } | ApplicationProgram2Binding::Present { relation, .. } => {
                Some(relation)
            }
        };
        if let Some(relation) = relation
            && relation.application_program_id != self.id
        {
            return Err(ProductError::ApplicationProgramRelationMismatch {
                product_application_program_id: self.id.clone(),
                relation_application_program_id: relation.application_program_id.clone(),
            });
        }

        match &self.application_program_2 {
            ApplicationProgram2Binding::Unbound => self.application_program_2 = selected,
            current if current == &selected => {}
            _ => {
                return Err(ProductError::ApplicationProgram2BindingConflict {
                    current: Box::new(self.application_program_2),
                    selected: Box::new(selected),
                });
            }
        }

        Ok(self)
    }

    /// The bound secondary PEI Program, when its relation declares one and a
    /// package loader extracted it.
    pub fn secondary_application(&self) -> Option<&ProductData> {
        self.secondary_application.as_deref()
    }

    /// Bind the content of the relation's secondary PEI Program.
    ///
    /// The relation must already name this application as AP2, and both
    /// programs must target the same mask. A PEI Program has no parameters,
    /// communication objects or secondary application of its own; content
    /// that would need them is rejected rather than silently ignored. The
    /// primary's Master Data, if bound, is shared.
    pub fn bind_secondary_application(mut self, mut secondary: ProductData) -> Result<Self> {
        let expected = match &self.application_program_2 {
            ApplicationProgram2Binding::Present { application_program_id, .. } => Some(application_program_id),
            _ => None,
        };
        if expected != Some(&secondary.id) {
            return Err(ProductError::SecondaryApplicationMismatch {
                expected: expected.cloned(),
                actual: secondary.id.clone(),
            });
        }
        let unsupported = |reason: &str| ProductError::UnsupportedSecondaryApplication {
            application_program_id: secondary.id.clone(),
            reason: reason.to_owned(),
        };
        if secondary.programming_profile_id() != self.programming_profile_id() {
            return Err(unsupported("it targets another mask version"));
        }
        if !secondary.parameters.is_empty()
            || !secondary.property_parameters.is_empty()
            || !secondary.com_objects.is_empty()
        {
            return Err(unsupported("it declares parameters or communication objects"));
        }
        if let Some(document) = &self.master_data {
            secondary = secondary.bind_master_data(document.clone())?;
        }
        if let Some(current) = &self.secondary_application
            && current.id != secondary.id
        {
            return Err(ProductError::SecondaryApplicationMismatch {
                expected: Some(current.id.clone()),
                actual: secondary.id,
            });
        }
        self.secondary_application = Some(std::sync::Arc::new(secondary));
        Ok(self)
    }

    pub fn load_procedure_style(&self) -> LoadProcedureStyle {
        self.load_procedure_style
    }

    pub fn application_identity(&self) -> ApplicationIdentity {
        self.application_identity
    }

    pub fn supports_data_secure(&self) -> bool {
        self.supports_data_secure
    }

    pub fn max_security_individual_address_entries(&self) -> Option<u16> {
        self.max_security_individual_address_entries
    }

    pub fn max_security_group_key_table_entries(&self) -> Option<u16> {
        self.max_security_group_key_table_entries
    }

    pub fn max_security_p2p_key_table_entries(&self) -> Option<u16> {
        self.max_security_p2p_key_table_entries
    }

    /// Exact `<Static><BusInterfaces>` entries in source order.
    pub fn bus_interfaces(&self) -> &[BusInterface] {
        &self.bus_interfaces
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Position of a relative segment inside its load machine's allocation.
    ///
    /// Returns `None` for absolute segments and unknown ids.
    pub fn relative_segment_offset(&self, id: &str) -> Option<u32> {
        self.relative_segment_offsets.get(id).copied()
    }

    /// Untranslated text of the application message `id`.
    pub fn message_text(&self, id: &str) -> Option<&str> {
        self.messages.get(id).map(String::as_str)
    }

    pub fn load_procedures(&self) -> &[LoadProcedure] {
        &self.load_procedures
    }

    pub fn com_objects(&self) -> &[ComObjectDef] {
        &self.com_objects
    }

    pub fn com_object_numbers(&self) -> &[u16] {
        &self.com_object_numbers
    }

    pub fn parameters(&self) -> &[ParameterLocation] {
        &self.parameters
    }

    pub fn property_parameters(&self) -> &[PropertyParameterLocation] {
        &self.property_parameters
    }

    /// Return a stored raw-data parameter's maximum payload length in bytes.
    ///
    /// Root ids are exact. Module ids use the instantiated geometry retained
    /// by [`Self::resolve_module_geometry`]; an arbitrary instance prefix or an
    /// uninstantiated module definition does not identify a stored parameter.
    /// The capacity excludes the four-byte length prefix used in memory.
    pub fn raw_data_parameter_max_size(&self, id: &str) -> Option<u32> {
        let authored_id = if self.resolved_module_parameter_ids.contains(id) {
            id.rsplit_once("::")?.1
        } else if self.parameters.iter().any(|parameter| parameter.id == id)
            || self.property_parameters.iter().any(|parameter| parameter.id == id)
        {
            id
        } else {
            return None;
        };
        self.raw_data_parameter_max_sizes.get(authored_id).copied()
    }

    pub fn address_table_segment(&self) -> Option<&str> {
        self.address_table_segment.as_deref()
    }

    pub fn address_table_offset(&self) -> u32 {
        self.address_table_offset
    }

    pub fn address_table_max_entries(&self) -> Option<u16> {
        self.address_table_max_entries
    }

    pub fn association_table_segment(&self) -> Option<&str> {
        self.association_table_segment.as_deref()
    }

    pub fn association_table_offset(&self) -> u32 {
        self.association_table_offset
    }

    pub fn association_table_max_entries(&self) -> Option<u16> {
        self.association_table_max_entries
    }

    pub fn com_object_table_segment(&self) -> Option<&str> {
        self.com_object_table_segment.as_deref()
    }

    pub fn com_object_table_offset(&self) -> u32 {
        self.com_object_table_offset
    }

    pub fn fixups(&self) -> &[FixupDef] {
        &self.fixups
    }

    pub fn dynamic_table_management(&self) -> bool {
        self.dynamic_table_management
    }

    /// Read a loose MTXML application program file.
    pub fn from_mtxml_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let xml = std::fs::read_to_string(path)?;
        Self::from_mtxml_str(&xml)
    }

    /// Read a loose MTXML application program from a string.
    pub fn from_mtxml_str(xml: &str) -> Result<Self> {
        let knx = parse_application_program(xml)?;
        Self::from_knx(&knx)
    }

    /// Take the sole application program out of a parsed document.
    pub fn from_knx(knx: &Knx) -> Result<Self> {
        let programs = &knx.manufacturer_data.manufacturer.application_programs.programs;
        let provenance = ProductSchemaProvenance::from_knx(knx);

        match programs.as_slice() {
            [program] => Self::from_program_with_provenance(program, provenance),
            [] => Err(ProductError::MissingApplicationProgram),
            programs => Err(ProductError::AmbiguousApplicationProgram { count: programs.len() }),
        }
    }

    /// Read one application program out of a `.knxprod` archive by id.
    #[cfg(feature = "archives")]
    pub fn from_knxprod(archive: &KnxprodArchive, program_id: &str) -> Result<Self> {
        let knx = archive
            .parse_application_program(program_id)
            .ok_or_else(|| ProductError::UnknownApplicationProgram(program_id.to_owned()))??;
        let relation = archive.application_program_relation(program_id, None)?;
        extract_product(&knx, relation, archive.master_data_xml())
    }

    /// Extract from an already-parsed application program.
    pub fn from_program(program: &ApplicationProgram) -> Result<Self> {
        Self::from_program_with_provenance(program, ProductSchemaProvenance::default())
    }

    /// Resolve configuration-dependent module parameter locations for one
    /// concrete device instance.
    ///
    /// A module definition only declares local offsets. Its active instance
    /// supplies allocator-backed `BaseOffset` arguments, so the ordinary
    /// product extraction cannot know the final memory locations. Returning a
    /// derived product value keeps those locations beside the root locations
    /// consumed by the image compiler without mutating the imported package.
    pub fn resolve_device_geometry(&self, device: &Device) -> Result<Self> {
        let modules = device.all_expanded_modules().map(MaterializedModule::from).collect::<Vec<_>>();
        self.resolve_module_geometry(&modules)
    }

    /// Resolve storage from an already evaluated active module roster.
    ///
    /// This consumes final argument values and static package definitions;
    /// it does not evaluate dynamic pages, repeat counts or allocators. Calling
    /// it again replaces the prior module geometry, including removed instances.
    /// Root parameter locations and imported product metadata are preserved.
    ///
    /// Returns an error for duplicate instances, unknown definitions, missing
    /// numeric base arguments or offsets outside the segment's integer range.
    pub fn resolve_module_geometry(&self, modules: &[MaterializedModule]) -> Result<Self> {
        let mut resolved = self.clone();
        resolved.parameters.retain(|parameter| !self.resolved_module_parameter_ids.contains(&parameter.id));
        resolved.property_parameters.retain(|parameter| !self.resolved_module_parameter_ids.contains(&parameter.id));
        resolved.resolved_module_parameter_ids.clear();
        let mut modules = modules.iter().collect::<Vec<_>>();
        modules.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
        let mut instances = BTreeSet::new();

        for module in modules {
            if !instances.insert(&module.instance_id) {
                return Err(ProductError::DuplicateModuleInstance(module.instance_id.clone()));
            }
            let definition = self.module_definitions.get(&module.definition_id).ok_or_else(|| {
                ProductError::UnknownModuleDefinition {
                    module_id: module.instance_id.clone(),
                    definition_id: module.definition_id.clone(),
                }
            })?;
            let mut parameters = Vec::new();
            let mut property_parameters = Vec::new();

            for item in &definition.parameters {
                resolve_module_parameter_item(
                    &self.parameter_widths,
                    &self.byte_unordered_types,
                    definition,
                    module,
                    item,
                    &mut parameters,
                    &mut property_parameters,
                )?;
            }
            resolved.resolved_module_parameter_ids.extend(parameters.iter().map(|parameter| parameter.id.clone()));
            resolved
                .resolved_module_parameter_ids
                .extend(property_parameters.iter().map(|parameter| parameter.id.clone()));
            resolved.parameters.extend(parameters);
            resolved.property_parameters.extend(property_parameters);
        }

        Ok(resolved)
    }

    fn from_program_with_provenance(
        program: &ApplicationProgram,
        schema_provenance: ProductSchemaProvenance,
    ) -> Result<Self> {
        let ExtractedSegments {
            segments,
            relative_segment_offsets,
            address_table_segment,
            association_table_segment,
            com_object_table_segment,
        } = extract_segments(program)?;

        let com_objects = extract_com_objects(program)?;
        let mut com_object_numbers: Vec<u16> = com_objects.iter().map(|o| o.number).collect();
        com_object_numbers.sort_unstable();
        com_object_numbers.dedup();
        let (parameters, property_parameters) = extract_parameters(program)?;
        let programming_options = ProductProgrammingOptions::from_program(program, &schema_provenance);

        Ok(Self {
            id: program.id.clone(),
            mask_version_id: program.mask_version.clone(),
            mask_version: parse_mask_version(&program.mask_version),
            schema_provenance,
            master_data: None,
            programming_options,
            application_program_2: ApplicationProgram2Binding::Unbound,
            secondary_application: None,
            load_procedure_style: LoadProcedureStyle::from_mtxml(&program.load_procedure_style)?,
            application_identity: extract_application_identity(program),
            supports_data_secure: program.is_secure_enabled.unwrap_or(false),
            max_security_individual_address_entries: program.max_security_individual_address_entries,
            max_security_group_key_table_entries: program.max_security_group_key_table_entries,
            max_security_p2p_key_table_entries: program.max_security_p2p_key_table_entries,
            bus_interfaces: program
                .static_section
                .bus_interfaces
                .as_ref()
                .map(|interfaces| interfaces.interfaces.clone())
                .unwrap_or_default(),
            messages: program
                .static_section
                .messages
                .iter()
                .flat_map(|messages| &messages.messages)
                .map(|message| (message.id.clone(), message.text.clone()))
                .collect(),
            segments,
            relative_segment_offsets,
            load_procedures: program
                .static_section
                .load_procedures
                .as_ref()
                .map(|lp| lp.procedures.clone())
                .unwrap_or_default(),
            com_objects,
            com_object_numbers,
            parameters,
            property_parameters,
            module_definitions: program
                .module_defs
                .iter()
                .flat_map(|definitions| &definitions.module_defs)
                .map(|definition| {
                    (definition.id.clone(), ModuleGeometryDefinition {
                        parameters: definition
                            .static_section
                            .parameters
                            .as_ref()
                            .map(|parameters| parameters.items.clone())
                            .unwrap_or_default(),
                        argument_names: definition
                            .arguments
                            .iter()
                            .flat_map(|arguments| &arguments.arguments)
                            .map(|argument| (argument.id.clone(), argument.name.clone()))
                            .collect(),
                    })
                })
                .collect(),
            parameter_widths: program
                .static_section
                .parameter_types
                .iter()
                .flat_map(|types| &types.types)
                .map(|parameter_type| (parameter_type.id.clone(), parameter_type.type_def.size_bits()))
                .collect(),
            byte_unordered_types: program
                .static_section
                .parameter_types
                .iter()
                .flat_map(|types| &types.types)
                .filter(|parameter_type| !parameter_type.type_def.byte_ordered())
                .map(|parameter_type| parameter_type.id.clone())
                .collect(),
            raw_data_parameter_max_sizes: extract_raw_data_parameter_max_sizes(program),
            resolved_module_parameter_ids: BTreeSet::new(),
            address_table_segment,
            address_table_offset: program.static_section.address_table.as_ref().and_then(|t| t.offset).unwrap_or(0),
            address_table_max_entries: program.static_section.address_table.as_ref().map(|t| t.max_entries),
            association_table_segment,
            association_table_offset: program
                .static_section
                .association_table
                .as_ref()
                .and_then(|t| t.offset)
                .unwrap_or(0),
            association_table_max_entries: program.static_section.association_table.as_ref().map(|t| t.max_entries),
            com_object_table_segment,
            com_object_table_offset: program
                .static_section
                .com_object_table
                .as_ref()
                .and_then(|t| t.offset)
                .unwrap_or(0),
            fixups: extract_fixups(program),
            dynamic_table_management: program.dynamic_table_management,
        })
    }

    /// A segment by id.
    pub fn segment(&self, id: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| s.id == id)
    }

    /// The product's single `ProductProcedure` (System 7): the
    /// complete load procedure, needing no mask template.
    pub fn product_procedure(&self) -> Option<&[LoadControl]> {
        match self.load_procedures.as_slice() {
            [only] if only.merge_id.is_none() => Some(&only.controls),
            _ => None,
        }
    }

    /// The product's fragment for one `LdCtrlMerge` splice point
    /// (System B).
    pub fn merge_fragment(&self, merge_id: u8) -> Option<&[LoadControl]> {
        self.load_procedures.iter().find(|p| p.merge_id == Some(merge_id)).map(|p| p.controls.as_slice())
    }
}

#[cfg(feature = "test-fixtures")]
impl ProductData {
    pub fn with_fixture_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    pub fn with_fixture_mask_version_id(mut self, id: impl Into<String>) -> Self {
        self.mask_version_id = id.into();
        self.mask_version = parse_mask_version(&self.mask_version_id);
        self
    }

    pub fn with_fixture_not_loadable(mut self, behavior: impl Into<String>) -> Self {
        self.programming_options.options.get_or_insert_with(Options::default).not_loadable = Some(behavior.into());
        self
    }

    pub fn with_fixture_load_procedure_style(mut self, style: LoadProcedureStyle) -> Self {
        self.load_procedure_style = style;
        self
    }

    pub fn with_fixture_load_procedures(mut self, procedures: Vec<LoadProcedure>) -> Self {
        self.load_procedures = procedures;
        self
    }

    pub fn with_fixture_application_program_2(mut self, binding: ApplicationProgram2Binding) -> Self {
        self.application_program_2 = binding;
        self
    }

    pub fn with_fixture_application_identity(mut self, identity: ApplicationIdentity) -> Self {
        self.application_identity = identity;
        self
    }

    pub fn with_fixture_segments(mut self, segments: Vec<Segment>) -> Self {
        self.relative_segment_offsets = segments
            .iter()
            .filter(|segment| segment.load_state_machine.is_some())
            .map(|segment| {
                let offset = self.relative_segment_offsets.get(&segment.id).copied().unwrap_or(0);
                (segment.id.clone(), offset)
            })
            .collect();
        self.segments = segments;
        self
    }

    pub fn with_fixture_relative_segment_offset(mut self, segment_id: impl Into<String>, offset: u32) -> Self {
        self.relative_segment_offsets.insert(segment_id.into(), offset);
        self
    }

    pub fn with_fixture_parameters(mut self, parameters: Vec<ParameterLocation>) -> Self {
        self.parameters = parameters;
        self
    }

    pub fn with_fixture_property_parameters(mut self, parameters: Vec<PropertyParameterLocation>) -> Self {
        self.property_parameters = parameters;
        self
    }

    pub fn with_fixture_data_secure(mut self, enabled: bool) -> Self {
        self.supports_data_secure = enabled;
        self
    }

    pub fn with_fixture_security_capacities(mut self, individual: u16, group: u16, p2p: u16) -> Self {
        self.max_security_individual_address_entries = Some(individual);
        self.max_security_group_key_table_entries = Some(group);
        self.max_security_p2p_key_table_entries = Some(p2p);
        self
    }

    pub fn with_fixture_com_objects(mut self, objects: Vec<ComObjectDef>, numbers: Vec<u16>) -> Self {
        self.com_objects = objects;
        self.com_object_numbers = numbers;
        self
    }

    pub fn with_fixture_association_table_max_entries(mut self, max_entries: u16) -> Self {
        self.association_table_max_entries = Some(max_entries);
        self
    }
}

// ============================================================================
// Extraction
// ============================================================================

/// The application identity ETS stamps into task-segment records:
/// `[manufacturer:2][application number:2][version:1]`, manufacturer
/// from the program id's `M-XXXX` prefix, the rest from the program's
/// own attributes. A malformed id yields manufacturer 0 — the task
/// record is informational to the devices we drive, and failing the
/// whole product extraction over it would be out of proportion.
fn extract_application_identity(program: &ApplicationProgram) -> ApplicationIdentity {
    let manufacturer = program
        .id
        .strip_prefix("M-")
        .and_then(|rest| rest.get(..4))
        .and_then(|hex| u16::from_str_radix(hex, 16).ok())
        .unwrap_or(0);
    let [mfr_hi, mfr_lo] = manufacturer.to_be_bytes();
    let [app_hi, app_lo] = program.application_number.to_be_bytes();
    ApplicationIdentity {
        application_id: [mfr_hi, mfr_lo, app_hi, app_lo, program.application_version],
        pei_type: program.pei_type,
    }
}

/// `MV-0705` → `MaskVersion::System7Tp1`.
fn parse_mask_version(raw: &str) -> Option<MaskVersion> {
    let hex = raw.strip_prefix("MV-")?;
    // Some ids carry a suffix after the mask itself (MV-0300-0100...).
    let hex = hex.split('-').next()?;
    u16::from_str_radix(hex, 16).ok().map(MaskVersion::from)
}

/// The program's fixups, with each `FunctionRef` reduced to its
/// `_ME-…` suffix — the routine's identity across masks (the prefix
/// is the product's mask, and resolution happens against the mask the
/// download compiles for). A reference without the `_ME-` marker is
/// kept whole; the resolution will fail loudly on it.
fn extract_fixups(program: &ApplicationProgram) -> Vec<FixupDef> {
    program
        .static_section
        .fixup_list
        .iter()
        .flat_map(|list| &list.fixups)
        .map(|fixup| FixupDef {
            function: fixup
                .function_ref
                .rsplit_once("_ME-")
                .map(|(_, suffix)| suffix.to_string())
                .unwrap_or_else(|| fixup.function_ref.clone()),
            code_segment: fixup.code_segment.clone(),
            offsets: fixup.offsets.clone(),
        })
        .collect()
}

/// The segment facts extracted together because table declarations refer back
/// to the code section by id.
struct ExtractedSegments {
    segments: Vec<Segment>,
    relative_segment_offsets: BTreeMap<String, u32>,
    address_table_segment: Option<String>,
    association_table_segment: Option<String>,
    com_object_table_segment: Option<String>,
}

fn extract_segments(program: &ApplicationProgram) -> Result<ExtractedSegments> {
    let mut segments = Vec::new();
    let mut relative_segment_offsets = BTreeMap::new();

    if let Some(code) = &program.static_section.code {
        for abs in &code.absolute_segments {
            let (data, mask) = extract_segment_content(&abs.id, abs.data.as_deref(), abs.mask.as_deref())?;

            segments.push(Segment {
                id: abs.id.clone(),
                address: Some(abs.address),
                size: abs.size,
                memory_type: abs.memory_type.clone(),
                user_memory: abs.user_memory,
                load_state_machine: None,
                data,
                mask,
            });
        }

        for rel in &code.relative_segments {
            relative_segment_offsets.insert(rel.id.clone(), rel.offset);
            let (data, mask) = extract_segment_content(&rel.id, rel.data.as_deref(), rel.mask.as_deref())?;

            segments.push(Segment {
                id: rel.id.clone(),
                address: None,
                size: rel.size,
                memory_type: None,
                user_memory: None,
                load_state_machine: Some(rel.load_state_machine),
                data,
                mask,
            });
        }
    }

    let address_table_segment = program.static_section.address_table.as_ref().and_then(|t| t.code_segment.clone());
    let association_table_segment =
        program.static_section.association_table.as_ref().and_then(|t| t.code_segment.clone());
    let com_object_table_segment =
        program.static_section.com_object_table.as_ref().and_then(|t| t.code_segment.clone());

    Ok(ExtractedSegments {
        segments,
        relative_segment_offsets,
        address_table_segment,
        association_table_segment,
        com_object_table_segment,
    })
}

/// Decode one segment's value/mask pair before it enters the product model.
/// A mask byte describes the data byte at the same index, so unequal lengths
/// cannot represent a valid image.
fn extract_segment_content(
    segment_id: &str,
    data: Option<&str>,
    mask: Option<&str>,
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let data = decode_base64(segment_id, "Data", data)?;
    let mask = mask.map(|mask| decode_base64(segment_id, "Mask", Some(mask))).transpose()?;

    if let Some(mask) = &mask
        && mask.len() != data.len()
    {
        return Err(ProductError::SegmentMaskLength {
            segment_id: segment_id.to_owned(),
            data_length: data.len(),
            mask_length: mask.len(),
        });
    }

    Ok((data, mask))
}

/// XML Schema collapses spaces, tabs and line breaks in `xs:base64Binary`.
/// Normalize those characters explicitly because the Base64 decoder accepts
/// only the canonical, whitespace-free spelling.
fn decode_base64(segment_id: &str, field: &'static str, data: Option<&str>) -> Result<Vec<u8>> {
    let Some(data) = data else {
        return Ok(Vec::new());
    };
    let normalized: String = data.chars().filter(|character| !matches!(character, ' ' | '\t' | '\n' | '\r')).collect();

    BASE64.decode(normalized).map_err(|source| ProductError::InvalidSegmentBase64 {
        segment_id: segment_id.to_owned(),
        field,
        source,
    })
}

fn extract_com_objects(program: &ApplicationProgram) -> Result<Vec<ComObjectDef>> {
    let Some(table) = &program.static_section.com_object_table else {
        return Ok(Vec::new());
    };

    table
        .objects
        .iter()
        .map(|obj| {
            let object_type = ComObjectType::from_ets_size_string(&obj.object_size)
                .ok_or_else(|| ProductError::InvalidObjectSize { number: obj.number, size: obj.object_size.clone() })?;
            Ok(ComObjectDef {
                number: obj.number,
                object_type,
                datapoint_type: obj.datapoint_type.clone(),
                flags: pack_flags(obj),
            })
        })
        .collect()
}

/// Pack MTXML's per-flag `Enabled`/`Disabled` attributes and priority
/// into the group object table's `ComObjectFlags` octet.
///
/// Uses the proto flag masks and `Priority`, so the bit positions have
/// one definition rather than a copy here. The product schema exposes only
/// `ReadOnInitFlag` for bit 5; the selected table realization decides whether
/// that bit means read-on-init (RT7) or a memory-segment selector (RT1, RT2,
/// and System 300 RT6). Keeping the raw bit here avoids imposing RT7 semantics
/// before the exact Master Data profile is known.
fn pack_flags(obj: &crate::schema::ComObject) -> ComObjectFlags {
    use crate::schema::{ComObjectPriority, EnableFlag};
    let on = |f: &EnableFlag| matches!(f, EnableFlag::Enabled);

    // Priority occupies bits 1:0; ETS's default (and an absent
    // attribute) is Low. "Alert" is the wire's Alarm priority.
    let priority = match obj.priority.unwrap_or(ComObjectPriority::Low) {
        ComObjectPriority::Low => Priority::Low,
        ComObjectPriority::High => Priority::High,
        ComObjectPriority::Alert => Priority::Alarm,
    };
    ComObjectFlagFields {
        update: on(&obj.update_flag),
        transmit: on(&obj.transmit_flag),
        bit5: on(&obj.read_on_init_flag),
        write: on(&obj.write_flag),
        read: on(&obj.read_flag),
        communication: on(&obj.communication_flag),
        priority,
    }
    .into()
}

fn resolve_module_parameter_item(
    parameter_widths: &BTreeMap<String, u16>,
    byte_unordered_types: &BTreeSet<String>,
    definition: &ModuleGeometryDefinition,
    module: &MaterializedModule,
    item: &crate::schema::ParameterItem,
    locations: &mut Vec<ParameterLocation>,
    property_locations: &mut Vec<PropertyParameterLocation>,
) -> Result<()> {
    use crate::schema::ParameterItem;

    let size_of = |type_id: &str| parameter_widths.get(type_id).copied().unwrap_or(0);
    let ordered_of = |type_id: &str| !byte_unordered_types.contains(type_id);
    match item {
        ParameterItem::Parameter(parameter) => {
            let id = format!("{}::{}", module.instance_id, parameter.id);
            if let Some(memory) = &parameter.memory {
                locations.push(ParameterLocation {
                    id: id.clone(),
                    code_segment: memory.code_segment.clone(),
                    offset: resolve_module_offset(
                        definition,
                        module,
                        &parameter.id,
                        memory.base_offset.as_deref(),
                        memory.offset,
                    )?,
                    bit_offset: memory.bit_offset,
                    size_bits: size_of(&parameter.parameter_type),
                    byte_ordered: ordered_of(&parameter.parameter_type),
                    legacy_patch_always: parameter.legacy_patch_always,
                    seeds_default: true,
                });
            }
            if let Some(property) = &parameter.property {
                property_locations.push(PropertyParameterLocation {
                    id,
                    object: property_object(property, &parameter.id)?,
                    property_id: property.property_id,
                    offset: resolve_module_offset(
                        definition,
                        module,
                        &parameter.id,
                        property.base_offset.as_deref(),
                        property.offset,
                    )?,
                    bit_offset: property.bit_offset,
                    size_bits: size_of(&parameter.parameter_type),
                    byte_ordered: ordered_of(&parameter.parameter_type),
                    legacy_patch_always: parameter.legacy_patch_always,
                });
            }
        }
        ParameterItem::Union(union) => {
            for parameter in &union.parameters {
                let id = format!("{}::{}", module.instance_id, parameter.id);
                if let Some(memory) = &union.memory {
                    let total_bits = u32::from(memory.bit_offset) + u32::from(parameter.bit_offset);
                    let relative = memory
                        .offset
                        .checked_add(u32::from(parameter.offset))
                        .and_then(|offset| offset.checked_add(total_bits / 8))
                        .ok_or_else(|| ProductError::InvalidModuleParameterOffset {
                            module_id: module.instance_id.clone(),
                            parameter_id: parameter.id.clone(),
                        })?;
                    locations.push(ParameterLocation {
                        id: id.clone(),
                        code_segment: memory.code_segment.clone(),
                        offset: resolve_module_offset(
                            definition,
                            module,
                            &parameter.id,
                            memory.base_offset.as_deref(),
                            relative,
                        )?,
                        bit_offset: (total_bits % 8) as u8,
                        size_bits: size_of(&parameter.parameter_type),
                        byte_ordered: ordered_of(&parameter.parameter_type),
                        legacy_patch_always: false,
                        seeds_default: parameter.default_union_parameter == Some(true),
                    });
                }
                if let Some(property) = &union.property {
                    let total_bits = u32::from(property.bit_offset) + u32::from(parameter.bit_offset);
                    let offset = property
                        .offset
                        .checked_add(u32::from(parameter.offset))
                        .and_then(|offset| offset.checked_add(total_bits / 8))
                        .ok_or_else(|| ProductError::InvalidModuleParameterOffset {
                            module_id: module.instance_id.clone(),
                            parameter_id: parameter.id.clone(),
                        })?;
                    property_locations.push(PropertyParameterLocation {
                        id,
                        object: property_object(property, &parameter.id)?,
                        property_id: property.property_id,
                        offset: resolve_module_offset(
                            definition,
                            module,
                            &parameter.id,
                            property.base_offset.as_deref(),
                            offset,
                        )?,
                        bit_offset: (total_bits % 8) as u8,
                        size_bits: size_of(&parameter.parameter_type),
                        byte_ordered: ordered_of(&parameter.parameter_type),
                        legacy_patch_always: false,
                    });
                }
            }
        }
    }
    Ok(())
}

fn resolve_module_offset(
    definition: &ModuleGeometryDefinition,
    module: &MaterializedModule,
    parameter_id: &str,
    base_offset: Option<&str>,
    relative: u32,
) -> Result<u32> {
    let Some(argument_id) = base_offset else {
        return Ok(relative);
    };
    let base = definition
        .argument_names
        .get(argument_id)
        .and_then(|name| module.arguments.get(name))
        .and_then(|value| match value {
            MaterializedModuleArgument::Numeric(value) => Some(*value),
            MaterializedModuleArgument::Text(_) => None,
        })
        .ok_or_else(|| ProductError::UnresolvedModuleBaseOffset {
            module_id: module.instance_id.clone(),
            parameter_id: parameter_id.to_owned(),
            argument_id: argument_id.to_owned(),
        })?;
    let base = u32::try_from(base).map_err(|_| ProductError::InvalidModuleParameterOffset {
        module_id: module.instance_id.clone(),
        parameter_id: parameter_id.to_owned(),
    })?;
    base.checked_add(relative).ok_or_else(|| ProductError::InvalidModuleParameterOffset {
        module_id: module.instance_id.clone(),
        parameter_id: parameter_id.to_owned(),
    })
}

fn property_object(location: &crate::schema::PropertyLocation, parameter_id: &str) -> Result<PropertyObject> {
    match (location.object_index, location.object_type) {
        (Some(index), None) => Ok(PropertyObject::Index(index)),
        (None, Some(object_type)) => Ok(PropertyObject::Type {
            object_type: InterfaceObjectType::from(object_type),
            occurrence: location.occurrence,
        }),
        (None, None) => Err(ProductError::MissingPropertyObject { parameter_id: parameter_id.to_owned() }),
        (Some(_), Some(_)) => Err(ProductError::ConflictingPropertyObject { parameter_id: parameter_id.to_owned() }),
    }
}

fn extract_raw_data_parameter_max_sizes(program: &ApplicationProgram) -> BTreeMap<String, u32> {
    use crate::schema::{ParameterItem, ParameterTypeDef};

    let raw_types: BTreeMap<_, _> = program
        .static_section
        .parameter_types
        .iter()
        .flat_map(|types| &types.types)
        .filter_map(|parameter_type| match &parameter_type.type_def {
            ParameterTypeDef::TypeRawData(raw) => Some((parameter_type.id.as_str(), raw.max_size)),
            _ => None,
        })
        .collect();
    let mut capacities = BTreeMap::new();
    let mut retain = |id: &str, type_id: &str| {
        if let Some(capacity) = raw_types.get(type_id) {
            capacities.insert(id.to_owned(), *capacity);
        }
    };
    // XML parameter ids are document-wide identifiers, including members of
    // module definitions. Concrete instance ids are resolved separately so
    // retaining a definition cannot authorize an arbitrary module instance.
    for parameters in program.static_section.parameters.iter().chain(
        program
            .module_defs
            .iter()
            .flat_map(|definitions| &definitions.module_defs)
            .filter_map(|definition| definition.static_section.parameters.as_ref()),
    ) {
        for item in &parameters.items {
            match item {
                ParameterItem::Parameter(parameter) => retain(&parameter.id, &parameter.parameter_type),
                ParameterItem::Union(union) => {
                    for parameter in &union.parameters {
                        retain(&parameter.id, &parameter.parameter_type);
                    }
                }
            }
        }
    }
    capacities
}

fn extract_parameters(
    program: &ApplicationProgram,
) -> Result<(Vec<ParameterLocation>, Vec<PropertyParameterLocation>)> {
    use crate::schema::ParameterItem;

    let Some(parameters) = &program.static_section.parameters else {
        return Ok((Vec::new(), Vec::new()));
    };

    // Width lookup through the parameter-type table. A product without
    // one (our own generated test fixtures) degrades every width to 0,
    // which keeps the whole-byte patching path.
    let types = program.static_section.parameter_types.as_ref().map(|pt| pt.types.as_slice()).unwrap_or_default();
    let size_of =
        |type_id: &str| -> u16 { types.iter().find(|t| t.id == type_id).map_or(0, |t| t.type_def.size_bits()) };
    let ordered_of =
        |type_id: &str| -> bool { types.iter().find(|t| t.id == type_id).is_none_or(|t| t.type_def.byte_ordered()) };

    let mut locations = Vec::new();
    let mut property_locations = Vec::new();

    for item in &parameters.items {
        match item {
            // Only stored parameters have a location; the memoryless
            // ones exist purely to drive the ETS UI.
            ParameterItem::Parameter(p) => {
                if let Some(m) = &p.memory {
                    locations.push(ParameterLocation {
                        id: p.id.clone(),
                        code_segment: m.code_segment.clone(),
                        offset: m.offset,
                        bit_offset: m.bit_offset,
                        size_bits: size_of(&p.parameter_type),
                        byte_ordered: ordered_of(&p.parameter_type),
                        legacy_patch_always: p.legacy_patch_always,
                        seeds_default: true,
                    });
                }
                if let Some(property) = &p.property {
                    property_locations.push(PropertyParameterLocation {
                        id: p.id.clone(),
                        object: property_object(property, &p.id)?,
                        property_id: property.property_id,
                        offset: property.offset,
                        bit_offset: property.bit_offset,
                        size_bits: size_of(&p.parameter_type),
                        byte_ordered: ordered_of(&p.parameter_type),
                        legacy_patch_always: p.legacy_patch_always,
                    });
                }
            }
            // A union's members each carry a byte+bit offset relative
            // to the union's own location; normalize the bit sum so a
            // location's bit offset always stays inside its byte.
            ParameterItem::Union(u) => {
                for sub in &u.parameters {
                    if let Some(memory) = &u.memory {
                        let total_bits = u32::from(memory.bit_offset) + u32::from(sub.bit_offset);
                        locations.push(ParameterLocation {
                            id: sub.id.clone(),
                            code_segment: memory.code_segment.clone(),
                            offset: memory.offset + u32::from(sub.offset) + total_bits / 8,
                            bit_offset: (total_bits % 8) as u8,
                            size_bits: size_of(&sub.parameter_type),
                            byte_ordered: ordered_of(&sub.parameter_type),
                            legacy_patch_always: false,
                            seeds_default: sub.default_union_parameter == Some(true),
                        });
                    }
                    if let Some(property) = &u.property {
                        let total_bits = u32::from(property.bit_offset) + u32::from(sub.bit_offset);
                        property_locations.push(PropertyParameterLocation {
                            id: sub.id.clone(),
                            object: property_object(property, &sub.id)?,
                            property_id: property.property_id,
                            offset: property.offset + u32::from(sub.offset) + total_bits / 8,
                            bit_offset: (total_bits % 8) as u8,
                            size_bits: size_of(&sub.parameter_type),
                            byte_ordered: ordered_of(&sub.parameter_type),
                            legacy_patch_always: false,
                        });
                    }
                }
            }
        }
    }
    Ok((locations, property_locations))
}

// ProductData::from_knxprod retains both the application and its exact Master
// Data association. Loose products receive an explicit document before use.

#[cfg(any(test, feature = "test-fixtures"))]
#[doc(hidden)]
#[allow(dead_code)]
pub mod fixtures {
    use super::*;

    /// A System 7 product in the shape our own generator emits: four
    /// absolute segments, a `ProductProcedure`, table elements naming
    /// their segments.
    pub const SYSTEM7_MTXML: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-0306-02-0000" ApplicationNumber="774" ApplicationVersion="2" ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="S7 Light Switch" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="false" Linkable="false">
      <Static>
        <Code>
          <AbsoluteSegment Id="M-00FA_A-0306-02-0000_AS-4000" Address="16384" Size="17" MemoryType="EEPROM" />
          <AbsoluteSegment Id="M-00FA_A-0306-02-0000_AS-4100" Address="16640" Size="15" MemoryType="EEPROM" />
          <AbsoluteSegment Id="M-00FA_A-0306-02-0000_AS-4200" Address="16896" Size="31" MemoryType="EEPROM" />
          <AbsoluteSegment Id="M-00FA_A-0306-02-0000_AS-4300" Address="17152" Size="4" MemoryType="EEPROM"><Data>AQIDBA==</Data></AbsoluteSegment>
        </Code>
        <Parameters>
          <Parameter Id="M-00FA_A-0306-02-0000_P-1" Name="Mode" ParameterType="M-00FA_A-0306-02-0000_PT-1" Text="Mode" Value="0">
            <Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="2" BitOffset="0" />
          </Parameter>
        </Parameters>
        <ComObjectTable CodeSegment="M-00FA_A-0306-02-0000_AS-4200" Offset="0">
          <ComObject Id="M-00FA_A-0306-02-0000_O-1" Name="Switch" Text="Switch" Number="1" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Enabled" ReadOnInitFlag="Disabled" />
        </ComObjectTable>
        <AddressTable CodeSegment="M-00FA_A-0306-02-0000_AS-4000" Offset="0" MaxEntries="7" />
        <AssociationTable CodeSegment="M-00FA_A-0306-02-0000_AS-4100" Offset="0" MaxEntries="7" />
        <LoadProcedures>
          <LoadProcedure>
            <LdCtrlConnect />
            <LdCtrlCompareProp ObjIdx="0" PropId="78" InlineData="00FA0000000A0000" />
            <LdCtrlUnload LsmIdx="1" />
            <LdCtrlLoad LsmIdx="1" />
            <LdCtrlAbsSegment LsmIdx="1" SegType="0" Address="16384" Size="17" Access="255" MemType="3" SegFlags="128" />
            <LdCtrlLoadCompleted LsmIdx="1" />
            <LdCtrlRestart />
            <LdCtrlDisconnect />
          </LoadProcedure>
        </LoadProcedures>
      </Static>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    /// A BCU1 product in the vendor shape (the MDT MV-0012 reference):
    /// one 256-byte EEPROM segment covering the whole ETS-visible
    /// window at 0100h, all three tables pointing *into* it at
    /// offsets, `DefaultProcedure` (the mask template is the whole
    /// procedure). The segment's default data is the 00..FF ramp so
    /// splice tests can see what survived.
    pub const BCU1_MTXML: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-0310-01-0000" ApplicationNumber="784" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0012" Name="BCU1 Switch" LoadProcedureStyle="DefaultProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="false" Linkable="false">
      <Static>
        <Code>
          <AbsoluteSegment Id="M-00FA_A-0310-01-0000_AS-0100" Address="256" Size="256" MemoryType="EEPROM"><Data>AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w==</Data></AbsoluteSegment>
        </Code>
        <Parameters>
          <Parameter Id="M-00FA_A-0310-01-0000_P-1" Name="Mode" ParameterType="M-00FA_A-0310-01-0000_PT-1" Text="Mode" Value="0">
            <Memory CodeSegment="M-00FA_A-0310-01-0000_AS-0100" Offset="200" BitOffset="0" />
          </Parameter>
        </Parameters>
        <ComObjectTable CodeSegment="M-00FA_A-0310-01-0000_AS-0100" Offset="80">
          <ComObject Id="M-00FA_A-0310-01-0000_O-0" Name="Switch" Text="Switch" Number="0" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
          <ComObject Id="M-00FA_A-0310-01-0000_O-1" Name="Status" Text="Status" Number="1" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Enabled" WriteFlag="Disabled" CommunicationFlag="Enabled" TransmitFlag="Enabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
        </ComObjectTable>
        <AddressTable CodeSegment="M-00FA_A-0310-01-0000_AS-0100" Offset="22" MaxEntries="5" />
        <AssociationTable CodeSegment="M-00FA_A-0310-01-0000_AS-0100" Offset="60" MaxEntries="5" />
        <FixupList>
          <Fixup FunctionRef="MV-0012_ME-U.5FGetTMx" CodeSegment="M-00FA_A-0310-01-0000_AS-0100">
            <Offset>239</Offset>
          </Fixup>
        </FixupList>
        <LoadProcedures />
      </Static>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    fn product() -> ProductData {
        ProductData::from_mtxml_str(SYSTEM7_MTXML).expect("the fixture parses")
    }

    fn relation() -> ApplicationProgramRelationIdentity {
        ApplicationProgramRelationIdentity {
            catalog_product_id: Some("M-00FA_H-1_P-1".to_owned()),
            catalog_item_id: Some("M-00FA_CI-1".to_owned()),
            hardware_id: "M-00FA_H-1".to_owned(),
            hardware2program_id: "M-00FA_H-1_HP-1".to_owned(),
            application_program_id: "M-00FA_A-0306-02-0000".to_owned(),
        }
    }

    #[test]
    fn product_error_does_not_inflate_every_result_with_rare_binding_context() {
        // Product errors are embedded in archive, runtime and client results.
        // Budget the representation rather than pinning Rust's exact layout.
        let size = std::mem::size_of::<ProductError>();
        assert!(size <= 128, "ProductError occupies {size} bytes");
    }

    #[test]
    fn conflicting_application_program_binding_retains_both_relations() {
        let current = ApplicationProgram2Binding::Absent { relation: relation() };
        let selected = ApplicationProgram2Binding::Present {
            relation: ApplicationProgramRelationIdentity {
                hardware2program_id: "M-00FA_H-1_HP-2".to_owned(),
                ..relation()
            },
            application_program_id: "M-00FA_A-0307-01-0000".to_owned(),
        };
        let bound = product().bind_application_program_2(current.clone()).expect("initial relation");
        let bound = bound.bind_application_program_2(current.clone()).expect("same relation is idempotent");
        assert_eq!(bound.application_program_2(), &current);

        let error = bound.bind_application_program_2(selected.clone()).expect_err("contradictory relation");
        assert!(matches!(error, ProductError::ApplicationProgram2BindingConflict { .. }));
        assert_eq!(
            error.to_string(),
            format!("application-program-2 binding {selected:?} conflicts with the existing binding {current:?}")
        );
    }

    #[test]
    fn secondary_application_binds_only_the_relation_s_pei_program() {
        let pei_id = "M-00FA_A-0307-01-0000";
        let present =
            ApplicationProgram2Binding::Present { relation: relation(), application_program_id: pei_id.to_owned() };
        let pei =
            || ProductData::default().with_fixture_id(pei_id).with_fixture_mask_version_id(product().mask_version_id());

        // Without a declared AP2, or for another ID, no content can bind.
        let error = product().bind_secondary_application(pei()).expect_err("no AP2 is declared");
        assert!(matches!(error, ProductError::SecondaryApplicationMismatch { expected: None, .. }));
        let primary = product().bind_application_program_2(present).expect("relation binds");
        let error = primary.clone().bind_secondary_application(product()).expect_err("another application");
        assert!(matches!(error, ProductError::SecondaryApplicationMismatch { expected: Some(_), .. }));

        // A PEI Program shares the mask and carries no configuration.
        let error = primary
            .clone()
            .bind_secondary_application(pei().with_fixture_mask_version_id("MV-0701"))
            .expect_err("another mask");
        assert!(error.to_string().contains("another mask version"));
        let configurable = pei().with_fixture_parameters(product().parameters().to_vec());
        assert!(!configurable.parameters().is_empty(), "the fixture product has parameters");
        let error = primary.clone().bind_secondary_application(configurable).expect_err("parameters");
        assert!(error.to_string().contains("parameters or communication objects"));

        let bound = primary.bind_secondary_application(pei()).expect("the declared PEI Program binds");
        assert_eq!(bound.secondary_application().map(ProductData::id), Some(pei_id));
    }

    #[test]
    fn application_profile_alias_preserves_authored_identity_and_qualified_architectures() {
        for (authored, effective) in [
            ("MV-0300", "MV-0300-01000001000000000000"),
            ("MV-0300-01000001000000000000", "MV-0300-01000001000000000000"),
            ("MV-0300-01000000000000000000", "MV-0300-01000000000000000000"),
            ("MV-07B0", "MV-07B0"),
        ] {
            let application = ProductData::default().with_fixture_mask_version_id(authored);
            assert_eq!(application.mask_version_id(), authored);
            assert_eq!(application.programming_profile_id(), effective);
        }
    }

    #[test]
    fn secondary_application_compatibility_uses_effective_profile_without_merging_architectures() {
        let pei_id = "M-00FA_A-0307-01-0000";
        for (primary_mask, secondary_mask, compatible) in [
            ("MV-0300", "MV-0300-01000001000000000000", true),
            ("MV-0300-01000001000000000000", "MV-0300", true),
            ("MV-0300", "MV-0300-01000000000000000000", false),
        ] {
            let primary = ProductData::default()
                .with_fixture_id(relation().application_program_id)
                .with_fixture_mask_version_id(primary_mask)
                .bind_application_program_2(ApplicationProgram2Binding::Present {
                    relation: relation(),
                    application_program_id: pei_id.to_owned(),
                })
                .expect("fixture relation binds");
            let secondary = ProductData::default().with_fixture_id(pei_id).with_fixture_mask_version_id(secondary_mask);
            let result = primary.bind_secondary_application(secondary);
            assert_eq!(result.is_ok(), compatible, "{primary_mask} / {secondary_mask}");
            if let Ok(bound) = result {
                assert_eq!(bound.mask_version_id(), primary_mask);
                assert_eq!(bound.secondary_application().expect("secondary bound").mask_version_id(), secondary_mask);
            }
        }
    }

    #[test]
    fn lone_application_mtxml_does_not_infer_application_program_2() {
        let product = product();
        assert_eq!(product.application_program_2(), &ApplicationProgram2Binding::Unbound);

        let absent = product
            .clone()
            .bind_application_program_2(ApplicationProgram2Binding::Absent { relation: relation() })
            .expect("hardware metadata binds");
        assert!(matches!(absent.application_program_2(), ApplicationProgram2Binding::Absent { .. }));

        let present = product
            .bind_application_program_2(ApplicationProgram2Binding::Present {
                relation: relation(),
                application_program_id: "M-00FA_A-0307-01-0000".to_owned(),
            })
            .expect("hardware metadata binds");
        assert!(matches!(present.application_program_2(), ApplicationProgram2Binding::Present { .. }));
    }

    const PROGRAMMING_METADATA_MTXML: &str = r#"<KNX CreatedBy="CvNext" ToolVersion="6.4" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-000C"><ApplicationPrograms>
    <ApplicationProgram Id="M-000C_A-0001-01-0000" ApplicationNumber="1" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0300-01000001000000000000" Name="Profile variant" LoadProcedureStyle="ProductProcedure" PeiType="17" DefaultLanguage="en-US" DynamicTableManagement="true" Linkable="true" MinEtsVersion="4.0" OriginalManufacturer="M-00FA" PreEts4Style="true" ConvertedFromPreEts4Data="false" CreatedFromLegacySchemaVersion="true" IPConfig="Custom" AdditionalAddressesCount="4" IsSecureEnabled="true" MaxUserEntries="5" MaxTunnelingUserEntries="4" MaxSecurityIndividualAddressEntries="9" MaxSecurityGroupKeyTableEntries="8" MaxSecurityP2PKeyTableEntries="7" MaxSecurityProxyGroupKeyTableEntries="6" MaxSecurityProxyIndividualAddressTableEntries="5" NonRegRelevantDataVersion="3" Broken="false" DownloadInfoIncomplete="true" ReplacesVersions="1 2" Hash="AQIDBA==" TunnelingAddressIndices="AQID">
      <Static>
        <Code><AbsoluteSegment Id="M-000C_A-0001-01-0000_AS-100" Address="256" Size="1" MemoryType="EEPROM" UserMemory="true" /></Code>
        <BusInterfaces>
          <BusInterface Id="M-000C_A-0001-01-0000_BI-1" AddressIndex="1" AccessType="Tunneling" Text="Tunnel 1" />
          <BusInterface Id="M-000C_A-0001-01-0000_BI-2" AddressIndex="2" AccessType="Routing" />
        </BusInterfaces>
        <Extension EtsDownloadPlugin="Vendor.Download" EtsUiPlugin="Vendor.Ui" EtsDataHandler="Vendor.Data" EtsDataHandlerCapabilities="Load" RequiresExternalSoftware="true" />
        <Options PreferPartialDownloadIfApplicationLoaded="true" EasyCtrlModeModeStyleEmptyGroupComTables="true" SetObjectTableLengthAlwaysToOne="true" TextParameterEncoding="utf-8" TextParameterEncodingSelector="UseProjectCodePage" TextParameterZeroTerminate="true" ParameterByteOrder="LittleEndian" PartialDownloadOnlyVisibleParameters="true" LegacyNoPartialDownload="true" LegacyNoMemoryVerifyMode="true" LegacyNoOptimisticWrite="true" LegacyDoNotReportPropertyWriteErrors="true" LegacyNoBackgroundDownload="true" LegacyDoNotCheckManufacturerId="true" LegacyAlwaysReloadAppIfCoVisibilityChanged="true" LegacyNeverReloadAppIfCoVisibilityChanged="false" LegacyDoNotSupportUndoDelete="true" LegacyAllowPartialDownloadIfAp2Mismatch="true" LegacyKeepObjectTableGaps="true" LegacyProxyCommunicationObjects="true" DeviceInfoIgnoreRunState="true" DeviceInfoIgnoreLoadedState="true" DeviceCompareAllowCompatibleManufacturerId="true" LineCoupler0912NewProgrammingStyle="true" MaxRoutingApduLength="254" Comparable="false" Reconstructable="true" DownloadInvisibleParameters="FutureBehavior" SupportsExtendedMemoryServices="true" SupportsExtendedPropertyServices="true" SupportsIpSystemBroadcast="true" NotLoadable="DisplayError" NotLoadableMessageRef="M-000C_A-0001-01-0000_MSG-1" CustomerAdjustableParameters="Sync" MasterResetOnCRCMismatch="true" PromptBeforeFullDownload="true" LegacyPatchManufacturerIdInTaskSegment="true" />
      </Static>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    #[test]
    fn preserves_programming_metadata_without_applying_defaults() {
        let product = ProductData::from_mtxml_str(PROGRAMMING_METADATA_MTXML).expect("metadata fixture parses");
        let provenance = product.schema_provenance();
        let options = product.programming_options();
        let raw = options.raw_options().expect("Options element is retained");

        assert_eq!(product.mask_version_id(), "MV-0300-01000001000000000000");
        assert_eq!(product.mask_version(), Some(MaskVersion::from(0x0300)));
        assert_eq!(provenance.namespace(), Some("http://knx.org/xml/project/20"));
        assert_eq!(provenance.schema_version(), Some(20));
        assert_eq!(provenance.schema_version_source(), Some(ProductSchemaVersionSource::DocumentNamespace));
        assert_eq!(provenance.created_by(), Some("CvNext"));
        assert_eq!(provenance.tool_version(), Some("6.4"));

        assert_eq!(options.application_attributes().pre_ets4_style, Some(true));
        assert_eq!(options.application_attributes().converted_from_pre_ets4_data, Some(false));
        assert_eq!(options.application_attributes().created_from_legacy_schema_version, Some(true));
        assert_eq!(options.original_manufacturer(), Some("M-00FA"));
        assert_eq!(options.tunneling_address_indices(), Some("AQID"));
        assert_eq!(options.application_hash(), Some("AQIDBA=="));
        assert_eq!(options.replaces_versions(), Some("1 2"));
        assert_eq!(options.ip_configuration().value, IpConfigurationMode::Custom);
        assert!(options.ip_configuration().is_explicit());
        assert_eq!(options.max_security_proxy_group_key_table_entries().value, 6);
        assert_eq!(options.max_security_proxy_individual_address_table_entries().value, 5);

        assert_eq!(raw.prefer_partial_download_if_application_loaded, Some(true));
        assert_eq!(raw.parameter_byte_order.as_deref(), Some("LittleEndian"));
        assert_eq!(raw.legacy_no_memory_verify_mode, Some(true));
        assert_eq!(raw.legacy_no_optimistic_write, Some(true));
        assert_eq!(raw.line_coupler_0912_new_programming_style, Some(true));
        assert_eq!(raw.max_routing_apdu_length, Some(254));
        assert_eq!(raw.not_loadable.as_deref(), Some("DisplayError"));
        assert_eq!(raw.master_reset_on_crc_mismatch, Some(true));
        assert_eq!(raw.legacy_patch_manufacturer_id_in_task_segment, Some(true));

        assert_eq!(options.parameter_byte_order().value, ParameterByteOrder::LittleEndian);
        assert_eq!(options.not_loadable(), Some(NotLoadableBehavior::DisplayError));
        assert_eq!(options.customer_adjustable_parameters(), Some(CustomerAdjustableParameterBehavior::Sync));
        assert_eq!(
            options.download_invisible_parameters().value,
            DownloadBehavior::Unknown("FutureBehavior".to_owned())
        );
        assert!(options.requires_external_software().value);
        assert_eq!(
            options.extension().and_then(|extension| extension.ets_download_plugin.as_deref()),
            Some("Vendor.Download")
        );

        let segment = product.segments().first().expect("absolute segment survives");
        assert_eq!(segment.user_memory, Some(true));
        assert_eq!(product.bus_interfaces().len(), 2);
        assert_eq!(product.bus_interfaces()[0].address_index, 1);
        assert_eq!(product.bus_interfaces()[0].access_type, crate::schema::BusAccessType::Tunneling);
        assert_eq!(product.bus_interfaces()[0].text.as_deref(), Some("Tunnel 1"));
        assert_eq!(product.bus_interfaces()[1].access_type, crate::schema::BusAccessType::Routing);
    }

    #[test]
    fn exposes_schema_defaults_with_their_source() {
        let product = product();
        let options = product.programming_options();
        let default_source = ProductValueSource::SchemaDefault { schema_version: Some(20) };

        assert!(options.raw_options().is_none());
        assert_eq!(options.pre_ets4_style(), EffectiveProductValue { value: false, source: default_source });
        assert_eq!(options.parameter_byte_order(), EffectiveProductValue {
            value: ParameterByteOrder::BigEndian,
            source: default_source
        });
        assert_eq!(options.download_invisible_parameters(), EffectiveProductValue {
            value: DownloadBehavior::DefaultValue,
            source: default_source
        });
        assert_eq!(options.prefer_partial_download_if_application_loaded(), EffectiveProductValue {
            value: false,
            source: default_source
        });

        let without_namespace = SYSTEM7_MTXML.replace(r#" xmlns="http://knx.org/xml/project/20""#, "");
        let converted = ProductData::from_mtxml_str(&without_namespace).expect("namespace-free product parses");
        assert_eq!(converted.schema_provenance().schema_version(), None);
        assert_eq!(converted.schema_provenance().schema_version_source(), None);
        assert_eq!(converted.programming_options().pre_ets4_style().source, ProductValueSource::SchemaDefault {
            schema_version: None
        });
    }

    #[test]
    fn explicitly_versions_a_namespace_free_product_and_its_schema_defaults() {
        let xml = SYSTEM7_MTXML.replace(r#" xmlns="http://knx.org/xml/project/20""#, "");
        let product = ProductData::from_mtxml_str(&xml).expect("namespace-free product parses");

        let product = product.bind_schema_version(KnxSchemaVersion::V23).expect("explicit schema binds");

        assert_eq!(product.schema_provenance().namespace(), None);
        assert_eq!(product.schema_provenance().schema_version(), Some(23));
        assert_eq!(
            product.schema_provenance().schema_version_source(),
            Some(ProductSchemaVersionSource::ExplicitBinding)
        );
        assert_eq!(product.schema_provenance().created_by(), Some("zweidraehte"));
        assert_eq!(product.schema_provenance().tool_version(), Some("0.1.0"));
        assert_eq!(product.programming_options().pre_ets4_style().source, ProductValueSource::SchemaDefault {
            schema_version: Some(23)
        });
    }

    #[test]
    fn matching_explicit_schema_preserves_document_provenance() {
        let xml = SYSTEM7_MTXML
            .replace(r#"xmlns="http://knx.org/xml/project/20""#, r#"xmlns="http://knx.org/xml/project/20/""#);
        let product = ProductData::from_mtxml_str(&xml).expect("versioned product parses");
        let provenance = product.schema_provenance().clone();

        let product = product.bind_schema_version(KnxSchemaVersion::V20).expect("matching schema binds");

        assert_eq!(product.schema_provenance(), &provenance);
        assert_eq!(product.programming_options().pre_ets4_style().source, ProductValueSource::SchemaDefault {
            schema_version: Some(20)
        });
    }

    #[test]
    fn explicit_schema_rejects_existing_mismatched_or_unrecognized_provenance() {
        let error = product().bind_schema_version(KnxSchemaVersion::V23).expect_err("mismatched schema is rejected");
        assert!(matches!(error, ProductError::SchemaProvenanceConflict {
            declared_version: Some(20),
            selected_version: 23,
            ..
        }));

        let xml = SYSTEM7_MTXML.replace("http://knx.org/xml/project/20", "urn:vendor:project");
        let product = ProductData::from_mtxml_str(&xml).expect("unknown namespace remains parseable");
        let error = product
            .bind_schema_version(KnxSchemaVersion::V20)
            .expect_err("an existing unrecognized namespace is not overwritten");
        assert!(matches!(error, ProductError::SchemaProvenanceConflict {
            declared_version: None,
            selected_version: 20,
            ..
        }));

        let xml = SYSTEM7_MTXML.replace("http://knx.org/xml/project/20", "urn:vendor/project/20");
        let product = ProductData::from_mtxml_str(&xml).expect("numeric-suffix namespace remains parseable");
        assert_eq!(product.schema_provenance().schema_version(), None);
        let error = product
            .bind_schema_version(KnxSchemaVersion::V20)
            .expect_err("a numeric suffix does not impersonate the canonical KNX namespace");
        assert!(matches!(error, ProductError::SchemaProvenanceConflict {
            declared_version: None,
            selected_version: 20,
            ..
        }));
    }

    #[test]
    fn extracts_bcu1_table_offsets() {
        let p = ProductData::from_mtxml_str(BCU1_MTXML).expect("the BCU1 fixture parses");
        assert_eq!(p.mask_version, Some(MaskVersion::Bcu1Tp1));
        assert_eq!(p.load_procedure_style, LoadProcedureStyle::Default);
        assert_eq!(p.address_table_offset, 22);
        assert_eq!(p.association_table_offset, 60);
        assert_eq!(p.com_object_table_offset, 80);
        // All three point into the one EEPROM segment.
        let segment = p.address_table_segment.as_deref().expect("ADT segment named");
        assert_eq!(p.association_table_segment.as_deref(), Some(segment));
        assert_eq!(p.com_object_table_segment.as_deref(), Some(segment));

        // The fixup, reduced to its cross-mask routine identity.
        assert_eq!(p.fixups, vec![FixupDef {
            function: "U.5FGetTMx".to_string(),
            code_segment: segment.to_string(),
            offsets: vec![239],
        }]);
    }

    #[test]
    fn extracts_dynamic_table_management() {
        assert!(!ProductData::from_mtxml_str(BCU1_MTXML).expect("the BCU1 fixture parses").dynamic_table_management);

        let converted = BCU1_MTXML.replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"");
        let p = ProductData::from_mtxml_str(&converted).expect("the converted fixture parses");
        assert!(p.dynamic_table_management);
    }

    #[test]
    fn extracts_identity_and_style() {
        let p = product();
        assert_eq!(p.id, "M-00FA_A-0306-02-0000");
        assert_eq!(p.mask_version, Some(MaskVersion::System7Tp1));
        assert_eq!(p.load_procedure_style, LoadProcedureStyle::Product);
    }

    #[test]
    fn rejects_an_unknown_load_procedure_style() {
        let xml = SYSTEM7_MTXML.replace("ProductProcedure", "InventedProcedure");
        let error = ProductData::from_mtxml_str(&xml).expect_err("the schema enumeration is closed");

        assert!(matches!(error, ProductError::InvalidLoadProcedureStyle(style) if style == "InventedProcedure"));
    }

    #[test]
    fn extracts_data_secure_capacities() {
        let xml = SYSTEM7_MTXML.replace(
            "Linkable=\"false\"",
            "Linkable=\"false\" IsSecureEnabled=\"true\" \
             MaxSecurityIndividualAddressEntries=\"190\" \
             MaxSecurityGroupKeyTableEntries=\"64\" \
             MaxSecurityP2PKeyTableEntries=\"0\"",
        );
        let p = ProductData::from_mtxml_str(&xml).expect("secure attributes parse");
        assert!(p.supports_data_secure);
        assert_eq!(p.max_security_individual_address_entries, Some(190));
        assert_eq!(p.max_security_group_key_table_entries, Some(64));
        assert_eq!(p.max_security_p2p_key_table_entries, Some(0));
    }

    #[test]
    fn extracts_absolute_segments_with_decoded_defaults() {
        let p = product();
        assert_eq!(p.segments.len(), 4);

        let adt = p.segment("M-00FA_A-0306-02-0000_AS-4000").expect("ADT segment");
        assert_eq!(adt.address, Some(0x4000));
        assert_eq!(adt.size, 17);
        assert_eq!(adt.memory_type.as_deref(), Some("EEPROM"));
        assert!(adt.data.is_empty(), "no <Data> means no defaults");

        // The parameter segment's base64 defaults decode to bytes —
        // this is what the download image gets seeded with.
        let params = p.segment("M-00FA_A-0306-02-0000_AS-4300").expect("param segment");
        assert_eq!(params.data, [1, 2, 3, 4]);
    }

    #[test]
    fn decodes_segment_content_and_exact_masks_with_xml_whitespace() {
        const SEGMENT: &str = r#"<AbsoluteSegment Id="M-00FA_A-0306-02-0000_AS-4300" Address="17152" Size="4" MemoryType="EEPROM"><Data>AQIDBA==</Data></AbsoluteSegment>"#;
        const WRAPPED_SEGMENT: &str = r#"<AbsoluteSegment Id="M-00FA_A-0306-02-0000_AS-4300" Address="17152" Size="4" MemoryType="EEPROM">
            <Data>AQID
              BA==</Data>
            <Mask>/w8A
              /w==</Mask>
          </AbsoluteSegment>"#;

        let xml = SYSTEM7_MTXML.replace(SEGMENT, WRAPPED_SEGMENT);
        let product = ProductData::from_mtxml_str(&xml).expect("whitespace in base64 is legal");
        let segment = product.segment("M-00FA_A-0306-02-0000_AS-4300").expect("segment is extracted");

        assert_eq!(segment.data, [1, 2, 3, 4]);
        assert_eq!(segment.mask.as_deref(), Some(&[0xFF, 0x0F, 0x00, 0xFF][..]));
    }

    #[test]
    fn rejects_invalid_segment_base64() {
        let xml = SYSTEM7_MTXML.replace("<Data>AQIDBA==</Data>", "<Data>not-base64!</Data>");
        let error = ProductData::from_mtxml_str(&xml).expect_err("invalid base64 must not become an empty image");

        assert!(matches!(error, ProductError::InvalidSegmentBase64 { field: "Data", .. }));
    }

    #[test]
    fn rejects_a_mask_with_the_wrong_length() {
        let xml = SYSTEM7_MTXML.replace("<Data>AQIDBA==</Data>", "<Data>AQIDBA==</Data><Mask>/wAA</Mask>");
        let error = ProductData::from_mtxml_str(&xml).expect_err("three mask bytes cannot describe four data bytes");

        assert!(matches!(error, ProductError::SegmentMaskLength { data_length: 4, mask_length: 3, .. }));
    }

    #[test]
    fn extracts_relative_segment_offset() {
        const SEGMENT_ID: &str = "M-00FA_A-0306-02-0000_AS-4300";

        let xml = SYSTEM7_MTXML.replace(
            r#"<AbsoluteSegment Id="M-00FA_A-0306-02-0000_AS-4300" Address="17152" Size="4" MemoryType="EEPROM"><Data>AQIDBA==</Data></AbsoluteSegment>"#,
            r#"<RelativeSegment Id="M-00FA_A-0306-02-0000_AS-4300" Size="4" LoadStateMachine="4" Offset="7"><Data>AQIDBA==</Data></RelativeSegment>"#,
        );
        let product = ProductData::from_mtxml_str(&xml).expect("relative segment parses");
        let segment = product.segment(SEGMENT_ID).expect("relative segment is extracted");

        assert_eq!(segment.address, None);
        assert_eq!(segment.load_state_machine, Some(4));
        assert_eq!(product.relative_segment_offset(SEGMENT_ID), Some(7));
        assert_eq!(product.relative_segment_offset("M-00FA_A-0306-02-0000_AS-4000"), None);
    }

    #[test]
    fn extracts_table_segment_bindings() {
        let p = product();
        assert_eq!(p.address_table_segment.as_deref(), Some("M-00FA_A-0306-02-0000_AS-4000"));
        assert_eq!(p.address_table_max_entries, Some(7));
        assert_eq!(p.association_table_segment.as_deref(), Some("M-00FA_A-0306-02-0000_AS-4100"));
        assert_eq!(p.com_object_table_segment.as_deref(), Some("M-00FA_A-0306-02-0000_AS-4200"));
    }

    #[test]
    fn extracts_the_product_procedure() {
        let p = product();
        let procedure = p.product_procedure().expect("System 7 carries one unmerged procedure");
        assert_eq!(procedure.len(), 8);
        assert!(matches!(procedure[0], LoadControl::LdCtrlConnect(_)));
        // The identity guard survives with its inline serial.
        match &procedure[1] {
            LoadControl::LdCtrlCompareProp(c) => {
                assert_eq!(c.obj_idx, Some(0));
                assert_eq!(c.prop_id, 78);
                assert_eq!(c.inline_data.as_deref(), Some("00FA0000000A0000"));
            }
            other => panic!("expected CompareProp, got {other:?}"),
        }
        assert!(p.merge_fragment(1).is_none(), "a ProductProcedure has no merge points");
    }

    #[test]
    fn packs_com_object_type_and_flags_into_the_device_coding() {
        let p = product();
        let obj = &p.com_objects[0];
        assert_eq!(obj.number, 1);
        assert_eq!(obj.object_type, ComObjectType::Uint1, "1 Bit");
        // Write + Communication + Update enabled, Read/Transmit/ROI
        // off, priority Low — 0b1001_0100 | 0b11.
        assert_eq!(obj.flags.to_byte(), 0b1001_0100 | 0b11);
    }

    #[test]
    fn an_unrecognized_object_size_is_rejected() {
        // A product whose ComObject declares a size string outside the
        // ETS coding fails to extract, rather than silently becoming
        // Uint1.
        let xml = SYSTEM7_MTXML.replace(r#"ObjectSize="1 Bit""#, r#"ObjectSize="3 Widgets""#);
        assert!(matches!(ProductData::from_mtxml_str(&xml), Err(ProductError::InvalidObjectSize { .. })));
    }

    #[test]
    fn honors_com_object_priority() {
        // The fixture's object omits Priority (defaults Low = 3); an
        // Alert priority must reach the descriptor as the wire's Alarm
        // (2), not stay Low.
        let xml =
            SYSTEM7_MTXML.replace(r#"ObjectSize="1 Bit" ReadFlag"#, r#"ObjectSize="1 Bit" Priority="Alert" ReadFlag"#);
        let p = ProductData::from_mtxml_str(&xml).expect("parses");
        assert_eq!(p.com_objects[0].flags.priority(), Priority::Alarm);
    }

    #[test]
    fn extracts_parameter_locations() {
        let p = product();
        assert_eq!(p.parameters.len(), 1);
        let param = &p.parameters[0];
        assert_eq!(param.code_segment, "M-00FA_A-0306-02-0000_AS-4300");
        assert_eq!(param.offset, 2);
        assert_eq!(param.bit_offset, 0);
        // The fixture declares no ParameterTypes section, so the width
        // is unknown and patching falls back to whole-byte copies.
        assert_eq!(param.size_bits, 0);
        assert!(!param.legacy_patch_always);
    }

    #[test]
    fn raw_data_capacities_follow_only_stored_root_and_resolved_module_ids() {
        let xml = SYSTEM7_MTXML
            .replace(
                "<Parameters>",
                r#"<ParameterTypes><ParameterType Id="M-00FA_A-0306-02-0000_PT-1" Name="Raw"><TypeRawData MaxSize="307200"/></ParameterType></ParameterTypes><Parameters>"#,
            )
            .replace(
                "</Parameters>",
                r#"<Union SizeInBit="8"><Property ObjectIndex="3" PropertyId="100" Offset="0" BitOffset="0"/>
                  <Parameter Id="root-union" Name="RootUnion" Text="Root union" ParameterType="M-00FA_A-0306-02-0000_PT-1" Value="" Offset="0" BitOffset="0" DefaultUnionParameter="true"/>
                </Union></Parameters>"#,
            )
            .replace(
                "</ApplicationProgram>",
                r#"<ModuleDefs><ModuleDef Id="channel" Name="Channel"><Static><Parameters>
                  <Parameter Id="module-raw" Name="Raw" Text="Raw" ParameterType="M-00FA_A-0306-02-0000_PT-1" Value="">
                    <Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="0" BitOffset="0"/>
                  </Parameter>
                  <Union SizeInBit="8"><Property ObjectIndex="3" PropertyId="101" Offset="0" BitOffset="0"/>
                    <Parameter Id="module-union" Name="ModuleUnion" Text="Module union" ParameterType="M-00FA_A-0306-02-0000_PT-1" Value="" Offset="0" BitOffset="0" DefaultUnionParameter="true"/>
                  </Union>
                </Parameters></Static></ModuleDef></ModuleDefs></ApplicationProgram>"#,
            );
        let product = ProductData::from_mtxml_str(&xml).expect("raw parameter product parses");
        let root_id = "M-00FA_A-0306-02-0000_P-1";
        assert_eq!(product.raw_data_parameter_max_size(root_id), Some(307200));
        assert_eq!(product.raw_data_parameter_max_size("root-union"), Some(307200));
        assert_eq!(product.parameters()[0].size_bits, 0, "raw capacity does not truncate to a u16 bit width");
        for id in ["unknown", "module-raw", "first::module-raw", "invented::module-raw", "invented::root-union"] {
            assert_eq!(product.raw_data_parameter_max_size(id), None, "unresolved {id}");
        }
        let resolved = product
            .resolve_module_geometry(&[MaterializedModule {
                instance_id: "first".to_owned(),
                definition_id: "channel".to_owned(),
                arguments: BTreeMap::new(),
            }])
            .expect("raw module geometry resolves");
        assert_eq!(resolved.raw_data_parameter_max_size("first::module-raw"), Some(307200));
        assert_eq!(resolved.raw_data_parameter_max_size("first::module-union"), Some(307200));
        assert_eq!(resolved.raw_data_parameter_max_size("invented::module-raw"), None);
        assert_eq!(resolved.raw_data_parameter_max_size("first::root-union"), None);
        let removed = resolved.resolve_module_geometry(&[]).expect("module geometry removes");
        assert_eq!(removed.raw_data_parameter_max_size("first::module-raw"), None);
        assert_eq!(removed.raw_data_parameter_max_size(root_id), Some(307200));

        let raw_identity = serde_json::to_value(product.programming_identity()).expect("raw identity serializes");
        let ordinary = ProductData::from_mtxml_str(&xml.replace(r#"<TypeRawData MaxSize="307200"/>"#, "<TypeNone/>"))
            .expect("untyped parameter product parses");
        let ordinary_identity =
            serde_json::to_value(ordinary.programming_identity()).expect("ordinary identity serializes");
        assert_eq!(raw_identity["raw_data_parameter_max_sizes"][root_id], 307200);
        assert!(ordinary_identity.get("raw_data_parameter_max_sizes").is_none());
        assert_ne!(raw_identity, ordinary_identity, "raw framing changes the programming identity");
    }

    #[test]
    fn extracts_property_parameter_locations() {
        let xml = SYSTEM7_MTXML.replace(
            r#"<Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="2" BitOffset="0" />"#,
            r#"<Property ObjectIndex="0" PropertyId="86" Offset="0" BitOffset="0" />"#,
        );
        let product = ProductData::from_mtxml_str(&xml).expect("property parameter product parses");

        assert!(product.parameters.is_empty());
        assert_eq!(product.property_parameters.len(), 1);
        let parameter = &product.property_parameters[0];
        assert_eq!(parameter.object, PropertyObject::Index(0));
        assert_eq!(parameter.property_id, 86);
    }

    #[test]
    fn property_parameters_preserve_absent_and_explicit_zero_occurrence() {
        for (occurrence_attribute, expected) in [("", None), (" Occurrence=\"0\"", Some(0))] {
            let xml = SYSTEM7_MTXML.replace(
                r#"<Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="2" BitOffset="0" />"#,
                &format!(
                    r#"<Property ObjectType="417"{occurrence_attribute} PropertyId="109" Offset="0" BitOffset="0" />"#,
                ),
            );
            let product = ProductData::from_mtxml_str(&xml).expect("property parameter product parses");
            let expected_object =
                PropertyObject::Type { object_type: InterfaceObjectType::from(417), occurrence: expected };
            assert_eq!(product.property_parameters()[0].object, expected_object);
        }
    }

    /// The fixture's `<Parameters>` block swapped for one with a type
    /// table, a `LegacyPatchAlways` parameter, and a union — the
    /// shapes a vendor program (the MDT Push Button Lite) uses.
    fn vendor_shaped_product() -> ProductData {
        let old = r#"<Parameters>
          <Parameter Id="M-00FA_A-0306-02-0000_P-1" Name="Mode" ParameterType="M-00FA_A-0306-02-0000_PT-1" Text="Mode" Value="0">
            <Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="2" BitOffset="0" />
          </Parameter>
        </Parameters>"#;
        let new = r#"<ParameterTypes>
          <ParameterType Id="M-00FA_A-0306-02-0000_PT-1" Name="N8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
          <ParameterType Id="M-00FA_A-0306-02-0000_PT-2" Name="E4"><TypeRestriction Base="Value" SizeInBit="4"><Enumeration Text="Off" Value="0" Id="M-00FA_A-0306-02-0000_PT-2_EN-0" /></TypeRestriction></ParameterType>
        </ParameterTypes>
        <Parameters>
          <Parameter Id="M-00FA_A-0306-02-0000_P-1" Name="Mode" ParameterType="M-00FA_A-0306-02-0000_PT-1" Text="Mode" Value="0" LegacyPatchAlways="true">
            <Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="2" BitOffset="0" />
          </Parameter>
          <Union SizeInBit="16">
            <Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="0" BitOffset="4" />
            <Parameter Id="M-00FA_A-0306-02-0000_P-2" Name="UnionA" ParameterType="M-00FA_A-0306-02-0000_PT-2" Text="A" Value="0" Offset="0" BitOffset="0" DefaultUnionParameter="true" />
            <Parameter Id="M-00FA_A-0306-02-0000_P-3" Name="UnionB" ParameterType="M-00FA_A-0306-02-0000_PT-2" Text="B" Value="0" Offset="1" BitOffset="6" />
          </Union>
        </Parameters>"#;
        let xml = SYSTEM7_MTXML.replace(old, new);
        assert_ne!(xml, SYSTEM7_MTXML, "the Parameters block must have matched");
        ProductData::from_mtxml_str(&xml).expect("the vendor-shaped fixture parses")
    }

    #[test]
    fn only_numeric_parameter_types_follow_the_byte_order() {
        let xml = SYSTEM7_MTXML.replacen(
            "<Parameters>",
            r#"<ParameterTypes>
          <ParameterType Id="M-00FA_A-0306-02-0000_PT-1" Name="N8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
          <ParameterType Id="M-00FA_A-0306-02-0000_PT-9" Name="T3"><TypeText SizeInBit="24" /></ParameterType>
        </ParameterTypes>
        <Parameters>"#,
            1,
        );
        let xml = xml.replacen(
            "</Parameters>",
            r#"<Parameter Id="M-00FA_A-0306-02-0000_P-9" Name="Label" ParameterType="M-00FA_A-0306-02-0000_PT-9" Text="Label" Value="ABC"><Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4000" Offset="8" BitOffset="0" /></Parameter></Parameters>"#,
            1,
        );
        let product = ProductData::from_mtxml_str(&xml).expect("text fixture parses");
        let label = product.parameters.iter().find(|l| l.id.ends_with("_P-9")).expect("text parameter");
        assert_eq!(label.size_bits, 24);
        assert!(!label.byte_ordered, "text keeps its byte sequence under any byte order");
        assert!(
            product.parameters.iter().filter(|l| !l.id.ends_with("_P-9")).all(|l| l.byte_ordered),
            "numeric parameters follow the byte order"
        );
    }

    #[test]
    fn resolves_type_widths_and_legacy_patch_always() {
        let p = vendor_shaped_product();
        let mode = p.parameters.iter().find(|l| l.id.ends_with("_P-1")).expect("P-1");
        assert_eq!(mode.size_bits, 8);
        assert!(mode.legacy_patch_always, "the attribute must survive extraction");
    }

    #[test]
    fn extracts_union_members_with_normalized_offsets() {
        let p = vendor_shaped_product();

        // Union base: offset 0, bit 4. Member A adds nothing on top:
        // it stays in byte 0 at bit 4.
        let a = p.parameters.iter().find(|l| l.id.ends_with("_P-2")).expect("P-2");
        assert_eq!((a.offset, a.bit_offset, a.size_bits), (0, 4, 4));
        assert!(a.seeds_default);

        // Member B adds byte 1 and bit 6: 4 + 6 = 10 bits carries one
        // byte, so it lands in byte 2 at bit 2.
        let b = p.parameters.iter().find(|l| l.id.ends_with("_P-3")).expect("P-3");
        assert_eq!((b.offset, b.bit_offset, b.size_bits), (2, 2, 4));
        assert!(!b.seeds_default);
    }

    #[test]
    fn mask_version_parses_from_the_mtxml_spelling() {
        assert_eq!(parse_mask_version("MV-0705"), Some(MaskVersion::System7Tp1));
        assert_eq!(parse_mask_version("MV-07B0"), Some(MaskVersion::SystemBTp1));
        // Masks with a variant suffix keep the mask itself.
        assert_eq!(parse_mask_version("MV-0300-01000000000000000000"), Some(MaskVersion::from(0x0300)));
        assert_eq!(parse_mask_version("nonsense"), None);
    }
}
