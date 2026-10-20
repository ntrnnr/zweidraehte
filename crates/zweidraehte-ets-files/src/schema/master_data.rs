//! KNX Master Data Parser
//!
//! Parses the knx_master.xml file to extract mask version definitions,
//! resource locations, and table configurations. This information is
//! essential for properly generating memory layouts and table structures
//! based on the device's mask version.
//!
//! # Overview
//!
//! Different KNX mask versions (e.g., MV-0705 for System 7.5, MV-07B0 for System B)
//! define different memory addressing schemes:
//!
//! - **StandardMemory**: Fixed absolute addresses (older BCU systems)
//! - **SystemProperty / Property**: Properties addressed by object index or type
//! - **RelativeMemory**: Dynamic allocation via load state machines (System B)
//! - **LcFilterMemory / LcSlaveMemory**: Coupler-specific memory banks
//!
//! # Example
//!
//! ```rust,ignore
//! use zweidraehte_ets_files::MasterData;
//!
//! let master = MasterData::from_file("knx_master.xml")?;
//! let mv = master.get_mask_version("MV-07B0")?;
//!
//! // Select the exact address-table realization needed by the caller.
//! if let Some(resource) = mv.resources().iter().find(|resource| resource.name == "GroupAddressTable") {
//!     match resource.location.as_ref().map(Location::to_address_space).transpose()? {
//!         Some(AddressSpaceLocation::RelativeMemory { interface_object_ref, property_id, .. }) => {
//!             // System B: table is loaded dynamically
//!         }
//!         Some(AddressSpaceLocation::StandardMemory { start_address }) => {
//!             // System 7.x: table is at fixed address
//!         }
//!         _ => {}
//!     }
//! }
//! ```

use serde::Deserialize;
use std::path::Path;
use std::str::FromStr;

use crate::schema::LoadControl;

#[derive(Debug, thiserror::Error)]
pub enum MasterDataError {
    #[error("cannot read ETS master data from {path}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse ETS master data")]
    Xml(#[source] quick_xml::DeError),

    #[cfg(feature = "master-data-download")]
    #[error("cannot download ETS master data")]
    Http(#[from] reqwest::Error),

    #[error("master-data download support is disabled")]
    DownloadDisabled,

    #[error("Master Data has no unambiguous project-schema namespace ({namespace:?})")]
    MissingSchema { namespace: Option<String> },

    #[error("requested project-{expected} Master Data, but the resolver supplied project-{actual}")]
    SchemaMismatch { expected: u16, actual: u16 },

    #[error("Master Data version {version:?} is not a decimal table version")]
    InvalidTableVersion { version: String },

    #[error("package Master Data uses project-{package}, newer than the installation's project-{installation}")]
    NewerPackageSchema { package: u16, installation: u16 },
}

/// A malformed or unsupported resource location from Master Data.
///
/// `ResourceLocation_t` makes its payload attributes optional because their
/// required combination depends on `AddressSpace`. Resolving a location is
/// therefore the point where an incomplete combination must fail. Inventing a
/// zero address here can turn malformed metadata into writes to device memory.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LocationError {
    #[error("address space `{address_space}` requires `{field}`")]
    MissingField { address_space: String, field: &'static str },

    #[error("unknown resource address space `{0}`")]
    UnknownAddressSpace(String),
}

/// Root element of the KNX XML file (wraps MasterData).
#[derive(Debug, Clone, Deserialize)]
pub struct KnxRoot {
    /// The project-schema namespace identifies which version of Master Data
    /// this document implements. Keep it at the parsing boundary so callers
    /// never have to infer a version from file names or XML contents.
    #[serde(rename = "@xmlns", default)]
    pub xmlns: String,

    #[serde(rename = "MasterData")]
    pub master_data: MasterDataElement,
}

/// MasterData element containing mask versions.
#[derive(Debug, Clone, Deserialize)]
pub struct MasterDataElement {
    /// Stable document ID in current schemas. Project-11 master data predates
    /// the attribute, so an empty value represents its absence there.
    #[serde(rename = "@Id", default)]
    pub id: String,

    #[serde(rename = "@Version")]
    pub version: String,

    #[serde(rename = "MaskVersions")]
    pub mask_versions: Option<MaskVersions>,

    #[serde(rename = "InterfaceObjectProperties", default)]
    pub interface_object_properties: Option<InterfaceObjectProperties>,

    #[serde(rename = "PropertyDataTypes", default)]
    pub property_data_types: Option<PropertyDataTypes>,

    #[serde(rename = "DatapointTypes", default)]
    datapoint_types: Option<DatapointTypes>,

    /// KNX's global manufacturer directory. Product files refer to entries by
    /// stable IDs such as `M-0083`; the human-readable name belongs here, not
    /// in an individual vendor's `Catalog.xml`.
    #[serde(rename = "Manufacturers", default)]
    manufacturers: Option<Manufacturers>,
}

/// Convenience wrapper for working with KNX master data.
pub struct MasterData {
    root: KnxRoot,
    source_xml: std::sync::Arc<str>,
}

impl std::fmt::Debug for MasterData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MasterData")
            .field("schema_version", &self.schema_version())
            .field("document_version", &self.document_version())
            .finish_non_exhaustive()
    }
}

impl FromStr for MasterData {
    type Err = MasterDataError;

    fn from_str(xml: &str) -> Result<Self, Self::Err> {
        let root: KnxRoot = quick_xml::de::from_str(xml).map_err(MasterDataError::Xml)?;
        Ok(Self { root, source_xml: xml.into() })
    }
}

impl MasterData {
    /// Exact document bytes, retained for provenance and immutable association.
    pub fn source_xml(&self) -> &str {
        &self.source_xml
    }

    /// Parse master data from an XML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, MasterDataError> {
        let path = path.as_ref();
        let content = crate::master_data::read_xml(path)?;
        content.parse()
    }

    /// Raw project-schema namespace declared by the Master Data document.
    ///
    /// Converted legacy documents may omit it. Callers selecting a versioned
    /// commissioning profile must treat an empty namespace as ambiguous rather
    /// than silently assuming the newest or default schema.
    pub fn namespace(&self) -> Option<&str> {
        (!self.root.xmlns.is_empty()).then_some(self.root.xmlns.as_str())
    }

    /// Project-schema version parsed from the document namespace.
    pub fn schema_version(&self) -> Option<u16> {
        super::schema_version_from_namespace(self.namespace()?)
    }

    /// Stable ID carried by the `MasterData` element, when present.
    pub fn document_id(&self) -> Option<&str> {
        (!self.root.master_data.id.is_empty()).then_some(self.root.master_data.id.as_str())
    }

    /// Publication version carried by the `MasterData` element.
    pub fn document_version(&self) -> &str {
        &self.root.master_data.version
    }

    /// Get the raw mask versions container.
    pub fn mask_versions(&self) -> Option<&MaskVersions> {
        self.root.master_data.mask_versions.as_ref()
    }

    /// Get a mask version by its ID (e.g., "MV-07B0").
    pub fn get_mask_version(&self, id: &str) -> Option<&MaskVersion> {
        self.mask_versions().and_then(|mv| mv.versions.iter().find(|v| v.id == id))
    }

    /// Get the single mask version with this numeric DD0 code.
    ///
    /// DD0 is not a unique mask identity. In particular, current Master Data
    /// contains several System 300 definitions with code `0300h`, distinguished
    /// by `MgmtDescriptor01`. Returning `None` for an ambiguous code prevents a
    /// caller from accidentally selecting whichever XML element happens to be
    /// first.
    pub fn get_mask_version_by_code(&self, code: u16) -> Option<&MaskVersion> {
        let mut matches = self.get_mask_versions_by_code(code);
        let mask = matches.next()?;

        matches.next().is_none().then_some(mask)
    }

    /// Iterate over every exact mask definition carrying this DD0 code.
    pub fn get_mask_versions_by_code(&self, code: u16) -> impl Iterator<Item = &MaskVersion> {
        self.mask_versions()
            .into_iter()
            .flat_map(|versions| &versions.versions)
            .filter(move |mask| mask.mask_version_code == code)
    }

    /// Resolve an exact mask identity from DD0 and Management Descriptor 01.
    ///
    /// KNX Resources 03/05/01, PID 72 defines the ten-byte management
    /// descriptor used to distinguish masks that share DD0.
    pub fn get_mask_version_by_descriptor(
        &self,
        code: u16,
        management_descriptor_01: Option<&[u8; 10]>,
    ) -> Option<&MaskVersion> {
        self.get_mask_versions_by_code(code)
            .find(|mask| mask.management_descriptor_01.as_ref() == management_descriptor_01)
    }

    /// Get total number of mask versions.
    pub fn mask_version_count(&self) -> usize {
        self.mask_versions().map(|mv| mv.versions.len()).unwrap_or(0)
    }

    /// Resolve a stable KNX manufacturer ID to its current display name.
    pub fn manufacturer_name(&self, id: &str) -> Option<&str> {
        self.root
            .master_data
            .manufacturers
            .as_ref()
            .map(|manufacturers| manufacturers.manufacturers.as_slice())
            .unwrap_or_default()
            .iter()
            .find(|manufacturer| manufacturer.id == id)
            .map(|manufacturer| manufacturer.name.trim())
            .filter(|name| !name.is_empty())
    }

    /// Fixed wire width of a property data type declared by master data.
    /// Variable-length PDTs intentionally return `None`.
    pub fn property_data_type_size(&self, token: &str) -> Option<u32> {
        self.property_data_type(token)?.size
    }

    /// Property data type definitions in source order, including their XML
    /// identifiers, declaration names and optional wire numbers.
    ///
    /// A descriptor declaration uses a name such as `PDT_GENERIC_06`, whereas
    /// global property metadata can refer to its identifier `PDT-22`.
    pub fn property_data_types(&self) -> &[PropertyDataType] {
        self.root.master_data.property_data_types.as_ref().map_or(&[], |types| types.types.as_slice())
    }

    /// Fixed wire width returned when reading a property data type.
    ///
    /// `PDT_CONTROL` is the notable asymmetric case: its write record is ten
    /// bytes while its read status is one byte. An absent `ReadSize` uses the
    /// ordinary element size.
    pub fn property_data_type_read_size(&self, token: &str) -> Option<u32> {
        let data_type = self.property_data_type(token)?;

        data_type.read_size.or(data_type.size)
    }

    /// Master Data token of the PDT a device reports by number, for example in
    /// a property description. Numbers without a declaration return `None`.
    pub fn property_data_type_token(&self, number: u16) -> Option<&str> {
        let types = &self.root.master_data.property_data_types.as_ref()?.types;
        let mut matches = types.iter().filter(|data_type| data_type.number == Some(number));
        let selected = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(selected.id.as_str())
    }

    /// PDT declared by the parent of a datapoint type or subtype.
    pub fn datapoint_type_property_data_type(&self, token: &str) -> Option<&str> {
        let types = &self.root.master_data.datapoint_types.as_ref()?.types;
        let mut matches = types.iter().filter(|data_type| {
            data_type.id == token
                || data_type
                    .subtypes
                    .as_ref()
                    .is_some_and(|subtypes| subtypes.types.iter().any(|subtype| subtype.id == token))
        });
        let selected = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        selected.property_data_type.as_deref()
    }

    /// Global interface-object property definitions in source order.
    pub fn interface_object_properties(&self) -> &[MasterInterfaceObjectProperty] {
        self.root
            .master_data
            .interface_object_properties
            .as_ref()
            .map(|properties| properties.properties.as_slice())
            .unwrap_or_default()
    }

    fn property_data_type(&self, token: &str) -> Option<&PropertyDataType> {
        self.root
            .master_data
            .property_data_types
            .as_ref()?
            .types
            .iter()
            .find(|data_type| data_type.id == token || data_type.name == token)
    }
}

/// Global manufacturer catalogue bundled with Master Data.
#[derive(Debug, Clone, Default, Deserialize)]
struct Manufacturers {
    #[serde(rename = "Manufacturer", default)]
    manufacturers: Vec<MasterManufacturer>,
}

/// Stable manufacturer identity and its human-readable catalogue name.
///
/// Master Data carries considerably more manufacturer-owned material below
/// this element. It is intentionally omitted here: resolving catalogue labels
/// needs only these required attributes, and Serde ignores the unrelated
/// nested tables.
#[derive(Debug, Clone, Deserialize)]
struct MasterManufacturer {
    #[serde(rename = "@Id")]
    id: String,

    #[serde(rename = "@Name")]
    name: String,
}

/// Global standard property catalogue.
///
/// A missing `ObjectType` denotes a property common to every interface
/// object. Symbolic PDT/DPT and object-type references remain raw strings so
/// newer Master Data revisions stay diagnosable instead of being guessed.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct InterfaceObjectProperties {
    #[serde(rename = "InterfaceObjectProperty", default)]
    pub properties: Vec<MasterInterfaceObjectProperty>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MasterInterfaceObjectProperty {
    #[serde(rename = "@Id")]
    pub id: String,

    #[serde(rename = "@Number")]
    pub number: u16,

    #[serde(rename = "@ObjectType", default)]
    pub object_type: Option<String>,

    #[serde(rename = "@Name")]
    pub name: String,

    #[serde(rename = "@Text", default)]
    pub text: Option<String>,

    #[serde(rename = "@PDT", default)]
    pub property_data_types: Option<String>,

    #[serde(rename = "@DPT", default)]
    pub datapoint_type: Option<String>,

    #[serde(rename = "@Array", default)]
    pub array: Option<bool>,

    #[serde(rename = "@AccessPolicy", default)]
    pub access_policy: Option<String>,
}

/// Property data type catalogue bundled with `knx_master.xml`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PropertyDataTypes {
    #[serde(rename = "PropertyDataType", default)]
    pub types: Vec<PropertyDataType>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PropertyDataType {
    #[serde(rename = "@Id", default)]
    pub id: String,

    #[serde(rename = "@Number", default)]
    pub number: Option<u16>,

    #[serde(rename = "@Name")]
    pub name: String,

    #[serde(rename = "@Size", default)]
    pub size: Option<u32>,

    #[serde(rename = "@ReadSize", default)]
    pub read_size: Option<u32>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DatapointTypes {
    #[serde(rename = "DatapointType", default)]
    types: Vec<DatapointType>,
}

#[derive(Debug, Clone, Deserialize)]
struct DatapointType {
    #[serde(rename = "@Id", default)]
    id: String,
    #[serde(rename = "@PDT", default)]
    property_data_type: Option<String>,
    #[serde(rename = "DatapointSubtypes", default)]
    subtypes: Option<DatapointSubtypes>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DatapointSubtypes {
    #[serde(rename = "DatapointSubtype", default)]
    types: Vec<DatapointSubtype>,
}

#[derive(Debug, Clone, Deserialize)]
struct DatapointSubtype {
    #[serde(rename = "@Id", default)]
    id: String,
}

/// Container for mask version definitions.
#[derive(Debug, Clone, Deserialize)]
pub struct MaskVersions {
    #[serde(rename = "MaskVersion", default)]
    pub versions: Vec<MaskVersion>,
}

/// A KNX mask version definition.
///
/// Each mask version defines the capabilities and memory layout of a
/// particular device family.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MaskVersion {
    /// Mask version ID (e.g., "MV-07B0")
    #[serde(rename = "@Id")]
    pub id: String,

    /// Numeric mask version code (e.g., 1968 = 0x07B0)
    #[serde(rename = "@MaskVersion")]
    pub mask_version_code: u16,

    /// Human-readable name (e.g., "System B")
    #[serde(rename = "@Name")]
    pub name: String,

    /// Management model identifier (e.g., "SystemB", "BimM112")
    #[serde(rename = "@ManagementModel")]
    pub management_model: String,

    /// Optional ten-byte value returned by Device Object PID 72.
    #[serde(rename = "@MgmtDescriptor01", default, deserialize_with = "deserialize_management_descriptor")]
    pub management_descriptor_01: Option<[u8; 10]>,

    /// Medium type reference ID
    #[serde(rename = "@MediumTypeRefId", default)]
    pub medium_type_ref_id: Option<String>,

    /// A second medium used by coupler masks.
    #[serde(rename = "@OtherMediumTypeRefId", default)]
    pub other_medium_type_ref_id: Option<String>,

    /// Programming configuration containing features and resources.
    /// Some mask versions have multiple configuration elements.
    #[serde(rename = "HawkConfigurationData", default)]
    pub hawk_configs: Vec<HawkConfigurationData>,

    /// The older masks whose application programs this mask runs
    /// (MV-0020 lists MV-0010/0011/0012: a BCU2 executes BCU1
    /// programs in its compat mode). ETS accepts a product for any
    /// mask listed here and then programs the device per *its own*
    /// mask — see `VerifyCompatibleMaskVersionTask` ("Match
    /// compatible") in an ETS download trace.
    #[serde(rename = "DownwardCompatibleMasks", default)]
    downward_compatible_masks: Option<DownwardCompatibleMasks>,

    /// The mask's OS entry points — the routine addresses a program's
    /// `FixupList` patches into its code segments. Per mask: the same
    /// routine lives at 0D6Ch on MV-0012 and 5063h on MV-0020, which
    /// is the whole reason fixups exist.
    #[serde(rename = "MaskEntries", default)]
    mask_entries: Option<MaskEntries>,
}

fn deserialize_management_descriptor<'de, D>(deserializer: D) -> Result<Option<[u8; 10]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let Some(encoded) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };

    if encoded.len() != 20 {
        return Err(D::Error::custom(format!(
            "MgmtDescriptor01 must contain exactly 10 bytes, got {} hexadecimal digits",
            encoded.len()
        )));
    }

    let mut descriptor = [0_u8; 10];

    for (index, byte) in descriptor.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&encoded[start..start + 2], 16)
            .map_err(|_| D::Error::custom("MgmtDescriptor01 contains non-hexadecimal data"))?;
    }

    Ok(Some(descriptor))
}

/// Container for the mask's OS entry points.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MaskEntries {
    #[serde(rename = "MaskEntry", default)]
    pub entries: Vec<MaskEntry>,
}

/// One `<MaskEntry Id="MV-0012_ME-U.5Fdeb30" Name="U_deb30"
/// Address="3183" />`.
#[derive(Debug, Clone, Deserialize)]
pub struct MaskEntry {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Address")]
    pub address: u32,
}

/// Container for the downward-compatible mask references.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DownwardCompatibleMasks {
    #[serde(rename = "DownwardCompatibleMask", default)]
    pub masks: Vec<DownwardCompatibleMask>,
}

/// One `<DownwardCompatibleMask RefId="MV-0012" />` reference.
#[derive(Debug, Clone, Deserialize)]
pub struct DownwardCompatibleMask {
    #[serde(rename = "@RefId")]
    pub ref_id: String,
}

impl MaskVersion {
    /// The mask codes this mask is downward compatible with — whose
    /// application programs it runs (empty for most masks).
    ///
    /// The ref ids are `MV-xxxx` with the code in hex; a ref this
    /// cannot be read out of is skipped rather than failing the whole
    /// mask.
    pub fn downward_compatible_masks(&self) -> impl Iterator<Item = u16> + '_ {
        self.downward_compatible_masks
            .iter()
            .flat_map(|dcm| &dcm.masks)
            .filter_map(|mask| mask.ref_id.strip_prefix("MV-"))
            .filter_map(|hex| u16::from_str_radix(hex, 16).ok())
    }

    /// Whether a program written for mask `code` runs on this mask —
    /// the identical mask, or one this mask lists as downward
    /// compatible.
    pub fn is_downward_compatible_with(&self, code: u16) -> bool {
        self.mask_version_code == code || self.downward_compatible_masks().any(|mask| mask == code)
    }

    /// The address of a mask OS entry point, looked up by the
    /// `_ME-…` id suffix a program's `Fixup/@FunctionRef` carries.
    ///
    /// Matched by suffix, never by the full id: the reference embeds
    /// the *product's* mask (`MV-0012_ME-U.5Fdeb30`) while every
    /// mask's own entry carries its own prefix — and the point of the
    /// lookup is resolving a BCU1 program's routine names against the
    /// BCU2 that actually executes them.
    pub fn mask_entry_address(&self, me_suffix: &str) -> Option<u32> {
        self.mask_entries
            .iter()
            .flat_map(|me| &me.entries)
            .find(|entry| entry.id.rsplit_once("_ME-").map(|(_, suffix)| suffix) == Some(me_suffix))
            .map(|entry| entry.address)
    }

    /// Check if this is a System B mask version.
    pub fn is_system_b(&self) -> bool {
        self.management_model == "SystemB"
    }

    /// Check whether this mask uses the System 7 management model.
    pub fn is_system7(&self) -> bool {
        self.management_model == "BimM112"
    }

    /// Get the current (`LegacyVersion` zero) configuration.
    ///
    /// XML order is not a version selector: `MV-091A` deliberately places its
    /// legacy configuration first. An absent `LegacyVersion` is version zero,
    /// as defined by the Master Data schema's current configuration convention.
    pub fn hawk_config(&self) -> Option<&HawkConfigurationData> {
        self.hawk_config_for_legacy_version(0)
    }

    /// Get the configuration explicitly selected by its legacy version.
    pub fn hawk_config_for_legacy_version(&self, legacy_version: i32) -> Option<&HawkConfigurationData> {
        self.hawk_configs.iter().find(|config| config.legacy_version.unwrap_or(0) == legacy_version)
    }

    /// Get a feature value by name.
    pub fn get_feature(&self, name: &str) -> Option<&str> {
        self.hawk_config().and_then(|hc| {
            hc.features
                .as_ref()
                .and_then(|f| f.features.iter().find(|feat| feat.name == name))
                .map(|f| f.value.as_str())
        })
    }

    /// Get the declared first application object index.
    ///
    /// Absence is meaningful for profiles that discover objects differently;
    /// callers must not manufacture the historical value `5`.
    pub fn first_app_object_idx(&self) -> Option<u8> {
        self.get_feature("FirstAppObjectIdx").and_then(|value| value.parse().ok())
    }

    /// Every resource declaration in the current mask configuration block.
    ///
    /// Resource names are not unique. BCU2 masks, for example, declare table
    /// pointers once for simple memory management and again for load-state
    /// management. Callers selecting a resource must therefore also inspect
    /// its management style and location.
    pub fn resources(&self) -> &[Resource] {
        self.hawk_config()
            .and_then(|hc| hc.resources.as_ref())
            .map(|resources| resources.resources.as_slice())
            .unwrap_or_default()
    }

    /// All programming procedures of this mask (empty slice when the
    /// master data carries none).
    pub fn procedures(&self) -> &[Procedure] {
        self.hawk_config().and_then(|hc| hc.procedures.as_ref()).map(|p| p.procedures.as_slice()).unwrap_or_default()
    }

    /// PDT name for an indexed interface-object property.
    pub fn indexed_property_data_type(&self, object_index: u8, property_id: u16) -> Option<&str> {
        self.hawk_config()?
            .interface_objects
            .as_ref()?
            .objects
            .iter()
            .find(|object| object.index == Some(object_index))?
            .properties
            .iter()
            .find(|property| property.property_id == property_id)
            .map(|property| property.property_data_type.as_str())
    }

    /// PDT name for an extended object-type-addressed property.
    pub fn typed_property_data_type(&self, object_type: u16, property_id: u16) -> Option<&str> {
        self.hawk_config()?
            .interface_objects
            .as_ref()?
            .objects
            .iter()
            .find(|object| object.object_type == Some(object_type))?
            .properties
            .iter()
            .find(|property| property.property_id == property_id)
            .map(|property| property.property_data_type.as_str())
    }

    /// Find a procedure by type (`"Load"` / `"Unload"`) and subtype
    /// (`"all"`, `"grp"`, …), preferring one a remote client may run.
    pub fn find_procedure(&self, procedure_type: &str, sub_type: &str) -> Option<&Procedure> {
        let matches =
            |p: &&Procedure| p.procedure_type == procedure_type && p.procedure_sub_type.as_deref() == Some(sub_type);
        // Should a mask ever list the same procedure twice with
        // different Access scopes, prefer the remote-capable one —
        // we are always the bus-side client.
        self.procedures()
            .iter()
            .find(|p| matches(p) && p.allows_remote())
            .or_else(|| self.procedures().iter().find(matches))
    }
}

/// Programming configuration data for a mask version.
///
/// Note: We only deserialize this, not serialize. Serialization derives are kept for
/// consistency but some fields are skipped during serialization.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HawkConfigurationData {
    /// Optional identifier of a system plug-in required by this profile.
    #[serde(rename = "@Ets3SystemPlugin", default)]
    pub ets3_system_plugin: Option<String>,

    /// Zero (represented by an absent attribute) selects the current
    /// configuration; positive values select explicitly supported legacy data.
    #[serde(rename = "@LegacyVersion", default)]
    pub legacy_version: Option<i32>,

    #[serde(rename = "Features", default)]
    pub features: Option<Features>,

    #[serde(rename = "Resources", default)]
    pub resources: Option<Resources>,

    /// The per-mask programming procedure templates (`LdCtrl*`
    /// instruction streams). System B masks carry complete generic
    /// Load procedures (with `LdCtrlMerge` splice points for the
    /// product's MTXML fragments); System 7 masks carry
    /// only `Unload all` — their Load procedures are entirely
    /// product-specific.
    #[serde(rename = "Procedures", default)]
    pub procedures: Option<Procedures>,

    #[serde(rename = "InterfaceObjects", default)]
    pub interface_objects: Option<InterfaceObjects>,

    #[serde(rename = "MemorySegments", default)]
    pub memory_segments: Option<MemorySegments>,
}

/// Physical memory regions exposed by one exact mask configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MemorySegments {
    #[serde(rename = "MemorySegment", default)]
    pub segments: Vec<MemorySegment>,
}

/// A memory region declared by KNX Master Data.
#[derive(Debug, Clone, Deserialize)]
pub struct MemorySegment {
    #[serde(rename = "@Length")]
    pub length: u32,

    /// Keep absence distinct from `false`; schema defaults belong in semantic
    /// resolution, not the lossless XML representation.
    #[serde(rename = "@Optional", default)]
    pub optional: Option<bool>,

    #[serde(rename = "@MemoryType", default)]
    pub memory_type: Option<String>,

    #[serde(rename = "Location")]
    pub location: Location,

    #[serde(rename = "AccessRights")]
    pub access_rights: AccessRights,
}

/// Interface-object property metadata for one mask. This is what gives a
/// load procedure's raw `InlineData` its actual per-element wire width.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct InterfaceObjects {
    #[serde(rename = "InterfaceObject", default)]
    pub objects: Vec<InterfaceObject>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InterfaceObject {
    #[serde(rename = "@Index", default)]
    pub index: Option<u8>,
    #[serde(rename = "@ObjectType", default)]
    pub object_type: Option<u16>,
    #[serde(rename = "Property", default)]
    pub properties: Vec<InterfaceObjectProperty>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InterfaceObjectProperty {
    #[serde(rename = "@PropertyID")]
    pub property_id: u16,
    #[serde(rename = "@PropertyDataType")]
    pub property_data_type: String,
}

/// Container for the programming procedures of a mask version.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Procedures {
    #[serde(rename = "Procedure", default)]
    pub procedures: Vec<Procedure>,
}

/// One access path token from `ResourceAccess_t`.
///
/// Unknown values are retained so a newer Master Data file remains
/// diagnosable. Profile resolution must reject an unknown token before using
/// the affected resource or procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceAccess {
    Remote,
    Local1,
    Local2,
    Unknown(String),
}

impl ResourceAccess {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Remote => "remote",
            Self::Local1 => "local1",
            Self::Local2 => "local2",
            Self::Unknown(value) => value,
        }
    }
}

impl From<&str> for ResourceAccess {
    fn from(value: &str) -> Self {
        match value {
            "remote" => Self::Remote,
            "local1" => Self::Local1,
            "local2" => Self::Local2,
            value => Self::Unknown(value.to_owned()),
        }
    }
}

/// Ordered set of access tokens carried by one XML attribute.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceAccessSet {
    entries: Vec<ResourceAccess>,
}

impl ResourceAccessSet {
    pub fn iter(&self) -> impl Iterator<Item = &ResourceAccess> {
        self.entries.iter()
    }

    pub fn contains(&self, access: &ResourceAccess) -> bool {
        self.entries.contains(access)
    }

    pub fn contains_name(&self, access: &str) -> bool {
        self.entries.iter().any(|candidate| candidate.as_str() == access)
    }

    pub fn unknown(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().filter_map(|entry| match entry {
            ResourceAccess::Unknown(value) => Some(value.as_str()),
            _ => None,
        })
    }
}

impl<'de> Deserialize<'de> for ResourceAccessSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let entries = value.split_whitespace().map(ResourceAccess::from).collect();

        Ok(Self { entries })
    }
}

/// One management-style token from `ResourceMgmtStyle_t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceManagementStyle {
    Simple,
    LoadStateMachine,
    Unknown(String),
}

impl ResourceManagementStyle {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Simple => "simple",
            Self::LoadStateMachine => "lsm",
            Self::Unknown(value) => value,
        }
    }
}

impl From<&str> for ResourceManagementStyle {
    fn from(value: &str) -> Self {
        match value {
            "simple" => Self::Simple,
            "lsm" => Self::LoadStateMachine,
            value => Self::Unknown(value.to_owned()),
        }
    }
}

/// Ordered set of management-style tokens carried by one XML attribute.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceManagementStyleSet {
    entries: Vec<ResourceManagementStyle>,
}

impl ResourceManagementStyleSet {
    pub fn iter(&self) -> impl Iterator<Item = &ResourceManagementStyle> {
        self.entries.iter()
    }

    pub fn contains(&self, style: &ResourceManagementStyle) -> bool {
        self.entries.contains(style)
    }

    pub fn contains_name(&self, style: &str) -> bool {
        self.entries.iter().any(|candidate| candidate.as_str() == style)
    }

    pub fn unknown(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().filter_map(|entry| match entry {
            ResourceManagementStyle::Unknown(value) => Some(value.as_str()),
            _ => None,
        })
    }
}

impl<'de> Deserialize<'de> for ResourceManagementStyleSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let entries = value.split_whitespace().map(ResourceManagementStyle::from).collect();

        Ok(Self { entries })
    }
}

/// One programming procedure: a typed stream of `LdCtrl*`
/// instructions, reusing the MTXML [`LoadControl`] vocabulary from
/// [`crate::schema`] (master data uses the same element language
/// plus the tool-side-only superset).
#[derive(Debug, Clone, Deserialize)]
pub struct Procedure {
    /// `"Load"` or `"Unload"`.
    #[serde(rename = "@ProcedureType")]
    pub procedure_type: String,

    /// What the procedure covers: `"all"`, `"grp"` (group addresses +
    /// associations), `"par"` (parameters), `"par,grp"`, `"cfg"`, or
    /// `"ap1"` (application 1 only).
    #[serde(rename = "@ProcedureSubType", default)]
    pub procedure_sub_type: Option<String>,

    /// Where the procedure may run from (e.g. `"remote local1
    /// local2"`); `remote` is the bus-client path.
    #[serde(rename = "@Access", default)]
    pub access: Option<ResourceAccessSet>,

    #[serde(rename = "$value", default)]
    pub controls: Vec<LoadControl>,
}

impl Procedure {
    pub fn is_load(&self) -> bool {
        self.procedure_type == "Load"
    }

    pub fn is_unload(&self) -> bool {
        self.procedure_type == "Unload"
    }

    /// Whether a remote management client (our case: the bus-side
    /// tool) may run this procedure. Procedures without an `Access`
    /// attribute carry no restriction.
    pub fn allows_remote(&self) -> bool {
        self.access.as_ref().is_none_or(|access| access.contains(&ResourceAccess::Remote))
    }
}

/// Container for feature definitions.
#[derive(Debug, Clone, Deserialize)]
pub struct Features {
    #[serde(rename = "Feature", default)]
    pub features: Vec<Feature>,
}

/// A feature definition.
#[derive(Debug, Clone, Deserialize)]
pub struct Feature {
    #[serde(rename = "@Name")]
    pub name: String,

    #[serde(rename = "@Value")]
    pub value: String,
}

/// Container for resource definitions.
#[derive(Debug, Clone, Deserialize)]
pub struct Resources {
    #[serde(rename = "Resource", default)]
    pub resources: Vec<Resource>,
}

/// A resource definition specifying how to access a particular memory region.
#[derive(Debug, Clone, Deserialize)]
pub struct Resource {
    /// Resource name (e.g., "GroupAddressTable")
    #[serde(rename = "@Name")]
    pub name: String,

    /// Whether absence of this resource is valid for the selected profile.
    /// Keep the XML absence distinct from an explicit `false`; semantic
    /// defaults are applied only while resolving an executable profile.
    #[serde(rename = "@Optional", default)]
    pub optional: Option<bool>,

    /// Access modes (e.g., "remote local2")
    #[serde(rename = "@Access", default)]
    pub access: Option<ResourceAccessSet>,

    /// Management styles for which this realization applies (`simple`,
    /// `lsm`, or both). An omitted attribute leaves the resource unqualified.
    #[serde(rename = "@MgmtStyle", default)]
    pub management_style: Option<ResourceManagementStyleSet>,

    /// Location specification
    #[serde(rename = "Location")]
    pub location: Option<Location>,

    /// Location of the resource inside the downloadable device image.
    ///
    /// This differs from `Location` when remote access uses an interface
    /// object while the image still contains the corresponding memory byte.
    #[serde(rename = "ImgLocation")]
    pub image_location: Option<Location>,

    /// Resource type specification
    #[serde(rename = "ResourceType")]
    pub resource_type: Option<ResourceType>,

    /// Access rights
    #[serde(rename = "AccessRights")]
    pub access_rights: Option<AccessRights>,
}

impl Resource {
    /// Whether this resource can be used through the named access path.
    pub fn supports_access(&self, access: &str) -> bool {
        self.access.as_ref().is_none_or(|accesses| accesses.contains_name(access))
    }

    /// Whether this realization applies to `style`.
    ///
    /// `MgmtStyle` is optional in the schema; an unqualified resource applies
    /// independently of the selected management style.
    pub fn supports_management_style(&self, style: &str) -> bool {
        self.management_style.as_ref().is_none_or(|styles| styles.contains_name(style))
    }

    /// Whether this realization explicitly names `style`.
    pub fn declares_management_style(&self, style: &str) -> bool {
        self.management_style.as_ref().is_some_and(|styles| styles.contains_name(style))
    }

    /// Check if this resource uses relative memory (System B style).
    pub fn is_relative_memory(&self) -> bool {
        self.location.as_ref().map(|l| l.address_space == "RelativeMemory").unwrap_or(false)
    }

    /// Check if this resource uses standard memory (fixed address).
    pub fn is_standard_memory(&self) -> bool {
        self.location.as_ref().map(|l| l.address_space == "StandardMemory").unwrap_or(false)
    }

    /// Check if this resource is a system property.
    pub fn is_system_property(&self) -> bool {
        self.location.as_ref().map(|l| l.address_space == "SystemProperty").unwrap_or(false)
    }

    /// Get the interface object reference if applicable.
    pub fn interface_object_ref(&self) -> Option<u16> {
        self.location.as_ref().and_then(|l| l.interface_object_ref)
    }

    /// Get the property ID if applicable.
    pub fn property_id(&self) -> Option<u16> {
        self.location.as_ref().and_then(|l| l.property_id)
    }

    /// Get the start address if applicable.
    pub fn start_address(&self) -> Option<u32> {
        self.location.as_ref().and_then(|l| l.start_address)
    }

    /// Get the downloadable image location's start address.
    pub fn image_start_address(&self) -> Option<u32> {
        self.image_location.as_ref().and_then(|location| location.start_address)
    }

    /// Get the location's address space type.
    pub fn address_space(&self) -> Option<&str> {
        self.location.as_ref().map(|l| l.address_space.as_str())
    }
}

/// Location specification for a resource.
///
/// The meaning of fields depends on the `address_space` type:
/// - StandardMemory: Uses `start_address` as absolute memory address
/// - SystemProperty: Uses an interface-object index + property ID
/// - Property: Uses an object type, occurrence + property ID
/// - RelativeMemory: Uses an interface-object index + allocation property ID
/// - RelativeMemoryByObjectType: Uses an object type + occurrence
/// - Pointer: Uses `ptr_resource` to reference another resource
/// - Constant: Uses `start_address` as constant value
/// - ADC: Uses `start_address` for ADC channel
/// - LcFilterMemory/LcSlaveMemory: Uses a coupler-specific memory address
/// - None: No physical location
#[derive(Debug, Clone, Deserialize)]
pub struct Location {
    /// Address space type
    #[serde(rename = "@AddressSpace")]
    pub address_space: String,

    /// Start address (for StandardMemory, Constant, ADC)
    #[serde(rename = "@StartAddress")]
    pub start_address: Option<u32>,

    /// Interface object reference (for SystemProperty, RelativeMemory)
    #[serde(rename = "@InterfaceObjectRef")]
    pub interface_object_ref: Option<u16>,

    /// Property ID (for SystemProperty, RelativeMemory)
    #[serde(rename = "@PropertyID")]
    pub property_id: Option<u16>,

    /// Occurrence of an object type. Absence must remain distinct from zero:
    /// both forms occur in published programming data and select different
    /// resolution rules.
    #[serde(rename = "@Occurrence", default)]
    pub occurrence: Option<u16>,

    /// Pointer resource name (for Pointer address space)
    #[serde(rename = "@PtrResource")]
    pub ptr_resource: Option<String>,
}

impl Location {
    /// Resolve the raw XML fields into a checked address-space shape.
    pub fn to_address_space(&self) -> Result<AddressSpaceLocation, LocationError> {
        match self.address_space.as_str() {
            "StandardMemory" => Ok(AddressSpaceLocation::StandardMemory {
                start_address: required_location_field(self, self.start_address, "StartAddress")?,
            }),
            "UserMemory" => Ok(AddressSpaceLocation::UserMemory {
                start_address: required_location_field(self, self.start_address, "StartAddress")?,
            }),
            "SystemProperty" => Ok(AddressSpaceLocation::SystemProperty {
                interface_object_ref: required_location_field(self, self.interface_object_ref, "InterfaceObjectRef")?,
                property_id: required_location_field(self, self.property_id, "PropertyID")?,
                start_address: required_location_field(self, self.start_address, "StartAddress")?,
                occurrence: self.occurrence,
            }),
            "AppProperty" => Ok(AddressSpaceLocation::AppProperty {
                interface_object_ref: required_location_field(self, self.interface_object_ref, "InterfaceObjectRef")?,
                property_id: required_location_field(self, self.property_id, "PropertyID")?,
                start_address: required_location_field(self, self.start_address, "StartAddress")?,
                occurrence: self.occurrence,
            }),
            "Property" => Ok(AddressSpaceLocation::Property {
                object_type: required_location_field(self, self.interface_object_ref, "InterfaceObjectRef")?,
                property_id: required_location_field(self, self.property_id, "PropertyID")?,
                start_address: required_location_field(self, self.start_address, "StartAddress")?,
                occurrence: self.occurrence,
            }),
            "RelativeMemory" => Ok(AddressSpaceLocation::RelativeMemory {
                interface_object_ref: required_location_field(self, self.interface_object_ref, "InterfaceObjectRef")?,
                property_id: required_location_field(self, self.property_id, "PropertyID")?,
                start_address: required_location_field(self, self.start_address, "StartAddress")?,
                occurrence: self.occurrence,
            }),
            "RelativeMemoryByObjectType" => Ok(AddressSpaceLocation::RelativeMemoryByObjectType {
                object_type: required_location_field(self, self.interface_object_ref, "InterfaceObjectRef")?,
                property_id: required_location_field(self, self.property_id, "PropertyID")?,
                start_address: required_location_field(self, self.start_address, "StartAddress")?,
                occurrence: self.occurrence,
            }),
            "LcSlaveMemory" => Ok(AddressSpaceLocation::LcSlaveMemory {
                start_address: required_location_field(self, self.start_address, "StartAddress")?,
            }),
            "LcFilterMemory" => Ok(AddressSpaceLocation::LcFilterMemory {
                start_address: required_location_field(self, self.start_address, "StartAddress")?,
            }),
            "LcSlave" => Ok(AddressSpaceLocation::LcSlave {
                start_address: required_location_field(self, self.start_address, "StartAddress")?,
            }),
            "LcFilter" => Ok(AddressSpaceLocation::LcFilter {
                start_address: required_location_field(self, self.start_address, "StartAddress")?,
            }),
            "Constant" => Ok(AddressSpaceLocation::Constant {
                value: required_location_field(self, self.start_address, "StartAddress")?,
            }),
            "Pointer" => Ok(AddressSpaceLocation::Pointer {
                ptr_resource: self.ptr_resource.clone().ok_or_else(|| LocationError::MissingField {
                    address_space: self.address_space.clone(),
                    field: "PtrResource",
                })?,
            }),
            "ADC" => Ok(AddressSpaceLocation::Adc {
                channel: required_location_field(self, self.start_address, "StartAddress")?,
            }),
            "None" => Ok(AddressSpaceLocation::None),
            unknown => Err(LocationError::UnknownAddressSpace(unknown.to_owned())),
        }
    }
}

fn required_location_field<T>(location: &Location, value: Option<T>, field: &'static str) -> Result<T, LocationError> {
    value.ok_or_else(|| LocationError::MissingField { address_space: location.address_space.clone(), field })
}

/// Structured address space location for easier pattern matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressSpaceLocation {
    /// Fixed absolute address in device memory.
    StandardMemory { start_address: u32 },

    /// User-memory service address space.
    UserMemory { start_address: u32 },

    /// System property on an indexed interface object.
    SystemProperty { interface_object_ref: u16, property_id: u16, start_address: u32, occurrence: Option<u16> },

    /// Application property on an indexed interface object.
    AppProperty { interface_object_ref: u16, property_id: u16, start_address: u32, occurrence: Option<u16> },

    /// Property addressed by interface-object type and occurrence.
    Property { object_type: u16, property_id: u16, start_address: u32, occurrence: Option<u16> },

    /// Relative memory allocated by an indexed load state machine.
    RelativeMemory { interface_object_ref: u16, property_id: u16, start_address: u32, occurrence: Option<u16> },

    /// Relative memory allocated by an object-type-addressed load state machine.
    RelativeMemoryByObjectType { object_type: u16, property_id: u16, start_address: u32, occurrence: Option<u16> },

    /// Coupler slave memory bank.
    LcSlaveMemory { start_address: u32 },

    /// Coupler filter memory bank.
    LcFilterMemory { start_address: u32 },

    /// Coupler slave service address space used by load controls.
    LcSlave { start_address: u32 },

    /// Coupler filter service address space used by load controls.
    LcFilter { start_address: u32 },

    /// Constant value (not a memory location).
    Constant { value: u32 },

    /// Indirect via pointer resource.
    Pointer { ptr_resource: String },

    /// ADC channel.
    Adc { channel: u32 },

    /// No physical location.
    None,
}

/// Resource type specification.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceType {
    /// Length in bytes
    #[serde(rename = "@Length")]
    pub length: u32,

    /// Semantic flavour (e.g., "AddressTable_SystemB")
    #[serde(rename = "@Flavour")]
    pub flavour: Option<String>,
}

/// Access rights for a resource.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessRights {
    #[serde(rename = "@Read")]
    pub read: String,

    #[serde(rename = "@Write")]
    pub write: String,
}

/// An unsupported semantic table flavour from Master Data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown table flavour `{0}`")]
pub struct TableFlavourError(pub String);

/// Table flavours that indicate the semantic type of a table resource.
///
/// These flavours determine the binary format of KNX tables (count field size,
/// entry size, and entry structure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableFlavour {
    /// BCU1-style address table (1-byte count + 2-byte entries)
    AddressTableBcu1,
    /// Power-line BCU1 address table (1-byte count + 2-byte entries)
    AddressTableBcu1Pl,
    /// System B address table (2-byte count + 2-byte entries)
    AddressTableSystemB,

    /// BCU1-style association table (1-byte count + 2-byte entries: u8 TSAP + u8 ASAP)
    AssociationTableBcu1,
    /// BCU2-style association table
    AssociationTableBcu2,
    /// System 7 association table
    AssociationTableSystem7,
    /// System B association table (2-byte count + 4-byte entries: u16 TSAP + u16 ASAP)
    AssociationTableSystemB,
    /// System B small association table (2-byte count + 2-byte entries: u8 TSAP + u8 ASAP)
    AssociationTableSystemBSmall,
    /// System B big association table (2-byte count + 4-byte entries: u16 TSAP + u16 ASAP)
    AssociationTableSystemBBig,

    /// BCU 1.0 group object table (RT1: narrow pointers)
    GroupObjectTableBcu10,
    /// BCU 1.1 group object table (RT1: narrow pointers)
    GroupObjectTableBcu11,
    /// Power-line BCU1 group object table (RT1: narrow pointers)
    GroupObjectTableBcu1Pl,
    /// BCU2 group object table (RT2: narrow pointers)
    GroupObjectTableBcu2,
    /// M112/System 7 group object table (wide pointers)
    GroupObjectTableM112,
    /// System 300 property-based group object table
    GroupObjectTableSystem300,
    /// System B group object table (flags and type rows)
    GroupObjectTableSystemB,
}

impl TableFlavour {
    /// Parse a table flavour without inventing a physical layout for unknown
    /// metadata.
    pub fn parse_flavour(value: &str) -> Result<Self, TableFlavourError> {
        let flavour = match value {
            "AddressTable_Bcu1" => TableFlavour::AddressTableBcu1,
            "AddressTable_Bcu1PL" => TableFlavour::AddressTableBcu1Pl,
            "AddressTable_SystemB" => TableFlavour::AddressTableSystemB,
            "AssociationTable_Bcu1" => TableFlavour::AssociationTableBcu1,
            "AssociationTable_Bcu2" => TableFlavour::AssociationTableBcu2,
            "AssociationTable_M112" => TableFlavour::AssociationTableSystem7,
            "AssociationTable_SystemB" => TableFlavour::AssociationTableSystemB,
            "AssociationTable_SystemBSmall" => TableFlavour::AssociationTableSystemBSmall,
            "AssociationTable_SystemBBig" => TableFlavour::AssociationTableSystemBBig,
            "GroupObjectTable_Bcu10" => TableFlavour::GroupObjectTableBcu10,
            "GroupObjectTable_Bcu11" => TableFlavour::GroupObjectTableBcu11,
            "GroupObjectTable_Bcu1PL" => TableFlavour::GroupObjectTableBcu1Pl,
            "GroupObjectTable_Bcu2" => TableFlavour::GroupObjectTableBcu2,
            "GroupObjectTable_M112" => TableFlavour::GroupObjectTableM112,
            "GroupObjectTable_System300" => TableFlavour::GroupObjectTableSystem300,
            "GroupObjectTable_SystemB" => TableFlavour::GroupObjectTableSystemB,
            unknown => return Err(TableFlavourError(unknown.to_owned())),
        };

        Ok(flavour)
    }

    /// Get the count field size in bytes.
    pub fn count_size(&self) -> usize {
        match self {
            // BCU1/BCU2/System 7 use a 1-byte count
            TableFlavour::AddressTableBcu1
            | TableFlavour::AddressTableBcu1Pl
            | TableFlavour::AssociationTableBcu1
            | TableFlavour::AssociationTableBcu2
            | TableFlavour::AssociationTableSystem7
            | TableFlavour::GroupObjectTableBcu10
            | TableFlavour::GroupObjectTableBcu11
            | TableFlavour::GroupObjectTableBcu1Pl
            | TableFlavour::GroupObjectTableBcu2
            | TableFlavour::GroupObjectTableM112 => 1,
            // System B uses 2-byte count
            _ => 2,
        }
    }

    /// Get the complete table header size in bytes.
    ///
    /// Most tables contain only their count field. Compact group-object
    /// tables also store the RAM-flags pointer before the first row.
    pub fn header_size(&self) -> usize {
        match self {
            TableFlavour::GroupObjectTableBcu10
            | TableFlavour::GroupObjectTableBcu11
            | TableFlavour::GroupObjectTableBcu1Pl
            | TableFlavour::GroupObjectTableBcu2 => 2,
            TableFlavour::GroupObjectTableM112 => 3,
            _ => self.count_size(),
        }
    }

    /// Get the entry size in bytes.
    pub fn entry_size(&self) -> usize {
        match self {
            // Address tables are always 2 bytes per entry (group address)
            TableFlavour::AddressTableBcu1 | TableFlavour::AddressTableBcu1Pl | TableFlavour::AddressTableSystemB => 2,

            // BCU1/BCU2/System 7 use 2-byte entries (u8 TSAP + u8 ASAP)
            TableFlavour::AssociationTableBcu1
            | TableFlavour::AssociationTableBcu2
            | TableFlavour::AssociationTableSystem7 => 2,

            // SystemBSmall uses 2-byte entries (u8 TSAP + u8 ASAP)
            TableFlavour::AssociationTableSystemBSmall => 2,

            // SystemB and SystemBBig use 4-byte entries (u16 TSAP + u16 ASAP)
            TableFlavour::AssociationTableSystemB | TableFlavour::AssociationTableSystemBBig => 4,

            // RT1/RT2 rows: narrow data pointer + config + type
            TableFlavour::GroupObjectTableBcu10
            | TableFlavour::GroupObjectTableBcu11
            | TableFlavour::GroupObjectTableBcu1Pl
            | TableFlavour::GroupObjectTableBcu2 => 3,

            // M112 rows: wide data pointer + config + type
            TableFlavour::GroupObjectTableM112 => 4,

            // System 300 RT6 property rows carry a 16-bit configuration and
            // the two 16-bit halves of the DPT identifier. System B RT7 rows
            // use the compact flags/type pair.
            TableFlavour::GroupObjectTableSystem300 => 6,
            TableFlavour::GroupObjectTableSystemB => 2,
        }
    }

    /// Check if this is a "small" format using u8 pairs for TSAP/ASAP.
    pub fn uses_u8_entries(&self) -> bool {
        matches!(
            self,
            TableFlavour::AssociationTableBcu1
                | TableFlavour::AssociationTableBcu2
                | TableFlavour::AssociationTableSystem7
                | TableFlavour::AssociationTableSystemBSmall
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_master_data_schema_and_document_identity() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278" />
</KNX>"#;

        let master: MasterData = xml.parse().expect("master data parses");

        assert_eq!(master.namespace(), Some("http://knx.org/xml/project/23"));
        assert_eq!(master.schema_version(), Some(23));
        assert_eq!(master.document_id(), Some("MD-1"));
        assert_eq!(master.document_version(), "278");
    }

    #[test]
    fn resolves_manufacturer_names_without_parsing_manufacturer_owned_catalogues() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278">
    <Manufacturers>
      <Manufacturer Id="M-000C" Name="Merten" KnxManufacturerId="12">
        <PublicKeys><PublicKey Id="PK-1" Number="1" Purpose="Registration" /></PublicKeys>
      </Manufacturer>
      <Manufacturer Id="M-0083" Name="MDT technologies" KnxManufacturerId="131" />
    </Manufacturers>
  </MasterData>
</KNX>"#;

        let master: MasterData = xml.parse().expect("manufacturer directory parses");

        assert_eq!(master.manufacturer_name("M-000C"), Some("Merten"));
        assert_eq!(master.manufacturer_name("M-0083"), Some("MDT technologies"));
        assert_eq!(master.manufacturer_name("M-FFFF"), None);
    }

    #[test]
    fn global_property_catalog_preserves_read_widths_and_symbolic_metadata() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278">
    <InterfaceObjectProperties>
      <InterfaceObjectProperty Id="PID-G-5" Number="5" Name="PID_LOAD_STATE_CONTROL"
        Text="Load Control" PDT="PDT-0" AccessPolicy="3FF/0CC" />
      <InterfaceObjectProperty Id="PID-0-78" Number="78" ObjectType="OT-0"
        Name="PID_HARDWARE_TYPE" PDT="PDT-22" Array="false" />
      <InterfaceObjectProperty Id="PID-800-67" Number="67" ObjectType="OT-800"
        Name="PID_MAX_SLAT_MOVE_TIME" DPT="DPST-7-2" />
    </InterfaceObjectProperties>
    <PropertyDataTypes>
      <PropertyDataType Id="PDT-0" Number="0" Name="PDT_CONTROL" Size="10" ReadSize="1" />
      <PropertyDataType Id="PDT-22" Number="22" Name="PDT_GENERIC_06" Size="6" />
      <PropertyDataType Id="PDT-4" Number="4" Name="PDT_UNSIGNED_INT" Size="2" />
    </PropertyDataTypes>
    <DatapointTypes>
      <DatapointType Id="DPT-7" PDT="PDT-4">
        <DatapointSubtypes><DatapointSubtype Id="DPST-7-2" /></DatapointSubtypes>
      </DatapointType>
    </DatapointTypes>
  </MasterData>
</KNX>"#;
        let master: MasterData = xml.parse().expect("global property catalogue parses");
        let properties = master.interface_object_properties();

        assert_eq!(properties.len(), 3);
        assert_eq!(properties[0].id, "PID-G-5");
        assert_eq!(properties[0].object_type, None);
        assert_eq!(properties[0].property_data_types.as_deref(), Some("PDT-0"));
        assert_eq!(properties[0].access_policy.as_deref(), Some("3FF/0CC"));
        assert_eq!(properties[1].object_type.as_deref(), Some("OT-0"));
        assert_eq!(properties[1].array, Some(false));
        assert_eq!(properties[2].datapoint_type.as_deref(), Some("DPST-7-2"));
        assert_eq!(master.property_data_type_size("PDT-22"), Some(6));
        assert_eq!(master.property_data_type_size("PDT_GENERIC_06"), Some(6));
        assert_eq!(master.property_data_type_read_size("PDT-0"), Some(1));
        assert_eq!(master.property_data_type_size("PDT-0"), Some(10));
        assert_eq!(master.datapoint_type_property_data_type("DPT-7"), Some("PDT-4"));
        assert_eq!(master.datapoint_type_property_data_type("DPST-7-2"), Some("PDT-4"));
        assert_eq!(master.datapoint_type_property_data_type("DPST-7-3"), None);
    }

    /// `DownwardCompatibleMasks` names the older masks whose programs
    /// a mask runs — the shape MV-0020 has in the real file.
    #[test]
    fn downward_compatible_masks_parse() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278"><MaskVersions>
    <MaskVersion Id="MV-0020" MaskVersion="32" Name="2.0" ManagementModel="Bcu2">
      <DownwardCompatibleMasks>
        <DownwardCompatibleMask RefId="MV-0010" />
        <DownwardCompatibleMask RefId="MV-0011" />
        <DownwardCompatibleMask RefId="MV-0012" />
      </DownwardCompatibleMasks>
      <HawkConfigurationData />
    </MaskVersion>
    <MaskVersion Id="MV-0012" MaskVersion="18" Name="1.2" ManagementModel="Bcu1">
      <HawkConfigurationData />
    </MaskVersion>
  </MaskVersions></MasterData>
</KNX>"#;
        let master: MasterData = xml.parse().expect("parses");

        let bcu2 = master.get_mask_version("MV-0020").expect("MV-0020");
        assert_eq!(bcu2.downward_compatible_masks().collect::<Vec<_>>(), vec![0x0010, 0x0011, 0x0012]);
        assert!(bcu2.is_downward_compatible_with(0x0012));
        assert!(bcu2.is_downward_compatible_with(0x0020), "a mask runs its own programs");
        assert!(!bcu2.is_downward_compatible_with(0x0705));

        let bcu1 = master.get_mask_version("MV-0012").expect("MV-0012");
        assert_eq!(bcu1.downward_compatible_masks().count(), 0, "absent element means none");
        assert!(bcu1.is_downward_compatible_with(0x0012));
    }

    /// `MaskEntries` resolve by their `_ME-` id suffix — a fixup's
    /// `FunctionRef` carries the *product's* mask prefix, and the
    /// lookup happens against the device's mask.
    #[test]
    fn mask_entries_resolve_by_suffix() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278"><MaskVersions>
    <MaskVersion Id="MV-0020" MaskVersion="32" Name="2.0" ManagementModel="Bcu2">
      <HawkConfigurationData />
      <MaskEntries>
        <MaskEntry Id="MV-0020_ME-U.5FGetTMx" Name="U_GetTMx" Address="20579" />
      </MaskEntries>
    </MaskVersion>
  </MaskVersions></MasterData>
</KNX>"#;
        let master: MasterData = xml.parse().expect("parses");
        let bcu2 = master.get_mask_version("MV-0020").expect("MV-0020");
        assert_eq!(bcu2.mask_entry_address("U.5FGetTMx"), Some(20579));
        assert_eq!(bcu2.mask_entry_address("U.5Fdeb30"), None);
    }

    #[test]
    fn project_11_master_data_does_not_require_an_id() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/11">
  <MasterData Version="420">
    <MaskVersions>
      <MaskVersion Id="MV-0012" MaskVersion="18" Name="1.2" ManagementModel="Bcu1" />
    </MaskVersions>
  </MasterData>
</KNX>"#;

        let master: MasterData = xml.parse().expect("project-11 master data parses");

        assert_eq!(master.root.master_data.id, "");
        assert!(master.get_mask_version("MV-0012").is_some());
    }

    #[test]
    fn resources_preserve_duplicate_names_and_management_styles() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278"><MaskVersions>
    <MaskVersion Id="MV-0020" MaskVersion="32" Name="2.0" ManagementModel="Bcu2">
      <HawkConfigurationData><Resources>
        <Resource Name="GroupAssociationTablePtr" Access="remote local1" MgmtStyle="simple">
          <Location AddressSpace="StandardMemory" StartAddress="273" />
          <ResourceType Length="1" Flavour="Ptr_StandardMemory100" />
        </Resource>
        <Resource Name="GroupAssociationTablePtr" Access="remote local2" MgmtStyle="lsm">
          <Location AddressSpace="SystemProperty" InterfaceObjectRef="2" PropertyID="7" />
          <ImgLocation AddressSpace="StandardMemory" StartAddress="273" />
          <ResourceType Length="2" Flavour="Ptr_StandardMemory" />
        </Resource>
      </Resources></HawkConfigurationData>
    </MaskVersion>
  </MaskVersions></MasterData>
</KNX>"#;
        let master: MasterData = xml.parse().expect("parses");
        let mask = master.get_mask_version("MV-0020").expect("MV-0020");
        let resources = mask.resources();

        assert_eq!(resources.len(), 2);
        assert!(resources[0].supports_management_style("simple"));
        assert!(!resources[0].supports_management_style("lsm"));
        assert!(resources[1].supports_management_style("lsm"));
        assert_eq!(resources[0].address_space(), Some("StandardMemory"));
        assert_eq!(resources[1].address_space(), Some("SystemProperty"));
        assert!(resources[1].supports_access("remote"));
        assert!(!resources[1].supports_access("local1"));
        assert_eq!(resources[1].image_start_address(), Some(273));
    }

    #[test]
    fn exact_mask_identity_preserves_management_descriptors() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278"><MaskVersions>
    <MaskVersion Id="MV-0300" MaskVersion="768" Name="System 300" ManagementModel="PropertyBased" />
    <MaskVersion Id="MV-0300-01000000000000000000" MaskVersion="768"
      MgmtDescriptor01="01000000000000000000" Name="System 300" ManagementModel="PropertyBased" />
    <MaskVersion Id="MV-0300-01000001000000000000" MaskVersion="768"
      MgmtDescriptor01="01000001000000000000" Name="System 300" ManagementModel="PropertyBased" />
  </MaskVersions></MasterData>
</KNX>"#;
        let master: MasterData = xml.parse().expect("exact System 300 identities parse");

        assert!(master.get_mask_version_by_code(0x0300).is_none(), "DD0 alone is ambiguous");
        assert_eq!(master.get_mask_versions_by_code(0x0300).count(), 3);

        let descriptor = [1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let selected =
            master.get_mask_version_by_descriptor(0x0300, Some(&descriptor)).expect("PID 72 selects the exact variant");

        assert_eq!(selected.id, "MV-0300-01000001000000000000");
        assert_eq!(selected.management_descriptor_01, Some(descriptor));
        assert_eq!(master.get_mask_version_by_descriptor(0x0300, None).expect("base selector").id, "MV-0300");
        assert_eq!(selected.first_app_object_idx(), None, "an absent feature is not the historical value 5");
    }

    #[test]
    fn current_configuration_is_selected_by_version_not_xml_order() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278"><MaskVersions>
    <MaskVersion Id="MV-091A" MaskVersion="2330" Name="Coupler" ManagementModel="Bcu1">
      <HawkConfigurationData LegacyVersion="1">
        <Features><Feature Name="FirstAppObjectIdx" Value="4" /></Features>
      </HawkConfigurationData>
      <HawkConfigurationData Ets3SystemPlugin="{01234567-89AB-CDEF-0123-456789ABCDEF}">
        <Features><Feature Name="FirstAppObjectIdx" Value="7" /></Features>
      </HawkConfigurationData>
    </MaskVersion>
  </MaskVersions></MasterData>
</KNX>"#;
        let master: MasterData = xml.parse().expect("configuration variants parse");
        let mask = master.get_mask_version("MV-091A").expect("mask exists");

        assert_eq!(mask.hawk_config().and_then(|config| config.legacy_version), None);
        assert_eq!(mask.hawk_config_for_legacy_version(1).and_then(|config| config.legacy_version), Some(1));
        assert_eq!(mask.first_app_object_idx(), Some(7));
        assert_eq!(
            mask.hawk_config().and_then(|config| config.ets3_system_plugin.as_deref()),
            Some("{01234567-89AB-CDEF-0123-456789ABCDEF}")
        );
    }

    #[test]
    fn locations_and_memory_segments_preserve_all_selector_fields() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278"><MaskVersions>
    <MaskVersion Id="MV-2920" MaskVersion="10528" Name="Coupler" ManagementModel="SystemB"
      MediumTypeRefId="MT-0" OtherMediumTypeRefId="MT-2">
      <HawkConfigurationData><Resources>
        <Resource Name="GroupAddressTable" Access="remote local2" MgmtStyle="lsm">
          <Location AddressSpace="Property" InterfaceObjectRef="6" PropertyID="23" StartAddress="0" />
          <ImgLocation AddressSpace="SystemProperty" InterfaceObjectRef="1" PropertyID="23" StartAddress="0" />
          <ResourceType Length="0" Flavour="AddressTable_SystemB" />
        </Resource>
        <Resource Name="GroupAssociationTable" Access="remote">
          <Location AddressSpace="Property" InterfaceObjectRef="6" Occurrence="0" PropertyID="23" StartAddress="0" />
          <ResourceType Length="0" />
        </Resource>
        <Resource Name="GroupFilterTable" Access="remote">
          <Location AddressSpace="RelativeMemoryByObjectType" InterfaceObjectRef="6" Occurrence="1"
            PropertyID="7" StartAddress="0" />
          <ResourceType Length="8192" />
        </Resource>
      </Resources><MemorySegments>
        <MemorySegment MemoryType="EEPROM" Length="256">
          <Location AddressSpace="StandardMemory" StartAddress="256" />
          <AccessRights Read="Configuration" Write="Configuration" />
        </MemorySegment>
        <MemorySegment MemoryType="EEPROM" Length="256" Optional="false">
          <Location AddressSpace="LcSlaveMemory" StartAddress="256" />
          <AccessRights Read="Configuration" Write="Configuration" />
        </MemorySegment>
        <MemorySegment MemoryType="EEPROM" Length="8192" Optional="true">
          <Location AddressSpace="LcFilterMemory" StartAddress="512" />
          <AccessRights Read="Configuration" Write="Configuration" />
        </MemorySegment>
      </MemorySegments></HawkConfigurationData>
    </MaskVersion>
  </MaskVersions></MasterData>
</KNX>"#;
        let master: MasterData = xml.parse().expect("typed resource locations parse");
        let mask = master.get_mask_version("MV-2920").expect("mask exists");
        let resources = mask.resources();

        assert_eq!(mask.other_medium_type_ref_id.as_deref(), Some("MT-2"));
        assert_eq!(resources[0].location.as_ref().and_then(|location| location.occurrence), None);
        assert_eq!(resources[1].location.as_ref().and_then(|location| location.occurrence), Some(0));
        assert_eq!(resources[2].location.as_ref().and_then(|location| location.occurrence), Some(1));
        assert!(matches!(
            resources[0].location.as_ref().expect("online location").to_address_space(),
            Ok(AddressSpaceLocation::Property { object_type: 6, occurrence: None, .. })
        ));
        assert!(matches!(
            resources[0].image_location.as_ref().expect("image location").to_address_space(),
            Ok(AddressSpaceLocation::SystemProperty { interface_object_ref: 1, .. })
        ));
        assert!(matches!(
            resources[2].location.as_ref().expect("filter location").to_address_space(),
            Ok(AddressSpaceLocation::RelativeMemoryByObjectType { object_type: 6, occurrence: Some(1), .. })
        ));

        let segments =
            &mask.hawk_config().expect("current config").memory_segments.as_ref().expect("segments").segments;

        assert_eq!(segments.iter().map(|segment| segment.optional).collect::<Vec<_>>(), [
            None,
            Some(false),
            Some(true)
        ]);
        assert!(matches!(segments[0].location.to_address_space(), Ok(AddressSpaceLocation::StandardMemory { .. })));
        assert!(matches!(segments[1].location.to_address_space(), Ok(AddressSpaceLocation::LcSlaveMemory { .. })));
        assert!(matches!(segments[2].location.to_address_space(), Ok(AddressSpaceLocation::LcFilterMemory { .. })));
    }

    #[test]
    fn unknown_tokens_are_retained_but_locations_fail_semantic_resolution() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278"><MaskVersions>
    <MaskVersion Id="MV-FFFF" MaskVersion="65535" Name="Future" ManagementModel="PropertyBased">
      <HawkConfigurationData><Resources>
        <Resource Name="GroupAddressTable" Access="remote satellite" MgmtStyle="simple future">
          <Location AddressSpace="QuantumMemory" StartAddress="1" />
          <ResourceType Length="1" />
        </Resource>
        <Resource Name="GroupAssociationTable" Access="remote">
          <Location AddressSpace="StandardMemory" />
          <ResourceType Length="1" />
        </Resource>
      </Resources></HawkConfigurationData>
    </MaskVersion>
  </MaskVersions></MasterData>
</KNX>"#;
        let master: MasterData = xml.parse().expect("unknown symbolic tokens remain inspectable");
        let resources = master.get_mask_version("MV-FFFF").expect("mask exists").resources();

        assert_eq!(resources[0].access.as_ref().expect("access").unknown().collect::<Vec<_>>(), ["satellite"]);
        assert_eq!(resources[0].management_style.as_ref().expect("style").unknown().collect::<Vec<_>>(), ["future"]);
        assert_eq!(
            resources[0].location.as_ref().expect("location").to_address_space(),
            Err(LocationError::UnknownAddressSpace("QuantumMemory".to_owned()))
        );
        assert_eq!(
            resources[1].location.as_ref().expect("location").to_address_space(),
            Err(LocationError::MissingField { address_space: "StandardMemory".to_owned(), field: "StartAddress" })
        );
    }

    #[test]
    fn malformed_management_descriptor_is_rejected() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278"><MaskVersions>
    <MaskVersion Id="MV-0300-short" MaskVersion="768" MgmtDescriptor01="0102"
      Name="System 300" ManagementModel="PropertyBased" />
  </MaskVersions></MasterData>
</KNX>"#;

        assert!(matches!(xml.parse::<MasterData>(), Err(MasterDataError::Xml(_))));
    }

    #[test]
    #[ignore] // Run with: cargo test -p zweidraehte-ets-files parse_master_data_file -- --ignored
    fn parse_master_data_file() {
        // manuf_tool_data sits at the workspace root (git-ignored:
        // licensed KNX XML stays out of the repository), two levels up
        // from this crate.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../manuf_tool_data/VC-EASY-03_MDT_KP_V35/knx_master.xml");
        let master = MasterData::from_file(path).expect("Failed to parse master data");

        let old_schema_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../manuf_tool_data/MDT_KP_BE_01_Push_Button_Lite_55_63_V14/knx_master.xml"
        );
        let old_schema_master = MasterData::from_file(old_schema_path).expect("project-11 master data parses");

        println!("Loaded {} mask versions", master.mask_version_count());
        assert!(master.mask_version_count() > 0);
        assert!(old_schema_master.mask_version_count() > 0);

        // Test MV-07B0 (System B)
        let mv_07b0 = master.get_mask_version("MV-07B0").expect("MV-07B0 not found");
        assert_eq!(mv_07b0.name, "System B");
        assert!(mv_07b0.is_system_b());
        assert_eq!(mv_07b0.first_app_object_idx(), Some(6));

        let adt = mv_07b0
            .resources()
            .iter()
            .find(|resource| resource.name == "GroupAddressTable")
            .expect("Address table not found");
        assert_eq!(adt.address_space(), Some("RelativeMemory"));
        assert_eq!(adt.interface_object_ref(), Some(1));
        assert_eq!(adt.property_id(), Some(7));

        // Test MV-0705 (System 7.5)
        let mv_0705 = master.get_mask_version("MV-0705").expect("MV-0705 not found");
        assert_eq!(mv_0705.name, "7.5");
        assert!(mv_0705.is_system7());
        assert_eq!(mv_0705.first_app_object_idx(), Some(5));

        let adt_0705 = mv_0705
            .resources()
            .iter()
            .find(|resource| resource.name == "GroupAddressTable")
            .expect("Address table not found");
        assert_eq!(adt_0705.address_space(), Some("StandardMemory"));
        assert_eq!(adt_0705.start_address(), Some(16384)); // 0x4000

        // Check flavours
        let adt_flavour_0705 = adt_0705
            .resource_type
            .as_ref()
            .and_then(|rt| rt.flavour.as_ref())
            .map(|flavour| TableFlavour::parse_flavour(flavour).expect("published table flavour"))
            .expect("address table declares a flavour");
        let adt_flavour_07b0 = adt
            .resource_type
            .as_ref()
            .and_then(|rt| rt.flavour.as_ref())
            .map(|flavour| TableFlavour::parse_flavour(flavour).expect("published table flavour"))
            .expect("address table declares a flavour");

        println!("MV-0705 ADT flavour: {:?}, count_size: {}", adt_flavour_0705, adt_flavour_0705.count_size());
        println!("MV-07B0 ADT flavour: {:?}, count_size: {}", adt_flavour_07b0, adt_flavour_07b0.count_size());

        println!("MV-07B0: {:?}", adt.location);
        println!("MV-0705: {:?}", adt_0705.location);

        // ------------------------------------------------------------
        // Programming procedures.
        //
        // System 7 masks carry ONLY "Unload all" — the Load
        // procedures are product-specific and live in each product's
        // .knxprod. System B carries the full generic template set.
        // ------------------------------------------------------------
        let procs_0705 = mv_0705.procedures();
        assert_eq!(procs_0705.len(), 1, "MV-0705 must carry exactly the Unload-all procedure");
        let unload = &procs_0705[0];
        assert!(unload.is_unload());
        assert_eq!(unload.procedure_sub_type.as_deref(), Some("all"));
        // Connect, Unload LSM 1-4, Disconnect.
        assert_eq!(unload.controls.len(), 6);
        assert!(matches!(unload.controls[0], LoadControl::LdCtrlConnect(_)));
        for (i, lsm) in (1..=4).enumerate() {
            match &unload.controls[1 + i] {
                LoadControl::LdCtrlUnload(u) => assert_eq!(u.lsm_idx, Some(lsm)),
                other => panic!("expected LdCtrlUnload, got {other:?}"),
            }
        }
        assert!(matches!(unload.controls[5], LoadControl::LdCtrlDisconnect(_)));

        // `procedures()` reads the current version-zero configuration only —
        // System B carries a second, `LegacyVersion="1"` config (with
        // its own Unload-all) that a current tool must not execute.
        let subtypes_07b0: Vec<_> =
            mv_07b0.procedures().iter().map(|p| (p.procedure_type.as_str(), p.procedure_sub_type.as_deref())).collect();
        assert_eq!(subtypes_07b0, [
            ("Load", Some("ap1")),
            ("Load", Some("all")),
            ("Load", Some("grp")),
            ("Load", Some("par")),
            ("Load", Some("par,grp")),
            ("Load", Some("cfg")),
            ("Unload", Some("all")),
        ]);
        assert_eq!(mv_07b0.hawk_configs.len(), 2, "System B has a primary and a LegacyVersion config");

        // The System B "Load all" template exercises the merge/splice
        // machinery: it must contain LdCtrlMerge points and
        // whole-blob relative writes.
        let load_all = mv_07b0.find_procedure("Load", "all").expect("System B Load-all template");
        assert!(load_all.allows_remote());
        assert!(load_all.controls.iter().any(|c| matches!(c, LoadControl::LdCtrlMerge(m) if m.merge_id == 4)));
        assert!(
            load_all
                .controls
                .iter()
                .any(|c| matches!(c, LoadControl::LdCtrlWriteRelMem(w) if w.obj_idx == Some(3) && w.verify))
        );
    }

    /// Hermetic exercise of the full master-data procedure vocabulary
    /// on a hand-written snippet (the licensed knx_master.xml stays
    /// out of the repository; this is our own minimal expression of
    /// the same element language, shaped after the project-23 file).
    #[test]
    fn parse_procedures_full_vocabulary() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278">
    <MaskVersions>
      <MaskVersion Id="MV-0012" MaskVersion="18" Name="1.2" ManagementModel="Bcu1">
        <HawkConfigurationData>
          <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote local1 local2">
              <LdCtrlConnect />
              <LdCtrlSetControlVariable Name="EnableVerifyOnWriteDirect" Value="true" />
              <LdCtrlLoadImageMem Address="278" Size="1" />
              <LdCtrlWriteMem Address="269" Size="1" Verify="true" InlineData="00" />
              <LdCtrlWriteMem Address="281" Size="230" Verify="true" />
              <LdCtrlCompareMem Address="278" Size="1" InlineData="01" />
              <LdCtrlDelay MilliSeconds="500" />
              <LdCtrlRestart />
            </Procedure>
          </Procedures>
        </HawkConfigurationData>
      </MaskVersion>
      <MaskVersion Id="MV-07B0" MaskVersion="1968" Name="System B" ManagementModel="SystemB">
        <HawkConfigurationData>
          <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="ap1" Access="remote local2">
              <LdCtrlConnect />
              <LdCtrlMerge MergeId="1" />
              <LdCtrlMapError OriginalError="3221498632" MappedError="0" />
              <LdCtrlUnload LsmIdx="5" />
              <LdCtrlLoad LsmIdx="3" />
              <LdCtrlRelSegment LsmIdx="3" Size="2" Mode="0" Fill="0" />
              <LdCtrlWriteRelMem ObjIdx="3" Offset="0" Size="1048576" Verify="true" />
              <LdCtrlWriteProp ObjIdx="4" PropId="13" Verify="true" InlineData="0000000000" />
              <LdCtrlLoadImageProp ObjIdx="4" PropId="7" />
              <LdCtrlCompareProp ObjIdx="4" PropId="7" InlineData="00000000" />
              <LdCtrlLoadCompleted LsmIdx="3" />
              <LdCtrlRestart />
            </Procedure>
          </Procedures>
        </HawkConfigurationData>
      </MaskVersion>
      <MaskVersion Id="MV-0020" MaskVersion="32" Name="2.0" ManagementModel="Bcu2">
        <HawkConfigurationData>
          <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
              <LdCtrlConnect />
              <LdCtrlTaskSegment LsmIdx="3" Address="17408" />
              <LdCtrlTaskPtr LsmIdx="3" InitPtr="284" SavePtr="285" SerialPtr="0" />
              <LdCtrlTaskCtrl1 LsmIdx="3" Address="0" Count="0" />
              <LdCtrlTaskCtrl2 LsmIdx="3" Callback="20609" Address="282" Seg0="208" Seg1="208" />
              <LdCtrlAbsSegment LsmIdx="1" SegType="0" Address="16384" Size="12" Access="255" MemType="3" SegFlags="128" />
              <LdCtrlWriteProp ObjIdx="1" PropId="53" Count="0" Verify="true" />
            </Procedure>
            <Procedure ProcedureType="Unload" ProcedureSubType="all" Access="local1">
              <LdCtrlClearLCFilterTable UseFunctionProp="true" />
              <LdCtrlLoad ObjType="6" Occurrence="1" />
              <LdCtrlRelSegment ObjType="6" Occurrence="1" Size="8192" Mode="0" Fill="0" />
              <LdCtrlWriteMem AddressSpace="LcFilter" Address="0" Size="8192" Verify="false" />
              <LdCtrlMasterReset EraseCode="7" ChannelNumber="0" />
            </Procedure>
          </Procedures>
        </HawkConfigurationData>
      </MaskVersion>
    </MaskVersions>
  </MasterData>
</KNX>"#;

        let master: MasterData = xml.parse().expect("snippet mirrors the master-data shape");

        // BCU1-style raw-memory download.
        let bcu1 = master.get_mask_version("MV-0012").expect("snippet defines MV-0012");
        let load = bcu1.find_procedure("Load", "all").expect("snippet defines Load all");
        assert!(load.allows_remote());
        assert_eq!(load.controls.len(), 8);
        assert!(matches!(&load.controls[1], LoadControl::LdCtrlSetControlVariable(v)
            if v.name == "EnableVerifyOnWriteDirect" && v.value));
        assert!(matches!(&load.controls[2], LoadControl::LdCtrlLoadImageMem(m)
            if m.address == 278 && m.size == 1));
        assert!(matches!(&load.controls[3], LoadControl::LdCtrlWriteMem(w)
            if w.address == 269 && w.inline_data.as_deref() == Some("00")));
        assert!(matches!(&load.controls[4], LoadControl::LdCtrlWriteMem(w)
            if w.size == 230 && w.inline_data.is_none()));
        assert!(matches!(&load.controls[5], LoadControl::LdCtrlCompareMem(c)
            if c.inline_data.as_deref() == Some("01")));
        assert!(matches!(&load.controls[6], LoadControl::LdCtrlDelay(d) if d.milli_seconds == 500));

        // System B template with merge/error scaffolding.
        let systemb = master.get_mask_version("MV-07B0").expect("snippet defines MV-07B0");
        let ap1 = systemb.find_procedure("Load", "ap1").expect("snippet defines Load ap1");
        assert!(matches!(&ap1.controls[1], LoadControl::LdCtrlMerge(m) if m.merge_id == 1));
        assert!(matches!(&ap1.controls[2], LoadControl::LdCtrlMapError(m)
            if m.original_error == 3221498632 && m.mapped_error == 0));
        assert!(matches!(&ap1.controls[5], LoadControl::LdCtrlRelSegment(r)
            if r.lsm_idx == Some(3) && r.applies_to.is_none() && r.size == 2));
        assert!(matches!(&ap1.controls[6], LoadControl::LdCtrlWriteRelMem(w)
            if w.obj_idx == Some(3) && w.size == 1_048_576 && w.verify));

        // BCU2 task plumbing + ObjType addressing + line-coupler ops.
        let bcu2 = master.get_mask_version("MV-0020").expect("snippet defines MV-0020");
        let load = bcu2.find_procedure("Load", "all").expect("snippet defines Load all");
        assert!(matches!(&load.controls[2], LoadControl::LdCtrlTaskPtr(t)
            if t.init_ptr == 284 && t.save_ptr == 285));
        assert!(matches!(&load.controls[4], LoadControl::LdCtrlTaskCtrl2(t)
            if t.callback == 20609 && t.seg0 == 208));
        assert!(matches!(&load.controls[5], LoadControl::LdCtrlAbsSegment(s)
            if s.address == 16384 && s.seg_flags == 128));
        assert!(matches!(&load.controls[6], LoadControl::LdCtrlWriteProp(w)
            if w.obj_idx == Some(1) && w.count == Some(0)));

        let unload = bcu2.find_procedure("Unload", "all").expect("snippet defines Unload all");
        assert!(!unload.allows_remote());
        assert!(matches!(&unload.controls[0], LoadControl::LdCtrlClearLCFilterTable(c)
            if c.use_function_prop == Some(true)));
        assert!(matches!(&unload.controls[1], LoadControl::LdCtrlLoad(l)
            if l.lsm_idx.is_none() && l.obj_type == Some(6) && l.occurrence == Some(1)));
        assert!(matches!(&unload.controls[3], LoadControl::LdCtrlWriteMem(w)
            if w.address_space.as_deref() == Some("LcFilter") && !w.verify));
        assert!(matches!(&unload.controls[4], LoadControl::LdCtrlMasterReset(m)
            if m.erase_code == 7 && m.channel_number == 0));
    }

    #[test]
    fn test_address_space_parsing() {
        let loc = Location {
            address_space: "RelativeMemory".to_string(),
            start_address: Some(0),
            interface_object_ref: Some(1),
            property_id: Some(7),
            occurrence: None,
            ptr_resource: None,
        };

        let addr_space = loc.to_address_space();
        assert!(matches!(
            addr_space,
            Ok(AddressSpaceLocation::RelativeMemory { interface_object_ref: 1, property_id: 7, .. })
        ));
    }

    #[test]
    fn test_table_flavour() {
        assert_eq!(
            TableFlavour::parse_flavour("AddressTable_SystemB").expect("known flavour"),
            TableFlavour::AddressTableSystemB
        );
        assert_eq!(TableFlavour::AddressTableSystemB.count_size(), 2);
        assert_eq!(TableFlavour::AddressTableBcu1.count_size(), 1);

        let power_line = TableFlavour::parse_flavour("AddressTable_Bcu1PL").expect("known flavour");

        assert_eq!(power_line, TableFlavour::AddressTableBcu1Pl);
        assert_eq!(power_line.count_size(), 1);
        assert_eq!(power_line.entry_size(), 2);
        assert_eq!(
            TableFlavour::parse_flavour("AddressTable_Future"),
            Err(TableFlavourError("AddressTable_Future".to_owned()))
        );
    }

    #[test]
    fn group_object_flavours_preserve_their_physical_layouts() {
        for (name, flavour) in [
            ("GroupObjectTable_Bcu10", TableFlavour::GroupObjectTableBcu10),
            ("GroupObjectTable_Bcu11", TableFlavour::GroupObjectTableBcu11),
            ("GroupObjectTable_Bcu1PL", TableFlavour::GroupObjectTableBcu1Pl),
            ("GroupObjectTable_Bcu2", TableFlavour::GroupObjectTableBcu2),
        ] {
            assert_eq!(TableFlavour::parse_flavour(name).expect("known flavour"), flavour);
            assert_eq!(flavour.count_size(), 1);
            assert_eq!(flavour.header_size(), 2);
            assert_eq!(flavour.entry_size(), 3);
        }

        let m112 = TableFlavour::parse_flavour("GroupObjectTable_M112").expect("known flavour");

        assert_eq!(m112, TableFlavour::GroupObjectTableM112);
        assert_eq!(m112.count_size(), 1);
        assert_eq!(m112.header_size(), 3);
        assert_eq!(m112.entry_size(), 4);

        let system_300 = TableFlavour::parse_flavour("GroupObjectTable_System300").expect("known flavour");

        assert_eq!(system_300, TableFlavour::GroupObjectTableSystem300);
        assert_eq!(system_300.entry_size(), 6);
        assert_eq!(
            TableFlavour::parse_flavour("GroupObjectTable_SystemB").expect("known flavour"),
            TableFlavour::GroupObjectTableSystemB
        );
    }
}
