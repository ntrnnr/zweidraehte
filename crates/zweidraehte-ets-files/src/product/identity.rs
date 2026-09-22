//! Explicit product identity schema, independent of diagnostic formatting.

use super::*;
use core::result::Result;
use serde::{Serialize, Serializer, ser::SerializeMap};

impl ProductData {
    /// Borrow the version-3 programming identity as a serializable value.
    ///
    /// The client hashes canonical JSON of this inventory. Arrays retain source
    /// order; object keys are canonicalized by the encoder. Master Data has its
    /// own exact-document identity. Tool/author labels are diagnostic provenance
    /// and are excluded; project values and credentials never enter this view.
    /// Changing its encoding requires a new fingerprint and evidence version.
    pub fn programming_identity(&self) -> impl Serialize + '_ {
        ProductIdentity(self)
    }
}

struct ProductIdentity<'a>(&'a ProductData);
struct OptionsIdentity<'a>(&'a ProductProgrammingOptions);
struct RelationIdentity<'a>(&'a ApplicationProgramRelationIdentity);

// Explicit field lists keep the schema reviewable. Exhaustive destructuring
// below forces new product fields to be classified instead of silently omitted.
macro_rules! fields {
    ($map:ident, $($field:ident),+ $(,)?) => {
        $($map.serialize_entry(stringify!($field), $field)?;)+
    };
}

impl Serialize for ProductIdentity<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ProductData {
            id,
            mask_version_id,
            mask_version: _,
            schema_provenance,
            master_data: _,
            programming_options,
            application_program_2,
            load_procedure_style,
            application_identity,
            supports_data_secure,
            max_security_individual_address_entries,
            max_security_group_key_table_entries,
            max_security_p2p_key_table_entries,
            bus_interfaces,
            segments,
            relative_segment_offsets,
            load_procedures,
            com_objects,
            com_object_numbers,
            parameters,
            module_definitions,
            parameter_widths,
            resolved_module_parameter_ids,
            property_parameters,
            address_table_segment,
            address_table_offset,
            address_table_max_entries,
            association_table_segment,
            association_table_offset,
            association_table_max_entries,
            com_object_table_segment,
            com_object_table_offset,
            fixups,
            dynamic_table_management,
        } = self.0;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("version", &3u8)?;
        fields!(
            map,
            id,
            mask_version_id,
            supports_data_secure,
            max_security_individual_address_entries,
            max_security_group_key_table_entries,
            max_security_p2p_key_table_entries,
            bus_interfaces,
            relative_segment_offsets,
            load_procedures,
            com_object_numbers,
            parameter_widths,
            resolved_module_parameter_ids,
            address_table_segment,
            address_table_offset,
            address_table_max_entries,
            association_table_segment,
            association_table_offset,
            association_table_max_entries,
            com_object_table_segment,
            com_object_table_offset,
            dynamic_table_management
        );
        // Numeric MaskVersion is derived from mask_version_id. Retain namespace
        // authority and effective schema defaults, not creation-tool labels.
        let source = schema_provenance.schema_version_source.map(|source| match source {
            ProductSchemaVersionSource::DocumentNamespace => "document_namespace",
            ProductSchemaVersionSource::ExplicitBinding => "explicit_binding",
        });
        map.serialize_entry("schema", &(&schema_provenance.namespace, schema_provenance.schema_version, source))?;
        map.serialize_entry("programming_options", &OptionsIdentity(programming_options))?;
        map.serialize_entry("load_procedure_style", &match load_procedure_style {
            LoadProcedureStyle::Default => "default",
            LoadProcedureStyle::Product => "product",
            LoadProcedureStyle::Merged => "merged",
        })?;
        let ApplicationIdentity { application_id, pei_type } = application_identity;
        map.serialize_entry("application_identity", &(application_id, pei_type))?;
        let (state, relation, secondary) = match application_program_2 {
            ApplicationProgram2Binding::Unbound => ("unbound", None, None),
            ApplicationProgram2Binding::Absent { relation } => ("absent", Some(RelationIdentity(relation)), None),
            ApplicationProgram2Binding::Present { relation, application_program_id } => {
                ("present", Some(RelationIdentity(relation)), Some(application_program_id))
            }
        };
        map.serialize_entry("application_program_2", &(state, relation, secondary))?;

        // Geometry records are fixed-order arrays; their positional schema is
        // specified in docs/PRODUCT_FINGERPRINT.md alongside the named fields.
        let segments: Vec<_> = segments
            .iter()
            .map(|Segment { id, address, size, memory_type, user_memory, load_state_machine, data, mask }| {
                (id, address, size, memory_type, user_memory, load_state_machine, data, mask)
            })
            .collect();
        map.serialize_entry("segments", &segments)?;
        let objects: Vec<_> = com_objects
            .iter()
            .map(|ComObjectDef { number, object_type, datapoint_type, flags }| {
                (number, u8::from(*object_type), datapoint_type, flags.to_byte())
            })
            .collect();
        map.serialize_entry("com_objects", &objects)?;
        let parameters: Vec<_> = parameters
            .iter()
            .map(
                |ParameterLocation {
                     id,
                     code_segment,
                     offset,
                     bit_offset,
                     size_bits,
                     legacy_patch_always,
                     seeds_default,
                 }| {
                    (id, code_segment, offset, bit_offset, size_bits, legacy_patch_always, seeds_default)
                },
            )
            .collect();
        map.serialize_entry("parameters", &parameters)?;
        let properties: Vec<_> = property_parameters
            .iter()
            .map(
                |PropertyParameterLocation {
                     id,
                     object,
                     property_id,
                     offset,
                     bit_offset,
                     size_bits,
                     legacy_patch_always,
                 }| {
                    let object = match *object {
                        PropertyObject::Index(index) => (0u8, u16::from(index), None),
                        PropertyObject::Type { object_type, occurrence } => {
                            (1, u16::from(object_type), Some(occurrence))
                        }
                    };
                    (id, object, property_id, offset, bit_offset, size_bits, legacy_patch_always)
                },
            )
            .collect();
        map.serialize_entry("property_parameters", &properties)?;
        let modules: BTreeMap<_, _> = module_definitions
            .iter()
            .map(|(id, ModuleGeometryDefinition { parameters, argument_names })| (id, (parameters, argument_names)))
            .collect();
        map.serialize_entry("module_definitions", &modules)?;
        let fixups: Vec<_> = fixups
            .iter()
            .map(|FixupDef { function, code_segment, offsets }| (function, code_segment, offsets))
            .collect();
        map.serialize_entry("fixups", &fixups)?;
        map.end()
    }
}

impl Serialize for OptionsIdentity<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ProductProgrammingOptions {
            schema_version,
            application_attributes,
            program_type,
            min_ets_version,
            replaces_versions,
            application_hash,
            dynamic_table_management,
            linkable,
            ip_config,
            additional_addresses_count,
            is_secure_enabled,
            max_user_entries,
            max_tunneling_user_entries,
            max_security_individual_address_entries,
            max_security_group_key_table_entries,
            max_security_p2p_key_table_entries,
            non_reg_relevant_data_version,
            options,
            extension,
        } = self.0;
        let mut map = serializer.serialize_map(None)?;
        fields!(
            map,
            schema_version,
            application_attributes,
            program_type,
            min_ets_version,
            replaces_versions,
            application_hash,
            dynamic_table_management,
            linkable,
            ip_config,
            additional_addresses_count,
            is_secure_enabled,
            max_user_entries,
            max_tunneling_user_entries,
            max_security_individual_address_entries,
            max_security_group_key_table_entries,
            max_security_p2p_key_table_entries,
            non_reg_relevant_data_version,
            options,
            extension
        );
        map.end()
    }
}

impl Serialize for RelationIdentity<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ApplicationProgramRelationIdentity {
            catalog_product_id,
            catalog_item_id,
            hardware_id,
            hardware2program_id,
            application_program_id,
        } = self.0;
        let mut map = serializer.serialize_map(None)?;
        fields!(map, catalog_product_id, catalog_item_id, hardware_id, hardware2program_id, application_program_id);
        map.end()
    }
}
