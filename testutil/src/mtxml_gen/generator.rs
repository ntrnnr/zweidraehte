//! MTXML Generator - Builds ApplicationProgram XML from device definitions.

use base64::Engine;

use zweidraehte::ets::{
    DeviceDescriptor, EtsCommObjectDef, EtsParamDefExt, EtsParamType,
    EtsUnionFieldInfo,
};

use super::schema::*;

/// Configuration for generating MTXML files (ApplicationProgram, Hardware, Catalog).
pub struct ApplicationProgramConfig<'a> {
    /// Human-readable application name
    pub name: &'a str,
    /// Device descriptor with mask version, manufacturer ID, etc.
    pub device: &'a DeviceDescriptor,
    /// Extended parameter definitions with enum variants
    pub params: &'a [EtsParamDefExt],
    /// Default parameter values as raw bytes
    pub param_defaults: &'a [u8],
    /// Communication object definitions
    pub comm_objects: &'a [EtsCommObjectDef],
    /// Union fields from derive macro (optional)
    pub union_fields: Option<&'a [EtsUnionFieldInfo]>,
    /// Channel name for the UI grouping
    pub channel_name: &'a str,
    /// Base address for absolute segments (System 7 only)
    /// For System 7, this is the memory address where parameters start
    pub absolute_segment_address: Option<u32>,

    // ========================================================================
    // Hardware/Catalog fields (for Hardware.mtxml and Catalog.mtxml generation)
    // ========================================================================
    /// Device serial number (6 bytes, unique per device).
    /// First 2 bytes should match manufacturer_id.
    pub serial_number: [u8; 6],
    /// Hardware version number (displayed in ETS)
    pub hardware_version: u8,
    /// Hardware name (displayed in ETS hardware list)
    pub hardware_name: &'a str,
    /// Product display text (shown in ETS catalog)
    pub product_name: &'a str,
    /// Product order number (for ordering/identification)
    pub order_number: &'a str,
    /// Whether the device is rail-mounted (DIN rail)
    pub is_rail_mounted: bool,
    /// Catalog section name (category in ETS catalog)
    pub catalog_section: &'a str,
}

impl<'a> ApplicationProgramConfig<'a> {
    /// Get the mask family for this configuration
    pub fn mask_family(&self) -> MaskFamily {
        MaskFamily::from_mask_version(self.device.mask_version)
    }
}

/// Generator for creating ApplicationProgram MTXML files.
pub struct MtxmlGenerator;

impl MtxmlGenerator {
    /// Generate a complete KNX MTXML document from the configuration.
    pub fn generate(config: &ApplicationProgramConfig) -> Result<String, GeneratorError> {
        let knx = Self::build_knx(config)?;
        Self::serialize(&knx)
    }

    /// Build the complete KNX document structure.
    fn build_knx(config: &ApplicationProgramConfig) -> Result<Knx, GeneratorError> {
        let app_id = Self::format_app_id(config.device);

        let mut knx = Knx::default();
        knx.manufacturer_data.manufacturer.ref_id =
            format!("M-{:04X}", config.device.manufacturer_id);
        knx.manufacturer_data
            .manufacturer
            .application_programs
            .programs
            .push(Self::build_application_program(config, &app_id)?);

        Ok(knx)
    }

    /// Format the application ID string.
    fn format_app_id(device: &DeviceDescriptor) -> String {
        format!(
            "M-{:04X}_A-{:04X}-{:02X}-0000",
            device.manufacturer_id, device.application_id, device.application_version
        )
    }

    /// Build the ApplicationProgram element.
    fn build_application_program(
        config: &ApplicationProgramConfig,
        app_id: &str,
    ) -> Result<ApplicationProgram, GeneratorError> {
        let mask_family = config.mask_family();

        // Build code segment ID based on mask family
        let code_segment_id = match mask_family.data_segment_type() {
            DataSegmentType::Relative => format!("{}_RS-04-00000", app_id),
            DataSegmentType::Absolute => format!("{}_AS-00000", app_id),
        };

        let mut app = ApplicationProgram {
            id: app_id.to_string(),
            application_number: config.device.application_id,
            application_version: config.device.application_version,
            mask_version: format!("MV-{:04X}", config.device.mask_version),
            name: config.name.to_string(),
            load_procedure_style: mask_family.load_procedure_style().to_string(),
            ..Default::default()
        };

        // Build Static section
        app.static_section = Self::build_static_section(config, app_id, &code_segment_id, mask_family)?;

        // Build Dynamic section
        app.dynamic = Some(Self::build_dynamic_section(config, app_id, mask_family)?);

        Ok(app)
    }

    /// Build the Static section with all components.
    fn build_static_section(
        config: &ApplicationProgramConfig,
        app_id: &str,
        code_segment_id: &str,
        mask_family: MaskFamily,
    ) -> Result<StaticSection, GeneratorError> {
        let param_size = config.param_defaults.len() as u32;

        // Build address/association tables only for masks that support them
        let (address_table, association_table) = if mask_family.generates_address_tables() {
            (
                Some(AddressTable {
                    offset: 0,
                    max_entries: config.device.max_address_table_entries,
                }),
                Some(AssociationTable {
                    offset: 0,
                    max_entries: config.device.max_association_table_entries,
                }),
            )
        } else {
            (None, None)
        };

        // Build ComObject table only for masks that support it
        let (com_object_table, com_object_refs) = if mask_family.has_com_object_table() {
            (
                Some(Self::build_com_object_table(config, app_id, mask_family)),
                Some(Self::build_com_object_refs(config, app_id, mask_family)),
            )
        } else {
            (None, None)
        };

        Ok(StaticSection {
            code: Some(Self::build_code(config, code_segment_id, param_size, mask_family)),
            parameter_types: Some(Self::build_parameter_types(config, app_id)),
            parameters: Some(Self::build_parameters(config, app_id, code_segment_id)),
            parameter_refs: Some(Self::build_parameter_refs(config, app_id)),
            com_object_table,
            com_object_refs,
            address_table,
            association_table,
            load_procedures: Some(Self::build_load_procedures(param_size, mask_family)),
            options: Some(Options {
                comparable: Some(true),
                reconstructable: Some(true),
            }),
        })
    }

    /// Build the Code section with appropriate segment type for the mask.
    fn build_code(
        config: &ApplicationProgramConfig,
        code_segment_id: &str,
        size: u32,
        mask_family: MaskFamily,
    ) -> Code {
        let data = base64::engine::general_purpose::STANDARD.encode(config.param_defaults);

        match mask_family.data_segment_type() {
            DataSegmentType::Relative => Code {
                absolute_segments: vec![],
                relative_segments: vec![RelativeSegment {
                    id: code_segment_id.to_string(),
                    size,
                    load_state_machine: 4,
                    offset: 0,
                    data: Some(data),
                }],
            },
            DataSegmentType::Absolute => Code {
                absolute_segments: vec![AbsoluteSegment {
                    id: code_segment_id.to_string(),
                    size,
                    address: config.absolute_segment_address.unwrap_or(0),
                    memory_type: Some("Ram".to_string()),
                    data: Some(data),
                }],
                relative_segments: vec![],
            },
        }
    }

    /// Build parameter type definitions.
    fn build_parameter_types(config: &ApplicationProgramConfig, app_id: &str) -> ParameterTypes {
        let mut types = ParameterTypes::default();
        let mut seen_types = std::collections::HashSet::new();

        for param in config.params {
            let type_name = Self::param_type_name(&param.base);
            if seen_types.contains(&type_name) {
                continue;
            }
            seen_types.insert(type_name.clone());

            // URL-encode the type name for the ID
            let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));
            let type_def = Self::build_type_def(&param.base, param.enum_variants, &type_id);

            types.types.push(ParameterType {
                id: type_id,
                name: type_name,
                internal_description: Some("generated".to_string()),
                type_def,
            });
        }

        // Add types for union parameters if any
        if let Some(union_fields) = config.union_fields {
            for field in union_fields {
                // Selector type
                let selector_type_name = format!("tENUM_{}_selector_8", field.field_name);
                if !seen_types.contains(&selector_type_name) {
                    seen_types.insert(selector_type_name.clone());
                    let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&selector_type_name));
                    types.types.push(ParameterType {
                        id: type_id.clone(),
                        name: selector_type_name,
                        internal_description: Some("generated".to_string()),
                        type_def: ParameterTypeDef::TypeRestriction(TypeRestriction {
                            base: "Value".to_string(),
                            size_in_bit: 8,
                            enumerations: field
                                .selector_variants
                                .iter()
                                .map(|v| Enumeration {
                                    text: v.text.to_string(),
                                    value: v.value as u32,
                                    // Enum ID includes full prefix and the value (not index)
                                    id: format!("{}_EN-{}", type_id, v.value),
                                })
                                .collect(),
                        }),
                    });
                }

                // Types for variant parameters
                for param in field.union_info.variant_params {
                    let type_name = Self::param_type_name(&param.param);
                    if !seen_types.contains(&type_name) {
                        seen_types.insert(type_name.clone());
                        let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));
                        let type_def = Self::build_type_def(&param.param, None, &type_id);
                        types.types.push(ParameterType {
                            id: type_id,
                            name: type_name,
                            internal_description: Some("generated".to_string()),
                            type_def,
                        });
                    }
                }
            }
        }

        types
    }

    /// Generate a type name from a parameter definition.
    fn param_type_name(param: &zweidraehte::ets::EtsParamDef) -> String {
        match param.param_type {
            EtsParamType::UnsignedInt => format!("tUINT{}", param.size_bits),
            EtsParamType::SignedInt => format!("tSINT{}", param.size_bits),
            EtsParamType::Enum => format!("tENUM_{}_{}", param.name, param.size_bits),
            EtsParamType::String => format!("tTEXT{}", param.size_bits),
            EtsParamType::None => format!("tNONE{}", param.size_bits),
        }
    }

    /// URL-encode a name for use in IDs (underscores become .5F)
    /// This applies to all user-defined names that appear in IDs
    fn encode_id(name: &str) -> String {
        name.replace('_', ".5F")
    }

    /// Build a type definition for a parameter.
    fn build_type_def(
        param: &zweidraehte::ets::EtsParamDef,
        enum_variants: Option<&[zweidraehte::ets::EtsEnumVariant]>,
        type_id: &str,
    ) -> ParameterTypeDef {
        match param.param_type {
            EtsParamType::UnsignedInt => {
                let max = (1i64 << param.size_bits) - 1;
                ParameterTypeDef::TypeNumber(TypeNumber {
                    size_in_bit: param.size_bits,
                    num_type: "unsignedInt".to_string(),
                    min_inclusive: 0,
                    max_inclusive: max,
                })
            }
            EtsParamType::SignedInt => {
                let half = 1i64 << (param.size_bits - 1);
                ParameterTypeDef::TypeNumber(TypeNumber {
                    size_in_bit: param.size_bits,
                    num_type: "signedInt".to_string(),
                    min_inclusive: -half,
                    max_inclusive: half - 1,
                })
            }
            EtsParamType::Enum => {
                let enumerations = if let Some(variants) = enum_variants {
                    variants
                        .iter()
                        .map(|v| Enumeration {
                            text: v.text.to_string(),
                            value: v.value as u32,
                            // Enum ID includes full type prefix and the value
                            id: format!("{}_EN-{}", type_id, v.value),
                        })
                        .collect()
                } else {
                    vec![]
                };
                ParameterTypeDef::TypeRestriction(TypeRestriction {
                    base: "Value".to_string(),
                    size_in_bit: param.size_bits as u32,
                    enumerations,
                })
            }
            EtsParamType::String => ParameterTypeDef::TypeText(TypeText {
                size_in_bit: param.size_bits as u32,
                pattern: None,
            }),
            EtsParamType::None => ParameterTypeDef::TypeNone(TypeNone {}),
        }
    }

    /// Build parameters section.
    fn build_parameters(
        config: &ApplicationProgramConfig,
        app_id: &str,
        code_segment_id: &str,
    ) -> Parameters {
        let mut params = Parameters::default();
        let mut param_counter = 1u32;

        // Build a set of union selector names to skip them in regular params
        // (they are generated inside the Union element, not as separate Parameters)
        let union_selector_names: std::collections::HashSet<String> = config
            .union_fields
            .map(|fields| {
                fields
                    .iter()
                    .map(|f| format!("{}_selector", f.field_name))
                    .collect()
            })
            .unwrap_or_default();

        // Regular parameters
        for param_ext in config.params {
            let param = &param_ext.base;

            // Skip union selector parameters - they go inside the Union, not as separate params
            if union_selector_names.contains(param.name) {
                continue;
            }

            let param_id = format!("{}_P-{}", app_id, param_counter);
            let type_name = Self::param_type_name(param);
            // Use encoded type ID
            let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));

            // Get default value from param_defaults
            let default_value = if (param.offset as usize) < config.param_defaults.len() {
                config.param_defaults[param.offset as usize].to_string()
            } else {
                "0".to_string()
            };

            params.items.push(ParameterItem::Parameter(Parameter {
                id: param_id,
                name: param.name.to_string(),
                parameter_type: type_id,
                text: param.display_name.to_string(),
                value: default_value,
                internal_description: Some("generated".to_string()),
                memory: Some(MemoryLocation {
                    code_segment: code_segment_id.to_string(),
                    offset: param.offset as u32,
                    bit_offset: param.bit_offset,
                }),
            }));

            param_counter += 1;
        }

        // Union parameters - start counting from 1
        if let Some(union_fields) = config.union_fields {
            let mut up_counter = 1u32;
            for field in union_fields {
                let (union_elem, next_counter) = Self::build_union(
                    field,
                    app_id,
                    code_segment_id,
                    up_counter,
                );
                params.items.push(ParameterItem::Union(union_elem));
                up_counter = next_counter;
            }
        }

        params
    }

    /// Build a union element from a union field info.
    /// Returns (Union, next_up_counter) to track union parameter numbering.
    fn build_union(
        field: &EtsUnionFieldInfo,
        app_id: &str,
        code_segment_id: &str,
        up_counter: u32,
    ) -> (Union, u32) {
        let union_info = field.union_info;
        let total_size_bits = union_info.total_size as u32 * 8;

        let mut parameters = vec![];
        let mut counter = up_counter;

        // Selector parameter (discriminant) - uses sequential UP- numbering
        let selector_type_name = format!("tENUM_{}_selector_8", field.field_name);
        let selector_type = format!("{}_PT-{}", app_id, Self::encode_id(&selector_type_name));
        parameters.push(UnionParameter {
            id: format!("{}_UP-{}", app_id, counter),
            name: format!("{}_selector", field.field_name),
            parameter_type: selector_type,
            text: format!("{} Mode", field.field_name),
            value: "0".to_string(),
            offset: 0,
            bit_offset: 0,
            default_union_parameter: Some(true),
            internal_description: Some("generated".to_string()),
        });
        counter += 1;

        // Variant field parameters - in the order they appear in variant_params
        for param in union_info.variant_params {
            let type_name = Self::param_type_name(&param.param);
            // Use encoded type ID
            let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));

            parameters.push(UnionParameter {
                id: format!("{}_UP-{}", app_id, counter),
                name: format!("{}_{}", param.variant_name, param.param.name),
                parameter_type: type_id,
                text: param.param.display_name.to_string(),
                value: "0".to_string(),
                offset: union_info.data_offset + param.param.offset, // data_offset accounts for discriminant + alignment padding
                bit_offset: param.param.bit_offset,
                default_union_parameter: None,
                internal_description: Some("generated".to_string()),
            });
            counter += 1;
        }

        (Union {
            size_in_bit: total_size_bits,
            internal_description: Some("generated".to_string()),
            memory: UnionMemory {
                code_segment: code_segment_id.to_string(),
                offset: field.offset as u32,
                bit_offset: 0,
            },
            parameters,
        }, counter)
    }

    /// Build parameter references.
    fn build_parameter_refs(config: &ApplicationProgramConfig, app_id: &str) -> ParameterRefs {
        let mut refs = ParameterRefs::default();
        let mut ref_counter = 1u32;
        let mut param_counter = 1u32;

        // Build a set of union selector names to skip them in regular params
        let union_selector_names: std::collections::HashSet<String> = config
            .union_fields
            .map(|fields| {
                fields
                    .iter()
                    .map(|f| format!("{}_selector", f.field_name))
                    .collect()
            })
            .unwrap_or_default();

        for param in config.params {
            // Skip union selector parameters - they are referenced via union param refs
            if union_selector_names.contains(param.base.name) {
                continue;
            }

            let param_id = format!("{}_P-{}", app_id, param_counter);
            let ref_id = format!("{}_R-{}", param_id, ref_counter);

            refs.refs.push(ParameterRef {
                id: ref_id,
                ref_id: param_id,
                internal_description: Some("generated".to_string()),
            });

            param_counter += 1;
            ref_counter += 1;
        }

        // Union parameter refs - uses same sequential numbering as build_union
        if let Some(union_fields) = config.union_fields {
            let mut up_counter = 1u32;
            for field in union_fields {
                // Selector ref - must match ID in build_union (UP-1, UP-2, etc.)
                let selector_id = format!("{}_UP-{}", app_id, up_counter);
                refs.refs.push(ParameterRef {
                    id: format!("{}_R-{}", selector_id, ref_counter),
                    ref_id: selector_id,
                    internal_description: Some("generated".to_string()),
                });
                ref_counter += 1;
                up_counter += 1;

                // Variant parameter refs - in the same order as build_union
                for _param in field.union_info.variant_params {
                    let param_id = format!("{}_UP-{}", app_id, up_counter);
                    refs.refs.push(ParameterRef {
                        id: format!("{}_R-{}", param_id, ref_counter),
                        ref_id: param_id,
                        internal_description: Some("generated".to_string()),
                    });
                    ref_counter += 1;
                    up_counter += 1;
                }
            }
        }

        refs
    }

    /// Build communication object table.
    fn build_com_object_table(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
    ) -> ComObjectTable {
        let mut table = ComObjectTable::default();
        let start_index = mask_family.com_object_start_index();

        for co in config.comm_objects {
            // Adjust index based on mask family
            let adjusted_index = co.index + start_index;
            let obj_id = format!("{}_O-{}", app_id, adjusted_index);
            let flags = co.default_flags;

            table.objects.push(ComObject {
                id: obj_id,
                name: co.name.to_string(),
                text: co.display_name.to_string(),
                number: adjusted_index,
                function_text: co.function_text.to_string(),
                object_size: object_size_to_string(co.size_bits).to_string(),
                datapoint_type: Some(dpt_to_string(co.dpt_main, co.dpt_sub)),
                read_flag: (flags & 0x08 != 0).into(),
                write_flag: (flags & 0x10 != 0).into(),
                communication_flag: (flags & 0x40 != 0).into(),
                transmit_flag: (flags & 0x04 != 0).into(),
                update_flag: (flags & 0x80 != 0).into(),
                read_on_init_flag: (flags & 0x02 != 0).into(),
                priority: Some(priority_from_flags(flags)),
                internal_description: Some("generated".to_string()),
            });
        }

        table
    }

    /// Build communication object references.
    fn build_com_object_refs(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
    ) -> ComObjectRefs {
        let mut refs = ComObjectRefs::default();
        let start_index = mask_family.com_object_start_index();

        for (i, co) in config.comm_objects.iter().enumerate() {
            let adjusted_index = co.index + start_index;
            let co_id = format!("{}_O-{}", app_id, adjusted_index);
            let ref_id = format!("{}_R-{}", co_id, i + 1);

            refs.refs.push(ComObjectRef {
                id: ref_id,
                ref_id: co_id,
                name: Some(co.name.to_string()),
                internal_description: Some("generated".to_string()),
            });
        }

        refs
    }

    /// Build load procedures based on mask family.
    fn build_load_procedures(param_size: u32, mask_family: MaskFamily) -> LoadProcedures {
        match mask_family {
            MaskFamily::SystemB => Self::build_system_b_load_procedures(param_size),
            MaskFamily::System7 => Self::build_system_7_load_procedures(),
            MaskFamily::Bim | MaskFamily::BimM => Self::build_bim_load_procedures(),
        }
    }

    /// Build load procedures for System B (MergedProcedure with relative segments).
    fn build_system_b_load_procedures(param_size: u32) -> LoadProcedures {
        LoadProcedures {
            procedures: vec![
                LoadProcedure {
                    merge_id: 2,
                    controls: vec![
                        LoadControl::LdCtrlRelSegment(LdCtrlRelSegment {
                            applies_to: "full".to_string(),
                            lsm_idx: 4,
                            size: param_size,
                            mode: 1,
                            fill: 0,
                        }),
                        LoadControl::LdCtrlRelSegment(LdCtrlRelSegment {
                            applies_to: "par".to_string(),
                            lsm_idx: 4,
                            size: param_size,
                            mode: 0,
                            fill: 0,
                        }),
                    ],
                },
                LoadProcedure {
                    merge_id: 4,
                    controls: vec![LoadControl::LdCtrlWriteRelMem(LdCtrlWriteRelMem {
                        applies_to: "full,par".to_string(),
                        obj_idx: 4,
                        offset: 0,
                        size: param_size,
                        verify: true,
                    })],
                },
                LoadProcedure {
                    merge_id: 7,
                    controls: vec![
                        LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                            obj_idx: 1,
                            prop_id: 27,
                        }),
                        LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                            obj_idx: 2,
                            prop_id: 27,
                        }),
                        LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                            obj_idx: 3,
                            prop_id: 27,
                        }),
                        LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                            obj_idx: 4,
                            prop_id: 27,
                        }),
                    ],
                },
            ],
        }
    }

    /// Build load procedures for System 7 (ProductProcedure with absolute segments).
    /// System 7 uses simpler load procedures - typically just loads memory directly.
    fn build_system_7_load_procedures() -> LoadProcedures {
        // System 7 typically doesn't need complex load procedures
        // The actual loading is handled by the ProductProcedure mechanism
        LoadProcedures { procedures: vec![] }
    }

    /// Build load procedures for BIM devices.
    fn build_bim_load_procedures() -> LoadProcedures {
        // BIM devices have their own load mechanism
        LoadProcedures { procedures: vec![] }
    }

    /// Build the Dynamic section with channel and parameter blocks.
    fn build_dynamic_section(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
    ) -> Result<DynamicSection, GeneratorError> {
        let co_start_index = mask_family.com_object_start_index();
        let mut items = vec![];

        // Build a set of union selector names to skip them in regular params
        let union_selector_names: std::collections::HashSet<String> = config
            .union_fields
            .map(|fields| {
                fields
                    .iter()
                    .map(|f| format!("{}_selector", f.field_name))
                    .collect()
            })
            .unwrap_or_default();

        // Add ParameterRefRefs for regular parameters
        let mut param_counter = 1usize;
        for param in config.params {
            // Skip union selector parameters
            if union_selector_names.contains(param.base.name) {
                continue;
            }

            let param_id = format!("{}_P-{}", app_id, param_counter);
            // The ref_id must match what we generate in build_parameter_refs
            let ref_id = format!("{}_R-{}", param_id, param_counter);

            items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                ref_id,
                internal_description: Some("generated".to_string()),
            }));
            param_counter += 1;
        }

        // Add union fields with choose/when for conditional visibility
        if let Some(union_fields) = config.union_fields {
            // Count non-selector params for ref_counter
            let non_selector_param_count = config
                .params
                .iter()
                .filter(|p| !union_selector_names.contains(p.base.name))
                .count();
            let mut ref_counter = non_selector_param_count + 1;
            let mut up_counter = 1u32; // Sequential UP- counter matching build_union and build_parameter_refs

            for field in union_fields {
                // First, add the selector parameter (always visible)
                // Uses sequential UP-N ID matching build_union and build_parameter_refs
                let selector_id = format!("{}_UP-{}", app_id, up_counter);
                let selector_ref_id = format!("{}_R-{}", selector_id, ref_counter);

                items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                    ref_id: selector_ref_id.clone(),
                    internal_description: Some("generated".to_string()),
                }));
                ref_counter += 1;
                up_counter += 1;

                // Build a map of discriminant_value -> (display_name, param_ref_ids)
                let mut variant_refs: std::collections::HashMap<i64, (&str, Vec<String>)> =
                    std::collections::HashMap::new();

                // Get display names from selector_variants (keyed by discriminant value)
                for variant in field.selector_variants {
                    variant_refs.insert(variant.value, (variant.text, vec![]));
                }

                // Assign parameter refs to their variants (matching by discriminant value)
                // Uses sequential UP-N IDs matching build_union
                for param in field.union_info.variant_params {
                    let param_id = format!("{}_UP-{}", app_id, up_counter);
                    let param_ref_id = format!("{}_R-{}", param_id, ref_counter);

                    // Match by variant_value (discriminant), not by name
                    if let Some((_, refs)) = variant_refs.get_mut(&param.variant_value) {
                        refs.push(param_ref_id);
                    }
                    ref_counter += 1;
                    up_counter += 1;
                }

                // Build the choose/when structure
                let mut whens = vec![];

                // Sort variants by discriminant value for consistent output
                let mut sorted_variants: Vec<_> = variant_refs.into_iter().collect();
                sorted_variants.sort_by_key(|(disc, _)| *disc);

                for (discriminant, (display_name, param_ref_ids)) in sorted_variants {
                    // Create when clause for this variant
                    let when_items: Vec<WhenItem> = param_ref_ids
                        .into_iter()
                        .map(|ref_id| {
                            WhenItem::ParameterRefRef(ParameterRefRef {
                                ref_id,
                                internal_description: Some("generated".to_string()),
                            })
                        })
                        .collect();

                    whens.push(When {
                        test: Some(discriminant.to_string()),
                        default: None,
                        internal_description: Some(format!("{} parameters", display_name)),
                        items: when_items,
                    });
                }

                items.push(ParameterBlockItem::Choose(Choose {
                    param_ref_id: selector_ref_id,
                    whens,
                }));
            }
        }

        // Add ComObjectRefRefs
        for (i, co) in config.comm_objects.iter().enumerate() {
            let adjusted_index = co.index + co_start_index;
            let co_id = format!("{}_O-{}", app_id, adjusted_index);
            let ref_id = format!("{}_R-{}", co_id, i + 1);

            items.push(ParameterBlockItem::ComObjectRefRef(ComObjectRefRef {
                ref_id,
                internal_description: Some("generated".to_string()),
            }));
        }

        Ok(DynamicSection {
            channels: vec![Channel {
                id: format!("{}_CH-1", app_id),
                name: config.channel_name.to_string(),
                number: Some("1".to_string()),
                internal_description: Some("generated".to_string()),
                parameter_blocks: vec![ParameterBlock {
                    id: format!("{}_PB-1", app_id),
                    name: config.name.to_string(),
                    internal_description: Some("generated".to_string()),
                    items,
                }],
            }],
        })
    }

    /// Serialize the KNX document to XML string.
    fn serialize(knx: &Knx) -> Result<String, GeneratorError> {
        let mut buffer = String::new();
        buffer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        let mut serializer = quick_xml::se::Serializer::new(&mut buffer);
        serializer.indent(' ', 2);

        serde::Serialize::serialize(knx, serializer)
            .map_err(|e| GeneratorError::Serialization(e.to_string()))?;

        Ok(buffer)
    }
}

// ============================================================================
// Hardware MTXML Generator
// ============================================================================

/// Generator for creating Hardware MTXML files.
pub struct HardwareGenerator;

impl HardwareGenerator {
    /// Generate a complete Hardware MTXML document from the configuration.
    pub fn generate(config: &ApplicationProgramConfig) -> Result<String, GeneratorError> {
        let knx = Self::build_hardware_knx(config);
        Self::serialize(&knx)
    }

    /// Build the complete Hardware KNX document structure.
    fn build_hardware_knx(config: &ApplicationProgramConfig) -> HardwareKnx {
        let manufacturer_id = format!("M-{:04X}", config.device.manufacturer_id);
        let serial_hex = config
            .serial_number
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();

        // Hardware ID: M-XXXX_H-<serial>-<version>
        let hardware_id = format!("{}_H-{}-{}", manufacturer_id, serial_hex, config.hardware_version);

        // Application ID for reference
        let app_id = format!(
            "{}_A-{:04X}-{:02X}-0000",
            manufacturer_id, config.device.application_id, config.device.application_version
        );

        // Hardware2Program ID: <hardware_id>_HP-<app_number>-<app_version>-0000
        let h2p_id = format!(
            "{}_HP-{:04X}-{:02X}-0000",
            hardware_id, config.device.application_id, config.device.application_version
        );

        // Product ID: <hardware_id>_P-<order_number>
        let product_id = format!("{}_P-{}", hardware_id, config.order_number);

        let mut knx = HardwareKnx::default();
        knx.manufacturer_data.manufacturer.ref_id = manufacturer_id;
        knx.manufacturer_data.manufacturer.hardware.hardware = Hardware {
            id: hardware_id,
            name: config.hardware_name.to_string(),
            serial_number: serial_hex,
            version_number: config.hardware_version,
            has_individual_address: true,
            has_application_program: true,
            products: Products {
                product: Product {
                    id: product_id,
                    text: config.product_name.to_string(),
                    order_number: config.order_number.to_string(),
                    is_rail_mounted: config.is_rail_mounted,
                    default_language: "en-US".to_string(),
                },
            },
            hardware2programs: Hardware2Programs {
                hardware2program: Hardware2Program {
                    id: h2p_id,
                    medium_types: medium_type_from_mask(config.device.mask_version).to_string(),
                    application_program_ref: ApplicationProgramRef { ref_id: app_id },
                },
            },
        };

        knx
    }

    /// Serialize the Hardware KNX document to XML string.
    fn serialize(knx: &HardwareKnx) -> Result<String, GeneratorError> {
        let mut buffer = String::new();
        buffer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        let mut serializer = quick_xml::se::Serializer::new(&mut buffer);
        serializer.indent(' ', 2);

        serde::Serialize::serialize(knx, serializer)
            .map_err(|e| GeneratorError::Serialization(e.to_string()))?;

        Ok(buffer)
    }
}

// ============================================================================
// Catalog MTXML Generator
// ============================================================================

/// Generator for creating Catalog MTXML files.
pub struct CatalogGenerator;

impl CatalogGenerator {
    /// Generate a complete Catalog MTXML document from the configuration.
    pub fn generate(config: &ApplicationProgramConfig) -> Result<String, GeneratorError> {
        let knx = Self::build_catalog_knx(config);
        Self::serialize(&knx)
    }

    /// Build the complete Catalog KNX document structure.
    fn build_catalog_knx(config: &ApplicationProgramConfig) -> CatalogKnx {
        let manufacturer_id = format!("M-{:04X}", config.device.manufacturer_id);
        let serial_hex = config
            .serial_number
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();

        // Hardware ID: M-XXXX_H-<serial>-<version>
        let hardware_id = format!("{}_H-{}-{}", manufacturer_id, serial_hex, config.hardware_version);

        // Hardware2Program ID
        let h2p_id = format!(
            "{}_HP-{:04X}-{:02X}-0000",
            hardware_id, config.device.application_id, config.device.application_version
        );

        // Product ID
        let product_id = format!("{}_P-{}", hardware_id, config.order_number);

        // Catalog Section ID
        let section_id = format!("{}_CS-1", manufacturer_id);

        // Catalog Item ID: <h2p_id>_CI-<order_number>-1
        let catalog_item_id = format!("{}_CI-{}-1", h2p_id, config.order_number);

        let mut knx = CatalogKnx::default();
        knx.manufacturer_data.manufacturer.ref_id = manufacturer_id;
        knx.manufacturer_data.manufacturer.catalog.catalog_section = CatalogSection {
            id: section_id,
            name: config.catalog_section.to_string(),
            number: "1".to_string(),
            default_language: "en-US".to_string(),
            catalog_item: CatalogItem {
                id: catalog_item_id,
                name: config.product_name.to_string(),
                number: "1".to_string(),
                product_ref_id: product_id,
                hardware2program_ref_id: h2p_id,
                default_language: "en-US".to_string(),
            },
        };

        knx
    }

    /// Serialize the Catalog KNX document to XML string.
    fn serialize(knx: &CatalogKnx) -> Result<String, GeneratorError> {
        let mut buffer = String::new();
        buffer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        let mut serializer = quick_xml::se::Serializer::new(&mut buffer);
        serializer.indent(' ', 2);

        serde::Serialize::serialize(knx, serializer)
            .map_err(|e| GeneratorError::Serialization(e.to_string()))?;

        Ok(buffer)
    }
}

/// Errors that can occur during MTXML generation.
#[derive(Debug)]
pub enum GeneratorError {
    /// Error during XML serialization
    Serialization(String),
}

impl std::fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeneratorError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for GeneratorError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_app_id() {
        let device = DeviceDescriptor {
            mask_version: 0x57B0,
            manufacturer_id: 0x00FA,
            hardware_type: [0; 6],
            application_id: 0x0200,
            application_version: 0x01,
            max_address_table_entries: 16,
            max_association_table_entries: 16,
            max_com_objects: 8,
        };

        let app_id = MtxmlGenerator::format_app_id(&device);
        assert_eq!(app_id, "M-00FA_A-0200-01-0000");
    }

    #[test]
    fn test_generate_empty_system_b() {
        let config = ApplicationProgramConfig {
            name: "TestDevice",
            device: &DeviceDescriptor {
                mask_version: 0x57B0,
                manufacturer_id: 0x00FA,
                hardware_type: [0; 6],
                application_id: 0x0200,
                application_version: 0x01,
                max_address_table_entries: 16,
                max_association_table_entries: 16,
                max_com_objects: 8,
            },
            params: &[],
            param_defaults: &[],
            comm_objects: &[],
            union_fields: None,
            channel_name: "General",
            absolute_segment_address: None,
            serial_number: [0x00, 0xFA, 0x00, 0x00, 0x00, 0x01],
            hardware_version: 1,
            hardware_name: "Test Hardware",
            product_name: "Test Product",
            order_number: "TEST-001",
            is_rail_mounted: false,
            catalog_section: "Test Section",
        };

        let xml = MtxmlGenerator::generate(&config).unwrap();
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("TestDevice"));
        assert!(xml.contains("MV-57B0"));
        assert!(xml.contains("M-00FA_A-0200-01-0000"));
        assert!(xml.contains("MergedProcedure")); // System B uses MergedProcedure
        assert!(xml.contains("RelativeSegment")); // System B uses relative segments
    }

    #[test]
    fn test_generate_empty_system_7() {
        let config = ApplicationProgramConfig {
            name: "System7Device",
            device: &DeviceDescriptor {
                mask_version: 0x0705,
                manufacturer_id: 0x00FA,
                hardware_type: [0; 6],
                application_id: 0x0100,
                application_version: 0x01,
                max_address_table_entries: 16,
                max_association_table_entries: 16,
                max_com_objects: 8,
            },
            params: &[],
            param_defaults: &[],
            comm_objects: &[],
            union_fields: None,
            channel_name: "General",
            absolute_segment_address: Some(0x4000),
            serial_number: [0x00, 0xFA, 0x00, 0x00, 0x00, 0x02],
            hardware_version: 1,
            hardware_name: "System 7 Hardware",
            product_name: "System 7 Product",
            order_number: "SYS7-001",
            is_rail_mounted: true,
            catalog_section: "Test Section",
        };

        let xml = MtxmlGenerator::generate(&config).unwrap();
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("System7Device"));
        assert!(xml.contains("MV-0705"));
        assert!(xml.contains("ProductProcedure")); // System 7 uses ProductProcedure
        assert!(xml.contains("AbsoluteSegment")); // System 7 uses absolute segments
    }

    #[test]
    fn test_mask_family_detection() {
        assert_eq!(MaskFamily::from_mask_version(0x57B0), MaskFamily::SystemB);
        assert_eq!(MaskFamily::from_mask_version(0x07B0), MaskFamily::SystemB);
        assert_eq!(MaskFamily::from_mask_version(0x0705), MaskFamily::System7);
        assert_eq!(MaskFamily::from_mask_version(0x0701), MaskFamily::System7);
        assert_eq!(MaskFamily::from_mask_version(0x0912), MaskFamily::Bim);
        assert_eq!(MaskFamily::from_mask_version(0x0920), MaskFamily::BimM);
    }
}
