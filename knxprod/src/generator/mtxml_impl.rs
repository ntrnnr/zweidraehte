pub struct MtxmlGenerator;

impl MtxmlGenerator {
    /// Generate a complete KNX MTXML document from the configuration.
    ///
    /// This method builds the KNX document, validates all references, and then
    /// serializes to XML. If any references are invalid (e.g., a ParameterRefRef
    /// refers to a non-existent ParameterRef), an error is returned.
    ///
    /// The `schema_version` parameter controls the xmlns namespace and tool version
    /// in the generated XML. If `None`, defaults to V20.
    pub fn generate(
        config: &ApplicationProgramConfig,
        schema_version: Option<KnxSchemaVersion>,
    ) -> Result<String, GeneratorError> {
        let knx = Self::build_knx(config, schema_version)?;

        // Validate all references before serialization
        Self::validate(&knx)?;

        Self::serialize(&knx)
    }

    /// Build the complete KNX document structure.
    fn build_knx(
        config: &ApplicationProgramConfig,
        schema_version: Option<KnxSchemaVersion>,
    ) -> Result<Knx, GeneratorError> {
        let app_id = Self::format_app_id(config);

        let mut knx = Knx::default();
        // Set schema version namespace and tool version if specified
        if let Some(version) = schema_version {
            knx.xmlns = version.namespace_url();
            knx.tool_version = version.tool_version().to_string();
        }
        knx.manufacturer_data.manufacturer.ref_id = format!("M-{:04X}", config.device.manufacturer_id);
        knx.manufacturer_data
            .manufacturer
            .application_programs
            .programs
            .push(Self::build_application_program(config, &app_id)?);

        // Build Languages at the Manufacturer level (not inside ApplicationProgram).
        // Per XSD, Languages is a child of Manufacturer, after ApplicationPrograms.
        if let Some(translations) = config.translations {
            knx.manufacturer_data.manufacturer.languages =
                Self::build_languages(config, &app_id, translations)?;
        }

        Ok(knx)
    }

    /// Format the application ID string.
    fn format_app_id(config: &ApplicationProgramConfig) -> String {
        let hash = config.application_hash.unwrap_or("0000");
        format!(
            "M-{:04X}_A-{:04X}-{:02X}-{}",
            config.device.manufacturer_id, config.device.application_id, config.device.application_version, hash
        )
    }

    /// Build the ApplicationProgram element.
    fn build_application_program(
        config: &ApplicationProgramConfig,
        app_id: &str,
    ) -> Result<ApplicationProgram, GeneratorError> {
        let mask_family = config.mask_family();

        let mut app = ApplicationProgram {
            id: app_id.to_string(),
            application_number: config.device.application_id,
            application_version: config.device.application_version,
            mask_version: format!("MV-{:04X}", config.device.mask_version.as_u16()),
            name: config.name.to_string(),
            load_procedure_style: mask_family.load_procedure_style().to_string(),
            non_reg_relevant_data_version: config.non_reg_relevant_data_version,
            replaces_versions: config.replaces_versions.map(|s| s.to_string()),
            hash: config.application_data_hash.map(|s| s.to_string()),
            ..Default::default()
        };

        // Build Static section
        app.static_section = Self::build_static_section(config, app_id, mask_family)?;

        // Build ModuleDefs (placed between Static and Dynamic per XSD schema)
        app.module_defs = Self::build_module_defs(config, app_id);

        // Build Dynamic section - use page layout if provided, otherwise auto-generate
        let dynamic = if let Some(ref layout) = config.page_layout {
            Self::build_dynamic_section_from_layout(config, app_id, mask_family, layout)?
        } else {
            Self::build_dynamic_section(config, app_id, mask_family)?
        };
        app.dynamic = Some(dynamic);

        Ok(app)
    }

    /// Build the Languages section from translation definitions.
    ///
    /// Returns an error if any translation references an unknown parameter, enum variant,
    /// or communication object.
    fn build_languages(
        config: &ApplicationProgramConfig,
        app_id: &str,
        translations: &[EtsTranslation],
    ) -> Result<Option<Languages>, GeneratorError> {
        if translations.is_empty() {
            return Ok(None);
        }

        // Group translations by language
        let mut by_language: HashMap<&str, Vec<&EtsTranslation>> = HashMap::new();
        for trans in translations {
            by_language.entry(trans.language).or_default().push(trans);
        }

        let mut languages = Languages::new();

        for (lang_id, trans_list) in by_language {
            let mut language = Language::new(lang_id);
            let mut unit = TranslationUnit::new(app_id);

            // Group translations by ref_path to create TranslationElements
            let mut by_ref_path: HashMap<&str, Vec<&EtsTranslation>> = HashMap::new();
            for trans in trans_list {
                by_ref_path.entry(trans.ref_path).or_default().push(trans);
            }

            for (ref_path, trans_items) in by_ref_path {
                // Convert ref_path to actual XML RefId, validating the reference exists
                let ref_id = Self::translation_ref_path_to_id(config, app_id, ref_path, lang_id)?;

                let mut element = TranslationElement::new(&ref_id);
                for trans in trans_items {
                    match trans.attribute {
                        TranslationAttribute::Text => {
                            element = element.with_text(trans.text);
                        }
                        TranslationAttribute::SuffixText => {
                            element = element.with_suffix(trans.text);
                        }
                        TranslationAttribute::FunctionText => {
                            element = element.with_function(trans.text);
                        }
                        TranslationAttribute::Name => {
                            element = element.with_name(trans.text);
                        }
                    }
                }
                unit.add_element(element);
            }

            language.add_unit(unit);
            languages.add_language(language);
        }

        Ok(Some(languages))
    }

    /// Convert a translation ref_path to an actual XML RefId.
    ///
    /// Ref paths have formats:
    /// - `"EnumType::Variant"` -> `"{app_id}_PT-{EnumType}_EN-{variant_value}"`
    /// - `"param::field_name"` -> `"{app_id}_P-{param_num}"`
    /// - `"obj::object_name"` -> `"{app_id}_O-{object_index}"`
    ///
    /// Returns an error if the reference cannot be resolved to an existing entity.
    fn translation_ref_path_to_id(
        config: &ApplicationProgramConfig,
        app_id: &str,
        ref_path: &str,
        language: &str,
    ) -> Result<String, GeneratorError> {
        if let Some(obj_name) = ref_path.strip_prefix("obj::") {
            // Find comm object by name - check device-level objects
            if let Some(obj) = config.comm_objects.iter().find(|o| o.name == obj_name) {
                return Ok(format!("{}_O-{}", app_id, obj.index));
            }
            // Check module objects if modules are defined
            if let Some(ref modules) = config.modules {
                for module_def in modules.definitions() {
                    if let Some(objs) = module_def.comm_objects {
                        if objs.iter().any(|o| o.name == obj_name) {
                            // Module comm object - use name-based ref
                            return Ok(format!("{}_O-{}", app_id, obj_name));
                        }
                    }
                }
            }
            // Object not found
            return Err(GeneratorError::UnknownTranslation {
                language: language.to_string(),
                ref_path: ref_path.to_string(),
                kind: "communication object".to_string(),
            });
        }

        if let Some(param_name) = ref_path.strip_prefix("param::") {
            // Find parameter number by name in device-level params
            if let Some(num) = config.find_param_num_by_name(param_name) {
                return Ok(format!("{}_P-{}", app_id, num));
            }
            // Check module params if modules are defined
            if let Some(ref modules) = config.modules {
                for module_def in modules.definitions() {
                    // Check module params
                    if let Some(params) = module_def.params {
                        if params.iter().any(|p: &_| p.base.name == param_name) {
                            // Module param - use name-based ref
                            return Ok(format!("{}_P-{}", app_id, param_name));
                        }
                    }
                    // Check module virtual params
                    if let Some(vparams) = module_def.virtual_params {
                        if vparams.iter().any(|p: &_| p.base.name == param_name) {
                            return Ok(format!("{}_P-{}", app_id, param_name));
                        }
                    }
                }
            }
            // Parameter not found
            return Err(GeneratorError::UnknownTranslation {
                language: language.to_string(),
                ref_path: ref_path.to_string(),
                kind: "parameter".to_string(),
            });
        }

        // Enum variant format: "EnumType::Variant"
        if ref_path.contains("::") {
            let parts: Vec<&str> = ref_path.split("::").collect();
            if parts.len() == 2 {
                let enum_type = parts[0];
                let variant = parts[1];

                // For enum translations, we need to find the variant value
                // The ref_id format is {app_id}_PT-{EnumType}_EN-{value}
                // We search through all params to find enum variants with this type/variant name
                if let Some(value) = Self::find_enum_variant_value(config, enum_type, variant) {
                    return Ok(format!("{}_PT-{}_EN-{}", app_id, enum_type, value));
                }

                // Enum variant not found
                return Err(GeneratorError::UnknownTranslation {
                    language: language.to_string(),
                    ref_path: ref_path.to_string(),
                    kind: "enum variant".to_string(),
                });
            }
        }

        // Unknown format
        Err(GeneratorError::UnknownTranslation {
            language: language.to_string(),
            ref_path: ref_path.to_string(),
            kind: "unknown".to_string(),
        })
    }

    /// Find an enum variant value by searching through parameter definitions.
    ///
    /// The `variant_name` is the Rust identifier (e.g., "Fast", "NotActive").
    /// We match case-insensitively against the display text (e.g., "fast", "not active")
    /// since that's more likely to match.
    ///
    /// The `enum_type` is the Rust type name from the translation macro.
    /// We try to match it against the type_name (may differ due to #[ets(type_name = "...")])
    /// or just search by variant text if type matching fails.
    fn find_enum_variant_value(config: &ApplicationProgramConfig, enum_type: &str, variant_name: &str) -> Option<i64> {
        let variant_lower = variant_name.to_lowercase();
        let type_lower = enum_type.to_lowercase();

        // Helper to check if a type_name matches (case-insensitive, handles underscores)
        let type_matches = |type_name: Option<&str>| -> bool {
            if let Some(tn) = type_name {
                let tn_lower = tn.to_lowercase();
                // Direct match
                if tn_lower == type_lower {
                    return true;
                }
                // Match ignoring underscores (GEDPT_Switch vs GedptSwitch)
                if tn_lower.replace('_', "") == type_lower.replace('_', "") {
                    return true;
                }
            }
            false
        };

        // Helper to check if variant matches
        let variant_matches = |text: &str| -> bool {
            let text_lower = text.to_lowercase();
            // Direct match
            if text_lower == variant_lower {
                return true;
            }
            // Match removing spaces (NotActive -> notactive vs "not active")
            let text_no_spaces = text_lower.replace(' ', "");
            if text_no_spaces == variant_lower {
                return true;
            }
            false
        };

        // Collect all enum variants from all sources
        let mut all_variants: Vec<(&Option<&str>, &[zweidraehte::ets::EtsEnumVariant])> = Vec::new();

        // Device-level params
        for param in config.all_params() {
            if let Some(variants) = param.enum_variants {
                all_variants.push((&param.base.type_name, variants));
            }
        }

        // Module params
        if let Some(ref modules) = config.modules {
            for module_def in modules.definitions() {
                if let Some(params) = module_def.params {
                    for param in params.iter() {
                        if let Some(variants) = param.enum_variants {
                            all_variants.push((&param.base.type_name, variants));
                        }
                    }
                }
            }
        }

        // First pass: try to match by both type AND variant text
        for (param_type_name, variants) in all_variants.iter() {
            if type_matches(**param_type_name) {
                for variant in variants.iter() {
                    if variant_matches(variant.text) {
                        return Some(variant.value);
                    }
                }
            }
        }

        // Second pass: try to match by variant text only (type_name may be None)
        // This is useful when enum fields don't have explicit type_name set
        for (_param_type_name, variants) in all_variants.iter() {
            for variant in variants.iter() {
                if variant_matches(variant.text) {
                    return Some(variant.value);
                }
            }
        }

        // Also check union fields
        if let Some(union_fields) = config.union_fields {
            for union_field in union_fields.iter() {
                // Check selector variants (the union's discriminant enum)
                for variant in union_field.selector_variants.iter() {
                    if variant_matches(variant.text) {
                        return Some(variant.value);
                    }
                }

                // Check variant params (nested enums within union variants)
                for variant_param in union_field.union_info.variant_params.iter() {
                    if let Some(variants) = variant_param.enum_variants {
                        if type_matches(variant_param.param.type_name) {
                            for variant in variants.iter() {
                                if variant_matches(variant.text) {
                                    return Some(variant.value);
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Build the Static section with all components.
    fn build_static_section(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
    ) -> Result<StaticSection, GeneratorError> {
        // Calculate the stripped param size (excluding no_memory virtual parameters)
        let stripped_defaults = strip_no_memory_bytes(config.param_defaults, config.params);
        let param_size = stripped_defaults.len() as u32;

        // Build code segment ID based on mask family (for parameter references)
        let code_segment_id = match mask_family.data_segment_type() {
            DataSegmentType::Relative => format!("{}_RS-04-00000", app_id),
            DataSegmentType::Absolute => {
                // For System 7 with full layout, use the first EEPROM segment
                if let Some(ref layout) = config.system7_layout {
                    // Find the EEPROM segment (usually the parameter segment)
                    let eeprom_seg = layout
                        .segments
                        .iter()
                        .find(|s| s.memory_type == Some("EEPROM") && s.data.is_some())
                        .or_else(|| layout.segments.first());
                    if let Some(seg) = eeprom_seg {
                        format!("{}_AS-{}", app_id, seg.name)
                    } else {
                        format!("{}_AS-{:04X}", app_id, config.absolute_segment_address.unwrap_or(0))
                    }
                } else {
                    format!("{}_AS-{:04X}", app_id, config.absolute_segment_address.unwrap_or(0))
                }
            }
        };

        // Build address/association tables only for masks that support them
        let (address_table, association_table) = if mask_family.generates_address_tables() {
            // For System 7, use code segments from the layout if available
            let (addr_seg, assoc_seg) = if let Some(ref layout) = config.system7_layout {
                (
                    Some(format!("{}_AS-{}", app_id, layout.address_table_segment)),
                    Some(format!("{}_AS-{}", app_id, layout.association_table_segment)),
                )
            } else {
                (None, None)
            };
            (
                Some(AddressTable {
                    code_segment: addr_seg,
                    offset: Some(0),
                    max_entries: config.device.max_address_table_entries,
                }),
                Some(AssociationTable {
                    code_segment: assoc_seg,
                    offset: Some(0),
                    max_entries: config.device.max_association_table_entries,
                }),
            )
        } else {
            (None, None)
        };

        // Count selector usages from page layout for creating multiple ParameterRefs
        // We need the comm_obj_ref_map to count PageItem::Obj usages
        let (selector_usage_counts, union_variant_texts) = if let Some(layout) = config.page_layout.as_ref() {
            let comm_obj_ref_map = Self::build_comm_object_ref_map(config, app_id, mask_family);
            let counts = count_selector_usages_with_objects(layout, &comm_obj_ref_map);
            let texts = collect_union_variant_texts(layout);
            (Some(counts), Some(texts))
        } else {
            (None, None)
        };

        // Build ParameterRefs first to get the param_name -> ref_num mapping for text param refs
        let (parameter_refs, param_ref_nums) =
            Self::build_parameter_refs(config, app_id, selector_usage_counts.as_ref(), union_variant_texts.as_ref());

        // Build ComObject table only for masks that support it
        let (com_object_table, com_object_refs) = if mask_family.has_com_object_table() {
            let table = Self::build_com_object_table(config, app_id, mask_family);
            let refs = Self::build_com_object_refs(config, app_id, mask_family, &param_ref_nums);
            // XSD requires ComObjectRefs to have at least one child if present
            let refs_opt = if refs.refs.is_empty() { None } else { Some(refs) };
            (Some(table), refs_opt)
        } else {
            (None, None)
        };

        Ok(StaticSection {
            code: Some(Self::build_code(config, app_id, param_size, mask_family)),
            parameter_types: Some(Self::build_parameter_types(config, app_id)),
            parameters: Some(Self::build_parameters(config, app_id, &code_segment_id)),
            parameter_refs: Some(parameter_refs),
            com_object_table,
            com_object_refs,
            address_table,
            association_table,
            load_procedures: {
                let procs = Self::build_load_procedures(config, param_size, mask_family);
                if procs.procedures.is_empty() {
                    None
                } else {
                    Some(procs)
                }
            },
            extension: Some(Extension {
                baggages: config.baggages.map_or(Vec::new(), |b| baggages_to_refs(config.device.manufacturer_id, b)),
            }),
            messages: None,
            options: Some(Options { comparable: Some(true), reconstructable: Some(true) }),
        })
    }

    /// Build ModuleDefs from the module collection if present.
    fn build_module_defs(config: &ApplicationProgramConfig, app_id: &str) -> Option<ModuleDefs> {
        let modules = config.modules.as_ref()?;
        if modules.is_empty() {
            return None;
        }

        let mut module_defs = Vec::new();

        for (def_idx, def) in modules.definitions().iter().enumerate() {
            let module_id = format!("{}_MD-{}", app_id, def_idx + 1);

            // Compute allocates values from params/objects for role-based arguments
            let param_size: u32 = def
                .params
                .map(|p| {
                    p.iter()
                        // Exclude no_memory (virtual) parameters - they don't occupy device memory
                        .filter(|param| !param.base.no_memory)
                        .map(|param| (param.base.size_bits as u32 + 7) / 8)
                        .sum()
                })
                .unwrap_or(0);
            let object_count: u32 = def.comm_objects.map(|o| o.len() as u32).unwrap_or(0);

            // Build argument definitions
            let arguments = if def.arguments.is_empty() {
                None
            } else {
                let args: Vec<ModuleDefArgument> = def
                    .arguments
                    .iter()
                    .enumerate()
                    .map(|(arg_idx, arg)| {
                        // Compute allocates based on role
                        let allocates = match arg.role {
                            ModuleArgRole::ParamOffset => param_size,
                            ModuleArgRole::ObjectNumber => object_count,
                            _ => arg.allocates,
                        };
                        ModuleDefArgument {
                            id: format!("{}_A-{}", module_id, arg_idx + 1),
                            name: arg.name.to_string(),
                            allocates,
                            alignment: arg.alignment,
                            arg_type: match arg.arg_type {
                                ModuleArgType::Numeric => None, // Default, no need to specify
                                ModuleArgType::Text => Some("Text".to_string()),
                            },
                        }
                    })
                    .collect();
                Some(ModuleDefArguments { arguments: args })
            };

            // Build the BaseOffset argument ID using role-based lookup
            let base_offset_arg_id =
                def.arg_index_by_role(ModuleArgRole::ParamOffset).map(|idx| format!("{}_A-{}", module_id, idx + 1));

            // Build the BaseNumber argument ID using role-based lookup
            let base_number_arg_id =
                def.arg_index_by_role(ModuleArgRole::ObjectNumber).map(|idx| format!("{}_A-{}", module_id, idx + 1));

            // Build the BaseValue argument ID using role-based lookup
            let base_value_arg_id =
                def.arg_index_by_role(ModuleArgRole::ValueBase).map(|idx| format!("{}_A-{}", module_id, idx + 1));

            // Build module-internal parameters if provided (including picture params)
            let (module_params, module_param_refs, picture_param_map) = Self::build_module_parameters(
                config,
                app_id,
                &module_id,
                def,
                base_offset_arg_id.as_deref(),
                base_value_arg_id.as_deref(),
            );

            // Build the TextParameterRefId for {{0}} text template substitution
            // This references the parameter ref of the text parameter within this module
            // Auto-detect text source parameter via #[ets(text_source)] attribute
            // Must search both virtual_params (first) and regular params, matching XML generation order
            let virtual_params = def.virtual_params.unwrap_or(&[]);
            let regular_params = def.params.unwrap_or(&[]);

            // First check virtual params for text_source
            let text_param_num = zweidraehte::ets::EtsParamDefExt::find_text_source_index(virtual_params)
                .map(|idx| idx + 1) // 1-based param number
                .or_else(|| {
                    // Then check regular params (offset by virtual_params length)
                    zweidraehte::ets::EtsParamDefExt::find_text_source_index(regular_params)
                        .map(|idx| virtual_params.len() + idx + 1)
                });

            let text_param_ref_id = text_param_num.map(|param_num| {
                // Reference the ParameterRef ID within this module
                format!("{}_P-{}_R-{}", module_id, param_num, param_num)
            });

            // Build module-internal communication objects if provided
            let (module_com_objects, module_com_object_refs) = Self::build_module_com_objects(
                app_id,
                &module_id,
                def,
                base_number_arg_id.as_deref(),
                text_param_ref_id.as_deref(),
            );

            // Build module Dynamic section with a ParameterBlock containing all parameter refs
            let module_dynamic =
                Self::build_module_dynamic(&module_id, def, text_param_ref_id.as_deref(), &picture_param_map);

            module_defs.push(ModuleDef {
                id: module_id,
                name: def.name.clone(),
                internal_description: def.internal_description.clone(),
                arguments,
                static_section: ModuleDefStatic {
                    parameters: module_params,
                    parameter_refs: module_param_refs,
                    com_objects: module_com_objects,
                    com_object_refs: module_com_object_refs,
                },
                dynamic: module_dynamic,
            });
        }

        Some(ModuleDefs { module_defs })
    }

    /// Build parameters for a module definition.
    ///
    /// Creates the Parameters and ParameterRefs elements for the module's Static section.
    /// Parameters use `BaseOffset` to reference the module's parameter base argument,
    /// and `BaseValue` to reference the module's value base argument for relative values.
    ///
    /// Returns (Parameters, ParameterRefs, picture_param_map) where picture_param_map
    /// maps baggage names to their assigned param numbers for use in layout generation.
    #[allow(unused_variables)]
    fn build_module_parameters(
        config: &ApplicationProgramConfig,
        app_id: &str,
        module_id: &str,
        def: &StoredModuleDef,
        base_offset_arg_id: Option<&str>,
        base_value_arg_id: Option<&str>,
    ) -> (Option<Parameters>, Option<ParameterRefs>, HashMap<String, usize>) {
        // Combine virtual params (first) and regular params
        // Virtual params come first so that text_source param gets the right index for {{0}}
        let virtual_params = def.virtual_params.unwrap_or(&[]);
        let regular_params = def.params.unwrap_or(&[]);

        // Collect pictures from the module's layout
        let mut pictures = Vec::new();
        let mut seen_pictures = std::collections::HashSet::new();
        if let Some(ref layout) = def.page_layout {
            collect_pictures_from_module_layout(layout, &mut pictures, &mut seen_pictures);
        }

        if virtual_params.is_empty() && regular_params.is_empty() && pictures.is_empty() {
            return (None, None, HashMap::new());
        }

        let code_segment_id = format!("{}_RS-04-00000", app_id);
        let mut parameters = Parameters::default();
        let mut parameter_refs = ParameterRefs::default();

        // Process all parameters (virtual + regular)
        let all_params: Vec<_> = virtual_params.iter().chain(regular_params.iter()).collect();

        for (idx, param_ext) in all_params.iter().enumerate() {
            let param = &param_ext.base;
            let param_num = idx + 1;

            // Generate parameter ID within the module
            let param_id = format!("{}_P-{}", module_id, param_num);

            // Get the parameter type ID (reuse the app-level type if available)
            let type_name = Self::param_type_name(param);
            let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));

            // Get default value - use empty string for text parameters
            let default_value: String = if let Some(val) = param_ext.default_value {
                val.to_string()
            } else if param.param_type == zweidraehte::ets::EtsParamType::String {
                String::new() // Empty string for text parameters
            } else {
                "0".to_string()
            };

            // Build memory location with BaseOffset if argument is specified
            // Virtual (no_memory) parameters don't have a Memory element
            let memory = if param.no_memory {
                None
            } else {
                Some(MemoryLocation {
                    code_segment: code_segment_id.clone(),
                    offset: param.offset as u32,
                    bit_offset: param.bit_offset,
                    base_offset: base_offset_arg_id.map(|s| s.to_string()),
                })
            };

            parameters.items.push(ParameterItem::Parameter(Parameter {
                id: param_id.clone(),
                name: param.name.to_string(),
                parameter_type: type_id,
                text: param.display_name.to_string(),
                value: default_value,
                suffix_text: param.suffix.map(|s| s.to_string()),
                access: None,
                base_value: base_value_arg_id.map(|s| s.to_string()),
                memory,
                internal_description: None,
            }));

            // Generate parameter reference
            let ref_id = format!("{}_R-{}", param_id, param_num);
            parameter_refs.refs.push(ParameterRef {
                id: ref_id,
                ref_id: param_id,
                text: None,
                internal_description: None,
                access: None,
                value: None,
                base_value: None,
            });
        }

        // Track picture param numbers for layout generation
        let mut picture_param_map = HashMap::new();

        // Add picture parameters after regular params
        let base_param_count = all_params.len();
        for (pic_idx, pic) in pictures.iter().enumerate() {
            let param_num = base_param_count + pic_idx + 1;
            let param_id = format!("{}_P-{}", module_id, param_num);

            // Create the picture type name and ID (reuse app-level type)
            let type_name = format!("tPIC_{}", pic.baggage_name.replace('.', "_"));
            let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));

            // Picture parameter - no memory, no value
            parameters.items.push(ParameterItem::Parameter(Parameter {
                id: param_id.clone(),
                name: format!("Pic_{}", pic.baggage_name.replace('.', "_")),
                parameter_type: type_id,
                text: String::new(),
                value: String::new(),
                suffix_text: None,
                access: None,
                base_value: None,
                memory: None, // Pictures are virtual - no device memory
                internal_description: None,
            }));

            // Generate parameter reference for the picture
            let ref_id = format!("{}_R-{}", param_id, param_num);
            parameter_refs.refs.push(ParameterRef {
                id: ref_id,
                ref_id: param_id,
                text: None,
                internal_description: None,
                access: None,
                value: None,
                base_value: None,
            });

            // Track the param number for this picture
            picture_param_map.insert(pic.baggage_name.clone(), param_num);
        }

        (Some(parameters), if parameter_refs.refs.is_empty() { None } else { Some(parameter_refs) }, picture_param_map)
    }

    /// Build communication objects for a module definition.
    ///
    /// Creates the ComObjects and ComObjectRefs elements for the module's Static section.
    /// Note: Module static sections use `<ComObjects>` (not `<ComObjectTable>`).
    /// ComObjects use `BaseNumber` to reference the module's object base argument.
    /// ComObjectRefs use `TextParameterRefId` for `{{0}}` text template substitution.
    #[allow(unused_variables)]
    fn build_module_com_objects(
        app_id: &str,
        module_id: &str,
        def: &StoredModuleDef,
        base_number_arg_id: Option<&str>,
        text_param_ref_id: Option<&str>,
    ) -> (Option<ModuleComObjects>, Option<ComObjectRefs>) {
        let objects: &[EtsCommObjectDef] = match def.comm_objects {
            Some(objects) if !objects.is_empty() => objects,
            _ => return (None, None),
        };

        let mut module_com_objects = ModuleComObjects { objects: Vec::new() };
        let mut com_object_refs = ComObjectRefs::default();

        for obj_def in objects.iter() {
            // Module ComObject IDs use a different format: {module_id}_O-{table}-{number}
            let obj_id = format!("{}_O-2-{}", module_id, obj_def.index);

            // Parse flags from bitmask (same as in build_com_object_table)
            let flags = obj_def.default_flags;
            let communication_flag = if flags & 0x04 != 0 { EnableFlag::Enabled } else { EnableFlag::Disabled };
            let read_flag = if flags & 0x08 != 0 { EnableFlag::Enabled } else { EnableFlag::Disabled };
            let write_flag = if flags & 0x10 != 0 { EnableFlag::Enabled } else { EnableFlag::Disabled };
            let transmit_flag = if flags & 0x20 != 0 { EnableFlag::Enabled } else { EnableFlag::Disabled };
            let update_flag = if flags & 0x80 != 0 { EnableFlag::Enabled } else { EnableFlag::Disabled };
            let read_on_init_flag = EnableFlag::Disabled; // Not in bitmask

            module_com_objects.objects.push(ComObject {
                id: obj_id.clone(),
                name: obj_def.name.to_string(),
                text: obj_def.display_name.to_string(),
                number: obj_def.index,
                function_text: obj_def.function_text.to_string(),
                object_size: object_size_to_string(obj_def.size_bits).to_string(),
                datapoint_type: Some(dpt_to_string(obj_def.dpt_main, obj_def.dpt_sub)),
                read_flag,
                write_flag,
                communication_flag,
                transmit_flag,
                update_flag,
                read_on_init_flag,
                priority: None,
                internal_description: None,
                base_number: base_number_arg_id.map(|s| s.to_string()),
            });

            // Generate ComObjectRef with text template support
            let ref_id = format!("{}_R-{}", obj_id, obj_def.index + 1);

            // Use text_template if provided, otherwise use display_name
            let text = obj_def.text_template.map(|t| t.to_string()).unwrap_or_else(|| obj_def.display_name.to_string());

            // Only set TextParameterRefId if we have a text template containing {{0}}
            let text_parameter_ref_id = if obj_def.text_template.map(|t| t.contains("{{0}}")).unwrap_or(false) {
                text_param_ref_id.map(|s| s.to_string())
            } else {
                None
            };

            com_object_refs.refs.push(ComObjectRef {
                id: ref_id,
                ref_id: obj_id,
                name: None,
                text: Some(text),
                function_text: Some(obj_def.function_text.to_string()),
                datapoint_type: Some(dpt_to_string(obj_def.dpt_main, obj_def.dpt_sub)),
                object_size: Some(object_size_to_string(obj_def.size_bits).to_string()),
                text_parameter_ref_id,
                ..Default::default()
            });
        }

        (Some(module_com_objects), if com_object_refs.refs.is_empty() { None } else { Some(com_object_refs) })
    }

    /// Build the Dynamic section for a module definition.
    ///
    /// Creates a ParameterBlock containing ParameterRefRef elements for all
    /// parameters in the module. This defines the UI layout that ETS displays
    /// when the module is active/visible.
    fn build_module_dynamic(
        module_id: &str,
        def: &StoredModuleDef,
        text_param_ref_id: Option<&str>,
        picture_param_map: &HashMap<String, usize>,
    ) -> Option<ModuleDefDynamic> {
        // If a custom page_layout is provided, use it
        if let Some(ref layout) = def.page_layout {
            return Self::build_module_dynamic_from_layout(
                module_id,
                def,
                layout,
                text_param_ref_id,
                picture_param_map,
            );
        }

        // Otherwise, auto-generate a simple layout
        Self::build_default_module_dynamic(module_id, def, text_param_ref_id)
    }

    /// Build module dynamic layout from the new ModulePageLayout structure.
    fn build_module_dynamic_from_layout(
        module_id: &str,
        def: &StoredModuleDef,
        layout: &crate::definition::page_layout::ModulePageLayout,
        text_param_ref_id: Option<&str>,
        picture_param_map: &HashMap<String, usize>,
    ) -> Option<ModuleDefDynamic> {
        use crate::definition::page_layout::ModuleLayoutElement;

        let obj_base_arg_idx =
            def.arg_index_by_role(crate::definition::module::ModuleArgRole::ObjectNumber).unwrap_or(1);

        let mut block_counter = 0u32;
        let mut sep_counter = 0u32;
        let mut dynamic_items = Vec::new();

        for element in &layout.elements {
            match element {
                ModuleLayoutElement::Block(block) => {
                    block_counter += 1;
                    let block_id = format!("{}_PB-{}", module_id, block_counter);
                    let block_items = Self::convert_module_layout_items(
                        module_id,
                        def,
                        obj_base_arg_idx,
                        &block.items,
                        &mut sep_counter,
                        picture_param_map,
                    );
                    // Only set text_parameter_ref_id if the text contains {{0}}
                    let block_text_ref =
                        if block.text.contains("{{0}}") { text_param_ref_id.map(|s| s.to_string()) } else { None };
                    dynamic_items.push(ModuleDefDynamicItem::ParameterBlock(ParameterBlock {
                        id: block_id,
                        name: Some(block.name.to_string()),
                        text: Some(block.text.to_string()),
                        text_parameter_ref_id: block_text_ref,
                        internal_description: None,
                        inline: None,
                        show_in_com_object_tree: None,
                        layout: None,
                        items: block_items,
                    }));
                }
                ModuleLayoutElement::When(when_elem) => {
                    if let Some(choose) = Self::convert_module_layout_when_to_choose(
                        module_id,
                        def,
                        obj_base_arg_idx,
                        when_elem,
                        &mut sep_counter,
                        picture_param_map,
                    ) {
                        dynamic_items.push(ModuleDefDynamicItem::Choose(choose));
                    }
                }
            }
        }

        if dynamic_items.is_empty() {
            None
        } else {
            Some(ModuleDefDynamic { items: dynamic_items })
        }
    }

    /// Convert ModuleLayoutItem list to ParameterBlockItem list.
    fn convert_module_layout_items(
        module_id: &str,
        def: &StoredModuleDef,
        obj_base_arg_idx: usize,
        items: &[crate::definition::page_layout::ModuleLayoutItem],
        sep_counter: &mut u32,
        picture_param_map: &HashMap<String, usize>,
    ) -> Vec<ParameterBlockItem> {
        use crate::definition::page_layout::ModuleLayoutItem;

        let mut result = Vec::new();
        for item in items {
            match item {
                ModuleLayoutItem::Param(name) => {
                    // Look up param number by name (searches both virtual_params and params)
                    if let Some(param_num) = def.find_param_num_by_name(name) {
                        let ref_id = format!("{}_P-{}_R-{}", module_id, param_num, param_num);
                        result.push(block_param_ref(ref_id));
                    }
                }
                ModuleLayoutItem::Obj(name) => {
                    // Look up comm object index by name
                    if let Some(objs) = def.comm_objects {
                        if let Some(idx) = objs.iter().position(|o| o.name == *name) {
                            let ref_num = idx + 1;
                            let ref_id = format!("{}_O-{}-{}_R-{}", module_id, obj_base_arg_idx + 1, idx, ref_num);
                            result.push(block_com_obj_ref(ref_id));
                        }
                    }
                }
                ModuleLayoutItem::Separator(text) => {
                    *sep_counter += 1;
                    result.push(ParameterBlockItem::ParameterSeparator(ParameterSeparator {
                        id: format!("{}_PS-{}", module_id, sep_counter),
                        text: text.map(|s| s.to_string()),
                    }));
                }
                ModuleLayoutItem::When(when_item) => {
                    if let Some(choose) = Self::convert_module_layout_when_to_choose(
                        module_id,
                        def,
                        obj_base_arg_idx,
                        when_item,
                        sep_counter,
                        picture_param_map,
                    ) {
                        result.push(ParameterBlockItem::Choose(choose));
                    }
                }
                ModuleLayoutItem::Picture(baggage_name) => {
                    // Look up the picture param number from the map
                    if let Some(&param_num) = picture_param_map.get(*baggage_name) {
                        let ref_id = format!("{}_P-{}_R-{}", module_id, param_num, param_num);
                        result.push(block_param_ref(ref_id));
                    } else {
                        log::warn!("Picture '{}' not found in picture_param_map for module", baggage_name);
                    }
                }
            }
        }
        result
    }

    /// Convert ModuleLayoutItem list to WhenItem list (for inside choose/when clauses).
    fn convert_module_layout_items_to_when(
        module_id: &str,
        def: &StoredModuleDef,
        obj_base_arg_idx: usize,
        items: &[crate::definition::page_layout::ModuleLayoutItem],
        sep_counter: &mut u32,
        picture_param_map: &HashMap<String, usize>,
    ) -> Vec<WhenItem> {
        use crate::definition::page_layout::ModuleLayoutItem;

        let mut result = Vec::new();
        for item in items {
            match item {
                ModuleLayoutItem::Param(name) => {
                    // Look up param number by name (searches both virtual_params and params)
                    if let Some(param_num) = def.find_param_num_by_name(name) {
                        let ref_id = format!("{}_P-{}_R-{}", module_id, param_num, param_num);
                        result.push(when_param_ref(ref_id));
                    }
                }
                ModuleLayoutItem::Obj(name) => {
                    // Look up comm object index by name
                    if let Some(objs) = def.comm_objects {
                        if let Some(idx) = objs.iter().position(|o| o.name == *name) {
                            let ref_num = idx + 1;
                            let ref_id = format!("{}_O-{}-{}_R-{}", module_id, obj_base_arg_idx + 1, idx, ref_num);
                            result.push(when_com_obj_ref(ref_id));
                        }
                    }
                }
                ModuleLayoutItem::Separator(text) => {
                    *sep_counter += 1;
                    result.push(WhenItem::ParameterSeparator(ParameterSeparator {
                        id: format!("{}_PS-{}", module_id, sep_counter),
                        text: text.map(|s| s.to_string()),
                    }));
                }
                ModuleLayoutItem::When(when_item) => {
                    if let Some(choose) = Self::convert_module_layout_when_to_choose(
                        module_id,
                        def,
                        obj_base_arg_idx,
                        when_item,
                        sep_counter,
                        picture_param_map,
                    ) {
                        result.push(WhenItem::Choose(choose));
                    }
                }
                ModuleLayoutItem::Picture(baggage_name) => {
                    // Look up the picture param number from the map
                    if let Some(&param_num) = picture_param_map.get(*baggage_name) {
                        let ref_id = format!("{}_P-{}_R-{}", module_id, param_num, param_num);
                        result.push(when_param_ref(ref_id));
                    } else {
                        log::warn!("Picture '{}' not found in picture_param_map for module", baggage_name);
                    }
                }
            }
        }
        result
    }

    /// Convert a ModuleLayoutWhen to a Choose element.
    fn convert_module_layout_when_to_choose(
        module_id: &str,
        def: &StoredModuleDef,
        obj_base_arg_idx: usize,
        when_elem: &crate::definition::page_layout::ModuleLayoutWhen,
        sep_counter: &mut u32,
        picture_param_map: &HashMap<String, usize>,
    ) -> Option<Choose> {
        // Look up selector param number by name (searches both virtual_params and params)
        let param_num = def.find_param_num_by_name(&when_elem.selector)?;
        let param_ref_id = format!("{}_P-{}_R-{}", module_id, param_num, param_num);

        let mut when_items = Vec::new();
        for case in &when_elem.cases {
            let test_str = case.condition.to_test_string();
            let is_default = case.condition.is_default();
            let converted = Self::convert_module_layout_items_to_when(
                module_id,
                def,
                obj_base_arg_idx,
                &case.items,
                sep_counter,
                picture_param_map,
            );
            when_items.push(When {
                test: test_str,
                default: if is_default { Some(true) } else { None },
                internal_description: None,
                items: converted,
            });
        }

        Some(Choose { param_ref_id, whens: when_items })
    }

    /// Build default module dynamic layout (all params and comm objects in one block).
    fn build_default_module_dynamic(
        module_id: &str,
        def: &StoredModuleDef,
        text_param_ref_id: Option<&str>,
    ) -> Option<ModuleDefDynamic> {
        // Check if we have either params or comm objects
        let has_params = def.params.map_or(false, |p| !p.is_empty());
        let has_comm_objs = def.comm_objects.map_or(false, |c| !c.is_empty());

        if !has_params && !has_comm_objs {
            return None;
        }

        let mut items: Vec<ParameterBlockItem> = Vec::new();

        // Build ParameterRefRef items for each parameter
        if let Some(params) = def.params {
            for (idx, _param) in params.iter().enumerate() {
                let param_num = idx + 1;
                let ref_id = format!("{}_P-{}_R-{}", module_id, param_num, param_num);
                items.push(block_param_ref(ref_id));
            }
        }

        // Build ComObjectRefRef items for each communication object
        // This makes the comm objects visible in ETS when the module is instantiated
        if let Some(comm_objs) = def.comm_objects {
            // Find the ObjBase argument index (argument with ObjectNumber role)
            let obj_base_arg_idx = def.arg_index_by_role(crate::definition::module::ModuleArgRole::ObjectNumber);
            let obj_base_arg_idx = obj_base_arg_idx.unwrap_or(1); // Default to second argument

            for (idx, _obj) in comm_objs.iter().enumerate() {
                let ref_num = idx + 1;
                // ComObjectRef ID format: {module_id}_O-{arg_idx+1}-{obj_index}_R-{ref_num}
                let ref_id = format!("{}_O-{}-{}_R-{}", module_id, obj_base_arg_idx + 1, idx, ref_num);
                items.push(block_com_obj_ref(ref_id));
            }
        }

        // Create a ParameterBlock with a name based on module name
        // The text uses {{ChNo}} for channel number and {{0}} for the text param value
        // TextParameterRefId must be set when using {{0}} template
        let block = ParameterBlock {
            id: format!("{}_PB-1", module_id),
            name: Some(def.name.clone()),
            text: Some("{{ChNo}}: {{0}}".to_string()), // Use module argument for channel and text param for name
            text_parameter_ref_id: text_param_ref_id.map(|s| s.to_string()),
            internal_description: None,
            inline: None,
            show_in_com_object_tree: None,
            layout: None,
            items,
        };

        Some(ModuleDefDynamic { items: vec![ModuleDefDynamicItem::ParameterBlock(block)] })
    }

    /// Build the Code section with appropriate segment type for the mask.
    fn build_code(config: &ApplicationProgramConfig, app_id: &str, size: u32, mask_family: MaskFamily) -> Code {
        // Strip no_memory (virtual) parameters' bytes from the raw defaults
        let stripped_defaults = strip_no_memory_bytes(config.param_defaults, config.params);
        let data = base64::engine::general_purpose::STANDARD.encode(&stripped_defaults);

        match mask_family.data_segment_type() {
            DataSegmentType::Relative => {
                let code_segment_id = format!("{}_RS-04-00000", app_id);
                Code {
                    absolute_segments: vec![],
                    relative_segments: vec![RelativeSegment {
                        id: code_segment_id,
                        size,
                        load_state_machine: 4,
                        offset: 0,
                        data: Some(data),
                    }],
                }
            }
            DataSegmentType::Absolute => {
                // Check if we have a full System 7 layout
                if let Some(ref layout) = config.system7_layout {
                    Self::build_system7_code(app_id, layout)
                } else {
                    // Simple single-segment layout
                    let code_segment_id = format!("{}_AS-{:04X}", app_id, config.absolute_segment_address.unwrap_or(0));
                    Code {
                        absolute_segments: vec![AbsoluteSegment {
                            id: code_segment_id,
                            address: config.absolute_segment_address.unwrap_or(0),
                            size,
                            memory_type: Some("RAM".to_string()),
                            data: Some(data),
                            mask: None,
                        }],
                        relative_segments: vec![],
                    }
                }
            }
        }
    }

    /// Build Code section for System 7 with full memory layout.
    fn build_system7_code(app_id: &str, layout: &System7MemoryLayout) -> Code {
        let mut segments = Vec::new();

        for seg in &layout.segments {
            let segment_id = format!("{}_AS-{}", app_id, seg.name);
            let data = seg.data.map(|d| base64::engine::general_purpose::STANDARD.encode(d));
            let mask = seg.mask.map(|m| base64::engine::general_purpose::STANDARD.encode(m));

            segments.push(AbsoluteSegment {
                id: segment_id,
                address: seg.address,
                size: seg.size,
                memory_type: seg.memory_type.map(|s| s.to_string()),
                data,
                mask,
            });
        }

        Code { absolute_segments: segments, relative_segments: vec![] }
    }

    /// Build parameter type definitions.
    fn build_parameter_types(config: &ApplicationProgramConfig, app_id: &str) -> ParameterTypes {
        let mut types = ParameterTypes::default();
        let mut seen_types = std::collections::HashSet::new();

        // Process all device params (virtual first, then regular)
        for param in config.all_params() {
            let type_name = Self::param_type_name(&param.base);
            if seen_types.contains(&type_name) {
                continue;
            }
            seen_types.insert(type_name.clone());

            // URL-encode the type name for the ID
            let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));
            let type_def = Self::build_type_def(&param.base, param.enum_variants, &type_id);

            types.types.push(ParameterType { id: type_id, name: type_name, internal_description: None, type_def });
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
                        internal_description: None,
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
                    // For union variant params with enum types and custom enum_variants,
                    // include the variant name in the type name to make it unique.
                    // This ensures ForcibleControl's value gets a different type than Switch's value.
                    let type_name =
                        Self::union_variant_param_type_name(&param.param, param.variant_name, param.enum_variants);
                    if !seen_types.contains(&type_name) {
                        seen_types.insert(type_name.clone());
                        let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));
                        let type_def = Self::build_type_def(&param.param, param.enum_variants, &type_id);
                        types.types.push(ParameterType {
                            id: type_id,
                            name: type_name,
                            internal_description: None,
                            type_def,
                        });
                    }
                }
            }
        }

        // Add types for module parameters (both virtual and regular)
        if let Some(modules) = &config.modules {
            for def in modules.definitions() {
                // Process virtual params first (they come first in the combined param list)
                let virtual_params = def.virtual_params.unwrap_or(&[]);
                let regular_params = def.params.unwrap_or(&[]);
                let all_params = virtual_params.iter().chain(regular_params.iter());

                for param_ext in all_params {
                    let type_name = Self::param_type_name(&param_ext.base);
                    if seen_types.contains(&type_name) {
                        continue;
                    }
                    seen_types.insert(type_name.clone());

                    let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));
                    let type_def = Self::build_type_def(&param_ext.base, param_ext.enum_variants, &type_id);

                    types.types.push(ParameterType {
                        id: type_id,
                        name: type_name,
                        internal_description: None,
                        type_def,
                    });
                }
            }
        }

        // Add types for picture parameters (TypePicture)
        let pictures = collect_pictures_from_layout(config);
        for pic in &pictures {
            let type_name = format!("tPIC_{}", pic.baggage_name.replace('.', "_"));
            if !seen_types.contains(&type_name) {
                seen_types.insert(type_name.clone());
                let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));
                let baggage_id = make_baggage_id(config.device.manufacturer_id, &pic.baggage_name);
                types.types.push(ParameterType {
                    id: type_id,
                    name: type_name,
                    internal_description: None,
                    type_def: ParameterTypeDef::TypePicture(TypePicture { ref_id: baggage_id }),
                });
            }
        }

        types
    }

    /// Generate a type name from a parameter definition.
    fn param_type_name(param: &zweidraehte::ets::EtsParamDef) -> String {
        // Use explicit type_name if provided
        if let Some(type_name) = param.type_name {
            return type_name.to_string();
        }
        // Otherwise auto-generate based on type
        match param.param_type {
            EtsParamType::UnsignedInt => format!("tUINT{}", param.size_bits),
            EtsParamType::SignedInt => format!("tSINT{}", param.size_bits),
            EtsParamType::Enum => format!("tENUM_{}_{}", param.name, param.size_bits),
            EtsParamType::String => {
                // For text with patterns, generate a unique type name
                if let Some(pattern) = param.text_pattern {
                    // Extract type hint from pattern comment if present (e.g., "(?# TypeColor:RGB)")
                    if pattern.contains("TypeColor:RGB") {
                        "RGBColor".to_string()
                    } else if pattern.contains("TypeColor:HSV") {
                        "HSV-Werte".to_string() // MDT uses hyphen in display name
                    } else {
                        format!("tTEXT{}", param.size_bits)
                    }
                } else {
                    format!("tTEXT{}", param.size_bits)
                }
            }
            EtsParamType::None => format!("tNONE{}", param.size_bits),
        }
    }

    /// Generate a type name for a union variant parameter.
    ///
    /// For enum types with custom enum_variants, includes the variant name
    /// in the type name to ensure each variant's params get unique types.
    /// This is necessary because different variants (e.g., ForcibleControl vs Switch)
    /// may have the same param name (e.g., "value") but different enum options.
    fn union_variant_param_type_name(
        param: &zweidraehte::ets::EtsParamDef,
        variant_name: &str,
        enum_variants: Option<&[zweidraehte::ets::EtsEnumVariant]>,
    ) -> String {
        // Use explicit type_name if provided
        if let Some(type_name) = param.type_name {
            return type_name.to_string();
        }
        // For enum types with custom enum_variants, include variant name for uniqueness
        if param.param_type == EtsParamType::Enum && enum_variants.is_some() {
            return format!("tENUM_{}_{}", variant_name, param.size_bits);
        }
        // Otherwise use the standard type name generation
        Self::param_type_name(param)
    }

    /// URL-encode a name for use in IDs
    /// - Underscores become .5F
    /// - Hyphens become .2D
    /// - Slashes become .2F
    /// This applies to all user-defined names that appear in IDs
    pub fn encode_id(name: &str) -> String {
        name.replace('_', ".5F").replace('-', ".2D").replace('/', ".2F")
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
            EtsParamType::String => {
                // Use pattern if provided, with fixed size for color types
                let (size, pattern) = if let Some(pat) = param.text_pattern {
                    // Color patterns use 56 bits (7 bytes for "#RRGGBB" text representation)
                    if pat.contains("TypeColor:") {
                        (56, Some(pat.to_string()))
                    } else {
                        (param.size_bits as u32, Some(pat.to_string()))
                    }
                } else {
                    (param.size_bits as u32, None)
                };
                ParameterTypeDef::TypeText(TypeText { size_in_bit: size, pattern })
            }
            EtsParamType::None => ParameterTypeDef::TypeNone(TypeNone {}),
        }
    }

    /// Build parameters section.
    fn build_parameters(config: &ApplicationProgramConfig, app_id: &str, code_segment_id: &str) -> Parameters {
        let mut params = Parameters::default();
        let mut param_counter = 1u32;

        // Build a set of union selector names to skip them in regular params
        // (they are generated inside the Union element, not as separate Parameters)
        let union_selector_names: std::collections::HashSet<String> = config
            .union_fields
            .map(|fields| fields.iter().map(|f| format!("{}_selector", f.field_name)).collect())
            .unwrap_or_default();

        // Process all parameters (virtual first, then regular)
        // Virtual params have no_memory=true and don't use param_defaults
        for param_ext in config.all_params() {
            let param = &param_ext.base;

            // Skip union selector parameters - they go inside the Union, not as separate params
            if union_selector_names.contains(param.name) {
                continue;
            }

            let param_id = format!("{}_P-{}", app_id, param_counter);
            let type_name = Self::param_type_name(param);
            // Use encoded type ID
            let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));

            // Get default value: prefer explicit default_value, then fall back to param_defaults byte slice
            let param_offset = param.offset as usize;
            let size_bytes = (param.size_bits as usize + 7) / 8;
            let default_value = if let Some(val) = param_ext.default_value {
                val.to_string()
            } else if param.param_type == EtsParamType::String {
                // String parameters default to empty string
                String::new()
            } else if param_offset + size_bytes <= config.param_defaults.len() {
                match size_bytes {
                    1 => config.param_defaults[param_offset].to_string(),
                    2 => {
                        let val = u16::from_le_bytes([
                            config.param_defaults[param_offset],
                            config.param_defaults[param_offset + 1],
                        ]);
                        val.to_string()
                    }
                    4 => {
                        let val = u32::from_le_bytes([
                            config.param_defaults[param_offset],
                            config.param_defaults[param_offset + 1],
                            config.param_defaults[param_offset + 2],
                            config.param_defaults[param_offset + 3],
                        ]);
                        val.to_string()
                    }
                    _ => config.param_defaults[param_offset].to_string(),
                }
            } else {
                "0".to_string()
            };

            // Virtual (no_memory) parameters don't have a Memory element
            let memory = if param.no_memory {
                None
            } else {
                Some(MemoryLocation {
                    code_segment: code_segment_id.to_string(),
                    offset: param.offset as u32,
                    bit_offset: param.bit_offset,
                    base_offset: None,
                })
            };

            params.items.push(ParameterItem::Parameter(Parameter {
                id: param_id,
                name: param.name.to_string(),
                parameter_type: type_id,
                text: param.display_name.to_string(),
                suffix_text: param.suffix.map(|s| s.to_string()),
                access: if param.hidden { Some("None".to_string()) } else { None },
                value: default_value,
                base_value: None,
                internal_description: None,
                memory,
            }));

            param_counter += 1;
        }

        // Picture parameters (virtual - no Memory, displayed as images in ETS)
        let pictures = collect_pictures_from_layout(config);
        for pic in &pictures {
            let param_id = format!("{}_P-{}", app_id, param_counter);
            let type_name = format!("tPIC_{}", pic.baggage_name.replace('.', "_"));
            let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));

            params.items.push(ParameterItem::Parameter(Parameter {
                id: param_id,
                name: format!("Pic_{}", pic.baggage_name.replace('.', "_")),
                parameter_type: type_id,
                text: String::new(), // Pictures typically have no text label
                suffix_text: None,
                access: None,
                value: String::new(), // Pictures don't have a value
                base_value: None,
                internal_description: None,
                memory: None, // Pictures are virtual - no device memory
            }));

            param_counter += 1;
        }

        // Union parameters - start counting from 1
        if let Some(union_fields) = config.union_fields {
            let mut up_counter = 1u32;
            for field in union_fields {
                // Look up the selector's explicit default from EtsParamDefExt
                let selector_name = format!("{}_selector", field.field_name);
                let selector_default =
                    config.all_params().find(|p| p.base.name == selector_name).and_then(|p| p.default_value);

                let (union_elem, next_counter) =
                    Self::build_union(field, app_id, code_segment_id, up_counter, selector_default);
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
        selector_default: Option<i64>,
    ) -> (Union, u32) {
        let union_info = field.union_info;
        let total_size_bits = union_info.total_size as u32 * 8;

        let mut parameters = vec![];
        let mut counter = up_counter;

        // Selector parameter (discriminant) - uses sequential UP- numbering
        let selector_type_name = format!("tENUM_{}_selector_8", field.field_name);
        let selector_type = format!("{}_PT-{}", app_id, Self::encode_id(&selector_type_name));
        let selector_value = selector_default.unwrap_or(0).to_string();
        parameters.push(UnionParameter {
            id: format!("{}_UP-{}", app_id, counter),
            name: format!("{}_selector", field.field_name),
            parameter_type: selector_type,
            text: format!("{} Mode", field.field_name),
            suffix_text: None,
            value: selector_value,
            offset: 0,
            bit_offset: 0,
            default_union_parameter: Some(true),
            internal_description: None,
        });
        counter += 1;

        // Variant field parameters - in the order they appear in variant_params
        for param in union_info.variant_params {
            // Use union_variant_param_type_name to match the type generation in build_parameter_types
            let type_name = Self::union_variant_param_type_name(&param.param, param.variant_name, param.enum_variants);
            // Use encoded type ID
            let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));

            // Use default_value if specified, otherwise:
            // - For color fields (TypeColor pattern), use "#000000"
            // - Otherwise use 0
            let default_value = if let Some(val) = param.default_value {
                val.to_string()
            } else if param.param.text_pattern.map_or(false, |p| p.contains("TypeColor")) {
                "#000000".to_string()
            } else {
                "0".to_string()
            };

            parameters.push(UnionParameter {
                id: format!("{}_UP-{}", app_id, counter),
                name: format!("{}_{}", param.variant_name, param.param.name),
                parameter_type: type_id,
                text: param.param.display_name.to_string(),
                suffix_text: param.param.suffix.map(|s| s.to_string()),
                value: default_value,
                offset: union_info.data_offset + param.param.offset, // data_offset accounts for discriminant + alignment padding
                bit_offset: param.param.bit_offset,
                default_union_parameter: None,
                internal_description: None,
            });
            counter += 1;
        }

        (
            Union {
                size_in_bit: total_size_bits,
                internal_description: None,
                memory: UnionMemory {
                    code_segment: code_segment_id.to_string(),
                    offset: field.offset as u32,
                    bit_offset: 0,
                    base_offset: None,
                },
                parameters,
            },
            counter,
        )
    }

    /// Build parameter references.
    /// If `selector_usage_counts` is provided, creates multiple refs for parameters that are
    /// used multiple times as selectors in ObjWithValue/GroupedObjChoose.
    /// If `union_variant_texts` is provided, creates multiple refs for union variant params with
    /// different text overrides (matching MDT's approach where each use context has its own ref).
    /// This must use the same numbering scheme as `build_multi_param_ref_map` so the refs match.
    /// Returns both the ParameterRefs and a mapping of param_name -> first_ref_num for text param refs.
    fn build_parameter_refs(
        config: &ApplicationProgramConfig,
        app_id: &str,
        selector_usage_counts: Option<&HashMap<String, usize>>,
        union_variant_texts: Option<&HashMap<(String, String), Vec<Option<String>>>>,
    ) -> (ParameterRefs, HashMap<String, u32>) {
        let mut refs = ParameterRefs::default();
        let mut param_ref_nums: HashMap<String, u32> = HashMap::new();

        // Build a set of union selector names to skip them in regular params
        let union_selector_names: std::collections::HashSet<String> = config
            .union_fields
            .map(|fields| fields.iter().map(|f| format!("{}_selector", f.field_name)).collect())
            .unwrap_or_default();

        // Use a single sequential counter for all ref numbers (matching build_multi_param_ref_map)
        let mut next_ref_num = 1u32;
        let mut param_counter = 1u32;

        // Process all params (virtual first, then regular)
        for param in config.all_params() {
            // Skip union selector parameters - they are referenced via union param refs
            if union_selector_names.contains(param.base.name) {
                continue;
            }

            let param_id = format!("{}_P-{}", app_id, param_counter);

            // Determine how many refs to create for this parameter
            let num_refs =
                selector_usage_counts.and_then(|counts| counts.get(param.base.name)).copied().unwrap_or(0).max(1); // At least 1 ref

            // Track the first ref number for this param (for text param ref resolution)
            param_ref_nums.insert(param.base.name.to_string(), next_ref_num);

            // Create refs with sequential numbering
            for _ in 0..num_refs {
                let ref_id = format!("{}_R-{}", param_id, next_ref_num);
                refs.refs.push(ParameterRef {
                    id: ref_id,
                    ref_id: param_id.clone(),
                    text: None,
                    internal_description: None,
                    access: None,
                    value: None,
                    base_value: None,
                });
                next_ref_num += 1;
            }

            param_counter += 1;
        }

        // Picture parameter refs (one ref per picture)
        let pictures = collect_pictures_from_layout(config);
        for pic in &pictures {
            let param_id = format!("{}_P-{}", app_id, param_counter);
            let ref_id = format!("{}_R-{}", param_id, next_ref_num);

            // Track the ref number for this picture (for layout processing)
            let pic_param_name = format!("Pic_{}", pic.baggage_name.replace('.', "_"));
            param_ref_nums.insert(pic_param_name, next_ref_num);

            refs.refs.push(ParameterRef {
                id: ref_id,
                ref_id: param_id,
                text: None,
                internal_description: None,
                access: None,
                value: None,
                base_value: None,
            });
            next_ref_num += 1;
            param_counter += 1;
        }

        // Union parameter refs
        if let Some(union_fields) = config.union_fields {
            let mut up_counter = 1u32;

            for field in union_fields {
                // Selector ref - must match ID in build_union (UP-1, UP-2, etc.)
                let selector_id = format!("{}_UP-{}", app_id, up_counter);
                let selector_name = format!("{}_selector", field.field_name);

                // How many refs for the selector?
                let num_refs =
                    selector_usage_counts.and_then(|counts| counts.get(&selector_name)).copied().unwrap_or(0).max(1);

                for _ in 0..num_refs {
                    refs.refs.push(ParameterRef {
                        id: format!("{}_R-{}", selector_id, next_ref_num),
                        ref_id: selector_id.clone(),
                        text: None,
                        internal_description: None,
                        access: None,
                        value: None,
                        base_value: None,
                    });
                    next_ref_num += 1;
                }
                up_counter += 1;

                // Variant parameter refs - in the same order as build_union
                // Create multiple refs for each unique text override
                for param in field.union_info.variant_params {
                    let param_id = format!("{}_UP-{}", app_id, up_counter);

                    // Look up text overrides for this variant
                    let key = (field.field_name.to_string(), param.variant_name.to_string());
                    let text_overrides =
                        union_variant_texts.and_then(|texts| texts.get(&key)).cloned().unwrap_or_else(|| vec![None]); // At least one ref with no text

                    // Create a ref for each unique text override
                    for text in text_overrides {
                        refs.refs.push(ParameterRef {
                            id: format!("{}_R-{}", param_id, next_ref_num),
                            ref_id: param_id.clone(),
                            text,
                            internal_description: None,
                            access: None,
                            value: None,
                            base_value: None,
                        });
                        next_ref_num += 1;
                    }
                    up_counter += 1;
                }
            }
        }

        (refs, param_ref_nums)
    }

    /// Resolve text parameter references in a string.
    /// Replaces `{{param_name:default}}` with `{{N:default}}` where N is the ref number.
    fn resolve_text_param_refs(text: &str, param_ref_nums: &HashMap<String, u32>) -> String {
        // Quick check if there are any references to resolve
        if !text.contains("{{") {
            return text.to_string();
        }

        let mut result = text.to_string();

        // Find all {{param_name:default}} patterns and replace with {{N:default}}
        // Pattern: {{ followed by param_name, then :, then anything until }}
        let re = regex::Regex::new(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*):([^}]*)\}\}").unwrap();

        for cap in re.captures_iter(text) {
            let full_match = cap.get(0).unwrap().as_str();
            let param_name = cap.get(1).unwrap().as_str();
            let default_text = cap.get(2).unwrap().as_str();

            if let Some(&ref_num) = param_ref_nums.get(param_name) {
                // Use {{N}} format when default is empty, {{N:default}} otherwise (matches MDT)
                let replacement = if default_text.is_empty() {
                    format!("{{{{{}}}}}", ref_num)
                } else {
                    format!("{{{{{}:{}}}}}", ref_num, default_text)
                };
                result = result.replace(full_match, &replacement);
            }
            // If param not found, leave the original text (will show as static text)
        }

        result
    }

    /// Build communication object table.
    fn build_com_object_table(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
    ) -> ComObjectTable {
        // For System 7, use the third segment (typically 4400) for ComObjectTable
        let code_segment = if let Some(ref layout) = config.system7_layout {
            // Find the com object table segment (usually after address and association tables)
            if let Some(seg) = layout.segments.get(2) {
                Some(format!("{}_AS-{}", app_id, seg.name))
            } else {
                None
            }
        } else {
            None
        };
        let mut table = ComObjectTable { code_segment, offset: Some(0), ..ComObjectTable::default() };
        let start_index = mask_family.com_object_start_index();

        // Build a map of object_index -> (ref_count, max_size_bits)
        let mut ref_info: std::collections::HashMap<u16, (usize, u8)> = std::collections::HashMap::new();
        for ref_def in config.comm_object_refs {
            let entry = ref_info.entry(ref_def.object_index).or_insert((0, 0));
            entry.0 += 1; // increment ref count
            entry.1 = entry.1.max(ref_def.size_bits); // track max size
        }

        for co in config.comm_objects {
            // Adjust index based on mask family
            let adjusted_index = co.index + start_index;
            let obj_id = format!("{}_O-{}", app_id, adjusted_index);
            let flags = co.default_flags;

            // Check if this object has multiple refs
            let (ref_count, max_size) = ref_info.get(&co.index).copied().unwrap_or((1, co.size_bits));
            let is_multi_ref = ref_count > 1;

            // For multi-ref objects: no DPT on base object, use max size from refs
            // For single-ref objects: include DPT and use object's size
            // object_size_override takes precedence if specified
            let (datapoint_type, object_size) = if is_multi_ref {
                let size = co
                    .object_size_override
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| object_size_to_string(max_size).to_string());
                (None, size)
            } else {
                let size = co
                    .object_size_override
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| object_size_to_string(co.size_bits).to_string());
                (Some(dpt_to_string(co.dpt_main, co.dpt_sub)), size)
            };

            table.objects.push(ComObject {
                id: obj_id,
                name: co.name.to_string(),
                text: co.display_name.to_string(),
                number: adjusted_index,
                function_text: co.function_text.to_string(),
                object_size,
                datapoint_type,
                // KNX ComObjectFlags bit layout (from tables/mod.rs):
                // Bit 7 (0x80): Update Enable (UE)
                // Bit 6 (0x40): Transmit Enable (TE)
                // Bit 5 (0x20): Read On Init (ROI)
                // Bit 4 (0x10): Write Enable (WE)
                // Bit 3 (0x08): Read Enable (RE)
                // Bit 2 (0x04): Communication Enable (CE)
                // Bits 0-1: Priority
                read_flag: (flags & 0x08 != 0).into(),
                write_flag: (flags & 0x10 != 0).into(),
                communication_flag: (flags & 0x04 != 0).into(),
                transmit_flag: (flags & 0x40 != 0).into(),
                update_flag: (flags & 0x80 != 0).into(),
                read_on_init_flag: (flags & 0x20 != 0).into(),
                priority: None, // MDT doesn't include Priority in ComObjects
                internal_description: None,
                base_number: None,
            });
        }

        table
    }

    /// Build communication object references.
    ///
    /// Uses the comm_object_refs array which contains one entry per ref.
    /// For multi-ref objects, there will be multiple refs pointing to the same ComObject.
    /// The param_ref_nums map is used to resolve text parameter references in Text attributes.
    fn build_com_object_refs(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_nums: &HashMap<String, u32>,
    ) -> ComObjectRefs {
        let mut refs = ComObjectRefs::default();
        let start_index = mask_family.com_object_start_index();

        for (i, ref_def) in config.comm_object_refs.iter().enumerate() {
            let adjusted_index = ref_def.object_index + start_index;
            let co_id = format!("{}_O-{}", app_id, adjusted_index);
            let ref_id = format!("{}_R-{}", co_id, i + 1);

            // Resolve text parameter references in the text attribute
            let text = ref_def.text.map(|s| Self::resolve_text_param_refs(s, param_ref_nums));

            // Build the ComObjectRef with potential overrides from the ref definition
            // Note: MDT doesn't include Name attribute on ComObjectRefs, only on ComObjects
            let mut com_ref = ComObjectRef {
                id: ref_id,
                ref_id: co_id,
                name: None,
                text,
                function_text: Some(ref_def.function_text.to_string()),
                datapoint_type: Some(dpt_to_string(ref_def.dpt_main, ref_def.dpt_sub)),
                object_size: Some(object_size_to_string(ref_def.size_bits).to_string()),
                internal_description: None,
                ..Default::default()
            };

            // Apply flag overrides if present
            if let Some(flags) = &ref_def.flag_overrides {
                com_ref.read_flag = flags.read.map(|b| b.into());
                com_ref.write_flag = flags.write.map(|b| b.into());
                com_ref.communication_flag = flags.communication.map(|b| b.into());
                com_ref.transmit_flag = flags.transmit.map(|b| b.into());
                com_ref.update_flag = flags.update.map(|b| b.into());
                com_ref.read_on_init_flag = flags.read_on_init.map(|b| b.into());
            }

            refs.refs.push(com_ref);
        }

        refs
    }

    /// Build load procedures based on mask family.
    fn build_load_procedures(
        config: &ApplicationProgramConfig,
        param_size: u32,
        mask_family: MaskFamily,
    ) -> LoadProcedures {
        match mask_family {
            MaskFamily::SystemB => Self::build_system_b_load_procedures(param_size),
            MaskFamily::System7 => Self::build_system_7_load_procedures(config),
            MaskFamily::Bim | MaskFamily::BimM => Self::build_bim_load_procedures(),
        }
    }

    /// Build load procedures for System B (MergedProcedure with relative segments).
    fn build_system_b_load_procedures(param_size: u32) -> LoadProcedures {
        LoadProcedures {
            procedures: vec![
                LoadProcedure {
                    merge_id: Some(2),
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
                    merge_id: Some(4),
                    controls: vec![LoadControl::LdCtrlWriteRelMem(LdCtrlWriteRelMem {
                        applies_to: "full,par".to_string(),
                        obj_idx: 4,
                        offset: 0,
                        size: param_size,
                        verify: true,
                    })],
                },
                LoadProcedure {
                    merge_id: Some(7),
                    controls: vec![
                        LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp { obj_idx: 1, prop_id: 27 }),
                        LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp { obj_idx: 2, prop_id: 27 }),
                        LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp { obj_idx: 3, prop_id: 27 }),
                        LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp { obj_idx: 4, prop_id: 27 }),
                    ],
                },
            ],
        }
    }

    /// Build load procedures for System 7 (ProductProcedure with absolute segments).
    ///
    /// System 7 LoadProcedure format (based on MDT M-0083_A-009B-14-E59D.xml):
    /// 1. LdCtrlConnect - Establish connection
    /// 2. LdCtrlCompareProp - Verify device identity (ObjIdx=0, PropId=78 is PID_SERIAL_NUMBER)
    /// 3. LdCtrlUnload LSM 1,2,3 - Unload existing load state machines
    /// 4. For each LSM:
    ///    - LdCtrlLoad
    ///    - LdCtrlAbsSegment(s) for the segments belonging to this LSM
    ///    - LdCtrlTaskSegment
    ///    - LdCtrlLoadCompleted
    /// 5. LdCtrlRestart
    /// 6. LdCtrlDisconnect
    fn build_system_7_load_procedures(config: &ApplicationProgramConfig) -> LoadProcedures {
        // If no System 7 layout is provided, return empty
        let Some(ref layout) = config.system7_layout else {
            return LoadProcedures { procedures: vec![] };
        };

        let mut controls = Vec::new();

        // 1. Connect
        controls.push(LoadControl::LdCtrlConnect(LdCtrlConnect {}));

        // 2. Compare device serial number (PID_SERIAL_NUMBER = 78, ObjIdx = 0 for Device Object)
        // The InlineData is the expected serial number as hex
        let serial_hex = config.serial_number.iter().map(|b| format!("{:02X}", b)).collect::<String>();
        // Pad to 10 bytes (20 hex chars) like MDT does
        let serial_padded = format!("{:0<20}", serial_hex);
        controls.push(LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
            obj_idx: 0,
            prop_id: 78, // PID_SERIAL_NUMBER
            inline_data: Some(serial_padded),
            range: None,
            on_error: None,
        }));

        // 3. Unload existing LSMs (1, 2, 3)
        controls.push(LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: 1 }));
        controls.push(LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: 2 }));
        controls.push(LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: 3 }));

        // 4. Load LSM 1 - Address Table
        controls.push(LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: 1 }));
        if let Some(seg) = layout.segments.iter().find(|s| s.name == layout.address_table_segment) {
            controls.push(LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                lsm_idx: 1,
                seg_type: 0,
                address: seg.address as u16,
                size: seg.size as u16,
                access: 255,    // Full access
                mem_type: 3,    // EEPROM
                seg_flags: 128, // Standard flags
            }));
            controls
                .push(LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment { lsm_idx: 1, address: seg.address as u16 }));
        }
        controls.push(LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: 1 }));

        // 5. Load LSM 2 - Association Table
        controls.push(LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: 2 }));
        if let Some(seg) = layout.segments.iter().find(|s| s.name == layout.association_table_segment) {
            controls.push(LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                lsm_idx: 2,
                seg_type: 0,
                address: seg.address as u16,
                size: seg.size as u16,
                access: 255,
                mem_type: 3,
                seg_flags: 128,
            }));
            controls
                .push(LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment { lsm_idx: 2, address: seg.address as u16 }));
        }
        controls.push(LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: 2 }));

        // 6. Load LSM 3 - Application (RAM segments, COT, Parameters)
        controls.push(LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: 3 }));

        // Add RAM segments first
        for seg in &layout.segments {
            if seg.memory_type == Some("RAM") {
                let seg_type = if seg.size == 1 { 1 } else { 0 }; // Type 1 for 1-byte segments
                controls.push(LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                    lsm_idx: 3,
                    seg_type,
                    address: seg.address as u16,
                    size: seg.size as u16,
                    access: 0,   // No external access for RAM
                    mem_type: 2, // RAM
                    seg_flags: 0,
                }));
            }
        }

        // Add EEPROM segments (COT and Parameters) - skip address/assoc tables
        for seg in &layout.segments {
            if seg.name != layout.address_table_segment
                && seg.name != layout.association_table_segment
                && seg.memory_type != Some("RAM")
            {
                controls.push(LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                    lsm_idx: 3,
                    seg_type: 0,
                    address: seg.address as u16,
                    size: seg.size as u16,
                    access: 255,
                    mem_type: 3, // EEPROM
                    seg_flags: 128,
                }));
            }
        }

        // Task segment points to COT (17408 = 0x4400)
        // Find the COT segment (typically the one that's not address table, assoc table, RAM, or param EEPROM)
        // For simplicity, use address 17408 (0x4400) which is standard for COT
        let cot_address = layout
            .segments
            .iter()
            .find(|s| {
                s.name != layout.address_table_segment
                    && s.name != layout.association_table_segment
                    && s.memory_type != Some("RAM")
                    && s.memory_type != Some("EEPROM")
            })
            .map(|s| s.address as u16)
            .unwrap_or(17408);
        controls.push(LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment { lsm_idx: 3, address: cot_address }));
        controls.push(LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: 3 }));

        // 7. Restart and disconnect
        controls.push(LoadControl::LdCtrlRestart(LdCtrlRestart {}));
        controls.push(LoadControl::LdCtrlDisconnect(LdCtrlDisconnect {}));

        LoadProcedures {
            procedures: vec![LoadProcedure {
                merge_id: None, // ProductProcedure doesn't use MergeId
                controls,
            }],
        }
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
            .map(|fields| fields.iter().map(|f| format!("{}_selector", f.field_name)).collect())
            .unwrap_or_default();

        // Add ParameterRefRefs for all parameters (virtual first, then regular)
        let mut param_counter = 1usize;
        for param in config.all_params() {
            // Skip union selector parameters
            if union_selector_names.contains(param.base.name) {
                continue;
            }

            let param_id = format!("{}_P-{}", app_id, param_counter);
            // The ref_id must match what we generate in build_parameter_refs
            let ref_id = format!("{}_R-{}", param_id, param_counter);

            items.push(block_param_ref(ref_id));
            param_counter += 1;
        }

        // Add union fields with choose/when for conditional visibility
        if let Some(union_fields) = config.union_fields {
            // Count non-selector params for ref_counter
            let non_selector_param_count =
                config.all_params().filter(|p| !union_selector_names.contains(p.base.name)).count();
            let mut ref_counter = non_selector_param_count + 1;
            let mut up_counter = 1u32; // Sequential UP- counter matching build_union and build_parameter_refs

            for field in union_fields {
                // First, add the selector parameter (always visible)
                // Uses sequential UP-N ID matching build_union and build_parameter_refs
                let selector_id = format!("{}_UP-{}", app_id, up_counter);
                let selector_ref_id = format!("{}_R-{}", selector_id, ref_counter);

                items.push(block_param_ref(selector_ref_id.clone()));
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

                for (discriminant, (_display_name, param_ref_ids)) in sorted_variants {
                    // Create when clause for this variant
                    let when_items: Vec<WhenItem> =
                        param_ref_ids.into_iter().map(|ref_id| when_param_ref(ref_id)).collect();

                    whens.push(When {
                        test: Some(discriminant.to_string()),
                        default: None,
                        internal_description: None,
                        items: when_items,
                    });
                }

                items.push(ParameterBlockItem::Choose(Choose { param_ref_id: selector_ref_id, whens }));
            }
        }

        // Add ComObjectRefRefs - reference each ref from comm_object_refs
        // The ref IDs must match those generated in build_com_object_refs
        //
        // For refs with selector_param, we need to group them and create choose/when structures.
        // For refs without selector_param (simple objects), add them directly.

        // First, build a map: selector_param -> (object_index -> [(ref_index, selector_value)])
        let mut selector_groups: std::collections::HashMap<
            &str,                                              // selector_param name
            std::collections::HashMap<u16, Vec<(usize, i64)>>, // object_index -> [(ref_index, selector_value)]
        > = std::collections::HashMap::new();

        // Also track which refs need choose/when (have selector_param)
        let mut refs_in_choose: std::collections::HashSet<usize> = std::collections::HashSet::new();

        for (i, ref_def) in config.comm_object_refs.iter().enumerate() {
            if let (Some(param), Some(value)) = (ref_def.selector_param, ref_def.selector_value) {
                selector_groups.entry(param).or_default().entry(ref_def.object_index).or_default().push((i, value));
                refs_in_choose.insert(i);
            }
        }

        // Add simple refs (those without selector) directly
        for (i, ref_def) in config.comm_object_refs.iter().enumerate() {
            if refs_in_choose.contains(&i) {
                continue; // Skip - will be added in choose/when
            }

            let adjusted_index = ref_def.object_index + co_start_index;
            let co_id = format!("{}_O-{}", app_id, adjusted_index);
            let ref_id = format!("{}_R-{}", co_id, i + 1);

            items.push(block_com_obj_ref(ref_id));
        }

        // Now build choose/when for each selector_param
        // Need to find the parameter ref ID for each selector_param
        for (selector_param, objects) in &selector_groups {
            // Find the parameter ref ID for this selector
            // The selector_param is the parameter name, we need to find its ref ID
            let param_ref_id = Self::find_param_ref_id(config, app_id, selector_param);

            // Build when clauses - group by selector_value across all objects
            let mut value_to_refs: std::collections::HashMap<i64, Vec<String>> = std::collections::HashMap::new();

            for (object_index, ref_list) in objects {
                for (ref_index, selector_value) in ref_list {
                    let adjusted_index = object_index + co_start_index;
                    let co_id = format!("{}_O-{}", app_id, adjusted_index);
                    let ref_id = format!("{}_R-{}", co_id, ref_index + 1);
                    value_to_refs.entry(*selector_value).or_default().push(ref_id);
                }
            }

            // Sort by selector value for consistent output
            let mut sorted_values: Vec<_> = value_to_refs.into_iter().collect();
            sorted_values.sort_by_key(|(v, _)| *v);

            let whens: Vec<When> = sorted_values
                .into_iter()
                .map(|(selector_value, ref_ids)| {
                    let when_items: Vec<WhenItem> =
                        ref_ids.into_iter().map(|ref_id| when_com_obj_ref(ref_id)).collect();

                    When {
                        test: Some(selector_value.to_string()),
                        default: None,
                        internal_description: None,
                        items: when_items,
                    }
                })
                .collect();

            items.push(ParameterBlockItem::Choose(Choose { param_ref_id, whens }));
        }

        Ok(DynamicSection {
            channel_independent_block: None,
            channels: vec![Channel {
                id: format!("{}_CH-1", app_id),
                name: config.channel_name.to_string(),
                text: None,
                number: Some("1".to_string()),
                internal_description: None,
                text_parameter_ref_id: None,
                items: vec![ChannelItem::ParameterBlock(ParameterBlock {
                    id: format!("{}_PB-1", app_id),
                    name: Some(config.name.to_string()),
                    text: None,
                    text_parameter_ref_id: None,
                    internal_description: None,
                    inline: None,
                    show_in_com_object_tree: None,
                    layout: None,
                    items,
                })],
            }],
        })
    }

    /// Find the parameter ref ID for a given parameter name.
    ///
    /// This looks through the params to find the parameter by name, then
    /// constructs the corresponding ParameterRef ID.
    fn find_param_ref_id(config: &ApplicationProgramConfig, app_id: &str, param_name: &str) -> String {
        // Build a set of union selector names that are handled specially
        let union_selector_names: std::collections::HashSet<String> = config
            .union_fields
            .map(|fields| fields.iter().map(|f| format!("{}_selector", f.field_name)).collect())
            .unwrap_or_default();

        // Search through all params (virtual first, then regular)
        let mut param_counter = 1usize;
        for param_ext in config.all_params() {
            // Skip union selector params - they are numbered differently
            if union_selector_names.contains(param_ext.base.name) {
                continue;
            }

            if param_ext.base.name == param_name {
                let param_id = format!("{}_P-{}", app_id, param_counter);
                let ref_id = format!("{}_R-{}", param_id, param_counter);
                return ref_id;
            }
            param_counter += 1;
        }

        // Search through union selectors
        if let Some(union_fields) = config.union_fields {
            // Count non-selector params for ref_counter
            let non_selector_param_count =
                config.all_params().filter(|p| !union_selector_names.contains(p.base.name)).count();
            let mut ref_counter = non_selector_param_count + 1;
            let mut up_counter = 1u32;

            for field in union_fields {
                let selector_name = format!("{}_selector", field.field_name);
                if selector_name == param_name {
                    let selector_id = format!("{}_UP-{}", app_id, up_counter);
                    let selector_ref_id = format!("{}_R-{}", selector_id, ref_counter);
                    return selector_ref_id;
                }
                ref_counter += 1;
                up_counter += 1;

                // Skip variant params
                for _param in field.union_info.variant_params {
                    ref_counter += 1;
                    up_counter += 1;
                }
            }
        }

        // Fallback: just construct a reasonable ref ID
        format!("{}_P-{}_R-1", app_id, param_name)
    }

    /// Build the Dynamic section from a page layout definition.
    ///
    /// This generates the Dynamic section based on user-defined page structure,
    /// allowing precise control over how parameters are organized in the ETS UI.
    fn build_dynamic_section_from_layout(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        layout: &PageStructure,
    ) -> Result<DynamicSection, GeneratorError> {
        // Build name-to-RefId mapping for all comm objects (needed for counting)
        let comm_obj_ref_map = Self::build_comm_object_ref_map(config, app_id, mask_family);

        // Count selector usages (including PageItem::Obj which needs comm_obj_ref_map)
        let selector_usage_counts = count_selector_usages_with_objects(layout, &comm_obj_ref_map);

        // Collect union variant text overrides for creating multiple ParameterRefs with different Text
        let union_variant_texts = collect_union_variant_texts(layout);

        // Build multi-ref parameter map (supports multiple refs per selector param)
        let param_ref_map =
            Self::build_multi_param_ref_map(config, app_id, &selector_usage_counts, Some(&union_variant_texts));

        // Generate block and separator counters
        let mut block_counter = 1u32;
        let mut sep_counter = 1u32;

        // Track selector ref usage for allocating unique refs to each choose block
        let mut selector_counters = SelectorRefCounters::new();

        // Build ChannelIndependentBlock if device_settings is non-empty
        let channel_independent_block = if layout.device_settings.is_empty() {
            None
        } else {
            let items = Self::build_channel_independent_items(
                &layout.device_settings,
                config,
                app_id,
                mask_family,
                &param_ref_map,
                &comm_obj_ref_map,
                &mut block_counter,
                &mut sep_counter,
                &mut selector_counters,
            )?;
            Some(ChannelIndependentBlock { items })
        };

        // Build Channel elements
        let channels: Vec<Channel> = layout
            .channels
            .iter()
            .enumerate()
            .map(|(i, ch_def)| {
                let items = Self::build_channel_items(
                    &ch_def.elements,
                    config,
                    app_id,
                    mask_family,
                    &param_ref_map,
                    &comm_obj_ref_map,
                    &mut block_counter,
                    &mut sep_counter,
                    &mut selector_counters,
                )?;
                // Use channel number in ID if specified, otherwise use sequential index
                let ch_num = ch_def.number.unwrap_or(i as u32 + 1);
                Ok(Channel {
                    id: format!("{}_CH-{}", app_id, ch_num),
                    // Use display text for Name attribute (matches MDT convention)
                    name: ch_def.text.to_string(),
                    text: Some(ch_def.text.to_string()),
                    // XSD requires Number attribute (use index + 1 as default)
                    number: Some(ch_num.to_string()),
                    internal_description: None,
                    text_parameter_ref_id: None,
                    items,
                })
            })
            .collect::<Result<Vec<_>, GeneratorError>>()?;

        Ok(DynamicSection { channel_independent_block, channels })
    }
    /// Build a multi-ref parameter map that supports multiple refs per parameter.
    /// Parameters that are used as selectors in ObjWithValue/GroupedObjChoose
    /// get multiple refs (matching MDT's fine-grained structure).
    fn build_multi_param_ref_map(
        config: &ApplicationProgramConfig,
        app_id: &str,
        selector_usage_counts: &HashMap<String, usize>,
        union_variant_texts: Option<&HashMap<(String, String), Vec<Option<String>>>>,
    ) -> MultiParamRefMap {
        let mut primary = HashMap::new();
        let mut multi: HashMap<String, Vec<String>> = HashMap::new();
        let mut by_text: HashMap<(String, Option<String>), String> = HashMap::new();
        let mut param_ref_nums: HashMap<String, u32> = HashMap::new();

        // Build a set of union selector names
        let union_selector_names: std::collections::HashSet<String> = config
            .union_fields
            .map(|fields| fields.iter().map(|f| format!("{}_selector", f.field_name)).collect())
            .unwrap_or_default();

        // Track ref numbering - we need unique numbers for all refs
        // MDT uses high numbers for additional refs (e.g., R-90, R-174, R-216 for same P-35)
        let mut next_ref_num = 1u32;

        // Map all params (virtual first, then regular, non-selector)
        let mut param_counter = 1usize;
        for param_ext in config.all_params() {
            if union_selector_names.contains(param_ext.base.name) {
                continue;
            }
            let param_name = param_ext.base.name.to_string();
            let param_id = format!("{}_P-{}", app_id, param_counter);

            // How many refs do we need for this param?
            let num_refs = selector_usage_counts.get(&param_name).copied().unwrap_or(0).max(1);

            // Create refs
            let mut refs = Vec::with_capacity(num_refs);
            let first_ref_num = next_ref_num; // Track for param_ref_nums
            for i in 0..num_refs {
                let ref_id = format!("{}_R-{}", param_id, next_ref_num);
                if i == 0 {
                    primary.insert(param_name.clone(), ref_id.clone());
                }
                refs.push(ref_id);
                next_ref_num += 1;
            }

            // Store the primary ref number for text interpolation
            param_ref_nums.insert(param_name.clone(), first_ref_num);

            if num_refs > 1 {
                multi.insert(param_name, refs);
            }

            param_counter += 1;
        }

        // Map picture params (one ref per picture)
        let pictures = collect_pictures_from_layout(config);
        for pic in &pictures {
            let param_id = format!("{}_P-{}", app_id, param_counter);
            let pic_param_name = format!("Pic_{}", pic.baggage_name.replace('.', "_"));
            let ref_id = format!("{}_R-{}", param_id, next_ref_num);

            primary.insert(pic_param_name.clone(), ref_id);
            param_ref_nums.insert(pic_param_name, next_ref_num);
            next_ref_num += 1;
            param_counter += 1;
        }

        // Map union fields (selector and variant params)
        if let Some(union_fields) = config.union_fields {
            let mut up_counter = 1u32;

            for field in union_fields {
                // Selector param
                let selector_name = format!("{}_selector", field.field_name);
                let selector_id = format!("{}_UP-{}", app_id, up_counter);

                // How many refs for the selector?
                let num_refs = selector_usage_counts.get(&selector_name).copied().unwrap_or(0).max(1);

                let mut refs = Vec::with_capacity(num_refs);
                let first_ref_num = next_ref_num; // Track for param_ref_nums
                for i in 0..num_refs {
                    let ref_id = format!("{}_R-{}", selector_id, next_ref_num);
                    if i == 0 {
                        primary.insert(selector_name.clone(), ref_id.clone());
                    }
                    refs.push(ref_id);
                    next_ref_num += 1;
                }

                // Store the primary ref number for text interpolation
                param_ref_nums.insert(selector_name.clone(), first_ref_num);

                if num_refs > 1 {
                    multi.insert(selector_name, refs);
                }

                up_counter += 1;

                // Variant params - create refs for each unique text override
                for variant_param in field.union_info.variant_params {
                    let param_id = format!("{}_UP-{}", app_id, up_counter);
                    let full_param_name =
                        format!("{}_{}_{}", field.field_name, variant_param.variant_name, variant_param.param.name);

                    // Look up text overrides for this variant
                    let key = (field.field_name.to_string(), variant_param.variant_name.to_string());
                    let text_overrides =
                        union_variant_texts.and_then(|texts| texts.get(&key)).cloned().unwrap_or_else(|| vec![None]); // At least one ref with no text

                    // Create a ref for each unique text override
                    for (i, text) in text_overrides.iter().enumerate() {
                        let ref_id = format!("{}_R-{}", param_id, next_ref_num);
                        if i == 0 {
                            primary.insert(full_param_name.clone(), ref_id.clone());
                        }
                        // Also add to by_text for text-based lookup
                        by_text.insert((full_param_name.clone(), text.clone()), ref_id.clone());
                        next_ref_num += 1;
                    }
                    up_counter += 1;
                }
            }
        }

        MultiParamRefMap { primary, multi, by_text, param_ref_nums }
    }

    /// Build a mapping from comm object field names to their ComObjectRefRef info.
    ///
    /// Returns a map where the key is the field name (e.g., "channel_a_in") and the
    /// value is a tuple of (ref_id, selector_param, selector_value).
    ///
    /// For objects without selectors, selector_param and selector_value are None.
    /// For objects with selectors, multiple refs exist with different selector_values.
    fn build_comm_object_ref_map(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
    ) -> HashMap<String, Vec<(String, Option<String>, Option<i64>)>> {
        let mut map: HashMap<String, Vec<(String, Option<String>, Option<i64>)>> = HashMap::new();
        let co_start_index = mask_family.com_object_start_index();

        // Build ref info map
        for (i, ref_def) in config.comm_object_refs.iter().enumerate() {
            let adjusted_index = ref_def.object_index + co_start_index;
            let co_id = format!("{}_O-{}", app_id, adjusted_index);
            let ref_id = format!("{}_R-{}", co_id, i + 1);

            // Use the ref_name as the key (this is the field name from the struct)
            map.entry(ref_def.ref_name.to_string()).or_default().push((
                ref_id,
                ref_def.selector_param.map(|s| s.to_string()),
                ref_def.selector_value,
            ));
        }

        map
    }

    /// Build items for a ChannelIndependentBlock.
    fn build_channel_independent_items(
        elements: &[PageElement],
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_map: &MultiParamRefMap,
        comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
        block_counter: &mut u32,
        sep_counter: &mut u32,
        selector_counters: &mut SelectorRefCounters,
    ) -> Result<Vec<ChannelIndependentItem>, GeneratorError> {
        let mut items = Vec::new();

        // Start with empty active conditions at the top level
        let active_conditions = ActiveConditions::new();

        for element in elements {
            match element {
                PageElement::Block(block) => {
                    let pb = Self::build_parameter_block(
                        block,
                        config,
                        app_id,
                        mask_family,
                        param_ref_map,
                        comm_obj_ref_map,
                        block_counter,
                        sep_counter,
                        selector_counters,
                        &active_conditions,
                    )?;
                    items.push(ChannelIndependentItem::ParameterBlock(pb));
                }
                PageElement::When(cond) => {
                    let choose = Self::build_element_choose(
                        cond,
                        config,
                        app_id,
                        mask_family,
                        param_ref_map,
                        comm_obj_ref_map,
                        block_counter,
                        sep_counter,
                        selector_counters,
                        &active_conditions,
                    )?;
                    items.push(ChannelIndependentItem::Choose(choose));
                }
            }
        }

        Ok(items)
    }

    /// Build items for a Channel.
    fn build_channel_items(
        elements: &[PageElement],
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_map: &MultiParamRefMap,
        comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
        block_counter: &mut u32,
        sep_counter: &mut u32,
        selector_counters: &mut SelectorRefCounters,
    ) -> Result<Vec<ChannelItem>, GeneratorError> {
        let mut items = Vec::new();

        // Start with empty active conditions at the top level
        let active_conditions = ActiveConditions::new();

        for element in elements {
            match element {
                PageElement::Block(block) => {
                    let pb = Self::build_parameter_block(
                        block,
                        config,
                        app_id,
                        mask_family,
                        param_ref_map,
                        comm_obj_ref_map,
                        block_counter,
                        sep_counter,
                        selector_counters,
                        &active_conditions,
                    )?;
                    items.push(ChannelItem::ParameterBlock(pb));
                }
                PageElement::When(cond) => {
                    let choose = Self::build_element_choose(
                        cond,
                        config,
                        app_id,
                        mask_family,
                        param_ref_map,
                        comm_obj_ref_map,
                        block_counter,
                        sep_counter,
                        selector_counters,
                        &active_conditions,
                    )?;
                    items.push(ChannelItem::Choose(choose));
                }
            }
        }

        Ok(items)
    }

    /// Build a ParameterBlock from a PageBlock definition.
    fn build_parameter_block(
        block: &PageBlock,
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_map: &MultiParamRefMap,
        comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
        block_counter: &mut u32,
        sep_counter: &mut u32,
        selector_counters: &mut SelectorRefCounters,
        active_conditions: &ActiveConditions,
    ) -> Result<ParameterBlock, GeneratorError> {
        let block_id = *block_counter;
        *block_counter += 1;

        let items = Self::build_block_items(
            &block.items,
            config,
            app_id,
            mask_family,
            param_ref_map,
            comm_obj_ref_map,
            sep_counter,
            selector_counters,
            active_conditions,
        )?;

        // Resolve text parameter references in block text
        let resolved_text = Self::resolve_text_param_refs(block.text, &param_ref_map.param_ref_nums);

        Ok(ParameterBlock {
            id: format!("{}_PB-{}", app_id, block_id),
            name: Some(block.name.to_string()),
            text: Some(resolved_text),
            text_parameter_ref_id: None,
            internal_description: None,
            inline: None,
            show_in_com_object_tree: None,
            layout: None,
            items,
        })
    }

    /// Build items for a ParameterBlock.
    fn build_block_items(
        page_items: &[PageItem],
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_map: &MultiParamRefMap,
        comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
        sep_counter: &mut u32,
        selector_counters: &mut SelectorRefCounters,
        active_conditions: &ActiveConditions,
    ) -> Result<Vec<ParameterBlockItem>, GeneratorError> {
        let mut items = Vec::new();

        for page_item in page_items {
            match page_item {
                PageItem::Param(name) => {
                    if let Some(ref_id) = param_ref_map.get_primary(*name) {
                        items.push(block_param_ref(ref_id.clone()));
                    } else {
                        // Try to find it using the existing method as fallback
                        let ref_id = Self::find_param_ref_id(config, app_id, name);
                        items.push(block_param_ref(ref_id));
                    }
                }
                PageItem::Obj(name) => {
                    // Look up comm object refs by field name
                    if let Some(refs) = comm_obj_ref_map.get(*name) {
                        // Group refs by selector_param
                        let refs_with_selector: Vec<&(String, Option<String>, Option<i64>)> = refs
                            .iter()
                            .filter(|(_, sel_param, sel_val)| sel_param.is_some() && sel_val.is_some())
                            .collect();
                        let refs_without_selector: Vec<&(String, Option<String>, Option<i64>)> =
                            refs.iter().filter(|(_, sel_param, _)| sel_param.is_none()).collect();

                        // If there are no selector-based refs, just emit the unconditional ref
                        if refs_with_selector.is_empty() {
                            if let Some((ref_id, _, _)) = refs_without_selector.first() {
                                items.push(block_com_obj_ref(ref_id.clone()));
                            }
                        } else {
                            // Group refs by selector_param name
                            let mut by_selector: std::collections::HashMap<&str, Vec<(&String, i64)>> =
                                std::collections::HashMap::new();
                            for (ref_id, sel_param, sel_val) in &refs_with_selector {
                                if let (Some(param), Some(val)) = (sel_param.as_ref(), sel_val) {
                                    by_selector.entry(param.as_str()).or_default().push((ref_id, *val));
                                }
                            }

                            // For each selector_param, check if there's an active condition
                            // If so, emit only the matching ref(s) directly without a choose block
                            for (selector_param, ref_vals) in by_selector {
                                // Check if this selector_param has an active condition
                                if let Some(active_vals) = active_conditions.get_active_values(selector_param) {
                                    // We're inside a when block for this selector - emit only matching refs
                                    // Group refs by selector value
                                    let mut value_to_ref: std::collections::HashMap<i64, &String> =
                                        std::collections::HashMap::new();
                                    for (ref_id, val) in &ref_vals {
                                        value_to_ref.entry(*val).or_insert(ref_id);
                                    }

                                    // Emit refs that match the active values
                                    for active_val in active_vals {
                                        if let Some(ref_id) = value_to_ref.get(active_val) {
                                            items.push(block_com_obj_ref((*ref_id).clone()));
                                        }
                                    }
                                } else {
                                    // No active condition - create a choose/when block as before
                                    // Get unique ref index for this choose block
                                    let ref_index = selector_counters.next_index(selector_param);
                                    let selector_ref_id = param_ref_map
                                        .get(selector_param, Some(ref_index))
                                        .cloned()
                                        .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, selector_param));

                                    // Group refs by selector value - each value gets ONE when clause
                                    // with ONE ComObjectRefRef (use the first one for that value)
                                    let mut value_to_ref: std::collections::HashMap<i64, &String> =
                                        std::collections::HashMap::new();
                                    for (ref_id, val) in &ref_vals {
                                        // Only keep the first ref for each selector value
                                        value_to_ref.entry(*val).or_insert(ref_id);
                                    }

                                    // Build when clauses - one per unique selector value
                                    let mut whens: Vec<When> = value_to_ref
                                        .iter()
                                        .map(|(val, ref_id)| When {
                                            default: None,
                                            test: Some(val.to_string()),
                                            internal_description: None,
                                            items: vec![when_com_obj_ref((*ref_id).clone())],
                                        })
                                        .collect();

                                    // Sort by selector value for consistent output
                                    whens.sort_by(|a, b| {
                                        let a_val: i64 = a.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                                        let b_val: i64 = b.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                                        a_val.cmp(&b_val)
                                    });

                                    items.push(ParameterBlockItem::Choose(Choose {
                                        param_ref_id: selector_ref_id,
                                        whens,
                                    }));
                                }
                            }
                        }
                    }
                }
                PageItem::Separator(text) => {
                    let sep_id = *sep_counter;
                    *sep_counter += 1;
                    items.push(ParameterBlockItem::ParameterSeparator(ParameterSeparator {
                        id: format!("{}_PS-{}", app_id, sep_id),
                        text: text.map(|t| t.to_string()),
                    }));
                }
                PageItem::When(cond_item) => {
                    let choose = Self::build_item_choose(
                        cond_item,
                        config,
                        app_id,
                        mask_family,
                        param_ref_map,
                        comm_obj_ref_map,
                        sep_counter,
                        selector_counters,
                        active_conditions,
                    )?;
                    items.push(ParameterBlockItem::Choose(choose));
                }
                PageItem::UnionSelector(union_name) => {
                    // UnionSelector emits:
                    // 1. The selector parameter reference
                    // 2. A choose/when block for each variant's parameters

                    // Get the selector param name
                    let selector_name = format!("{}_selector", union_name);

                    // Emit selector parameter ref
                    if let Some(ref_id) = param_ref_map.get_primary(&selector_name) {
                        items.push(block_param_ref(ref_id.clone()));
                    }

                    // Find the union field info to get variant info
                    if let Some(union_fields) = config.union_fields {
                        if let Some(union_info) = union_fields.iter().find(|u| u.field_name == *union_name) {
                            // Get selector ref ID for the choose
                            let selector_ref_id = param_ref_map
                                .get_primary(&selector_name)
                                .cloned()
                                .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, &selector_name));

                            // Build when clauses for each variant
                            let mut whens: Vec<When> = Vec::new();
                            for variant in union_info.selector_variants {
                                // For each variant, find all the variant parameters
                                // Variant params are named like: union_name_VariantName_field
                                let variant_prefix = format!("{}_{}_", union_name, variant.text);

                                // Collect param refs for this variant
                                let variant_param_refs: Vec<_> = param_ref_map
                                    .primary
                                    .iter()
                                    .filter(|(name, _)| name.starts_with(&variant_prefix))
                                    .map(|(_, ref_id)| when_param_ref(ref_id.clone()))
                                    .collect();

                                // Only add when clause if there are params for this variant
                                if !variant_param_refs.is_empty() {
                                    whens.push(When {
                                        default: None,
                                        test: Some(variant.value.to_string()),
                                        internal_description: None,
                                        items: variant_param_refs,
                                    });
                                }
                            }

                            // Sort by selector value for consistent output
                            whens.sort_by(|a, b| {
                                let a_val: i64 = a.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                                let b_val: i64 = b.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                                a_val.cmp(&b_val)
                            });

                            // Only add choose if we have when clauses
                            if !whens.is_empty() {
                                items.push(ParameterBlockItem::Choose(Choose { param_ref_id: selector_ref_id, whens }));
                            }
                        }
                    }
                }
                PageItem::ObjWithValue { obj_name, selector_param, value_union, extra_params, sub_selectors } => {
                    // ObjWithValue combines object ref, optional extra params, and value param in same when blocks
                    // This matches MDT's structure where each when contains:
                    // - ComObjectRefRef
                    // - Extra param refs (optional, e.g., P-27, P-15, etc.)
                    // - Value param ref (UP-xxx)
                    //
                    // For variants with sub_selectors, the structure is different:
                    // - Extra param refs
                    // - Sub-selector param ref
                    // - Nested choose on sub-selector with:
                    //   - ComObjectRefRef (from ref_name)
                    //   - Value param ref (from variant_name)

                    // Get unique selector ref ID for this choose block
                    let ref_index = selector_counters.next_index(selector_param);
                    let selector_ref_id = param_ref_map
                        .get(*selector_param, Some(ref_index))
                        .cloned()
                        .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, selector_param));

                    // Get object refs grouped by selector value
                    let obj_refs = comm_obj_ref_map.get(*obj_name);

                    // Get union field info for value params
                    let union_info =
                        config.union_fields.and_then(|fields| fields.iter().find(|u| u.field_name == *value_union));

                    // Build a map of variant_value -> sub_selector info for quick lookup
                    let sub_selector_map: std::collections::HashMap<i64, _> =
                        sub_selectors.iter().map(|(val, param, variants)| (*val, (*param, *variants))).collect();

                    if let (Some(refs), Some(union_info)) = (obj_refs, union_info) {
                        // Group object refs by selector value
                        let mut obj_by_value: std::collections::HashMap<i64, &String> =
                            std::collections::HashMap::new();
                        for (ref_id, sel_param, sel_val) in refs {
                            if sel_param.as_ref().map(|s| s.as_str()) == Some(*selector_param) {
                                if let Some(val) = sel_val {
                                    obj_by_value.entry(*val).or_insert(ref_id);
                                }
                            }
                        }

                        // Build when clauses combining object ref, extra params, and value params
                        let mut whens: Vec<When> = Vec::new();

                        for variant in union_info.selector_variants {
                            let selector_value = variant.value;
                            let mut when_items: Vec<WhenItem> = Vec::new();

                            // Check if this variant has a sub-selector
                            if let Some((sub_selector_param, sub_variants)) = sub_selector_map.get(&selector_value) {
                                // Variant with sub-selector: extra params + sub-selector + nested choose

                                // Add extra param refs first
                                for extra_param in *extra_params {
                                    if let Some(ref_id) = param_ref_map.get_primary(*extra_param) {
                                        when_items.push(when_param_ref(ref_id.clone()));
                                    }
                                }

                                // Add sub-selector param ref
                                if let Some(ref_id) = param_ref_map.get_primary(*sub_selector_param) {
                                    when_items.push(when_param_ref(ref_id.clone()));
                                }

                                // Build nested choose on sub-selector
                                let sub_selector_ref_id = param_ref_map
                                    .get_primary(*sub_selector_param)
                                    .cloned()
                                    .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, sub_selector_param));

                                let mut nested_whens: Vec<When> = Vec::new();

                                for (sub_value, ref_name, variant_name) in *sub_variants {
                                    let mut nested_when_items: Vec<WhenItem> = Vec::new();

                                    // Look up object ref by ref_name
                                    if let Some(named_refs) = comm_obj_ref_map.get(*ref_name) {
                                        if let Some((ref_id, _, _)) = named_refs.first() {
                                            nested_when_items.push(when_com_obj_ref(ref_id.clone()));
                                        }
                                    }

                                    // Add value param refs for this sub-variant
                                    let variant_prefix = format!("{}_{}_", value_union, variant_name);
                                    for (param_name, ref_id) in param_ref_map.primary.iter() {
                                        if param_name.starts_with(&variant_prefix) {
                                            nested_when_items.push(when_param_ref(ref_id.clone()));
                                        }
                                    }

                                    if !nested_when_items.is_empty() {
                                        nested_whens.push(When {
                                            default: None,
                                            test: Some(sub_value.to_string()),
                                            internal_description: None,
                                            items: nested_when_items,
                                        });
                                    }
                                }

                                if !nested_whens.is_empty() {
                                    when_items.push(WhenItem::Choose(Choose {
                                        param_ref_id: sub_selector_ref_id,
                                        whens: nested_whens,
                                    }));
                                }
                            } else {
                                // Standard variant: object ref + extra params + value param

                                // Add object ref for this selector value
                                if let Some(obj_ref_id) = obj_by_value.get(&selector_value) {
                                    when_items.push(when_com_obj_ref((*obj_ref_id).clone()));
                                }

                                // Add extra param refs
                                for extra_param in *extra_params {
                                    if let Some(ref_id) = param_ref_map.get_primary(*extra_param) {
                                        when_items.push(when_param_ref(ref_id.clone()));
                                    }
                                }

                                // Add value param refs for this variant
                                // We need the variant NAME (like "ForcibleControl"), not display text (like "Forcible control")
                                // Look it up from variant_params using the selector value
                                let variant_name = union_info
                                    .union_info
                                    .variant_params
                                    .iter()
                                    .find(|vp| vp.variant_value == selector_value)
                                    .map(|vp| vp.variant_name)
                                    .unwrap_or("");
                                let variant_prefix = format!("{}_{}_{}", value_union, variant_name, "");
                                for (param_name, ref_id) in param_ref_map.primary.iter() {
                                    if !variant_name.is_empty()
                                        && param_name.starts_with(&variant_prefix.trim_end_matches('_'))
                                        && param_name.len() > variant_prefix.len() - 1
                                    {
                                        when_items.push(when_param_ref(ref_id.clone()));
                                    }
                                }
                            }

                            // Only add when clause if there's content
                            if !when_items.is_empty() {
                                whens.push(When {
                                    default: None,
                                    test: Some(selector_value.to_string()),
                                    internal_description: None,
                                    items: when_items,
                                });
                            }
                        }

                        // Sort by selector value
                        whens.sort_by(|a, b| {
                            let a_val: i64 = a.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                            let b_val: i64 = b.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                            a_val.cmp(&b_val)
                        });

                        if !whens.is_empty() {
                            items.push(ParameterBlockItem::Choose(Choose { param_ref_id: selector_ref_id, whens }));
                        }
                    }
                }
                PageItem::GroupedObjChoose { selector_param, hidden_params, objects } => {
                    // GroupedObjChoose creates ONE choose block containing ALL specified objects.
                    // Each when clause contains all objects' ComObjectRefRefs and value params for that type variant.
                    // This matches MDT's pattern where a single choose on P-35 (object_type) contains
                    // multiple objects like button1_main, button1_status_toggle, etc.

                    // Get unique selector ref ID for this choose block
                    let ref_index = selector_counters.next_index(selector_param);
                    let selector_ref_id = param_ref_map
                        .get(*selector_param, Some(ref_index))
                        .cloned()
                        .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, selector_param));

                    // We need to find union info from one of the value_union fields
                    // All objects in the group should use the same selector (object_type param)
                    // so we can use any value_union to get the variant list
                    let union_info = if let Some((_, first_value_union)) = objects.first() {
                        config
                            .union_fields
                            .and_then(|fields| fields.iter().find(|u| u.field_name == *first_value_union))
                    } else {
                        None
                    };

                    if let Some(union_info) = union_info {
                        // Pre-collect object refs for all objects in the group
                        let mut all_obj_refs: Vec<(&str, &str, std::collections::HashMap<i64, &String>)> = Vec::new();

                        for (obj_name, value_union) in *objects {
                            let mut obj_by_value: std::collections::HashMap<i64, &String> =
                                std::collections::HashMap::new();

                            if let Some(refs) = comm_obj_ref_map.get(*obj_name) {
                                for (ref_id, sel_param, sel_val) in refs {
                                    if sel_param.as_ref().map(|s| s.as_str()) == Some(*selector_param) {
                                        if let Some(val) = sel_val {
                                            obj_by_value.entry(*val).or_insert(ref_id);
                                        }
                                    }
                                }
                            }
                            all_obj_refs.push((*obj_name, *value_union, obj_by_value));
                        }

                        // Build when clauses - one for each variant
                        let mut whens: Vec<When> = Vec::new();

                        for variant in union_info.selector_variants {
                            let selector_value = variant.value;
                            let mut when_items: Vec<WhenItem> = Vec::new();

                            // For each object in the group, add its ComObjectRefRef and value params
                            for (_obj_name, _value_union, obj_by_value) in &all_obj_refs {
                                // Add object ref for this selector value
                                if let Some(obj_ref_id) = obj_by_value.get(&selector_value) {
                                    when_items.push(when_com_obj_ref((*obj_ref_id).clone()));
                                }

                                // Add hidden param refs (same for all objects in the group)
                                // Only add once per when clause, not per object
                                // We'll add these after all objects are processed
                            }

                            // Add hidden param refs (once per when clause)
                            for hidden_param in *hidden_params {
                                if let Some(ref_id) = param_ref_map.get_primary(*hidden_param) {
                                    when_items.push(when_param_ref(ref_id.clone()));
                                }
                            }

                            // Add value param refs for each object's union
                            for (_obj_name, value_union, _) in &all_obj_refs {
                                let variant_prefix = format!("{}_{}_", value_union, variant.text);
                                for (param_name, ref_id) in param_ref_map.primary.iter() {
                                    if param_name.starts_with(&variant_prefix) {
                                        when_items.push(when_param_ref(ref_id.clone()));
                                    }
                                }
                            }

                            // Only add when clause if there's content
                            if !when_items.is_empty() {
                                whens.push(When {
                                    default: None,
                                    test: Some(selector_value.to_string()),
                                    internal_description: None,
                                    items: when_items,
                                });
                            }
                        }

                        // Sort by selector value
                        whens.sort_by(|a, b| {
                            let a_val: i64 = a.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                            let b_val: i64 = b.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                            a_val.cmp(&b_val)
                        });

                        if !whens.is_empty() {
                            items.push(ParameterBlockItem::Choose(Choose { param_ref_id: selector_ref_id, whens }));
                        }
                    }
                }
                PageItem::ObjDirect { obj_name, params } => {
                    // ObjDirect outputs object and params directly without a choose block
                    // Used in switch mode where object type is fixed to 1Bit Switch

                    // Get object refs for this object - use the unconditional ref or first ref
                    if let Some(refs) = comm_obj_ref_map.get(*obj_name) {
                        // Prefer the unconditional ref (no selector), otherwise use first available
                        let ref_to_use =
                            refs.iter().find(|(_, sel_param, _)| sel_param.is_none()).or_else(|| refs.first());

                        if let Some((ref_id, _, _)) = ref_to_use {
                            items.push(block_com_obj_ref(ref_id.clone()));
                        }
                    }

                    // Add param refs directly
                    for param_name in *params {
                        if let Some(ref_id) = param_ref_map.get_primary(*param_name) {
                            items.push(block_param_ref(ref_id.clone()));
                        }
                    }
                }
                PageItem::ObjsDirectWithParams { obj_names, params } => {
                    // ObjsDirectWithParams outputs multiple objects followed by params directly
                    // Used in toggle mode where O-0 and O-1 appear together

                    // Add each object ref
                    for obj_name in *obj_names {
                        if let Some(refs) = comm_obj_ref_map.get(*obj_name) {
                            // Prefer the unconditional ref (no selector), otherwise use first available
                            let ref_to_use =
                                refs.iter().find(|(_, sel_param, _)| sel_param.is_none()).or_else(|| refs.first());

                            if let Some((ref_id, _, _)) = ref_to_use {
                                items.push(block_com_obj_ref(ref_id.clone()));
                            }
                        }
                    }

                    // Add param refs directly
                    for param_name in *params {
                        if let Some(ref_id) = param_ref_map.get_primary(*param_name) {
                            items.push(block_param_ref(ref_id.clone()));
                        }
                    }
                }
                PageItem::ObjsByRefName { ref_names, params } => {
                    // ObjsByRefName outputs objects by looking up specific ref_names
                    // Used when objects have named refs for different modes (e.g., dimming, blinds)

                    // Add each object ref by its ref_name
                    for ref_name in *ref_names {
                        if let Some(refs) = comm_obj_ref_map.get(*ref_name) {
                            // Get the first ref with this name (should be unique)
                            if let Some((ref_id, _, _)) = refs.first() {
                                items.push(block_com_obj_ref(ref_id.clone()));
                            }
                        }
                    }

                    // Add param refs directly
                    for param_name in *params {
                        if let Some(ref_id) = param_ref_map.get_primary(*param_name) {
                            items.push(block_param_ref(ref_id.clone()));
                        }
                    }
                }
                PageItem::ObjWithFixedVariant {
                    obj_name,
                    hidden_params,
                    union_field,
                    variant_name,
                    selector_value,
                    text_override,
                } => {
                    // ObjWithFixedVariant outputs object + hidden params + specific union variant
                    // Used in switch mode where object type is fixed (always Switch/1Bit)
                    // No choose block - outputs directly
                    // selector_value specifies which object ref to use (matching the selector's value)

                    // Get object ref matching the specified selector_value
                    if let Some(refs) = comm_obj_ref_map.get(*obj_name) {
                        let ref_to_use = refs
                            .iter()
                            .find(|(_, _, sel_val)| sel_val.as_ref() == Some(selector_value))
                            .or_else(|| refs.first());

                        if let Some((ref_id, _, _)) = ref_to_use {
                            items.push(block_com_obj_ref(ref_id.clone()));
                        }
                    }

                    // Add hidden param refs
                    for param_name in *hidden_params {
                        if let Some(ref_id) = param_ref_map.get_primary(*param_name) {
                            items.push(block_param_ref(ref_id.clone()));
                        }
                    }

                    // Add the specific union variant param
                    // Variant params are named like: union_field_VariantName_field
                    // Use get_by_text to find the ref with the matching text override (Text is on ParameterRef)
                    let variant_prefix = format!("{}_{}_", union_field, variant_name);
                    for (param_name, _) in param_ref_map.primary.iter() {
                        if param_name.starts_with(&variant_prefix) {
                            // Look up ref by text - the ParameterRef already has the Text attribute
                            let ref_id = param_ref_map
                                .get_by_text(param_name, *text_override)
                                .or_else(|| param_ref_map.get_primary(param_name));
                            if let Some(ref_id) = ref_id {
                                items.push(block_param_ref(ref_id.clone()));
                            }
                        }
                    }
                }
                PageItem::UnionVariantDirect { union_field, variant_name, text_override } => {
                    // UnionVariantDirect outputs specific variant's params directly (no choose block)
                    // Used when variant is already determined by outer context (e.g., inside switch mode)
                    // This matches MDT's pattern where UP-xxx params appear directly without choose

                    // Add the specific union variant param(s)
                    // Variant params are named like: union_field_VariantName_field
                    // Use get_by_text to find the ref with the matching text override
                    let variant_prefix = format!("{}_{}_", union_field, variant_name);
                    for (param_name, _) in param_ref_map.primary.iter() {
                        if param_name.starts_with(&variant_prefix) {
                            // Look up ref by text - the ParameterRef already has the Text attribute
                            let ref_id = param_ref_map
                                .get_by_text(param_name, *text_override)
                                .or_else(|| param_ref_map.get_primary(param_name));
                            if let Some(ref_id) = ref_id {
                                items.push(block_param_ref(ref_id.clone()));
                            }
                        }
                    }
                }
                PageItem::UnionVariantWithChoose { union_field, variant_name, text_override, cases } => {
                    // UnionVariantWithChoose outputs the union variant param FIRST,
                    // then creates a choose block that references that same param.
                    // This matches MDT's pattern:
                    //   <ParameterRefRef RefId="...UP-143_R-172" />
                    //   <choose ParamRefId="...UP-143_R-172">
                    //     <when test="2">...</when>
                    //   </choose>

                    // First, find and output the union variant param ref
                    // Use get_by_text to find the ref with the matching text override
                    let variant_prefix = format!("{}_{}_", union_field, variant_name);
                    let mut param_ref_id: Option<String> = None;
                    for (param_name, _) in param_ref_map.primary.iter() {
                        if param_name.starts_with(&variant_prefix) {
                            // Look up ref by text - the ParameterRef already has the Text attribute
                            let ref_id = param_ref_map
                                .get_by_text(param_name, *text_override)
                                .or_else(|| param_ref_map.get_primary(param_name));
                            if let Some(ref_id) = ref_id {
                                items.push(block_param_ref(ref_id.clone()));
                                param_ref_id = Some(ref_id.clone());
                            }
                            break; // Only output one param for the union variant
                        }
                    }

                    // Now create the choose block referencing that same param
                    if let Some(ref_id) = param_ref_id {
                        let mut whens = Vec::new();
                        for case in cases {
                            // Recursively build the items for this case
                            let case_block_items = Self::build_block_items(
                                &case.items,
                                config,
                                app_id,
                                mask_family,
                                param_ref_map,
                                comm_obj_ref_map,
                                sep_counter,
                                selector_counters,
                                active_conditions,
                            )?;
                            // Convert ParameterBlockItem to WhenItem
                            let when_items = block_items_to_when_items(case_block_items);
                            whens.push(When {
                                test: case.condition.to_test_string(),
                                default: if case.condition.is_default() { Some(true) } else { None },
                                internal_description: None,
                                items: when_items,
                            });
                        }
                        if !whens.is_empty() {
                            items.push(ParameterBlockItem::Choose(Choose { param_ref_id: ref_id, whens }));
                        }
                    }
                }
                PageItem::ChooseOnUnionVariant { union_field, variant_name, cases } => {
                    // ChooseOnUnionVariant creates ONLY a choose block referencing an already-output
                    // union variant parameter. Use this after union_variant to create additional
                    // choose blocks that reference the same param without re-outputting it.
                    // This matches MDT's pattern where UP-xxx is output once, then referenced
                    // by multiple choose blocks in nested contexts.

                    // Find the union variant param ref (should have been output earlier)
                    let variant_prefix = format!("{}_{}_", union_field, variant_name);
                    let mut param_ref_id: Option<String> = None;
                    for (param_name, ref_id) in param_ref_map.primary.iter() {
                        if param_name.starts_with(&variant_prefix) {
                            param_ref_id = Some(ref_id.clone());
                            break;
                        }
                    }

                    // Create the choose block (without outputting the param ref)
                    if let Some(ref_id) = param_ref_id {
                        let mut whens = Vec::new();
                        for case in cases {
                            // Recursively build the items for this case
                            let case_block_items = Self::build_block_items(
                                &case.items,
                                config,
                                app_id,
                                mask_family,
                                param_ref_map,
                                comm_obj_ref_map,
                                sep_counter,
                                selector_counters,
                                active_conditions,
                            )?;
                            // Convert ParameterBlockItem to WhenItem
                            let when_items = block_items_to_when_items(case_block_items);
                            whens.push(When {
                                test: case.condition.to_test_string(),
                                default: if case.condition.is_default() { Some(true) } else { None },
                                internal_description: None,
                                items: when_items,
                            });
                        }
                        if !whens.is_empty() {
                            items.push(ParameterBlockItem::Choose(Choose { param_ref_id: ref_id, whens }));
                        }
                    }
                }
                PageItem::Module { module_name, instance_index } => {
                    // Module instances are generated as Module XML elements.
                    // They need the module collection to look up the definition and instance data.
                    if let Some(modules) = config.modules.as_ref() {
                        // Find the module definition by name
                        let def = modules.definitions().iter().enumerate().find(|(_, d)| d.name == *module_name);
                        if let Some((def_idx, def)) = def {
                            // Find the specific instance
                            let instances_for_def: Vec<_> = modules
                                .raw_instances()
                                .iter()
                                .enumerate()
                                .filter(|(_, inst)| inst.def_index == def_idx)
                                .collect();

                            if let Some((global_idx, instance)) = instances_for_def.get(*instance_index) {
                                // Build the Module schema element
                                let module_def_id = format!("{}_MD-{}", app_id, def_idx + 1);
                                let module_instance_id = format!("{}_M-{}", module_def_id, global_idx + 1);

                                let mut args = Vec::new();
                                for (arg_idx, (_arg_def, arg_val)) in
                                    def.arguments.iter().zip(instance.args.iter()).enumerate()
                                {
                                    let arg_ref_id = format!("{}_A-{}", module_def_id, arg_idx + 1);
                                    match arg_val {
                                        crate::definition::module::ModuleArgValue::Numeric(v) => {
                                            args.push(ModuleArg::NumericArg { ref_id: arg_ref_id, value: *v });
                                        }
                                        crate::definition::module::ModuleArgValue::Text(v) => {
                                            args.push(ModuleArg::TextArg {
                                                ref_id: arg_ref_id,
                                                id: format!("{}_TA-{}", module_instance_id, arg_idx + 1),
                                                value: v.clone(),
                                            });
                                        }
                                    }
                                }

                                items.push(ParameterBlockItem::Module(Module {
                                    id: module_instance_id,
                                    ref_id: module_def_id,
                                    name: None,
                                    internal_description: None,
                                    args,
                                }));
                            }
                        }
                    }
                }
                PageItem::ModuleInline { module_name, args: inline_args } => {
                    // Module instances with inline arguments - create instance on the fly.
                    // This allows defining module instances directly in the page layout.
                    if let Some(modules) = config.modules.as_ref() {
                        // Find the module definition by name
                        let def = modules.definitions().iter().enumerate().find(|(_, d)| d.name == *module_name);
                        if let Some((def_idx, def)) = def {
                            // Count how many inline instances we've seen for this module
                            // to generate unique instance IDs
                            // We use a simple approach: hash the inline args to create a unique suffix
                            let args_hash: i64 =
                                inline_args.iter().map(|(name, val)| name.len() as i64 * 31 + val).sum();
                            let instance_suffix = (args_hash.abs() % 10000) + 1;

                            let module_def_id = format!("{}_MD-{}", app_id, def_idx + 1);
                            let module_instance_id = format!("{}_M-{}", module_def_id, instance_suffix);

                            // Build argument values from inline args, matching by name
                            let mut schema_args = Vec::new();
                            for (arg_idx, arg_def) in def.arguments.iter().enumerate() {
                                let arg_ref_id = format!("{}_A-{}", module_def_id, arg_idx + 1);
                                // Find the inline arg value by name
                                if let Some((_, value)) = inline_args.iter().find(|(name, _)| *name == arg_def.name) {
                                    schema_args.push(ModuleArg::NumericArg { ref_id: arg_ref_id, value: *value });
                                } else {
                                    // Argument not found in inline args - use 0 as default
                                    schema_args.push(ModuleArg::NumericArg { ref_id: arg_ref_id, value: 0 });
                                }
                            }

                            items.push(ParameterBlockItem::Module(Module {
                                id: module_instance_id,
                                ref_id: module_def_id,
                                name: None,
                                internal_description: None,
                                args: schema_args,
                            }));
                        }
                    }
                }
                PageItem::ModuleInstances { module_name, instances } => {
                    // Multiple module instances with visibility conditions.
                    // Generates a choose/when block for each instance.
                    if let Some(modules) = config.modules.as_ref() {
                        // Find the module definition by name
                        let def = modules.definitions().iter().enumerate().find(|(_, d)| d.name == *module_name);
                        if let Some((def_idx, def)) = def {
                            let module_def_id = format!("{}_MD-{}", app_id, def_idx + 1);

                            for (idx, (selector, inline_args)) in instances.iter().enumerate() {
                                // Get the param ref for the selector
                                if let Some(selector_ref_id) = param_ref_map.get_primary(selector) {
                                    // Create module instance
                                    let instance_suffix = idx + 1;
                                    let module_instance_id = format!("{}_M-{}", module_def_id, instance_suffix);

                                    // Build argument values from inline args
                                    let mut schema_args = Vec::new();
                                    for (arg_idx, arg_def) in def.arguments.iter().enumerate() {
                                        let arg_ref_id = format!("{}_A-{}", module_def_id, arg_idx + 1);
                                        if let Some((_, value)) =
                                            inline_args.iter().find(|(name, _)| *name == arg_def.name)
                                        {
                                            schema_args
                                                .push(ModuleArg::NumericArg { ref_id: arg_ref_id, value: *value });
                                        } else {
                                            schema_args.push(ModuleArg::NumericArg { ref_id: arg_ref_id, value: 0 });
                                        }
                                    }

                                    // Create a choose/when wrapper for visibility
                                    let module_item = WhenItem::Module(Module {
                                        id: module_instance_id,
                                        ref_id: module_def_id.clone(),
                                        name: None,
                                        internal_description: None,
                                        args: schema_args,
                                    });

                                    // Wrap in choose/when for conditional visibility
                                    items.push(ParameterBlockItem::Choose(Choose {
                                        param_ref_id: selector_ref_id.clone(),
                                        whens: vec![When {
                                            test: Some("1".to_string()),
                                            default: None,
                                            internal_description: None,
                                            items: vec![module_item],
                                        }],
                                    }));
                                }
                            }
                        }
                    }
                }
                PageItem::Picture(baggage_name) => {
                    // Pictures are virtual parameters with TypePicture.
                    // Look up the ParameterRefRef for this picture.
                    let pic_param_name = format!("Pic_{}", baggage_name.replace('.', "_"));
                    if let Some(ref_id) = param_ref_map.get_primary(&pic_param_name) {
                        items.push(block_param_ref(ref_id.clone()));
                    } else {
                        log::warn!("Picture param ref not found for: {}", baggage_name);
                    }
                }
            }
        }

        Ok(items)
    }

    /// Build a Choose element for block-level conditionals (wrapping ParameterBlocks).
    fn build_element_choose(
        cond: &ConditionalElement,
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_map: &MultiParamRefMap,
        comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
        block_counter: &mut u32,
        sep_counter: &mut u32,
        selector_counters: &mut SelectorRefCounters,
        active_conditions: &ActiveConditions,
    ) -> Result<Choose, GeneratorError> {
        let selector_ref_id = param_ref_map
            .get_primary(cond.selector)
            .cloned()
            .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, cond.selector));

        let mut whens = Vec::new();
        for case in &cond.cases {
            // Create new active conditions with this case's selector and values
            let case_active_conditions = active_conditions.with_condition(cond.selector, case.condition.to_values());

            let mut when_items: Vec<WhenItem> = Vec::new();
            for elem in &case.elements {
                match elem {
                    PageElement::Block(block) => {
                        if let Ok(pb) = Self::build_parameter_block(
                            block,
                            config,
                            app_id,
                            mask_family,
                            param_ref_map,
                            comm_obj_ref_map,
                            block_counter,
                            sep_counter,
                            selector_counters,
                            &case_active_conditions,
                        ) {
                            when_items.push(WhenItem::ParameterBlock(pb));
                        }
                    }
                    PageElement::When(nested_cond) => {
                        if let Ok(choose) = Self::build_element_choose(
                            nested_cond,
                            config,
                            app_id,
                            mask_family,
                            param_ref_map,
                            comm_obj_ref_map,
                            block_counter,
                            sep_counter,
                            selector_counters,
                            &case_active_conditions,
                        ) {
                            when_items.push(WhenItem::Choose(choose));
                        }
                    }
                }
            }

            whens.push(When {
                test: case.condition.to_test_string(),
                default: if case.condition.is_default() { Some(true) } else { None },
                internal_description: None,
                items: when_items,
            });
        }

        Ok(Choose { param_ref_id: selector_ref_id, whens })
    }

    /// Build a Choose element for item-level conditionals (within a ParameterBlock).
    fn build_item_choose(
        cond: &ConditionalItem,
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_map: &MultiParamRefMap,
        comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
        sep_counter: &mut u32,
        selector_counters: &mut SelectorRefCounters,
        active_conditions: &ActiveConditions,
    ) -> Result<Choose, GeneratorError> {
        let selector_ref_id = param_ref_map
            .get_primary(cond.selector)
            .cloned()
            .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, cond.selector));

        let mut whens = Vec::new();
        for case in &cond.cases {
            // Create new active conditions with this case's selector and values
            let case_active_conditions = active_conditions.with_condition(cond.selector, case.condition.to_values());
            let items = Self::build_block_items(
                &case.items,
                config,
                app_id,
                mask_family,
                param_ref_map,
                comm_obj_ref_map,
                sep_counter,
                selector_counters,
                &case_active_conditions,
            )?;

            // Convert ParameterBlockItem to WhenItem (filter out Buttons/Rows/Columns which aren't in WhenItem)
            let when_items: Vec<WhenItem> = items
                .into_iter()
                .filter_map(|item| match item {
                    ParameterBlockItem::ParameterRefRef(prr) => Some(WhenItem::ParameterRefRef(prr)),
                    ParameterBlockItem::ComObjectRefRef(corr) => Some(WhenItem::ComObjectRefRef(corr)),
                    ParameterBlockItem::ParameterSeparator(ps) => Some(WhenItem::ParameterSeparator(ps)),
                    ParameterBlockItem::Choose(c) => Some(WhenItem::Choose(c)),
                    ParameterBlockItem::Module(m) => Some(WhenItem::Module(m)),
                    ParameterBlockItem::Button(_) => None,
                    ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => None,
                })
                .collect();

            whens.push(When {
                test: case.condition.to_test_string(),
                default: if case.condition.is_default() { Some(true) } else { None },
                internal_description: None,
                items: when_items,
            });
        }

        Ok(Choose { param_ref_id: selector_ref_id, whens })
    }

    /// Serialize the KNX document to XML string.
    fn serialize(knx: &Knx) -> Result<String, GeneratorError> {
        let mut buffer = String::new();
        buffer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        let mut serializer = quick_xml::se::Serializer::new(&mut buffer);
        serializer.indent(' ', 2);

        serde::Serialize::serialize(knx, serializer).map_err(|e| GeneratorError::Serialization(e.to_string()))?;

        Ok(buffer)
    }

    /// Validate all references in the generated document.
    ///
    /// This checks that:
    /// 1. All ParameterRefRef RefIds have matching ParameterRef Ids
    /// 2. All ComObjectRefRef RefIds have matching ComObjectRef Ids
    /// 3. All Choose ParamRefId values have matching ParameterRef Ids
    /// 4. All Parameter ParameterType references have matching ParameterType Ids
    pub fn validate(knx: &Knx) -> Result<(), GeneratorError> {
        let app = &knx.manufacturer_data.manufacturer.application_programs.programs[0];

        // Collect all defined IDs
        let param_ref_ids: std::collections::HashSet<&str> = app
            .static_section
            .parameter_refs
            .as_ref()
            .map(|refs| refs.refs.iter().map(|r| r.id.as_str()).collect())
            .unwrap_or_default();

        let com_obj_ref_ids: std::collections::HashSet<&str> = app
            .static_section
            .com_object_refs
            .as_ref()
            .map(|refs| refs.refs.iter().map(|r| r.id.as_str()).collect())
            .unwrap_or_default();

        let param_type_ids: std::collections::HashSet<&str> = app
            .static_section
            .parameter_types
            .as_ref()
            .map(|types| types.types.iter().map(|t| t.id.as_str()).collect())
            .unwrap_or_default();

        // Check Parameter -> ParameterType references
        if let Some(params) = &app.static_section.parameters {
            for item in &params.items {
                if let ParameterItem::Parameter(param) = item {
                    if !param_type_ids.contains(param.parameter_type.as_str()) {
                        return Err(GeneratorError::MissingReference {
                            ref_type: "ParameterType".to_string(),
                            ref_id: param.parameter_type.clone(),
                            context: format!("Parameter '{}'", param.name),
                        });
                    }
                }
            }
        }

        // Check references in Dynamic section
        if let Some(dynamic) = &app.dynamic {
            // Check ChannelIndependentBlock
            if let Some(cib) = &dynamic.channel_independent_block {
                Self::validate_channel_independent_items(&cib.items, &param_ref_ids, &com_obj_ref_ids)?;
            }

            // Check Channels
            for channel in &dynamic.channels {
                Self::validate_channel_items(&channel.items, &param_ref_ids, &com_obj_ref_ids)?;
            }
        }

        Ok(())
    }

    fn validate_channel_independent_items(
        items: &[ChannelIndependentItem],
        param_ref_ids: &std::collections::HashSet<&str>,
        com_obj_ref_ids: &std::collections::HashSet<&str>,
    ) -> Result<(), GeneratorError> {
        for item in items {
            match item {
                ChannelIndependentItem::ParameterBlock(pb) => {
                    Self::validate_parameter_block_items(&pb.items, param_ref_ids, com_obj_ref_ids)?;
                }
                ChannelIndependentItem::Choose(choose) => {
                    Self::validate_choose(choose, param_ref_ids, com_obj_ref_ids)?;
                }
            }
        }
        Ok(())
    }

    fn validate_channel_items(
        items: &[ChannelItem],
        param_ref_ids: &std::collections::HashSet<&str>,
        com_obj_ref_ids: &std::collections::HashSet<&str>,
    ) -> Result<(), GeneratorError> {
        for item in items {
            match item {
                ChannelItem::ParameterBlock(pb) => {
                    Self::validate_parameter_block_items(&pb.items, param_ref_ids, com_obj_ref_ids)?;
                }
                ChannelItem::Choose(choose) => {
                    Self::validate_choose(choose, param_ref_ids, com_obj_ref_ids)?;
                }
                ChannelItem::Module(_) => {
                    // Module instances are validated separately - skip for now
                }
            }
        }
        Ok(())
    }

    fn validate_parameter_block_items(
        items: &[ParameterBlockItem],
        param_ref_ids: &std::collections::HashSet<&str>,
        com_obj_ref_ids: &std::collections::HashSet<&str>,
    ) -> Result<(), GeneratorError> {
        for item in items {
            match item {
                ParameterBlockItem::ParameterRefRef(prr) => {
                    if !param_ref_ids.contains(prr.ref_id.as_str()) {
                        return Err(GeneratorError::MissingReference {
                            ref_type: "ParameterRef".to_string(),
                            ref_id: prr.ref_id.clone(),
                            context: "ParameterRefRef in ParameterBlock".to_string(),
                        });
                    }
                }
                ParameterBlockItem::ComObjectRefRef(corr) => {
                    if !com_obj_ref_ids.contains(corr.ref_id.as_str()) {
                        return Err(GeneratorError::MissingReference {
                            ref_type: "ComObjectRef".to_string(),
                            ref_id: corr.ref_id.clone(),
                            context: "ComObjectRefRef in ParameterBlock".to_string(),
                        });
                    }
                }
                ParameterBlockItem::Choose(choose) => {
                    Self::validate_choose(choose, param_ref_ids, com_obj_ref_ids)?;
                }
                ParameterBlockItem::ParameterSeparator(_) => {}
                ParameterBlockItem::Module(_) => {
                    // Module instances are validated separately - skip for now
                }
                ParameterBlockItem::Button(_) => {
                    // Buttons are UI elements, no validation needed
                }
                ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => {
                    // Table layout elements, no validation needed
                }
            }
        }
        Ok(())
    }

    fn validate_choose(
        choose: &Choose,
        param_ref_ids: &std::collections::HashSet<&str>,
        com_obj_ref_ids: &std::collections::HashSet<&str>,
    ) -> Result<(), GeneratorError> {
        // Validate the Choose's ParamRefId
        if !param_ref_ids.contains(choose.param_ref_id.as_str()) {
            return Err(GeneratorError::MissingReference {
                ref_type: "ParameterRef".to_string(),
                ref_id: choose.param_ref_id.clone(),
                context: "Choose ParamRefId".to_string(),
            });
        }

        // Validate items in each when clause
        for when in &choose.whens {
            Self::validate_when_items(&when.items, param_ref_ids, com_obj_ref_ids)?;
        }

        Ok(())
    }

    fn validate_when_items(
        items: &[WhenItem],
        param_ref_ids: &std::collections::HashSet<&str>,
        com_obj_ref_ids: &std::collections::HashSet<&str>,
    ) -> Result<(), GeneratorError> {
        for item in items {
            match item {
                WhenItem::ParameterRefRef(prr) => {
                    if !param_ref_ids.contains(prr.ref_id.as_str()) {
                        return Err(GeneratorError::MissingReference {
                            ref_type: "ParameterRef".to_string(),
                            ref_id: prr.ref_id.clone(),
                            context: "ParameterRefRef in When".to_string(),
                        });
                    }
                }
                WhenItem::ComObjectRefRef(corr) => {
                    if !com_obj_ref_ids.contains(corr.ref_id.as_str()) {
                        return Err(GeneratorError::MissingReference {
                            ref_type: "ComObjectRef".to_string(),
                            ref_id: corr.ref_id.clone(),
                            context: "ComObjectRefRef in When".to_string(),
                        });
                    }
                }
                WhenItem::Choose(nested_choose) => {
                    Self::validate_choose(nested_choose, param_ref_ids, com_obj_ref_ids)?;
                }
                WhenItem::ParameterBlock(pb) => {
                    Self::validate_parameter_block_items(&pb.items, param_ref_ids, com_obj_ref_ids)?;
                }
                WhenItem::ParameterSeparator(_) => {}
                WhenItem::Assign(_) => {
                    // Assign elements copy parameter values; validation would check refs exist
                }
                WhenItem::Module(_) => {
                    // Module instances are validated separately - skip for now
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// Hardware MTXML Generator
// ============================================================================
