//! Project checked parameter locations into the compiler's native address spaces.
//! The editor owns labels and clipping; ETS evaluation owns parameter geometry.

use super::ProductEditor;
use crate::app::ProjectContext;
use zweidraehte_client::commissioning::{
    ImageLocation, ImageRequirement, ImageSpace, NativeImageRegion, ObjectSelector, Occurrence, ProgramImage,
};
use zweidraehte_client::configuration::{
    InstallationConfiguration, MaterializedDevice, MembershipRole as ClientMembershipRole,
    ObjectMembership as ClientObjectMembership, ResolvedKeyMaterial,
};
use zweidraehte_client::project::product_object_flags;
use zweidraehte_ets_files::product::ParameterLocation;
use zweidraehte_ets_files::runtime::configuration::ObjectSetting;
use zweidraehte_ets_files::schema::ModuleDef;
use zweidraehte_project::{MutableProjectState, ProjectDeviceId};

/// The editor's device and the project facts its previews consult.
pub(in crate::app) struct PreviewTarget {
    pub(in crate::app) device: MaterializedDevice,
    pub(in crate::app) id: ProjectDeviceId,
    pub(in crate::app) address: zweidraehte_proto::address::IndividualAddress,
    pub(in crate::app) state: Option<MutableProjectState>,
}

#[derive(Debug)]
pub(in crate::app) struct ConfigurationPreview {
    image: ProgramImage,
    annotations: ParameterAnnotations,
}

/// A parsed memory segment for display in the hex view.
#[derive(Debug, Clone)]
pub struct MemorySegment {
    /// Segment ID from XML
    pub id: String,
    /// Native compiler address space, retaining every object selector.
    pub placement: ImageSpace,
    /// Start address (for absolute) or offset (for relative)
    pub address: u32,
    /// Size in bytes (declared size)
    pub size: u32,
    /// Memory type (RAM, EEPROM, etc.) - optional for absolute segments
    pub memory_type: Option<String>,
    /// Raw byte data decoded from base64
    pub data: Vec<u8>,
    /// Desired writable bits; zero masks identify unowned reserved bytes.
    pub mask: Vec<u8>,
    /// Parameter annotations: regions occupied by parameters
    pub annotations: Vec<MemoryAnnotation>,
    /// Byte offset → index into `annotations` (`u32::MAX` = none), one
    /// entry per byte of `data`. The hex view queries an annotation for
    /// every visible cell every frame; with tens of thousands of
    /// annotations in one segment a linear scan per cell dominates the
    /// frame time, so the lookup is precomputed here at rebuild time.
    pub annotation_index: Vec<u32>,
}

impl MemorySegment {
    pub fn location_label(&self) -> String {
        let space = image_space_label(&self.placement);
        format!("{space} +0x{:04X}", self.address)
    }
}

/// Human-readable name of a native compiler address space.
pub(in crate::app) fn image_space_label(space: &ImageSpace) -> String {
    let object_label = |object: &ObjectSelector| match object {
        ObjectSelector::Index { index } => format!("object index {index}"),
        ObjectSelector::Type { object_type, occurrence } => {
            let occurrence = match occurrence {
                Occurrence::Absent => "unspecified occurrence".to_owned(),
                Occurrence::Zero => "occurrence 0".to_owned(),
                Occurrence::Positive { value } => format!("occurrence {value}"),
            };
            format!("object type {object_type}, {occurrence}")
        }
    };
    match space {
        ImageSpace::StandardMemory => "memory".to_owned(),
        ImageSpace::UserMemory => "user memory".to_owned(),
        ImageSpace::RelativeMemory { object } => format!("relative to {}", object_label(object)),
        ImageSpace::Property { object, property_id } => {
            format!("{}, PID {property_id}", object_label(object))
        }
        ImageSpace::PropertyCount { object, property_id } => {
            format!("{}, PID {property_id} array count", object_label(object))
        }
        ImageSpace::Pointer { resource_id } => format!("pointer {resource_id}"),
        ImageSpace::LineCouplerFilter => "coupler filter".to_owned(),
        ImageSpace::LineCouplerSlave => "coupler slave".to_owned(),
    }
}

pub fn image_requirements_label(requirements: &[ImageRequirement]) -> String {
    requirements
        .iter()
        .map(|requirement| match requirement {
            ImageRequirement::AssociationTableEntrySize { .. } => "association table row size".to_owned(),
            ImageRequirement::DataSecurityMode => "current Data Secure mode".to_owned(),
            _ => "device-specific live fact".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Annotation for a memory region occupied by a parameter.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields reserved for future use (click-to-navigate)
pub struct MemoryAnnotation {
    /// Byte offset within the segment
    pub offset: u32,
    /// Bit offset (0-7)
    pub bit_offset: u8,
    /// Parameter name for display
    pub name: String,
    /// Size in bits
    pub size_bits: u16,
    /// Parameter ID for linking
    pub param_id: String,
}

#[derive(Debug)]
pub(super) struct ParameterAnnotations(Vec<(ImageLocation, MemoryAnnotation)>);

impl ParameterAnnotations {
    pub(in crate::app) fn new(parameters: &[(ParameterLocation, String)], regions: &[NativeImageRegion]) -> Self {
        Self(
            parameters
                .iter()
                .filter_map(|(parameter, name)| {
                    // Parameters without a known width or a compiled segment have no
                    // memory span to display. Inventing a byte would mislabel the image.
                    if parameter.size_bits == 0 {
                        return None;
                    }
                    let region =
                        regions.iter().find(|region| region.source_id.as_deref() == Some(&parameter.code_segment))?;
                    let offset = region.location.offset.checked_add(parameter.offset)?;
                    Some((ImageLocation { space: region.location.space.clone(), offset }, MemoryAnnotation {
                        offset: 0,
                        bit_offset: parameter.bit_offset,
                        size_bits: parameter.size_bits,
                        name: name.clone(),
                        param_id: parameter.id.clone(),
                    }))
                })
                .collect(),
        )
    }

    pub(in crate::app) fn for_region(&self, location: &ImageLocation, length: u32) -> Vec<MemoryAnnotation> {
        let start = u64::from(location.offset) * 8;
        let end = start + u64::from(length) * 8;
        let mut annotations: Vec<_> = self
            .0
            .iter()
            .filter_map(|(source, annotation)| {
                if source.space != location.space {
                    return None;
                }
                let source_start = u64::from(source.offset) * 8 + u64::from(annotation.bit_offset);
                let source_end = source_start + u64::from(annotation.size_bits);
                let overlap_start = start.max(source_start);
                let overlap_end = end.min(source_end);
                if overlap_start >= overlap_end {
                    return None;
                }
                let relative = overlap_start - start;
                Some(MemoryAnnotation {
                    offset: (relative / 8) as u32,
                    bit_offset: (relative % 8) as u8,
                    size_bits: (overlap_end - overlap_start) as u16,
                    ..annotation.clone()
                })
            })
            .collect();
        annotations.sort_by_key(|annotation| (annotation.offset, annotation.bit_offset));
        annotations
    }
}

impl MemorySegment {
    pub(in crate::app) fn rebuild_annotation_index(&mut self) {
        self.annotation_index = vec![u32::MAX; self.data.len()];
        for (index, annotation) in self.annotations.iter().enumerate() {
            let start = annotation.offset as usize;
            let end = (start + (usize::from(annotation.bit_offset) + usize::from(annotation.size_bits)).div_ceil(8))
                .min(self.data.len());
            for slot in self.annotation_index.get_mut(start..end).unwrap_or_default() {
                if *slot == u32::MAX {
                    *slot = index as u32;
                }
            }
        }
    }
}

impl ProductEditor {
    /// Rebuild memory segments from the Code section in the ApplicationProgram.
    pub(in crate::app) fn rebuild_memory_segments(&mut self, context: Option<&ProjectContext>) -> Option<String> {
        self.memory_dirty = false;
        self.view.memory_segments.clear();
        self.view.memory_requirements.clear();
        let preview = match self.configuration_preview(context) {
            Ok(preview) => preview,
            Err(error) => {
                return Some(format!("Cannot build configuration preview: {error}"));
            }
        };
        self.view.memory_requirements = preview.image.requirements().to_vec();
        let message = if !self.view.memory_requirements.is_empty() {
            Some(format!(
                "Preview needs target observations: {}",
                image_requirements_label(&self.view.memory_requirements)
            ))
        } else {
            None
        };
        for (region, bytes) in preview.image.projected_regions() {
            let id = region.display_id().into_owned();
            let annotations = preview.annotations.for_region(&region.location, region.length);
            self.view.memory_segments.push(MemorySegment {
                id,
                placement: region.location.space.clone(),
                address: region.location.offset,
                size: region.length,
                memory_type: region.memory_type.clone(),
                data: bytes.data().to_vec(),
                mask: bytes.mask().to_vec(),
                annotations,
                annotation_index: Vec::new(),
            });
        }

        for table in preview.image.table_spans() {
            let target = self.view.memory_segments.iter_mut().find(|segment| {
                segment.placement == table.location.space
                    && table.location.offset >= segment.address
                    && table.location.offset < segment.address.saturating_add(segment.data.len() as u32)
            });
            let Some(segment) = target else { continue };
            let offset = table.location.offset.saturating_sub(segment.address);
            segment.annotations.push(MemoryAnnotation {
                offset,
                bit_offset: 0,
                name: format!("{:?} table", table.kind),
                size_bits: u16::try_from(table.len.saturating_mul(8)).unwrap_or(u16::MAX),
                param_id: String::new(),
            });
        }

        self.view
            .memory_segments
            .sort_by(|left, right| (&left.placement, left.address).cmp(&(&right.placement, right.address)));

        // Build the per-byte annotation lookup last: the synthetic table
        // generators above may still extend a code segment's annotation
        // list after the segment was pushed. First annotation in list
        // order wins, matching the scan this index replaces (bit fields
        // sharing a byte resolve to the lowest (offset, bit_offset)).
        for segment in &mut self.view.memory_segments {
            segment.rebuild_annotation_index();
        }
        message
    }

    /// Materialize the editor's device as a download from its project would,
    /// with the project identity and durable state every preview consults.
    pub(in crate::app) fn preview_target(&self, context: Option<&ProjectContext>) -> Result<PreviewTarget, String> {
        let object_settings: Vec<_> = self
            .view
            .object_flag_overrides
            .iter()
            .map(|(&com_object, &flags)| ObjectSetting { com_object, flags: product_object_flags(flags) })
            .collect();

        let authored_device = context
            .and_then(|context| context.authored.as_ref().and_then(|project| project.devices.get(&context.device)));
        let address = authored_device
            .map_or_else(|| zweidraehte_proto::address::IndividualAddress::new(1, 1, 1), |device| device.address);
        let serial_number = authored_device.and_then(|device| device.serial);
        let object_memberships = self
            .view
            .device
            .all_bindings()
            .flat_map(|(com_object, bindings)| {
                bindings.iter().map(move |binding| ClientObjectMembership {
                    group_address: binding.group_address,
                    com_object,
                    role: if binding.is_sending {
                        ClientMembershipRole::Primary
                    } else {
                        ClientMembershipRole::Additional
                    },
                })
            })
            .collect();
        let mut base = InstallationConfiguration::new(address);
        base.object_memberships = object_memberships;
        base.max_apdu = authored_device.and_then(|device| device.max_apdu);
        // Project keys are intentionally absent from UI memory. The preview
        // redacts Security IO key spans when a caller supplies them; this
        // product view compiles the ordinary application image.
        base.security.serial_number = serial_number;
        let evaluated = self.view.device.evaluate(&object_settings).map_err(|error| error.to_string())?;
        let resolved = MaterializedDevice::from_evaluated(evaluated, base).map_err(|error| error.to_string())?;
        // The editor bound its product to the selected Master Data when it
        // was prepared, so the resolved device already carries that document.
        let keys = serial_number.map_or_else(ResolvedKeyMaterial::default, |serial| {
            ResolvedKeyMaterial::default().with_serial_number(serial)
        });
        let device = resolved.into_keyed(keys);

        // A project device may have been programmed before. Its deployment
        // record holds the target facts Master Data cannot tell, so previews
        // read the durable state at every rebuild: a download by this editor
        // or any other tool is reflected on the next one. A standalone
        // product has no project, hence no deployment evidence to consult.
        let state = match context.filter(|context| context.authored.is_some()) {
            Some(context) => zweidraehte_project::ProjectStore::open(&context.path)
                .map_err(|error| format!("opening project state: {error}"))?
                .state()
                .cloned(),
            None => None,
        };
        let id = context.map_or_else(
            || ProjectDeviceId::new("standalone-product").expect("literal is an identifier"),
            |context| context.device.clone(),
        );
        Ok(PreviewTarget { device, id, address, state })
    }

    pub(in crate::app) fn configuration_preview(
        &self,
        context: Option<&ProjectContext>,
    ) -> Result<ConfigurationPreview, String> {
        let PreviewTarget { device, id, address, state } = self.preview_target(context)?;
        let parameters = device
            .product()
            .parameters()
            .iter()
            .map(|location| {
                let description = self.view.device.parameter_description(&location.id);
                let name = description.as_ref().map_or_else(
                    || location.id.clone(),
                    |description| {
                        if let Some(module) = description.module {
                            let label = self
                                .view
                                .device
                                .get_module_def(&module.module_def_id)
                                .map(|definition| self.build_module_instance_label(module, definition))
                                .unwrap_or_else(|| module.instance_id.clone());
                            format!("[{label}] {}", self.view.device.interpolate_module_text(description.text, module))
                        } else {
                            self.view.device.interpolate_text(description.text)
                        }
                    },
                );
                (location.clone(), name)
            })
            .collect::<Vec<(ParameterLocation, String)>>();
        let image =
            device.project_preview(&id, address, state.as_ref()).map_err(|error| crate::error_message(&error))?;
        let annotations = ParameterAnnotations::new(&parameters, image.regions());
        Ok(ConfigurationPreview { image, annotations })
    }

    /// Build a display label for a module instance.
    /// Tries to find a channel number or similar identifier from the module arguments.
    /// Falls back to the module definition name if no identifier is found.
    pub(in crate::app) fn build_module_instance_label(
        &self,
        expanded: &zweidraehte_ets_files::runtime::model::ExpandedModule,
        module_def: &ModuleDef,
    ) -> String {
        // Try to find a channel/instance number argument (commonly named ChNo, Channel, ChannelNo, etc.)
        let channel_arg = module_def.arguments.as_ref().and_then(|args| {
            args.arguments.iter().find(|a| {
                let name_lower = a.name.to_lowercase();
                name_lower.contains("ch") || name_lower.contains("channel") || name_lower.contains("instance")
            })
        });

        if let Some(arg_def) = channel_arg
            && let Some(zweidraehte_ets_files::runtime::model::ModuleArgValue::Numeric(val)) =
                expanded.args.get(&arg_def.name)
        {
            // Use module name with channel number, e.g., "Ch1" or "DimmerChannel 1"
            return format!("Ch{}", val);
        }

        // Fallback: use interpolated module name if available
        if let Some(name) = &expanded.name {
            // The name might contain templates like "{{ChNo}}" - try to interpolate
            let interpolated = self.view.device.interpolate_module_text(name, expanded);
            if !interpolated.is_empty() && interpolated != *name {
                return interpolated;
            }
        }

        // Final fallback: use module definition name
        module_def.name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_client::commissioning::ImageSpace;

    #[test]
    fn annotations_follow_native_placement_and_clip_across_region_boundaries() {
        let locations = vec![(
            ParameterLocation {
                id: "channel::level".into(),
                code_segment: "parameters".into(),
                offset: 2,
                bit_offset: 6,
                size_bits: 12,
                legacy_patch_always: false,
                seeds_default: true,
                byte_ordered: true,
            },
            "[Kanal 1] Helligkeit".into(),
        )];
        let native = NativeImageRegion {
            source_id: Some("parameters".into()),
            memory_type: None,
            seed: vec![],
            location: ImageLocation::standard_memory(0x1000),
            length: 16,
        };
        let annotations = ParameterAnnotations::new(&locations, &[native]);

        let whole = annotations.for_region(&ImageLocation::standard_memory(0x1000), 16);
        assert_eq!((whole[0].offset, whole[0].bit_offset, whole[0].size_bits), (2, 6, 12));
        assert_eq!(whole[0].name, "[Kanal 1] Helligkeit");
        assert_eq!(whole[0].param_id, "channel::level");
        let left = annotations.for_region(&ImageLocation::standard_memory(0x1000), 3);
        assert_eq!((left[0].offset, left[0].bit_offset, left[0].size_bits), (2, 6, 2));
        let right = annotations.for_region(&ImageLocation::standard_memory(0x1003), 2);
        assert_eq!((right[0].offset, right[0].bit_offset, right[0].size_bits), (0, 0, 10));
        assert!(
            annotations.for_region(&ImageLocation { space: ImageSpace::UserMemory, offset: 0x1000 }, 16).is_empty()
        );
        assert!(annotations.for_region(&ImageLocation::standard_memory(0x1005), 1).is_empty());

        let mut segment = MemorySegment {
            id: "parameters".into(),
            placement: ImageSpace::StandardMemory,
            address: 0x1000,
            size: 16,
            memory_type: None,
            data: vec![0; 16],
            mask: vec![0; 16],
            annotations: whole,
            annotation_index: vec![],
        };
        segment.rebuild_annotation_index();
        assert_eq!(&segment.annotation_index[..6], &[u32::MAX, u32::MAX, 0, 0, 0, u32::MAX]);
    }
}
