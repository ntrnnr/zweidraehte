//! Read-only configuration images built by the download compiler.
//!
//! Frontends use this instead of maintaining a second parameter/table
//! assembler. With mask master data the preview is the compiler's exact
//! [`DeviceImage`](super::DeviceImage). Without it, product-owned defaults
//! and exact parameter overlays remain useful, while mask-derived tables are
//! explicitly unavailable.

use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::dpt::InterfaceObjectType;

use super::configuration::DeviceConfiguration;
use super::mask::{MachineRole, MaskData};
use super::model::{DownloadModel, Placement};
use super::project::{ProjectConfig, SecurityConfig, co_rows, compile, dynamic_table_layout, patch_parameters};
use crate::error::{Error, Result};
use zweidraehte_ets_files::product::ProductData;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewCompleteness {
    Complete,
    MaskDerivedTablesUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewPlacement {
    Absolute { address: u16 },
    Relative { object_index: u8 },
    InterfaceProperty { object_type: InterfaceObjectType, property_id: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewTableKind {
    GroupAddress,
    Association,
    GroupObject,
    SecurityGroupKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewTableSpan {
    pub kind: PreviewTableKind,
    pub placement: PreviewPlacement,
    pub offset: u32,
    pub len: usize,
    /// Secret-bearing content is described by length, never copied here.
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewSegment {
    pub id: String,
    pub placement: PreviewPlacement,
    pub size: u32,
    pub memory_type: Option<String>,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationPreview {
    pub completeness: PreviewCompleteness,
    pub segments: Vec<PreviewSegment>,
    pub tables: Vec<PreviewTableSpan>,
}

pub struct ConfigurationPreviewBuilder<'a> {
    product: &'a ProductData,
    configuration: &'a DeviceConfiguration,
    security: Option<SecurityConfig>,
    mask: Option<MaskData<'a>>,
}

impl<'a> ConfigurationPreviewBuilder<'a> {
    pub fn new(product: &'a ProductData, configuration: &'a DeviceConfiguration) -> Self {
        Self { product, configuration, security: None, mask: None }
    }

    pub fn with_security(mut self, security: SecurityConfig) -> Self {
        self.security = Some(security);
        self
    }

    pub fn with_mask(mut self, mask: MaskData<'a>) -> Self {
        self.mask = Some(mask);
        self
    }

    pub fn build(self) -> Result<ConfigurationPreview> {
        let lowered = self.configuration.lower(self.security.clone())?;
        match self.mask {
            Some(mask) => build_complete(&mask, self.product, &lowered, self.security.as_ref()),
            None => build_product_only(self.product, &lowered.project, self.security.as_ref()),
        }
    }
}

fn build_complete(
    mask: &MaskData<'_>,
    product: &ProductData,
    configuration: &super::configuration::LoweredDeviceConfiguration,
    security: Option<&SecurityConfig>,
) -> Result<ConfigurationPreview> {
    // The compiler call keeps fixups, sparse ownership, resource patches,
    // dynamic placement and table codings byte-identical to a download.
    let compiled = compile(mask, product, configuration)?;
    let model = DownloadModel::for_management_model(mask.management_model())
        .ok_or(Error::DownloadConfig("downloads for this management model are not implemented"))?;
    let lsm = mask.lsm_model();

    let mut segments = Vec::new();
    for (address, bytes) in compiled.image.regions() {
        let source = product.segments().iter().find(|segment| {
            segment.address.is_some_and(|base| {
                let end = u32::from(base) + segment.size;
                u32::from(address) >= u32::from(base) && u32::from(address) < end
            })
        });
        segments.push(PreviewSegment {
            id: source.map_or_else(|| format!("absolute-{address:04X}"), |segment| segment.id.clone()),
            placement: PreviewPlacement::Absolute { address },
            size: bytes.len() as u32,
            memory_type: source.and_then(|segment| segment.memory_type.clone()),
            bytes: bytes.to_vec(),
        });
    }
    for (object_index, bytes) in compiled.image.relative_objects() {
        let source = product.segments().iter().find(|segment| segment.load_state_machine == Some(object_index));
        segments.push(PreviewSegment {
            id: source.map_or_else(|| relative_role_name(&lsm, object_index), |segment| segment.id.clone()),
            placement: PreviewPlacement::Relative { object_index },
            size: bytes.len() as u32,
            memory_type: source.and_then(|segment| segment.memory_type.clone()),
            bytes: bytes.to_vec(),
        });
    }
    segments.sort_by_key(|segment| match segment.placement {
        PreviewPlacement::Absolute { address } => (0, u32::from(address)),
        PreviewPlacement::Relative { object_index } => (1, u32::from(object_index)),
        PreviewPlacement::InterfaceProperty { object_type, property_id } => {
            (2, (u32::from(u16::from(object_type)) << 16) | u32::from(property_id))
        }
    });

    Ok(ConfigurationPreview {
        completeness: PreviewCompleteness::Complete,
        segments,
        tables: table_spans(mask, model, product, configuration, security)?,
    })
}

fn build_product_only(
    product: &ProductData,
    project: &ProjectConfig,
    security: Option<&SecurityConfig>,
) -> Result<ConfigurationPreview> {
    let mut segments = Vec::new();
    for segment in product.segments() {
        // A configured value may be the first meaningful content past a
        // short (or absent) product `Data` block. The compiler grows absolute
        // buffers to that value and capacity-sizes relative buffers; using the
        // declared capacity here accommodates both without inventing bytes
        // outside the product segment.
        let mut bytes = vec![0; segment.size as usize];
        let defaults = segment.data.len().min(bytes.len());
        bytes[..defaults].copy_from_slice(&segment.data[..defaults]);
        patch_parameters(&mut bytes, segment.size as usize, &segment.id, product, project)?;
        let placement = match (segment.address, segment.load_state_machine) {
            (Some(address), _) => PreviewPlacement::Absolute { address },
            (_, Some(object_index)) => PreviewPlacement::Relative { object_index },
            _ => continue,
        };
        segments.push(PreviewSegment {
            id: segment.id.clone(),
            placement,
            size: segment.size,
            memory_type: segment.memory_type.clone(),
            bytes,
        });
    }
    Ok(ConfigurationPreview {
        completeness: PreviewCompleteness::MaskDerivedTablesUnavailable,
        segments,
        tables: security_spans(security),
    })
}

fn relative_role_name(model: &super::mask::LsmModel, object_index: u8) -> String {
    for (role, name) in [
        (MachineRole::GroupAddressTable, "Group Address Table"),
        (MachineRole::GroupAssociationTable, "Association Table"),
        (MachineRole::GroupObjectTable, "Group Object Table"),
    ] {
        if model.object_of(role) == Some(object_index) {
            return name.to_string();
        }
    }
    format!("Interface Object {object_index}")
}

fn table_spans(
    mask: &MaskData<'_>,
    model: &DownloadModel,
    product: &ProductData,
    configuration: &super::configuration::LoweredDeviceConfiguration,
    security: Option<&SecurityConfig>,
) -> Result<Vec<PreviewTableSpan>> {
    let project = &configuration.project;
    let mut groups: Vec<GroupAddress> = project.links.iter().map(|link| link.group_address).collect();
    groups.sort_unstable();
    groups.dedup();
    let associations: Vec<(u16, u16)> = project
        .links
        .iter()
        .map(|link| {
            let tsap = groups.binary_search(&link.group_address).expect("links supplied the group roster") + 1;
            (tsap as u16, u16::from(link.com_object))
        })
        .collect();
    let layout = &model.layout;
    let blobs = [
        (layout.address_table)(project.individual_address, &groups)?,
        (layout.association_table)(&associations, product.com_object_numbers())?,
        (layout.group_object_table)(&co_rows(product, &configuration.com_objects, layout.first_asap)?)?,
    ];
    let kinds = [PreviewTableKind::GroupAddress, PreviewTableKind::Association, PreviewTableKind::GroupObject];
    let roles = [MachineRole::GroupAddressTable, MachineRole::GroupAssociationTable, MachineRole::GroupObjectTable];
    let segment_ids =
        [product.address_table_segment(), product.association_table_segment(), product.com_object_table_segment()];
    let offsets =
        [product.address_table_offset(), product.association_table_offset(), product.com_object_table_offset()];
    let lsm = mask.lsm_model();
    let dynamic = if product.dynamic_table_management() && matches!(model.management_model, "Bcu1" | "Bcu2") {
        let alignment = if model.management_model == "Bcu2" { 2 } else { 1 };
        Some(dynamic_table_layout(product, project, alignment)?)
    } else {
        None
    };

    let mut spans = Vec::new();
    for index in 0..3 {
        let placement = match layout.placement {
            Placement::RelativeObjects => PreviewPlacement::Relative {
                object_index: lsm
                    .object_of(roles[index])
                    .ok_or(Error::DownloadConfig("the mask omits a generated table machine"))?,
            },
            Placement::AbsoluteSegments => {
                if let Some(dynamic) = dynamic {
                    let address = [dynamic.address_start, dynamic.association_start, dynamic.object_start][index];
                    spans.push(PreviewTableSpan {
                        kind: kinds[index],
                        placement: PreviewPlacement::Absolute { address },
                        offset: 0,
                        len: blobs[index].len(),
                        redacted: false,
                    });
                    continue;
                }
                let segment = segment_ids[index]
                    .and_then(|id| product.segments().iter().find(|segment| segment.id == id))
                    .ok_or(Error::DownloadConfig("the product omits a generated table segment"))?;
                let offset = u16::try_from(offsets[index])
                    .map_err(|_| Error::DownloadConfig("a generated table offset exceeds 16 bits"))?;
                PreviewPlacement::Absolute {
                    address: segment
                        .address
                        .and_then(|base| base.checked_add(offset))
                        .ok_or(Error::DownloadConfig("a generated table has no absolute placement"))?,
                }
            }
        };
        spans.push(PreviewTableSpan {
            kind: kinds[index],
            placement,
            offset: 0,
            len: blobs[index].len(),
            redacted: false,
        });
    }
    spans.extend(security_spans(security));
    Ok(spans)
}

fn security_spans(security: Option<&SecurityConfig>) -> Vec<PreviewTableSpan> {
    let Some(security) = security else { return Vec::new() };
    let entries = security.group_keys().len();
    if entries == 0 {
        return Vec::new();
    }
    vec![PreviewTableSpan {
        kind: PreviewTableKind::SecurityGroupKey,
        placement: PreviewPlacement::InterfaceProperty {
            object_type: InterfaceObjectType::Security,
            property_id: zweidraehte_proto::pid::security::GROUP_KEY_TABLE,
        },
        offset: 0,
        len: entries * 18,
        redacted: true,
    }]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
    use zweidraehte_proto::device::MaskVersion;

    use super::*;
    use crate::download::configuration::{DeviceIdentity, MembershipRole, ObjectMembership};
    use crate::download::mask::MaskDb;
    use crate::download::project::ParameterValue;
    use zweidraehte_ets_files::product::fixtures::{BCU1_MTXML, SYSTEM7_MTXML};

    fn configuration(product: &ProductData, memberships: Vec<ObjectMembership>) -> DeviceConfiguration {
        DeviceConfiguration {
            identity: DeviceIdentity { desired_address: IndividualAddress::new(1, 1, 42), serial_number: None },
            data_secure_enabled: false,
            parameters: Vec::new(),
            object_memberships: memberships,
            objects: product.com_objects().to_vec(),
            net_security: BTreeMap::new(),
            max_apdu: None,
        }
    }

    fn assert_matches_compiler(mask: &MaskData<'_>, product: &ProductData, configuration: &DeviceConfiguration) {
        let lowered = configuration.lower(None).expect("configuration lowers");
        let compiled = compile(mask, product, &lowered).expect("configuration compiles");
        let preview =
            ConfigurationPreviewBuilder::new(product, configuration).with_mask(*mask).build().expect("preview builds");

        let expected_absolute =
            compiled.image.regions().map(|(address, bytes)| (address, bytes.to_vec())).collect::<BTreeMap<_, _>>();
        let actual_absolute = preview
            .segments
            .iter()
            .filter_map(|segment| match segment.placement {
                PreviewPlacement::Absolute { address } => Some((address, segment.bytes.clone())),
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(actual_absolute, expected_absolute);

        let expected_relative = compiled
            .image
            .relative_objects()
            .map(|(object, bytes)| (object, bytes.to_vec()))
            .collect::<BTreeMap<_, _>>();
        let actual_relative = preview
            .segments
            .iter()
            .filter_map(|segment| match segment.placement {
                PreviewPlacement::Relative { object_index } => Some((object_index, segment.bytes.clone())),
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(actual_relative, expected_relative);
        assert_eq!(preview.completeness, PreviewCompleteness::Complete);
    }

    #[test]
    fn system7_preview_is_the_compiled_image() {
        let product = ProductData::from_mtxml_str(SYSTEM7_MTXML).expect("fixture parses");
        let mut configuration = configuration(&product, vec![ObjectMembership {
            group_address: GroupAddress::from_three_level(1, 0, 1),
            com_object: 1,
            role: MembershipRole::Primary,
        }]);
        configuration.parameters.push(ParameterValue { id: "M-00FA_A-0306-02-0000_P-1".into(), value: vec![0xEE] });
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0705).expect("mask fixture parses");
        let mask = db.mask(MaskVersion::System7Tp1).expect("System 7 mask exists");
        assert_matches_compiler(&mask, &product, &configuration);
    }

    #[test]
    fn system_b_preview_is_the_compiled_relative_image() {
        let product = ProductData::from_mtxml_str(crate::download::interpreter::system_b_tests::PRODUCT_XML)
            .expect("product fixture parses");
        let configuration = configuration(&product, vec![ObjectMembership {
            group_address: GroupAddress::from_three_level(1, 0, 1),
            com_object: 1,
            role: MembershipRole::Primary,
        }]);
        let db =
            MaskDb::from_xml_str(crate::download::interpreter::system_b_tests::MASK_XML).expect("mask fixture parses");
        let mask = db.mask(MaskVersion::SystemBTp1).expect("System B mask exists");
        assert_matches_compiler(&mask, &product, &configuration);
    }

    #[test]
    fn indexed_association_preview_preserves_the_primary_membership() {
        let product = ProductData::from_mtxml_str(BCU1_MTXML).expect("fixture parses");
        let primary = GroupAddress::from_three_level(0, 0, 2);
        let additional = GroupAddress::from_three_level(0, 0, 1);
        let configuration = configuration(&product, vec![
            ObjectMembership { group_address: additional, com_object: 0, role: MembershipRole::Additional },
            ObjectMembership { group_address: primary, com_object: 0, role: MembershipRole::Primary },
        ]);
        let db = MaskDb::from_xml_str(crate::download::mask::fixtures::MV_0012).expect("mask fixture parses");
        let mask = db.mask(MaskVersion::Bcu1Tp1).expect("BCU1 mask exists");
        let preview =
            ConfigurationPreviewBuilder::new(&product, &configuration).with_mask(mask).build().expect("preview builds");
        let segment = preview
            .segments
            .iter()
            .find(|segment| matches!(segment.placement, PreviewPlacement::Absolute { address: 0x0100 }))
            .expect("EEPROM segment is present");
        assert_eq!(&segment.bytes[60..67], &[3, 2, 0, 0xFE, 1, 1, 0]);
        assert_matches_compiler(&mask, &product, &configuration);
    }

    #[test]
    fn product_only_preview_marks_tables_unavailable_and_redacts_keys() {
        let product =
            ProductData::from_mtxml_str(SYSTEM7_MTXML).expect("fixture parses").with_fixture_data_secure(true);
        let mut configuration = configuration(&product, Vec::new());
        configuration.data_secure_enabled = true;
        let security = SecurityConfig::new(
            vec![(GroupAddress::from_three_level(1, 0, 1), *b"group-key-canary")],
            Vec::new(),
            Vec::new(),
        );
        let preview = ConfigurationPreviewBuilder::new(&product, &configuration)
            .with_security(security)
            .build()
            .expect("product-only preview builds");
        assert_eq!(preview.completeness, PreviewCompleteness::MaskDerivedTablesUnavailable);
        let key_span = preview
            .tables
            .iter()
            .find(|span| span.kind == PreviewTableKind::SecurityGroupKey)
            .expect("security span is described");
        assert!(key_span.redacted);
        assert!(!format!("{preview:?}").contains("group-key-canary"));
    }
}
