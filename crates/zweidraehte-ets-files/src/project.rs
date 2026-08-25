//! ETS project definitions and `.knxproj` generation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::product::ManufacturerContent;
use crate::schema::{
    Area, CatalogItem, CatalogKnx, CatalogSection, GroupAddresses, GroupRanges, HardwareKnx, Installation,
    Installations, Line, Locations, Project, ProjectDeviceInstance, ProjectInformation, ProjectKnx, Topology,
    UnassignedDevices,
};
use crate::signing::{KnxSchemaVersion, MasterDataSource};
use crate::xml;

const DEFAULT_RF_DOMAIN_ADDRESS: u64 = 0x02DA_0000_0001;

/// An ETS project independent of any product generator.
#[derive(Debug, Clone)]
pub struct ProjectDefinition {
    pub id: String,
    pub name: String,
    pub guid: String,
    pub group_address_style: String,
    pub areas: Vec<ProjectArea>,
    pub devices: Vec<ProjectDevice>,
}

impl ProjectDefinition {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: "P-0001".to_owned(),
            name: name.into(),
            guid: uuid::Uuid::new_v4().to_string(),
            group_address_style: "ThreeLevel".to_owned(),
            areas: vec![ProjectArea {
                address: 0,
                name: "Backbone area".to_owned(),
                lines: vec![ProjectLine {
                    address: 0,
                    name: "Backbone line".to_owned(),
                    medium_type_ref_id: None,
                    domain_address: None,
                }],
            }],
            devices: Vec::new(),
        }
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    pub fn with_guid(mut self, guid: impl Into<String>) -> Self {
        self.guid = guid.into();
        self
    }

    pub fn with_areas(mut self, areas: Vec<ProjectArea>) -> Self {
        self.areas = areas;
        self
    }

    pub fn with_devices(mut self, devices: Vec<ProjectDevice>) -> Self {
        self.devices = devices;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectArea {
    pub address: u8,
    pub name: String,
    pub lines: Vec<ProjectLine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectLine {
    pub address: u8,
    pub name: String,
    /// `None` derives the medium from devices assigned to this line, or from
    /// all unassigned devices for the default backbone.
    pub medium_type_ref_id: Option<String>,
    pub domain_address: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDevice {
    pub name: String,
    pub catalogue_product_id: String,
    pub application_program_id: String,
    pub placement: ProjectPlacement,
}

impl ProjectDevice {
    pub fn unassigned(
        name: impl Into<String>,
        catalogue_product_id: impl Into<String>,
        application_program_id: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            catalogue_product_id: catalogue_product_id.into(),
            application_program_id: application_program_id.into(),
            placement: ProjectPlacement::Unassigned,
        }
    }
}

/// Where a project device is represented in topology.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProjectPlacement {
    #[default]
    Unassigned,
    Line {
        area: u8,
        line: u8,
        address: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDocuments {
    pub project_id: String,
    pub project_xml: String,
    pub topology_xml: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    #[error("project contains no topology area")]
    MissingArea,
    #[error("project area {0} contains no line")]
    MissingLine(u8),
    #[error("duplicate topology area address {0}")]
    DuplicateArea(u8),
    #[error("duplicate line address {line} in area {area}")]
    DuplicateLine { area: u8, line: u8 },
    #[error("device {device:?} refers to missing area {area}, line {line}")]
    UnknownLine { device: String, area: u8, line: u8 },
    #[error("duplicate manufacturer directory {0}")]
    DuplicateManufacturer(String),
    #[error("cannot parse hardware XML for {manufacturer}")]
    HardwareXml {
        manufacturer: String,
        #[source]
        source: quick_xml::DeError,
    },
    #[error("cannot parse catalogue XML for {manufacturer}")]
    CatalogueXml {
        manufacturer: String,
        #[source]
        source: quick_xml::DeError,
    },
    #[error("manufacturer {manufacturer} does not contain application program {application}")]
    MissingApplication { manufacturer: String, application: String },
    #[error("no supplied manufacturer contains catalogue product {product}")]
    MissingProduct { product: String },
    #[error("catalogue product {product} is not linked to application program {application}")]
    ProductApplicationMismatch { product: String, application: String },
    #[error("catalogue product {product} and application {application} resolve in more than one manufacturer")]
    AmbiguousProduct { product: String, application: String },
    #[error("line {area}.{line} uses {line_medium}, but device {device:?} requires {device_medium}")]
    MediumMismatch { device: String, area: u8, line: u8, line_medium: String, device_medium: String },
    #[error("cannot serialize project XML")]
    Xml(#[from] xml::XmlError),
    #[cfg(feature = "signing")]
    #[error("cannot package project")]
    Signing(#[from] crate::signing::SigningError),
    #[error("master_data() must be set before building a .knxproj")]
    MissingMasterData,
    #[error("a converter key must be supplied before building a signed .knxproj")]
    MissingConverterKey,
    #[error("cannot write project archive to {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
struct ResolvedDevice {
    hardware2program_id: String,
    medium: String,
}

/// Builds project documents from one or more generated or imported
/// manufacturer bundles.
pub struct KnxprojBuilder {
    definition: ProjectDefinition,
    manufacturers: Vec<ManufacturerContent>,
    schema_version: KnxSchemaVersion,
    master_data: Option<MasterDataSource>,
    #[cfg(feature = "signing")]
    converter_key: Option<crate::signing::ConverterKey>,
}

impl KnxprojBuilder {
    pub fn new(definition: ProjectDefinition) -> Self {
        Self {
            definition,
            manufacturers: Vec::new(),
            schema_version: KnxSchemaVersion::default(),
            master_data: None,
            #[cfg(feature = "signing")]
            converter_key: None,
        }
    }

    pub fn add_manufacturer(&mut self, content: ManufacturerContent) -> &mut Self {
        self.manufacturers.push(content);
        self
    }

    pub fn manufacturer(mut self, content: ManufacturerContent) -> Self {
        self.manufacturers.push(content);
        self
    }

    pub fn schema_version(mut self, version: KnxSchemaVersion) -> Self {
        self.schema_version = version;
        self
    }

    pub fn master_data(mut self, source: MasterDataSource) -> Self {
        self.master_data = Some(source);
        self
    }

    /// Supply the converter key explicitly for package signing.
    #[cfg(feature = "signing")]
    pub fn converter_key(mut self, key: crate::signing::ConverterKey) -> Self {
        self.converter_key = Some(key);
        self
    }

    /// Read the caller-selected converter key file for package signing.
    #[cfg(feature = "signing")]
    pub fn converter_key_file(mut self, path: impl AsRef<std::path::Path>) -> Result<Self, ProjectError> {
        self.converter_key = Some(crate::signing::ConverterKey::from_file(path)?);
        Ok(self)
    }

    pub fn generate(&self) -> Result<ProjectDocuments, ProjectError> {
        self.validate_topology()?;
        let resolved = self.resolve_devices()?;
        self.generate_documents(&resolved)
    }

    #[cfg(feature = "signing")]
    pub fn build(&self) -> Result<Vec<u8>, ProjectError> {
        let documents = self.generate()?;
        let master_data = self.master_data.clone().ok_or(ProjectError::MissingMasterData)?;
        let converter_key = self.converter_key.as_ref().ok_or(ProjectError::MissingConverterKey)?;
        let configs = self.manufacturers.iter().map(crate::signing::SigningConfig::from).collect::<Vec<_>>();
        let project = crate::signing::ProjectConfig {
            project_id: documents.project_id,
            project_xml: documents.project_xml,
            topology_xml: documents.topology_xml,
        };
        crate::signing::create_knxproj_multi(&configs, &project, master_data, converter_key).map_err(ProjectError::from)
    }

    #[cfg(feature = "signing")]
    pub fn write(&self, path: impl AsRef<std::path::Path>) -> Result<(), ProjectError> {
        let path = path.as_ref();
        let bytes = self.build()?;
        std::fs::write(path, bytes).map_err(|source| ProjectError::Io { path: path.to_owned(), source })
    }

    fn validate_topology(&self) -> Result<(), ProjectError> {
        if self.definition.areas.is_empty() {
            return Err(ProjectError::MissingArea);
        }
        let mut areas = BTreeSet::new();
        for area in &self.definition.areas {
            if !areas.insert(area.address) {
                return Err(ProjectError::DuplicateArea(area.address));
            }
            if area.lines.is_empty() {
                return Err(ProjectError::MissingLine(area.address));
            }
            let mut lines = BTreeSet::new();
            for line in &area.lines {
                if !lines.insert(line.address) {
                    return Err(ProjectError::DuplicateLine { area: area.address, line: line.address });
                }
            }
        }
        Ok(())
    }

    fn resolve_devices(&self) -> Result<Vec<ResolvedDevice>, ProjectError> {
        let mut directories = BTreeSet::new();
        let mut indexes = Vec::with_capacity(self.manufacturers.len());
        for content in &self.manufacturers {
            let directory = content.directory_name();
            if !directories.insert(directory.clone()) {
                return Err(ProjectError::DuplicateManufacturer(directory));
            }
            indexes.push(ManufacturerIndex::parse(content)?);
        }

        self.definition
            .devices
            .iter()
            .map(|device| {
                let candidates = indexes
                    .iter()
                    .filter_map(|index| {
                        index.resolve(&device.catalogue_product_id, &device.application_program_id).map(
                            |(relation, medium)| ResolvedDevice {
                                hardware2program_id: relation.to_owned(),
                                medium: medium.to_owned(),
                            },
                        )
                    })
                    .collect::<Vec<_>>();
                match candidates.as_slice() {
                    [only] => Ok(only.clone()),
                    [] => {
                        let product_exists =
                            indexes.iter().any(|index| index.products.contains(&device.catalogue_product_id));
                        if product_exists {
                            Err(ProjectError::ProductApplicationMismatch {
                                product: device.catalogue_product_id.clone(),
                                application: device.application_program_id.clone(),
                            })
                        } else {
                            Err(ProjectError::MissingProduct { product: device.catalogue_product_id.clone() })
                        }
                    }
                    _ => Err(ProjectError::AmbiguousProduct {
                        product: device.catalogue_product_id.clone(),
                        application: device.application_program_id.clone(),
                    }),
                }
            })
            .collect()
    }

    fn generate_documents(&self, resolved: &[ResolvedDevice]) -> Result<ProjectDocuments, ProjectError> {
        let project_id = &self.definition.id;
        let mut next_puid = 1u32;
        let mut areas = Vec::with_capacity(self.definition.areas.len());

        for area in &self.definition.areas {
            let area_puid = next_puid;
            next_puid += 1;
            let mut lines = Vec::with_capacity(area.lines.len());
            for line in &area.lines {
                let line_puid = next_puid;
                next_puid += 1;
                lines.push(Line {
                    id: format!("{project_id}-0_L-{area}-{line}", area = area.address, line = line.address),
                    name: line.name.clone(),
                    address: line.address.to_string(),
                    medium_type_ref_id: String::new(),
                    domain_address: line.domain_address,
                    puid: line_puid,
                    device_instances: Vec::new(),
                });
            }
            areas.push(Area {
                id: format!("{project_id}-0_A-{}", area.address),
                name: area.name.clone(),
                address: area.address.to_string(),
                puid: area_puid,
                lines,
            });
        }

        let mut unassigned = Vec::new();
        for (index, (device, resolution)) in self.definition.devices.iter().zip(resolved).enumerate() {
            let instance = ProjectDeviceInstance {
                id: format!("{project_id}-0_DI-{}", index + 1),
                product_ref_id: device.catalogue_product_id.clone(),
                hardware2program_ref_id: resolution.hardware2program_id.clone(),
                puid: next_puid,
                name: (!device.name.is_empty()).then(|| device.name.clone()),
                address: match device.placement {
                    ProjectPlacement::Unassigned => None,
                    ProjectPlacement::Line { address, .. } => Some(address.to_string()),
                },
            };
            next_puid += 1;

            match device.placement {
                ProjectPlacement::Unassigned => unassigned.push(instance),
                ProjectPlacement::Line { area, line, .. } => {
                    let target = areas
                        .iter_mut()
                        .find(|candidate| candidate.address == area.to_string())
                        .and_then(|candidate| {
                            candidate.lines.iter_mut().find(|candidate| candidate.address == line.to_string())
                        })
                        .ok_or_else(|| ProjectError::UnknownLine { device: device.name.clone(), area, line })?;
                    target.device_instances.push(instance);
                }
            }
        }

        for (area_index, area) in self.definition.areas.iter().enumerate() {
            for (line_index, line) in area.lines.iter().enumerate() {
                let assigned_media = self
                    .definition
                    .devices
                    .iter()
                    .zip(resolved)
                    .filter_map(|(device, resolution)| match device.placement {
                        ProjectPlacement::Line { area: a, line: l, .. } if a == area.address && l == line.address => {
                            Some((device, resolution.medium.as_str()))
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let fallback_media = if area_index == 0 && line_index == 0 {
                    self.definition
                        .devices
                        .iter()
                        .zip(resolved)
                        .filter_map(|(device, resolution)| {
                            matches!(device.placement, ProjectPlacement::Unassigned)
                                .then_some(resolution.medium.as_str())
                        })
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                let derived = homogeneous_medium(
                    assigned_media.iter().map(|(_, medium)| *medium).chain(fallback_media.iter().copied()),
                );
                let medium = line.medium_type_ref_id.as_deref().unwrap_or(derived);
                for (device, device_medium) in &assigned_media {
                    if *device_medium != medium {
                        return Err(ProjectError::MediumMismatch {
                            device: device.name.clone(),
                            area: area.address,
                            line: line.address,
                            line_medium: medium.to_owned(),
                            device_medium: (*device_medium).to_owned(),
                        });
                    }
                }
                let schema_line = &mut areas[area_index].lines[line_index];
                schema_line.medium_type_ref_id = medium.to_owned();
                if medium == "MT-2" && schema_line.domain_address.is_none() {
                    schema_line.domain_address = Some(DEFAULT_RF_DOMAIN_ADDRESS);
                }
            }
        }

        let root = |project: Project| ProjectKnx {
            xmlns: self.schema_version.namespace_url(),
            tool_version: self.schema_version.tool_version().to_owned(),
            project,
            ..ProjectKnx::default()
        };
        let last_used_puid = next_puid.saturating_sub(1);
        let project_document = root(Project {
            id: project_id.clone(),
            project_information: Some(ProjectInformation {
                name: self.definition.name.clone(),
                group_address_style: self.definition.group_address_style.clone(),
                guid: self.definition.guid.clone(),
                last_used_puid,
            }),
            installations: None,
        });
        let topology_document = root(Project {
            id: project_id.clone(),
            project_information: None,
            installations: Some(Installations {
                installations: vec![Installation {
                    name: String::new(),
                    installation_id: "0".to_owned(),
                    topology: Topology {
                        areas,
                        unassigned_devices: UnassignedDevices { device_instances: unassigned },
                    },
                    locations: Locations,
                    group_addresses: GroupAddresses { group_ranges: GroupRanges },
                }],
            }),
        });

        Ok(ProjectDocuments {
            project_id: project_id.clone(),
            project_xml: xml::to_string(&project_document)?,
            topology_xml: xml::to_string(&topology_document)?,
        })
    }
}

struct ManufacturerIndex {
    products: BTreeSet<String>,
    /// `(product, application) -> (Hardware2Program Id, medium)`.
    links: BTreeMap<(String, String), (String, String)>,
}

impl ManufacturerIndex {
    fn parse(content: &ManufacturerContent) -> Result<Self, ProjectError> {
        let manufacturer = content.directory_name();
        let hardware: HardwareKnx = quick_xml::de::from_str(&content.hardware)
            .map_err(|source| ProjectError::HardwareXml { manufacturer: manufacturer.clone(), source })?;
        let catalogue: CatalogKnx = quick_xml::de::from_str(&content.catalogue)
            .map_err(|source| ProjectError::CatalogueXml { manufacturer: manufacturer.clone(), source })?;
        let applications = content.application_programs.iter().map(|(id, _)| id.as_str()).collect::<BTreeSet<_>>();

        let mut products = BTreeSet::new();
        let mut relations = BTreeMap::new();
        for hardware in &hardware.manufacturer_data.manufacturer.hardware.hardware {
            for product in &hardware.products.products {
                products.insert(product.id.clone());
            }
            for relation in &hardware.hardware2programs.hardware2programs {
                let application = &relation.application_program_ref.ref_id;
                if !applications.contains(application.as_str()) {
                    return Err(ProjectError::MissingApplication {
                        manufacturer: manufacturer.clone(),
                        application: application.clone(),
                    });
                }
                relations.insert(relation.id.clone(), (application.clone(), relation.medium_types.clone()));
            }
        }

        let mut items = Vec::new();
        collect_catalogue_items(&catalogue.manufacturer_data.manufacturer.catalog.catalog_sections, &mut items);
        let mut links = BTreeMap::new();
        for item in items {
            let Some((application, medium)) = relations.get(&item.hardware2program_ref_id) else {
                continue;
            };
            if products.contains(&item.product_ref_id) {
                links.insert(
                    (item.product_ref_id.clone(), application.clone()),
                    (item.hardware2program_ref_id.clone(), primary_medium(medium).to_owned()),
                );
            }
        }

        Ok(Self { products, links })
    }

    fn resolve(&self, product: &str, application: &str) -> Option<(&str, &str)> {
        self.links
            .get(&(product.to_owned(), application.to_owned()))
            .map(|(relation, medium)| (relation.as_str(), medium.as_str()))
    }
}

fn collect_catalogue_items<'a>(sections: &'a [CatalogSection], output: &mut Vec<&'a CatalogItem>) {
    for section in sections {
        output.extend(&section.catalog_items);
        collect_catalogue_items(&section.subsections, output);
    }
}

fn primary_medium(mediums: &str) -> &str {
    mediums.split_whitespace().next().unwrap_or("MT-0")
}

fn homogeneous_medium<'a>(mut media: impl Iterator<Item = &'a str>) -> &'a str {
    match media.next() {
        Some(first) if media.all(|other| other == first) => first,
        _ => "MT-5",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = r#"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="test" ToolVersion="1" xmlns="http://knx.org/xml/project/23""#;

    fn content(manufacturer: &str, product: &str, application: &str, medium: &str) -> ManufacturerContent {
        let hardware = format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-{manufacturer}"><Hardware><Hardware Id="M-{manufacturer}_H-1" Name="Hardware" SerialNumber="1" VersionNumber="1" HasIndividualAddress="true" HasApplicationProgram="true"><Products><Product Id="{product}" Text="Product" OrderNumber="P-1" IsRailMounted="false" DefaultLanguage="en-US"/></Products><Hardware2Programs><Hardware2Program Id="M-{manufacturer}_H-1_HP-1" MediumTypes="{medium}"><ApplicationProgramRef RefId="{application}"/></Hardware2Program></Hardware2Programs></Hardware></Hardware></Manufacturer></ManufacturerData></KNX>"#
        );
        let catalogue = format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-{manufacturer}"><Catalog><CatalogSection Id="M-{manufacturer}_CS-1" Name="Products" Number="1" DefaultLanguage="en-US"><CatalogItem Id="M-{manufacturer}_CI-1" Name="Product" Number="1" ProductRefId="{product}" Hardware2ProgramRefId="M-{manufacturer}_H-1_HP-1" DefaultLanguage="en-US"/></CatalogSection></Catalog></Manufacturer></ManufacturerData></KNX>"#
        );
        ManufacturerContent::new(manufacturer, vec![(application.to_owned(), "<KNX/>".to_owned())], hardware, catalogue)
    }

    #[test]
    fn validates_ids_across_multiple_manufacturers_and_keeps_vector_topology() {
        let mut definition = ProjectDefinition::new("Mixed project").with_guid("stable-guid");
        definition.areas.push(ProjectArea {
            address: 1,
            name: "Area 1".to_owned(),
            lines: vec![ProjectLine {
                address: 1,
                name: "TP line".to_owned(),
                medium_type_ref_id: Some("MT-0".to_owned()),
                domain_address: None,
            }],
        });
        definition.areas.push(ProjectArea {
            address: 2,
            name: "Area 2".to_owned(),
            lines: vec![ProjectLine {
                address: 1,
                name: "IP line".to_owned(),
                medium_type_ref_id: Some("MT-5".to_owned()),
                domain_address: None,
            }],
        });
        definition.devices = vec![
            ProjectDevice::unassigned("RF sensor", "M-0001_H-1_P-1", "M-0001_A-1"),
            ProjectDevice {
                name: "TP actuator".to_owned(),
                catalogue_product_id: "M-0002_H-1_P-1".to_owned(),
                application_program_id: "M-0002_A-1".to_owned(),
                placement: ProjectPlacement::Line { area: 1, line: 1, address: 10 },
            },
            ProjectDevice {
                name: "IP interface".to_owned(),
                catalogue_product_id: "M-0003_H-1_P-1".to_owned(),
                application_program_id: "M-0003_A-1".to_owned(),
                placement: ProjectPlacement::Line { area: 2, line: 1, address: 20 },
            },
        ];
        let documents = KnxprojBuilder::new(definition)
            .manufacturer(content("0001", "M-0001_H-1_P-1", "M-0001_A-1", "MT-2"))
            .manufacturer(content("0002", "M-0002_H-1_P-1", "M-0002_A-1", "MT-0"))
            .manufacturer(content("0003", "M-0003_H-1_P-1", "M-0003_A-1", "MT-5"))
            .generate()
            .expect("project resolves");

        let topology: ProjectKnx = xml::from_str(&documents.topology_xml).expect("topology parses");
        let topology = &topology.project.installations.expect("installation exists").installations[0].topology;
        assert_eq!(topology.areas.len(), 3);
        assert_eq!(topology.areas[1].lines[0].device_instances[0].address.as_deref(), Some("10"));
        assert_eq!(topology.areas[2].lines[0].device_instances[0].address.as_deref(), Some("20"));
        assert_eq!(topology.unassigned_devices.device_instances.len(), 1);
        assert_eq!(topology.areas[0].lines[0].medium_type_ref_id, "MT-2");
    }

    #[test]
    fn rejects_a_catalogue_application_mismatch() {
        let definition = ProjectDefinition::new("Invalid").with_devices(vec![ProjectDevice::unassigned(
            "Device",
            "M-0001_H-1_P-1",
            "M-0001_A-2",
        )]);
        let error = KnxprojBuilder::new(definition)
            .manufacturer(content("0001", "M-0001_H-1_P-1", "M-0001_A-1", "MT-0"))
            .generate()
            .expect_err("mismatch is rejected");
        assert!(matches!(error, ProjectError::ProductApplicationMismatch { .. }));
    }

    #[test]
    fn rejects_a_missing_catalogue_product() {
        let definition = ProjectDefinition::new("Invalid").with_devices(vec![ProjectDevice::unassigned(
            "Device",
            "M-0001_H-1_P-missing",
            "M-0001_A-1",
        )]);
        let error = KnxprojBuilder::new(definition)
            .manufacturer(content("0001", "M-0001_H-1_P-1", "M-0001_A-1", "MT-0"))
            .generate()
            .expect_err("missing product is rejected");
        assert!(matches!(error, ProjectError::MissingProduct { .. }));
    }
}
