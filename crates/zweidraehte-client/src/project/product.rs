//! Product loading and evaluation of authored project devices.

use super::product_configuration;
use crate::configuration::ErrorDetail;
use crate::configuration::{
    GroupFilterConfiguration, InstallationConfiguration, MaterializedDevice, MembershipRole, NetSecurityPolicy,
    ObjectMembership, SecurityIntent, ToolManagedIpConfiguration, TopologyConfiguration, Unkeyed,
};
use crate::project::error::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use zweidraehte_ets_files::archive::{PackageCatalogSelector, PackageDigest, PackageStore};
use zweidraehte_ets_files::product::IpConfigurationMode;
use zweidraehte_ets_files::product::{ProductData, SelectedProduct};
use zweidraehte_ets_files::runtime::Device;
use zweidraehte_ets_files::runtime::configuration::{ProductDptReference, ProductDptReferences, apply_configuration};
use zweidraehte_ets_files::schema::{ApplicationProgram, Knx};
use zweidraehte_project::{
    AuthoredProject, CouplerRoutingPolicy, MembershipRole as ProjectMembershipRole,
    NetSecurityPolicy as ProjectSecurityPolicy, ProductReference, ProjectDevice, ProjectDeviceId, ProjectStore,
};
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::com_object::ComObjectType;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EvaluatedProjectDevice {
    pub id: ProjectDeviceId,
    pub resolved: MaterializedDevice<Unkeyed>,
    /// Protocol address to logical net identity, used to select group keys.
    pub net_ids: BTreeMap<GroupAddress, String>,
    pub warnings: Vec<String>,
}

/// One checked product selection, shared by all devices using its catalogue leaf.
/// Runtime edits belong to each device; cloning this handle never copies the
/// immutable document or its compilation metadata.
///
/// The application cannot be replaced independently of the selected product:
/// ```compile_fail,E0594
/// use zweidraehte_client::project::ProjectProduct;
/// fn replace_application(product: &mut ProjectProduct) {
///     product.program().id = "another-application".into();
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ProjectProduct {
    selected: Arc<SelectedProduct>,
}

impl ProjectProduct {
    /// Load the exact catalogue leaf pinned by one project device.
    ///
    /// The content digest selects immutable package bytes and `CatalogItem`
    /// selects the authoritative Product/Hardware2Program/AP chain within
    /// those bytes. No schema, Product or application selector is inferred
    /// from project-wide state.
    pub fn load(packages: &PackageStore, selector: &PackageCatalogSelector) -> Result<Self> {
        Ok(Self::new(packages.open(selector.package)?.load_product(selector)?))
    }

    /// Retain a selection validated by the ETS product boundary, including
    /// generated or loose XML assembled with `SelectedProduct::from_document`.
    pub fn new(selected: SelectedProduct) -> Self {
        Self { selected: Arc::new(selected) }
    }

    pub fn program(&self) -> &ApplicationProgram {
        self.selected.program()
    }

    pub fn product(&self) -> &ProductData {
        self.selected.product()
    }

    pub fn document(&self) -> &Knx {
        self.selected.document()
    }
}

/// Load only the product definitions needed by one already-resolved project
/// operation.
///
/// Equal package/catalogue selectors are parsed once even when several
/// project devices instantiate the same product.
impl ProjectProduct {
    pub fn load_for<'a>(
        store: &ProjectStore,
        ids: impl IntoIterator<Item = &'a ProjectDeviceId>,
    ) -> Result<BTreeMap<ProjectDeviceId, ProjectProduct>> {
        Self::load_for_with_progress(store, ids, |_, _, _| {})
    }

    /// Observe each device selection, including reuse of a parsed product.
    pub fn load_for_with_progress<'a>(
        store: &ProjectStore,
        ids: impl IntoIterator<Item = &'a ProjectDeviceId>,
        progress: impl FnMut(&ProjectDeviceId, usize, usize),
    ) -> Result<BTreeMap<ProjectDeviceId, ProjectProduct>> {
        ProductCache::default().load(store.authored(), ids, progress)
    }
}

/// Keep package acquisition identical for operations and repeated draft status
/// refreshes. The cache owns shared immutable selections, never runtime edits.
#[derive(Debug, Clone, Default)]
pub(super) struct ProductCache(BTreeMap<(PathBuf, PackageCatalogSelector), ProjectProduct>);

impl ProductCache {
    pub(super) fn load<'a>(
        &mut self,
        project: &AuthoredProject,
        ids: impl IntoIterator<Item = &'a ProjectDeviceId>,
        mut progress: impl FnMut(&ProjectDeviceId, usize, usize),
    ) -> Result<BTreeMap<ProjectDeviceId, ProjectProduct>> {
        let ids: Vec<_> = ids.into_iter().collect();
        if ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let directory = project.package_store_directory().ok_or_else(|| Error::NoPackageStore)?;
        let package_store = PackageStore::new(&directory);
        let mut products = BTreeMap::new();
        for (index, id) in ids.iter().copied().enumerate() {
            progress(id, index, ids.len());
            let device = project.devices.get(id).ok_or_else(|| Error::UnknownDevice(id.clone()))?;
            let ProductReference::Package { package, catalog_item } = &device.product;
            let selector = PackageCatalogSelector {
                package: PackageDigest::from_bytes(*package.as_bytes()),
                catalog_item_id: catalog_item.clone(),
            };
            let key = (directory.clone(), selector);
            let product = match self.0.get(&key) {
                Some(product) => product.clone(),
                None => {
                    let product = ProjectProduct::load(&package_store, &key.1)?;
                    self.0.insert(key, product.clone());
                    product
                }
            };
            products.insert(id.clone(), product);
        }

        Ok(products)
    }
}

/// Load every active project product.
///
/// Bulk status, validation, synchronization, and affected-device selection
/// need this complete view. Named operations should use
/// [`ProjectProduct::load_for`] with [`super::ProjectPlanner::product_scope`] instead.
impl ProjectProduct {
    pub fn load_active(store: &ProjectStore) -> Result<BTreeMap<ProjectDeviceId, ProjectProduct>> {
        let ids = store
            .authored()
            .devices
            .values()
            .filter(|device| device.active)
            .map(|device| device.id.clone())
            .collect::<Vec<_>>();
        ProjectProduct::load_for(store, &ids)
    }
}

/// Apply project parameter/object overrides over product and visible-ref
/// values, then produce the existing format-neutral download model.
impl ProjectProduct {
    pub fn evaluate(
        &self,
        project: &AuthoredProject,
        project_device: &ProjectDevice,
    ) -> Result<EvaluatedProjectDevice> {
        let product = self.product();
        validate_data_secure_capability(project_device, product)?;
        let topology = topology_configuration(project, project_device, product)?;

        let mut object_memberships = Vec::new();
        let mut net_security = BTreeMap::new();
        let mut net_ids = BTreeMap::new();
        for object in project_device.objects.values() {
            for membership in &object.memberships {
                let net = project.nets.get(&membership.net).ok_or_else(|| Error::UnknownNet(membership.net.clone()))?;
                object_memberships.push(ObjectMembership {
                    group_address: net.address,
                    com_object: object.com_object,
                    role: match membership.role {
                        ProjectMembershipRole::Primary => MembershipRole::Primary,
                        ProjectMembershipRole::Additional => MembershipRole::Additional,
                    },
                });
                let effective_security =
                    project.effective_net_security(&net.id).expect("the membership net was found in this project");
                net_security.insert(net.address, match effective_security {
                    ProjectSecurityPolicy::Plain => NetSecurityPolicy::Plain,
                    ProjectSecurityPolicy::Authentication => NetSecurityPolicy::Authentication,
                    ProjectSecurityPolicy::AuthenticationConfidentiality => {
                        NetSecurityPolicy::AuthenticationConfidentiality
                    }
                    ProjectSecurityPolicy::Automatic => {
                        unreachable!("effective net security never remains automatic")
                    }
                });
                net_ids.insert(net.address, membership.net.0.clone());
            }
        }
        let settings = product_configuration(project_device);

        let mut device = Device::from_product(self.selected.clone(), None, None);
        apply_configuration(&mut device, &settings)?;
        let configuration = InstallationConfiguration {
            individual_address: project_device.address,
            object_memberships,
            topology,
            max_apdu: project_device.max_apdu,
            security: SecurityIntent {
                serial_number: project_device.serial,
                data_secure_enabled: project_device.data_secure.is_enabled(),
                net_security,
            },
        };
        let resolved = MaterializedDevice::from_evaluated(device.evaluate(&settings.objects)?, configuration)?;

        let mut warnings = Vec::new();
        for object in resolved.com_objects() {
            let flags = object.flags;
            // Product objects omitted from the project have no authored links or
            // overrides. Their default T/R/I flags do not create a half-defined
            // association; they simply remain unlinked in the generated tables.
            let Some(authored) = project_device.objects.get(&object.number) else { continue };
            let primary_count = {
                authored
                    .memberships
                    .iter()
                    .filter(|membership| membership.role == ProjectMembershipRole::Primary)
                    .count()
            };
            if (flags.transmission_enable() || flags.read_enable() || flags.read_on_init()) && primary_count != 1 {
                return Err(Error::InvalidProject(ErrorDetail::new(format!(
                    "device `{}`, object {} has effective T/R/I traffic but no unique primary association",
                    project_device.id, object.number
                ))));
            }
            if flags.read_on_init() && !flags.update_enable() {
                warnings.push(format!(
                    "device `{}`, object {} enables read-on-init without update and cannot consume the response",
                    project_device.id, object.number
                ));
            }
            if !flags.communication_enable()
                && (flags.read_enable()
                    || flags.write_enable()
                    || flags.transmission_enable()
                    || flags.update_enable()
                    || flags.read_on_init())
            {
                warnings.push(format!(
                    "device `{}`, object {} has inert traffic flags because communication is disabled",
                    project_device.id, object.number
                ));
            }

            for membership in &authored.memberships {
                let net = &project.nets[&membership.net];
                check_dpt(&net.dpt, object.datapoint_type.as_deref(), object.object_type).map_err(|reason| {
                    Error::InvalidProject(ErrorDetail::new(format!(
                        "device `{}`, object {}, net `{}`: {reason}",
                        project_device.id, object.number, net.id
                    )))
                })?;
            }
        }

        Ok(EvaluatedProjectDevice { id: project_device.id.clone(), resolved, net_ids, warnings })
    }
}

fn topology_configuration(
    project: &AuthoredProject,
    project_device: &ProjectDevice,
    product: &ProductData,
) -> Result<TopologyConfiguration> {
    let line = project.line_topology(project_device.area, project_device.line).ok_or_else(|| {
        Error::InvalidProject(ErrorDetail::new(format!(
            "device `{}` has no unique authored topology line {}.{}",
            project_device.id, project_device.area, project_device.line
        )))
    })?;

    let group_filter = match (project_device.coupler_role(), project_device.routing) {
        (None, None) => None,
        (None, Some(_)) => {
            return Err(Error::InvalidProject(ErrorDetail::new(format!(
                "device `{}` declares group routing but is not an address-zero topology coupler",
                project_device.id
            ))));
        }
        (Some(_), None) => {
            return Err(Error::InvalidProject(ErrorDetail::new(format!(
                "topology coupler `{}` has no group-routing policy",
                project_device.id
            ))));
        }
        (Some(_), Some(policy)) => {
            let addresses = match policy {
                CouplerRoutingPolicy::Filter => project
                    .coupler_filter_addresses(&project_device.id)
                    .map_err(|error| {
                        Error::InvalidProject(ErrorDetail::new(format!(
                            "could not derive group filter for `{}`: {error}",
                            project_device.id
                        )))
                    })?
                    .ok_or_else(|| {
                        Error::InvalidProject(ErrorDetail::new(format!(
                            "filtering coupler `{}` produced no group-filter configuration",
                            project_device.id
                        )))
                    })?,
                CouplerRoutingPolicy::RouteAll | CouplerRoutingPolicy::BlockAll => BTreeSet::new(),
            };

            Some(GroupFilterConfiguration { policy, addresses })
        }
    };

    // RF uses an open-medium network-management phase. KNX/IP's routing
    // multicast address instead belongs to the standard Parameter Object
    // overlay and must never be sent through the RF domain-address services.
    let domain_address = match line.domain {
        Some(zweidraehte_project::DomainAddress::Rf(domain)) => Some(zweidraehte_project::DomainAddress::Rf(domain)),
        Some(zweidraehte_project::DomainAddress::Ip(_)) | None => None,
    };
    let authored_ip = match (line.domain, line.ip, project_device.ip.as_ref()) {
        (Some(zweidraehte_project::DomainAddress::Ip(routing_multicast_address)), Some(line), Some(device)) => {
            Some(ToolManagedIpConfiguration {
                project_installation_id: line.project_installation_id,
                assignment: device.assignment,
                routing_multicast_address,
                multicast_ttl: device.multicast_ttl,
                friendly_name: device.friendly_name.clone(),
                additional_individual_addresses: device.additional_individual_addresses.clone(),
                security: device.security.clone(),
                password_users: device.password_users.clone(),
            })
        }
        (Some(zweidraehte_project::DomainAddress::Ip(_)), Some(_), None) => None,
        (Some(zweidraehte_project::DomainAddress::Rf(_)) | None, None, None) => None,
        _ => {
            return Err(Error::InvalidProject(ErrorDetail::new(format!(
                "device `{}` has inconsistent KNX/IP line and device configuration",
                project_device.id
            ))));
        }
    };
    let ip = if project_device.medium == zweidraehte_project::Medium::Ip {
        match product.programming_options().ip_configuration().value {
            IpConfigurationMode::Tool => Some(authored_ip.ok_or_else(|| {
                Error::InvalidProject(ErrorDetail::new(format!(
                    "tool-managed KNX/IP product `{}` needs complete authored IP configuration",
                    project_device.id
                )))
            })?),
            IpConfigurationMode::Custom if authored_ip.is_none() => None,
            IpConfigurationMode::Custom => {
                return Err(Error::InvalidProject(ErrorDetail::new(format!(
                    "KNX/IP product `{}` declares IPConfig=Custom; configure its manufacturer parameters instead of the standard IP fields",
                    project_device.id
                ))));
            }
            IpConfigurationMode::Unknown(value) => {
                return Err(Error::InvalidProject(ErrorDetail::new(format!(
                    "KNX/IP product `{}` declares unknown IPConfig value `{value}`",
                    project_device.id
                ))));
            }
        }
    } else {
        debug_assert!(authored_ip.is_none(), "non-IP topology cannot carry IP configuration");
        None
    };

    Ok(TopologyConfiguration { domain_address, rf_device_mode: project_device.rf_mode, group_filter, ip })
}

fn validate_data_secure_capability(project_device: &ProjectDevice, product: &ProductData) -> Result<()> {
    if project_device.data_secure.is_enabled() && !product.supports_data_secure() {
        return Err(Error::InvalidProject(ErrorDetail::new(format!(
            "device `{}` enables Data Secure, but product `{}` does not support it",
            project_device.id,
            product.id()
        ))));
    }
    Ok(())
}

pub(super) fn check_dpt(
    net: &str,
    product: Option<&str>,
    object_type: ComObjectType,
) -> core::result::Result<(), String> {
    let net = canonical_dpt(net).ok_or_else(|| format!("invalid net DPT `{net}`"))?;
    if let Some(product) = product {
        let references =
            ProductDptReferences::parse(product).ok_or_else(|| format!("unknown product DPT `{product}`"))?;
        if !references.accepts(ProductDptReference { main: net.0, subtype: net.1 }) {
            return Err(format!("net DPT main type is incompatible with effective product DPT `{product}`"));
        }
    }
    let expected_bits =
        dpt_payload_bits(net.0).ok_or_else(|| format!("payload size for DPT main type {} is not known", net.0))?;
    let actual_bits = match object_type {
        ComObjectType::Uint1 => 1,
        ComObjectType::Uint2 => 2,
        ComObjectType::Uint3 => 3,
        ComObjectType::Uint4 => 4,
        ComObjectType::Uint5 => 5,
        ComObjectType::Uint6 => 6,
        ComObjectType::Uint7 => 7,
        other => other.size_in_bytes().0 * 8,
    };
    if expected_bits != actual_bits {
        return Err(format!("DPT needs {expected_bits} bits but the effective object has {actual_bits}"));
    }
    Ok(())
}

fn canonical_dpt(value: &str) -> Option<(u16, Option<u16>)> {
    let (main, sub) = value.split_once('.')?;
    Some((main.parse().ok()?, Some(sub.parse().ok()?)))
}

fn dpt_payload_bits(main: u16) -> Option<usize> {
    Some(match main {
        1 => 1,
        2 => 2,
        3 => 4,
        4..=6 | 17 | 18 | 20 | 21 | 23 | 26 => 8,
        7..=9 | 22 => 16,
        10 | 11 | 30 | 232 => 24,
        12..=15 | 27 | 235 => 32,
        16 => 112,
        19 | 29 => 64,
        234 | 236 | 251 => 48,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::product::check_dpt;

    #[test]
    fn product_cache_shares_exact_selectors_and_rejects_changed_leaves() {
        let fixture = crate::project::tests::secure_fixture();
        let directory = tempfile::tempdir().expect("project directory");
        let path = directory.path().join("project.knx");
        std::fs::write(&path, fixture.project.source()).expect("source");
        let store = ProjectStore::open(&path).expect("project");
        let project = store.authored();
        let id = ProjectDeviceId::new("receiver").expect("literal is an identifier");
        let ProductReference::Package { package, catalog_item } = &project.devices[&id].product;
        let selector = PackageCatalogSelector {
            package: PackageDigest::from_bytes(*package.as_bytes()),
            catalog_item_id: catalog_item.clone(),
        };
        let mut cache = ProductCache(BTreeMap::from([(
            (project.package_store_directory().expect("store path"), selector),
            fixture.products[&id].clone(),
        )]));

        let first = cache.load(project, project.devices.keys(), |_, _, _| {}).expect("cached selections");
        let second = cache.load(project, project.devices.keys(), |_, _, _| {}).expect("next refresh");
        assert!(Arc::ptr_eq(&first[&id].selected, &second["sender"].selected));

        // Equal application IDs do not authorize reuse under another leaf or
        // digest. With no archive behind the new selector, acquisition fails.
        let changed = project
            .reparse(project.source().replace("catalog_item \"switch\"", "catalog_item \"other\""))
            .expect("different leaf");
        assert!(cache.load(&changed, [&id], |_, _, _| {}).is_err());
        let changed =
            project.reparse(project.source().replace(&"0".repeat(64), &"1".repeat(64))).expect("different digest");
        assert!(cache.load(&changed, [&id], |_, _, _| {}).is_err());
    }

    #[test]
    fn dpt_validation_accepts_semantic_subtypes_with_the_same_wire_type() {
        assert!(check_dpt("1.001", Some("DPT-1 DPST-1-11"), ComObjectType::Uint1).is_ok());

        let incompatible_main =
            check_dpt("5.001", Some("DPT-1 DPST-1-11"), ComObjectType::Byte1).expect_err("main types differ");
        assert!(incompatible_main.contains("main type is incompatible"));

        let incompatible_width = check_dpt("1.001", None, ComObjectType::Byte1).expect_err("wire widths differ");
        assert!(incompatible_width.contains("DPT needs 1 bits"));
    }
}
