//! Product facts and resolved configuration consumed together by commissioning.
//!
//! One device passes through two states. Evaluation produces a
//! [`MaterializedDevice<Unkeyed>`] that still holds the authored
//! [`SecurityIntent`]; key resolution reads that intent and replaces it with
//! [`ResolvedKeyMaterial`], producing a [`MaterializedDevice<Keyed>`]. Only the
//! keyed state compiles, so no program is built before key sources were
//! consulted, and a keyed device cannot carry intent that disagrees with its
//! keys. Everything else — product, address, links, topology and encoded
//! values — is the same data in both states.

use zweidraehte_ets_files::product::{ComObjectDef, MaterializedModule, ProductData};
use zweidraehte_proto::address::IndividualAddress;

use super::{
    EncodedConfiguration, EncodedParameter, InstallationConfiguration, MembershipRole, ObjectMembership,
    ProcedureParameter, SecurityIntent, TopologyConfiguration,
};
use crate::configuration::ResolvedKeyMaterial;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Unkeyed {}
    impl Sealed for super::Keyed {}
}

/// Whether a [`MaterializedDevice`] holds authored security intent or the
/// key material resolved from it.
///
/// Sealed: [`Unkeyed`] and [`Keyed`] are the only states.
pub trait KeyState: sealed::Sealed {
    /// The security data a device in this state carries.
    type Security: Clone + core::fmt::Debug;
}

/// Evaluated, but key sources not yet consulted. Holds a [`SecurityIntent`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Unkeyed;

/// Key material resolved. Holds a [`ResolvedKeyMaterial`] and can be compiled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Keyed;

impl KeyState for Unkeyed {
    type Security = SecurityIntent;
}

impl KeyState for Keyed {
    type Security = ResolvedKeyMaterial;
}

/// One device's compiler input, before target discovery and commissioning-policy
/// selection.
///
/// Normally produced by [`Self::from_evaluated`] from a checked product
/// evaluation. Expert adapters holding an evaluation made elsewhere use
/// [`Self::from_parts`]; that constructor cannot prove the encoded values came
/// from the same evaluation as the product's module geometry. Every
/// programming compiler consumes this same boundary and validates its inputs.
///
/// A device must be keyed before it compiles:
///
/// ```compile_fail
/// use zweidraehte_client::commissioning::{
///     CommissioningIntent, CompileOptions, DownloadMode, ProgrammingInput, TargetSelection,
/// };
/// use zweidraehte_client::configuration::{EncodedConfiguration, InstallationConfiguration, MaterializedDevice};
/// use zweidraehte_client::IndividualAddress;
/// use zweidraehte_ets_files::product::ProductData;
///
/// let address = IndividualAddress::new(1, 1, 10);
/// let unkeyed = MaterializedDevice::from_parts(
///     ProductData::default(),
///     InstallationConfiguration::new(address),
///     EncodedConfiguration::default(),
/// );
/// let options = CompileOptions {
///     target: TargetSelection::ExistingAddress(address),
///     automatic_sections: None,
///     progress_messages_by_reference: Default::default(),
///     progress_messages_by_id: Default::default(),
/// };
/// // Fails: `ProgrammingInput::new` takes a `MaterializedDevice<Keyed>`; an
/// // unkeyed device must pass through `into_keyed` first.
/// let _ = ProgrammingInput::new(unkeyed, CommissioningIntent::Download(DownloadMode::Full), options);
/// ```
pub struct MaterializedDevice<S: KeyState = Keyed> {
    /// Product data with module geometry resolved for this device; it carries
    /// the module roster that geometry came from.
    product: ProductData,
    individual_address: IndividualAddress,
    /// Every primary link before any additional one.
    object_memberships: Vec<ObjectMembership>,
    topology: TopologyConfiguration,
    max_apdu: Option<u16>,
    encoded: EncodedConfiguration,
    security: S::Security,
}

impl MaterializedDevice<Unkeyed> {
    /// Assemble an evaluation made outside this crate.
    ///
    /// `product` must already have its module geometry resolved
    /// ([`ProductData::resolve_module_geometry`]), which also fixes its module
    /// roster. Expert adapters are responsible for `encoded` matching that
    /// product; compiler validation checks supported programming constraints,
    /// not the correctness of an independently supplied evaluation.
    pub fn from_parts(
        product: ProductData,
        installation: InstallationConfiguration,
        encoded: EncodedConfiguration,
    ) -> Self {
        let InstallationConfiguration { individual_address, mut object_memberships, topology, max_apdu, security } =
            installation;

        // The association table lists primary links first. A stable sort keeps
        // the authored order within each role.
        object_memberships.sort_by_key(|membership| match membership.role {
            MembershipRole::Primary => 0,
            MembershipRole::Additional => 1,
        });

        Self { product, individual_address, object_memberships, topology, max_apdu, encoded, security }
    }

    /// The authored security choices key resolution consumes.
    pub fn security_intent(&self) -> &SecurityIntent {
        &self.security
    }

    /// Replace the security intent with the key material resolved from it.
    ///
    /// Preview callers may supply unresolved keys; live preparation validates
    /// the requested security transition.
    pub fn into_keyed(self, key_material: ResolvedKeyMaterial) -> MaterializedDevice<Keyed> {
        let Self { product, individual_address, object_memberships, topology, max_apdu, encoded, security: _ } = self;
        MaterializedDevice {
            product,
            individual_address,
            object_memberships,
            topology,
            max_apdu,
            encoded,
            security: key_material,
        }
    }
}

impl MaterializedDevice<Keyed> {
    pub fn key_material(&self) -> &ResolvedKeyMaterial {
        &self.security
    }

    /// Resolve this device's exact profile against its product's bound
    /// Master Data. The result is what [`crate::commissioning::ProgrammingInput::compile`]
    /// and [`crate::commissioning::ProgrammingInput::preview`] take.
    pub fn resolve_profile(
        &self,
        selection: &crate::commissioning::ProfileSelection,
    ) -> Result<crate::commissioning::ResolvedProfile, crate::commissioning::CompileError> {
        crate::commissioning::ResolvedProfile::for_product(&self.product, selection)
    }
}

impl<S: KeyState> MaterializedDevice<S> {
    pub fn product(&self) -> &ProductData {
        &self.product
    }

    /// The active module instances the product's geometry was resolved from.
    pub fn modules(&self) -> &[MaterializedModule] {
        self.product.modules()
    }

    pub fn individual_address(&self) -> IndividualAddress {
        self.individual_address
    }

    /// Group links, every primary link before any additional one.
    pub fn object_memberships(&self) -> &[ObjectMembership] {
        &self.object_memberships
    }

    pub fn topology(&self) -> &TopologyConfiguration {
        &self.topology
    }

    /// Project-authored APDU ceiling, applied after capability discovery.
    pub fn max_apdu(&self) -> Option<u16> {
        self.max_apdu
    }

    pub fn encoded(&self) -> &EncodedConfiguration {
        &self.encoded
    }

    pub fn parameters(&self) -> &[EncodedParameter] {
        &self.encoded.parameters
    }

    pub fn com_objects(&self) -> &[ComObjectDef] {
        &self.encoded.com_objects
    }

    pub fn procedure_parameters(&self) -> &std::collections::BTreeMap<String, ProcedureParameter> {
        &self.encoded.procedure_parameters
    }
}

impl<S: KeyState> Clone for MaterializedDevice<S> {
    fn clone(&self) -> Self {
        Self {
            product: self.product.clone(),
            individual_address: self.individual_address,
            object_memberships: self.object_memberships.clone(),
            topology: self.topology.clone(),
            max_apdu: self.max_apdu,
            encoded: self.encoded.clone(),
            security: self.security.clone(),
        }
    }
}

impl<S: KeyState> core::fmt::Debug for MaterializedDevice<S> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MaterializedDevice")
            .field("product_id", &self.product.id())
            .field("modules", &self.product.modules())
            .field("individual_address", &self.individual_address)
            .field("object_memberships", &self.object_memberships)
            .field("topology", &self.topology)
            .field("max_apdu", &self.max_apdu)
            .field("encoded", &self.encoded)
            .field("security", &self.security)
            .finish()
    }
}

/// Fixture access for unit tests, which vary one input of an otherwise fixed
/// device. Mutation bypasses the constructor's primary-first link order; tests
/// that add an additional link must keep that order themselves.
#[cfg(test)]
impl MaterializedDevice<Keyed> {
    /// A keyless device for `ProductData::default()` at `individual_address`.
    pub(crate) fn fixture(individual_address: IndividualAddress, max_apdu: Option<u16>) -> Self {
        let installation = InstallationConfiguration { max_apdu, ..InstallationConfiguration::new(individual_address) };
        MaterializedDevice::from_parts(ProductData::default(), installation, EncodedConfiguration::default())
            .into_keyed(ResolvedKeyMaterial::default())
    }

    pub(crate) fn with_product(mut self, product: ProductData) -> Self {
        self.product = product;
        self
    }

    pub(crate) fn with_key_material(mut self, key_material: ResolvedKeyMaterial) -> Self {
        self.security = key_material;
        self
    }

    pub(crate) fn with_com_objects(mut self, com_objects: Vec<ComObjectDef>) -> Self {
        self.encoded.com_objects = com_objects;
        self
    }

    pub(crate) fn with_topology(mut self, topology: TopologyConfiguration) -> Self {
        self.topology = topology;
        self
    }

    pub(crate) fn object_memberships_mut(&mut self) -> &mut Vec<ObjectMembership> {
        &mut self.object_memberships
    }

    pub(crate) fn encoded_mut(&mut self) -> &mut EncodedConfiguration {
        &mut self.encoded
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::num::NonZeroU8;

    use zweidraehte_proto::address::GroupAddress;

    use super::*;
    use crate::configuration::{ProcedureParameterValue, ResolvedIpSecureConfiguration, SecurityConfig};

    #[test]
    fn primary_associations_are_ordered_before_additional_ones() {
        let primary = GroupAddress::from_three_level(1, 0, 1);
        let additional = GroupAddress::from_three_level(1, 0, 2);
        let installation = InstallationConfiguration {
            object_memberships: vec![
                ObjectMembership { group_address: additional, com_object: 971, role: MembershipRole::Additional },
                ObjectMembership { group_address: primary, com_object: 971, role: MembershipRole::Primary },
            ],
            ..InstallationConfiguration::new(IndividualAddress::new(1, 1, 1))
        };

        let device = MaterializedDevice::from_parts(ProductData::default(), installation, Default::default());

        let order = device.object_memberships().iter().map(|link| link.group_address).collect::<Vec<_>>();
        assert_eq!(order, [primary, additional]);
    }

    #[test]
    fn keying_keeps_structure_and_replaces_intent_with_key_material() {
        let selector = ProcedureParameter { active: false, value: ProcedureParameterValue::Signed(3) };
        let encoded = EncodedConfiguration {
            parameters: vec![EncodedParameter { id: "P-1".into(), value: vec![7] }],
            procedure_parameters: BTreeMap::from([("P-1_R-1".to_owned(), selector.clone())]),
            ..Default::default()
        };
        let installation = InstallationConfiguration {
            max_apdu: Some(15),
            security: SecurityIntent {
                serial_number: Some([1, 2, 3, 4, 5, 6]),
                data_secure_enabled: true,
                ..Default::default()
            },
            ..InstallationConfiguration::new(IndividualAddress::new(1, 1, 10))
        };
        let unkeyed = MaterializedDevice::from_parts(ProductData::default(), installation, encoded);
        assert!(unkeyed.security_intent().data_secure_enabled);

        let group = GroupAddress::from_three_level(1, 2, 3);
        let application_security = SecurityConfig::new(vec![(group, [0x33; 16])], Vec::new(), Vec::new());
        let ip_secure = ResolvedIpSecureConfiguration::new()
            .with_backbone_key([0x44; 16])
            .with_device_authentication_code([0x55; 16])
            .with_password_hash(NonZeroU8::new(1).expect("one is nonzero"), [0x66; 16]);
        let keys = ResolvedKeyMaterial::default()
            .with_serial_number([1, 2, 3, 4, 5, 6])
            .with_fdsk([0x11; 16])
            .with_tool_key([0x22; 16])
            .with_application_security(application_security)
            .with_ip_secure(ip_secure);

        let device = unkeyed.into_keyed(keys);

        assert_eq!(device.individual_address(), IndividualAddress::new(1, 1, 10));
        assert_eq!(device.max_apdu(), Some(15));
        assert_eq!(device.parameters()[0].value, [7]);
        assert_eq!(device.procedure_parameters().get("P-1_R-1"), Some(&selector));
        assert_eq!(device.key_material().serial_number(), Some([1, 2, 3, 4, 5, 6]));
        assert_eq!(device.key_material().fdsk(), Some(&[0x11; 16]));
        assert_eq!(device.key_material().tool_key(), Some(&[0x22; 16]));
        let ip_secure = device.key_material().ip_secure().expect("IP Secure material is retained");
        assert_eq!(ip_secure.backbone_key(), Some(&[0x44; 16]));
        assert_eq!(ip_secure.device_authentication_code(), Some(&[0x55; 16]));
        assert_eq!(ip_secure.password_hashes().collect::<Vec<_>>(), [(NonZeroU8::MIN, &[0x66; 16])]);
        assert_eq!(
            device
                .key_material()
                .application_security()
                .expect("application security is canonical")
                .group_keys()
                .next(),
            Some((group, &[0x33; 16]))
        );
    }
}

#[cfg(feature = "project")]
mod project {
    use super::*;

    impl MaterializedDevice<Unkeyed> {
        /// The same device for key resolution of a management-only operation,
        /// which needs credentials but no group keys or links.
        pub(crate) fn without_group_communication(&self) -> Self {
            let mut device = self.clone();
            device.object_memberships.clear();
            device.security.net_security.clear();
            device
        }
    }

    impl MaterializedDevice<Keyed> {
        pub(crate) fn key_material_mut(&mut self) -> &mut ResolvedKeyMaterial {
            &mut self.security
        }

        /// Complete loose project product input before it enters the
        /// programming pipeline. Callers outside the crate bind the
        /// [`ProductData`] before assembling the device.
        pub(crate) fn bind_master_data(
            mut self,
            document: std::sync::Arc<zweidraehte_ets_files::MasterData>,
        ) -> Result<Self, zweidraehte_ets_files::product::ProductError> {
            self.product = self.product.bind_master_data(document)?;
            Ok(self)
        }
    }
}
