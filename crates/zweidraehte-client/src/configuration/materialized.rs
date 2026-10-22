//! Product facts and resolved configuration consumed together by commissioning.

use zweidraehte_ets_files::product::ProductData;

use super::{LoweredDeviceConfiguration, MaterializedModule};
use crate::configuration::ResolvedKeyMaterial;

/// One device's compiler input, before target discovery and commissioning-policy
/// selection.
///
/// Normally produced by [`super::ResolvedDevice::into_materialized`] from a
/// checked product evaluation. Expert adapters may supply facts with [`Self::new`];
/// this type alone does not prove they came from the same evaluation. It holds
/// the supplied product, objects, module geometry and keys together without
/// re-evaluating authored UI choices. Every programming compiler consumes this
/// same boundary and validates its inputs.
#[derive(Clone)]
pub struct MaterializedDevice {
    product: ProductData,
    configuration: LoweredDeviceConfiguration,
    modules: Vec<MaterializedModule>,
    key_material: ResolvedKeyMaterial,
}

impl MaterializedDevice {
    /// Assemble supplied parts without evaluating their consistency. Normal
    /// callers consume [`super::ResolvedDevice::into_materialized`]. Expert
    /// adapters are responsible for consistent product, object and module facts;
    /// compiler validation checks supported programming constraints, not the
    /// correctness of an independently supplied dynamic evaluation.
    pub fn new(
        product: ProductData,
        configuration: LoweredDeviceConfiguration,
        modules: Vec<MaterializedModule>,
        key_material: ResolvedKeyMaterial,
    ) -> Self {
        Self { product, configuration, modules, key_material }
    }

    pub fn product(&self) -> &ProductData {
        &self.product
    }

    /// Complete loose project product input before it enters the programming
    /// pipeline. Callers outside the crate bind the [`ProductData`] before
    /// assembling the device.
    #[cfg(feature = "project")]
    pub(crate) fn bind_master_data(
        mut self,
        document: std::sync::Arc<zweidraehte_ets_files::MasterData>,
    ) -> Result<Self, zweidraehte_ets_files::product::ProductError> {
        self.product = self.product.bind_master_data(document)?;
        Ok(self)
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

    pub fn configuration(&self) -> &LoweredDeviceConfiguration {
        &self.configuration
    }

    pub fn modules(&self) -> &[MaterializedModule] {
        &self.modules
    }

    pub fn key_material(&self) -> &ResolvedKeyMaterial {
        &self.key_material
    }
}

impl core::fmt::Debug for MaterializedDevice {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MaterializedDevice")
            .field("product_id", &self.product.id())
            .field("configuration", &self.configuration)
            .field("modules", &self.modules)
            .field("key_material", &self.key_material)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::num::NonZeroU8;

    use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

    use super::*;
    use crate::configuration::ResolvedIpSecureConfiguration;
    use crate::configuration::{
        MaterializedModuleArgument, ProcedureParameter, ProcedureParameterValue, SecurityConfig,
    };

    #[test]
    fn one_instance_keeps_procedure_module_and_key_inputs_together() {
        let selector = ProcedureParameter { active: false, value: ProcedureParameterValue::Signed(3) };
        let mut configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 10), Some(15));
        configuration.procedure_parameters.insert("P-1_R-1".to_owned(), selector.clone());
        let module = MaterializedModule {
            instance_id: "MD-1".to_owned(),
            definition_id: "MD-Channel".to_owned(),
            arguments: BTreeMap::from([("Channel".to_owned(), MaterializedModuleArgument::Numeric(4))]),
        };
        let group = GroupAddress::from_three_level(1, 2, 3);
        let application_security = SecurityConfig::new(vec![(group, [0x33; 16])], Vec::new(), Vec::new());
        let ip_secure = ResolvedIpSecureConfiguration::new()
            .with_backbone_key(Some([0x44; 16]))
            .with_device_authentication_code(Some([0x55; 16]))
            .with_password_hash(NonZeroU8::new(1).expect("one is nonzero"), [0x66; 16]);
        let keys = ResolvedKeyMaterial::new(Some([1, 2, 3, 4, 5, 6]))
            .with_fdsk(Some([0x11; 16]))
            .with_tool_key(Some([0x22; 16]))
            .with_application_security(Some(application_security))
            .with_ip_secure(Some(ip_secure));

        let device = MaterializedDevice::new(ProductData::default(), configuration, vec![module.clone()], keys);

        assert_eq!(device.configuration().procedure_parameters.get("P-1_R-1"), Some(&selector));
        assert_eq!(device.modules(), [module]);
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

    impl MaterializedDevice {
        pub(crate) fn key_material_mut(&mut self) -> &mut ResolvedKeyMaterial {
            &mut self.key_material
        }
    }
}
