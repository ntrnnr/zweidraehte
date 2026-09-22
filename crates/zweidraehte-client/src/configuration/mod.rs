//! Product lowering and target-independent desired device configuration.

mod device;
mod error;
mod materialized;
mod product;
mod security;

pub use device::{
    DeviceConfiguration, DeviceIdentity, GroupFilterConfiguration, InstallationConfiguration,
    LoweredDeviceConfiguration, MaterializedModule, MaterializedModuleArgument, MembershipRole, NetSecurityPolicy,
    ObjectMembership, ProcedureParameter, ProcedureParameterValue, ToolManagedIpConfiguration, TopologyConfiguration,
};
pub use device::{GroupLink, ParameterValue};
pub use error::{ConfigurationError, ConfigurationResult};
pub use materialized::MaterializedDevice;
pub use product::ResolvedDevice;
pub use security::{
    GroupObjectProtection, GroupObjectSecurity, ResolvedIpSecureConfiguration, ResolvedKeyMaterial, SecurityConfig,
};
