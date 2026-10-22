//! Product lowering and target-independent desired device configuration.
//!
//! # Errors
//!
//! Lowering product data returns [`ConfigurationError`]. Assembling a
//! [`MaterializedDevice`] from product files reports the product crate's
//! `ProductError`; resolving its profile returns
//! [`crate::commissioning::ProfileError`].

mod device;
mod error;
mod materialized;
mod product;
mod security;

pub use device::{
    EncodedConfiguration, EncodedParameter, GroupFilterConfiguration, InstallationConfiguration, MaterializedModule,
    MaterializedModuleArgument, MembershipRole, NetSecurityPolicy, ObjectMembership, ProcedureParameter,
    ProcedureParameterValue, SecurityIntent, ToolManagedIpConfiguration, TopologyConfiguration,
};
pub use error::{ConfigurationError, ConfigurationResult, ErrorDetail};
pub use materialized::{KeyState, Keyed, MaterializedDevice, Unkeyed};
pub use security::{
    GroupObjectProtection, GroupObjectSecurity, ResolvedIpSecureConfiguration, ResolvedKeyMaterial, SecurityConfig,
};
