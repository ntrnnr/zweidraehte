//! Standard IP facts, enabled only after product ownership is validated.

use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence, ResolvedProfile};
use crate::commissioning::error::ProfileError;
use crate::configuration::ToolManagedIpConfiguration;
use zweidraehte_ets_files::product::{IpConfigurationMode, ProductData};
use zweidraehte_proto::pid;

const IP_PARAMETER_OBJECT_TYPE: u16 = 11;

/// Validate the product-owned/tool-owned boundary and add the exact standard
/// OT11 property facts which versioned Master Data intentionally leaves sparse.
pub(crate) fn prepare_classic_ip_profile(
    profile: &mut ResolvedProfile,
    product: &ProductData,
    topology_ip: Option<&ToolManagedIpConfiguration>,
) -> Result<(), ProfileError> {
    let mode = &product.programming_options().ip_configuration().value;
    match mode {
        IpConfigurationMode::Unknown(token) => {
            return Err(ProfileError::unsupported(format!(
                "product declares unknown IPConfig token {0:?}",
                token.clone()
            )));
        }
        IpConfigurationMode::Custom if topology_ip.is_some() => {
            return Err(ProfileError::invalid(
                "tool-managed IP intent was supplied for a product with IPConfig=Custom",
            ));
        }
        IpConfigurationMode::Custom => return Ok(()),
        IpConfigurationMode::Tool => {}
    }

    if !is_classic_ip_mask(profile) {
        if topology_ip.is_some() {
            return Err(ProfileError::unsupported(format!(
                "tool-managed IP intent was supplied for non-IP profile {0}",
                profile.mask().full_id.clone()
            )));
        }
        return Ok(());
    }
    require_ip_medium(profile)?;

    let objects = profile
        .interface_objects()
        .iter()
        .filter(|object| object.object_type == Some(IP_PARAMETER_OBJECT_TYPE))
        .count();
    if objects > 1 {
        return Err(ProfileError::invalid(format!(
            "profile resolves {objects} IP Parameter Objects; exactly one is required"
        )));
    }
    profile.tool_managed_ip = Some(product.programming_options().is_secure_enabled().value);

    Ok(())
}

pub(crate) fn is_classic_ip_mask(profile: &ResolvedProfile) -> bool {
    matches!(profile.mask().full_id.as_str(), "MV-5705" | "MV-57B0")
}

pub(crate) fn require_ip_medium(profile: &ResolvedProfile) -> Result<(), ProfileError> {
    let mask = profile.mask_source();
    if mask.medium_type_ref_id.as_deref() == Some("MT-5") || mask.other_medium_type_ref_id.as_deref() == Some("MT-5") {
        Ok(())
    } else {
        Err(ProfileError::invalid(format!(
            "classic IP profile {0} does not resolve the KNX IP medium",
            profile.mask().full_id.clone()
        )))
    }
}

pub(crate) const IP_OBJECT: ObjectSelector =
    ObjectSelector::Type { object_type: IP_PARAMETER_OBJECT_TYPE, occurrence: Occurrence::Zero };

pub(crate) fn standard_property(
    profile: &ResolvedProfile,
    selector: &ObjectSelector,
    property_id: u16,
) -> Option<(&'static str, Option<u32>)> {
    let secure = profile.tool_managed_ip?;
    let is_ip = match selector {
        ObjectSelector::Type { object_type, .. } => *object_type == IP_PARAMETER_OBJECT_TYPE,
        ObjectSelector::Index { index } => profile.interface_objects().iter().any(|object| {
            object.index.map(u16::from) == Some(*index) && object.object_type == Some(IP_PARAMETER_OBJECT_TYPE)
        }),
    };
    if !is_ip {
        return None;
    }
    Some(match property_id {
        pid::ip::PROJECT_INSTALLATION_ID | pid::ip::ADDITIONAL_INDIVIDUAL_ADDRESSES => ("PDT_UNSIGNED_INT", Some(2)),
        pid::ip::IP_ASSIGNMENT_METHOD | pid::ip::TTL => ("PDT_UNSIGNED_CHAR", Some(1)),
        pid::ip::IP_ADDRESS | pid::ip::SUBNET_MASK | pid::ip::DEFAULT_GATEWAY | pid::ip::ROUTING_MULTICAST_ADDRESS => {
            ("PDT_GENERIC_04", Some(4))
        }
        pid::ip::MAC_ADDRESS => ("PDT_GENERIC_06", Some(6)),
        pid::ip::FRIENDLY_NAME => ("PDT_CHAR", Some(1)),
        pid::ip::BACKBONE_KEY | pid::ip::DEVICE_AUTHENTICATION_CODE | pid::ip::PASSWORD_HASHES if secure => {
            ("PDT_GENERIC_16", Some(16))
        }
        pid::ip::SECURED_SERVICE_FAMILIES if secure => ("PDT_FUNCTION", None),
        pid::ip::MULTICAST_LATENCY_TOLERANCE if secure => ("PDT_UNSIGNED_INT", Some(2)),
        pid::ip::SYNC_LATENCY_FRACTION if secure => ("PDT_UNSIGNED_CHAR", Some(1)),
        pid::ip::TUNNELING_USERS if secure => ("PDT_GENERIC_02", Some(2)),
        _ => return None,
    })
}
