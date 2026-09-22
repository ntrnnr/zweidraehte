//! Build coupler routing filters from the configured group-address policy.

pub(super) fn require_length_and_flavour(
    resource: &SelectedResource<'_>,
    expected_length: u32,
    expected_flavours: &[ResourceFlavour],
) -> Result<(), CompileError> {
    if resource.length() != expected_length {
        return Err(CompileError::invalid(format!(
            "resource {resource:?} has length {actual}, expected {expected}",
            resource = resource.name().to_owned(),
            expected = "one octet",
            actual = resource.length()
        )));
    }
    let actual = resource.flavour()?;
    if !actual.is_some_and(|actual| expected_flavours.contains(&actual)) {
        return Err(CompileError::invalid(format!(
            "resource {resource:?} has flavour {actual:?}, expected one of {expected:?}",
            resource = resource.name().to_owned(),
            expected = expected_flavours.to_vec()
        )));
    }
    Ok(())
}

use super::resource_image_location;
use crate::commissioning::catalog::SelectedResource;
use crate::commissioning::catalog::profile::{ResolvedProfile, ResourceFlavour};
use crate::commissioning::error::CompileError;
use crate::commissioning::image::ImageSegment;
use zweidraehte_project::CouplerRoutingPolicy;

pub(super) fn compile_group_filter(
    profile: &ResolvedProfile,
    resource: &SelectedResource<'_>,
    policy: CouplerRoutingPolicy,
    addresses: &std::collections::BTreeSet<zweidraehte_proto::address::GroupAddress>,
) -> Result<Vec<ImageSegment>, CompileError> {
    if policy != CouplerRoutingPolicy::Filter && !addresses.is_empty() {
        return Err(CompileError::invalid("route-all and block-all policies cannot carry selective filter addresses"));
    }

    let legacy_config = profile.resource("LcConfig")?;
    let legacy_group_config = profile.resource("LcGrpConfig")?;
    let main_group_config = profile.resource("MainLcGrpConfig")?;
    let sub_group_config = profile.resource("SubLcGrpConfig")?;
    let filter_table_use = profile.resource("GroupFilterTableUse")?;

    let architecture = match (legacy_config, legacy_group_config, main_group_config, sub_group_config, filter_table_use)
    {
        (Some(config), Some(group), None, None, None) => RoutingArchitecture::Legacy { config, group },
        (None, None, Some(main), Some(sub), None)
            if main.flavour()? == Some(ResourceFlavour::Lc12) && sub.flavour()? == Some(ResourceFlavour::Lc12) =>
        {
            RoutingArchitecture::Modern { main, sub }
        }
        (None, None, None, None, Some(_)) if profile.mask().full_id == "MV-2920" => {
            if !matches!(
                &profile.disposition(),
                crate::commissioning::catalog::profile::ProfileDisposition::CouplerRoutingRequired
            ) {
                return Err(CompileError::invalid(
                    "Coupler Model 2.0 routing was not classified as requiring its product routing selector",
                ));
            }

            RoutingArchitecture::CouplerModel20
        }
        _ => {
            return Err(CompileError::unsupported(format!(
                "profile {profile} has no recognized group-routing selector architecture",
                profile = profile.mask().full_id.clone()
            )));
        }
    };

    let (expected_length, maximum, allow_upper_legacy_range) = match architecture {
        RoutingArchitecture::Legacy { .. } => (3584, 0x6fff, true),
        RoutingArchitecture::Modern { .. } | RoutingArchitecture::CouplerModel20 => (8192, 0xffff, false),
    };
    if resource.length() != expected_length {
        return Err(CompileError::invalid(format!(
            "resource {resource:?} has length {actual}, expected {expected}",
            resource = resource.name().to_owned(),
            expected = match expected_length {
                3584 => "3584 octets for an RT1 legacy filter",
                8192 => "8192 octets for a full group-address filter",
                _ => unreachable!("known coupler filter size"),
            },
            actual = resource.length()
        )));
    }

    let data = encode_filter_bitmap(resource, policy, addresses, maximum, allow_upper_legacy_range)?;
    let mut segments = vec![ImageSegment::owned(resource_image_location(resource)?, data)?];

    match architecture {
        RoutingArchitecture::Legacy { config, group } => {
            require_length_and_flavour(&config, 1, &[ResourceFlavour::Lc10, ResourceFlavour::Lc11])?;
            require_length_and_flavour(&group, 1, &[ResourceFlavour::Lc10, ResourceFlavour::Lc11])?;
            if config.flavour()? != group.flavour()? {
                return Err(CompileError::invalid(format!(
                    "resources {first:?} and {second:?} declare conflicting routing flavours",
                    first = config.name().to_owned(),
                    second = group.name().to_owned()
                )));
            }

            let group_value = legacy_group_selector(policy);
            segments.push(masked_resource_segment(&group, group_value, 0x33)?);

            // Legacy filters cover only 0000..6FFF. Bit 4 is the standardized
            // coarse selector for the entire 7000..FFFF range, so exact
            // filtering above the table range is impossible on these masks.
            let route_upper = policy == CouplerRoutingPolicy::RouteAll
                || (policy == CouplerRoutingPolicy::Filter
                    && addresses.iter().any(|address| raw_group_address(*address) > 0x6fff));
            segments.push(masked_resource_segment(&config, u8::from(route_upper) << 4, 0x10)?);
        }
        RoutingArchitecture::Modern { main, sub } => {
            require_length_and_flavour(&main, 1, &[ResourceFlavour::Lc12])?;
            require_length_and_flavour(&sub, 1, &[ResourceFlavour::Lc12])?;

            let value = modern_group_selector(policy);
            segments.push(masked_resource_segment(&main, value, 0x0f)?);
            segments.push(masked_resource_segment(&sub, value, 0x0f)?);
        }
        RoutingArchitecture::CouplerModel20 => {
            // PID 67 only says whether the filter table is valid. The actual
            // routing selector is product-defined for Coupler Model 2.0, so
            // the product must declare a parameter or property selecting it.
        }
    }

    Ok(segments)
}

#[derive(Debug, Clone)]
enum RoutingArchitecture<'a> {
    Legacy { config: SelectedResource<'a>, group: SelectedResource<'a> },
    Modern { main: SelectedResource<'a>, sub: SelectedResource<'a> },
    CouplerModel20,
}

pub(super) fn encode_filter_bitmap(
    resource: &SelectedResource<'_>,
    policy: CouplerRoutingPolicy,
    addresses: &std::collections::BTreeSet<zweidraehte_proto::address::GroupAddress>,
    maximum: u32,
    allow_addresses_above_maximum: bool,
) -> Result<Vec<u8>, CompileError> {
    let length = usize::try_from(resource.length()).map_err(|_| {
        CompileError::invalid(format!("resource {0:?} is too large for this host", resource.name().to_owned()))
    })?;
    if length == 0 {
        return Err(CompileError::invalid(format!(
            "resource {resource:?} has length {actual}, expected {expected}",
            resource = resource.name().to_owned(),
            expected = "a non-empty filter bitmap",
            actual = 0
        )));
    }

    // The table always contains the exact crossing-address set. Route-all and
    // block-all are encoded by their separate selectors, never by fabricating
    // an all-one or all-zero table as the policy itself.
    let mut data = vec![0; length];

    if policy == CouplerRoutingPolicy::Filter {
        for address in addresses {
            let raw = raw_group_address(*address);
            if raw > maximum {
                if allow_addresses_above_maximum {
                    continue;
                }
                return Err(CompileError::invalid(format!(
                    "group address {address} exceeds this profile's filter-table maximum {maximum:#06x}",
                    address = *address
                )));
            }

            // 03/03/07 RT1 numbers bits least-significant first inside each
            // octet: GA n selects byte n/8 and mask 1 << (n%8).
            data[(raw / 8) as usize] |= 1 << (raw % 8);
        }
    }

    Ok(data)
}

pub(super) fn masked_resource_segment(
    resource: &SelectedResource<'_>,
    data: u8,
    mask: u8,
) -> Result<ImageSegment, CompileError> {
    Ok(ImageSegment::new(resource_image_location(resource)?, vec![data], vec![mask])?)
}

pub(super) fn raw_group_address(address: zweidraehte_proto::address::GroupAddress) -> u32 {
    u32::from(u16::from_be_bytes([address.as_bytes()[0], address.as_bytes()[1]]))
}

pub(super) const fn legacy_group_selector(policy: CouplerRoutingPolicy) -> u8 {
    match policy {
        CouplerRoutingPolicy::Filter => 0x33,
        CouplerRoutingPolicy::RouteAll => 0x11,
        CouplerRoutingPolicy::BlockAll => 0x22,
    }
}

pub(super) const fn modern_group_selector(policy: CouplerRoutingPolicy) -> u8 {
    match policy {
        CouplerRoutingPolicy::Filter => 0x0f,
        CouplerRoutingPolicy::RouteAll => 0x05,
        CouplerRoutingPolicy::BlockAll => 0x0a,
    }
}
