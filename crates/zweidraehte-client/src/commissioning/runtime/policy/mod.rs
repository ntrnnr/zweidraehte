//! Shared commissioning policy, grouped by the decisions its callers need.
//!
//! Helpers retain exact request and device evidence; this layer owns no hidden
//! phase state. Live address verification remains explicit in the network policy.

mod access;
mod differential;
mod identity;
mod network;
mod outcomes;

pub(in crate::commissioning) use access::{
    operation_requires_installed_management_style, resolve_profile_authorization, validate_apdu_requirements,
    validate_credential_inputs, validate_options, validate_partial_management_style,
};

pub(in crate::commissioning) use identity::{unique_domain_target, unique_target};

pub(in crate::commissioning) use network::{
    open_medium_domain, programming_mode_scan, requested_topology_network_configuration,
    system_status_with_programming_mode, verify_programming_mode_address, verify_serial_address,
};

#[cfg(test)]
pub(in crate::commissioning) use network::verify_programming_mode_address_responses;

pub(in crate::commissioning) use differential::{
    differential_fallback, validate_differential_inputs, verified_undifferenced_fallback,
};

pub(in crate::commissioning) use outcomes::successful_section_outcomes;
