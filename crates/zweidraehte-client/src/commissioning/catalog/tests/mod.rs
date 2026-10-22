pub(super) use crate::commissioning::catalog_testing::*;
use std::num::NonZeroU16;

use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence, ProfileDisposition, ResourceManagementStyle};
use crate::commissioning::error::ProfileErrorKind;
use zweidraehte_ets_files::product::{ProductData, PropertyObject, PropertyParameterLocation};
use zweidraehte_ets_files::schema::{LdCtrlWriteProp, LoadControl, LoadProcedure};

mod fixtures;
mod loading;
mod properties;
mod selection;
mod stamps;
mod validation;

use fixtures::{
    AMBIGUOUS_0300, GLOBAL_PROPERTY_METADATA, RESOURCE_SELECTION, TOPOLOGY_DEPENDENT_PROFILE, cached_master_data,
    coupler_catalog, product, resolve_location_cases, resolve_resource_selection, unauditable_catalog,
};
