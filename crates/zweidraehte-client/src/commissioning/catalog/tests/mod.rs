use std::num::NonZeroU16;

use zweidraehte_ets_files::product::{ProductData, PropertyObject, PropertyParameterLocation};
use zweidraehte_ets_files::schema::{LdCtrlWriteProp, LoadControl, LoadProcedure};

use super::{ProgrammingCatalog, ProgrammingCatalogLoadRequest, ProgrammingCatalogSource};
use crate::commissioning::catalog::profile::{
    ObjectSelector, Occurrence, ProfileDiscovery, ProfileDisposition, ProfileRequest, ResourceManagementStyle,
    VariantHint,
};
use crate::commissioning::error::CompileErrorKind;

mod fixtures;
mod loading;
mod properties;
mod selection;
mod stamps;
mod validation;

use fixtures::{
    AMBIGUOUS_0300, GLOBAL_PROPERTY_METADATA, RESOURCE_SELECTION, TOPOLOGY_DEPENDENT_PROFILE, cached_master_data,
    coupler_catalog, product, product_with_schema, resolve_location_cases, resolve_resource_selection,
    unauditable_catalog,
};
