//! Commissioning policy for which Master Data documents the compiler accepts.
//!
//! Acquisition itself belongs to `zweidraehte_ets_files::master_data`: callers
//! load documents with [`MasterDataLoadRequest`] and bind them to products.
//! This layer only decides whether a document it is handed can be compiled
//! against, and fails at resolution or live preparation rather than at load.
//!
//! [`MasterDataLoadRequest`]: zweidraehte_ets_files::master_data::MasterDataLoadRequest

use super::CompileError;
use std::sync::Arc;
use zweidraehte_ets_files::MasterData;
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_ets_files::schema::KnxSchemaVersion;
use zweidraehte_ets_files::schema::master_data::MaskVersion;

const LATEST_SCHEMA: u16 = KnxSchemaVersion::LATEST.as_u16();

pub(super) fn supported_master_data_schema(version: u16) -> Result<(), CompileError> {
    match version {
        10..=LATEST_SCHEMA => Ok(()),
        version => Err(CompileError::unsupported(format!(
            "Master Data uses unsupported project schema {version}; live commissioning supports project-10 through project-23"
        ))),
    }
}

/// The product's bound document. This never performs I/O.
pub(crate) fn bound_master_data(product: &ProductData) -> Result<&Arc<MasterData>, CompileError> {
    product.master_data().ok_or_else(|| {
        CompileError::missing_evidence(format!(
            "product `{}` has no selected Master Data; select its installation catalog before compilation",
            product.id()
        ))
    })
}

pub(super) fn validate_mask_tokens(mask: &MaskVersion) -> Result<(), CompileError> {
    for medium in [mask.medium_type_ref_id.as_deref(), mask.other_medium_type_ref_id.as_deref()].into_iter().flatten() {
        if !matches!(medium, "MT-0" | "MT-1" | "MT-2" | "MT-5" | "MT-6") {
            return Err(CompileError::unsupported(format!("unknown Master Data medium type {medium:?}")));
        }
    }
    Ok(())
}

/// Live preparation is the mutation boundary. Offline resolution tolerates an
/// unversioned document for inspection; a device is only written from a
/// document that names a supported project schema.
pub(crate) fn validate_for_live_commissioning(master_data: &MasterData) -> Result<(), CompileError> {
    let version =
        master_data.schema_version().ok_or_else(|| CompileError::missing_evidence(format!(
            "Master Data has no unambiguous project-schema namespace ({:?}); live commissioning requires a versioned project-10 through project-23 catalog", master_data.namespace()
        )))?;
    supported_master_data_schema(version)
}
