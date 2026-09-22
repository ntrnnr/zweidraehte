//! Fixed rules for the management realizations described by Master Data.

pub(crate) mod ip;
mod stamps;
pub(crate) use stamps::resolved_download_stamp_output;
pub(crate) mod lifecycle;

pub(crate) use stamps::resolved_download_stamp_resources;

use crate::commissioning::catalog::profile::{ManagementModel, ResolvedProfile, ResourceManagementStyle};
use crate::commissioning::error::CompileError;
use crate::commissioning::procedure::RestartKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigurationAnchorPolicy {
    SessionClose,
    AfterRoutingTableLoad,
}

impl ResolvedProfile {
    pub(crate) fn configuration_anchor(&self) -> ConfigurationAnchorPolicy {
        if self.management_model == ManagementModel::System7 && self.mask.dd0 == 0x5705 {
            ConfigurationAnchorPolicy::AfterRoutingTableLoad
        } else {
            ConfigurationAnchorPolicy::SessionClose
        }
    }
}

impl ResolvedProfile {
    pub(crate) fn retain_final_disconnect(&self) -> bool {
        self.management_model == ManagementModel::SystemB
    }
}

impl ResolvedProfile {
    pub(crate) fn network_restart_kind(
        &self,
        style: ResourceManagementStyle,
        supports_data_secure: bool,
    ) -> RestartKind {
        if style == ResourceManagementStyle::LoadStateMachine
            && (self.management_model == ManagementModel::SystemB || supports_data_secure)
        {
            RestartKind::Confirmed
        } else {
            RestartKind::Basic
        }
    }
}

impl ResolvedProfile {
    pub(crate) fn program_restart_kind(
        &self,
        downloads_application: bool,
        management_secure: bool,
        target: RestartKind,
    ) -> RestartKind {
        if self.management_model == ManagementModel::SystemB && downloads_application && !management_secure {
            RestartKind::Basic
        } else {
            target
        }
    }
}

impl ResolvedProfile {
    pub(crate) fn supports_full_image_stamp_coverage(&self) -> Result<bool, CompileError> {
        // Flavour 1 stamps cover restricted ranges, so equality does not establish
        // that every byte from the previous desired image remains resident.
        Ok(self.management_model != ManagementModel::SystemB || self.feature("DownloadStamp")? != Some(1))
    }
}

impl ResolvedProfile {
    pub(crate) fn validate_programming(&self) -> Result<(), CompileError> {
        if self.management_model == ManagementModel::None {
            Err(CompileError::unsupported("this profile has no programming management model"))
        } else {
            Ok(())
        }
    }
}

use crate::commissioning::catalog::SelectedResource;
use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence};
use crate::commissioning::image::{ImageLocation, ImageSpace};
use zweidraehte_ets_files::product::{ProductData, PropertyObject, Segment};

pub(crate) fn product_property_object(object: PropertyObject) -> ObjectSelector {
    match object {
        PropertyObject::Index(index) => ObjectSelector::Index { index: u16::from(index) },
        PropertyObject::Type { object_type, occurrence } => ObjectSelector::Type {
            object_type: u16::from(object_type),
            occurrence: Occurrence::from_option(Some(occurrence)),
        },
    }
}

pub(crate) fn product_segment(product: &ProductData, segment: &Segment) -> Result<ImageLocation, CompileError> {
    if let Some(address) = segment.address {
        return Ok(ImageLocation {
            space: if segment.user_memory == Some(true) { ImageSpace::UserMemory } else { ImageSpace::StandardMemory },
            offset: address,
        });
    }

    let machine = segment.load_state_machine.ok_or_else(|| {
        CompileError::invalid(format!(
            "product segment {0:?} has neither an absolute address nor a load-state machine",
            segment.id.clone()
        ))
    })?;
    let offset = product.relative_segment_offset(&segment.id).ok_or_else(|| {
        CompileError::invalid(format!("relative product segment {0:?} has no allocation offset", segment.id.clone()))
    })?;

    Ok(ImageLocation {
        space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: u16::from(machine) } },
        offset,
    })
}

pub(crate) fn resource(resource: &SelectedResource<'_>) -> Result<ImageLocation, CompileError> {
    resource.image_location()?.ok_or_else(|| {
        CompileError::invalid(format!(
            "resource {0:?} does not have a writable image location",
            resource.name().to_owned()
        ))
    })
}
