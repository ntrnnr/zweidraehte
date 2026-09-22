//! Resolve facts which describe a target's table realization.
//!
//! System B's generic Master Data association flavour does not say whether
//! TSAP/ASAP fields occupy one or two octets. PID_TABLE's property description
//! is the device's authoritative declaration; the current project cannot infer it.

use crate::bus::DeviceConnection;
use crate::commissioning::Diagnostic;
use crate::commissioning::catalog::profile::{
    AssociationTableEntrySize, ImageRequirement, ObjectSelector, ResolvedProfile,
};
use crate::commissioning::error::DiagnosticResult as Result;
use zweidraehte_proto::dpt::{PDT_Generic02, PDT_Generic04, PropertyDataDefinition};
use zweidraehte_proto::pid;

pub(crate) async fn observe_association_table_entry_size(
    connection: &mut DeviceConnection,
    profile: &ResolvedProfile,
) -> Result<Option<AssociationTableEntrySize>> {
    let requirements = profile.image_requirements().map_err(|error| Diagnostic::preparation(error.to_string()))?;
    let resources = requirements
        .iter()
        .filter_map(|requirement| match requirement {
            ImageRequirement::AssociationTableEntrySize { resource } => Some(resource),
            ImageRequirement::DataSecurityMode => None,
        })
        .collect::<Vec<_>>();
    let resource = match resources.as_slice() {
        [] => return Ok(None),
        [resource] => profile
            .resource_by_id(resource)
            .map_err(|error| Diagnostic::preparation(error.to_string()))?
            .expect("requirement belongs to profile"),
        _ => return Err(Diagnostic::preparation("association-table realization is ambiguous")),
    };
    let selector =
        resource.object_selector().map_err(|error| Diagnostic::preparation(error.to_string()))?.ok_or_else(|| {
            Diagnostic::preparation(format!(
                "association-table resource {} has no interface-object selector",
                resource.id
            ))
        })?;
    let index = object_index(connection, &selector).await?;
    let description = connection
        .property_description_read(index, pid::TABLE, 0)
        .await
        .map_err(|error| Diagnostic::from(error).preparation_context("read association-table property description"))?;
    if description.prop_id != pid::TABLE {
        return Err(Diagnostic::preparation("association-table description identifies a different property"));
    }
    let size = match description.pdt {
        PDT_Generic02::ID => AssociationTableEntrySize::TwoBytes,
        PDT_Generic04::ID => AssociationTableEntrySize::FourBytes,
        pdt => {
            return Err(Diagnostic::preparation(format!(
                "association-table property declares unsupported PDT {pdt:#04x}"
            )));
        }
    };
    Ok(Some(size))
}

async fn object_index(connection: &mut DeviceConnection, selector: &ObjectSelector) -> Result<u8> {
    let ObjectSelector::Type { object_type, occurrence } = selector else {
        let ObjectSelector::Index { index } = selector else { unreachable!() };
        return u8::try_from(*index)
            .map_err(|_| Diagnostic::preparation("association object index exceeds classic property addressing"));
    };

    // Property descriptions use indexed addressing. Resolve type selectors
    // against the observed object list, preserving their zero-based occurrence.
    let count = connection
        .property_read(0, pid::device::IO_LIST, 0, 1)
        .await
        .map_err(|error| Diagnostic::from(error).preparation_context("read interface-object list count"))?;
    let count = u16::from_be_bytes(
        count.try_into().map_err(|_| Diagnostic::preparation("interface-object list count is not two octets"))?,
    );
    if count > u16::from(u8::MAX) + 1 {
        return Err(Diagnostic::preparation("interface-object list exceeds classic property addressing"));
    }
    let mut matching = 0;
    for index in 0..count {
        let value = connection.property_read(0, pid::device::IO_LIST, index + 1, 1).await.map_err(|error| {
            Diagnostic::from(error).preparation_context(format!("read interface-object list entry {index}"))
        })?;
        let value = u16::from_be_bytes(
            value.try_into().map_err(|_| Diagnostic::preparation("interface-object type is not two octets"))?,
        );
        if value == *object_type {
            if matching == occurrence.value().unwrap_or(0) {
                return Ok(index as u8);
            }
            matching += 1;
        }
    }
    Err(Diagnostic::preparation(format!("target interface-object list does not contain {selector:?}")))
}
