//! Emit Data Secure image bytes and controls for the selected group section.
//! Group keys are image content; their write names the keyed addresses.

use crate::commissioning::compiler::ProgramCompiler;
use crate::commissioning::compiler::credentials::CredentialEffects;
use crate::commissioning::compiler::image::tables::ObjectTable;
use crate::commissioning::error::{CompileError, OverflowedTable};
use crate::commissioning::input::ProgramSections;
use crate::commissioning::input::security::DesiredDataSecurity;

use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence, ResolvedProfile};
use crate::commissioning::image::{ImageLocation, ImageSegment, ImageSpace};
use crate::commissioning::procedure::{
    ErrorAction, ErrorHandler, LoadControlCause, OperationData, OperationExtent, OperationTarget, ProcedureOperation,
    WriteIntent,
};
use crate::configuration::{GroupObjectProtection, GroupObjectSecurity, MaterializedDevice};
use std::collections::BTreeSet;
use zweidraehte_ets_files::product::{ComObjectDef, ProductData};
use zweidraehte_project::ProgrammingSection;
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::messages::apdu::load_control::{LoadControlRecord, LoadEvent, LoadState};
use zweidraehte_proto::pid;
use zweidraehte_proto::security::{SEQ6_MAX, u64_to_seq6};
use zweidraehte_util::secret::SecretBytes;

// Master Data uses zero-based occurrences; OT17 occurrence zero binds to
// wire instance one for every Security IO table and load service.
const SECURITY_OBJECT: ObjectSelector = ObjectSelector::Type { object_type: 17, occurrence: Occurrence::Zero };

impl ProgramCompiler<'_> {
    pub(in crate::commissioning::compiler) fn contribute_data_secure(&mut self) -> Result<(), CompileError> {
        let input = self.input;
        if !self.feature_sections.contains(ProgramSections::GROUP_COMMUNICATION)
            || input.desired_data_security == DesiredDataSecurity::Preserve
        {
            return Ok(());
        }

        let profile = &self.profile;
        let product = input.device.product();
        let device = &input.device;
        let enabled = input.desired_data_security == DesiredDataSecurity::Enabled;
        if !enabled && input.device.key_material().application_security().is_some() {
            return Err(CompileError::invalid("Data Secure intent contradicts the supplied security configuration"));
        }
        if !product.supports_data_secure() {
            if enabled {
                return Err(CompileError::invalid(
                    "security configuration was supplied for a product without Data Secure support",
                ));
            }
            return Ok(());
        }

        // Disabling protection still owns the complete public group-flags
        // image: empty tables, and flags for every effective object. Enabling
        // fills the same tables from the explicit configuration. Management
        // credentials select the transfers, not the desired bytes.
        let (siat, group_keys, addresses, go_flags) = if enabled {
            let security = input.device.key_material().application_security().ok_or_else(|| {
                CompileError::invalid("enabling Data Secure requires explicit security configuration")
            })?;
            validate_product_capabilities(product, security.group_keys().len(), security.siat().len())?;
            let first_group_object = first_group_object_number(profile)?;
            let go_flags =
                encode_group_object_security(security.group_objects(), device.com_objects(), first_group_object)?;
            let siat = encode_siat(security.siat())?;
            let group_keys = encode_group_keys(device, security.group_keys())?;
            // Encoding orders rows by address-table position. Name the same
            // identities now so split writes never infer keys from bytes.
            let mut addresses: Vec<_> = security.group_keys().map(|(address, _)| address).collect();
            addresses.sort_unstable();
            if addresses.len().checked_mul(18) != Some(group_keys.len()) {
                return Err(CompileError::invalid("group-key identities do not match the encoded 18-byte rows"));
            }
            (siat, group_keys, addresses, go_flags)
        } else {
            // Products without group objects have no flags range and need
            // no Group Object Table realization merely to disable security.
            let go_flags = if device.com_objects().is_empty() {
                Vec::new()
            } else {
                encode_group_object_security(&[], device.com_objects(), first_group_object_number(profile)?)?
            };
            (Vec::new(), SecretBytes::from(Vec::new()), Vec::new(), go_flags)
        };

        if !enabled && !input.facts.target.is_some_and(|target| target.credential.is_secure()) {
            // Plaintext plans retain the public image while omitting
            // secure-only operations that their management cannot run.
            // Without a transfer, no section can confirm the flags; MDT's GTS
            // (M-0083_A-018C-23-81D7) kept Group communication unprogrammed
            // after every download. The bytes keep their mask for the image
            // but count toward no section digest.
            self.own_public_table(pid::security::GO_SECURITY_FLAGS, go_flags, 1)?;
            self.image.image.release_sections(
                &ImageSpace::Property { object: SECURITY_OBJECT, property_id: pid::security::GO_SECURITY_FLAGS },
                |_| true,
            );
            return Ok(());
        }

        // The reference download loads Security IO at its own source cursors,
        // captured before final source filtering: the unload after the last
        // authored unload, and the reload block before the first ordinary
        // LoadCompleted (else the last restart, erase-code-one master reset or
        // disconnect). Both enabling and disabling use the same block; only
        // the table contents differ.
        self.recipes.security_unload(security_load(LoadEvent::Unload, LoadState::Unloaded));
        self.recipes.security_reload(security_load(LoadEvent::StartLoading, LoadState::Loading), Vec::new());

        // 03/04/01 §§4.3.2.3 and 4.3.3.3 define element zero as the current
        // valid-element count. Clearing PID 54 before replacement ensures peers
        // removed from the project cannot retain a live receive-sequence row.
        // Without rows to write, a device lacking the table may answer the
        // reset with ResourceNotFound, which the reference download ignores.
        let reset_handlers = if siat.is_empty() {
            vec![ErrorHandler { cause: LoadControlCause::ResourceNotFound, action: ErrorAction::Ignore }]
        } else {
            Vec::new()
        };
        self.recipes.security_reload(
            ProcedureOperation::Write {
                target: property_target(pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 0),
                data: OperationData::Inline(vec![0, 0]),
                extent: OperationExtent::property(2, 1),
                policy: WriteIntent::Property { verify: true },
            },
            reset_handlers,
        );
        // TODO: Model zero-count table replacement before emitting its control.
        self.add_public_table(pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, siat, 8)?;

        // PID 53 normatively has a writable element-zero count as well. Some
        // classic devices reject the reset with E_DATA_OVERFLOW, while their
        // Security IO unload already invalidates the old table. Preserve that
        // established interoperable sequence: unload, then stream replacement
        // rows from element one without a separate element-zero write.
        if !group_keys.is_empty() {
            let (location, extent) = self
                .own_public_table(pid::security::GROUP_KEY_TABLE, group_keys.as_slice().to_vec(), 18)?
                .expect("a nonempty group-key table owns image bytes");
            self.recipes.security_reload(
                ProcedureOperation::Write {
                    target: property_target(pid::security::GROUP_KEY_TABLE, 1),
                    data: OperationData::Credential {
                        location,
                        length: extent.byte_length,
                        effects: CredentialEffects::group_keys(addresses),
                    },
                    extent,
                    policy: WriteIntent::Property { verify: true },
                },
                Vec::new(),
            );
        }

        // PID 61 has one fixed one-byte element per Group Object Table entry. It
        // is not resized through element zero; write the complete dense range.
        self.add_public_table(pid::security::GO_SECURITY_FLAGS, go_flags, 1)?;
        self.recipes.security_reload(security_load(LoadEvent::LoadCompleted, LoadState::Loaded), Vec::new());

        // Loading the tables does not itself change the device's Security
        // Mode. That transition belongs to the session before the download
        // (the network program), which reads the observed mode and switches
        // it only when it differs, exactly as the reference download does.
        Ok(())
    }
}

pub(super) fn validate_product_capabilities(
    product: &ProductData,
    group_keys: usize,
    siat: usize,
) -> Result<(), CompileError> {
    // An undeclared capacity is zero, as in the reference tool, which reports
    // either table's overflow as too many secure communication partners. It
    // checks the SIAT first.
    for (table, count, capacity) in [
        ("SIAT", siat, product.max_security_individual_address_entries()),
        ("group-key table", group_keys, product.max_security_group_key_table_entries()),
    ] {
        let capacity = capacity.unwrap_or(0);
        if count > usize::from(capacity) {
            return Err(CompileError::table_overflow(
                OverflowedTable::SecureCommunicationPartners,
                format!("{table} has {count} entries, exceeding the product capacity {capacity}"),
            ));
        }
    }

    Ok(())
}

pub(super) fn encode_group_keys<'a>(
    device: &MaterializedDevice,
    keys: impl ExactSizeIterator<Item = (GroupAddress, &'a [u8; 16])>,
) -> Result<SecretBytes, CompileError> {
    let mut group_addresses: Vec<_> = device.object_memberships().iter().map(|link| link.group_address).collect();
    group_addresses.sort_unstable();
    group_addresses.dedup();

    let mut rows = Vec::with_capacity(keys.len());
    for (address, key) in keys {
        let table_index = group_addresses
            .binary_search(&address)
            .map_err(|_| CompileError::invalid(format!("group key for {address} has no address-table entry")))?
            .checked_add(1)
            .ok_or(CompileError::invalid(format!(
                "{table} exceeds the representable property array size",
                table = "group address table"
            )))?;
        let table_index = u16::try_from(table_index).map_err(|_| {
            CompileError::invalid(format!(
                "{table} exceeds the representable property array size",
                table = "group address table"
            ))
        })?;

        rows.push((table_index, key));
    }

    rows.sort_unstable_by_key(|(index, _)| *index);
    if rows.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(CompileError::invalid("security configuration repeats a group key"));
    }

    let mut encoded = Vec::with_capacity(rows.len() * 18);
    for (index, key) in rows {
        encoded.extend_from_slice(&index.to_be_bytes());
        encoded.extend_from_slice(key);
    }

    Ok(encoded.into())
}

pub(super) fn encode_siat(
    rows: &[(zweidraehte_proto::address::IndividualAddress, u64)],
) -> Result<Vec<u8>, CompileError> {
    let mut rows = rows.to_vec();
    rows.sort_unstable_by_key(|(address, _)| *address);

    if rows.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(CompileError::invalid("security configuration repeats a SIAT address"));
    }
    if let Some((_, sequence)) = rows.iter().find(|(_, sequence)| *sequence > SEQ6_MAX) {
        return Err(CompileError::invalid(format!("SIAT sequence number {0} exceeds 48 bits", *sequence)));
    }

    let mut encoded = Vec::with_capacity(rows.len() * 8);
    for (address, sequence) in rows {
        encoded.extend_from_slice(address.as_bytes());
        encoded.extend_from_slice(&u64_to_seq6(sequence));
    }

    Ok(encoded)
}

pub(super) fn encode_group_object_security(
    configured: &[GroupObjectSecurity],
    effective_objects: &[ComObjectDef],
    first_group_object: u16,
) -> Result<Vec<u8>, CompileError> {
    // PID 61 follows the effective Group Object Table, including its internal
    // gaps. Later inactive declarations do not extend the security property.
    let Some(maximum) = effective_objects.iter().map(|object| object.number).max() else {
        return if configured.is_empty() {
            Ok(Vec::new())
        } else {
            Err(CompileError::invalid("security configuration names no declared group object"))
        };
    };
    if maximum < first_group_object {
        return Err(CompileError::invalid(format!(
            "group object {object} lies below this profile's first ASAP {first_group_object}",
            object = maximum
        )));
    }

    let mut flags = vec![0; usize::from(maximum - first_group_object) + 1];
    let mut seen = BTreeSet::new();

    for configured in configured {
        if !seen.insert(configured.com_object) {
            return Err(CompileError::invalid(format!(
                "security configuration repeats group object {0}",
                configured.com_object
            )));
        }
        if configured.com_object < first_group_object
            || !effective_objects.iter().any(|candidate| candidate.number == configured.com_object)
        {
            return Err(CompileError::invalid(format!(
                "GO security names object {0}, which is absent from the effective product",
                configured.com_object
            )));
        }

        flags[usize::from(configured.com_object - first_group_object)] = match configured.protection {
            GroupObjectProtection::Plain => 0,
            GroupObjectProtection::Authentication => 1,
            GroupObjectProtection::AuthenticationConfidentiality => 3,
        };
    }

    Ok(flags)
}

/// Derive the ASAP origin from the exact selected Group Object Table
/// realization. `FirstAppObjectIdx` identifies an interface-object index, not
/// a group-object number, so it is retained for diagnostics but never
/// misinterpreted as the PID 61 origin.
pub(super) fn first_group_object_number(profile: &ResolvedProfile) -> Result<u16, CompileError> {
    let first_application_object_index =
        profile.feature("FirstAppObjectIdx")?.and_then(|index| u16::try_from(index).ok());
    let resource = profile
        .resource("GroupObjectTable")?
        .ok_or(CompileError::invalid(format!("the exact profile has no GroupObjectTable flavour from which to derive the PID 61 origin; FirstAppObjectIdx is {first_application_object_index:?}")))?;
    let flavour = resource
        .flavour()?
        .ok_or(CompileError::invalid(format!("the exact profile has no GroupObjectTable flavour from which to derive the PID 61 origin; FirstAppObjectIdx is {first_application_object_index:?}")))?;
    ObjectTable::from_flavour(flavour).map(|codec| codec.first_object_number()).map_err(|_| {
        CompileError::invalid(format!(
            "unknown GroupObjectTable flavour {0:?} cannot define the PID 61 origin",
            flavour.as_str().to_owned()
        ))
    })
}

impl ProgramCompiler<'_> {
    pub(in crate::commissioning::compiler) fn add_public_table(
        &mut self,
        property_id: u16,
        data: Vec<u8>,
        element_width: usize,
    ) -> Result<(), CompileError> {
        let Some((location, extent)) = self.own_public_table(property_id, data, element_width)? else {
            return Ok(());
        };
        // The desired image is the sole owner of public table bytes. Controls keep
        // its address and extent, just as ordinary product transfers do.
        let operation = ProcedureOperation::Write {
            target: property_target(property_id, 1),
            data: OperationData::Image { location, length: extent.byte_length },
            extent,
            policy: WriteIntent::Property { verify: true },
        };
        self.recipes.security_reload(operation, Vec::new());
        Ok(())
    }

    fn own_public_table(
        &mut self,
        property_id: u16,
        data: Vec<u8>,
        element_width: usize,
    ) -> Result<Option<(ImageLocation, OperationExtent)>, CompileError> {
        if data.is_empty() {
            return Ok(None);
        }
        let elements = property_element_count(data.len(), element_width, "security property")?;
        let byte_length = u32::from(elements) * element_width as u32;
        let location =
            ImageLocation { space: ImageSpace::Property { object: SECURITY_OBJECT, property_id }, offset: 0 };
        self.image.add_section(ProgrammingSection::GroupCommunication, ImageSegment::owned(location.clone(), data)?);
        Ok(Some((location, OperationExtent::property(byte_length, elements))))
    }
}

pub(super) fn property_target(property_id: u16, start_element: u16) -> OperationTarget {
    crate::commissioning::procedure::operands::property_target(&SECURITY_OBJECT, property_id, start_element)
        .expect("builtin property selector fits service fields")
}

pub(super) fn property_element_count(
    byte_length: usize,
    element_size: usize,
    table: &'static str,
) -> Result<u16, CompileError> {
    if byte_length % element_size != 0 {
        return Err(CompileError::invalid(format!(
            "{table} has {byte_length} bytes, which is not a multiple of its {element_size}-byte element width"
        )));
    }

    u16::try_from(byte_length / element_size)
        .map_err(|_| CompileError::invalid(format!("{table} exceeds the representable property array size")))
}

fn security_load(event: LoadEvent, state: LoadState) -> ProcedureOperation {
    use crate::commissioning::procedure::{LoadRecord, ServiceRead};
    let target = property_target(5, 1);
    let bytes = LoadControlRecord::event(event).to_vec();
    ProcedureOperation::LoadRecord(LoadRecord {
        write: ServiceRead { target: target.clone(), extent: OperationExtent::property(bytes.len() as u32, 1) },
        bytes,
        poll: Some((ServiceRead { target, extent: OperationExtent::property(1, 1) }, state)),
        effect: if event == LoadEvent::Unload {
            crate::commissioning::procedure::LoadEffect::InvalidateAll
        } else {
            crate::commissioning::procedure::LoadEffect::None
        },
    })
}

#[cfg(test)]
mod tests;
