//! Construct secure routing, tunnelling, and management contributions.

use super::KEY_LENGTH;
use crate::commissioning::compiler::ProgramCompiler;
use crate::commissioning::error::{CompileError, OverflowedTable};

use super::property_target;
use crate::commissioning::compiler::credentials::{CredentialEffects, CredentialTransition};
use crate::commissioning::procedure::operands::FUNCTION_PROPERTY_NOT_SUPPORTED_ERROR;
use crate::commissioning::procedure::{
    FunctionPropertyOperation, OperationData, OperationExtent, ProcedureOperation, WritePolicy,
};
use crate::configuration::ResolvedIpSecureConfiguration;
use crate::configuration::ToolManagedIpConfiguration;
use std::collections::{BTreeMap, BTreeSet};
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_ets_files::schema::BusAccessType;
use zweidraehte_project::IpServiceSecurity;
use zweidraehte_proto::pid;
use zweidraehte_util::secret::SecretBytes;

impl ProgramCompiler<'_> {
    pub(in crate::commissioning::compiler) fn compile_ip_secure(
        &mut self,
        intent: &ToolManagedIpConfiguration,
    ) -> Result<(), CompileError> {
        let input = self.input;
        let product = input.device.product();
        let secrets = input.device.key_material().ip_secure();
        let security = intent
            .security
            .as_ref()
            .ok_or(CompileError::invalid("secure IP product has no public IP security intent"))?;
        validate_secure_intent(product, intent, security)?;

        let needs_private_material = security.routing == IpServiceSecurity::Secure
            || security.device_management == IpServiceSecurity::Secure
            || security.tunnelling == IpServiceSecurity::Secure;
        let resolved = if needs_private_material {
            let resolved = secrets
                .ok_or(CompileError::missing_evidence("IP Secure preparation has no resolved private credentials"))?;
            Some(resolved)
        } else {
            None
        };
        let mut credentials_written = false;

        // Service family order is normative: routing, device management, then
        // tunneling. Plain versions temporarily suppress the one defined
        // "function not supported" result and restore the exact mapping after the
        // call; no global error policy leaks into the following family.
        if security.routing == IpServiceSecurity::Secure {
            let key =
                credential_bytes(resolved.and_then(|resolved| resolved.backbone_key.as_ref()), "IP backbone key")?;
            self.add_credential_property_write(
                pid::ip::BACKBONE_KEY,
                key,
                1,
                CredentialEffects::transitions(vec![CredentialTransition::IpBackboneKey]),
            )?;
            self.add_image_property_write_secure(
                pid::ip::MULTICAST_LATENCY_TOLERANCE,
                security.multicast_latency_tolerance_ms.to_be_bytes().to_vec(),
                1,
            )?;
            self.add_image_property_write_secure(
                pid::ip::SYNC_LATENCY_FRACTION,
                vec![security.sync_latency_fraction],
                1,
            )?;
        }
        self.add_service_family(5, security.routing);

        if security.device_management == IpServiceSecurity::Secure {
            self.add_management_credentials(
                intent,
                resolved.expect("secure device management validated resolved credentials"),
            )?;
            credentials_written = true;
        }
        self.add_service_family(3, security.device_management);

        if security.tunnelling == IpServiceSecurity::Secure {
            if !credentials_written {
                self.add_management_credentials(
                    intent,
                    resolved.expect("secure tunnelling validated resolved credentials"),
                )?;
            }
            self.add_tunnelling_bindings(security)?;
        }
        self.add_service_family(4, security.tunnelling);

        Ok(())
    }
}

impl ProgramCompiler<'_> {
    pub(in crate::commissioning::compiler) fn add_management_credentials(
        &mut self,
        intent: &ToolManagedIpConfiguration,
        resolved: &ResolvedIpSecureConfiguration,
    ) -> Result<(), CompileError> {
        let authentication =
            credential_bytes(resolved.device_authentication_code.as_ref(), "IP device authentication code")?;
        self.add_credential_property_write(
            pid::ip::DEVICE_AUTHENTICATION_CODE,
            authentication,
            1,
            CredentialEffects::transitions(vec![CredentialTransition::IpDeviceAuthenticationCode]),
        )?;

        let count = u16::try_from(intent.password_users.len()).expect("password count validated");
        self.recipes.before_close(true, ProcedureOperation::Write {
            target: property_target(pid::ip::PASSWORD_HASHES, 0),
            data: OperationData::Inline(count.to_be_bytes().to_vec()),
            extent: OperationExtent::property(2, 1),
            // Verified like every other KNXnet/IP Secure property write.
            policy: crate::commissioning::procedure::WriteIntent::Explicit(WritePolicy::ReadBack),
        });

        if !intent.password_users.is_empty() {
            let mut hashes = Vec::with_capacity(intent.password_users.len() * KEY_LENGTH);
            let mut transitions = Vec::with_capacity(intent.password_users.len());
            // Validate while binding the ordered table. Collecting straight into a
            // map would silently accept conflicting credentials for the same user.
            let mut resolved_by_user = BTreeMap::new();
            for (user_id, hash) in &resolved.password_hashes {
                if resolved_by_user.insert(*user_id, hash).is_some() {
                    return Err(CompileError::invalid(format!(
                        "IP Secure preparation repeats password hash for user {user_id}"
                    )));
                }
            }
            if resolved_by_user.keys().ne(intent.password_users.iter()) {
                return Err(CompileError::invalid(format!(
                    "resolved password users {:?} do not match requested users {:?}",
                    resolved_by_user.keys().collect::<Vec<_>>(),
                    intent.password_users
                )));
            }
            for (user_id, hash) in resolved_by_user {
                require_secret_length(hash, "IP password hash")?;
                hashes.extend_from_slice(hash.as_slice());
                transitions.push(CredentialTransition::IpPasswordHash { user_id });
            }

            self.add_credential_property_write(
                pid::ip::PASSWORD_HASHES,
                hashes,
                count,
                CredentialEffects::transitions(transitions),
            )?;
        }

        Ok(())
    }
}

impl ProgramCompiler<'_> {
    pub(in crate::commissioning::compiler) fn add_tunnelling_bindings(
        &mut self,
        security: &zweidraehte_project::IpSecurityIntent,
    ) -> Result<(), CompileError> {
        let count = u16::try_from(security.tunnelling_users.len()).map_err(|_| {
            CompileError::invalid(format!(
                "tunnelling binding count {0} cannot be represented by the property service",
                security.tunnelling_users.len()
            ))
        })?;
        self.recipes.before_close(true, ProcedureOperation::Write {
            target: property_target(pid::ip::TUNNELING_USERS, 0),
            data: OperationData::Inline(count.to_be_bytes().to_vec()),
            extent: OperationExtent::property(2, 1),
            // Verified like every other KNXnet/IP Secure property write.
            policy: crate::commissioning::procedure::WriteIntent::Explicit(WritePolicy::ReadBack),
        });

        if count == 0 {
            return Ok(());
        }

        let mut data = Vec::with_capacity(usize::from(count) * 2);
        for binding in &security.tunnelling_users {
            data.extend_from_slice(&[binding.user_id.get(), binding.address_index]);
        }
        self.add_image_property_write_secure(pid::ip::TUNNELING_USERS, data, count)
    }
}

impl ProgramCompiler<'_> {
    pub(in crate::commissioning::compiler) fn add_service_family(&mut self, family: u8, security: IpServiceSecurity) {
        let version = u8::from(security == IpServiceSecurity::Secure);
        if security == IpServiceSecurity::Plain {
            self.recipes.before_close(true, ProcedureOperation::MapError {
                filter: None,
                original: FUNCTION_PROPERTY_NOT_SUPPORTED_ERROR,
                mapped: 0,
            });
        }

        self.recipes.before_close(
            true,
            ProcedureOperation::FunctionProperty(FunctionPropertyOperation::Invoke {
                address: crate::commissioning::procedure::operands::pure_property_address(
                    &super::IP_OBJECT,
                    pid::ip::SECURED_SERVICE_FAMILIES,
                )
                .expect("builtin property selector"),
                data: vec![0, 0, family, version],
                // The command carries its payload inline and discards the
                // response, so it changes no image bytes or ownership, like an
                // authored inline `LdCtrlInvokeFunctionProp`. Only the
                // service family's protection changes, which no image tracks.
                effect: crate::commissioning::procedure::LoadEffect::None,
            }),
        );

        if security == IpServiceSecurity::Plain {
            self.recipes.before_close(true, ProcedureOperation::MapError {
                filter: None,
                original: FUNCTION_PROPERTY_NOT_SUPPORTED_ERROR,
                mapped: FUNCTION_PROPERTY_NOT_SUPPORTED_ERROR,
            });
        }
    }
}

pub(super) fn credential_bytes(value: Option<&SecretBytes>, name: &'static str) -> Result<Vec<u8>, CompileError> {
    let value = value.ok_or(CompileError::missing_evidence(format!("IP Secure preparation is missing {name}")))?;
    require_secret_length(value, name)?;
    Ok(value.as_slice().to_vec())
}

pub(super) fn require_secret_length(value: &SecretBytes, name: &'static str) -> Result<(), CompileError> {
    if value.len() == KEY_LENGTH {
        Ok(())
    } else {
        Err(CompileError::invalid(format!("{name} has {} bytes, expected {KEY_LENGTH}", value.len())))
    }
}

pub(super) fn validate_secure_intent(
    product: &ProductData,
    intent: &ToolManagedIpConfiguration,
    security: &zweidraehte_project::IpSecurityIntent,
) -> Result<(), CompileError> {
    if intent.password_users.len() > usize::from(u8::MAX) {
        return Err(CompileError::invalid(format!(
            "password user count {0} cannot be represented by the property service",
            intent.password_users.len()
        )));
    }
    if intent.password_users.iter().map(|user| usize::from(user.get())).ne(1..=intent.password_users.len()) {
        return Err(CompileError::invalid(format!(
            "password users must be the dense sequence 1..N, got {0:?}",
            intent.password_users.clone()
        )));
    }
    let user_capacity = product.programming_options().max_user_entries().value;
    if intent.password_users.len() > usize::from(user_capacity) {
        return Err(CompileError::table_overflow(
            OverflowedTable::IpPasswordUsers,
            format!(
                "configured {configured} password users, exceeding product capacity {capacity}",
                configured = intent.password_users.len(),
                capacity = user_capacity
            ),
        ));
    }

    let needs_credentials =
        security.device_management == IpServiceSecurity::Secure || security.tunnelling == IpServiceSecurity::Secure;
    if needs_credentials && intent.password_users.is_empty() {
        return Err(CompileError::invalid(
            "secure device-management or tunnelling requires at least one password user",
        ));
    }
    if !needs_credentials && !intent.password_users.is_empty() {
        return Err(CompileError::invalid(
            "password users were supplied although device-management and tunnelling are both plain",
        ));
    }

    let binding_capacity = product.programming_options().max_tunneling_user_entries().value;
    if security.tunnelling_users.len() > usize::from(binding_capacity) {
        return Err(CompileError::table_overflow(
            OverflowedTable::IpTunnellingUsers,
            format!(
                "configured {configured} tunnelling bindings, exceeding product capacity {capacity}",
                configured = security.tunnelling_users.len(),
                capacity = binding_capacity
            ),
        ));
    }
    if security.tunnelling != IpServiceSecurity::Secure && !security.tunnelling_users.is_empty() {
        return Err(CompileError::invalid("tunnelling-user bindings were supplied while tunnelling is plain"));
    }
    if security.tunnelling == IpServiceSecurity::Secure && security.tunnelling_users.is_empty() {
        return Err(CompileError::invalid("secure tunnelling requires at least one user/address binding"));
    }

    let tunnelling_indices: BTreeSet<_> = product
        .bus_interfaces()
        .iter()
        .filter(|interface| interface.access_type == BusAccessType::Tunneling)
        .map(|interface| interface.address_index)
        .collect();
    // Secure routing deliberately does not require a declared Routing
    // BusInterface. Routing is a function of every KNXnet/IP device, and the
    // reference tool secures it from the project's backbone key alone; secure
    // IP archives commonly declare no BusInterfaces at all.

    let mut bound_users = BTreeSet::new();
    let mut bound_addresses = BTreeSet::new();
    for binding in &security.tunnelling_users {
        if usize::from(binding.user_id.get()) > intent.password_users.len() {
            return Err(CompileError::invalid(format!(
                "tunnelling binding refers to unknown password user {0}",
                binding.user_id
            )));
        }
        if !bound_users.insert(binding.user_id) {
            return Err(CompileError::invalid(format!(
                "tunnelling user {0} is bound to more than one address index",
                binding.user_id
            )));
        }
        if !bound_addresses.insert(binding.address_index) {
            return Err(CompileError::invalid(format!(
                "tunnelling address index {0} is bound to more than one user",
                binding.address_index
            )));
        }
        if !tunnelling_indices.contains(&binding.address_index) {
            return Err(CompileError::invalid(format!(
                "tunnelling binding refers to address index {0}, which is not a Tunneling BusInterface",
                binding.address_index
            )));
        }
        if usize::from(binding.address_index) > intent.additional_individual_addresses.len() {
            return Err(CompileError::invalid(format!(
                "tunnelling address index {0} has no configured additional individual address",
                binding.address_index
            )));
        }
    }

    Ok(())
}
