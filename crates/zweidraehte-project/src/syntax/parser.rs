//! Parser from the textual project language into the authored semantic model.
//!
//! The grammar establishes syntax; this lowering pass resolves declarations,
//! rejects duplicate identities, and attaches precise source spans used by
//! validation and editor diagnostics.

use std::collections::BTreeMap;
use std::num::NonZeroU8;
use std::path::PathBuf;

use pest::Parser as _;
use pest::error::{InputLocation, LineColLocation};
use pest::iterators::Pair;
use pest_derive::Parser;
use thiserror::Error;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use super::{AuthoredArea, AuthoredLine, AuthoredProject};
use crate::model::{
    CouplerRoutingPolicy, DataSecureMode, DomainAddress, ExternalSender, IpAssignment, IpDeviceConfiguration,
    IpLineConfiguration, IpSecurityIntent, IpServiceSecurity, IpTunnellingUserBinding, Medium, MembershipRole, Net,
    NetId, NetSecurityPolicy, ObjectFlagOverrides, ObjectMembership, ObjectPriority, ParamValue, ParameterAssignment,
    ProductReference, ProjectDevice, ProjectDeviceId, ProjectInstallationId, ProjectObjectConfiguration,
    ProjectPackageId, RfDeviceMode, SourceSpan,
};

#[derive(Parser)]
#[grammar = "syntax/project.pest"]
struct ProjectParser;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("{message} at {line}:{column}")]
pub struct ParseError {
    pub message: String,
    pub line: usize,
    pub column: usize,
    pub span: SourceSpan,
}

pub(crate) fn parse_project(source: String, project_path: Option<PathBuf>) -> Result<AuthoredProject, ParseError> {
    let mut parsed = ProjectParser::parse(Rule::project, &source).map_err(pest_error)?;
    let project = parsed.next().expect("successful parse yields the project rule");
    let mut group_addresses = BTreeMap::<NetId, (GroupAddress, SourceSpan)>::new();
    let mut raw_nets = BTreeMap::<NetId, RawNet>::new();
    let mut devices = BTreeMap::new();
    let mut external_senders = BTreeMap::new();
    let mut areas = Vec::new();
    let mut language = None;
    let mut language_decl_span = None;
    let mut language_value_span = None;

    for declaration in project.into_inner() {
        match declaration.as_rule() {
            Rule::language_decl => {
                let declaration_span = span(&declaration);
                let value = meaningful(declaration).next().expect("grammar supplies language");
                let value_span = span(&value);
                let value = unquote(value, &source)?;
                if value.is_empty() {
                    return Err(error_at(&source, value_span, "language cannot be empty"));
                }
                if language.replace(value).is_some() {
                    return Err(error_at(&source, declaration_span, "a project may only declare one language"));
                }
                language_decl_span = Some(declaration_span);
                language_value_span = Some(value_span);
            }
            Rule::ga_decl => {
                let (id, address, declaration_span) = parse_group_address_declaration(declaration, &source)?;
                if group_addresses.insert(id.clone(), (address, declaration_span)).is_some() {
                    return Err(error_at(
                        &source,
                        declaration_span,
                        format!("duplicate group address identifier `{id}`"),
                    ));
                }
            }
            Rule::net_decl => {
                let net = parse_net(declaration, &source)?;
                if raw_nets.insert(net.id.clone(), net.clone()).is_some() {
                    return Err(error_at(&source, net.span, format!("duplicate net identifier `{}`", net.id)));
                }
            }
            Rule::area_decl => {
                let parsed = parse_area(declaration, &source)?;
                for device in parsed.devices {
                    if devices.insert(device.id.clone(), device.clone()).is_some() {
                        return Err(error_at(
                            &source,
                            device.span,
                            format!("duplicate device identifier `{}`", device.id),
                        ));
                    }
                }
                areas.push(parsed.area);
            }
            Rule::external_sender_decl => {
                let sender = parse_external_sender(declaration, &source)?;
                if external_senders.insert(sender.id.clone(), sender.clone()).is_some() {
                    return Err(error_at(&source, sender.span, format!("duplicate external sender `{}`", sender.id)));
                }
            }
            Rule::EOI => {}
            rule => unreachable!("grammar yielded unexpected top-level rule {rule:?}"),
        }
    }

    let mut nets = BTreeMap::new();
    for (id, raw) in raw_nets {
        let Some((address, _)) = group_addresses.remove(&id) else {
            return Err(error_at(&source, raw.span, format!("net `{id}` has no matching `ga` declaration")));
        };
        nets.insert(id.clone(), Net {
            id,
            name: raw.name,
            address,
            dpt: raw.dpt,
            security: raw.security,
            security_span: raw.security_span,
            security_decl_span: raw.security_decl_span,
            name_span: raw.name_span,
            span: raw.span,
        });
    }
    if let Some((id, (_, declaration_span))) = group_addresses.into_iter().next() {
        return Err(error_at(
            &source,
            declaration_span,
            format!("group address `{id}` has no matching `net` declaration"),
        ));
    }

    Ok(AuthoredProject {
        source,
        project_path,
        language,
        language_decl_span,
        language_value_span,
        nets,
        devices,
        external_senders,
        areas,
    })
}

#[derive(Debug, Clone)]
struct RawNet {
    id: NetId,
    name: Option<String>,
    dpt: String,
    security: NetSecurityPolicy,
    security_span: SourceSpan,
    security_decl_span: SourceSpan,
    name_span: Option<SourceSpan>,
    span: SourceSpan,
}

fn parse_group_address_declaration(
    pair: Pair<'_, Rule>,
    source: &str,
) -> Result<(NetId, GroupAddress, SourceSpan), ParseError> {
    let declaration_span = span(&pair);
    let mut fields = meaningful(pair);
    let id = NetId(required_text(fields.next(), Rule::identifier));
    let address = parse_group_address(fields.next().expect("grammar supplies group address"), source)?;
    Ok((id, address, declaration_span))
}

fn parse_net(pair: Pair<'_, Rule>, source: &str) -> Result<RawNet, ParseError> {
    let declaration_span = span(&pair);
    let mut fields = meaningful(pair);
    let id = NetId(required_text(fields.next(), Rule::identifier));
    let dpt_pair = fields.next().expect("grammar supplies DPT");
    let dpt = canonical_dpt(dpt_pair.as_str(), span(&dpt_pair), source)?;
    let next = fields.next().expect("grammar supplies net contents");
    let (name, name_span, security) = if next.as_rule() == Rule::name_decl {
        let name_pair = meaningful(next).next().expect("grammar supplies net name");
        let name_span = span(&name_pair);
        let name = unquote(name_pair, source)?;
        (Some(name), Some(name_span), fields.next().expect("grammar supplies security declaration"))
    } else {
        (None, None, next)
    };
    let security_decl_span = span(&security);
    let policy_pair = meaningful(security).next().expect("grammar supplies security policy");
    let security_span = span(&policy_pair);
    let security = match policy_pair.as_str() {
        "plain" => NetSecurityPolicy::Plain,
        "automatic" => NetSecurityPolicy::Automatic,
        "authentication" => NetSecurityPolicy::Authentication,
        "authentication_confidentiality" => NetSecurityPolicy::AuthenticationConfidentiality,
        other => return Err(error_at(source, span(&policy_pair), format!("unknown security policy `{other}`"))),
    };
    Ok(RawNet { id, name, dpt, security, security_span, security_decl_span, name_span, span: declaration_span })
}

struct ParsedArea {
    area: AuthoredArea,
    devices: Vec<ProjectDevice>,
}

struct ParsedLine {
    line: AuthoredLine,
    devices: Vec<ProjectDevice>,
}

fn parse_area(pair: Pair<'_, Rule>, source: &str) -> Result<ParsedArea, ParseError> {
    let area_span = span(&pair);
    let mut fields = meaningful(pair);
    let area_pair = fields.next().expect("grammar supplies area number");
    let area = bounded_u8(&area_pair, 15, "area must be 0..15", source)?;
    let _area_name = fields.next().expect("grammar supplies area name");
    let mut devices = Vec::new();
    let mut lines = Vec::new();
    for line in fields {
        let parsed = parse_line(line, area, source)?;
        devices.extend(parsed.devices);
        lines.push(parsed.line);
    }
    Ok(ParsedArea { area: AuthoredArea { number: area, span: area_span, lines }, devices })
}

fn parse_line(pair: Pair<'_, Rule>, area: u8, source: &str) -> Result<ParsedLine, ParseError> {
    let line_span = span(&pair);
    let mut fields = meaningful(pair);
    let line_pair = fields.next().expect("grammar supplies line number");
    let line = bounded_u8(&line_pair, 15, "line must be 0..15", source)?;
    let _line_name = fields.next().expect("grammar supplies line name");
    let medium_decl = fields.next().expect("grammar supplies medium");
    let medium_pair = meaningful(medium_decl).next().expect("grammar supplies medium value");
    let medium = match medium_pair.as_str() {
        "tp1" => Medium::Tp1,
        "rf" => Medium::Rf,
        "ip" => Medium::Ip,
        other => return Err(error_at(source, span(&medium_pair), format!("unknown medium `{other}`"))),
    };

    let mut domain = None;
    let mut domain_span = None;
    let mut project_installation_id = None;
    let mut multicast_latency_tolerance_ms = None;
    let mut sync_latency_fraction = None;
    let mut devices = Vec::new();

    for field in fields {
        match field.as_rule() {
            Rule::domain_decl => {
                let value = meaningful(field).next().expect("grammar supplies domain address");
                let value_span = span(&value);
                let value = unquote(value, source)?;
                domain = Some(
                    parse_domain_address(&value, medium).map_err(|message| error_at(source, value_span, message))?,
                );
                domain_span = Some(value_span);
            }
            Rule::project_installation_id_decl => {
                let mut values = meaningful(field);
                let project = values.next().expect("grammar supplies project ID");
                let installation = values.next().expect("grammar supplies installation ID");
                let project = u16::try_from(parse_u64(&project, source)?)
                    .map_err(|_| error_at(source, span(&project), "project ID exceeds 4095"))?;
                let installation = u8::try_from(parse_u64(&installation, source)?)
                    .map_err(|_| error_at(source, span(&installation), "installation ID exceeds 15"))?;
                let value = ProjectInstallationId::new(project, installation).ok_or_else(|| {
                    error_at(
                        source,
                        line_span,
                        "project_installation_id must be project 0..4095 and installation 0..15",
                    )
                })?;
                if project_installation_id.replace(value).is_some() {
                    return Err(error_at(source, line_span, "a line may declare project_installation_id only once"));
                }
            }
            Rule::multicast_latency_tolerance_decl => {
                let value = meaningful(field).next().expect("grammar supplies multicast latency");
                let value = u16::try_from(parse_u64(&value, source)?)
                    .map_err(|_| error_at(source, span(&value), "multicast latency exceeds 65535 ms"))?;
                if multicast_latency_tolerance_ms.replace(value).is_some() {
                    return Err(error_at(source, line_span, "a line may declare multicast latency only once"));
                }
            }
            Rule::sync_latency_fraction_decl => {
                let value = meaningful(field).next().expect("grammar supplies sync latency fraction");
                let value = u8::try_from(parse_u64(&value, source)?)
                    .map_err(|_| error_at(source, span(&value), "sync latency fraction exceeds 255"))?;
                if sync_latency_fraction.replace(value).is_some() {
                    return Err(error_at(source, line_span, "a line may declare sync latency fraction only once"));
                }
            }
            Rule::device_decl => {
                let ip = project_installation_id.map(|project_installation_id| IpLineConfiguration {
                    project_installation_id,
                    multicast_latency_tolerance_ms,
                    sync_latency_fraction,
                });
                devices.push(parse_device(field, area, line, medium, ip, source)?);
            }
            rule => unreachable!("grammar yielded unexpected line rule {rule:?}"),
        }
    }

    let any_ip_field = project_installation_id.is_some()
        || multicast_latency_tolerance_ms.is_some()
        || sync_latency_fraction.is_some();
    let ip = match (medium, project_installation_id) {
        (Medium::Ip, Some(project_installation_id)) => {
            Some(IpLineConfiguration { project_installation_id, multicast_latency_tolerance_ms, sync_latency_fraction })
        }
        (Medium::Ip, None) => None,
        (_, _) if any_ip_field => {
            return Err(error_at(source, line_span, "only an IP line may declare IP installation values"));
        }
        _ => None,
    };

    Ok(ParsedLine { line: AuthoredLine { number: line, medium, domain, domain_span, ip, span: line_span }, devices })
}

fn parse_device(
    pair: Pair<'_, Rule>,
    area: u8,
    line: u8,
    medium: Medium,
    ip_line: Option<IpLineConfiguration>,
    source: &str,
) -> Result<ProjectDevice, ParseError> {
    let device_span = span(&pair);
    let mut fields = meaningful(pair);
    let id = ProjectDeviceId::new(required_text(fields.next(), Rule::identifier))
        .expect("the grammar's identifier rule is the device-id rule");
    let mut package = None;
    let mut catalog_item = None;
    let mut active = None;
    let mut address = None;
    let mut address_decl_span = None;
    let mut rf_mode = None;
    let mut rf_mode_span = None;
    let mut routing = None;
    let mut ip_assignment = None;
    let mut ip_address = None;
    let mut subnet_mask = None;
    let mut default_gateway = None;
    let mut multicast_ttl = None;
    let mut friendly_name = None;
    let mut additional_individual_addresses = Vec::new();
    let mut ip_routing = None;
    let mut ip_device_management = None;
    let mut ip_tunnelling = None;
    let mut ip_password_users = Vec::new();
    let mut ip_tunnelling_users = Vec::new();
    let mut serial = None;
    let mut serial_decl_span = None;
    let mut serial_value_span = None;
    let mut max_apdu = None;
    let mut data_secure = None;
    let mut parameters = Vec::new();
    let mut objects = BTreeMap::new();

    for item in fields {
        match item.as_rule() {
            Rule::product_decl => {
                let value = meaningful(item).next().expect("grammar supplies package ID");
                let value_span = span(&value);
                let value = unquote(value, source)?;
                let parsed = value
                    .parse::<ProjectPackageId>()
                    .map_err(|error| error_at(source, value_span, error.to_string()))?;
                if package.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may only declare one product"));
                }
            }
            Rule::catalog_item_decl => {
                let value = meaningful(item).next().expect("grammar supplies CatalogItem ID");
                let value_span = span(&value);
                let value = unquote(value, source)?;
                if value.is_empty() {
                    return Err(error_at(source, value_span, "CatalogItem ID cannot be empty"));
                }
                if catalog_item.replace(value).is_some() {
                    return Err(error_at(source, device_span, "a device may only declare one catalog_item"));
                }
            }
            Rule::active_decl => {
                let value = meaningful(item).next().expect("grammar supplies active state");
                let parsed = match value.as_str() {
                    "true" => true,
                    "false" => false,
                    other => {
                        return Err(error_at(
                            source,
                            span(&value),
                            format!("unknown active state `{other}`; expected `true` or `false`"),
                        ));
                    }
                };
                if active.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may only declare one active state"));
                }
            }
            Rule::address_decl => {
                let declaration_span = span(&item);
                let value = meaningful(item).next().expect("grammar supplies address");
                if address.replace(parse_individual_address(value, source)?).is_some() {
                    return Err(error_at(source, device_span, "a device may only declare one address"));
                }
                address_decl_span = Some(declaration_span);
            }
            Rule::rf_mode_decl => {
                let value = meaningful(item).next().expect("grammar supplies RF device mode");
                let value_span = span(&value);
                let parsed = match value.as_str() {
                    "ready" => RfDeviceMode::Ready,
                    "multi" => RfDeviceMode::Multi,
                    other => {
                        return Err(error_at(
                            source,
                            value_span,
                            format!("unknown RF device mode `{other}`; expected `ready` or `multi`"),
                        ));
                    }
                };
                if rf_mode.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may only declare one rf_mode"));
                }
                rf_mode_span = Some(value_span);
            }
            Rule::routing_decl => {
                let value = meaningful(item).next().expect("grammar supplies routing policy");
                let parsed = match value.as_str() {
                    "filter" => CouplerRoutingPolicy::Filter,
                    "route_all" => CouplerRoutingPolicy::RouteAll,
                    "block_all" => CouplerRoutingPolicy::BlockAll,
                    other => {
                        return Err(error_at(
                            source,
                            span(&value),
                            format!(
                                "unknown coupler routing policy `{other}`; expected `filter`, `route_all`, or `block_all`"
                            ),
                        ));
                    }
                };
                if routing.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may only declare one routing policy"));
                }
            }
            Rule::ip_assignment_decl => {
                let value = meaningful(item).next().expect("grammar supplies IP assignment method");
                let parsed = match value.as_str() {
                    "dhcp" => false,
                    "fixed" => true,
                    other => {
                        return Err(error_at(
                            source,
                            span(&value),
                            format!("unknown IP assignment `{other}`; expected `dhcp` or `fixed`"),
                        ));
                    }
                };
                if ip_assignment.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may declare ip_assignment only once"));
                }
            }
            Rule::ip_address_decl => {
                let value = meaningful(item).next().expect("grammar supplies IP address");
                let parsed =
                    parse_ipv4(&unquote(value, source)?).map_err(|message| error_at(source, device_span, message))?;
                if ip_address.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may declare ip_address only once"));
                }
            }
            Rule::subnet_mask_decl => {
                let value = meaningful(item).next().expect("grammar supplies subnet mask");
                let parsed =
                    parse_ipv4(&unquote(value, source)?).map_err(|message| error_at(source, device_span, message))?;
                if subnet_mask.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may declare subnet_mask only once"));
                }
            }
            Rule::default_gateway_decl => {
                let value = meaningful(item).next().expect("grammar supplies default gateway");
                let parsed =
                    parse_ipv4(&unquote(value, source)?).map_err(|message| error_at(source, device_span, message))?;
                if default_gateway.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may declare default_gateway only once"));
                }
            }
            Rule::multicast_ttl_decl => {
                let value = meaningful(item).next().expect("grammar supplies multicast TTL");
                let parsed = u8::try_from(parse_u64(&value, source)?)
                    .map_err(|_| error_at(source, span(&value), "multicast TTL exceeds 255"))?;
                if multicast_ttl.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may declare multicast_ttl only once"));
                }
            }
            Rule::friendly_name_decl => {
                let value = meaningful(item).next().expect("grammar supplies friendly name");
                let value_span = span(&value);
                let parsed = unquote(value, source)?;
                if parsed.chars().any(|character| u32::from(character) > u32::from(u8::MAX))
                    || parsed.chars().count() > 30
                {
                    return Err(error_at(source, value_span, "friendly_name must be at most 30 ISO-8859-1 octets"));
                }
                if friendly_name.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may declare friendly_name only once"));
                }
            }
            Rule::additional_address_decl => {
                let value = meaningful(item).next().expect("grammar supplies additional address");
                additional_individual_addresses.push(parse_individual_address(value, source)?);
            }
            Rule::ip_routing_decl => {
                parse_unique_ip_service(item, source, device_span, "ip_routing", &mut ip_routing)?;
            }
            Rule::ip_device_management_decl => {
                parse_unique_ip_service(item, source, device_span, "ip_device_management", &mut ip_device_management)?;
            }
            Rule::ip_tunnelling_decl => {
                parse_unique_ip_service(item, source, device_span, "ip_tunnelling", &mut ip_tunnelling)?;
            }
            Rule::ip_password_user_decl => {
                let value = meaningful(item).next().expect("grammar supplies IP password user");
                let value_span = span(&value);
                let value = u8::try_from(parse_u64(&value, source)?)
                    .map_err(|_| error_at(source, value_span, "IP user ID exceeds 255"))?;
                let value =
                    NonZeroU8::new(value).ok_or_else(|| error_at(source, value_span, "IP user ID zero is reserved"))?;
                ip_password_users.push(value);
            }
            Rule::ip_tunnelling_user_decl => {
                let mut values = meaningful(item);
                let user = values.next().expect("grammar supplies tunnelling user ID");
                let index = values.next().expect("grammar supplies tunnelling address index");
                let user_value = u8::try_from(parse_u64(&user, source)?)
                    .map_err(|_| error_at(source, span(&user), "IP user ID exceeds 255"))?;
                let user_id = NonZeroU8::new(user_value)
                    .ok_or_else(|| error_at(source, span(&user), "IP user ID zero is reserved"))?;
                let address_index = u8::try_from(parse_u64(&index, source)?)
                    .map_err(|_| error_at(source, span(&index), "tunnelling address index exceeds 255"))?;
                ip_tunnelling_users.push(IpTunnellingUserBinding { user_id, address_index });
            }
            Rule::serial_decl => {
                let declaration_span = span(&item);
                let value = meaningful(item).next().expect("grammar supplies serial");
                let value_span = span(&value);
                let value = unquote(value, source)?;
                let parsed = parse_serial(&value).map_err(|message| error_at(source, value_span, message))?;
                if serial.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may only declare one serial"));
                }
                serial_decl_span = Some(declaration_span);
                serial_value_span = Some(value_span);
            }
            Rule::max_apdu_decl => {
                let value = meaningful(item).next().expect("grammar supplies APDU size");
                let parsed = u16::try_from(parse_u64(&value, source)?)
                    .map_err(|_| error_at(source, span(&value), "APDU size exceeds 65535"))?;
                if max_apdu.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may only declare one max_apdu"));
                }
            }
            Rule::data_secure_decl => {
                let value = meaningful(item).next().expect("grammar supplies Data Secure mode");
                let parsed = match value.as_str() {
                    "enabled" => DataSecureMode::Enabled,
                    "disabled" => DataSecureMode::Disabled,
                    other => {
                        return Err(error_at(
                            source,
                            span(&value),
                            format!("unknown Data Secure mode `{other}`; expected `enabled` or `disabled`"),
                        ));
                    }
                };
                if data_secure.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may only declare one data_secure mode"));
                }
            }
            Rule::parameter_decl => parameters.push(parse_parameter(item, source)?),
            Rule::object_decl => {
                let object = parse_object(item, source)?;
                if objects.insert(object.com_object, object.clone()).is_some() {
                    return Err(error_at(source, object.span, format!("duplicate object {}", object.com_object)));
                }
            }
            rule => unreachable!("grammar yielded unexpected device rule {rule:?}"),
        }
    }

    let package = package.ok_or_else(|| error_at(source, device_span, "device is missing its `product`"))?;
    let catalog_item =
        catalog_item.ok_or_else(|| error_at(source, device_span, "device is missing its `catalog_item`"))?;
    let product = ProductReference::Package { package, catalog_item };
    let address = address.ok_or_else(|| error_at(source, device_span, "device is missing its `address`"))?;
    if address.area() != area || address.line() != line {
        return Err(error_at(
            source,
            device_span,
            format!("device address {address} does not belong to enclosing area {area}, line {line}"),
        ));
    }
    let any_ip_device_field = ip_assignment.is_some()
        || ip_address.is_some()
        || subnet_mask.is_some()
        || default_gateway.is_some()
        || multicast_ttl.is_some()
        || friendly_name.is_some()
        || !additional_individual_addresses.is_empty()
        || ip_routing.is_some()
        || ip_device_management.is_some()
        || ip_tunnelling.is_some()
        || !ip_password_users.is_empty()
        || !ip_tunnelling_users.is_empty();
    let ip = if any_ip_device_field {
        if medium != Medium::Ip {
            return Err(error_at(source, device_span, "only an IP device may declare IP configuration"));
        }
        let assignment = match ip_assignment {
            Some(false) if ip_address.is_none() && subnet_mask.is_none() && default_gateway.is_none() => {
                IpAssignment::AutomaticDhcp
            }
            Some(false) => {
                return Err(error_at(
                    source,
                    device_span,
                    "DHCP assignment must not declare ip_address, subnet_mask, or default_gateway",
                ));
            }
            Some(true) => IpAssignment::Fixed {
                address: ip_address
                    .ok_or_else(|| error_at(source, device_span, "fixed IP assignment needs ip_address"))?,
                subnet_mask: subnet_mask
                    .ok_or_else(|| error_at(source, device_span, "fixed IP assignment needs subnet_mask"))?,
                default_gateway: default_gateway
                    .ok_or_else(|| error_at(source, device_span, "fixed IP assignment needs default_gateway"))?,
            },
            None => return Err(error_at(source, device_span, "IP configuration needs ip_assignment")),
        };
        let security = match (ip_routing, ip_device_management, ip_tunnelling) {
            (None, None, None) if ip_password_users.is_empty() && ip_tunnelling_users.is_empty() => None,
            (Some(routing), Some(device_management), Some(tunnelling)) => {
                let line = ip_line.ok_or_else(|| {
                    error_at(source, device_span, "IP Secure configuration needs line project_installation_id")
                })?;
                Some(IpSecurityIntent {
                    routing,
                    device_management,
                    tunnelling,
                    multicast_latency_tolerance_ms: line.multicast_latency_tolerance_ms.ok_or_else(|| {
                        error_at(source, device_span, "IP Secure configuration needs multicast_latency_tolerance")
                    })?,
                    sync_latency_fraction: line.sync_latency_fraction.ok_or_else(|| {
                        error_at(source, device_span, "IP Secure configuration needs sync_latency_fraction")
                    })?,
                    tunnelling_users: ip_tunnelling_users,
                })
            }
            _ => {
                return Err(error_at(
                    source,
                    device_span,
                    "IP Secure configuration must declare ip_routing, ip_device_management, and ip_tunnelling",
                ));
            }
        };
        ip_password_users.sort_unstable();
        if ip_password_users.windows(2).any(|users| users[0] == users[1]) {
            return Err(error_at(source, device_span, "IP password user IDs must be unique"));
        }
        ip_password_users.dedup();
        Some(IpDeviceConfiguration {
            assignment,
            multicast_ttl: multicast_ttl
                .ok_or_else(|| error_at(source, device_span, "IP configuration needs multicast_ttl"))?,
            friendly_name: friendly_name
                .ok_or_else(|| error_at(source, device_span, "IP configuration needs friendly_name"))?,
            additional_individual_addresses,
            security,
            password_users: ip_password_users,
        })
    } else {
        None
    };
    Ok(ProjectDevice {
        id,
        name: None,
        active: active.unwrap_or(true),
        area,
        line,
        medium,
        product,
        address,
        rf_mode,
        ip,
        routing,
        serial,
        address_decl_span: address_decl_span.expect("a parsed device has an address declaration"),
        rf_mode_span,
        serial_decl_span,
        serial_value_span,
        max_apdu,
        data_secure: data_secure.unwrap_or_default(),
        parameters,
        objects,
        span: device_span,
    })
}

fn parse_parameter(pair: Pair<'_, Rule>, source: &str) -> Result<ParameterAssignment, ParseError> {
    let assignment_span = span(&pair);
    let mut fields = meaningful(pair);
    let id = unquote(fields.next().expect("grammar supplies parameter ID"), source)?;
    let value = fields.next().expect("grammar supplies parameter value");
    let value = match value.as_rule() {
        Rule::number if value.as_str().contains('.') => ParamValue::Float(
            value.as_str().parse().map_err(|_| error_at(source, span(&value), "invalid floating-point value"))?,
        ),
        Rule::number => ParamValue::Integer(
            value.as_str().parse().map_err(|_| error_at(source, span(&value), "integer is too large"))?,
        ),
        Rule::quoted_string => ParamValue::Text(unquote(value, source)?),
        rule => unreachable!("grammar yielded unexpected parameter value {rule:?}"),
    };
    Ok(ParameterAssignment { id, value, span: assignment_span })
}

fn parse_object(pair: Pair<'_, Rule>, source: &str) -> Result<ProjectObjectConfiguration, ParseError> {
    let object_span = span(&pair);
    let mut fields = meaningful(pair);
    let number = fields.next().expect("grammar supplies object number");
    let com_object = u16::try_from(parse_u64(&number, source)?)
        .map_err(|_| error_at(source, span(&number), "communication object number exceeds 65535"))?;
    let mut memberships = Vec::new();
    let mut flags = ObjectFlagOverrides::default();
    let mut saw_flags = false;
    for item in fields {
        match item.as_rule() {
            Rule::primary_membership | Rule::additional_membership => {
                let role = if item.as_rule() == Rule::primary_membership {
                    MembershipRole::Primary
                } else {
                    MembershipRole::Additional
                };
                let membership_span = span(&item);
                let net = NetId(required_text(meaningful(item).next(), Rule::identifier));
                memberships.push(ObjectMembership { net, role, span: membership_span });
            }
            Rule::flags_block if !saw_flags => {
                flags = parse_flags(item, source)?;
                saw_flags = true;
            }
            Rule::flags_block => return Err(error_at(source, span(&item), "an object may only have one flags block")),
            rule => unreachable!("grammar yielded unexpected object rule {rule:?}"),
        }
    }
    Ok(ProjectObjectConfiguration { com_object, memberships, flags, span: object_span })
}

fn parse_flags(pair: Pair<'_, Rule>, source: &str) -> Result<ObjectFlagOverrides, ParseError> {
    let mut flags = ObjectFlagOverrides::default();
    for entry in meaningful(pair) {
        let mut fields = entry.into_inner();
        let name = fields.next().expect("grammar supplies flag name");
        let value = fields.next().expect("grammar supplies flag value");
        if name.as_str() == "priority" {
            let priority = match value.as_str() {
                "system" => ObjectPriority::System,
                "high" => ObjectPriority::High,
                "alarm" | "alert" => ObjectPriority::Alarm,
                "low" => ObjectPriority::Low,
                other => return Err(error_at(source, span(&value), format!("unknown object priority `{other}`"))),
            };
            set_once(&mut flags.priority, priority, "priority", span(&name), source)?;
            continue;
        }
        let enabled = match value.as_str() {
            "true" => true,
            "false" => false,
            _ => return Err(error_at(source, span(&value), "flag values are `true` or `false`")),
        };
        let slot = match name.as_str() {
            "communication" => &mut flags.communication,
            "read" => &mut flags.read,
            "write" => &mut flags.write,
            "transmit" => &mut flags.transmit,
            "update" => &mut flags.update,
            "read_on_init" => &mut flags.read_on_init,
            other => return Err(error_at(source, span(&name), format!("unknown object flag `{other}`"))),
        };
        set_once(slot, enabled, name.as_str(), span(&name), source)?;
    }
    Ok(flags)
}

fn parse_external_sender(pair: Pair<'_, Rule>, source: &str) -> Result<ExternalSender, ParseError> {
    let sender_span = span(&pair);
    let mut fields = meaningful(pair);
    let id = required_text(fields.next(), Rule::identifier);
    let address_decl = fields.next().expect("grammar supplies external address");
    let address = parse_individual_address(
        meaningful(address_decl).next().expect("grammar supplies external address value"),
        source,
    )?;
    let mut data_secure = DataSecureMode::Disabled;
    let mut nets = Vec::new();
    for field in fields {
        match field.as_rule() {
            Rule::data_secure_decl => {
                let value = meaningful(field).next().expect("grammar supplies Data Secure mode");
                data_secure = match value.as_str() {
                    "enabled" => DataSecureMode::Enabled,
                    "disabled" => DataSecureMode::Disabled,
                    other => {
                        return Err(error_at(
                            source,
                            span(&value),
                            format!("unknown Data Secure mode `{other}`; expected `enabled` or `disabled`"),
                        ));
                    }
                };
            }
            Rule::primary_membership => {
                nets.push(NetId(required_text(meaningful(field).next(), Rule::identifier)));
            }
            rule => unreachable!("grammar yielded unexpected external-sender rule {rule:?}"),
        }
    }
    Ok(ExternalSender { id, address, data_secure, nets, span: sender_span })
}

fn meaningful(pair: Pair<'_, Rule>) -> impl Iterator<Item = Pair<'_, Rule>> {
    pair.into_inner().filter(|pair| !is_keyword(pair.as_rule()))
}

fn is_keyword(rule: Rule) -> bool {
    matches!(
        rule,
        Rule::kw_ga
            | Rule::kw_net
            | Rule::kw_name
            | Rule::kw_security
            | Rule::kw_area
            | Rule::kw_line
            | Rule::kw_medium
            | Rule::kw_domain
            | Rule::kw_project_installation_id
            | Rule::kw_multicast_latency_tolerance
            | Rule::kw_sync_latency_fraction
            | Rule::kw_rf_mode
            | Rule::kw_device
            | Rule::kw_product
            | Rule::kw_package
            | Rule::kw_catalog_item
            | Rule::kw_language
            | Rule::kw_active
            | Rule::kw_address
            | Rule::kw_routing
            | Rule::kw_ip_assignment
            | Rule::kw_ip_address
            | Rule::kw_subnet_mask
            | Rule::kw_default_gateway
            | Rule::kw_multicast_ttl
            | Rule::kw_friendly_name
            | Rule::kw_additional_address
            | Rule::kw_ip_routing
            | Rule::kw_ip_device_management
            | Rule::kw_ip_tunnelling
            | Rule::kw_ip_password_user
            | Rule::kw_ip_tunnelling_user
            | Rule::kw_serial
            | Rule::kw_max_apdu
            | Rule::kw_data_secure
            | Rule::kw_param
            | Rule::kw_object
            | Rule::kw_on
            | Rule::kw_also
            | Rule::kw_flags
            | Rule::kw_external_sender
    )
}

fn required_text(pair: Option<Pair<'_, Rule>>, expected: Rule) -> String {
    let pair = pair.expect("grammar supplies required field");
    debug_assert_eq!(pair.as_rule(), expected);
    pair.as_str().to_string()
}

fn canonical_dpt(value: &str, value_span: SourceSpan, source: &str) -> Result<String, ParseError> {
    let (main, sub) = value.split_once('.').expect("DPT grammar supplies a dot");
    let main: u16 = main.parse().map_err(|_| error_at(source, value_span, "DPT main number is too large"))?;
    let sub: u16 = sub.parse().expect("DPT subtype is at most three digits");
    if main > 999 || sub > 999 {
        return Err(error_at(source, value_span, "DPT components must fit three decimal digits"));
    }
    Ok(format!("{main}.{sub:03}"))
}

fn parse_group_address(pair: Pair<'_, Rule>, source: &str) -> Result<GroupAddress, ParseError> {
    pair.as_str().parse().map_err(|error| error_at(source, span(&pair), &format!("group address: {error}")))
}

fn parse_individual_address(pair: Pair<'_, Rule>, source: &str) -> Result<IndividualAddress, ParseError> {
    pair.as_str().parse().map_err(|error| error_at(source, span(&pair), &format!("individual address: {error}")))
}

fn bounded_u8(pair: &Pair<'_, Rule>, maximum: u8, message: &str, source: &str) -> Result<u8, ParseError> {
    let value = parse_u64(pair, source)?;
    u8::try_from(value).ok().filter(|value| *value <= maximum).ok_or_else(|| error_at(source, span(pair), message))
}

fn parse_u64(pair: &Pair<'_, Rule>, source: &str) -> Result<u64, ParseError> {
    pair.as_str().parse().map_err(|_| error_at(source, span(pair), "integer is too large"))
}

fn unquote(pair: Pair<'_, Rule>, source: &str) -> Result<String, ParseError> {
    let raw = pair.as_str();
    let mut value = String::new();
    let mut chars = raw[1..raw.len() - 1].chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            value.push(character);
            continue;
        }
        let escaped = chars.next().expect("grammar rejects trailing escapes");
        value.push(match escaped {
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            '"' => '"',
            '\\' => '\\',
            _ => return Err(error_at(source, span(&pair), "unsupported string escape")),
        });
    }
    Ok(value)
}

fn set_once<T: Copy>(
    slot: &mut Option<T>,
    value: T,
    name: &str,
    value_span: SourceSpan,
    source: &str,
) -> Result<(), ParseError> {
    if slot.replace(value).is_some() {
        Err(error_at(source, value_span, format!("duplicate `{name}` override")))
    } else {
        Ok(())
    }
}

fn parse_serial(input: &str) -> Result<[u8; 6], &'static str> {
    let compact = input.replace(':', "");
    if compact.len() != 12 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("serial number must contain 12 hexadecimal digits, optionally with a manufacturer separator");
    }
    let mut serial = [0; 6];
    for (index, byte) in serial.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).map_err(|_| "invalid serial number")?;
    }
    Ok(serial)
}

fn parse_domain_address(input: &str, medium: Medium) -> Result<DomainAddress, &'static str> {
    match medium {
        Medium::Rf => {
            if !input.bytes().all(|byte| byte.is_ascii_hexdigit() || byte == b':') {
                return Err("RF domain address may contain only hexadecimal digits and colons");
            }
            let compact = input.replace(':', "");
            if compact.len() != 12 {
                return Err("RF domain address must contain twelve hexadecimal digits");
            }
            let mut domain = [0; 6];
            for (index, byte) in domain.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
                    .map_err(|_| "invalid RF domain address")?;
            }
            Ok(DomainAddress::Rf(domain))
        }
        Medium::Ip => Ok(DomainAddress::Ip(parse_ipv4(input)?)),
        Medium::Tp1 => Err("TP1 lines cannot declare a domain address"),
    }
}

fn parse_ipv4(input: &str) -> Result<[u8; 4], &'static str> {
    input.parse::<std::net::Ipv4Addr>().map(|address| address.octets()).map_err(|_| "invalid IPv4 address")
}

fn parse_unique_ip_service(
    item: Pair<'_, Rule>,
    source: &str,
    device_span: SourceSpan,
    name: &'static str,
    slot: &mut Option<IpServiceSecurity>,
) -> Result<(), ParseError> {
    let value = meaningful(item).next().expect("grammar supplies IP service security");
    let parsed = match value.as_str() {
        "plain" => IpServiceSecurity::Plain,
        "secure" => IpServiceSecurity::Secure,
        other => {
            return Err(error_at(
                source,
                span(&value),
                format!("unknown {name} mode `{other}`; expected `plain` or `secure`"),
            ));
        }
    };
    if slot.replace(parsed).is_some() {
        return Err(error_at(source, device_span, format!("a device may declare {name} only once")));
    }
    Ok(())
}

fn pest_error(error: pest::error::Error<Rule>) -> ParseError {
    let (line, column) = match error.line_col {
        LineColLocation::Pos(position) | LineColLocation::Span(position, _) => position,
    };
    let error_span = match error.location {
        InputLocation::Pos(position) => SourceSpan { start: position, end: position },
        InputLocation::Span((start, end)) => SourceSpan { start, end },
    };
    ParseError { message: error.variant.message().into_owned(), line, column, span: error_span }
}

fn span(pair: &Pair<'_, Rule>) -> SourceSpan {
    SourceSpan { start: pair.as_span().start(), end: pair.as_span().end() }
}

fn error_at(source: &str, error_span: SourceSpan, message: impl Into<String>) -> ParseError {
    let prefix = &source[..error_span.start.min(source.len())];
    ParseError {
        message: message.into(),
        line: prefix.bytes().filter(|byte| *byte == b'\n').count() + 1,
        column: prefix.rsplit_once('\n').map_or(prefix.len() + 1, |(_, tail)| tail.len() + 1),
        span: error_span,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROJECT: &str = r#"# bench project
language "de-DE"

ga kitchen_switch = 1/0/1
ga all_off = 0/0/1

net kitchen_switch : 1.001 {
    name "Kitchen switch"
    security authentication_confidentiality
}
net all_off : 1.001 { security authentication_confidentiality }

area 1 bench {
    line 1 main {
        medium tp1
        device button {
            product package:"sha256:1111111111111111111111111111111111111111111111111111111111111111"
            catalog_item "M-00FA_H-1_P-1_CI-1"
            address 1.1.10
            serial "00FA:00000001"
            data_secure enabled
            param "M-00FA_A-0001_P-1" = 3
            object 0 {
                on kitchen_switch
                flags { communication true transmit true }
            }
        }
        device relay {
            product package:"sha256:2222222222222222222222222222222222222222222222222222222222222222"
            catalog_item "M-00FA_H-1_P-2_CI-1"
            address 1.1.20
            data_secure enabled
            object 0 {
                on kitchen_switch
                also on all_off
                flags {
                    communication true
                    write true
                    update true
                    priority low
                }
            }
        }
    }
}

external_sender visualisation {
    address 1.1.250
    data_secure enabled
    on kitchen_switch
}
"#;

    #[test]
    fn parses_the_minimal_language_without_reformatting_it() {
        let project = AuthoredProject::parse(PROJECT).expect("project parses");
        assert_eq!(project.source(), PROJECT);
        assert_eq!(project.nets[&NetId("kitchen_switch".into())].address, GroupAddress::from_three_level(1, 0, 1));
        assert_eq!(project.nets[&NetId("kitchen_switch".into())].name.as_deref(), Some("Kitchen switch"));
        assert_eq!(project.devices["button"].serial, Some([0x00, 0xFA, 0, 0, 0, 1]));
        assert_eq!(project.language.as_deref(), Some("de-DE"));
        assert!(project.devices["button"].active);
        assert_eq!(project.devices["button"].data_secure, DataSecureMode::Enabled);
        assert_eq!(project.devices["relay"].data_secure, DataSecureMode::Enabled);
        assert_eq!(project.devices["relay"].objects[&0].memberships.len(), 2);
    }

    #[test]
    fn rejects_empty_or_duplicate_language_preferences() {
        let empty = PROJECT.replace("language \"de-DE\"", "language \"\"");
        let error = AuthoredProject::parse(empty).expect_err("empty language is rejected");
        assert!(error.message.contains("language cannot be empty"));

        let duplicate = PROJECT.replace("language \"de-DE\"", "language \"de-DE\" language \"en-US\"");
        let error = AuthoredProject::parse(duplicate).expect_err("duplicate language is rejected");
        assert!(error.message.contains("project may only declare one language"));
    }

    #[test]
    fn package_selector_keeps_the_exact_digest_and_catalog_item() {
        let relay = ProjectDeviceId::new("relay").expect("literal is an identifier");
        let project = AuthoredProject::parse(PROJECT).expect("project parses");

        assert_eq!(project.devices[&relay].product, ProductReference::Package {
            package: ProjectPackageId::from_bytes([0x22; 32]),
            catalog_item: "M-00FA_H-1_P-2_CI-1".into(),
        });
    }

    #[test]
    fn rejects_incomplete_duplicate_or_noncanonical_package_selectors() {
        let product = concat!(
            "product package:\"sha256:2222222222222222222222222222222222222222222222222222222222222222\"\n",
            "            catalog_item \"M-00FA_H-1_P-2_CI-1\"",
        );
        for (replacement, expected) in [
            (
                "product package:\"sha256:2222222222222222222222222222222222222222222222222222222222222222\"",
                "missing its `catalog_item`",
            ),
            (
                concat!(
                    "product package:\"sha256:2222222222222222222222222222222222222222222222222222222222222222\"\n",
                    "            catalog_item \"M-00FA_H-1_P-2_CI-1\"\n",
                    "            catalog_item \"M-00FA_H-1_P-2_CI-2\"",
                ),
                "only declare one catalog_item",
            ),
            (
                concat!(
                    "product package:\"sha256:2222222222222222222222222222222222222222222222222222222222222222\"\n",
                    "            catalog_item \"\"",
                ),
                "CatalogItem ID cannot be empty",
            ),
        ] {
            let error = AuthoredProject::parse(PROJECT.replace(product, replacement))
                .expect_err("invalid selector is rejected");
            assert!(error.message.contains(expected), "{}", error.message);
        }

        for digest in [
            "sha256:22",
            "sha256:222222222222222222222222222222222222222222222222222222222222222G",
            "sha256:222222222222222222222222222222222222222222222222222222222222222A",
            "sha256-2222222222222222222222222222222222222222222222222222222222222222",
        ] {
            let source =
                PROJECT.replace("sha256:2222222222222222222222222222222222222222222222222222222222222222", digest);
            let error = AuthoredProject::parse(source).expect_err("noncanonical digest is rejected");
            assert!(error.message.contains("canonical sha256"));
        }

        let duplicate_product = PROJECT.replace(
            "catalog_item \"M-00FA_H-1_P-2_CI-1\"",
            concat!(
                "product package:\"sha256:3333333333333333333333333333333333333333333333333333333333333333\"\n",
                "            catalog_item \"M-00FA_H-1_P-2_CI-1\"",
            ),
        );
        let error = AuthoredProject::parse(duplicate_product).expect_err("duplicate product is rejected");
        assert!(error.message.contains("only declare one product"));

        assert!(
            AuthoredProject::parse(PROJECT.replace(
                "product package:\"sha256:1111111111111111111111111111111111111111111111111111111111111111\"",
                "product local:\"products/button.mtxml\"",
            ))
            .is_err()
        );
    }

    #[test]
    fn inactive_devices_are_explicit_and_active_is_the_default() {
        let project = AuthoredProject::parse(PROJECT.replace("device relay {", "device relay { active false"))
            .expect("inactive project parses");

        assert!(project.devices["button"].active);
        assert!(!project.devices["relay"].active);

        let error = AuthoredProject::parse(PROJECT.replace("device relay {", "device relay { active maybe"))
            .expect_err("unknown active state is rejected");
        assert!(error.message.contains("expected `true` or `false`"));
    }

    #[test]
    fn rejects_a_device_outside_its_enclosing_line() {
        let source = PROJECT.replace("address 1.1.10", "address 1.2.10");
        let error = AuthoredProject::parse(source).expect_err("wrong line is rejected");
        assert!(error.message.contains("does not belong"));
    }

    #[test]
    fn rejects_an_orphan_group_address() {
        let source = PROJECT.replace("net all_off : 1.001 { security authentication_confidentiality }", "");
        let error = AuthoredProject::parse(source).expect_err("orphan address is rejected");
        assert!(error.message.contains("no matching `net`"));
    }

    #[test]
    fn comments_escapes_and_negative_values_are_grammar_features() {
        let source = PROJECT
            .replace("param \"M-00FA_A-0001_P-1\" = 3", "param \"M-00FA_A-0001_P-1\" = -1.5 // retained")
            .replace("catalog_item \"M-00FA_H-1_P-1_CI-1\"", "catalog_item \"M-00FA_H-1_P-1_CI-\\\"1\"");
        let project = AuthoredProject::parse(source).expect("extended lexical forms parse");
        assert_eq!(project.devices["button"].parameters[0].value, ParamValue::Float(-1.5));
    }

    #[test]
    fn keywords_require_a_token_boundary() {
        let error = AuthoredProject::parse("garbage x = 1/0/1").expect_err("keyword prefix is rejected");
        assert_eq!(error.line, 1);
    }

    #[test]
    fn rejects_an_unknown_data_secure_mode() {
        let source = PROJECT.replace("data_secure enabled", "data_secure maybe");
        let error = AuthoredProject::parse(source).expect_err("unknown mode is rejected");
        assert!(error.message.contains("expected `enabled` or `disabled`"));
    }

    #[test]
    fn omitted_data_secure_mode_defaults_to_disabled() {
        let source = PROJECT.replacen("            data_secure enabled\n", "", 1);
        let project = AuthoredProject::parse(source).expect("project parses");
        assert_eq!(project.devices["button"].data_secure, DataSecureMode::Disabled);
    }

    #[test]
    fn parses_typed_rf_and_coupler_values() {
        let source = r#"area 1 installation {
    line 2 radio {
        medium rf
        domain "00:FA:12:34:56:78"
        device rf_coupler {
            product package:"sha256:3333333333333333333333333333333333333333333333333333333333333333"
            catalog_item "M-00FA_H-3_P-1_CI-1"
            address 1.2.0
            rf_mode multi
            routing route_all
        }
    }
}"#;

        let project = AuthoredProject::parse(source).expect("open-medium project parses");
        assert_eq!(
            project.line_topology(1, 2).expect("RF line exists").domain,
            Some(DomainAddress::Rf([0x00, 0xFA, 0x12, 0x34, 0x56, 0x78]))
        );
        assert_eq!(project.devices["rf_coupler"].rf_mode, Some(RfDeviceMode::Multi));
        assert_eq!(project.devices["rf_coupler"].routing, Some(CouplerRoutingPolicy::RouteAll));
    }

    #[test]
    fn parses_complete_tool_managed_ip_and_secure_service_intent() {
        let source = r#"area 1 installation {
    line 0 backbone {
        medium ip
        domain "224.0.23.12"
        project_installation_id 42.3
        multicast_latency_tolerance 50
        sync_latency_fraction 4
        device router {
            product package:"sha256:4444444444444444444444444444444444444444444444444444444444444444"
            catalog_item "M-00FA_H-4_P-1_CI-1"
            address 1.0.1
            ip_assignment fixed
            ip_address "192.0.2.10"
            subnet_mask "255.255.255.0"
            default_gateway "192.0.2.1"
            multicast_ttl 16
            friendly_name "Main IP Router"
            additional_address 1.0.2
            ip_routing secure
            ip_device_management secure
            ip_tunnelling secure
            ip_password_user 1
            ip_tunnelling_user 1 1
        }
    }
}"#;

        let project = AuthoredProject::parse(source).expect("KNX/IP project parses");
        let line = project.line_topology(1, 0).expect("IP backbone exists");
        assert_eq!(line.domain, Some(DomainAddress::Ip([224, 0, 23, 12])));
        assert_eq!(line.ip.expect("line IP values").project_installation_id.encode(), 0x02a3);
        let device = &project.devices["router"];
        let ip = device.ip.as_ref().expect("device IP values");
        assert!(matches!(ip.assignment, IpAssignment::Fixed { address: [192, 0, 2, 10], .. }));
        let security = ip.security.as_ref().expect("IP Secure intent");
        assert_eq!(security.routing, IpServiceSecurity::Secure);
        assert_eq!(security.multicast_latency_tolerance_ms, 50);
        assert_eq!(security.tunnelling_users[0].address_index, 1);
    }

    #[test]
    fn rejects_removed_medium_malformed_domain_and_routing_tokens() {
        let product = concat!(
            "product package:\"sha256:0000000000000000000000000000000000000000000000000000000000000000\" ",
            "catalog_item \"M-00FA_H-1_P-1_CI-1\"",
        );
        let removed_medium = format!("area 1 a {{ line 1 l {{ medium pl device d {{ {product} address 1.1.1 }} }} }}");
        let error = AuthoredProject::parse(removed_medium).expect_err("removed PL medium is rejected");
        assert!(error.message.contains("unknown medium `pl`"));

        let malformed_domain = format!(
            "area 1 a {{ line 1 l {{ medium rf domain \"123\" device d {{ {product} address 1.1.1 rf_mode ready }} }} }}"
        );
        let error = AuthoredProject::parse(malformed_domain).expect_err("short domain is rejected");
        assert!(error.message.contains("twelve hexadecimal digits"));

        let line_wide_rf_mode = format!(
            "area 1 a {{ line 1 l {{ medium rf domain \"00:FA:12:34:56:78\" rf_mode ready device d {{ {product} address 1.1.1 }} }} }}"
        );
        AuthoredProject::parse(line_wide_rf_mode).expect_err("line-wide RF mode is rejected");

        let unknown_rf_mode = format!(
            "area 1 a {{ line 1 l {{ medium rf domain \"00:FA:12:34:56:78\" device d {{ {product} address 1.1.1 rf_mode maybe }} }} }}"
        );
        let error = AuthoredProject::parse(unknown_rf_mode).expect_err("unknown RF mode is rejected");
        assert!(error.message.contains("expected `ready` or `multi`"));

        let unknown_routing =
            format!("area 1 a {{ line 1 l {{ medium tp1 device d {{ {product} address 1.1.0 routing maybe }} }} }}");
        let error = AuthoredProject::parse(unknown_routing).expect_err("unknown routing policy is rejected");
        assert!(error.message.contains("expected `filter`, `route_all`, or `block_all`"));
    }
}
