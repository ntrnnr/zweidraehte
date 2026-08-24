use std::collections::BTreeMap;
use std::path::PathBuf;

use pest::Parser as _;
use pest::error::{InputLocation, LineColLocation};
use pest::iterators::Pair;
use pest_derive::Parser;
use thiserror::Error;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use crate::model::{
    AuthoredProject, ExternalSender, Medium, MembershipRole, Net, NetId, NetSecurityPolicy, ObjectFlagOverrides,
    ObjectMembership, ObjectPriority, ParamValue, ParameterAssignment, ProductReference, ProjectDevice,
    ProjectDeviceId, ProjectObjectConfiguration, SourceSpan,
};

#[derive(Parser)]
#[grammar = "project.pest"]
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

    for declaration in project.into_inner() {
        match declaration.as_rule() {
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
                for device in parse_area(declaration, &source)? {
                    if devices.insert(device.id.clone(), device.clone()).is_some() {
                        return Err(error_at(
                            &source,
                            device.span,
                            format!("duplicate device identifier `{}`", device.id),
                        ));
                    }
                }
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
            address,
            dpt: raw.dpt,
            security: raw.security,
            security_span: raw.security_span,
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

    Ok(AuthoredProject { source, project_path, nets, devices, external_senders })
}

#[derive(Debug, Clone)]
struct RawNet {
    id: NetId,
    dpt: String,
    security: NetSecurityPolicy,
    security_span: SourceSpan,
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
    let security = fields.next().expect("grammar supplies security declaration");
    let policy_pair = meaningful(security).next().expect("grammar supplies security policy");
    let security_span = span(&policy_pair);
    let security = match policy_pair.as_str() {
        "plain" => NetSecurityPolicy::Plain,
        "automatic" => NetSecurityPolicy::Automatic,
        "authentication" => NetSecurityPolicy::Authentication,
        "authentication_confidentiality" => NetSecurityPolicy::AuthenticationConfidentiality,
        other => return Err(error_at(source, span(&policy_pair), format!("unknown security policy `{other}`"))),
    };
    Ok(RawNet { id, dpt, security, security_span, span: declaration_span })
}

fn parse_area(pair: Pair<'_, Rule>, source: &str) -> Result<Vec<ProjectDevice>, ParseError> {
    let mut fields = meaningful(pair);
    let area_pair = fields.next().expect("grammar supplies area number");
    let area = bounded_u8(&area_pair, 15, "area must be 0..15", source)?;
    let _area_name = fields.next().expect("grammar supplies area name");
    let mut devices = Vec::new();
    for line in fields {
        devices.extend(parse_line(line, area, source)?);
    }
    Ok(devices)
}

fn parse_line(pair: Pair<'_, Rule>, area: u8, source: &str) -> Result<Vec<ProjectDevice>, ParseError> {
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
    fields.map(|device| parse_device(device, area, line, medium, source)).collect()
}

fn parse_device(
    pair: Pair<'_, Rule>,
    area: u8,
    line: u8,
    medium: Medium,
    source: &str,
) -> Result<ProjectDevice, ParseError> {
    let device_span = span(&pair);
    let mut fields = meaningful(pair);
    let id = ProjectDeviceId(required_text(fields.next(), Rule::identifier));
    let mut product = None;
    let mut address = None;
    let mut serial = None;
    let mut max_apdu = None;
    let mut parameters = Vec::new();
    let mut objects = BTreeMap::new();

    for item in fields {
        match item.as_rule() {
            Rule::product_decl => {
                let path = unquote(meaningful(item).next().expect("grammar supplies product path"), source)?;
                if product.replace(ProductReference::Local(PathBuf::from(path))).is_some() {
                    return Err(error_at(source, device_span, "a device may only declare one product"));
                }
            }
            Rule::address_decl => {
                let value = meaningful(item).next().expect("grammar supplies address");
                if address.replace(parse_individual_address(value, source)?).is_some() {
                    return Err(error_at(source, device_span, "a device may only declare one address"));
                }
            }
            Rule::serial_decl => {
                let value = meaningful(item).next().expect("grammar supplies serial");
                let value_span = span(&value);
                let value = unquote(value, source)?;
                let parsed = parse_serial(&value).map_err(|message| error_at(source, value_span, message))?;
                if serial.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may only declare one serial"));
                }
            }
            Rule::max_apdu_decl => {
                let value = meaningful(item).next().expect("grammar supplies APDU size");
                let parsed = u16::try_from(parse_u64(&value, source)?)
                    .map_err(|_| error_at(source, span(&value), "APDU size exceeds 65535"))?;
                if max_apdu.replace(parsed).is_some() {
                    return Err(error_at(source, device_span, "a device may only declare one max_apdu"));
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

    let product = product.ok_or_else(|| error_at(source, device_span, "device is missing its `product`"))?;
    let address = address.ok_or_else(|| error_at(source, device_span, "device is missing its `address`"))?;
    if address.area() != area || address.line() != line {
        return Err(error_at(
            source,
            device_span,
            format!("device address {address} does not belong to enclosing area {area}, line {line}"),
        ));
    }
    Ok(ProjectDevice {
        id,
        name: None,
        area,
        line,
        medium,
        product,
        address,
        serial,
        max_apdu,
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
    let nets = fields.map(|membership| NetId(required_text(meaningful(membership).next(), Rule::identifier))).collect();
    Ok(ExternalSender { id, address, nets, span: sender_span })
}

fn meaningful(pair: Pair<'_, Rule>) -> impl Iterator<Item = Pair<'_, Rule>> {
    pair.into_inner().filter(|pair| !is_keyword(pair.as_rule()))
}

fn is_keyword(rule: Rule) -> bool {
    matches!(
        rule,
        Rule::kw_ga
            | Rule::kw_net
            | Rule::kw_security
            | Rule::kw_area
            | Rule::kw_line
            | Rule::kw_medium
            | Rule::kw_device
            | Rule::kw_product
            | Rule::kw_local
            | Rule::kw_address
            | Rule::kw_serial
            | Rule::kw_max_apdu
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
    let parts = pair
        .as_str()
        .split('/')
        .map(str::parse::<u16>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| error_at(source, span(&pair), "group address components must be decimal integers"))?;
    if parts[0] > 31 || parts[1] > 7 || parts[2] > 255 {
        return Err(error_at(source, span(&pair), "group address must be main 0..31, middle 0..7, subgroup 0..255"));
    }
    Ok(GroupAddress::from_three_level(parts[0] as u8, parts[1] as u8, parts[2] as u8))
}

fn parse_individual_address(pair: Pair<'_, Rule>, source: &str) -> Result<IndividualAddress, ParseError> {
    let parts = pair
        .as_str()
        .split('.')
        .map(str::parse::<u16>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| error_at(source, span(&pair), "individual address components must be decimal integers"))?;
    if parts[0] > 15 || parts[1] > 15 || parts[2] > 255 {
        return Err(error_at(source, span(&pair), "individual address must be area 0..15, line 0..15, device 0..255"));
    }
    Ok(IndividualAddress::new(parts[0] as u8, parts[1] as u8, parts[2] as u8))
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
ga kitchen_switch = 1/0/1
ga all_off = 0/0/1

net kitchen_switch : 1.001 {
    security authentication_confidentiality
}
net all_off : 1.001 { security authentication_confidentiality }

area 1 bench {
    line 1 main {
        medium tp1
        device button {
            product local:"products/button.mtxml"
            address 1.1.10
            serial "00FA:00000001"
            param "M-00FA_A-0001_P-1" = 3
            object 0 {
                on kitchen_switch
                flags { communication true transmit true }
            }
        }
        device relay {
            product local:"products/relay.mtxml"
            address 1.1.20
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
    on kitchen_switch
}
"#;

    #[test]
    fn parses_the_minimal_language_without_reformatting_it() {
        let project = AuthoredProject::parse(PROJECT).expect("project parses");
        assert_eq!(project.source(), PROJECT);
        assert_eq!(project.nets[&NetId("kitchen_switch".into())].address, GroupAddress::from_three_level(1, 0, 1));
        assert_eq!(project.devices[&ProjectDeviceId("button".into())].serial, Some([0x00, 0xFA, 0, 0, 0, 1]));
        assert_eq!(project.devices[&ProjectDeviceId("relay".into())].objects[&0].memberships.len(), 2);
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
            .replace("product local:\"products/button.mtxml\"", "product local:\"products/button\\\"x.mtxml\"");
        let project = AuthoredProject::parse(source).expect("extended lexical forms parse");
        assert_eq!(project.devices[&ProjectDeviceId("button".into())].parameters[0].value, ParamValue::Float(-1.5));
    }

    #[test]
    fn keywords_require_a_token_boundary() {
        let error = AuthoredProject::parse("garbage x = 1/0/1").expect_err("keyword prefix is rejected");
        assert_eq!(error.line, 1);
    }
}
