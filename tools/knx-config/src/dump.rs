//! Rendering the mods-file skeleton `knx-dump` emits.
//!
//! The output is a complete, commented catalogue of everything
//! configurable *under the current configuration*: every visible
//! parameter as a commented `[[param]]` block annotated with its
//! meaning and choices, every visible com object as a commented
//! `[[link]]` block. Entries the input mods file already set are
//! emitted un-commented, so `knx-dump --mods current.toml` regenerates
//! the skeleton around existing edits — the way to iterate when a
//! choice reveals new parameters.

use std::collections::HashMap;
use std::fmt::Write;

use zweidraehte_knxprod::runtime::Device;
use zweidraehte_knxprod::runtime::model::ParameterValue;
use zweidraehte_knxprod::runtime::mods::{
    DeviceMods, GroupSecurityPolicy, ModsValue, effective_com_objects, effective_default,
};
use zweidraehte_knxprod::schema::{ParameterRef, ParameterTypeDef};

/// Render the skeleton. `mods` carries the caller's current edits (or
/// `DeviceMods::default()` for a fresh dump) — they must already be
/// applied to `device`, so visibility matches what is printed.
pub fn dump_skeleton(device: &Device, mods: &DeviceMods) -> String {
    let mut out = String::new();
    let program = device.program();
    let _ = writeln!(out, "# Device configuration for {:?} ({})", program.name, program.id);
    let _ =
        writeln!(out, "# Mask {}. Uncomment a block to override; values shown are the defaults.", program.mask_version);
    let _ = writeln!(out, "# Regenerate around your edits with: knx-dump --product <file> --mods <this file>");
    out.push('\n');

    out.push_str("[device]\n");
    if mods.device.individual_address.is_empty() {
        out.push_str("individual_address = \"1.1.1\" # TODO: the address this installation assigns\n");
    } else {
        let _ = writeln!(out, "individual_address = \"{}\"", mods.device.individual_address);
    }
    if let Some(serial) = &mods.device.serial_number {
        let _ = writeln!(out, "serial_number = {serial:?}");
    }
    if let Some(max_apdu) = mods.device.max_apdu {
        let _ = writeln!(out, "max_apdu = {max_apdu}");
    }
    out.push('\n');

    render_security(&mut out, mods, program.is_secure_enabled.unwrap_or(false));

    let overridden: HashMap<&str, &ModsValue> = mods.params.iter().map(|p| (p.id.as_str(), &p.value)).collect();

    out.push_str("# ============================== Parameters ==============================\n\n");
    for param_ref in visible_refs_sorted(device) {
        let id = &param_ref.ref_id;
        let Some(info) = device.get_parameter_info(id) else { continue };
        // Hidden and display-only placements are not configuration: the
        // ref's access overrides the base parameter's.
        let effective_access = param_ref.access.as_deref().or(if info.hidden {
            Some("None")
        } else if info.read_only {
            Some("Read")
        } else {
            None
        });
        if matches!(effective_access, Some("None" | "Read")) {
            continue;
        }
        let type_def = device.get_parameter_type(&info.type_id).map(|t| &t.type_def);
        // Pictures and the like are pages furniture, not configuration.
        if matches!(type_def, Some(ParameterTypeDef::TypePicture(_) | ParameterTypeDef::TypeNone(_)) | None) {
            continue;
        }

        let text = device.interpolate_text(&info.text);
        let suffix = info.suffix.as_deref().filter(|s| !s.is_empty()).map(|s| format!(" [{s}]")).unwrap_or_default();
        let _ = writeln!(out, "# {} — {}{}", info.name, text, suffix);
        if let Some(choices) = describe_type(type_def) {
            let _ = writeln!(out, "#   {choices}");
        }

        match overridden.get(id.as_str()) {
            Some(value) => {
                let _ = writeln!(out, "[[param]]\nid = \"{id}\"\nvalue = {}", render_mods_value(value));
            }
            None => {
                let default = effective_default(device, id).unwrap_or(ParameterValue::Integer(0));
                let _ = writeln!(
                    out,
                    "# [[param]]\n# id = \"{id}\"\n# value = {}",
                    render_mods_value(&ModsValue::from(&default))
                );
            }
        }
        out.push('\n');
    }

    let linked: HashMap<u16, &_> = mods.links.iter().map(|l| (l.com_object, l)).collect();

    out.push_str("# =========================== Communication objects ===========================\n");
    out.push_str("# The first group address sends; the rest listen.\n\n");
    for object in effective_com_objects(device, mods) {
        let _ = writeln!(
            out,
            "# Object {} — {} ({}, {})",
            object.number,
            device.interpolate_text(&object.text),
            device.interpolate_text(&object.function_text),
            object.object_size
        );
        match linked.get(&object.number) {
            Some(link) => {
                let addresses: Vec<String> = link.group_addresses.iter().map(|a| format!("\"{a}\"")).collect();
                let _ = writeln!(
                    out,
                    "[[link]]\ncom_object = {}\ngroup_addresses = [{}]",
                    object.number,
                    addresses.join(", ")
                );
            }
            None => {
                let _ = writeln!(out, "# [[link]]\n# com_object = {}\n# group_addresses = [\"0/0/1\"]", object.number);
            }
        }
        out.push('\n');
    }

    out
}

fn render_security(out: &mut String, mods: &DeviceMods, secure_product: bool) {
    if mods.security.is_empty() {
        if secure_product {
            out.push_str("# ============================== Data Secure ==============================\n");
            out.push_str("# FDSK accepts 32 hex digits or the six-part KNX setup-key label.\n");
            out.push_str("# [security]\n");
            out.push_str("# fdsk = \"AD5N5L-N654AA-CAQDAQ-CQMBYI-BEFAWD-ANBYHX\"\n");
            out.push_str("# tool_key = \"00112233445566778899AABBCCDDEEFF\"\n\n");
            out.push_str("# [[security.group]]\n");
            out.push_str("# group_address = \"1/0/1\"\n");
            out.push_str("# policy = \"authentication-confidentiality\"\n");
            out.push_str("# key = \"102132435465768798A9BACBDCEDFE0F\"\n\n");
            out.push_str("# [[security.sender]]\n");
            out.push_str("# individual_address = \"1.1.10\"\n");
            out.push_str("# sequence_number = 1234\n\n");
        }
        return;
    }

    out.push_str("# ============================== Data Secure ==============================\n");
    out.push_str("[security]\n");
    if let Some(fdsk) = &mods.security.fdsk {
        let _ = writeln!(out, "fdsk = {fdsk:?}");
    }
    if let Some(tool_key) = &mods.security.tool_key {
        let _ = writeln!(out, "tool_key = {tool_key:?}");
    }
    out.push('\n');
    for group in &mods.security.groups {
        out.push_str("[[security.group]]\n");
        let _ = writeln!(out, "group_address = {:?}", group.group_address);
        let policy = match group.policy {
            GroupSecurityPolicy::Plain => "plain",
            GroupSecurityPolicy::Automatic => "automatic",
            GroupSecurityPolicy::Authentication => "authentication",
            GroupSecurityPolicy::AuthenticationConfidentiality => "authentication-confidentiality",
        };
        let _ = writeln!(out, "policy = {policy:?}");
        if let Some(key) = &group.key {
            let _ = writeln!(out, "key = {key:?}");
        }
        out.push('\n');
    }
    for sender in &mods.security.senders {
        out.push_str("[[security.sender]]\n");
        let _ = writeln!(out, "individual_address = {:?}", sender.individual_address);
        let _ = writeln!(out, "sequence_number = {}", sender.sequence_number);
        out.push('\n');
    }
}

/// The visible parameter refs, deduplicated per parameter and in a
/// stable order. Visibility is set-backed, so iteration order is
/// arbitrary; sorting by the id's numeric tail matches the program's
/// own declaration numbering closely enough to read naturally.
fn visible_refs_sorted(device: &Device) -> Vec<&ParameterRef> {
    let mut seen = std::collections::HashSet::new();
    let mut refs: Vec<&ParameterRef> = device.visible_param_refs().filter(|r| seen.insert(r.ref_id.clone())).collect();
    refs.sort_by_key(|r| numeric_tail(&r.ref_id));
    refs
}

/// `M-0083_A-009B-14-E59D_P-24` → (prefix, 24), so P-24 sorts before
/// P-100.
fn numeric_tail(id: &str) -> (String, u64) {
    let digits = id.len() - id.chars().rev().take_while(char::is_ascii_digit).count();
    (id[..digits].to_string(), id[digits..].parse().unwrap_or(0))
}

/// One line describing the allowed values.
fn describe_type(type_def: Option<&ParameterTypeDef>) -> Option<String> {
    Some(match type_def? {
        ParameterTypeDef::TypeNumber(n) => format!("range: {}..={}", n.min_inclusive, n.max_inclusive),
        ParameterTypeDef::TypeFloat(f) => {
            format!("range: {}..={} ({})", f.min_inclusive, f.max_inclusive, f.encoding)
        }
        ParameterTypeDef::TypeRestriction(r) => {
            let choices: Vec<String> = r.enumerations.iter().map(|e| format!("{} = {}", e.value, e.text)).collect();
            format!("one of: {}", choices.join(", "))
        }
        ParameterTypeDef::TypeText(t) => format!("text, up to {} bytes", t.size_in_bit / 8),
        ParameterTypeDef::TypeNone(_) | ParameterTypeDef::TypePicture(_) | ParameterTypeDef::TypeIpAddress(_) => {
            return None;
        }
    })
}

/// A `ModsValue` as its TOML literal.
fn render_mods_value(value: &ModsValue) -> String {
    match value {
        ModsValue::Int(i) => i.to_string(),
        // {:?} keeps the decimal point TOML requires of floats.
        ModsValue::Float(f) => format!("{f:?}"),
        ModsValue::Text(t) => format!("{t:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commented_security_skeleton_is_secure_product_only() {
        let mods = DeviceMods::default();
        let mut plain = String::new();
        render_security(&mut plain, &mods, false);
        assert!(plain.is_empty());

        let mut secure = String::new();
        render_security(&mut secure, &mods, true);
        assert!(secure.contains("# [security]"));
        assert!(secure.contains("# [[security.group]]"));
        assert!(secure.contains("# [[security.sender]]"));
    }
}
