//! Commented one-device `project.knx` skeleton rendering.

use std::fmt::Write;
use std::path::Path;

use zweidraehte_ets_files::runtime::Device;
use zweidraehte_ets_files::runtime::configuration::{ProductConfiguration, effective_com_objects, effective_default};
use zweidraehte_ets_files::runtime::model::ParameterValue;
use zweidraehte_ets_files::schema::ParameterTypeDef;

pub fn dump_project_skeleton(device: &Device, product_path: &Path) -> String {
    let mut out = String::new();
    let program = device.program();
    let _ = writeln!(out, "# Project for {:?} ({})", program.name, program.id);
    let _ = writeln!(out, "# Mask {}. Paths are relative to this file.", program.mask_version);
    out.push_str("# Add each group address as a named net, then reference that name from objects.\n");
    out.push_str("# ga kitchen_switch = 1/0/1\n");
    out.push_str("# net kitchen_switch : 1.001 { name \"Kitchen switch\" security plain }\n\n");
    out.push_str("area 1 bench {\n    line 1 main {\n        medium tp1\n\n");
    out.push_str("        device device {\n");
    let _ = writeln!(out, "            product local:{:?}", product_path.to_string_lossy());
    out.push_str("            address 1.1.1\n");
    if program.is_secure_enabled.unwrap_or(false) {
        out.push_str("            # This product supports Data Secure; enable it only when credentials are ready.\n");
        out.push_str("            data_secure disabled\n");
        out.push_str("            # serial \"00FA:00000001\"\n");
        out.push_str("            # Put the FDSK/tool key in keys.toml, never in project.knx.\n");
    } else {
        out.push_str("            # This product does not support Data Secure.\n");
        out.push_str("            data_secure disabled\n");
    }

    out.push_str("\n            # Parameters (uncomment desired assignments):\n");
    for (id, ref_access) in visible_parameters_sorted(device) {
        let Some(info) = device.get_parameter_info(&id) else { continue };
        let effective_access = ref_access.as_deref().or(if info.hidden {
            Some("None")
        } else if info.read_only {
            Some("Read")
        } else {
            None
        });
        if matches!(effective_access, Some("None" | "Read")) {
            continue;
        }
        let type_def = device.get_parameter_type(&info.type_id).map(|parameter| &parameter.type_def);
        if matches!(
            type_def,
            Some(ParameterTypeDef::TypePicture(_) | ParameterTypeDef::TypeNone(_) | ParameterTypeDef::TypeTime(_))
                | None
        ) {
            continue;
        }
        let text = device.interpolate_text(&info.text);
        let _ = writeln!(out, "            # {} — {}", info.name, text);
        if let Some(description) = describe_type(type_def) {
            let _ = writeln!(out, "            #   {description}");
        }
        let default = effective_default(device, &id).unwrap_or(ParameterValue::Integer(0));
        let _ = writeln!(out, "            # param {id:?} = {}", render_value(&default));
    }

    out.push_str("\n            # Communication objects. `on` is the one primary/sending\n");
    out.push_str("            # association; `also on` adds listening associations.\n");
    for object in effective_com_objects(device, &ProductConfiguration::default()) {
        let _ = writeln!(
            out,
            "            # Object {} — {} ({}, {})",
            object.number,
            device.interpolate_text(&object.text),
            device.interpolate_text(&object.function_text),
            object.object_size
        );
        let _ = writeln!(out, "            # object {} {{", object.number);
        out.push_str("            #     on kitchen_switch\n");
        out.push_str("            #     flags {\n");
        let _ = writeln!(out, "            #         communication {}", object.communication);
        let _ = writeln!(out, "            #         read {}", object.read);
        let _ = writeln!(out, "            #         write {}", object.write);
        let _ = writeln!(out, "            #         transmit {}", object.transmit);
        let _ = writeln!(out, "            #         update {}", object.update);
        let _ = writeln!(out, "            #         read_on_init {}", object.read_on_init);
        let _ = writeln!(out, "            #         priority {}", object.priority.to_string().to_lowercase());
        out.push_str("            #     }\n            # }\n");
    }
    out.push_str("        }\n    }\n}\n");
    out
}

fn visible_parameters_sorted(device: &Device) -> Vec<(String, Option<String>)> {
    let mut seen = std::collections::HashSet::new();
    let mut parameters: Vec<_> = device
        .visible_param_refs()
        .filter(|reference| seen.insert(reference.ref_id.clone()))
        .map(|reference| (reference.ref_id.clone(), reference.access.clone()))
        .collect();
    if parameters.is_empty()
        && device.static_section().parameter_refs.as_ref().is_none_or(|references| references.refs.is_empty())
    {
        parameters.extend(device.parameter_infos().map(|info| (info.id.clone(), None)));
    }
    parameters.sort_by_key(|(id, _)| numeric_tail(id));
    parameters
}

fn numeric_tail(id: &str) -> (String, u64) {
    let digits = id.len() - id.chars().rev().take_while(char::is_ascii_digit).count();
    (id[..digits].to_string(), id[digits..].parse().unwrap_or(0))
}

fn describe_type(type_def: Option<&ParameterTypeDef>) -> Option<String> {
    Some(match type_def? {
        ParameterTypeDef::TypeNumber(number) => format!("range: {}..={}", number.min_inclusive, number.max_inclusive),
        ParameterTypeDef::TypeFloat(float) => {
            format!("range: {}..={} ({})", float.min_inclusive, float.max_inclusive, float.encoding)
        }
        ParameterTypeDef::TypeRestriction(restriction) => {
            let choices = restriction
                .enumerations
                .iter()
                .map(|entry| format!("{} = {}", entry.value, entry.text))
                .collect::<Vec<_>>();
            format!("one of: {}", choices.join(", "))
        }
        ParameterTypeDef::TypeText(text) => format!("text, up to {} bytes", text.size_in_bit / 8),
        ParameterTypeDef::TypeColor(color) => format!("{} colour", color.space.name()),
        ParameterTypeDef::TypeTime(time) => format!("{} time value", time.unit),
        ParameterTypeDef::TypeNone(_) | ParameterTypeDef::TypePicture(_) | ParameterTypeDef::TypeIpAddress(_) => {
            return None;
        }
    })
}

fn render_value(value: &ParameterValue) -> String {
    match value {
        ParameterValue::Integer(value) => value.to_string(),
        ParameterValue::Float(value) => format!("{value:?}"),
        ParameterValue::Text(value) => format!("{value:?}"),
        ParameterValue::Bytes(value) => {
            format!("{:?}", value.iter().map(|byte| format!("{byte:02X}")).collect::<String>())
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_uses_project_syntax() {
        assert!(
            !super::render_value(&zweidraehte_ets_files::runtime::model::ParameterValue::Integer(1)).contains("[[")
        );
    }
}
