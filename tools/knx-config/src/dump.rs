//! Topology-only `project.knx` skeleton with a commented device guide.

use std::fmt::Write;

use zweidraehte_ets_files::runtime::Device;
use zweidraehte_ets_files::runtime::configuration::{ProductConfiguration, effective_com_objects, effective_default};
use zweidraehte_ets_files::runtime::model::ParameterValue;
use zweidraehte_ets_files::schema::ParameterTypeDef;

/// Render a parseable topology skeleton plus a commented product guide.
///
/// A product file alone is insufficient authority for a project device: the
/// durable reference must name an immutable imported package and one exact
/// `CatalogItem`. `knx-dump` may also inspect loose MTXML and may write to
/// stdout, where no project-local store exists. It therefore deliberately
/// authors no device; `knx-loader add` or the TUI performs the package import
/// and inserts the real selector later.
pub fn dump_project_skeleton(device: &Device) -> String {
    let mut out = String::new();
    let program = device.program();
    let _ = writeln!(out, "# Project topology guide for {:?} ({})", program.name, program.id);
    let _ = writeln!(out, "# Mask {}.", program.mask_version);
    out.push_str("# No device is authored here: a device must select an exact CatalogItem from an\n");
    out.push_str("# immutable .knxprod in this project's store. Use `knx-loader add` or the TUI.\n");
    out.push_str("# Add each group address as a named net, then reference that name from objects.\n");
    out.push_str("# ga kitchen_switch = 1/0/1\n");
    out.push_str("# net kitchen_switch : 1.001 { name \"Kitchen switch\" security plain }\n\n");
    out.push_str("area 1 bench {\n    line 1 main {\n        medium tp1\n\n");
    out.push_str("        # Suggested settings for the device after its package has been imported:\n");
    out.push_str("        # device device {\n");
    out.push_str("            # address 1.1.1\n");
    if program.is_secure_enabled.unwrap_or(false) {
        out.push_str("            # This product supports Data Secure; enable it only when credentials are ready.\n");
        out.push_str("            # data_secure disabled\n");
        out.push_str("            # serial \"00FA:00000001\"\n");
        out.push_str("            # Put the FDSK/tool key in keys.toml, never in project.knx.\n");
    } else {
        out.push_str("            # This product does not support Data Secure.\n");
        out.push_str("            # data_secure disabled\n");
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
        if matches!(type_def, Some(ParameterTypeDef::TypePicture(_) | ParameterTypeDef::TypeNone(_)) | None) {
            continue;
        }
        let text = single_line(&device.interpolate_text(&info.text));
        let _ = writeln!(out, "            # {} — {}", single_line(&info.name), text);
        if let Some(description) = describe_type(type_def) {
            let _ = writeln!(out, "            #   {}", single_line(&description));
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
            single_line(&device.interpolate_text(&object.text)),
            single_line(&device.interpolate_text(&object.function_text)),
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
    out.push_str("        # }\n    }\n}\n");
    out
}

fn single_line(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
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
        ParameterTypeDef::TypeTime(time) => {
            let display = time.ui_hint.as_deref().map_or(String::new(), |hint| format!(", display: {hint}"));

            format!(
                "range: {}..={} {} ({}, integer storage{display})",
                time.min_inclusive,
                time.max_inclusive,
                time.unit.value_unit(),
                time.unit
            )
        }
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
    use zweidraehte_ets_files::runtime::Device;
    use zweidraehte_ets_files::schema::ApplicationProgram;
    use zweidraehte_ets_files::schema::{ParameterTypeDef, TimeUnit, TypeTime};
    use zweidraehte_project::AuthoredProject;

    #[test]
    fn skeleton_uses_project_syntax() {
        assert!(
            !super::render_value(&zweidraehte_ets_files::runtime::model::ParameterValue::Integer(1)).contains("[[")
        );
    }

    #[test]
    fn skeleton_is_parseable_topology_without_a_fake_product_reference() {
        let program = ApplicationProgram {
            id: "M-00FA_A-0001-01-0000".into(),
            name: "Test switch".into(),
            ..ApplicationProgram::default()
        };
        let skeleton = super::dump_project_skeleton(&Device::new(program, None));

        let parsed = AuthoredProject::parse(skeleton.clone()).expect("topology skeleton parses");

        assert_eq!(parsed.source(), skeleton);
        assert!(parsed.devices.is_empty());
        assert!(skeleton.contains("No device is authored here"));
        assert!(!skeleton.contains("product local:"));
        assert!(!skeleton.lines().any(|line| line.trim_start().starts_with("device ")));
    }

    #[test]
    fn time_description_names_the_integer_basis() {
        let time = ParameterTypeDef::TypeTime(TypeTime {
            size_in_bit: 24,
            unit: TimeUnit::PackedDaysHoursMinutesAndSeconds,
            min_inclusive: 0,
            max_inclusive: 86_400,
            ui_hint: Some("Duration_hhmmss".to_string()),
        });

        assert_eq!(
            super::describe_type(Some(&time)).as_deref(),
            Some("range: 0..=86400 s (PackedDaysHoursMinutesAndSeconds, integer storage, display: Duration_hhmmss)")
        );
    }
}
