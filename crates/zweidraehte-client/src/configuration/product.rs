//! Lower checked product evaluation into commissioning-ready inputs.
//!
//! ETS runtime owns visibility, ref overrides, value validation and module
//! geometry. This module encodes those checked values as parameter bytes and
//! protocol object flags, and combines them with installation intent. The
//! commissioning compiler remains responsible for image and procedure safety.

use base64::Engine;
use zweidraehte_ets_files::runtime::evaluation::{
    EvaluatedProduct, ParameterOverlay, ParameterSource, ReferenceWriteOrder,
};
use zweidraehte_ets_files::runtime::model::ParameterValue as ModelValue;
use zweidraehte_ets_files::schema::{LoadControl, ParameterTypeDef};
use zweidraehte_proto::com_object::{ComObjectFlagFields, ComObjectType};
use zweidraehte_proto::dpt::KnxFloat16;

use super::device::{EncodedConfiguration, EncodedParameter, InstallationConfiguration};
use super::device::{ProcedureParameter, ProcedureParameterValue};
use super::materialized::{MaterializedDevice, Unkeyed};
use super::{ConfigurationError as Error, ConfigurationResult as Result};
use crate::configuration::ErrorDetail;
use zweidraehte_ets_files::product::ComObjectDef;

/// Render a configured device into the commissioning compiler's inputs.
///
/// The evaluated input binds product identity, valid settings and concrete
/// geometry. Callers cannot substitute an independently assembled runtime or
/// product, and encoding does not repeat product validation.
///
/// Parameter values first seed every ordinary stored parameter's base value
/// (and the designated default member of each union). Visible references,
/// explicit edits and `LegacyPatchAlways` parameters are then layered over
/// that base. Every property-backed parameter is included as well because,
/// unlike a seeded memory segment, its load-control data block has no other
/// source. This mirrors ETS even when segment `Data` omits defaults or a
/// `ParameterRef` value differs from the base parameter value.
impl MaterializedDevice<Unkeyed> {
    pub fn from_evaluated(evaluated: EvaluatedProduct<'_>, installation: InstallationConfiguration) -> Result<Self> {
        let mut parameters: Vec<EncodedParameter> = Vec::new();

        // Product-owned and merged load procedures may branch on a ParameterRef
        // rather than on its base storage parameter. Retain those exact effective
        // values before lowering the configured device to raw image bytes. This is
        // intentionally limited to procedure dependencies instead of copying the
        // thousands of dynamic-page controls found in large products.
        let procedure_parameters = collect_procedure_parameters(&evaluated)?;
        let mut encoded = Vec::new();
        for parameter in evaluated.parameter_overlays() {
            // Picture and none-typed parameters have no storage width. The
            // reference formatter skips parameters without bits even where
            // they name a memory location (witness: M-0234_A-0014-01 P-16).
            if matches!(
                parameter.parameter_type,
                Some(ParameterTypeDef::TypePicture(_) | ParameterTypeDef::TypeNone(_))
            ) {
                continue;
            }

            let derived = parameter.source == ParameterSource::Derived;
            let context = if derived { "derived parameter" } else { "parameter" };
            let value =
                encode_value(&parameter.value, parameter.parameter_type, parameter.size_bits).map_err(|reason| {
                    Error::ProductData(ErrorDetail::new(format!("{context} {}: {reason}", parameter.id)))
                })?;
            encoded.push((parameter, value));
        }

        // Several visible references may share one stored parameter. Each is
        // written in turn and the last write survives, so the latest
        // reference's bytes take the first reference's position.
        let winners = winning_references(&encoded)?;
        let mut written = std::collections::HashSet::new();
        for (parameter, value) in encoded {
            let id = parameter.id;
            let derived = parameter.source == ParameterSource::Derived;
            if matches!(parameter.source, ParameterSource::Reference(_)) {
                if !written.insert(id.clone()) {
                    continue;
                }
                let value = winners.get(&id).expect("every reference overlay has a winner").clone();
                parameters.push(EncodedParameter { id: id.into_owned(), value });
                continue;
            }
            if derived && let Some(existing) = parameters.iter_mut().find(|parameter| parameter.id == id) {
                existing.value = value;
                continue;
            }
            parameters.push(EncodedParameter { id: id.into_owned(), value });
        }

        let com_objects = evaluated
            .objects()
            .iter()
            .map(|object| {
                let object_type = ComObjectType::from_ets_size_string(&object.object_size).ok_or_else(|| {
                    Error::ProductData(ErrorDetail::new(format!(
                        "object {} has an unrecognized size {:?}",
                        object.number, object.object_size
                    )))
                })?;
                Ok(ComObjectDef {
                    number: object.number,
                    object_type,
                    datapoint_type: object.datapoint_type.clone(),
                    flags: ComObjectFlagFields {
                        update: object.update,
                        transmit: object.transmit,
                        bit5: object.read_on_init,
                        write: object.write,
                        read: object.read,
                        communication: object.communication,
                        priority: object.priority,
                    }
                    .into(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let encoded = EncodedConfiguration { parameters, com_objects, procedure_parameters };
        Ok(Self::from_parts(evaluated.into_product(), installation, encoded))
    }
}

/// Select the bytes each referenced stored parameter finally holds.
///
/// Bytes, not semantic values, are compared: rounding and enumerations can make
/// different reference values agree on the same stored value. Only the
/// references no other competitor follows can survive; when several such
/// unordered references disagree, the stored value is undefined.
fn winning_references<'a>(
    encoded: &[(ParameterOverlay<'a>, Vec<u8>)],
) -> Result<std::collections::HashMap<std::borrow::Cow<'a, str>, Vec<u8>>> {
    let mut competitors = std::collections::HashMap::<_, Vec<_>>::new();
    for (parameter, value) in encoded {
        if matches!(parameter.source, ParameterSource::Reference(_)) {
            competitors.entry(parameter.id.clone()).or_default().push((parameter.reference_order, value));
        }
    }

    competitors
        .into_iter()
        .map(|(id, candidates)| {
            let written_later = |order: Option<ReferenceWriteOrder>, other: Option<ReferenceWriteOrder>| {
                matches!((order, other), (Some(order), Some(other)) if other > order)
            };
            let mut last = candidates
                .iter()
                .filter(|(order, _)| !candidates.iter().any(|(other, _)| written_later(*order, *other)))
                .map(|(_, value)| *value);
            let value = last.next().expect("a finite non-empty set has an unfollowed element");
            if last.any(|other| other != value) {
                return Err(Error::ProductData(ErrorDetail::new(format!(
                    "visible ParameterRefs assign conflicting values to stored parameter {id} without a defined write order"
                ))));
            }
            Ok((id, value.clone()))
        })
        .collect()
}

fn collect_procedure_parameters(
    evaluated: &EvaluatedProduct<'_>,
) -> Result<std::collections::BTreeMap<String, ProcedureParameter>> {
    let mut ids = std::collections::BTreeSet::new();
    for procedure in evaluated.product().load_procedures() {
        collect_choice_parameter_ids(&procedure.controls, &mut ids);
    }

    ids.into_iter()
        .map(|id| {
            let selector = evaluated.procedure_selector(&id).ok_or_else(|| {
                Error::ProductData(ErrorDetail::new(format!("load procedure references unknown parameter `{id}`")))
            })?;
            let value = match selector.value {
                ModelValue::Integer(value) => ProcedureParameterValue::Signed(*value),
                ModelValue::Text(value) => ProcedureParameterValue::Text(value.clone()),
                ModelValue::Bytes(value) => ProcedureParameterValue::Bytes(value.clone()),
                ModelValue::Float(_) => {
                    return Err(Error::ProductData(ErrorDetail::new(format!(
                        "load procedure parameter `{id}` uses a floating-point value, which `choose` cannot compare"
                    ))));
                }
            };
            Ok((id, ProcedureParameter { active: selector.active, value }))
        })
        .collect()
}

fn collect_choice_parameter_ids(controls: &[LoadControl], ids: &mut std::collections::BTreeSet<String>) {
    for control in controls {
        let LoadControl::Choose(choice) = control else { continue };
        ids.insert(choice.param_ref_id.clone());
        for branch in &choice.when {
            collect_choice_parameter_ids(&branch.controls, ids);
        }
    }
}

/// Encode one typed value into device-memory bytes.
///
/// Big-endian throughout — that is how ETS stores multi-byte
/// parameters, and the commissioning image compiler interprets
/// bit-packed values the same way.
fn encode_value(
    value: &ModelValue,
    type_def: Option<&ParameterTypeDef>,
    size_bits: u16,
) -> core::result::Result<Vec<u8>, String> {
    if let Some(ParameterTypeDef::TypeIpAddress(address)) = type_def {
        if size_bits != address.version.size_bits() {
            return Err(format!(
                "the storage location is {size_bits} bits but the {} address requires {} bits",
                address.version.name(),
                address.version.size_bits()
            ));
        }

        return match value {
            ModelValue::Text(value) => address
                .decode_value(value)
                .ok_or_else(|| format!("{value:?} is not a valid {} address", address.version.name())),
            _ => Err(format!("this parameter takes a textual {} address", address.version.name())),
        };
    }

    if let Some(ParameterTypeDef::TypeDate(date)) = type_def {
        if size_bits != date.size_bits() {
            return Err(format!(
                "the storage location is {size_bits} bits but the date encoding requires {} bits",
                date.size_bits()
            ));
        }

        return match value {
            ModelValue::Text(value) => date.encode_value(value),
            _ => Err("this parameter takes a YYYY-MM-DD date".to_string()),
        };
    }

    match value {
        ModelValue::Integer(i) => {
            if let Some(ParameterTypeDef::TypeRestriction(restriction)) = type_def
                && restriction.base == "BinaryValue"
            {
                let selected = u32::try_from(*i)
                    .ok()
                    .and_then(|value| restriction.enumerations.iter().find(|item| item.value == value))
                    .ok_or_else(|| format!("{i} does not select a binary enumeration"))?;
                // Missing BinaryValue is native null, which owns existing
                // storage without changing its bits. Reserve an empty stored
                // value for that state; an explicitly empty payload below is
                // padded to the declared width and remains distinct.
                let Some(encoded) = selected.binary_value.as_deref() else {
                    return Ok(Vec::new());
                };
                let mut bytes = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|error| format!("enumeration {} has invalid BinaryValue: {error}", selected.id))?;

                // The reference formatter resizes a shorter binary value to
                // the declared storage, appending zero bytes; a property
                // transfer then sends only the described element width
                // (witness: M-014B_A-0F18-02 PID 78, six bytes in 64 bits).
                // A longer value has no such rule.
                let expected = usize::from(size_bits.div_ceil(8));
                if bytes.len() > expected {
                    return Err(format!(
                        "enumeration {} decodes to {} bytes but its storage is {expected} bytes",
                        selected.id,
                        bytes.len()
                    ));
                }
                bytes.resize(expected, 0);

                return Ok(bytes);
            }

            if let Some(ParameterTypeDef::TypeTime(time)) = type_def {
                if size_bits != u16::from(time.size_in_bit) {
                    return Err(format!(
                        "the storage location is {size_bits} bits but the time type declares {} bits",
                        time.size_in_bit
                    ));
                }

                return time.encode_value(*i).ok_or_else(|| {
                    format!("{i} {} is outside the time type's range or storage width", time.unit.value_unit())
                });
            }

            if size_bits == 0 {
                return Err("an integer value needs a type-declared width to be encoded".to_string());
            }
            if size_bits > 64 {
                return Err(format!("{size_bits}-bit integers are not supported"));
            }
            // Two's-complement masking covers signedInt and
            // unsignedInt alike; range validation already happened in
            // `apply_configuration`.
            let mask = if size_bits == 64 { u64::MAX } else { (1u64 << size_bits) - 1 };
            let raw = (*i as u64) & mask;
            let width = usize::from(size_bits.div_ceil(8));
            Ok(raw.to_be_bytes()[8 - width..].to_vec())
        }
        ModelValue::Float(f) => match type_def {
            Some(ParameterTypeDef::TypeFloat(t)) if t.encoding.starts_with("DPT 9") => {
                Ok(KnxFloat16::from_f32(*f as f32).to_bytes().to_vec())
            }
            Some(ParameterTypeDef::TypeFloat(t)) if t.encoding.starts_with("DPT 14") => {
                Ok((*f as f32).to_be_bytes().to_vec())
            }
            Some(ParameterTypeDef::TypeFloat(t)) if t.encoding == "IEEE-754 Single" => {
                Ok((*f as f32).to_be_bytes().to_vec())
            }
            Some(ParameterTypeDef::TypeFloat(t)) if t.encoding == "IEEE-754 Double" => Ok(f.to_be_bytes().to_vec()),
            Some(ParameterTypeDef::TypeFloat(t)) => Err(format!("float encoding {:?} is not supported", t.encoding)),
            _ => Err("a float value on a non-float parameter type".to_string()),
        },
        ModelValue::Text(s) if let Some(ParameterTypeDef::TypeColor(color)) = type_def => {
            color.space.decode_value(s).ok_or_else(|| format!("{s:?} is not a valid {} colour", color.space.name()))
        }
        ModelValue::Text(s) => {
            // A text field owns its full width; shorter strings are
            // zero-padded so stale bytes cannot survive behind them. Authored
            // defaults may exceed that width: retain only complete UTF-8
            // characters, as the reference encoder does, without growing the
            // field into its neighbour. Zero denotes an unspecified width.
            let width = if size_bits == 0 { s.len() } else { usize::from(size_bits.div_ceil(8)) };
            let mut end = s.len().min(width);
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            let mut bytes = vec![0u8; width];
            bytes[..end].copy_from_slice(&s.as_bytes()[..end]);
            Ok(bytes)
        }
        ModelValue::Bytes(b) => Ok(b.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use zweidraehte_ets_files::product::SelectedProduct;
    use zweidraehte_ets_files::runtime::Device;
    use zweidraehte_ets_files::runtime::configuration::ProductConfiguration;

    #[test]
    fn load_procedure_choices_retain_ref_specific_typed_values() {
        let xml = zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML
            .replace(
                "        <Parameters>",
                r#"        <ParameterTypes>
          <ParameterType Id="M-00FA_A-0306-02-0000_PT-1" Name="Mode"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
        </ParameterTypes>
        <Parameters>"#,
            )
            .replace(
                "        </Parameters>",
                r#"        </Parameters>
        <ParameterRefs>
          <ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-1" RefId="M-00FA_A-0306-02-0000_P-1" Value="1" />
        </ParameterRefs>"#,
            )
            .replace(
                "            <LdCtrlConnect />",
                r#"            <LdCtrlConnect />
            <choose ParamRefId="M-00FA_A-0306-02-0000_P-1_R-1">
              <when test="1" />
            </choose>"#,
            );
        let knx = zweidraehte_ets_files::runtime::parser::parse_application_program(&xml).expect("fixture parses");
        let selected = SelectedProduct::from_document(knx, None, None).expect("product selection");
        let mut device = Device::from_product(Arc::new(selected), None, None);
        let settings = ProductConfiguration::default();
        zweidraehte_ets_files::runtime::configuration::apply_configuration(&mut device, &settings)
            .expect("default configuration applies");
        let configuration = InstallationConfiguration::new(zweidraehte_proto::address::IndividualAddress::new(1, 1, 1));

        let resolved = MaterializedDevice::from_evaluated(
            device.evaluate(&settings.objects).expect("checked configuration"),
            configuration,
        )
        .expect("configuration resolves");

        assert_eq!(
            resolved.procedure_parameters().get("M-00FA_A-0306-02-0000_P-1_R-1"),
            Some(&ProcedureParameter { active: true, value: ProcedureParameterValue::Signed(1) })
        );
        let selectors = resolved.procedure_parameters().clone();
        let materialized = resolved.into_keyed(crate::configuration::ResolvedKeyMaterial::default());
        assert_eq!(materialized.procedure_parameters(), &selectors);
        assert_eq!(materialized.max_apdu(), None);
    }

    #[test]
    fn stored_base_defaults_seed_the_download_even_when_not_visible() {
        let xml = zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML
            .replace(
                "        <Parameters>",
                r#"        <ParameterTypes>
          <ParameterType Id="M-00FA_A-0306-02-0000_PT-1" Name="Mode"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
        </ParameterTypes>
        <Parameters>"#,
            )
            .replace(r#"Text="Mode" Value="0""#, r#"Text="Mode" Value="7""#);
        let knx = zweidraehte_ets_files::runtime::parser::parse_application_program(&xml).expect("fixture parses");
        let selected = SelectedProduct::from_document(knx, None, None).expect("product selection");
        let mut device = Device::from_product(Arc::new(selected), None, None);
        let settings = ProductConfiguration::default();
        zweidraehte_ets_files::runtime::configuration::apply_configuration(&mut device, &settings)
            .expect("default configuration applies");
        let configuration = InstallationConfiguration::new(zweidraehte_proto::address::IndividualAddress::new(1, 1, 1));

        let resolved = MaterializedDevice::from_evaluated(
            device.evaluate(&settings.objects).expect("checked configuration"),
            configuration,
        )
        .expect("configuration resolves");
        assert_eq!(resolved.parameters().len(), 1);
        assert_eq!(resolved.parameters()[0].value, [7]);
        let materialized = resolved.into_keyed(crate::configuration::ResolvedKeyMaterial::default());
        assert_eq!(materialized.parameters()[0].value, [7]);
    }

    #[test]
    fn picture_parameters_with_a_memory_location_store_nothing() {
        let xml = zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML
            .replace(
                "        <Parameters>",
                r#"        <ParameterTypes>
          <ParameterType Id="M-00FA_A-0306-02-0000_PT-1" Name="Diagram"><TypePicture RefId="M-00FA_BG--DIAGRAM.png" /></ParameterType>
        </ParameterTypes>
        <Parameters>"#,
            )
            .replace(r#"Text="Mode" Value="0""#, r#"Text="Mode" Value="""#);
        let knx = zweidraehte_ets_files::runtime::parser::parse_application_program(&xml).expect("fixture parses");
        let selected = SelectedProduct::from_document(knx, None, None).expect("product selection");
        let mut device = Device::from_product(Arc::new(selected), None, None);
        let settings = ProductConfiguration::default();
        zweidraehte_ets_files::runtime::configuration::apply_configuration(&mut device, &settings)
            .expect("default configuration applies");
        let configuration = InstallationConfiguration::new(zweidraehte_proto::address::IndividualAddress::new(1, 1, 1));

        let resolved = MaterializedDevice::from_evaluated(
            device.evaluate(&settings.objects).expect("checked configuration"),
            configuration,
        )
        .expect("a picture needs no encoding");
        assert!(resolved.parameters().is_empty());
    }

    #[test]
    fn visible_reference_conflicts_compare_encoded_bytes() {
        // Distinct f64 values collapse to one IEEE single value. Comparing the
        // evaluator's semantic values would reject this valid shared storage.
        for (second_value, conflicts) in [("1.000000002", false), ("2", true)] {
            let xml = zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML
                .replace("        <Parameters>", r#"<ParameterTypes>
                  <ParameterType Id="M-00FA_A-0306-02-0000_PT-1" Name="Level"><TypeFloat Encoding="IEEE-754 Single" minInclusive="0" maxInclusive="10" /></ParameterType>
                </ParameterTypes><Parameters>"#)
                .replace(r#"Offset="2" BitOffset="0""#, r#"Offset="0" BitOffset="0""#)
                .replace("</Parameters>", &format!(r#"</Parameters><ParameterRefs>
                  <ParameterRef Id="first" RefId="M-00FA_A-0306-02-0000_P-1" Value="1.000000001" />
                  <ParameterRef Id="second" RefId="M-00FA_A-0306-02-0000_P-1" Value="{second_value}" />
                </ParameterRefs>"#))
                .replace("</ApplicationProgram>", r#"<Dynamic><ChannelIndependentBlock>
                  <ParameterBlock Id="levels" Text="Levels"><ParameterRefRef RefId="first" /><ParameterRefRef RefId="second" /></ParameterBlock>
                </ChannelIndependentBlock></Dynamic></ApplicationProgram>"#);
            let knx = zweidraehte_ets_files::runtime::parser::parse_application_program(&xml).expect("float fixture");
            let selected = SelectedProduct::from_document(knx, None, None).expect("float storage");
            let device = Device::from_product(Arc::new(selected), None, None);
            let evaluated = device.evaluate(&[]).expect("valid float values");
            assert_ne!(
                evaluated.procedure_selector("first").expect("first").value,
                evaluated.procedure_selector("second").expect("second").value
            );
            let installation =
                InstallationConfiguration::new(zweidraehte_proto::address::IndividualAddress::new(1, 1, 1));

            let resolved = MaterializedDevice::from_evaluated(evaluated, installation);
            if conflicts {
                assert!(resolved.expect_err("different bytes conflict").to_string().contains("conflicting values"));
            } else {
                let resolved = resolved.expect("equal bytes agree");
                let parameters = resolved.parameters();
                assert_eq!(parameters.len(), 2, "one seed and one deduplicated reference");
                assert_eq!(parameters[1].value, 1.0_f32.to_be_bytes());
            }
        }
    }

    /// Resolve the stored byte of `P-1` for authored references and a dynamic
    /// tree in which a `P-2` selector (default 0) may reveal some of them.
    fn stored_mode(references: &str, dynamic: &str) -> Result<Vec<EncodedParameter>> {
        const PREFIX: &str = "M-00FA_A-0306-02-0000";
        let xml = zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML
            .replace(
                "        <Parameters>",
                r#"        <ParameterTypes>
          <ParameterType Id="M-00FA_A-0306-02-0000_PT-1" Name="Mode"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
        </ParameterTypes>
        <Parameters>
          <Parameter Id="M-00FA_A-0306-02-0000_P-2" Name="Selector" ParameterType="M-00FA_A-0306-02-0000_PT-1" Text="Selector" Value="0" />"#,
            )
            .replace(
                "</Parameters>",
                &format!(
                    r#"</Parameters><ParameterRefs>
                  <ParameterRef Id="{PREFIX}_P-2_R-11" RefId="{PREFIX}_P-2" />{references}
                </ParameterRefs>"#
                ),
            )
            .replace(
                "</ApplicationProgram>",
                &format!(
                    r#"<Dynamic><ChannelIndependentBlock><ParameterBlock Id="{PREFIX}_PB-1" Text="Main">
                  <ParameterRefRef RefId="{PREFIX}_P-2_R-11" />{dynamic}
                </ParameterBlock></ChannelIndependentBlock></Dynamic></ApplicationProgram>"#
                ),
            );
        let knx = zweidraehte_ets_files::runtime::parser::parse_application_program(&xml).expect("fixture parses");
        let selected = SelectedProduct::from_document(knx, None, None).expect("product selection");
        let device = Device::from_product(Arc::new(selected), None, None);
        let installation = InstallationConfiguration::new(zweidraehte_proto::address::IndividualAddress::new(1, 1, 1));
        let resolved =
            MaterializedDevice::from_evaluated(device.evaluate(&[]).expect("default evaluation"), installation)?;
        Ok(resolved.parameters().iter().filter(|parameter| parameter.id == format!("{PREFIX}_P-1")).cloned().collect())
    }

    #[test]
    fn competing_visible_references_store_the_last_written_value() {
        // Shape of M-011F_A-0693-24 P-11: an always-visible reference and a
        // hidden one revealed by the selector's default. The higher reference
        // number is written later, compared numerically (R-126 after R-12).
        let parameters = stored_mode(
            r#"<ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-126" RefId="M-00FA_A-0306-02-0000_P-1" Access="None" Value="4" />
               <ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-12" RefId="M-00FA_A-0306-02-0000_P-1" Value="1" />"#,
            r#"<ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-1_R-12" />
               <choose ParamRefId="M-00FA_A-0306-02-0000_P-2_R-11"><when test="0">
                 <ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-1_R-126" />
               </when></choose>"#,
        )
        .expect("ordered references resolve");
        let values = parameters.iter().map(|parameter| parameter.value.clone()).collect::<Vec<_>>();
        assert_eq!(values, [vec![0], vec![4]], "the seed, then one reference entry");

        // Numeric order, not text order: R-10 follows R-9.
        let parameters = stored_mode(
            r#"<ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-9" RefId="M-00FA_A-0306-02-0000_P-1" Value="9" />
               <ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-10" RefId="M-00FA_A-0306-02-0000_P-1" Value="10" />"#,
            r#"<ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-1_R-10" />
               <ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-1_R-9" />"#,
        )
        .expect("numbered references resolve");
        assert_eq!(parameters.last().expect("reference entry").value, [10]);

        // A numeric tag follows every untagged reference, then ascends.
        let parameters = stored_mode(
            r#"<ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-1" RefId="M-00FA_A-0306-02-0000_P-1" Tag="7" Value="1" />
               <ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-2" RefId="M-00FA_A-0306-02-0000_P-1" Tag="3" Value="2" />
               <ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-3" RefId="M-00FA_A-0306-02-0000_P-1" Value="3" />"#,
            r#"<ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-1_R-1" />
               <ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-1_R-2" />
               <ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-1_R-3" />"#,
        )
        .expect("tagged references resolve");
        assert_eq!(parameters.last().expect("reference entry").value, [1]);
    }

    #[test]
    fn equally_tagged_references_must_agree() {
        // Equal tags leave the write order undefined. Agreement is harmless,
        // even when an earlier untagged reference differs.
        let agreeing = stored_mode(
            r#"<ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-1" RefId="M-00FA_A-0306-02-0000_P-1" Tag="5" Value="8" />
               <ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-2" RefId="M-00FA_A-0306-02-0000_P-1" Tag="5" Value="8" />
               <ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-3" RefId="M-00FA_A-0306-02-0000_P-1" Value="3" />"#,
            r#"<ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-1_R-1" />
               <ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-1_R-2" />
               <ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-1_R-3" />"#,
        )
        .expect("agreeing references resolve");
        assert_eq!(agreeing.last().expect("reference entry").value, [8]);

        let error = stored_mode(
            r#"<ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-1" RefId="M-00FA_A-0306-02-0000_P-1" Tag="5" Value="8" />
               <ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-2" RefId="M-00FA_A-0306-02-0000_P-1" Tag="5" Value="9" />"#,
            r#"<ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-1_R-1" />
               <ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-1_R-2" />"#,
        )
        .expect_err("disagreeing references have no defined winner");
        assert!(error.to_string().contains("without a defined write order"), "{error}");
    }

    #[test]
    fn stored_calculation_results_reach_the_download_and_defaults_run_no_script() {
        let xml = zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML
            .replace(
                "        <Parameters>",
                r#"        <ParameterTypes>
          <ParameterType Id="M-00FA_A-0306-02-0000_PT-1" Name="Number"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
        </ParameterTypes>
        <Parameters>"#,
            )
            .replace(
                "        </Parameters>",
                r#"          <Parameter Id="M-00FA_A-0306-02-0000_P-2" Name="Derived" ParameterType="M-00FA_A-0306-02-0000_PT-1" Text="Derived" Value="0"><Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="3" BitOffset="0" /></Parameter>
        </Parameters>
        <ParameterRefs>
          <ParameterRef Id="M-00FA_A-0306-02-0000_P-1_R-1" RefId="M-00FA_A-0306-02-0000_P-1" />
          <ParameterRef Id="M-00FA_A-0306-02-0000_P-2_R-2" RefId="M-00FA_A-0306-02-0000_P-2" Access="None" />
        </ParameterRefs>
        <ParameterCalculations>
          <ParameterCalculation Id="M-00FA_A-0306-02-0000_PC-1" Language="JavaScript" Name="Triple">
            <LRTransformation>target = source * 3;</LRTransformation>
            <LParameters><ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-1_R-1" AliasName="source" /></LParameters>
            <RParameters><ParameterRefRef RefId="M-00FA_A-0306-02-0000_P-2_R-2" AliasName="target" /></RParameters>
          </ParameterCalculation>
        </ParameterCalculations>"#,
            )
            .replace(r#"Text="Mode" Value="0""#, r#"Text="Mode" Value="7""#);
        for property_backed in [false, true] {
            let xml = if property_backed {
                xml.replace(
                    r#"<Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="3" BitOffset="0" />"#,
                    r#"<Property ObjectIndex="3" PropertyId="100" Offset="0" BitOffset="0" />"#,
                )
            } else {
                xml.clone()
            };
            let knx = zweidraehte_ets_files::runtime::parser::parse_application_program(&xml).expect("fixture parses");
            // Defaults never run the product's scripts, so the hidden target
            // keeps its own default although `Triple` would compute 21. A
            // project which stores the calculation's result downloads it.
            for (stored, expected) in [(None, 0), (Some(21), 21)] {
                let selected = SelectedProduct::from_document(knx.clone(), None, None).expect("product selection");
                let mut device = Device::from_product(Arc::new(selected), None, None);
                let settings = ProductConfiguration {
                    parameters: stored
                        .into_iter()
                        .map(|value| zweidraehte_ets_files::runtime::configuration::ParameterSetting {
                            id: "M-00FA_A-0306-02-0000_P-2_R-2".to_owned(),
                            value: ModelValue::Integer(value),
                        })
                        .collect(),
                    objects: Vec::new(),
                };
                zweidraehte_ets_files::runtime::configuration::apply_configuration(&mut device, &settings)
                    .expect("stored configuration applies");
                let configuration =
                    InstallationConfiguration::new(zweidraehte_proto::address::IndividualAddress::new(1, 1, 1));

                let resolved = MaterializedDevice::from_evaluated(
                    device.evaluate(&settings.objects).expect("checked configuration"),
                    configuration,
                )
                .expect("configuration resolves");
                assert_eq!(
                    resolved
                        .parameters()
                        .iter()
                        .find(|parameter| parameter.id == "M-00FA_A-0306-02-0000_P-2")
                        .expect("the target's storage is present")
                        .value,
                    [expected]
                );
            }
        }
    }

    #[test]
    fn integers_encode_big_endian_and_masked() {
        assert_eq!(encode_value(&ModelValue::Integer(0x1234), None, 16).expect("encodes"), [0x12, 0x34]);
        // Negative values wrap into the field's two's complement.
        assert_eq!(encode_value(&ModelValue::Integer(-1), None, 8).expect("encodes"), [0xFF]);
        // Sub-byte fields occupy one byte for the bit patcher.
        assert_eq!(encode_value(&ModelValue::Integer(5), None, 4).expect("encodes"), [0x05]);
        assert!(encode_value(&ModelValue::Integer(1), None, 0).is_err(), "no width, no encoding");
    }

    #[test]
    fn binary_restriction_distinguishes_null_from_an_empty_payload() {
        let restriction = |encoded| {
            ParameterTypeDef::TypeRestriction(zweidraehte_ets_files::schema::TypeRestriction {
                base: "BinaryValue".to_owned(),
                size_in_bit: 8,
                enumerations: vec![zweidraehte_ets_files::schema::Enumeration {
                    text: "hardware record".to_owned(),
                    value: 0,
                    binary_value: encoded,
                    id: "hardware-type_EN-0".to_owned(),
                }],
            })
        };
        assert_eq!(
            encode_value(&ModelValue::Integer(0), Some(&restriction(None)), 8).expect("null binary value encodes"),
            Vec::<u8>::new()
        );
        assert_eq!(
            encode_value(&ModelValue::Integer(0), Some(&restriction(Some(String::new()))), 8)
                .expect("empty binary value pads its field"),
            [0]
        );
        assert!(encode_value(&ModelValue::Integer(1), Some(&restriction(None)), 8).is_err());
    }

    #[test]
    fn binary_restrictions_encode_the_selected_payload() {
        let restriction = ParameterTypeDef::TypeRestriction(zweidraehte_ets_files::schema::TypeRestriction {
            base: "BinaryValue".to_string(),
            size_in_bit: 48,
            enumerations: vec![zweidraehte_ets_files::schema::Enumeration {
                text: "hardware record".to_string(),
                value: 7,
                binary_value: Some("AIMAAAMo".to_string()),
                id: "PT-HWT_EN-7".to_string(),
            }],
        });

        assert_eq!(encode_value(&ModelValue::Integer(7), Some(&restriction), 48).expect("binary value encodes"), [
            0x00, 0x83, 0x00, 0x00, 0x03, 0x28
        ]);
        assert!(encode_value(&ModelValue::Integer(0), Some(&restriction), 48).is_err());

        // A shorter payload fills its declared storage with trailing zeros;
        // a longer one does not fit.
        assert_eq!(encode_value(&ModelValue::Integer(7), Some(&restriction), 64).expect("short value pads"), [
            0x00, 0x83, 0x00, 0x00, 0x03, 0x28, 0x00, 0x00
        ]);
        assert!(encode_value(&ModelValue::Integer(7), Some(&restriction), 40).is_err());
    }

    #[test]
    fn colours_encode_as_channel_octets_not_text() {
        let color = ParameterTypeDef::TypeColor(zweidraehte_ets_files::schema::TypeColor {
            space: zweidraehte_ets_files::schema::ColorSpace::Rgb,
        });
        assert_eq!(encode_value(&ModelValue::Text("#12ABEF".into()), Some(&color), 24).expect("colour encodes"), [
            0x12, 0xAB, 0xEF
        ]);
        assert!(encode_value(&ModelValue::Text("red".into()), Some(&color), 24).is_err());
    }

    #[test]
    fn ip_addresses_encode_in_their_declared_family_and_width() {
        use zweidraehte_ets_files::schema::{IpAddressVersion, TypeIpAddress};

        let ipv4 = ParameterTypeDef::TypeIpAddress(TypeIpAddress {
            address_type: "HostAddress".into(),
            version: IpAddressVersion::Ipv4,
        });
        assert_eq!(encode_value(&ModelValue::Text("192.168.1.135".into()), Some(&ipv4), 32).expect("IPv4 encodes"), [
            192, 168, 1, 135
        ]);
        for value in ["", "192.168.1.256", "1.2.3.4.5", "0x1G", "::1"] {
            assert!(encode_value(&ModelValue::Text(value.into()), Some(&ipv4), 32).is_err());
        }
        // Abbreviated numeric forms parse as the reference parser does.
        for (value, expected) in [("0", [0, 0, 0, 0]), ("127.1", [127, 0, 0, 1]), ("0xC0.0250.1.1", [192, 168, 1, 1])] {
            assert_eq!(encode_value(&ModelValue::Text(value.into()), Some(&ipv4), 32).expect("IPv4 encodes"), expected);
        }
        assert!(encode_value(&ModelValue::Integer(0), Some(&ipv4), 32).is_err());
        assert!(encode_value(&ModelValue::Text("1.2.3.4".into()), Some(&ipv4), 0).is_err());

        let ipv6 = ParameterTypeDef::TypeIpAddress(TypeIpAddress {
            address_type: "HostAddress".into(),
            version: IpAddressVersion::Ipv6,
        });
        assert_eq!(
            encode_value(&ModelValue::Text("2001:db8:abcd::1234".into()), Some(&ipv6), 128).expect("IPv6 encodes"),
            [0x20, 1, 0x0d, 0xb8, 0xab, 0xcd, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34]
        );
        assert!(encode_value(&ModelValue::Text("1.2.3.4".into()), Some(&ipv6), 128).is_err());
        assert!(encode_value(&ModelValue::Text("::1".into()), Some(&ipv6), 32).is_err());
    }

    #[test]
    fn stored_ip_default_and_visible_ref_keep_four_octets_before_the_next_field() {
        let xml = zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML
            .replace("        <Parameters>", r#"<ParameterTypes>
              <ParameterType Id="M-00FA_A-0306-02-0000_PT-1" Name="IP"><TypeIPAddress AddressType="HostAddress"/></ParameterType>
              <ParameterType Id="PT-BYTE" Name="Adjacent"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255"/></ParameterType>
            </ParameterTypes><Parameters>"#)
            .replace(r#"Text="Mode" Value="0""#, r#"Text="Mode" Value="192.168.1.135""#)
            .replace(r#"Offset="2" BitOffset="0""#, r#"Offset="0" BitOffset="0""#)
            .replace(r#"Size="4" MemoryType="EEPROM""#, r#"Size="5" MemoryType="EEPROM""#)
            .replace("</Parameters>", r#"<Parameter Id="adjacent" Name="Adjacent" Text="Adjacent" ParameterType="PT-BYTE" Value="85">
              <Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="4" BitOffset="0"/>
            </Parameter></Parameters><ParameterRefs>
              <ParameterRef Id="ip-ref" RefId="M-00FA_A-0306-02-0000_P-1" Value="10.20.30.40"/>
            </ParameterRefs>"#)
            .replace("</ApplicationProgram>", r#"<Dynamic><ChannelIndependentBlock><ParameterBlock Id="ip" Text="IP">
              <ParameterRefRef RefId="ip-ref"/>
            </ParameterBlock></ChannelIndependentBlock></Dynamic></ApplicationProgram>"#);
        let knx = zweidraehte_ets_files::runtime::parser::parse_application_program(&xml).expect("IP fixture parses");
        let selected = SelectedProduct::from_document(knx, None, None).expect("IP product selection");
        let device = Device::from_product(Arc::new(selected), None, None);
        let resolved = MaterializedDevice::from_evaluated(
            device.evaluate(&[]).expect("checked IP values"),
            InstallationConfiguration::new(zweidraehte_proto::address::IndividualAddress::new(1, 1, 1)),
        )
        .expect("IP configuration resolves");

        let addresses: Vec<_> = resolved
            .parameters()
            .iter()
            .filter(|parameter| parameter.id == "M-00FA_A-0306-02-0000_P-1")
            .map(|parameter| parameter.value.as_slice())
            .collect();
        assert_eq!(addresses, [vec![192, 168, 1, 135], vec![10, 20, 30, 40]]);
        assert_eq!(
            resolved.parameters().iter().find(|parameter| parameter.id == "adjacent").expect("adjacent default").value,
            [85]
        );
    }

    #[test]
    fn time_values_use_the_declared_integer_basis_and_width() {
        let time = ParameterTypeDef::TypeTime(zweidraehte_ets_files::schema::TypeTime {
            size_in_bit: 24,
            unit: zweidraehte_ets_files::schema::TimeUnit::PackedDaysHoursMinutesAndSeconds,
            min_inclusive: 0,
            max_inclusive: 691_199,
            ui_hint: Some("Duration_hhmmss".to_string()),
        });

        assert_eq!(encode_value(&ModelValue::Integer(86_400), Some(&time), 24).expect("time encodes"), [
            0x01, 0x51, 0x80
        ]);
        assert!(encode_value(&ModelValue::Integer(691_200), Some(&time), 24).is_err());
        assert!(encode_value(&ModelValue::Integer(60), Some(&time), 16).is_err());
    }

    #[test]
    fn text_pads_to_its_field_width() {
        assert_eq!(encode_value(&ModelValue::Text("AB".to_string()), None, 32).expect("encodes"), [
            0x41, 0x42, 0x00, 0x00
        ]);
    }

    #[test]
    fn authored_text_defaults_fit_their_byte_width_without_splitting_characters() {
        for (text, size_bits, expected) in [
            ("Leicht bewölkt", 112, "Leicht bewölk".as_bytes()),
            ("AäB", 16, &[0x41, 0x00][..]),
            ("Aä", 24, &[0x41, 0xC3, 0xA4][..]),
            ("AB", 32, &[0x41, 0x42, 0x00, 0x00][..]),
        ] {
            let text_type = ParameterTypeDef::TypeText(zweidraehte_ets_files::schema::TypeText {
                size_in_bit: u32::from(size_bits),
                pattern: None,
            });
            assert_eq!(
                encode_value(&ModelValue::Text(text.to_owned()), Some(&text_type), size_bits).expect("text encodes"),
                expected,
                "{text:?} in {size_bits} bits"
            );
        }
    }

    #[test]
    fn dpt9_floats_use_the_knx_float_coding() {
        let t = ParameterTypeDef::TypeFloat(zweidraehte_ets_files::schema::TypeFloat {
            encoding: "DPT 9".to_string(),
            min_inclusive: -100.0,
            max_inclusive: 100.0,
        });
        let bytes = encode_value(&ModelValue::Float(21.0), Some(&t), 0).expect("encodes");
        assert_eq!(KnxFloat16::from_bytes([bytes[0], bytes[1]]).to_f32(), 21.0);
    }

    #[test]
    fn dpt14_floats_use_ieee_754_network_order() {
        let t = ParameterTypeDef::TypeFloat(zweidraehte_ets_files::schema::TypeFloat {
            encoding: "DPT 14".to_string(),
            min_inclusive: -1.0e12,
            max_inclusive: 1.0e12,
        });
        assert_eq!(encode_value(&ModelValue::Float(21.5), Some(&t), 0).expect("encodes"), 21.5f32.to_be_bytes());
    }

    #[test]
    fn explicit_ieee_floats_use_the_declared_width() {
        let single = ParameterTypeDef::TypeFloat(zweidraehte_ets_files::schema::TypeFloat {
            encoding: "IEEE-754 Single".to_string(),
            min_inclusive: f64::MIN,
            max_inclusive: f64::MAX,
        });
        let double = ParameterTypeDef::TypeFloat(zweidraehte_ets_files::schema::TypeFloat {
            encoding: "IEEE-754 Double".to_string(),
            min_inclusive: f64::MIN,
            max_inclusive: f64::MAX,
        });

        assert_eq!(
            encode_value(&ModelValue::Float(21.5), Some(&single), 32).expect("single encodes"),
            21.5f32.to_be_bytes()
        );
        assert_eq!(
            encode_value(&ModelValue::Float(21.5), Some(&double), 64).expect("double encodes"),
            21.5f64.to_be_bytes()
        );
    }
}
