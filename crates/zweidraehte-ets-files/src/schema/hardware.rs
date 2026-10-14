//! Hardware MTXML schema types.

use serde::{Deserialize, Serialize};

// ============================================================================
// Hardware MTXML Schema Types
// ============================================================================

/// Root element for Hardware MTXML files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "KNX")]
pub struct HardwareKnx {
    #[serde(rename = "@xmlns:xsi", alias = "@xsi", default, skip_serializing_if = "String::is_empty")]
    pub xmlns_xsi: String,
    #[serde(rename = "@xmlns:xsd", alias = "@xsd", default, skip_serializing_if = "String::is_empty")]
    pub xmlns_xsd: String,
    #[serde(rename = "@CreatedBy", default, skip_serializing_if = "String::is_empty")]
    pub created_by: String,
    #[serde(rename = "@ToolVersion", default, skip_serializing_if = "String::is_empty")]
    pub tool_version: String,
    #[serde(rename = "@xmlns")]
    pub xmlns: String,
    #[serde(rename = "ManufacturerData")]
    pub manufacturer_data: HardwareManufacturerData,
}

impl Default for HardwareKnx {
    fn default() -> Self {
        Self {
            xmlns_xsi: "http://www.w3.org/2001/XMLSchema-instance".to_string(),
            xmlns_xsd: "http://www.w3.org/2001/XMLSchema".to_string(),
            created_by: "zweidraehte".to_string(),
            tool_version: "0.1.0".to_string(),
            xmlns: "http://knx.org/xml/project/23".to_string(),
            manufacturer_data: HardwareManufacturerData::default(),
        }
    }
}

/// ManufacturerData wrapper for Hardware files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardwareManufacturerData {
    #[serde(rename = "Manufacturer")]
    pub manufacturer: HardwareManufacturer,
}

/// Manufacturer element containing Hardware definitions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardwareManufacturer {
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    #[serde(rename = "Hardware")]
    pub hardware: HardwareContainer,
}

/// Container for Hardware elements.
///
/// Wraps a `Vec<Hardware>` but serializes each element as `<Hardware>`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardwareContainer {
    #[serde(rename = "Hardware", default)]
    pub hardware: Vec<Hardware>,
}

/// Hardware definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hardware {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@SerialNumber")]
    pub serial_number: String,
    #[serde(rename = "@VersionNumber")]
    pub version_number: u16,
    #[serde(rename = "@BusCurrent", skip_serializing_if = "Option::is_none")]
    pub bus_current: Option<f32>,
    #[serde(rename = "@HasIndividualAddress")]
    pub has_individual_address: bool,
    /// Whether this hardware is capable of carrying an application program.
    /// An individual hardware-to-program relation may still bind none.
    #[serde(rename = "@HasApplicationProgram")]
    pub has_application_program: bool,
    /// Whether this hardware is capable of carrying a second application
    /// program. An individual hardware-to-program relation may still bind
    /// fewer programs. The KNX schema defaults an omitted attribute to `false`.
    #[serde(rename = "@HasApplicationProgram2", default, skip_serializing_if = "is_false")]
    pub has_application_program_2: bool,
    #[serde(rename = "@IsIPEnabled", skip_serializing_if = "Option::is_none")]
    pub is_ip_enabled: Option<bool>,
    /// `Hardware/@IsRFRetransmitter` — whether this RF device acts as a
    /// retransmitter (repeater) on the KNX-RF medium. Registration-relevant.
    #[serde(rename = "@IsRFRetransmitter", skip_serializing_if = "Option::is_none")]
    pub is_rf_retransmitter: Option<bool>,
    /// `Hardware/@RFRxCapabilities` — RF receive capability class
    /// (`Ready` / `ReadyFast` / `Slow`). Registration-relevant.
    #[serde(rename = "@RFRxCapabilities", skip_serializing_if = "Option::is_none")]
    pub rf_rx_capabilities: Option<String>,
    /// `Hardware/@RFTxCapabilities` — RF transmit capability class
    /// (`Ready` / `ReadyFast` / `ReadyFastSlow`). Registration-relevant.
    #[serde(rename = "@RFTxCapabilities", skip_serializing_if = "Option::is_none")]
    pub rf_tx_capabilities: Option<String>,
    #[serde(rename = "Products")]
    pub products: Products,
    #[serde(rename = "Hardware2Programs")]
    pub hardware2programs: Hardware2Programs,
}

impl Default for Hardware {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            serial_number: String::new(),
            version_number: 1,
            bus_current: None,
            has_individual_address: true,
            has_application_program: true,
            has_application_program_2: false,
            is_ip_enabled: None,
            is_rf_retransmitter: None,
            rf_rx_capabilities: None,
            rf_tx_capabilities: None,
            products: Products::default(),
            hardware2programs: Hardware2Programs::default(),
        }
    }
}

/// Container for Product elements.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Products {
    #[serde(rename = "Product", default)]
    pub products: Vec<Product>,
}

/// Product definition within Hardware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Product {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Text")]
    pub text: String,
    #[serde(rename = "@OrderNumber")]
    pub order_number: String,
    #[serde(rename = "@IsRailMounted")]
    pub is_rail_mounted: bool,
    #[serde(rename = "@VisibleDescription", skip_serializing_if = "Option::is_none")]
    pub visible_description: Option<String>,
    /// Optional in the KNX schema (only `ApplicationProgram` requires it);
    /// older and converted products omit it. Empty means "not declared".
    #[serde(rename = "@DefaultLanguage", default)]
    pub default_language: String,
}

impl Default for Product {
    fn default() -> Self {
        Self {
            id: String::new(),
            text: String::new(),
            order_number: String::new(),
            is_rail_mounted: false,
            visible_description: None,
            default_language: "en-US".to_string(),
        }
    }
}

/// Container for Hardware2Program elements.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hardware2Programs {
    #[serde(rename = "Hardware2Program")]
    pub hardware2programs: Vec<Hardware2Program>,
}

/// Links Hardware to ApplicationProgram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hardware2Program {
    #[serde(rename = "@Id")]
    pub id: String,
    /// The schema makes this IDREFS attribute optional. Do not invent `MT-0`
    /// while reading an older package: an empty value preserves the absence
    /// so relation/application validation can apply the applicable schema rule.
    #[serde(rename = "@MediumTypes", default)]
    pub medium_types: String,
    /// Ordered application-program references. The first reference is AP1 and
    /// an optional second reference is AP2. `Hardware/@HasApplicationProgram2`
    /// must advertise the capability before a relation may carry AP2, but it
    /// does not require every relation to carry two references.
    ///
    /// This remains a `Vec` at the schema boundary so malformed documents do
    /// not silently lose a third reference. Use
    /// [`HardwareKnx::resolve_application_program_pairing`] to enforce the
    /// schema's zero-to-two reference contract and the hardware capabilities.
    #[serde(rename = "ApplicationProgramRef", default)]
    pub application_program_refs: Vec<ApplicationProgramRef>,
}

impl Default for Hardware2Program {
    fn default() -> Self {
        Self {
            id: String::new(),
            medium_types: "MT-0".to_string(),
            application_program_refs: vec![ApplicationProgramRef::default()],
        }
    }
}

/// Reference to an ApplicationProgram.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplicationProgramRef {
    #[serde(rename = "@RefId")]
    pub ref_id: String,
}

fn is_false(value: &bool) -> bool {
    !*value
}

// ============================================================================
// AP1/AP2 Hardware Relation Resolution
// ============================================================================

/// The second application-program declaration in a hardware relation.
///
/// `Absent` is authoritative: it means the matching `Hardware2Program`
/// relation binds AP1 only. This is independent of the hardware's AP2
/// capability. Callers use `None` from
/// [`HardwareKnx::resolve_application_program_pairing`] for the distinct case
/// where no matching relation was available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardwareApplicationProgram2 {
    Absent,
    Present { application_program_id: String },
}

/// One validated, ordered `Hardware2Program` AP1/AP2 relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareApplicationProgramPairing {
    pub hardware_id: String,
    pub hardware2program_id: String,
    pub application_program_id: String,
    pub application_program_2: HardwareApplicationProgram2,
}

/// Contradictions in the AP1/AP2 metadata owned by `Hardware.xml`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HardwareApplicationProgramError {
    #[error(
        "application program {application_program_id:?} belongs to manufacturer {expected:?}, but Hardware.xml belongs to {actual:?}"
    )]
    ManufacturerMismatch { application_program_id: String, expected: String, actual: String },
    #[error(
        "application-program XML schema {application_namespace:?} conflicts with Hardware.xml schema {hardware_namespace:?}"
    )]
    SchemaConflict { application_namespace: String, hardware_namespace: String },
    #[error(
        "hardware {hardware_id:?} relation {hardware2program_id:?} contains {count} application-program references; expected at most two"
    )]
    InvalidReferenceCount { hardware_id: String, hardware2program_id: String, count: usize },
    #[error(
        "application program {application_program_id:?} is the second reference of hardware {hardware_id:?} relation {hardware2program_id:?}, not its AP1 reference"
    )]
    SelectedProgramIsApplicationProgram2 {
        application_program_id: String,
        hardware_id: String,
        hardware2program_id: String,
    },
    #[error(
        "application program {application_program_id:?} matches {count} hardware relations; select one unambiguously"
    )]
    AmbiguousRelation { application_program_id: String, count: usize },
    #[error(
        "application program {application_program_id:?} has ProgramType={actual:?}; an AP1 hardware reference requires ProgramType=\"ApplicationProgram\""
    )]
    InvalidPrimaryProgramType { application_program_id: String, actual: String },
}

impl Hardware {
    /// Validate the capabilities required by one relation, independently of
    /// archive completeness, catalogue selection and registration policy.
    pub(crate) fn validate_application_program_relation(
        &self,
        relation: &Hardware2Program,
    ) -> Result<(), HardwareApplicationProgramError> {
        let count = relation.application_program_refs.len();
        if count > 2 {
            return Err(HardwareApplicationProgramError::InvalidReferenceCount {
                hardware_id: self.id.clone(),
                hardware2program_id: relation.id.clone(),
                count,
            });
        }

        // Capabilities permit bindings but do not require them: hardware-only
        // catalogue entries legitimately bind no application at all.
        //
        // The converse is not checked either. Catalogue products such as
        // M-00B6_H-00000014-1 and the M-007C RF USB interface declare
        // `HasApplicationProgram="false"` yet bind an application, and
        // M-0002_H-6108.2F06.2DBS.2D500-0-O0007 declares
        // `HasApplicationProgram2="false"` yet binds a second one. ETS imports
        // and programs them: its catalogue-item hardware view derives both
        // flags from the relation (`Hardware2ProgramId.ApplicationProgramId`
        // and `ApplicationProgram2Id != null`) rather than from the
        // attributes. The relation therefore wins.
        Ok(())
    }
}

impl HardwareKnx {
    /// Enumerate exact catalogue chains without choosing a caller's policy for
    /// missing or ambiguous metadata. Keeping all candidates lets strict
    /// package indexing detect duplicate selectors instead of taking the first.
    #[cfg(feature = "archives")]
    pub(crate) fn product_relations<'a>(
        &'a self,
        product_id: &'a str,
        hardware2program_id: &'a str,
    ) -> impl Iterator<Item = (&'a Hardware, &'a Product, &'a Hardware2Program)> {
        self.manufacturer_data.manufacturer.hardware.hardware.iter().flat_map(move |hardware| {
            hardware.products.products.iter().filter(move |product| product.id == product_id).flat_map(move |product| {
                hardware
                    .hardware2programs
                    .hardware2programs
                    .iter()
                    .filter(move |relation| relation.id == hardware2program_id)
                    .map(move |relation| (hardware, product, relation))
            })
        })
    }

    /// Prove that a sibling hardware document uses the selected application
    /// document's schema. Namespace-free converted applications cannot provide
    /// this proof, so only that explicit unknown case bypasses the comparison.
    pub fn validate_application_schema(
        &self,
        application_namespace: &str,
    ) -> Result<(), HardwareApplicationProgramError> {
        if application_namespace.is_empty()
            || application_namespace.trim_end_matches('/') == self.xmlns.trim_end_matches('/')
        {
            return Ok(());
        }

        Err(HardwareApplicationProgramError::SchemaConflict {
            application_namespace: application_namespace.to_owned(),
            hardware_namespace: self.xmlns.clone(),
        })
    }

    /// Resolve one selected AP1 through the ordered references in
    /// `Hardware.xml`.
    ///
    /// `Ok(None)` means this document contains no relation for the selected
    /// AP1. `Some(...Absent)` and `Some(...Present { .. })` are authoritative.
    /// Supplying `program_type` also proves that the selected first reference
    /// is an ordinary `ApplicationProgram`; pass `None` when only the hardware
    /// document is available.
    pub fn resolve_application_program_pairing(
        &self,
        application_program_id: &str,
        program_type: Option<&str>,
    ) -> Result<Option<HardwareApplicationProgramPairing>, HardwareApplicationProgramError> {
        self.resolve_pairing_from_relations(
            application_program_id,
            program_type,
            self.manufacturer_data.manufacturer.hardware.hardware.iter().flat_map(|hardware| {
                hardware.hardware2programs.hardware2programs.iter().map(move |relation| (hardware, relation))
            }),
        )
    }

    fn resolve_pairing_from_relations<'a>(
        &'a self,
        application_program_id: &str,
        program_type: Option<&str>,
        relations: impl IntoIterator<Item = (&'a Hardware, &'a Hardware2Program)>,
    ) -> Result<Option<HardwareApplicationProgramPairing>, HardwareApplicationProgramError> {
        if let Some((expected, _)) = application_program_id.split_once("_A-") {
            let actual = &self.manufacturer_data.manufacturer.ref_id;
            if actual != expected {
                return Err(HardwareApplicationProgramError::ManufacturerMismatch {
                    application_program_id: application_program_id.to_owned(),
                    expected: expected.to_owned(),
                    actual: actual.clone(),
                });
            }
        }

        let mut matches = Vec::new();
        let mut secondary_match = None;

        for (hardware, relation) in relations {
            hardware.validate_application_program_relation(relation)?;
            let [primary, rest @ ..] = relation.application_program_refs.as_slice() else {
                continue;
            };
            if primary.ref_id == application_program_id {
                let application_program_2 = match rest {
                    [] => HardwareApplicationProgram2::Absent,
                    [secondary] => {
                        HardwareApplicationProgram2::Present { application_program_id: secondary.ref_id.clone() }
                    }
                    _ => unreachable!("more than two references return above"),
                };
                matches.push(HardwareApplicationProgramPairing {
                    hardware_id: hardware.id.clone(),
                    hardware2program_id: relation.id.clone(),
                    application_program_id: primary.ref_id.clone(),
                    application_program_2,
                });
            } else if rest.iter().any(|reference| reference.ref_id == application_program_id) {
                secondary_match = Some((hardware.id.clone(), relation.id.clone()));
            }
        }

        let pairing = match matches.len() {
            0 => {
                if let Some((hardware_id, hardware2program_id)) = secondary_match {
                    return Err(HardwareApplicationProgramError::SelectedProgramIsApplicationProgram2 {
                        application_program_id: application_program_id.to_owned(),
                        hardware_id,
                        hardware2program_id,
                    });
                }
                return Ok(None);
            }
            1 => matches.pop().expect("one matching relation remains"),
            count => {
                return Err(HardwareApplicationProgramError::AmbiguousRelation {
                    application_program_id: application_program_id.to_owned(),
                    count,
                });
            }
        };

        if let Some(actual) = program_type
            && actual != "ApplicationProgram"
        {
            return Err(HardwareApplicationProgramError::InvalidPrimaryProgramType {
                application_program_id: application_program_id.to_owned(),
                actual: actual.to_owned(),
            });
        }

        Ok(Some(pairing))
    }

    /// Resolve AP1/AP2 through one catalogue-selected hardware relation.
    ///
    /// This is the precise archive path: `CatalogItem` already names the
    /// `Hardware2Program`, so another relation for the same AP1 must not make
    /// selection ambiguous. `None` means either exact ID does not exist or the
    /// selected relation does not name this program. Selecting its AP2 returns
    /// an error, just as unscoped resolution does.
    pub fn resolve_application_program_pairing_in_relation(
        &self,
        hardware_id: &str,
        hardware2program_id: &str,
        application_program_id: &str,
        program_type: Option<&str>,
    ) -> Result<Option<HardwareApplicationProgramPairing>, HardwareApplicationProgramError> {
        let mut relations = self
            .manufacturer_data
            .manufacturer
            .hardware
            .hardware
            .iter()
            .filter(|hardware| hardware.id == hardware_id)
            .flat_map(|hardware| {
                hardware
                    .hardware2programs
                    .hardware2programs
                    .iter()
                    .filter(move |relation| relation.id == hardware2program_id)
                    .map(move |relation| (hardware, relation))
            })
            .peekable();
        if relations.peek().is_none() {
            return Ok(None);
        }

        self.resolve_pairing_from_relations(application_program_id, program_type, relations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = r#"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="test" ToolVersion="1" xmlns="http://knx.org/xml/project/23""#;
    const AP1: &str = "M-00FA_A-0001-01-0000";
    const AP2: &str = "M-00FA_A-0002-01-0000";

    fn hardware(has_ap2: Option<bool>, refs: &[&str]) -> HardwareKnx {
        hardware_with_application_program(true, has_ap2, refs)
    }

    fn hardware_with_application_program(
        has_application_program: bool,
        has_ap2: Option<bool>,
        refs: &[&str],
    ) -> HardwareKnx {
        let has_ap2 = has_ap2.map(|value| format!(r#" HasApplicationProgram2="{value}""#)).unwrap_or_default();
        let refs = refs.iter().map(|id| format!(r#"<ApplicationProgramRef RefId="{id}"/>"#)).collect::<String>();
        let xml = format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><Hardware><Hardware Id="M-00FA_H-1" Name="Hardware" SerialNumber="1" VersionNumber="1" HasIndividualAddress="true" HasApplicationProgram="{has_application_program}"{has_ap2}><Products><Product Id="M-00FA_H-1_P-1" Text="Fixture" OrderNumber="F-1" IsRailMounted="false" DefaultLanguage="en-US"/></Products><Hardware2Programs><Hardware2Program Id="M-00FA_H-1_HP-1" MediumTypes="MT-0">{refs}</Hardware2Program></Hardware2Programs></Hardware></Hardware></Manufacturer></ManufacturerData></KNX>"#
        );
        crate::xml::from_str(&xml).expect("hardware fixture parses")
    }

    #[test]
    fn exact_relation_ignores_unselected_metadata_but_validates_its_own_binding() {
        let mut document = hardware(Some(true), &[AP1, AP2]);
        let hardware = &mut document.manufacturer_data.manufacturer.hardware.hardware[0];
        let mut unrelated = hardware.hardware2programs.hardware2programs[0].clone();
        unrelated.id = "M-00FA_H-1_HP-OTHER".to_owned();
        unrelated.application_program_refs.push(unrelated.application_program_refs[0].clone());
        hardware.hardware2programs.hardware2programs.push(unrelated);

        assert!(matches!(
            document.resolve_application_program_pairing(AP1, None),
            Err(HardwareApplicationProgramError::InvalidReferenceCount { count: 3, .. })
        ));
        let selected = document
            .resolve_application_program_pairing_in_relation(
                "M-00FA_H-1",
                "M-00FA_H-1_HP-1",
                AP1,
                Some("ApplicationProgram"),
            )
            .expect("unselected malformed relation is outside the selection")
            .expect("selected AP1 exists");
        assert_eq!(selected.application_program_2, HardwareApplicationProgram2::Present {
            application_program_id: AP2.to_owned(),
        });
        assert!(matches!(
            document.resolve_application_program_pairing_in_relation("M-00FA_H-1", "M-00FA_H-1_HP-1", AP2, None,),
            Err(HardwareApplicationProgramError::SelectedProgramIsApplicationProgram2 { .. })
        ));
        assert_eq!(
            document.resolve_application_program_pairing_in_relation("M-00FA_H-1", "missing", AP1, None,),
            Ok(None)
        );

        // The relation, not the hardware attribute, decides that AP2 exists.
        document.manufacturer_data.manufacturer.hardware.hardware[0].has_application_program_2 = false;
        let without_flag = document
            .resolve_application_program_pairing_in_relation("M-00FA_H-1", "M-00FA_H-1_HP-1", AP1, None)
            .expect("the relation outranks the AP2 attribute")
            .expect("selected AP1 exists");
        assert_eq!(without_flag.application_program_2, HardwareApplicationProgram2::Present {
            application_program_id: AP2.to_owned(),
        });
    }

    #[test]
    fn omitted_application_program_2_flag_defaults_to_false() {
        let hardware = hardware(None, &[AP1]);

        assert!(!hardware.manufacturer_data.manufacturer.hardware.hardware[0].has_application_program_2);
        let pairing = hardware
            .resolve_application_program_pairing(AP1, Some("ApplicationProgram"))
            .expect("relation is valid")
            .expect("AP1 relation exists");
        assert_eq!(pairing.application_program_2, HardwareApplicationProgram2::Absent);
    }

    #[test]
    fn omitted_medium_types_remains_absent() {
        let xml = format!(
            r#"<KNX {ROOT}><ManufacturerData><Manufacturer RefId="M-00FA"><Hardware><Hardware Id="M-00FA_H-1" Name="Hardware" SerialNumber="1" VersionNumber="1" HasIndividualAddress="true" HasApplicationProgram="true"><Products><Product Id="M-00FA_H-1_P-1" Text="Fixture" OrderNumber="F-1" IsRailMounted="false" DefaultLanguage="en-US"/></Products><Hardware2Programs><Hardware2Program Id="M-00FA_H-1_HP-1"><ApplicationProgramRef RefId="{AP1}"/></Hardware2Program></Hardware2Programs></Hardware></Hardware></Manufacturer></ManufacturerData></KNX>"#
        );

        let hardware: HardwareKnx = crate::xml::from_str(&xml).expect("hardware without MediumTypes parses");
        let relation =
            &hardware.manufacturer_data.manufacturer.hardware.hardware[0].hardware2programs.hardware2programs[0];
        assert!(relation.medium_types.is_empty());
    }

    #[test]
    fn retains_and_resolves_the_ordered_second_reference() {
        let hardware = hardware(Some(true), &[AP1, AP2]);
        let relation =
            &hardware.manufacturer_data.manufacturer.hardware.hardware[0].hardware2programs.hardware2programs[0];

        assert_eq!(relation.application_program_refs.len(), 2);
        let pairing = hardware
            .resolve_application_program_pairing(AP1, Some("ApplicationProgram"))
            .expect("relation is valid")
            .expect("AP1 relation exists");
        assert_eq!(pairing.application_program_2, HardwareApplicationProgram2::Present {
            application_program_id: AP2.to_owned()
        });
    }

    #[test]
    fn a_second_reference_binds_ap2_without_the_hardware_capability() {
        let pairing = hardware(None, &[AP1, AP2])
            .resolve_application_program_pairing(AP1, None)
            .expect("the relation outranks HasApplicationProgram2")
            .expect("AP1 relation exists");
        assert_eq!(pairing.application_program_2, HardwareApplicationProgram2::Present {
            application_program_id: AP2.to_owned()
        });
    }

    #[test]
    fn application_program_capabilities_do_not_require_relation_bindings() {
        let ap1_capable = hardware(None, &[]);
        assert_eq!(ap1_capable.resolve_application_program_pairing(AP1, None), Ok(None));

        let ap2_capable_without_binding = hardware(Some(true), &[]);
        assert_eq!(ap2_capable_without_binding.resolve_application_program_pairing(AP1, None), Ok(None));

        let ap2_capable_with_ap1_only = hardware(Some(true), &[AP1]);
        let pairing = ap2_capable_with_ap1_only
            .resolve_application_program_pairing(AP1, None)
            .expect("AP2 capability permits an AP1-only relation")
            .expect("the AP1 binding is present");
        assert_eq!(pairing.application_program_2, HardwareApplicationProgram2::Absent);
    }

    #[test]
    fn skips_hardware_relations_which_declare_no_application_program() {
        let mut document = hardware_with_application_program(false, None, &[]);
        assert_eq!(document.resolve_application_program_pairing(AP1, Some("ApplicationProgram")), Ok(None));

        let mut downloadable = hardware(None, &[AP1])
            .manufacturer_data
            .manufacturer
            .hardware
            .hardware
            .pop()
            .expect("one downloadable hardware fixture");
        downloadable.id = "M-00FA_H-2".to_owned();
        downloadable.hardware2programs.hardware2programs[0].id = "M-00FA_H-2_HP-1".to_owned();
        document.manufacturer_data.manufacturer.hardware.hardware.push(downloadable);

        let pairing = document
            .resolve_application_program_pairing(AP1, Some("ApplicationProgram"))
            .expect("both relations are internally consistent")
            .expect("the downloadable AP1 relation is found");
        assert_eq!(pairing.hardware_id, "M-00FA_H-2");
    }

    #[test]
    fn a_bound_application_wins_over_a_false_capability_flag() {
        // ETS derives the capability from the relation, so catalogue products
        // that bind an application despite the flag remain programmable.
        let pairing = hardware_with_application_program(false, None, &[AP1])
            .resolve_application_program_pairing(AP1, None)
            .expect("the relation is authoritative for AP1")
            .expect("the AP1 binding is present");
        assert_eq!(pairing.application_program_id, AP1);
        assert_eq!(pairing.application_program_2, HardwareApplicationProgram2::Absent);
    }

    #[test]
    fn rejects_a_secondary_selection_and_an_invalid_primary_program_type() {
        let hardware = hardware(Some(true), &[AP1, AP2]);
        assert!(matches!(
            hardware.resolve_application_program_pairing(AP2, None),
            Err(HardwareApplicationProgramError::SelectedProgramIsApplicationProgram2 { .. })
        ));
        assert!(matches!(
            hardware.resolve_application_program_pairing(AP1, Some("PeiProgram")),
            Err(HardwareApplicationProgramError::InvalidPrimaryProgramType { .. })
        ));
    }

    #[test]
    fn rejects_ambiguous_first_reference_relations() {
        let mut hardware = hardware(None, &[AP1]);
        let element = &mut hardware.manufacturer_data.manufacturer.hardware.hardware[0];
        let mut duplicate = element.hardware2programs.hardware2programs[0].clone();
        duplicate.id = "M-00FA_H-1_HP-2".to_owned();
        element.hardware2programs.hardware2programs.push(duplicate);

        assert!(matches!(
            hardware.resolve_application_program_pairing(AP1, Some("ApplicationProgram")),
            Err(HardwareApplicationProgramError::AmbiguousRelation { count: 2, .. })
        ));
    }
}
