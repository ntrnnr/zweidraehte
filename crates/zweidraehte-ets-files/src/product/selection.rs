//! Checked ownership of one application document and its compilation metadata.

use super::{ProductData, ProductError};
use crate::runtime::device::DeviceDefinition;
use crate::schema::{ApplicationProgram, HardwareApplicationProgram2, HardwareApplicationProgramPairing, Knx};
use std::sync::{Arc, OnceLock};

/// Exact package relation selected for one primary application program.
///
/// Catalogue identities are absent only for a genuinely loose MTXML or an
/// incomplete package without a catalogue entry. `hardware` always retains
/// the selected Hardware and Hardware2Program IDs plus the ordered AP1/AP2
/// references, so callers can persist or fingerprint the authority they used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationProgramRelation {
    pub catalog_item_id: Option<String>,
    pub product_id: Option<String>,
    pub hardware: HardwareApplicationProgramPairing,
}

impl ApplicationProgramRelation {
    pub fn ordered_application_program_ids(&self) -> Vec<&str> {
        let mut ids = vec![self.hardware.application_program_id.as_str()];
        if let HardwareApplicationProgram2::Present { application_program_id } = &self.hardware.application_program_2 {
            ids.push(application_program_id);
        }
        ids
    }
}

/// One parsed application with all package-owned compilation metadata bound.
/// The original document remains available for translations and editor state.
#[derive(Debug, Clone)]
pub struct SelectedProduct {
    document: Knx,
    product: ProductData,
    relation: Option<ApplicationProgramRelation>,
    runtime_definition: OnceLock<Arc<DeviceDefinition>>,
}

impl SelectedProduct {
    /// Assemble generated/extracted documents using their explicitly selected
    /// hardware relationship. No adjacent files or default Master Data are inferred.
    /// Returns an error for missing or ambiguous applications, a relation naming
    /// another application, or invalid product/Master Data content.
    pub fn from_document(
        document: Knx,
        relation: Option<ApplicationProgramRelation>,
        master_data_xml: Option<&str>,
    ) -> Result<Self, ProductError> {
        let product = extract_product(&document, relation.clone(), master_data_xml)?;
        Ok(Self { document, product, relation, runtime_definition: OnceLock::new() })
    }

    pub fn document(&self) -> &Knx {
        &self.document
    }

    pub fn product(&self) -> &ProductData {
        &self.product
    }

    pub(crate) fn runtime_definition(&self) -> &Arc<DeviceDefinition> {
        self.runtime_definition.get_or_init(|| Arc::new(DeviceDefinition::new(self.program().clone())))
    }

    pub fn relation(&self) -> Option<&ApplicationProgramRelation> {
        self.relation.as_ref()
    }

    pub fn program(&self) -> &ApplicationProgram {
        self.document
            .manufacturer_data
            .manufacturer
            .application_programs
            .programs
            .first()
            .expect("one application validated")
    }

    /// Bind an explicitly selected catalogue without changing the product identity.
    /// An existing conflicting catalogue is rejected by the product boundary.
    pub fn bind_master_data(mut self, document: std::sync::Arc<crate::MasterData>) -> Result<Self, ProductError> {
        self.product = self.product.bind_master_data(document)?;
        Ok(self)
    }

    /// Bind the relation's secondary PEI Program from its own application
    /// document.
    ///
    /// Only a `PeiProgram` can occupy the second application slot. Its
    /// segments and load-procedure fragments compile with the primary
    /// application; it contributes no editable configuration.
    pub fn with_secondary_document(mut self, document: Knx) -> Result<Self, ProductError> {
        let programs = &document.manufacturer_data.manufacturer.application_programs.programs;
        let [program] = programs.as_slice() else {
            return Err(ProductError::AmbiguousApplicationProgram { count: programs.len() });
        };
        if program.program_type != "PeiProgram" {
            return Err(ProductError::UnsupportedSecondaryApplication {
                application_program_id: program.id.clone(),
                reason: format!("ProgramType {:?} is not PeiProgram", program.program_type),
            });
        }
        let secondary = ProductData::from_knx(&document)?;
        self.product = self.product.bind_secondary_application(secondary)?;
        Ok(self)
    }

    pub fn into_parts(self) -> (Knx, ProductData) {
        (self.document, self.product)
    }
}

pub(crate) fn extract_product(
    document: &Knx,
    relation: Option<ApplicationProgramRelation>,
    master_data_xml: Option<&str>,
) -> Result<ProductData, ProductError> {
    let mut product = ProductData::from_knx(document)?;
    if let Some(relation) = relation {
        let has_individual_address = relation.hardware.has_individual_address;
        product = product.bind_application_program_2(relation.into())?;
        product = product.bind_hardware_individual_address(has_individual_address);
    }
    if let Some(xml) = master_data_xml {
        product = product.bind_master_data(std::sync::Arc::new(xml.parse()?))?;
    }
    Ok(product)
}

impl From<ApplicationProgramRelation> for crate::product::ApplicationProgram2Binding {
    fn from(selected: ApplicationProgramRelation) -> Self {
        use crate::product::ApplicationProgramRelationIdentity;
        let relation = ApplicationProgramRelationIdentity {
            catalog_product_id: selected.product_id,
            catalog_item_id: selected.catalog_item_id,
            hardware_id: selected.hardware.hardware_id,
            hardware2program_id: selected.hardware.hardware2program_id,
            application_program_id: selected.hardware.application_program_id,
        };
        match selected.hardware.application_program_2 {
            HardwareApplicationProgram2::Absent => Self::Absent { relation },
            HardwareApplicationProgram2::Present { application_program_id } => {
                Self::Present { relation, application_program_id }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::parse_application_program;

    fn document() -> Knx {
        parse_application_program(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
          <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
          <ApplicationProgram Id="M-00FA_A-0001-01-0000" ApplicationNumber="1"
            ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0012"
            Name="Button" LoadProcedureStyle="DefaultProcedure" PeiType="0"
            DefaultLanguage="en-US" DynamicTableManagement="false" Linkable="false">
            <Static/>
          </ApplicationProgram></ApplicationPrograms></Manufacturer></ManufacturerData>
        </KNX>"#,
        )
        .expect("single application document")
    }

    #[test]
    fn selection_requires_exactly_one_application_without_archive_support() {
        let mut empty = document();
        empty.manufacturer_data.manufacturer.application_programs.programs.clear();
        assert!(matches!(
            SelectedProduct::from_document(empty, None, None),
            Err(ProductError::MissingApplicationProgram)
        ));

        let mut ambiguous = document();
        let programs = &mut ambiguous.manufacturer_data.manufacturer.application_programs.programs;
        programs.push(programs[0].clone());
        assert!(matches!(
            SelectedProduct::from_document(ambiguous, None, None),
            Err(ProductError::AmbiguousApplicationProgram { count: 2 })
        ));
    }

    #[test]
    fn selection_binds_the_hardware_individual_address_capability() {
        assert_eq!(
            SelectedProduct::from_document(document(), None, None)
                .expect("loose XML")
                .product()
                .hardware_has_individual_address(),
            None
        );
        for has_individual_address in [true, false] {
            let relation = ApplicationProgramRelation {
                catalog_item_id: None,
                product_id: None,
                hardware: HardwareApplicationProgramPairing {
                    hardware_id: "power-supply".into(),
                    hardware2program_id: "power-supply-program".into(),
                    application_program_id: "M-00FA_A-0001-01-0000".into(),
                    application_program_2: HardwareApplicationProgram2::Absent,
                    has_individual_address,
                },
            };
            let selected = SelectedProduct::from_document(document(), Some(relation), None).expect("relation binds");
            assert_eq!(selected.product().hardware_has_individual_address(), Some(has_individual_address));
        }
    }

    #[test]
    fn selection_rejects_a_relation_for_another_application() {
        let relation = ApplicationProgramRelation {
            catalog_item_id: Some("catalogue-button".into()),
            product_id: Some("button".into()),
            hardware: HardwareApplicationProgramPairing {
                hardware_id: "button-hardware".into(),
                hardware2program_id: "button-program".into(),
                application_program_id: "M-00FA_A-0002-01-0000".into(),
                application_program_2: HardwareApplicationProgram2::Absent,
                has_individual_address: true,
            },
        };
        assert!(matches!(
            SelectedProduct::from_document(document(), Some(relation), None),
            Err(ProductError::ApplicationProgramRelationMismatch { .. })
        ));
    }

    #[test]
    fn selection_retains_catalogue_authority_when_binding_master_data() {
        let relation = ApplicationProgramRelation {
            catalog_item_id: Some("catalogue-button".into()),
            product_id: Some("button".into()),
            hardware: HardwareApplicationProgramPairing {
                hardware_id: "button-hardware".into(),
                hardware2program_id: "button-program".into(),
                application_program_id: "M-00FA_A-0001-01-0000".into(),
                application_program_2: HardwareApplicationProgram2::Present {
                    application_program_id: "M-00FA_A-0002-01-0000".into(),
                },
                has_individual_address: true,
            },
        };
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23"><MasterData Id="bundled" Version="1"/></KNX>"#;
        let selected = SelectedProduct::from_document(document(), Some(relation.clone()), Some(xml))
            .expect("selection with bundled catalogue");
        let selected = selected
            .bind_master_data(std::sync::Arc::new(xml.parse().expect("master data")))
            .expect("same catalogue is idempotent");
        assert_eq!(selected.relation(), Some(&relation));
        assert_eq!(selected.product().application_program_2(), &relation.into());
        let conflicting = xml.replace("bundled", "different");
        assert!(matches!(
            selected.bind_master_data(std::sync::Arc::new(conflicting.parse().expect("master data"))),
            Err(ProductError::MasterDataAlreadyBound)
        ));
    }
}
