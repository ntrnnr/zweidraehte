//! Catalog MTXML Generator - Creates Catalog.mtxml files.

use crate::schema::{CatalogItem, CatalogKnx, CatalogSection};
use crate::signing::KnxSchemaVersion;

use super::builder::AppProgramRef;
use super::{ApplicationProgramDef, CatalogSectionDef, GeneratorError, HardwareDef};

/// Generator for creating Catalog MTXML files.
pub struct CatalogGenerator;

impl CatalogGenerator {
    /// Generate Catalog XML from multiple catalog section definitions.
    pub fn generate_multi(
        manufacturer_id: u16,
        sections: &[CatalogSectionDef],
        hardware_defs: &[HardwareDef],
        application_programs: &[&ApplicationProgramDef],
        schema_version: Option<KnxSchemaVersion>,
    ) -> Result<String, GeneratorError> {
        let knx = Self::build_catalog_knx_multi(
            manufacturer_id,
            sections,
            hardware_defs,
            application_programs,
            schema_version,
        );
        Self::serialize(&knx)
    }

    /// Build a Catalog KNX document from multiple catalog section definitions.
    fn build_catalog_knx_multi(
        manufacturer_id: u16,
        sections: &[CatalogSectionDef],
        hardware_defs: &[HardwareDef],
        application_programs: &[&ApplicationProgramDef],
        schema_version: Option<KnxSchemaVersion>,
    ) -> CatalogKnx {
        let manuf_str = format!("M-{:04X}", manufacturer_id);

        let mut knx = CatalogKnx::default();
        if let Some(version) = schema_version {
            knx.xmlns = version.namespace_url();
            knx.tool_version = version.tool_version().to_string();
        }
        knx.manufacturer_data.manufacturer.ref_id = manuf_str.clone();

        // Global section counter for unique IDs.
        let mut section_counter = 0u32;
        let mut item_counter = 0u32;

        let catalog_sections: Vec<CatalogSection> = sections
            .iter()
            .map(|sec| {
                Self::build_section(
                    sec,
                    &manuf_str,
                    hardware_defs,
                    application_programs,
                    &mut section_counter,
                    &mut item_counter,
                )
            })
            .collect();

        knx.manufacturer_data.manufacturer.catalog.catalog_sections = catalog_sections;
        knx
    }

    /// Recursively build a CatalogSection from a CatalogSectionDef.
    fn build_section(
        def: &CatalogSectionDef,
        manuf_str: &str,
        hardware_defs: &[HardwareDef],
        application_programs: &[&ApplicationProgramDef],
        section_counter: &mut u32,
        item_counter: &mut u32,
    ) -> CatalogSection {
        *section_counter += 1;
        let section_id = format!("{}_CS-{}", manuf_str, section_counter);

        let catalog_items: Vec<CatalogItem> = def
            .entries
            .iter()
            .map(|entry| {
                *item_counter += 1;

                let hw_def = &hardware_defs[entry.hardware.0];
                let serial_hex = hw_def.serial_number.iter().map(|b| format!("{:02X}", b)).collect::<String>();
                let hardware_id = format!("{}_H-{}-{}", manuf_str, serial_hex, hw_def.hardware_version);

                let AppProgramRef(app_idx) = entry.application_program;
                let app = application_programs[app_idx];
                let app_hash = app.application_hash.unwrap_or("0000");

                // Hardware2Program ID
                let h2p_id = format!(
                    "{}_HP-{:04X}-{:02X}-{}",
                    hardware_id, app.device.application_id, app.device.application_version, app_hash
                );

                // Product ID by order number
                let product_id = format!(
                    "{}_P-{}",
                    hardware_id,
                    super::mtxml::MtxmlGenerator::encode_id(entry.product_order_number)
                );

                // Catalog Item ID
                let catalog_item_id = format!(
                    "{}_CI-{}-{}",
                    h2p_id,
                    super::mtxml::MtxmlGenerator::encode_id(entry.product_order_number),
                    item_counter
                );

                CatalogItem {
                    id: catalog_item_id,
                    name: entry.name.to_string(),
                    number: item_counter.to_string(),
                    product_ref_id: product_id,
                    hardware2program_ref_id: h2p_id,
                    default_language: "en-US".to_string(),
                }
            })
            .collect();

        let subsections: Vec<CatalogSection> = def
            .subsections
            .iter()
            .map(|sub| {
                Self::build_section(sub, manuf_str, hardware_defs, application_programs, section_counter, item_counter)
            })
            .collect();

        CatalogSection {
            id: section_id,
            name: def.name.to_string(),
            number: section_counter.to_string(),
            default_language: "en-US".to_string(),
            catalog_items,
            subsections,
        }
    }

    /// Serialize the Catalog KNX document to XML string.
    fn serialize(knx: &CatalogKnx) -> Result<String, GeneratorError> {
        let mut buffer = String::new();
        buffer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        let mut serializer = quick_xml::se::Serializer::new(&mut buffer);
        serializer.indent(' ', 2);

        serde::Serialize::serialize(knx, serializer).map_err(|e| GeneratorError::Serialization(e.to_string()))?;

        Ok(buffer)
    }
}
