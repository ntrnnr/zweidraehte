//! Hardware MTXML Generator - Creates Hardware.mtxml files.

use crate::schema::{
    ApplicationProgramRef, Hardware, Hardware2Program, Hardware2Programs, HardwareKnx, Product, Products,
};
use crate::signing::KnxSchemaVersion;

use super::builder::AppProgramRef;
use super::{medium_type_from_mask, ApplicationProgramDef, GeneratorError, HardwareDef};

/// Generator for creating Hardware MTXML files.
pub struct HardwareGenerator;

impl HardwareGenerator {
    /// Generate Hardware XML from multiple hardware definitions.
    ///
    /// Creates a single Hardware.xml containing all hardware elements, each with
    /// their products and hardware-to-program links.
    pub fn generate_multi(
        manufacturer_id: u16,
        hardware_defs: &[HardwareDef],
        application_programs: &[&ApplicationProgramDef],
        schema_version: Option<KnxSchemaVersion>,
    ) -> Result<String, GeneratorError> {
        let knx = Self::build_hardware_knx_multi(manufacturer_id, hardware_defs, application_programs, schema_version);
        Self::serialize(&knx)
    }

    /// Build a Hardware KNX document from multiple hardware definitions.
    fn build_hardware_knx_multi(
        manufacturer_id: u16,
        hardware_defs: &[HardwareDef],
        application_programs: &[&ApplicationProgramDef],
        schema_version: Option<KnxSchemaVersion>,
    ) -> HardwareKnx {
        let manuf_str = format!("M-{:04X}", manufacturer_id);

        let mut knx = HardwareKnx::default();
        if let Some(version) = schema_version {
            knx.xmlns = version.namespace_url();
            knx.tool_version = version.tool_version().to_string();
        }
        knx.manufacturer_data.manufacturer.ref_id = manuf_str.clone();

        let mut hardware_elements = Vec::new();

        for hw_def in hardware_defs {
            let serial_hex = hw_def.serial_number.iter().map(|b| format!("{:02X}", b)).collect::<String>();
            let hardware_id = format!("{}_H-{}-{}", manuf_str, serial_hex, hw_def.hardware_version);

            // Build Products
            let products: Vec<Product> = hw_def
                .products
                .iter()
                .map(|p| {
                    let product_id = format!(
                        "{}_P-{}",
                        hardware_id,
                        super::mtxml::MtxmlGenerator::encode_id(p.order_number)
                    );
                    Product {
                        id: product_id,
                        text: p.name.to_string(),
                        order_number: p.order_number.to_string(),
                        is_rail_mounted: p.is_rail_mounted,
                        visible_description: p.visible_description.map(|s| s.to_string()),
                        default_language: "en-US".to_string(),
                    }
                })
                .collect();

            // Build Hardware2Programs — one per referenced application program
            let h2p_elements: Vec<Hardware2Program> = hw_def
                .application_programs
                .iter()
                .map(|&AppProgramRef(app_idx)| {
                    let app = application_programs[app_idx];
                    let app_hash = app.application_hash.unwrap_or("0000");
                    let app_id = format!(
                        "{}_A-{:04X}-{:02X}-{}",
                        manuf_str, app.device.application_id, app.device.application_version, app_hash
                    );
                    let h2p_id = format!(
                        "{}_HP-{:04X}-{:02X}-{}",
                        hardware_id, app.device.application_id, app.device.application_version, app_hash
                    );
                    Hardware2Program {
                        id: h2p_id,
                        medium_types: medium_type_from_mask(app.device.mask_version.as_u16()).to_string(),
                        application_program_ref: ApplicationProgramRef { ref_id: app_id },
                    }
                })
                .collect();

            hardware_elements.push(Hardware {
                id: hardware_id,
                name: hw_def.name.to_string(),
                serial_number: serial_hex,
                version_number: hw_def.hardware_version,
                bus_current: hw_def.bus_current,
                has_individual_address: true,
                has_application_program: true,
                is_ip_enabled: hw_def.is_ip_enabled,
                products: Products { products },
                hardware2programs: Hardware2Programs { hardware2programs: h2p_elements },
            });
        }

        knx.manufacturer_data.manufacturer.hardware.hardware = hardware_elements;
        knx
    }

    /// Serialize the Hardware KNX document to XML string.
    fn serialize(knx: &HardwareKnx) -> Result<String, GeneratorError> {
        let mut buffer = String::new();
        buffer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        let mut serializer = quick_xml::se::Serializer::new(&mut buffer);
        serializer.indent(' ', 2);

        serde::Serialize::serialize(knx, serializer).map_err(|e| GeneratorError::Serialization(e.to_string()))?;

        Ok(buffer)
    }
}
