//! Static target acquisition policy before any device can be discovered.

use crate::commissioning::{ManagementModel, ProgrammingCatalog};
use zweidraehte_ets_files::product::ProductData;

/// Evidence for serial-number management from the exact product mask entry.
/// Unknown evidence never authorizes a serial-number shortcut.
/// This selects acquisition before discovery; live profile validation remains
/// necessary before programming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialAddressingSupport {
    Supported,
    Unsupported,
    Unknown,
}

impl SerialAddressingSupport {
    /// Inspect the exact product entry without live discovery or family guesses.
    pub fn for_product(product: &ProductData, catalog: &ProgrammingCatalog) -> Self {
        let Some(mask) = catalog.as_ref().get_mask_version(product.mask_version_id()) else {
            return Self::Unknown;
        };
        // A product's full mask identifier selects the entry, including any
        // descriptor qualifier. Numeric mask families are not capability proof.
        match mask.management_model.parse::<ManagementModel>() {
            Ok(ManagementModel::Bcu1 | ManagementModel::None) => Self::Unsupported,
            Ok(
                ManagementModel::Bcu2
                | ManagementModel::System7
                | ManagementModel::SystemB
                | ManagementModel::PropertyBased,
            ) => Self::Supported,
            Err(_) => Self::Unknown,
        }
    }

    /// Return a usable serial only when the product declares support.
    pub fn serial_target(self, serial: Option<[u8; 6]>) -> Option<[u8; 6]> {
        serial.filter(|serial| self == Self::Supported && *serial != [0; 6])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_catalog_evidence_controls_serial_addressing() {
        let catalog = ProgrammingCatalog::from_xml(
            r#"
            <KNX xmlns="http://knx.org/xml/project/23"><MasterData Version="1"><MaskVersions>
              <MaskVersion Id="MV-0012" MaskVersion="18" Name="BCU1" ManagementModel="Bcu1"/>
              <MaskVersion Id="MV-0020" MaskVersion="32" Name="BCU2" ManagementModel="Bcu2"/>
              <MaskVersion Id="MV-0705" MaskVersion="1797" Name="System 7" ManagementModel="BimM112"/>
              <MaskVersion Id="MV-07B0" MaskVersion="1968" Name="System B" ManagementModel="SystemB"/>
              <MaskVersion Id="MV-FFFF" MaskVersion="65535" Name="Future" ManagementModel="Future"/>
              <MaskVersion Id="MV-57B0-01" MaskVersion="22448" Name="Exact 1" ManagementModel="SystemB"/>
              <MaskVersion Id="MV-57B0-02" MaskVersion="22448" Name="Exact 2" ManagementModel="None"/>
            </MaskVersions></MasterData></KNX>"#,
        )
        .expect("catalog");
        for (id, expected) in [
            ("MV-0012", SerialAddressingSupport::Unsupported),
            ("MV-0020", SerialAddressingSupport::Supported),
            ("MV-0705", SerialAddressingSupport::Supported),
            ("MV-07B0", SerialAddressingSupport::Supported),
            ("", SerialAddressingSupport::Unknown),
            ("MV-ABCD", SerialAddressingSupport::Unknown),
            ("MV-FFFF", SerialAddressingSupport::Unknown),
            ("MV-57B0-01", SerialAddressingSupport::Supported),
            ("MV-57B0-02", SerialAddressingSupport::Unsupported),
            ("MV-57B0", SerialAddressingSupport::Unknown),
        ] {
            let product = ProductData::default().with_fixture_mask_version_id(id);
            let support = SerialAddressingSupport::for_product(&product, &catalog);
            assert_eq!(support, expected, "{id}");
            let serial = [0, 0xFA, 0, 0, 0, 1];
            assert_eq!(
                support.serial_target(Some(serial)),
                (expected == SerialAddressingSupport::Supported).then_some(serial)
            );
            assert_eq!(support.serial_target(Some([0; 6])), None);
            assert_eq!(support.serial_target(None), None);
        }
    }
}
