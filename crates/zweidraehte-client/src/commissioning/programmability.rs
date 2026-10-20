//! Products whose download the compiler refuses before any image work.
//!
//! This is the single list of reasons a product cannot be programmed. A
//! product either depends on software beyond its XML (manufacturer plug-ins,
//! external tools, a mask that is only programmed through a system plug-in),
//! or its authored data takes a path on which the reference tool fails
//! instead of downloading. Every reason has a stable identifier, so callers
//! report and classify a refusal without parsing its message.
//!
//! Refusals cover downloads only. Address assignment and unloads never read
//! the data that a refusal is about.

use crate::commissioning::input::CommissioningIntent;
use zweidraehte_ets_files::product::{LoadProcedureStyle, ProductData};
use zweidraehte_ets_files::schema::LoadControl;
use zweidraehte_ets_files::schema::master_data::MaskVersion;

/// Why a product's download cannot be compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Unprogrammable {
    /// The application names a download plug-in, UI plug-in or data handler.
    /// Such code can change defaults or download data outside the XML.
    // TODO: a UI-only plug-in may leave the download itself intact; refuse
    // it until a product proves its XML defaults are complete without it.
    ManufacturerPlugin,
    /// The application declares `RequiresExternalSoftware="true"`.
    ExternalSoftware,
    /// Every Master Data variant of the authored mask names a system plug-in
    /// (witness: MV-0300-01000000000000000000), so no plug-in-free download
    /// exists. A mask that keeps one plug-in-free variant stays programmable.
    SystemPlugin,
    /// The product procedure opens with `LdCtrlDisconnect` (witnesses: the
    /// converted MV-0300 USB interfaces M-0001_A-7002-01-E2F3 and
    /// M-00FD_A-C501-10-7FE7-O0001, whose whole procedure is one Disconnect).
    /// The reference fails while normalizing the connection controls of such
    /// a procedure, whatever follows the Disconnect.
    ProcedureStartsWithDisconnect,
    /// A BimM112 (System 7) application has no association table segment,
    /// yet the download writes group communication (witness:
    /// M-0009_A-208A-13-F1AA). The reference places the association table at
    /// the nominal address 0, which no image segment covers, and fails.
    MissingAssociationTable,
}

impl Unprogrammable {
    /// Stable identifier for reports and classification.
    pub const fn id(self) -> &'static str {
        match self {
            Self::ManufacturerPlugin => "manufacturer_plugin",
            Self::ExternalSoftware => "external_software",
            Self::SystemPlugin => "system_plugin",
            Self::ProcedureStartsWithDisconnect => "procedure_starts_with_disconnect",
            Self::MissingAssociationTable => "missing_association_table",
        }
    }

    /// A dependency needs software this compiler cannot run. The other
    /// refusals are complete product data on which the reference itself fails.
    pub const fn is_dependency(self) -> bool {
        matches!(self, Self::ManufacturerPlugin | Self::ExternalSoftware | Self::SystemPlugin)
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::ManufacturerPlugin => "the application depends on a manufacturer plug-in",
            Self::ExternalSoftware => "the application requires external software",
            Self::SystemPlugin => "every variant of the mask requires a system plug-in",
            Self::ProcedureStartsWithDisconnect => "the product load procedure starts with a disconnect",
            Self::MissingAssociationTable => {
                "the System 7 application has no association table for its group communication"
            }
        }
    }
}

impl std::fmt::Display for Unprogrammable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} ({})", self.description(), self.id())
    }
}

/// The first reason the product's download for `intent` cannot be compiled.
///
/// `mask` is the Master Data definition of the product's authored mask; the
/// mask-level rules are skipped when the caller has none. Dependencies are
/// reported before reference defects, so a plug-in product is always
/// classified by its plug-in.
pub fn unprogrammable(
    product: &ProductData,
    mask: Option<&MaskVersion>,
    intent: CommissioningIntent,
) -> Option<Unprogrammable> {
    // Only a download reads the data that the refusals are about.
    intent.download_mode()?;

    // Plug-in declarations live in `<Static><Extension>` and are read raw:
    // an absent `RequiresExternalSoftware` is no dependency.
    let extension = product.programming_options().extension();
    if extension.is_some_and(|extension| {
        extension.ets_download_plugin.is_some()
            || extension.ets_ui_plugin.is_some()
            || extension.ets_data_handler.is_some()
    }) {
        return Some(Unprogrammable::ManufacturerPlugin);
    }
    if extension.is_some_and(|extension| extension.requires_external_software == Some(true)) {
        return Some(Unprogrammable::ExternalSoftware);
    }
    if mask.is_some_and(|mask| {
        !mask.hawk_configs.is_empty() && mask.hawk_configs.iter().all(|variant| variant.ets3_system_plugin.is_some())
    }) {
        return Some(Unprogrammable::SystemPlugin);
    }

    // Only a product procedure reaches the device as authored. Merged and
    // default procedures open with the mask's own controls, so a product
    // fragment's first control is never the procedure's first control.
    // The product procedure is the one without a merge identifier.
    if product.load_procedure_style() == LoadProcedureStyle::Product
        && product
            .load_procedures()
            .iter()
            .find(|procedure| procedure.merge_id.is_none())
            .is_some_and(|procedure| matches!(procedure.controls.first(), Some(LoadControl::LdCtrlDisconnect(_))))
    {
        return Some(Unprogrammable::ProcedureStartsWithDisconnect);
    }

    // The failure is in building the group tables, so a download that leaves
    // group communication untouched is unaffected.
    // TODO: partial downloads without group communication are inferred from
    // that cause, not observed; confirm once partial downloads are compared.
    if mask.is_some_and(|mask| mask.management_model == "BimM112")
        && intent.updates_group_communication()
        && product.association_table_segment().is_none()
    {
        return Some(Unprogrammable::MissingAssociationTable);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::input::{DownloadMode, ProgramSections, UnloadMode};
    use zweidraehte_ets_files::MasterData;
    use zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML;

    const FULL: CommissioningIntent = CommissioningIntent::Download(DownloadMode::Full);

    fn master_data() -> MasterData {
        r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="1"><MaskVersions>
    <MaskVersion Id="MV-0705" MaskVersion="1797" Name="System 7" ManagementModel="BimM112">
      <HawkConfigurationData />
    </MaskVersion>
    <MaskVersion Id="MV-0300" MaskVersion="768" Name="System 300" ManagementModel="PropertyBased">
      <HawkConfigurationData />
      <HawkConfigurationData Ets3SystemPlugin="{2C37063B-67BC-4CAD-9BCA-3BF516DA7995}" />
    </MaskVersion>
    <MaskVersion Id="MV-0300-01000000000000000000" MaskVersion="768" Name="System 300" ManagementModel="PropertyBased">
      <HawkConfigurationData Ets3SystemPlugin="{2C37063B-67BC-4CAD-9BCA-3BF516DA7995}" />
    </MaskVersion>
  </MaskVersions></MasterData>
</KNX>"#
            .parse()
            .expect("masks parse")
    }

    fn product(xml: &str) -> ProductData {
        ProductData::from_mtxml_str(xml).expect("fixture parses")
    }

    #[test]
    fn a_complete_system7_product_is_programmable() {
        let master = master_data();
        assert_eq!(unprogrammable(&product(SYSTEM7_MTXML), master.get_mask_version("MV-0705"), FULL), None);
    }

    #[test]
    fn plug_in_declarations_refuse_the_download() {
        let master = master_data();
        let mask = master.get_mask_version("MV-0705");
        for (extension, expected) in [
            (r#"<Extension EtsDownloadPlugin="vendor.download" />"#, Unprogrammable::ManufacturerPlugin),
            (r#"<Extension EtsUiPlugin="vendor.ui" />"#, Unprogrammable::ManufacturerPlugin),
            (r#"<Extension EtsDataHandler="vendor.data" />"#, Unprogrammable::ManufacturerPlugin),
            (r#"<Extension RequiresExternalSoftware="true" />"#, Unprogrammable::ExternalSoftware),
        ] {
            let xml = SYSTEM7_MTXML.replacen("<LoadProcedures>", &format!("{extension}<LoadProcedures>"), 1);
            assert_eq!(unprogrammable(&product(&xml), mask, FULL), Some(expected), "{extension}");
        }
    }

    #[test]
    fn only_a_mask_without_a_plug_in_free_variant_is_refused() {
        let master = master_data();
        let product = product(SYSTEM7_MTXML);
        assert_eq!(unprogrammable(&product, master.get_mask_version("MV-0300"), FULL), None);
        assert_eq!(
            unprogrammable(&product, master.get_mask_version("MV-0300-01000000000000000000"), FULL),
            Some(Unprogrammable::SystemPlugin)
        );
    }

    #[test]
    fn a_product_procedure_opening_with_a_disconnect_is_refused() {
        let master = master_data();
        let mask = master.get_mask_version("MV-0705");
        let opening = SYSTEM7_MTXML.replacen("<LdCtrlConnect />", "<LdCtrlDisconnect />", 1);
        assert_eq!(unprogrammable(&product(&opening), mask, FULL), Some(Unprogrammable::ProcedureStartsWithDisconnect));

        // A trailing Disconnect is the ordinary shape.
        assert_eq!(unprogrammable(&product(SYSTEM7_MTXML), mask, FULL), None);

        // A merged fragment opens after the mask's own controls.
        let merged =
            opening.replacen(r#"LoadProcedureStyle="ProductProcedure""#, r#"LoadProcedureStyle="MergedProcedure""#, 1);
        assert_eq!(unprogrammable(&product(&merged), mask, FULL), None);
    }

    #[test]
    fn a_system7_download_without_an_association_table_is_refused_only_for_group_communication() {
        let master = master_data();
        let without = SYSTEM7_MTXML.replacen(
            r#"<AssociationTable CodeSegment="M-00FA_A-0306-02-0000_AS-4100" Offset="0" MaxEntries="7" />"#,
            "",
            1,
        );
        let product = product(&without);
        let mask = master.get_mask_version("MV-0705");
        assert_eq!(unprogrammable(&product, mask, FULL), Some(Unprogrammable::MissingAssociationTable));
        assert_eq!(
            unprogrammable(
                &product,
                mask,
                CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::PARAMETERS))
            ),
            None
        );

        // Other management models place their tables differently.
        assert_eq!(unprogrammable(&product, master.get_mask_version("MV-0300"), FULL), None);
    }

    #[test]
    fn intents_without_a_download_are_never_refused() {
        let master = master_data();
        let opening = SYSTEM7_MTXML.replacen("<LdCtrlConnect />", "<LdCtrlDisconnect />", 1);
        let product = product(&opening);
        for intent in [CommissioningIntent::AssignAddress, CommissioningIntent::Unload(UnloadMode::Application)] {
            assert_eq!(unprogrammable(&product, master.get_mask_version("MV-0705"), intent), None, "{intent:?}");
        }
    }
}
