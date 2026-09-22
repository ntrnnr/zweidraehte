//! Prepare one complete product editor before installing it in the UI.

use std::path::Path;
use std::sync::Arc;

use zweidraehte_client::commissioning::{ProgrammingCatalog, ProgrammingCatalogLoadRequest};
use zweidraehte_ets_files::product::{ProductData, SelectedProduct};
use zweidraehte_ets_files::runtime::configuration::{ProductConfiguration, apply_configuration};
use zweidraehte_ets_files::runtime::{BaggageIndex, Translations};
use zweidraehte_ets_files::schema::Knx;
use zweidraehte_ets_files::{Device, MasterData};
use zweidraehte_proto::address::GroupAddress;

use super::LanguageContext;

/// Exact selected document and product metadata, plus its materialized resources.
///
/// A document cannot be swapped independently of its checked metadata:
/// ```compile_fail,E0616
/// use knxproj_tui::app::EditorDocument;
/// use zweidraehte_ets_files::product::SelectedProduct;
/// fn replace_selection(editor: &mut EditorDocument, selected: SelectedProduct) {
///     editor.selected = selected;
/// }
/// ```
#[derive(Debug)]
pub struct EditorDocument {
    selected: SelectedProduct,
    baggage: Option<BaggageIndex>,
}

/// A product ready for both editing and preview compilation.
///
/// Construction binds the catalogue, translations and authored settings once.
/// The UI accepts this bundle as a unit, so startup and navigation cannot
/// install a new runtime device while retaining the old product's metadata.
pub struct PreparedEditorProduct {
    pub(super) device: Device,
    pub(super) programming_catalog: ProgrammingCatalog,
    pub(super) language_context: Option<LanguageContext>,
    pub(super) current_language: Option<String>,
}

impl std::fmt::Debug for PreparedEditorProduct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedEditorProduct")
            .field("product", &self.device.program().id)
            .field("language", &self.current_language)
            .finish_non_exhaustive()
    }
}

impl EditorDocument {
    pub fn new(selected: SelectedProduct, baggage: Option<BaggageIndex>) -> Self {
        Self { selected, baggage }
    }

    pub fn document(&self) -> &Knx {
        self.selected.document()
    }

    pub fn product(&self) -> &ProductData {
        self.selected.product()
    }

    pub fn baggage(&self) -> Option<&BaggageIndex> {
        self.baggage.as_ref()
    }

    /// Prepare an editor with project overrides and primary-first group bindings.
    ///
    /// Package Master Data remains authoritative. Otherwise an explicit file
    /// wins over the product's versioned resolver. Missing translations retain
    /// the default language. Errors leave the currently open editor untouched.
    pub fn prepare(
        self,
        configuration: &ProductConfiguration,
        bindings: impl IntoIterator<Item = (u16, Vec<GroupAddress>)>,
        language: Option<&str>,
        master_data: Option<&Path>,
    ) -> Result<PreparedEditorProduct, Box<dyn std::error::Error>> {
        let Self { selected, baggage } = self;
        let translations = Translations::from_knx(selected.document());
        let product_data = selected.product();

        let programming_catalog =
            ProgrammingCatalog::load(match master_data.filter(|_| product_data.master_data().is_none()) {
                Some(path) => ProgrammingCatalogLoadRequest::File(path),
                None => ProgrammingCatalogLoadRequest::Product(product_data),
            })?
            .into_catalog();
        let selected = Arc::new(selected.bind_master_data(programming_catalog.document())?);

        // Keep the original text for later language changes; translated text
        // must never become the starting point for a different translation.
        let current_language =
            language.filter(|language| translations.languages().contains(language)).map(str::to_owned);
        let mut device = Device::from_product(selected.clone(), baggage.clone(), current_language.as_deref());
        apply_configuration(&mut device, configuration)?;
        for (object, addresses) in bindings {
            for address in addresses {
                device.assign_group_address(object, address);
            }
        }
        let language_context =
            (!translations.is_empty()).then_some(LanguageContext { translations, selected, baggage });
        Ok(PreparedEditorProduct { device, programming_catalog, language_context, current_language })
    }
}

impl PreparedEditorProduct {
    pub fn master_data(&self) -> &MasterData {
        self.programming_catalog.as_ref()
    }

    pub fn current_language(&self) -> Option<&str> {
        self.current_language.as_deref()
    }

    pub fn default_language(&self) -> &str {
        &self.device.program().default_language
    }
}
