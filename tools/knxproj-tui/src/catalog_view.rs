//! Pure view state for browsing the immutable package catalogue.
//!
//! Package parsing, verification, and project mutation deliberately live
//! outside this module. The browser consumes a derived snapshot and returns
//! the exact opaque selector it received for a leaf. Consequently two
//! package versions may reuse every KNX XML identifier without the UI ever
//! confusing them: the package digest remains part of that selector.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use zweidraehte_ets_files::archive::{
    PackageCatalogIndex, PackageCatalogLeaf, PackageCatalogOnlyReason, PackageCatalogSection, PackageCatalogSelector,
    PackageInstantiation, PackageInstantiationBlock, PackageRegistration, PackageRegistrationStatus,
};
use zweidraehte_project::ProjectDeviceId;
use zweidraehte_proto::address::IndividualAddress;

/// Registration status carried independently by a Product and its
/// Hardware2Program relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogRegistrationKind {
    Certified,
    Registered,
    /// No RegistrationInfo was authored. This is distinct from an explicit
    /// `RegistrationStatus="Unregistered"` declaration.
    Unsigned,
    Unregistered,
    /// KNX reserves several `FutureUse*` values. They remain visible for
    /// inspection but are never offered as project devices.
    FutureUse(String),
    /// Preserve a value introduced by a newer schema instead of presenting it
    /// as one of the statuses above.
    Other(String),
}

impl CatalogRegistrationKind {
    pub fn label(&self) -> String {
        match self {
            Self::Certified => "Certified".to_owned(),
            Self::Registered => "Registered".to_owned(),
            Self::Unsigned => "Unsigned".to_owned(),
            Self::Unregistered => "Unregistered".to_owned(),
            Self::FutureUse(value) | Self::Other(value) => value.clone(),
        }
    }
}

/// Registration presentation for one Product, Hardware2Program, or their
/// effective combined result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogRegistrationView {
    pub kind: CatalogRegistrationKind,
    pub registration_number: Option<String>,
    pub registration_date: Option<String>,
}

impl CatalogRegistrationView {
    pub fn label(&self) -> String {
        let mut label = self.kind.label();
        if let Some(number) = &self.registration_number {
            label.push_str(&format!(" · no. {number}"));
        }
        if let Some(date) = &self.registration_date {
            label.push_str(&format!(" · {date}"));
        }
        label
    }
}

/// One exact, display-ready catalogue leaf.
///
/// `S` is the store-owned selector. The TUI treats it as opaque and returns
/// the same value on confirmation; package identity is also retained as text
/// so people can distinguish otherwise identical package revisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogLeafView<S> {
    pub selector: S,
    pub package_digest: String,
    pub catalog_item_id: String,
    pub manufacturer_id: String,
    pub product_id: String,
    pub hardware_id: String,
    pub hardware2program_id: String,
    /// Ordered AP1/AP2 identifiers. An empty list is valid for catalogue-only
    /// hardware whose package declares no application program.
    pub application_program_ids: Vec<String>,
    pub name: String,
    /// `CatalogItem/@Number`, used to preserve the vendor's heterogeneous
    /// item/subsection ordering.
    pub catalog_number: String,
    pub order_number: Option<String>,
    pub medium_types: String,
    pub mask_version: Option<String>,
    pub supports_data_secure: Option<bool>,
    pub product_registration: CatalogRegistrationView,
    pub h2p_registration: CatalogRegistrationView,
    pub effective_registration: CatalogRegistrationView,
    pub instantiable: bool,
    pub non_instantiable_reason: Option<String>,
    /// Fingerprint of the selected Catalog/Hardware/AP relation documents.
    pub chain_digest: String,
}

impl<S> CatalogLeafView<S> {
    /// Include a digest prefix in every row. Package revisions often retain
    /// the same CatalogItem ID, product name, and order number.
    pub fn row_label(&self) -> String {
        let order = self.order_number.as_ref().map_or_else(String::new, |order| format!(" [{order}]"));
        let mask = self.mask_version.as_deref().unwrap_or("catalogue only");
        format!("{}{order} · {mask} · {}", self.name, short_digest(&self.package_digest))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogSectionView<S> {
    pub id: String,
    pub name: String,
    pub number: String,
    pub items: Vec<CatalogLeafView<S>>,
    pub subsections: Vec<CatalogSectionView<S>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogManufacturerView<S> {
    pub id: String,
    pub name: Option<String>,
    pub sections: Vec<CatalogSectionView<S>>,
}

impl<S> CatalogManufacturerView<S> {
    fn display_name(&self) -> &str {
        self.name.as_deref().filter(|name| !name.trim().is_empty()).unwrap_or(&self.id)
    }

    fn row_label(&self) -> String {
        let name = self.display_name();
        if name == self.id { self.id.clone() } else { format!("{name} ({})", self.id) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageCatalogView<S> {
    pub manufacturers: Vec<CatalogManufacturerView<S>>,
}

impl From<PackageCatalogIndex> for PackageCatalogView<PackageCatalogSelector> {
    fn from(index: PackageCatalogIndex) -> Self {
        Self {
            manufacturers: index
                .manufacturers
                .into_iter()
                .map(|manufacturer| CatalogManufacturerView {
                    id: manufacturer.id,
                    name: manufacturer.name,
                    sections: manufacturer.sections.into_iter().map(catalog_section_view).collect(),
                })
                .collect(),
        }
    }
}

fn catalog_section_view(section: PackageCatalogSection) -> CatalogSectionView<PackageCatalogSelector> {
    CatalogSectionView {
        id: section.id,
        name: section.name,
        number: section.number,
        items: section.items.into_iter().map(catalog_leaf_view).collect(),
        subsections: section.subsections.into_iter().map(catalog_section_view).collect(),
    }
}

fn catalog_leaf_view(leaf: PackageCatalogLeaf) -> CatalogLeafView<PackageCatalogSelector> {
    let reason = (!leaf.instantiable).then(|| non_instantiable_reason(&leaf));
    let application_program_ids = leaf.application_program_ids().map(str::to_owned).collect();
    CatalogLeafView {
        package_digest: leaf.selector.package.to_string(),
        catalog_item_id: leaf.selector.catalog_item_id.clone(),
        selector: leaf.selector,
        manufacturer_id: leaf.manufacturer_id,
        product_id: leaf.product_id,
        hardware_id: leaf.hardware_id,
        hardware2program_id: leaf.hardware2program_id,
        application_program_ids,
        name: leaf.name,
        catalog_number: leaf.catalog_number,
        order_number: (!leaf.order_number.is_empty()).then_some(leaf.order_number),
        medium_types: leaf.medium_types,
        mask_version: leaf.mask_version,
        supports_data_secure: leaf.supports_data_secure,
        product_registration: registration_view(leaf.product_registration),
        h2p_registration: registration_view(leaf.hardware2program_registration),
        effective_registration: registration_view(leaf.effective_registration),
        instantiable: leaf.instantiable,
        non_instantiable_reason: reason,
        chain_digest: leaf.chain_digest.to_string(),
    }
}

fn registration_view(registration: PackageRegistration) -> CatalogRegistrationView {
    let kind = match registration.status {
        PackageRegistrationStatus::Unsigned => CatalogRegistrationKind::Unsigned,
        PackageRegistrationStatus::Unregistered => CatalogRegistrationKind::Unregistered,
        PackageRegistrationStatus::Registered => CatalogRegistrationKind::Registered,
        PackageRegistrationStatus::Certified => CatalogRegistrationKind::Certified,
        PackageRegistrationStatus::FutureUseNotRecommended => {
            CatalogRegistrationKind::FutureUse("FutureUseNotRecommended".into())
        }
        PackageRegistrationStatus::FutureUseNotAllowed => {
            CatalogRegistrationKind::FutureUse("FutureUseNotAllowed".into())
        }
    };
    CatalogRegistrationView {
        kind,
        registration_number: registration.registration_number,
        registration_date: registration.registration_date,
    }
}

fn non_instantiable_reason(leaf: &PackageCatalogLeaf) -> String {
    match leaf.instantiation {
        PackageInstantiation::CatalogOnly(PackageCatalogOnlyReason::NoApplicationProgram) => {
            return "Hardware declares no application program".into();
        }
        PackageInstantiation::Blocked(PackageInstantiationBlock::RegistrationStatus(status)) => {
            return format!("registration status {status} is not instantiable");
        }
        PackageInstantiation::Programmable => {}
    }
    for (kind, registration) in
        [("Product", &leaf.product_registration), ("Hardware2Program", &leaf.hardware2program_registration)]
    {
        if matches!(
            registration.status,
            PackageRegistrationStatus::FutureUseNotRecommended | PackageRegistrationStatus::FutureUseNotAllowed
        ) {
            return format!("{kind} registration status {} is not instantiable", registration.status);
        }
    }
    "The package relation is not instantiable".into()
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BranchPath(Vec<usize>);

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeafPath {
    section: BranchPath,
    item: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CatalogRowTarget {
    Branch(BranchPath),
    Leaf(LeafPath),
}

/// One cached visible row. Rebuilding the cache occurs only when expansion
/// changes, rather than cloning a large catalogue every rendered frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogRow {
    pub depth: usize,
    pub label: String,
    pub expanded: bool,
    pub has_children: bool,
    pub instantiable: bool,
    target: CatalogRowTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogAddField {
    DeviceId,
    IndividualAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogProjectDefaults {
    pub existing_device_ids: BTreeSet<String>,
    pub existing_addresses: BTreeSet<IndividualAddress>,
    pub area: u8,
    pub line: u8,
}

impl CatalogProjectDefaults {
    fn suggested_address(&self) -> String {
        (1..=u8::MAX)
            .map(|device| IndividualAddress::new(self.area, self.line, device))
            .find(|address| !self.existing_addresses.contains(address))
            .map_or_else(String::new, |address| address.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogAddRequest<S> {
    pub selector: S,
    pub device_id: ProjectDeviceId,
    pub address: IndividualAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogAddForm<S> {
    pub leaf: CatalogLeafView<S>,
    pub device_id: String,
    pub device_id_cursor: usize,
    pub address: String,
    pub address_cursor: usize,
    pub active_field: CatalogAddField,
    pub error: Option<String>,
}

impl<S: Clone> CatalogAddForm<S> {
    fn new(leaf: CatalogLeafView<S>, defaults: &CatalogProjectDefaults) -> Self {
        let device_id = suggested_device_id(&leaf, &defaults.existing_device_ids);
        let address = defaults.suggested_address();
        Self {
            device_id_cursor: device_id.len(),
            address_cursor: address.len(),
            device_id,
            address,
            leaf,
            active_field: CatalogAddField::DeviceId,
            error: None,
        }
    }

    pub fn toggle_field(&mut self) {
        self.active_field = match self.active_field {
            CatalogAddField::DeviceId => CatalogAddField::IndividualAddress,
            CatalogAddField::IndividualAddress => CatalogAddField::DeviceId,
        };
        self.error = None;
    }

    pub fn insert(&mut self, character: char) {
        if character.is_control() {
            return;
        }
        match self.active_field {
            CatalogAddField::DeviceId if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') => {
                self.device_id.insert(self.device_id_cursor, character);
                self.device_id_cursor += character.len_utf8();
            }
            CatalogAddField::IndividualAddress if character.is_ascii_digit() || character == '.' => {
                self.address.insert(self.address_cursor, character);
                self.address_cursor += character.len_utf8();
            }
            _ => return,
        }
        self.error = None;
    }

    pub fn backspace(&mut self) {
        let (buffer, cursor) = self.active_buffer_mut();
        if *cursor == 0 {
            return;
        }
        let previous = buffer[..*cursor].char_indices().next_back().map_or(0, |(index, _)| index);
        buffer.drain(previous..*cursor);
        *cursor = previous;
        self.error = None;
    }

    pub fn move_cursor_left(&mut self) {
        let (buffer, cursor) = self.active_buffer_mut();
        *cursor = buffer[..*cursor].char_indices().next_back().map_or(0, |(index, _)| index);
    }

    pub fn move_cursor_right(&mut self) {
        let (buffer, cursor) = self.active_buffer_mut();
        if *cursor < buffer.len() {
            *cursor += buffer[*cursor..].chars().next().expect("cursor is before one character").len_utf8();
        }
    }

    pub fn move_cursor_home(&mut self) {
        let (_, cursor) = self.active_buffer_mut();
        *cursor = 0;
    }

    pub fn move_cursor_end(&mut self) {
        let (buffer, cursor) = self.active_buffer_mut();
        *cursor = buffer.len();
    }

    fn active_buffer_mut(&mut self) -> (&mut String, &mut usize) {
        match self.active_field {
            CatalogAddField::DeviceId => (&mut self.device_id, &mut self.device_id_cursor),
            CatalogAddField::IndividualAddress => (&mut self.address, &mut self.address_cursor),
        }
    }

    fn validate(&mut self, defaults: &CatalogProjectDefaults) -> Option<CatalogAddRequest<S>> {
        let Ok(device_id) = ProjectDeviceId::new(self.device_id.as_str()) else {
            self.error = Some(
                "Device ID must start with a letter or underscore and contain only letters, digits, `_`, or `-`".into(),
            );
            return None;
        };
        if defaults.existing_device_ids.contains(&self.device_id) {
            self.error = Some(format!("Project already contains device `{}`", self.device_id));
            return None;
        }

        let address = match parse_individual_address(&self.address) {
            Ok(address) => address,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        if defaults.existing_addresses.contains(&address) {
            self.error = Some(format!("Project already uses individual address {address}"));
            return None;
        }
        if address.area() != defaults.area || address.line() != defaults.line {
            self.error =
                Some(format!("Individual address must remain on area {}, line {}", defaults.area, defaults.line));
            return None;
        }

        self.error = None;
        Some(CatalogAddRequest { selector: self.leaf.selector.clone(), device_id, address })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogDialogMode<S> {
    Browse,
    Add(Box<CatalogAddForm<S>>),
}

/// Modal catalogue browser and add-device form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCatalogDialog<S> {
    catalog: PackageCatalogView<S>,
    defaults: CatalogProjectDefaults,
    expanded: BTreeSet<BranchPath>,
    rows: Vec<CatalogRow>,
    selected: usize,
    scroll_offset: usize,
    mode: CatalogDialogMode<S>,
    notice: Option<String>,
}

impl<S: Clone> ProjectCatalogDialog<S> {
    pub fn new(catalog: PackageCatalogView<S>, defaults: CatalogProjectDefaults) -> Self {
        let expanded = (0..catalog.manufacturers.len()).map(|index| BranchPath(vec![index])).collect();
        let mut dialog = Self {
            catalog,
            defaults,
            expanded,
            rows: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            mode: CatalogDialogMode::Browse,
            notice: None,
        };
        dialog.rebuild_rows(None);
        dialog
    }

    pub fn rows(&self) -> &[CatalogRow] {
        &self.rows
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn mode(&self) -> &CatalogDialogMode<S> {
        &self.mode
    }

    pub fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    pub fn selected_leaf(&self) -> Option<&CatalogLeafView<S>> {
        let CatalogRowTarget::Leaf(path) = &self.rows.get(self.selected)?.target else { return None };
        self.leaf(path)
    }

    pub fn move_up(&mut self) {
        if matches!(self.mode, CatalogDialogMode::Browse) {
            self.selected = self.selected.saturating_sub(1);
            self.notice = None;
        }
    }

    pub fn move_down(&mut self) {
        if matches!(self.mode, CatalogDialogMode::Browse) {
            self.selected = (self.selected + 1).min(self.rows.len().saturating_sub(1));
            self.notice = None;
        }
    }

    pub fn move_left(&mut self) {
        if let CatalogDialogMode::Add(form) = &mut self.mode {
            form.move_cursor_left();
            return;
        }
        let Some(target) = self.rows.get(self.selected).map(|row| row.target.clone()) else { return };
        let parent = match target {
            CatalogRowTarget::Branch(path) if self.expanded.remove(&path) => {
                self.rebuild_rows(Some(CatalogRowTarget::Branch(path)));
                return;
            }
            CatalogRowTarget::Branch(path) => parent_branch(&path),
            CatalogRowTarget::Leaf(path) => Some(path.section),
        };
        let Some(parent) = parent else { return };
        if let Some(selected) =
            self.rows.iter().position(|row| matches!(&row.target, CatalogRowTarget::Branch(path) if path == &parent))
        {
            self.selected = selected;
        }
    }

    pub fn move_right(&mut self) {
        if let CatalogDialogMode::Add(form) = &mut self.mode {
            form.move_cursor_right();
            return;
        }
        let Some(CatalogRowTarget::Branch(path)) = self.rows.get(self.selected).map(|row| row.target.clone()) else {
            return;
        };
        if self.expanded.insert(path.clone()) {
            self.rebuild_rows(Some(CatalogRowTarget::Branch(path)));
        }
    }

    pub fn move_home(&mut self) {
        match &mut self.mode {
            CatalogDialogMode::Browse => self.selected = 0,
            CatalogDialogMode::Add(form) => form.move_cursor_home(),
        }
    }

    pub fn move_end(&mut self) {
        match &mut self.mode {
            CatalogDialogMode::Browse => self.selected = self.rows.len().saturating_sub(1),
            CatalogDialogMode::Add(form) => form.move_cursor_end(),
        }
    }

    /// Toggle a branch, open a leaf form, or validate that form.
    pub fn activate(&mut self) -> Option<CatalogAddRequest<S>> {
        if let CatalogDialogMode::Add(form) = &mut self.mode {
            return form.validate(&self.defaults);
        }

        let target = self.rows.get(self.selected)?.target.clone();
        match target {
            CatalogRowTarget::Branch(path) => {
                if !self.expanded.remove(&path) {
                    self.expanded.insert(path.clone());
                }
                self.rebuild_rows(Some(CatalogRowTarget::Branch(path)));
            }
            CatalogRowTarget::Leaf(path) => {
                let leaf = self.leaf(&path)?.clone();
                if !leaf.instantiable {
                    self.notice = Some(
                        leaf.non_instantiable_reason
                            .clone()
                            .unwrap_or_else(|| format!("{} is not an instantiable catalogue entry", leaf.name)),
                    );
                } else {
                    self.notice = None;
                    self.mode = CatalogDialogMode::Add(Box::new(CatalogAddForm::new(leaf, &self.defaults)));
                }
            }
        }
        None
    }

    /// Return `true` when the browser itself should close. Escape from the
    /// form first returns to the exact catalogue leaf that opened it.
    pub fn cancel(&mut self) -> bool {
        if matches!(self.mode, CatalogDialogMode::Browse) {
            return true;
        }
        self.mode = CatalogDialogMode::Browse;
        self.notice = None;
        false
    }

    pub fn toggle_add_field(&mut self) {
        if let CatalogDialogMode::Add(form) = &mut self.mode {
            form.toggle_field();
        }
    }

    pub fn insert(&mut self, character: char) {
        if let CatalogDialogMode::Add(form) = &mut self.mode {
            form.insert(character);
        }
    }

    pub fn backspace(&mut self) {
        if let CatalogDialogMode::Add(form) = &mut self.mode {
            form.backspace();
        }
    }

    pub fn set_add_error(&mut self, error: impl Into<String>) {
        if let CatalogDialogMode::Add(form) = &mut self.mode {
            form.error = Some(error.into());
        }
    }

    pub fn scroll_offset_for(&mut self, visible_rows: usize) -> usize {
        let visible_rows = visible_rows.max(1);
        if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        } else if self.selected >= self.scroll_offset + visible_rows {
            self.scroll_offset = self.selected + 1 - visible_rows;
        }
        self.scroll_offset
    }

    fn rebuild_rows(&mut self, retain: Option<CatalogRowTarget>) {
        let mut rows = Vec::new();
        let mut manufacturers = (0..self.catalog.manufacturers.len()).collect::<Vec<_>>();
        manufacturers.sort_by(|left, right| {
            let left = &self.catalog.manufacturers[*left];
            let right = &self.catalog.manufacturers[*right];
            natural_cmp(left.display_name(), right.display_name()).then_with(|| natural_cmp(&left.id, &right.id))
        });
        for manufacturer_index in manufacturers {
            let manufacturer = &self.catalog.manufacturers[manufacturer_index];
            let path = BranchPath(vec![manufacturer_index]);
            let expanded = self.expanded.contains(&path);
            rows.push(CatalogRow {
                depth: 0,
                label: manufacturer.row_label(),
                expanded,
                has_children: !manufacturer.sections.is_empty(),
                instantiable: false,
                target: CatalogRowTarget::Branch(path.clone()),
            });
            if expanded {
                append_sections(&manufacturer.sections, &path, 1, &self.expanded, &mut rows);
            }
        }
        self.rows = rows;
        self.selected = retain
            .and_then(|target| self.rows.iter().position(|row| row.target == target))
            .unwrap_or_else(|| self.selected.min(self.rows.len().saturating_sub(1)));
    }

    fn leaf(&self, path: &LeafPath) -> Option<&CatalogLeafView<S>> {
        let section = self.section(&path.section)?;
        section.items.get(path.item)
    }

    fn section(&self, path: &BranchPath) -> Option<&CatalogSectionView<S>> {
        let (&manufacturer, sections) = path.0.split_first()?;
        let (&first, rest) = sections.split_first()?;
        let mut section = self.catalog.manufacturers.get(manufacturer)?.sections.get(first)?;
        for &index in rest {
            section = section.subsections.get(index)?;
        }
        Some(section)
    }
}

enum ChildIndex {
    Section(usize),
    Item(usize),
}

fn append_sections<S>(
    sections: &[CatalogSectionView<S>],
    parent: &BranchPath,
    depth: usize,
    expanded_paths: &BTreeSet<BranchPath>,
    rows: &mut Vec<CatalogRow>,
) {
    let mut indices = (0..sections.len()).collect::<Vec<_>>();
    indices.sort_by(|left, right| compare_sections(&sections[*left], &sections[*right]));
    for section_index in indices {
        append_section(&sections[section_index], section_index, parent, depth, expanded_paths, rows);
    }
}

fn append_section<S>(
    section: &CatalogSectionView<S>,
    section_index: usize,
    parent: &BranchPath,
    depth: usize,
    expanded_paths: &BTreeSet<BranchPath>,
    rows: &mut Vec<CatalogRow>,
) {
    let mut path = parent.clone();
    path.0.push(section_index);
    let expanded = expanded_paths.contains(&path);
    let has_children = !section.items.is_empty() || !section.subsections.is_empty();
    rows.push(CatalogRow {
        depth,
        label: section.name.clone(),
        expanded,
        has_children,
        instantiable: false,
        target: CatalogRowTarget::Branch(path.clone()),
    });
    if !expanded {
        return;
    }

    let mut children = section
        .subsections
        .iter()
        .enumerate()
        .map(|(index, subsection)| (subsection.number.as_str(), subsection.name.as_str(), ChildIndex::Section(index)))
        .chain(
            section
                .items
                .iter()
                .enumerate()
                .map(|(index, item)| (item.catalog_number.as_str(), item.name.as_str(), ChildIndex::Item(index))),
        )
        .collect::<Vec<_>>();
    children.sort_by(|left, right| natural_cmp(left.0, right.0).then_with(|| natural_cmp(left.1, right.1)));
    for (_, _, child) in children {
        match child {
            ChildIndex::Section(index) => {
                append_section(&section.subsections[index], index, &path, depth + 1, expanded_paths, rows);
            }
            ChildIndex::Item(item) => {
                let leaf = &section.items[item];
                rows.push(CatalogRow {
                    depth: depth + 1,
                    label: leaf.row_label(),
                    expanded: false,
                    has_children: false,
                    instantiable: leaf.instantiable,
                    target: CatalogRowTarget::Leaf(LeafPath { section: path.clone(), item }),
                });
            }
        }
    }
}

fn compare_sections<S>(left: &CatalogSectionView<S>, right: &CatalogSectionView<S>) -> Ordering {
    natural_cmp(&left.number, &right.number).then_with(|| natural_cmp(&left.name, &right.name))
}

fn parent_branch(path: &BranchPath) -> Option<BranchPath> {
    (path.0.len() > 1).then(|| BranchPath(path.0[..path.0.len() - 1].to_vec()))
}

fn suggested_device_id<S>(leaf: &CatalogLeafView<S>, existing: &BTreeSet<String>) -> String {
    let basis = leaf.order_number.as_deref().filter(|value| !value.is_empty()).unwrap_or(&leaf.name);
    let mut stem = String::new();
    let mut separator = false;
    for character in basis.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            if separator && !stem.is_empty() {
                stem.push('-');
            }
            separator = false;
            stem.push(character.to_ascii_lowercase());
        } else {
            separator = true;
        }
    }
    if stem.is_empty() {
        stem.push_str("device");
    } else if !stem.starts_with(|character: char| character.is_ascii_alphabetic() || character == '_') {
        stem.insert_str(0, "device-");
    }

    if !existing.contains(&stem) {
        return stem;
    }
    for suffix in 2.. {
        let candidate = format!("{stem}-{suffix}");
        if !existing.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!("an unbounded numeric suffix eventually produces a unique ID")
}

pub fn parse_individual_address(value: &str) -> Result<IndividualAddress, String> {
    value.parse().map_err(|error| format!("Individual address: {error}; expected area.line.device"))
}

fn short_digest(digest: &str) -> String {
    let raw = digest.strip_prefix("sha256:").or_else(|| digest.strip_prefix("sha256-")).unwrap_or(digest);
    let short = raw.chars().take(12).collect::<String>();
    format!("sha256:{short}")
}

/// Natural comparison keeps catalogue number 2 before 10 without assuming
/// that vendor-authored numbers contain only digits.
fn natural_cmp(left: &str, right: &str) -> Ordering {
    let raw_left = left;
    let raw_right = right;
    let left = left.as_bytes();
    let right = right.as_bytes();
    let (mut left_at, mut right_at) = (0, 0);
    while left_at < left.len() && right_at < right.len() {
        if left[left_at].is_ascii_digit() && right[right_at].is_ascii_digit() {
            let left_end = digit_run_end(left, left_at);
            let right_end = digit_run_end(right, right_at);
            let left_digits = trim_zeroes(&left[left_at..left_end]);
            let right_digits = trim_zeroes(&right[right_at..right_end]);
            let order = left_digits
                .len()
                .cmp(&right_digits.len())
                .then_with(|| left_digits.cmp(right_digits))
                .then_with(|| (left_end - left_at).cmp(&(right_end - right_at)));
            if order != Ordering::Equal {
                return order;
            }
            left_at = left_end;
            right_at = right_end;
        } else {
            let order = left[left_at].to_ascii_lowercase().cmp(&right[right_at].to_ascii_lowercase());
            if order != Ordering::Equal {
                return order;
            }
            left_at += 1;
            right_at += 1;
        }
    }
    left.len().saturating_sub(left_at).cmp(&right.len().saturating_sub(right_at)).then_with(|| raw_left.cmp(raw_right))
}

fn digit_run_end(value: &[u8], mut at: usize) -> usize {
    while at < value.len() && value[at].is_ascii_digit() {
        at += 1;
    }
    at
}

fn trim_zeroes(mut value: &[u8]) -> &[u8] {
    while value.len() > 1 && value[0] == b'0' {
        value = &value[1..];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(kind: CatalogRegistrationKind) -> CatalogRegistrationView {
        CatalogRegistrationView { kind, registration_number: None, registration_date: None }
    }

    fn leaf(selector: &str, digest: &str, name: &str, instantiable: bool) -> CatalogLeafView<String> {
        CatalogLeafView {
            selector: selector.into(),
            package_digest: digest.into(),
            catalog_item_id: "M-00FA_CI-1".into(),
            manufacturer_id: "M-00FA".into(),
            product_id: "M-00FA_H-1_P-1".into(),
            hardware_id: "M-00FA_H-1".into(),
            hardware2program_id: "M-00FA_H-1_HP-1".into(),
            application_program_ids: vec!["M-00FA_A-0001-01-0000".into()],
            name: name.into(),
            catalog_number: "1".into(),
            order_number: Some("TA-10".into()),
            medium_types: "MT-0".into(),
            mask_version: Some("MV-07B0".into()),
            supports_data_secure: Some(true),
            product_registration: registration(CatalogRegistrationKind::Registered),
            h2p_registration: registration(CatalogRegistrationKind::Registered),
            effective_registration: registration(CatalogRegistrationKind::Registered),
            instantiable,
            non_instantiable_reason: (!instantiable).then(|| "FutureUse is not instantiable".into()),
            chain_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        }
    }

    fn fixture() -> PackageCatalogView<String> {
        PackageCatalogView {
            manufacturers: vec![CatalogManufacturerView {
                id: "M-00FA".into(),
                name: Some("Example Devices".into()),
                sections: vec![CatalogSectionView {
                    id: "M-00FA_CS-1".into(),
                    name: "Push buttons".into(),
                    number: "1".into(),
                    items: vec![
                        leaf("old", "sha256:11111111111111111111", "Button", true),
                        leaf("new", "sha256:22222222222222222222", "Button", true),
                    ],
                    subsections: vec![CatalogSectionView {
                        id: "M-00FA_CS-1-10".into(),
                        name: "Series 10".into(),
                        number: "10".into(),
                        items: vec![leaf("future", "sha256:33333333333333333333", "Future", false)],
                        subsections: Vec::new(),
                    }],
                }],
            }],
        }
    }

    fn defaults() -> CatalogProjectDefaults {
        CatalogProjectDefaults {
            existing_device_ids: BTreeSet::from(["ta-10".into()]),
            existing_addresses: BTreeSet::from([IndividualAddress::new(1, 1, 1)]),
            area: 1,
            line: 1,
        }
    }

    fn select_leaf(dialog: &mut ProjectCatalogDialog<String>, selector: &str) {
        dialog.selected = dialog
            .rows
            .iter()
            .position(|row| match &row.target {
                CatalogRowTarget::Leaf(path) => dialog.leaf(path).is_some_and(|leaf| leaf.selector == selector),
                CatalogRowTarget::Branch(_) => false,
            })
            .expect("requested leaf is visible");
    }

    fn select_branch(dialog: &mut ProjectCatalogDialog<String>, label: &str) {
        dialog.selected = dialog
            .rows
            .iter()
            .position(|row| matches!(row.target, CatalogRowTarget::Branch(_)) && row.label == label)
            .expect("requested branch is visible");
    }

    #[test]
    fn package_variants_keep_distinct_selectors_and_digest_labels() {
        let mut dialog = ProjectCatalogDialog::new(fixture(), defaults());
        dialog.move_down();
        dialog.activate();

        assert!(dialog.rows().iter().any(|row| row.label.contains("sha256:111111111111")));
        assert!(dialog.rows().iter().any(|row| row.label.contains("sha256:222222222222")));
        let selectors = dialog
            .rows
            .iter()
            .filter_map(|row| match &row.target {
                CatalogRowTarget::Leaf(path) => dialog.leaf(path).map(|leaf| leaf.selector.as_str()),
                CatalogRowTarget::Branch(_) => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(selectors, ["old", "new"]);
    }

    #[test]
    fn left_collapses_then_selects_the_parent() {
        let mut dialog = ProjectCatalogDialog::new(fixture(), defaults());
        dialog.move_down();
        dialog.move_right();
        dialog.move_down();

        dialog.move_left();

        assert_eq!(dialog.rows()[dialog.selected()].label, "Push buttons");
        dialog.move_left();
        assert!(!dialog.rows()[dialog.selected()].expanded);
    }

    #[test]
    fn form_suggests_unique_values_and_returns_the_exact_selector() {
        let mut dialog = ProjectCatalogDialog::new(fixture(), defaults());
        dialog.move_down();
        dialog.activate();
        select_leaf(&mut dialog, "old");
        dialog.activate();

        let CatalogDialogMode::Add(form) = dialog.mode() else { panic!("leaf opens add form") };
        assert_eq!(form.device_id, "ta-10-2");
        assert_eq!(form.address, "1.1.2");

        let request = dialog.activate().expect("valid defaults confirm");
        assert_eq!(request.selector, "old");
        assert_eq!(request.device_id.as_str(), "ta-10-2");
        assert_eq!(request.address, IndividualAddress::new(1, 1, 2));
    }

    #[test]
    fn future_use_leaf_stays_visible_but_cannot_open_a_form() {
        let mut dialog = ProjectCatalogDialog::new(fixture(), defaults());
        dialog.move_down();
        dialog.activate();
        select_branch(&mut dialog, "Series 10");
        dialog.activate();
        select_leaf(&mut dialog, "future");
        dialog.activate();

        assert!(matches!(dialog.mode(), CatalogDialogMode::Browse));
        assert_eq!(dialog.notice(), Some("FutureUse is not instantiable"));
    }

    #[test]
    fn address_parser_rejects_values_that_the_wire_type_would_mask() {
        assert_eq!(parse_individual_address("15.15.255"), Ok(IndividualAddress::new(15, 15, 255)));
        assert!(parse_individual_address("16.1.1").is_err());
        assert!(parse_individual_address("1.16.1").is_err());
        assert!(parse_individual_address("1.1.256").is_err());
        assert!(parse_individual_address("1.1").is_err());
    }

    #[test]
    fn add_form_rejects_moving_the_device_to_another_authored_line() {
        let mut dialog = ProjectCatalogDialog::new(fixture(), defaults());
        dialog.move_down();
        dialog.activate();
        select_leaf(&mut dialog, "old");
        dialog.activate();
        let CatalogDialogMode::Add(form) = &mut dialog.mode else { panic!("leaf opens add form") };
        form.address = "1.2.2".into();
        form.address_cursor = form.address.len();

        assert!(dialog.activate().is_none());
        let CatalogDialogMode::Add(form) = dialog.mode() else { panic!("invalid form remains open") };
        assert!(form.error.as_deref().is_some_and(|error| error.contains("area 1, line 1")));
    }

    #[test]
    fn second_sibling_subsection_keeps_its_real_path_and_leaf_selector() {
        let mut catalog = fixture();
        let root = &mut catalog.manufacturers[0].sections[0];
        root.subsections.push(CatalogSectionView {
            id: "M-00FA_CS-1-20".into(),
            name: "Series 20".into(),
            number: "20".into(),
            items: Vec::new(),
            subsections: vec![CatalogSectionView {
                id: "M-00FA_CS-1-20-1".into(),
                name: "Flush mounted".into(),
                number: "1".into(),
                items: vec![leaf("nested", "sha256:44444444444444444444", "Nested", true)],
                subsections: Vec::new(),
            }],
        });
        let mut dialog = ProjectCatalogDialog::new(catalog, defaults());
        select_branch(&mut dialog, "Push buttons");
        dialog.activate();
        select_branch(&mut dialog, "Series 20");
        dialog.activate();
        select_branch(&mut dialog, "Flush mounted");
        dialog.activate();
        select_leaf(&mut dialog, "nested");

        assert_eq!(dialog.selected_leaf().map(|leaf| leaf.selector.as_str()), Some("nested"));
        dialog.activate();
        assert!(matches!(dialog.mode(), CatalogDialogMode::Add(form) if form.leaf.selector == "nested"));
    }

    #[test]
    fn registration_label_keeps_status_number_and_date() {
        let certified = CatalogRegistrationView {
            kind: CatalogRegistrationKind::Certified,
            registration_number: Some("KNX-1234".into()),
            registration_date: Some("2026-08-31".into()),
        };

        assert_eq!(certified.label(), "Certified · no. KNX-1234 · 2026-08-31");
    }

    #[test]
    fn manufacturer_rows_use_names_sort_by_them_and_fall_back_to_ids() {
        let catalog = PackageCatalogView::<String> {
            manufacturers: vec![
                CatalogManufacturerView { id: "M-0003".into(), name: Some("Zeta".into()), sections: Vec::new() },
                CatalogManufacturerView { id: "M-0002".into(), name: None, sections: Vec::new() },
                CatalogManufacturerView { id: "M-0001".into(), name: Some("Alpha".into()), sections: Vec::new() },
            ],
        };

        let dialog = ProjectCatalogDialog::new(catalog, defaults());
        let labels =
            dialog.rows().iter().filter(|row| row.depth == 0).map(|row| row.label.as_str()).collect::<Vec<_>>();

        assert_eq!(labels, ["Alpha (M-0001)", "M-0002", "Zeta (M-0003)"]);
    }

    #[test]
    fn natural_order_handles_vendor_catalogue_numbers() {
        assert_eq!(natural_cmp("2", "10"), Ordering::Less);
        assert_eq!(natural_cmp("2.9", "2.10"), Ordering::Less);
        assert_eq!(natural_cmp("Series 9", "series 10"), Ordering::Less);
        assert_eq!(natural_cmp("series", "Series"), Ordering::Greater);
        assert_eq!(natural_cmp("2", "02"), Ordering::Less);
    }
}
