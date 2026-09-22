//! KNX project and product TUI.
//!
//! A terminal user interface for viewing and exploring KNX ApplicationProgram
//! MTXML files.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
use dialoguer::Select;
use dialoguer::theme::ColorfulTheme;
use log::LevelFilter;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use simplelog::{Config, WriteLogger};

use knxproj_tui::app::{self, App, EditorDocument, LoadedProjectDevice, ProjectContext};
use knxproj_tui::catalog_view::CatalogAddRequest;
use knxproj_tui::error_message;
use knxproj_tui::ui;
use zweidraehte_client::project::{ProjectProduct, product_configuration as project_product_configuration};
use zweidraehte_ets_files::MasterData;
use zweidraehte_ets_files::archive::{
    KnxprodDevice, PackageArchive, PackageCatalogIndex, PackageCatalogLeaf, PackageCatalogSelector, PackageDigest,
    PackageStore, ProgramSelection,
};
use zweidraehte_ets_files::product::SelectedProduct;
use zweidraehte_ets_files::runtime::baggage::BaggageIndex;
use zweidraehte_ets_files::runtime::configuration::ProductConfiguration;
use zweidraehte_ets_files::runtime::parser::ProgramSummary;
use zweidraehte_project::{
    AuthoredProject, DataSecureMode, Medium, MembershipRole, ProductReference, ProjectDeviceDraft, ProjectDeviceId,
    ProjectPackageId, ProjectStore,
};
use zweidraehte_proto::address::GroupAddress;

/// KNX ApplicationProgram TUI Viewer
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// A project.knx, MTXML, or .knxprod file
    #[arg()]
    file: PathBuf,

    /// Path to knx_master.xml for mask version info (enables proper table generation)
    #[arg(short = 'M', long)]
    master_data: Option<PathBuf>,

    /// Device to open when the input is project.knx (defaults to its first)
    #[arg(short, long)]
    device: Option<String>,

    /// Application program ID for non-interactive standalone product selection
    #[arg(long, value_name = "ID", conflicts_with = "catalog_item")]
    application: Option<String>,

    /// Exact CatalogItem ID for non-interactive standalone `.knxprod` selection
    #[arg(long, value_name = "ID")]
    catalog_item: Option<String>,

    /// Start with this display language (e.g. de-DE); `L` selects another
    /// available language at runtime
    #[arg(short, long)]
    language: Option<String>,

    /// Bus access for programming the device with `p` (KNX/IP
    /// tunneling or USB)
    #[command(flatten)]
    target: zweidraehte_client::cli::OptionalTargetArgs,

    /// Data Secure keyring and sequence-number persistence
    #[command(flatten)]
    security: zweidraehte_client::cli::SecurityArgs,

    /// Print summary only (no TUI)
    #[arg(long)]
    summary: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize file logging
    let log_file = File::create("/tmp/knxproj-tui.log")?;
    WriteLogger::init(LevelFilter::Debug, Config::default(), log_file)?;
    log::info!("KNX TUI starting");

    let is_project = args.file.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("knx"));
    // Standalone baggage is a temporary view, owned for the full editor session.
    let standalone_resources = (!is_project).then(tempfile::tempdir).transpose()?;
    let (
        editor,
        project_context,
        product_configuration,
        bindings,
        project_flags,
        project_language,
        mut package_catalog,
    ) = if is_project {
        if args.application.is_some() || args.catalog_item.is_some() {
            return Err(
                    "--application/--catalog-item apply to standalone product files; project.knx stores an exact package/CatalogItem selector"
                        .into(),
                );
        }
        let store = ProjectStore::open(&args.file)?;
        let authored = store.authored().clone();
        let device_id = args
            .device
            .as_ref()
            .map(|id| ProjectDeviceId(id.clone()))
            .or_else(|| authored.devices.keys().next().cloned())
            .ok_or("the project contains no devices")?;
        let authored_device =
            authored.devices.get(&device_id).ok_or_else(|| format!("project has no device `{device_id}`"))?;
        let editor = load_project_document(&authored, authored_device)?;
        let configuration = project_product_configuration(authored_device);
        let bindings = project_object_bindings(&authored, authored_device);
        let flags = authored_device.objects.values().map(|object| (object.com_object, object.flags)).collect();
        let project_language = authored.language.clone();
        let source = authored.source().to_string();
        let packages = PackageStore::new(
            authored.package_store_directory().ok_or("project source has no package-store directory")?,
        );
        let catalog = (!args.summary).then(|| packages.catalog_index()).transpose()?;
        (
            editor,
            ProjectContext {
                path: args.file.clone(),
                device: device_id,
                authored: Some(authored),
                original_source: Some(source),
            },
            configuration,
            bindings,
            flags,
            project_language,
            catalog,
        )
    } else {
        let editor = load_standalone_document(
            &args.file,
            args.catalog_item.as_deref(),
            args.application.as_deref(),
            standalone_resources.as_ref().expect("standalone input owns its resources").path(),
        )?;
        (
            editor,
            ProjectContext {
                path: args.file.clone(),
                device: ProjectDeviceId("standalone-product".into()),
                authored: None,
                original_source: None,
            },
            ProductConfiguration::default(),
            Vec::new(),
            BTreeMap::new(),
            None,
            None,
        )
    };

    // Print summary if requested
    if args.summary {
        if let Some(summary) = ProgramSummary::from_knx(editor.document()) {
            println!("Application Program: {}", summary.name);
            println!("  ID: {}", summary.id);
            println!("  Mask Version: {}", summary.mask_version);
            println!();
            println!("Static Section:");
            println!("  Parameter Types: {}", summary.parameter_type_count);
            println!("  Parameters: {}", summary.parameter_count);
            println!("  Parameter Refs: {}", summary.parameter_ref_count);
            println!("  ComObjects: {}", summary.com_object_count);
            println!("  ComObject Refs: {}", summary.com_object_ref_count);
            println!("  Code Segments: {}", summary.code_segment_count);
            println!();
            println!("Dynamic Section:");
            println!(
                "  Channel-Independent Block: {}",
                if summary.has_channel_independent_block { "yes" } else { "no" }
            );
            println!("  Channels: {}", summary.channel_count);
        } else {
            println!("No application program found in file.");
        }
        return Ok(());
    }

    let explicit_master_data = args.master_data.as_deref().filter(|_| editor.product().master_data().is_none());
    let requested_language = args.language.as_deref().or(project_language.as_deref());
    let product = editor.prepare(&product_configuration, bindings, requested_language, args.master_data.as_deref())?;

    // Reuse the prepared document for catalogue labels and diagnostics.
    if let Some(path) = explicit_master_data {
        let master = product.master_data();
        eprintln!("Loaded {} mask versions from {:?}", master.mask_version_count(), path);
        if let Some(catalog) = &mut package_catalog {
            override_catalog_manufacturer_names(catalog, master);
        }
    }
    if let Some(language) = requested_language {
        if product.current_language().is_some() {
            eprintln!("Display language: {language}");
        } else {
            eprintln!("Product has no language {language:?}; using default {}", product.default_language());
        }
    }

    let mut app = App::new(product);
    app.set_project_context(project_context, project_flags);
    if let Some(catalog) = package_catalog {
        app.set_package_catalog(catalog);
    }
    app.set_download_context(app::DownloadContext {
        target: args.target.to_target(),
        master_data: args.master_data.clone(),
        security: args.security,
    });

    // Run TUI
    run_tui(app)?;

    Ok(())
}

/// An explicitly selected Master Data document is authoritative for this TUI
/// session. Unknown IDs deliberately clear an older store-derived label so the
/// catalogue falls back to the stable `M-xxxx` identity instead of mixing two
/// manufacturer-directory generations.
fn override_catalog_manufacturer_names(catalog: &mut PackageCatalogIndex, master_data: &MasterData) {
    for manufacturer in &mut catalog.manufacturers {
        manufacturer.name = master_data.manufacturer_name(&manufacturer.id).map(str::to_owned);
        manufacturer.name_source_schema_version = manufacturer.name.as_ref().and_then(|_| master_data.schema_version());
        manufacturer.name_source_version =
            manufacturer.name.as_ref().and_then(|_| master_data.document_version().parse::<u64>().ok());
    }
}

fn load_standalone_document(
    path: &Path,
    catalog_item: Option<&str>,
    application_program: Option<&str>,
    baggage_cache: &Path,
) -> Result<EditorDocument, Box<dyn std::error::Error>> {
    if path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("knxprod")) {
        let archive = PackageArchive::open(path)?;
        let choice = select_archive_device(&archive, path, catalog_item, application_program)?;
        let selected = match choice.catalog_item_id {
            Some(item) => archive.load_product(&item)?,
            None => archive.load_application(&choice.application_program_id)?,
        };
        let baggage = archive
            .materialize_baggages_from_document(selected.document(), baggage_cache)?
            .map(|root| BaggageIndex::from_directory(&root))
            .transpose()?;
        return Ok(EditorDocument::new(selected, baggage));
    }
    if catalog_item.is_some() {
        return Err("--catalog-item requires a .knxprod archive".into());
    }
    let loaded = zweidraehte_ets_files::archive::load_program(path, ProgramSelection {
        catalog_product: None,
        application_program,
    })?;
    let selected = SelectedProduct::from_document(loaded.document, None, None)?;
    let baggage = path.parent().and_then(|directory| BaggageIndex::from_directory(directory).ok());
    Ok(EditorDocument::new(selected, baggage))
}

fn project_package_selector(device: &zweidraehte_project::ProjectDevice) -> PackageCatalogSelector {
    let ProductReference::Package { package, catalog_item } = &device.product;
    PackageCatalogSelector {
        package: PackageDigest::from_bytes(*package.as_bytes()),
        catalog_item_id: catalog_item.clone(),
    }
}

/// Resolve the exact package and CatalogItem authored for one project device.
/// Product, H2P, AP1, and optional AP2 identities are derived from this leaf;
/// no independently authored selector is allowed to drift from the package.
fn load_project_document(
    project: &AuthoredProject,
    device: &zweidraehte_project::ProjectDevice,
) -> Result<EditorDocument, Box<dyn std::error::Error>> {
    let selector = project_package_selector(device);
    let packages = PackageStore::new(
        project.package_store_directory().ok_or("project source has no filesystem path for its package store")?,
    );
    let package = packages.open(selector.package)?;
    let leaf = package
        .leaves()
        .find(|leaf| leaf.selector == selector)
        .cloned()
        .ok_or_else(|| zweidraehte_ets_files::archive::PackageStoreError::UnknownCatalogItem(selector.clone()))?;
    let selected = package.load_product(&selector)?;
    let baggage = package
        .materialize_baggages_from_document(&leaf, selected.document())?
        .map(|root| BaggageIndex::from_directory(&root))
        .transpose()?;
    Ok(EditorDocument::new(selected, baggage))
}

fn select_archive_device(
    archive: &PackageArchive,
    path: &Path,
    catalog_item: Option<&str>,
    application_program: Option<&str>,
) -> Result<KnxprodDevice, Box<dyn std::error::Error>> {
    let devices = archive.importable_devices()?;
    if devices.is_empty() {
        return Err(format!("{} contains no importable device", path.display()).into());
    }
    if let Some(catalog_item) = catalog_item {
        let matches = devices
            .into_iter()
            .filter(|device| device.catalog_item_id.as_deref() == Some(catalog_item))
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [device] if application_program.is_none_or(|id| id == device.application_program_id) => Ok(device.clone()),
            [_] => Err("--catalog-item and --application select different applications".into()),
            [] => Err(format!("{} has no CatalogItem `{catalog_item}`", path.display()).into()),
            _ => Err(format!(
                "{} contains {} relations for CatalogItem `{catalog_item}`; the archive is ambiguous",
                path.display(),
                matches.len()
            )
            .into()),
        };
    }
    if let Some(application_program) = application_program {
        let matches = devices
            .into_iter()
            .filter(|device| device.application_program_id == application_program)
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [device] => Ok(device.clone()),
            [] => Err(format!("{} has no device using application `{application_program}`", path.display()).into()),
            _ => Err(format!(
                "application `{application_program}` is used by {} catalogue items; select one with --catalog-item",
                matches.len()
            )
            .into()),
        };
    }
    if devices.len() == 1 {
        return Ok(devices.into_iter().next().expect("one device checked"));
    }

    let labels = devices.iter().map(archive_device_label).collect::<Vec<_>>();
    let selected = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select the KNX product to open")
        .items(&labels)
        .default(0)
        .interact_opt()?
        .ok_or("product selection cancelled")?;
    Ok(devices[selected].clone())
}

fn archive_device_label(device: &KnxprodDevice) -> String {
    format!(
        "{}{} — {} — {} — {}{}",
        device.name,
        device.order_number.as_ref().map_or_else(String::new, |number| format!(" [{number}]")),
        device.catalog_item_id.as_deref().unwrap_or("no CatalogItem"),
        device.mask_version,
        device.application_program_id,
        if device.supports_data_secure { " — Data Secure" } else { "" }
    )
}

fn load_project_editor(
    context: ProjectContext,
    device_id: &ProjectDeviceId,
    preferred_language: Option<&str>,
    master_data: Option<&Path>,
) -> Result<LoadedProjectDevice, Box<dyn std::error::Error>> {
    let authored = context.authored.as_ref().ok_or("project context has no authored project")?;
    let authored_device =
        authored.devices.get(device_id).ok_or_else(|| format!("project has no device `{device_id}`"))?;
    let product = load_project_document(authored, authored_device)?.prepare(
        &project_product_configuration(authored_device),
        project_object_bindings(authored, authored_device),
        preferred_language.or(authored.language.as_deref()),
        master_data,
    )?;
    let flags = authored_device.objects.values().map(|object| (object.com_object, object.flags)).collect();
    Ok(LoadedProjectDevice {
        product,
        context: ProjectContext {
            path: context.path,
            device: device_id.clone(),
            authored: context.authored,
            original_source: context.original_source,
        },
        flags,
    })
}

fn project_object_bindings(
    project: &zweidraehte_project::AuthoredProject,
    device: &zweidraehte_project::ProjectDevice,
) -> Vec<(u16, Vec<GroupAddress>)> {
    device
        .objects
        .values()
        .map(|object| {
            let mut memberships = object.memberships.clone();
            memberships.sort_by_key(|membership| membership.role != MembershipRole::Primary);
            let addresses = memberships.iter().map(|membership| project.nets[&membership.net].address).collect();
            (object.com_object, addresses)
        })
        .collect()
}

fn validate_catalog_medium(leaf: &PackageCatalogLeaf, medium: Medium) -> Result<(), String> {
    let required = match medium {
        Medium::Tp1 => "MT-0",
        Medium::Rf => "MT-2",
        Medium::Ip => "MT-5",
    };
    if leaf.medium_types.split_whitespace().any(|candidate| candidate == required) {
        return Ok(());
    }
    Err(format!(
        "CatalogItem {:?} declares H2P MediumTypes={:?}, which is incompatible with the authored {:?} line ({required})",
        leaf.selector.catalog_item_id, leaf.medium_types, medium
    ))
}

/// Stage one exact catalogue leaf into the lossless authored source. The
/// package store is read-only here; the project remains staged until `e` or a
/// programming/unload operation invokes the normal save path.
fn add_catalog_device(
    app: &mut App,
    request: CatalogAddRequest<PackageCatalogSelector>,
) -> Result<ProjectDeviceId, String> {
    let mut context = app.stage_current_project_device()?;
    let project = context.authored.as_ref().ok_or_else(|| {
        "standalone product files are editor-only; open a project before adding a catalogue device".to_string()
    })?;
    let packages = PackageStore::new(
        project
            .package_store_directory()
            .ok_or_else(|| "project source has no filesystem path for its package store".to_string())?,
    );
    let leaf = packages.resolve_catalog_item(&request.selector).map_err(|error| error.to_string())?;
    if !leaf.instantiable {
        return Err(format!(
            "CatalogItem {:?} is not instantiable: registration {}",
            leaf.selector.catalog_item_id, leaf.effective_registration.status,
        ));
    }
    ProjectProduct::load(&packages, &request.selector)
        .map_err(|error| format!("loading the selected package relation: {error}"))?;

    let line = project.line_topology(request.address.area(), request.address.line()).ok_or_else(|| {
        format!("project has no unique area {}, line {}", request.address.area(), request.address.line())
    })?;
    validate_catalog_medium(&leaf, line.medium)?;

    let device_id = ProjectDeviceId(request.device_id);
    let draft = ProjectDeviceDraft {
        id: device_id.clone(),
        active: true,
        product: ProductReference::Package {
            package: ProjectPackageId::from_bytes(*request.selector.package.as_bytes()),
            catalog_item: request.selector.catalog_item_id,
        },
        address: request.address,
        medium: line.medium,
        domain: line.domain,
        ip_line: line.ip,
        rf_mode: None,
        ip: None,
        routing: None,
        serial: None,
        max_apdu: None,
        data_secure: DataSecureMode::Disabled,
        parameters: Vec::new(),
        objects: BTreeMap::new(),
        nets: BTreeMap::new(),
    };
    let source = project.render_device_add(&draft).map_err(|error| error.to_string())?;
    let authored = project.reparse(source).map_err(|error| error.to_string())?;
    authored.validate_download().map_err(|error| {
        error.diagnostics().iter().map(|diagnostic| diagnostic.message.as_str()).collect::<Vec<_>>().join("; ")
    })?;
    context.device = device_id.clone();
    context.authored = Some(authored);

    let loaded = load_project_editor(context, &device_id, None, app.master_data_override())
        .map_err(|error| error_message(&*error))?;
    app.finish_catalog_add();
    app.open_project_device(loaded);
    app.set_status_message(format!("Added project device {device_id}; press e to save"));
    Ok(device_id)
}

fn switch_project_device(app: &mut App, device: ProjectDeviceId) -> Result<(), String> {
    let context = app.stage_current_project_device()?;
    let loaded = load_project_editor(context, &device, None, app.master_data_override())
        .map_err(|error| error_message(&*error))?;
    app.open_project_device(loaded);
    Ok(())
}

fn run_tui(mut app: App) -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    // The editor has no mouse interactions. Leaving mouse capture disabled
    // preserves the terminal's native drag-to-select and copy behavior.
    execute!(stdout, EnterAlternateScreen)?;
    #[cfg(feature = "images")]
    app.initialize_image_picker();

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Main loop
    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result?;
    app.persist_tui_preferences().map_err(io::Error::other)
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> io::Result<()> {
    // Building a frame is expensive on large products, so two rules keep
    // the UI responsive: only draw when something changed (a handled
    // event, a resize, or a running download animating), and drain the
    // whole input backlog before drawing so key autorepeat coalesces
    // into one redraw instead of queueing a frame per keypress.
    let mut needs_redraw = true;
    loop {
        needs_redraw |= app.poll_startup_status();
        app.poll_download();
        needs_redraw |= app.poll_status_message();
        if needs_redraw || app.startup_status_active() || app.operations().download_active() {
            terminal.draw(|frame| ui::render(frame, app))?;
            needs_redraw = false;
        }

        // Poll so the download popup animates while telegrams fly;
        // idle cost is one wakeup per interval.
        if !event::poll(std::time::Duration::from_millis(80))? {
            if app.navigation().should_quit {
                return Ok(());
            }
            continue;
        }
        // Cap the drain: under key autorepeat the queue refills as fast
        // as it drains, and waiting for it to empty would starve the
        // draw for as long as the key is held. After the cap a frame is
        // forced and draining resumes next iteration.
        let drain_start = std::time::Instant::now();
        loop {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    handle_key(app, key.code, key.modifiers);
                    if let Some(device) = app.take_pending_project_device()
                        && let Err(error) = switch_project_device(app, device)
                    {
                        app.set_status_message(format!("Cannot open project device: {error}"));
                    }
                    if let Some(request) = app.take_pending_catalog_add()
                        && let Err(error) = add_catalog_device(app, request)
                    {
                        app.reject_catalog_add(error);
                    }
                    needs_redraw = true;
                }
                Event::Resize(_, _) => {
                    needs_redraw = true;
                }
                _ => {}
            }
            if drain_start.elapsed() >= std::time::Duration::from_millis(100)
                || !event::poll(std::time::Duration::ZERO)?
            {
                break;
            }
        }

        if app.navigation().should_quit {
            return Ok(());
        }
    }
}

fn handle_key(app: &mut App, code: KeyCode, modifiers: KeyModifiers) {
    // Startup comparison owns the keyboard. It is read-only and normally
    // closes itself; a failure remains visible until acknowledged.
    if app.startup_status_active() {
        if app.startup_status_failed() && matches!(code, KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q')) {
            app.dismiss_startup_status();
        }
        return;
    }

    // The download popup owns the keyboard while it is up. A running
    // procedure remains non-interactive, while a finished result may need
    // scrolling before it is dismissed.
    if app.operations().download_active() {
        if app.operations().assignment_prompt_active() {
            match code {
                KeyCode::Char('s') | KeyCode::Char('S') => app.operations_mut().use_serial_number_for_assignment(),
                KeyCode::Esc | KeyCode::Char('q') => app.operations_mut().cancel_assignment_prompt(),
                _ => {}
            }
            return;
        }

        if app.operations().download_finished() {
            match code {
                KeyCode::Up => app.operations_mut().scroll_download_result(-1),
                KeyCode::Down => app.operations_mut().scroll_download_result(1),
                KeyCode::PageUp => app.operations_mut().scroll_download_result(-10),
                KeyCode::PageDown => app.operations_mut().scroll_download_result(10),
                KeyCode::Home => app.operations_mut().reset_download_result_scroll(),
                KeyCode::End => app.operations_mut().scroll_download_result_to_end(),
                KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q') => app.operations_mut().dismiss_download(),
                _ => {}
            }
        }
        return;
    }

    // The catalog owns all keyboard input while either its tree or add form
    // is visible. In particular, characters typed into a device ID must not
    // trigger project-wide shortcuts behind the modal.
    if app.catalog_dialog_active() {
        match code {
            KeyCode::Esc => app.catalog_cancel(),
            KeyCode::Up => app.catalog_move_up(),
            KeyCode::Down => app.catalog_move_down(),
            KeyCode::Left => app.catalog_move_left(),
            KeyCode::Right => app.catalog_move_right(),
            KeyCode::Home => app.catalog_move_home(),
            KeyCode::End => app.catalog_move_end(),
            KeyCode::Tab | KeyCode::BackTab => app.catalog_toggle_add_field(),
            KeyCode::Enter => app.catalog_activate(),
            KeyCode::Backspace => app.catalog_backspace(),
            KeyCode::Char(character) => app.catalog_insert(character),
            _ => {}
        }
        return;
    }

    if app.operations().programming_dialog_active() {
        if app.programming_address_input_active() {
            match code {
                KeyCode::Esc => app.cancel_programming_address_input(),
                KeyCode::Enter => app.confirm_programming_dialog(),
                KeyCode::Backspace => app.pop_programming_address_character(),
                KeyCode::Char(character) => app.push_programming_address_character(character),
                _ => {}
            }
            return;
        }

        match code {
            KeyCode::Esc | KeyCode::Char('q') => app.cancel_programming_dialog(),
            KeyCode::Up => app.move_programming_selection(-1),
            KeyCode::Down => app.move_programming_selection(1),
            KeyCode::Left | KeyCode::Right | KeyCode::Tab | KeyCode::BackTab => app.toggle_programming_target(),
            KeyCode::Char('1') => app.select_programming_operation(0),
            KeyCode::Char('2') => app.select_programming_operation(1),
            KeyCode::Char('3') => app.select_programming_operation(2),
            KeyCode::Char('4') => app.select_programming_operation(3),
            KeyCode::Char('5') => app.select_programming_operation(4),
            KeyCode::Enter => app.confirm_programming_dialog(),
            _ => {}
        }
        return;
    }

    if app.operations().unload_confirmation_active() {
        match code {
            KeyCode::Esc | KeyCode::Char('q') => app.operations_mut().cancel_unload_confirmation(),
            KeyCode::Up => app.operations_mut().move_unload_selection(-1),
            KeyCode::Down => app.operations_mut().move_unload_selection(1),
            KeyCode::Enter => app.confirm_unload(),
            _ => {}
        }
        return;
    }

    if app.project_overview_active() {
        if matches!(code, KeyCode::Esc | KeyCode::Char('o')) {
            app.toggle_project_overview();
        }
        return;
    }

    if app.key_editor_active() {
        match code {
            KeyCode::Esc => app.key_editor_cancel(),
            KeyCode::Char('K') if app.key_editor_accepts_close() => {
                app.toggle_key_editor();
            }
            KeyCode::Up => app.key_editor_move_up(),
            KeyCode::Down => app.key_editor_move_down(),
            KeyCode::Enter => app.key_editor_activate(),
            KeyCode::Backspace => app.key_editor_backspace(),
            KeyCode::Char(character) => app.key_editor_char(character),
            _ => {}
        }
        return;
    }

    // Check if we're in edit mode
    let in_edit_mode = app.is_editing();

    if !in_edit_mode && modifiers.contains(KeyModifiers::CONTROL) {
        match code {
            KeyCode::Left => app.resize_focused_pane(-1, 0),
            KeyCode::Right => app.resize_focused_pane(1, 0),
            KeyCode::Up => app.resize_focused_pane(0, -1),
            KeyCode::Down => app.resize_focused_pane(0, 1),
            _ => {}
        }
        if matches!(code, KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down) {
            return;
        }
    }

    match code {
        KeyCode::Char('q') if !in_edit_mode => {
            app.request_quit();
        }
        KeyCode::Char('e') if !in_edit_mode => {
            app.export_project();
        }
        KeyCode::Char('a' | '+') if !in_edit_mode => {
            app.open_package_catalog();
        }
        KeyCode::Char('f') if !in_edit_mode && app.navigation().current_tab == app::MainTab::CommObjects => {
            app.enter_object_flags_edit_mode();
        }
        KeyCode::Char('h') if !in_edit_mode && app.navigation().current_tab == app::MainTab::Parameters => {
            app.toggle_non_default_highlight();
        }
        KeyCode::Char('r') if !in_edit_mode => {
            app.enter_selected_net_name_edit_mode();
        }
        KeyCode::Char('s') if !in_edit_mode && app.navigation().current_tab == app::MainTab::CommObjects => {
            app.cycle_selected_net_security();
        }
        KeyCode::Char('d') if !in_edit_mode => {
            app.toggle_data_secure();
        }
        KeyCode::Char('o') if !in_edit_mode => {
            app.toggle_project_overview();
        }
        KeyCode::Char('K') if !in_edit_mode => {
            app.toggle_key_editor();
        }
        KeyCode::Char('L') if !in_edit_mode => {
            app.open_language_select();
        }
        KeyCode::Char('p') if !in_edit_mode => {
            app.open_programming_dialog();
        }
        KeyCode::Char('A') if !in_edit_mode => {
            app.program_all_affected();
        }
        KeyCode::Char('u') if !in_edit_mode => {
            app.open_unload_confirmation();
        }
        KeyCode::Esc if in_edit_mode => {
            app.cancel_edit();
        }
        KeyCode::BackTab if !in_edit_mode => {
            app.focus_previous();
        }
        KeyCode::Tab if !in_edit_mode && modifiers.contains(KeyModifiers::SHIFT) => {
            app.focus_previous();
        }
        KeyCode::Tab if !in_edit_mode => {
            app.toggle_focus();
        }
        KeyCode::Left if !in_edit_mode => {
            app.move_left();
        }
        KeyCode::Right if !in_edit_mode => {
            app.move_right();
        }
        KeyCode::Up => {
            app.move_up();
        }
        KeyCode::Down => {
            app.move_down();
        }
        KeyCode::PageUp if !in_edit_mode => {
            app.page_up();
        }
        KeyCode::PageDown if !in_edit_mode => {
            app.page_down();
        }
        KeyCode::Enter => {
            app.activate();
        }
        KeyCode::Backspace if in_edit_mode => {
            app.handle_backspace();
        }
        KeyCode::Char(c) if in_edit_mode => {
            app.handle_char(c);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use zweidraehte_ets_files::MasterData;
    use zweidraehte_ets_files::archive::{PackageCatalogIndex, PackageCatalogManufacturer};
    use zweidraehte_proto::address::GroupAddress;

    use super::{Args, load_standalone_document, override_catalog_manufacturer_names, project_object_bindings};

    #[test]
    fn project_bindings_put_primary_first_without_reencoding_addresses() {
        use zweidraehte_project::{AuthoredProject, ProjectDeviceId};

        let project = AuthoredProject::parse(r#"
          ga secondary = 0/0/1
          ga primary = 31/7/255
          net secondary : 1.001 { security plain }
          net primary : 1.001 { security plain }
          area 1 bench { line 1 main { medium tp1
            device relay {
              product package:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" catalog_item "relay"
              address 1.1.1
              object 0 { also on secondary on primary }
            }
          } }
        "#).expect("project with primary written last");
        let relay = &project.devices[&ProjectDeviceId("relay".into())];
        assert_eq!(project_object_bindings(&project, relay), [(0, vec![
            GroupAddress([255, 255]),
            GroupAddress([0, 1])
        ]),]);
    }

    #[test]
    fn standalone_loading_keeps_the_selected_leaf_and_bundled_baggage() {
        use zweidraehte_ets_files::archive::RawArchive;
        use zweidraehte_ets_files::product::ApplicationProgram2Binding;

        let temporary = tempfile::tempdir().expect("fixture directory");
        let path = temporary.path().join("switch.knxprod");
        // Empty ZIP end-of-central-directory record; RawArchive adds the files.
        let mut empty_zip = [0; 22];
        empty_zip[..4].copy_from_slice(b"PK\x05\x06");
        let mut archive = RawArchive::from_bytes(&empty_zip).expect("empty archive");
        let wrap = |body: &str| {
            format!(
                r#"<KNX xmlns="http://knx.org/xml/project/23"><ManufacturerData><Manufacturer RefId="M-00FA">{body}</Manufacturer></ManufacturerData></KNX>"#
            )
        };
        archive.upsert("M-00FA/M-00FA_A-0001-01-0000.xml", wrap(r#"<ApplicationPrograms><ApplicationProgram Id="M-00FA_A-0001-01-0000" ApplicationNumber="1" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-07B0" Name="Switch" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="en-US" DynamicTableManagement="false" Linkable="false"><Static><Code/><Extension><Baggage RefId="M-00FA_BG-icon"/></Extension></Static></ApplicationProgram></ApplicationPrograms>"#).into_bytes());
        archive.upsert("M-00FA/Hardware.xml", wrap(r#"<Hardware><Hardware Id="M-00FA_H-1" Name="Switch" SerialNumber="1" VersionNumber="1" HasIndividualAddress="true" HasApplicationProgram="true"><Products><Product Id="M-00FA_P-1" Text="Switch" OrderNumber="1" IsRailMounted="false" DefaultLanguage="en-US"/></Products><Hardware2Programs><Hardware2Program Id="M-00FA_HP-1" MediumTypes="MT-0"><ApplicationProgramRef RefId="M-00FA_A-0001-01-0000"/></Hardware2Program></Hardware2Programs></Hardware></Hardware>"#).into_bytes());
        archive.upsert("M-00FA/Catalog.xml", wrap(r#"<Catalog><CatalogSection Id="M-00FA_CS-1" Name="Switches" Number="1" DefaultLanguage="en-US"><CatalogItem Id="M-00FA_CI-white" Name="White switch" Number="1" ProductRefId="M-00FA_P-1" Hardware2ProgramRefId="M-00FA_HP-1" DefaultLanguage="en-US"/><CatalogItem Id="M-00FA_CI-black" Name="Black switch" Number="2" ProductRefId="M-00FA_P-1" Hardware2ProgramRefId="M-00FA_HP-1" DefaultLanguage="en-US"/></CatalogSection></Catalog>"#).into_bytes());
        archive.upsert(
            "M-00FA/Baggages.xml",
            wrap(r#"<Baggages><Baggage Id="M-00FA_BG-icon" Name="icon.png" TargetPath=""/></Baggages>"#).into_bytes(),
        );
        archive.upsert("M-00FA/Baggages/icon.png", vec![0, 1, 2, 255]);
        std::fs::write(&path, archive.to_bytes().expect("fixture ZIP")).expect("fixture writes");

        let resources = tempfile::tempdir().expect("editor resource lifetime");
        let editor = load_standalone_document(&path, Some("M-00FA_CI-black"), None, resources.path())
            .expect("exact leaf opens without an interactive prompt");
        let ApplicationProgram2Binding::Absent { relation } = editor.product().application_program_2() else {
            panic!("hardware authoritatively declares AP2 absent");
        };
        assert_eq!(relation.catalog_item_id.as_deref(), Some("M-00FA_CI-black"));
        let baggage = editor.baggage().expect("bundled baggage");
        let icon = baggage.get("M-00FA_BG-icon").expect("selected icon");
        assert!(icon.file_path().starts_with(resources.path()));
        assert_eq!(std::fs::read(icon.file_path()).expect("bundled image"), [0, 1, 2, 255]);
        assert!(!temporary.path().join(".zweidraehte").exists(), "inspection must not import into a store");
    }

    #[test]
    fn standalone_archive_selector_is_the_exact_catalog_item() {
        let args = Args::try_parse_from(["knxproj-tui", "fixture.knxprod", "--catalog-item", "M-00FA_H-1_P-1_CI-1"])
            .expect("CatalogItem selector parses");

        assert_eq!(args.catalog_item.as_deref(), Some("M-00FA_H-1_P-1_CI-1"));
        assert!(
            Args::try_parse_from([
                "knxproj-tui",
                "fixture.knxprod",
                "--catalog-item",
                "M-00FA_H-1_P-1_CI-1",
                "--application",
                "M-00FA_A-1",
            ])
            .is_err()
        );
    }

    #[test]
    fn explicit_master_data_replaces_store_names_and_clears_unknown_ids() {
        let mut catalog = PackageCatalogIndex {
            manufacturers: vec![
                PackageCatalogManufacturer {
                    id: "M-0083".into(),
                    name: Some("Stale MDT name".into()),
                    name_source_schema_version: Some(20),
                    name_source_version: Some(1),
                    sections: Vec::new(),
                },
                PackageCatalogManufacturer {
                    id: "M-FFFF".into(),
                    name: Some("Stale unknown name".into()),
                    name_source_schema_version: Some(20),
                    name_source_version: Some(1),
                    sections: Vec::new(),
                },
            ],
        };
        let master: MasterData = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278">
    <Manufacturers>
      <Manufacturer Id="M-0083" Name="MDT technologies" KnxManufacturerId="131" />
    </Manufacturers>
  </MasterData>
</KNX>"#
            .parse()
            .expect("explicit Master Data parses");

        override_catalog_manufacturer_names(&mut catalog, &master);

        assert_eq!(catalog.manufacturers[0].name.as_deref(), Some("MDT technologies"));
        assert_eq!(catalog.manufacturers[0].name_source_schema_version, Some(23));
        assert_eq!(catalog.manufacturers[0].name_source_version, Some(278));
        assert_eq!(catalog.manufacturers[1].name, None);
        assert_eq!(catalog.manufacturers[1].name_source_schema_version, None);
        assert_eq!(catalog.manufacturers[1].name_source_version, None);
    }
}
