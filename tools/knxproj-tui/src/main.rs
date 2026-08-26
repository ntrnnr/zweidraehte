//! KNX project and product TUI.
//!
//! A terminal user interface for viewing and exploring KNX ApplicationProgram
//! MTXML files.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use dialoguer::{Select, theme::ColorfulTheme};
use log::LevelFilter;
use ratatui::{Terminal, backend::CrosstermBackend};
use simplelog::{Config, WriteLogger};

use knxproj_tui::app::{self, App, LoadedProjectDevice, ProjectContext};
use knxproj_tui::ui;
use zweidraehte_ets_files::archive::{KnxprodArchive, KnxprodDevice, ProgramSelection};
use zweidraehte_ets_files::runtime::Translations;
use zweidraehte_ets_files::runtime::baggage::BaggageIndex;
use zweidraehte_ets_files::runtime::configuration::{
    ObjectFlagOverrides as ProductFlagOverrides, ObjectSetting, ProductConfiguration, apply_configuration,
};
use zweidraehte_ets_files::runtime::parser::ProgramSummary;
use zweidraehte_ets_files::schema::Knx;
use zweidraehte_ets_files::{Device, MasterData};
use zweidraehte_project::{
    MembershipRole, ObjectPriority, ParamValue, ProductReference, ProjectDeviceId, ProjectStore,
};

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

    /// Application program ID for non-interactive `.knxprod` selection
    #[arg(long, value_name = "ID", conflicts_with = "catalog_product")]
    application: Option<String>,

    /// Catalogue product ID for non-interactive `.knxprod` selection
    #[arg(long, value_name = "ID")]
    catalog_product: Option<String>,

    /// Start with this display language (e.g. de-DE); `l`/`L` cycle
    /// through the available languages at runtime
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
    let (product_path, project_context, product_configuration, bindings, project_flags, project_language) =
        if is_project {
            if args.application.is_some() || args.catalog_product.is_some() {
                return Err(
                    "--application/--catalog-product apply to product files; project.knx stores its own selection"
                        .into(),
                );
            }
            let store = ProjectStore::open(&args.file)?;
            let device_id = args
                .device
                .as_ref()
                .map(|id| ProjectDeviceId(id.clone()))
                .or_else(|| store.authored().devices.keys().next().cloned())
                .ok_or("the project contains no devices")?;
            let authored_device = store
                .authored()
                .devices
                .get(&device_id)
                .ok_or_else(|| format!("project has no device `{device_id}`"))?;
            let product_path =
                store.authored().resolve_product_path(authored_device).ok_or("project path has no parent")?;
            let product_reference = match &authored_device.product {
                ProductReference::Local(path) => path.clone(),
            };
            let configuration = project_product_configuration(authored_device);
            let bindings = project_object_bindings(store.authored(), authored_device);
            let flags = authored_device.objects.values().map(|object| (object.com_object, object.flags)).collect();
            let source = store.authored().source().to_string();
            (
                product_path,
                ProjectContext {
                    path: args.file.clone(),
                    device: device_id,
                    product_path: product_reference,
                    catalog_product: authored_device.catalog_product.clone(),
                    application_program: authored_device.application_program.clone(),
                    authored: Some(store.authored().clone()),
                    original_source: Some(source),
                },
                configuration,
                bindings,
                flags,
                authored_device.language.clone(),
            )
        } else {
            let (catalog_product, application_program) = if args
                .file
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("knxprod"))
            {
                let selected =
                    select_archive_device(&args.file, args.catalog_product.as_deref(), args.application.as_deref())?;
                (selected.product_id, Some(selected.application_program_id))
            } else {
                (None, args.application.clone())
            };
            let parent = args.file.parent().unwrap_or_else(|| Path::new("."));
            let stem = args.file.file_stem().and_then(|stem| stem.to_str()).unwrap_or("product");
            let project_dir = parent.join(format!("{stem}-project"));
            let product_reference = PathBuf::from("..")
                .join(args.file.file_name().ok_or_else(|| format!("{} has no file name", args.file.display()))?);
            (
                args.file.clone(),
                ProjectContext {
                    path: project_dir.join("project.knx"),
                    device: ProjectDeviceId("device".into()),
                    product_path: product_reference,
                    catalog_product,
                    application_program,
                    authored: None,
                    original_source: None,
                },
                ProductConfiguration::default(),
                Vec::new(),
                BTreeMap::new(),
                None,
            )
        };
    let knx = load_knx(
        &product_path,
        project_context.catalog_product.as_deref(),
        project_context.application_program.as_deref(),
    )?;

    // Print summary if requested
    if args.summary {
        if let Some(summary) = ProgramSummary::from_knx(&knx) {
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

    // Load master data if provided
    let master_data = if let Some(master_path) = &args.master_data {
        match MasterData::from_file(master_path) {
            Ok(md) => {
                eprintln!("Loaded {} mask versions from {:?}", md.mask_version_count(), master_path);
                Some(md)
            }
            Err(e) => {
                eprintln!("Warning: Failed to load master data from {:?}: {}", master_path, e);
                None
            }
        }
    } else {
        // Try to find knx_master.xml beside the selected product.
        let parent = product_path.parent();
        let auto_paths = [
            parent.map(|p| p.join("knx_master.xml")),
            parent.and_then(|p| p.parent()).map(|p| p.join("knx_master.xml")),
        ];

        auto_paths.into_iter().flatten().find_map(|path| {
            if path.exists() {
                match MasterData::from_file(&path) {
                    Ok(md) => {
                        eprintln!("Auto-loaded {} mask versions from {:?}", md.mask_version_count(), path);
                        Some(md)
                    }
                    Err(_) => None,
                }
            } else {
                None
            }
        })
    };

    // The document's translations live at the manufacturer level;
    // collect them before the program is moved out.
    let translations = Translations::from_knx(&knx);

    // Get the application program
    let mut program = knx
        .manufacturer_data
        .manufacturer
        .application_programs
        .programs
        .into_iter()
        .next()
        .ok_or("No application program found")?;

    // The pristine copy every language switch starts from.
    let pristine_program = program.clone();
    // A command-line selection intentionally wins for this session. Since
    // the editor's draft carries the active language, saving also makes the
    // override the device's new project preference.
    let selected_language = args.language.or(project_language);
    if let Some(language) = &selected_language {
        translations.apply(&mut program, language).ok_or_else(|| {
            format!("the product has no language {language:?}; available: {:?}", translations.languages())
        })?;
        eprintln!("Display language: {language}");
    }

    // Load baggage index from the same directory as the MTXML file.
    let baggage_index = product_path.parent().and_then(|dir| match BaggageIndex::from_directory(dir) {
        Ok(index) => {
            eprintln!("Loaded {} baggage files from {:?}", index.len(), dir);
            Some(index)
        }
        Err(_) => None,
    });

    // Create unified Device
    let mut device = Device::new(program, baggage_index.clone());
    apply_configuration(&mut device, &product_configuration)?;
    for (object, addresses) in bindings {
        for address in addresses {
            device.assign_group_address(object, address);
        }
    }

    // Create app with master data
    let mut app = App::with_master_data(device, master_data);
    app.set_project_context(project_context, project_flags);
    app.set_download_context(app::DownloadContext {
        target: args.target.to_target(),
        master_data: args.master_data.clone(),
        security: args.security,
    });
    if !translations.is_empty() {
        app.set_language_context(
            app::LanguageContext { translations, pristine: pristine_program, baggage: baggage_index },
            selected_language,
        );
    }

    // Run TUI
    run_tui(app)?;

    Ok(())
}

fn load_knx(
    path: &Path,
    catalog_product: Option<&str>,
    application_program: Option<&str>,
) -> Result<Knx, Box<dyn std::error::Error>> {
    Ok(zweidraehte_ets_files::archive::load_program(path, ProgramSelection { catalog_product, application_program })?
        .document)
}

fn select_archive_device(
    path: &Path,
    catalog_product: Option<&str>,
    application_program: Option<&str>,
) -> Result<KnxprodDevice, Box<dyn std::error::Error>> {
    let archive = KnxprodArchive::open(path)?;
    let devices = archive.importable_devices()?;
    if devices.is_empty() {
        return Err(format!("{} contains no importable device", path.display()).into());
    }
    if let Some(catalog_product) = catalog_product {
        return devices
            .into_iter()
            .find(|device| device.product_id.as_deref() == Some(catalog_product))
            .ok_or_else(|| format!("{} has no catalogue product `{catalog_product}`", path.display()).into());
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
                "application `{application_program}` is used by {} catalogue products; select one with --catalog-product",
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
        "{}{} — {} — {}{}",
        device.name,
        device.order_number.as_ref().map_or_else(String::new, |number| format!(" [{number}]")),
        device.mask_version,
        device.application_program_id,
        if device.supports_data_secure { " — Data Secure" } else { "" }
    )
}

fn project_product_configuration(device: &zweidraehte_project::ProjectDevice) -> ProductConfiguration {
    ProductConfiguration {
        parameters: device
            .parameters
            .iter()
            .map(|parameter| zweidraehte_ets_files::runtime::configuration::ParameterSetting {
                id: parameter.id.clone(),
                value: match &parameter.value {
                    ParamValue::Integer(value) => {
                        zweidraehte_ets_files::runtime::model::ParameterValue::Integer(*value)
                    }
                    ParamValue::Float(value) => zweidraehte_ets_files::runtime::model::ParameterValue::Float(*value),
                    ParamValue::Text(value) => {
                        zweidraehte_ets_files::runtime::model::ParameterValue::Text(value.clone())
                    }
                },
            })
            .collect(),
        objects: device
            .objects
            .values()
            .map(|object| ObjectSetting {
                com_object: object.com_object,
                flags: ProductFlagOverrides {
                    communication: object.flags.communication,
                    read: object.flags.read,
                    write: object.flags.write,
                    transmit: object.flags.transmit,
                    update: object.flags.update,
                    read_on_init: object.flags.read_on_init,
                    priority: object.flags.priority.map(|priority| match priority {
                        ObjectPriority::System => zweidraehte_proto::messages::knx::Priority::System,
                        ObjectPriority::High => zweidraehte_proto::messages::knx::Priority::High,
                        ObjectPriority::Alarm => zweidraehte_proto::messages::knx::Priority::Alarm,
                        ObjectPriority::Low => zweidraehte_proto::messages::knx::Priority::Low,
                    }),
                },
            })
            .collect(),
    }
}

fn load_project_editor(
    context: ProjectContext,
    device_id: &ProjectDeviceId,
    preferred_language: Option<&str>,
) -> Result<LoadedProjectDevice, Box<dyn std::error::Error>> {
    let authored = context.authored.as_ref().ok_or("project context has no authored project")?;
    let authored_device =
        authored.devices.get(device_id).ok_or_else(|| format!("project has no device `{device_id}`"))?;
    let product_reference = match &authored_device.product {
        ProductReference::Local(path) => path.clone(),
    };
    let product_path = context
        .path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", context.path.display()))?
        .join(&product_reference);
    let knx = load_knx(
        &product_path,
        authored_device.catalog_product.as_deref(),
        authored_device.application_program.as_deref(),
    )?;
    let translations = Translations::from_knx(&knx);
    let mut program = knx
        .manufacturer_data
        .manufacturer
        .application_programs
        .programs
        .into_iter()
        .next()
        .ok_or("No application program found")?;
    let pristine_program = program.clone();
    let requested_language = preferred_language.or(authored_device.language.as_deref());
    let current_language = if let Some(language) = requested_language {
        translations.apply(&mut program, language).ok_or_else(|| {
            format!(
                "application `{}` has no language {language:?}; available: {:?}",
                program.id,
                translations.languages()
            )
        })?;
        Some(language.to_string())
    } else {
        None
    };
    let baggage_index = product_path.parent().and_then(|directory| BaggageIndex::from_directory(directory).ok());
    let mut device = Device::new(program, baggage_index.clone());
    apply_configuration(&mut device, &project_product_configuration(authored_device))?;
    for (object, addresses) in project_object_bindings(authored, authored_device) {
        for address in addresses {
            device.assign_group_address(object, address);
        }
    }
    let flags = authored_device.objects.values().map(|object| (object.com_object, object.flags)).collect();
    let language_context = (!translations.is_empty()).then_some(app::LanguageContext {
        translations,
        pristine: pristine_program,
        baggage: baggage_index,
    });
    Ok(LoadedProjectDevice {
        device,
        context: ProjectContext {
            path: context.path,
            device: device_id.clone(),
            product_path: product_reference,
            catalog_product: authored_device.catalog_product.clone(),
            application_program: authored_device.application_program.clone(),
            authored: context.authored,
            original_source: context.original_source,
        },
        flags,
        language_context,
        current_language,
    })
}

fn project_object_bindings(
    project: &zweidraehte_project::AuthoredProject,
    device: &zweidraehte_project::ProjectDevice,
) -> Vec<(u16, Vec<zweidraehte_ets_files::runtime::model::GroupAddress>)> {
    device
        .objects
        .values()
        .map(|object| {
            let mut memberships = object.memberships.clone();
            memberships.sort_by_key(|membership| membership.role != MembershipRole::Primary);
            let addresses = memberships
                .iter()
                .map(|membership| {
                    let raw = u16::from_be_bytes(project.nets[&membership.net].address.0);
                    zweidraehte_ets_files::runtime::model::GroupAddress::new(
                        ((raw >> 11) & 0x1F) as u8,
                        ((raw >> 8) & 0x07) as u8,
                        (raw & 0xFF) as u8,
                    )
                })
                .collect();
            (object.com_object, addresses)
        })
        .collect()
}

fn switch_project_device(app: &mut App, device: ProjectDeviceId) -> Result<(), String> {
    let context = app.stage_current_project_device()?;
    // Language is a per-device preference. Carrying the current device's
    // selection across this boundary would silently overwrite another
    // product's preference and may name a translation it does not provide.
    let loaded = load_project_editor(context, &device, None).map_err(|error| error.to_string())?;
    app.open_project_device(loaded);
    Ok(())
}

fn run_tui(mut app: App) -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    #[cfg(feature = "images")]
    app.initialize_image_picker();

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Main loop
    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    result?;
    app.persist_pane_layout().map_err(io::Error::other)
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> io::Result<()> {
    // Building a frame is expensive on large products, so two rules keep
    // the UI responsive: only draw when something changed (a handled
    // event, a resize, or a running download animating), and drain the
    // whole input backlog before drawing so key autorepeat coalesces
    // into one redraw instead of queueing a frame per keypress.
    let mut needs_redraw = true;
    loop {
        app.poll_download();
        needs_redraw |= app.poll_status_message();
        if needs_redraw || app.download_active() {
            terminal.draw(|frame| ui::render(frame, app))?;
            needs_redraw = false;
        }

        // Poll so the download popup animates while telegrams fly;
        // idle cost is one wakeup per interval.
        if !event::poll(std::time::Duration::from_millis(80))? {
            if app.should_quit() {
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

        if app.should_quit() {
            return Ok(());
        }
    }
}

fn handle_key(app: &mut App, code: KeyCode, modifiers: KeyModifiers) {
    // The download popup owns the keyboard while it is up:
    // nothing to interact with while running, Enter/Esc/q
    // dismiss once finished.
    if app.download_active() {
        if app.download_finished() && matches!(code, KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q')) {
            app.dismiss_download();
        }
        return;
    }

    if app.project_overview_active() {
        if matches!(code, KeyCode::Esc | KeyCode::Char('P')) {
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
        KeyCode::Char('f') if !in_edit_mode && app.current_tab() == app::MainTab::CommObjects => {
            app.enter_object_flags_edit_mode();
        }
        KeyCode::Char('r') if !in_edit_mode => {
            app.enter_selected_net_name_edit_mode();
        }
        KeyCode::Char('s') if !in_edit_mode && app.current_tab() == app::MainTab::CommObjects => {
            app.cycle_selected_net_security();
        }
        KeyCode::Char('d') if !in_edit_mode => {
            app.toggle_data_secure();
        }
        KeyCode::Char('P') if !in_edit_mode => {
            app.toggle_project_overview();
        }
        KeyCode::Char('K') if !in_edit_mode => {
            app.toggle_key_editor();
        }
        KeyCode::Char('l') | KeyCode::Char('L') if !in_edit_mode => {
            app.open_language_select();
        }
        KeyCode::Char('p') if !in_edit_mode => {
            app.start_download();
        }
        KeyCode::Char('F') if !in_edit_mode => {
            app.start_full_download();
        }
        KeyCode::Char('a') if !in_edit_mode => {
            app.start_address_commissioning();
        }
        KeyCode::Char('u') if !in_edit_mode => {
            app.start_application_download();
        }
        KeyCode::Char('A') if !in_edit_mode => {
            app.start_affected_download();
        }
        KeyCode::Esc if in_edit_mode => {
            app.cancel_edit();
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
