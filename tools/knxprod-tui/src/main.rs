//! KNX ApplicationProgram TUI Viewer
//!
//! A terminal user interface for viewing and exploring KNX ApplicationProgram
//! MTXML files.

mod app;
mod download;
mod ui;

use std::fs::File;
use std::io;
use std::path::PathBuf;

use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use log::LevelFilter;
use ratatui::{Terminal, backend::CrosstermBackend};
use simplelog::{Config, WriteLogger};

use app::{App, EditMode};
use zweidraehte_knxprod::runtime::baggage::BaggageIndex;
use zweidraehte_knxprod::runtime::parser::ProgramSummary;
use zweidraehte_knxprod::{Device, MasterData, parse_application_program_from_file};

/// KNX ApplicationProgram TUI Viewer
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the MTXML file to view
    #[arg()]
    file: PathBuf,

    /// Path to knx_master.xml for mask version info (enables proper table generation)
    #[arg(short = 'M', long)]
    master_data: Option<PathBuf>,

    /// A mods TOML to apply after loading (parameter values and group
    /// links, same format knx-dump emits); `e` exports back to it
    #[arg(short, long)]
    mods: Option<PathBuf>,

    /// Start with this display language (e.g. de-DE); `l`/`L` cycle
    /// through the available languages at runtime
    #[arg(short, long)]
    language: Option<String>,

    /// Bus access for programming the device with `p` (KNX/IP
    /// tunneling or USB)
    #[command(flatten)]
    target: zweidraehte_client::cli::OptionalTargetArgs,

    /// Print summary only (no TUI)
    #[arg(long)]
    summary: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize file logging
    let log_file = File::create("/tmp/knxprod-tui.log")?;
    WriteLogger::init(LevelFilter::Debug, Config::default(), log_file)?;
    log::info!("KNX TUI starting");

    // Parse the XML file
    let knx = parse_application_program_from_file(&args.file)?;

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
        // Try to find knx_master.xml in the same directory as the input file
        let parent = args.file.parent();
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
    let translations = zweidraehte_knxprod::runtime::Translations::from_knx(&knx);

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
    if let Some(language) = &args.language {
        translations.apply(&mut program, language).ok_or_else(|| {
            format!("the product has no language {language:?}; available: {:?}", translations.languages())
        })?;
        eprintln!("Display language: {language}");
    }

    // Load baggage index from the same directory as the MTXML file
    let baggage_index = args.file.parent().and_then(|dir| match BaggageIndex::from_directory(dir) {
        Ok(index) => {
            eprintln!("Loaded {} baggage files from {:?}", index.len(), dir);
            Some(index)
        }
        Err(_) => None,
    });

    // Create unified Device
    let mut device = Device::new(program, master_data.as_ref(), baggage_index.clone());

    // Apply a mods file over the defaults, so the TUI opens showing
    // the configuration it describes. Hard errors, like the loader:
    // an entry the product rejects is a mistake to fix, not to skim
    // past silently.
    let loaded_mods = match &args.mods {
        Some(path) => {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("reading mods file {}: {e}", path.display()))?;
            let mods: zweidraehte_knxprod::runtime::mods::DeviceMods =
                toml::from_str(&text).map_err(|e| format!("parsing mods file {}: {e}", path.display()))?;
            zweidraehte_knxprod::runtime::mods::apply_mods(&mut device, &mods)
                .map_err(|e| format!("applying mods file {}: {e}", path.display()))?;
            eprintln!("Applied {} parameter(s), {} link(s) from {:?}", mods.params.len(), mods.links.len(), path);
            Some(mods)
        }
        None => None,
    };

    // Create app with master data
    let mut app = App::with_master_data(device, master_data);
    if let (Some(path), Some(mods)) = (args.mods, loaded_mods) {
        app.set_mods_context(path, mods.device);
    }
    app.download_context =
        Some(app::DownloadContext { target: args.target.to_target(), master_data: args.master_data.clone() });
    if !translations.is_empty() {
        app.set_language_context(
            app::LanguageContext { translations, pristine: pristine_program, baggage: baggage_index },
            args.language,
        );
    }

    // Run TUI
    run_tui(app)?;

    Ok(())
}

fn run_tui(mut app: App) -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Main loop
    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    result
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
        if needs_redraw || app.download.is_some() {
            terminal.draw(|frame| ui::render(frame, app))?;
            needs_redraw = false;
        }

        // Poll so the download popup animates while telegrams fly;
        // idle cost is one wakeup per interval.
        if !event::poll(std::time::Duration::from_millis(80))? {
            if app.should_quit {
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
                    handle_key(app, key.code);
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

        if app.should_quit {
            return Ok(());
        }
    }
}

fn handle_key(app: &mut App, code: KeyCode) {
    // The download popup owns the keyboard while it is up:
    // nothing to interact with while running, Enter/Esc/q
    // dismiss once finished.
    if let Some(download) = &app.download {
        if download.result.is_some() && matches!(code, KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q')) {
            app.dismiss_download();
        }
        return;
    }

    // Check if we're in edit mode
    let in_edit_mode = !matches!(app.edit_mode, EditMode::None);

    match code {
        KeyCode::Char('q') if !in_edit_mode => {
            app.should_quit = true;
        }
        KeyCode::Char('e') if !in_edit_mode => {
            app.export_mods();
        }
        KeyCode::Char('l') | KeyCode::Char('L') if !in_edit_mode => {
            app.open_language_select();
        }
        KeyCode::Char('p') if !in_edit_mode => {
            app.start_download();
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
