//! KNX ApplicationProgram TUI Viewer
//!
//! A terminal user interface for viewing and exploring KNX ApplicationProgram
//! MTXML files.

mod app;
mod ui;

use std::fs::File;
use std::io;
use std::path::PathBuf;

use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use log::LevelFilter;
use ratatui::{backend::CrosstermBackend, Terminal};
use simplelog::{Config, WriteLogger};

use app::{App, EditMode};
use knxprod::runtime::baggage::BaggageIndex;
use knxprod::runtime::parser::ProgramSummary;
use knxprod::{parse_application_program_from_file, Device, MasterData};

/// KNX ApplicationProgram TUI Viewer
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the MTXML file to view
    #[arg()]
    file: PathBuf,

    /// Path to knx_master.xml for mask version info (enables proper table generation)
    #[arg(short, long)]
    master_data: Option<PathBuf>,

    /// Print summary only (no TUI)
    #[arg(short, long)]
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

    // Get the application program
    let program = knx
        .manufacturer_data
        .manufacturer
        .application_programs
        .programs
        .into_iter()
        .next()
        .ok_or("No application program found")?;

    // Load baggage index from the same directory as the MTXML file
    let baggage_index = args.file.parent().and_then(|dir| match BaggageIndex::from_directory(dir) {
        Ok(index) => {
            eprintln!("Loaded {} baggage files from {:?}", index.len(), dir);
            Some(index)
        }
        Err(_) => None,
    });

    // Create unified Device
    let device = Device::new(program, master_data.as_ref(), baggage_index);

    // Create app with master data
    let app = App::with_master_data(device, master_data);

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
    loop {
        terminal.draw(|frame| ui::render(frame, app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            // Check if we're in edit mode
            let in_edit_mode = !matches!(app.edit_mode, EditMode::None);

            match key.code {
                KeyCode::Char('q') if !in_edit_mode => {
                    app.should_quit = true;
                }
                KeyCode::Esc => {
                    if in_edit_mode {
                        app.cancel_edit();
                    }
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

        if app.should_quit {
            return Ok(());
        }
    }
}
