//! KNX ApplicationProgram TUI Viewer
//!
//! A terminal user interface for viewing and exploring KNX ApplicationProgram
//! MTXML files.

mod app;
mod ui;

use std::io;
use std::path::PathBuf;

use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use app::{App, EditMode};
use knxprod::model::DeviceModel;
use knxprod::parser::{parse_application_program_from_file, ProgramSummary};

/// KNX ApplicationProgram TUI Viewer
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the MTXML file to view
    #[arg()]
    file: PathBuf,

    /// Print summary only (no TUI)
    #[arg(short, long)]
    summary: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

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
                if summary.has_channel_independent_block {
                    "yes"
                } else {
                    "no"
                }
            );
            println!("  Channels: {}", summary.channel_count);
        } else {
            println!("No application program found in file.");
        }
        return Ok(());
    }

    // Get the application program
    let program = knx
        .manufacturer_data
        .manufacturer
        .application_programs
        .programs
        .into_iter()
        .next()
        .ok_or("No application program found")?;

    // Create device model
    let model = DeviceModel::new(program);

    // Create app
    let app = App::new(model);

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
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> io::Result<()> {
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
