//! UI rendering for the KNX TUI viewer.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Row, Table, Wrap},
};

#[cfg(feature = "images")]
use ratatui_image::{FilterType, Resize, StatefulImage, protocol::StatefulProtocol};

use crate::app::{App, ContentItem, EditMode, Focus, MainTab, SegmentType, WidgetType};
use crate::project_view::ProjectNavigationTarget;

/// Render the application UI.
pub fn render(frame: &mut Frame, app: &mut App) {
    // Rebuild any view an earlier edit left stale, but only for the tab
    // about to be drawn.
    app.ensure_tab_data();

    let outer_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),
            Constraint::Length(2), // Status bar
        ])
        .split(frame.area());

    let editor_area = if app.project_navigation.is_some() {
        let left = responsive_left_width(app.pane_layout.project_width, outer_chunks[0].width, 24, 40);
        let columns = Layout::horizontal([Constraint::Length(left), Constraint::Min(1)]).split(outer_chunks[0]);
        render_project_navigation(frame, columns[0], app);
        columns[1]
    } else {
        outer_chunks[0]
    };
    let main_chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(7)]).split(editor_area);

    render_tabs(frame, main_chunks[0], app);

    match app.current_tab {
        MainTab::Parameters => render_parameters_view(frame, main_chunks[1], app),
        MainTab::CommObjects => render_comm_objects_view(frame, main_chunks[1], app),
        MainTab::Memory => render_memory_view(frame, main_chunks[1], app),
    }

    render_status(frame, outer_chunks[1], app);

    // Render edit popup if in edit mode
    if let EditMode::EnumDropdown { options, selected_idx, scroll_offset, .. } = &app.edit_mode {
        render_dropdown_popup(frame, options, *selected_idx, *scroll_offset, "Select Value");
    }
    if let EditMode::LanguageSelect { options, selected_idx, scroll_offset } = &app.edit_mode {
        let labels: Vec<(i64, String)> = options.iter().enumerate().map(|(i, (_, l))| (i as i64, l.clone())).collect();
        render_dropdown_popup(frame, &labels, *selected_idx, *scroll_offset, "Select Language");
    }

    if app.project_overview.is_some() {
        render_project_overview(frame, app);
    }

    if app.key_editor.is_some() {
        render_key_editor(frame, app);
    }

    // The download popup outranks everything.
    if app.download.is_some() {
        render_download_popup(frame, app);
    }
}

fn render_project_navigation(frame: &mut Frame, area: Rect, app: &App) {
    let navigation = app.project_navigation.as_ref().expect("project navigation presence checked");
    let focused = app.focus == Focus::Project;
    let sections = Layout::vertical([Constraint::Percentage(58), Constraint::Percentage(42)]).split(area);
    let border = if focused { Color::Yellow } else { Color::DarkGray };

    let topology_block =
        Block::default().borders(Borders::ALL).border_style(Style::default().fg(border)).title(" Topology ");
    let topology_inner = topology_block.inner(sections[0]);
    frame.render_widget(topology_block, sections[0]);
    let selected = navigation.selected_target();
    let selected_topology_row = navigation.topology.iter().position(|row| {
        row.target.as_ref().is_some_and(|device| selected == Some(&ProjectNavigationTarget::Device(device.clone())))
    });
    let topology = navigation
        .topology
        .iter()
        .map(|row| {
            let is_selected = row
                .target
                .as_ref()
                .is_some_and(|device| selected == Some(&ProjectNavigationTarget::Device(device.clone())));
            let is_active = row.target.as_ref() == Some(&navigation.active_device);
            let style = if is_selected && focused {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else if row.target.is_none() {
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else if is_active {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let marker = if is_active {
                "● "
            } else if row.target.is_some() {
                "  "
            } else {
                ""
            };
            ListItem::new(Line::from(Span::styled(format!("{}{}{}", "  ".repeat(row.depth), marker, row.label), style)))
        })
        .collect::<Vec<_>>();
    let mut topology_state = ListState::default().with_selected(selected_topology_row);
    frame.render_stateful_widget(List::new(topology), topology_inner, &mut topology_state);

    let net_block =
        Block::default().borders(Borders::ALL).border_style(Style::default().fg(border)).title(" Group addresses ");
    let net_inner = net_block.inner(sections[1]);
    frame.render_widget(net_block, sections[1]);
    let selected_net_row =
        navigation.nets.iter().position(|row| selected == Some(&ProjectNavigationTarget::Net(row.id.clone())));
    let editing_net = match &app.edit_mode {
        EditMode::NetNameInput { net, buffer, cursor } => Some((net, buffer, *cursor)),
        _ => None,
    };
    let nets = navigation
        .nets
        .iter()
        .map(|row| {
            let is_selected = selected == Some(&ProjectNavigationTarget::Net(row.id.clone()));
            let style = if is_selected && focused {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default().fg(Color::White)
            };
            let label = if let Some((_, buffer, cursor)) = editing_net.filter(|(net, _, _)| *net == &row.id) {
                let mut value = buffer.clone();
                value.insert(cursor, '▏');
                format!("Name: {value}")
            } else {
                row.label.clone()
            };
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect::<Vec<_>>();
    if nets.is_empty() {
        frame
            .render_widget(Paragraph::new("No group addresses").style(Style::default().fg(Color::DarkGray)), net_inner);
    } else {
        let mut net_state = ListState::default().with_selected(selected_net_row);
        frame.render_stateful_widget(List::new(nets), net_inner, &mut net_state);
    }
}

fn render_project_overview(frame: &mut Frame, app: &App) {
    let area = centered_rect(92, 88, frame.area());
    frame.render_widget(Clear, area);
    let lines = app
        .project_overview
        .as_ref()
        .expect("overview presence checked")
        .lines()
        .into_iter()
        .map(Line::from)
        .collect::<Vec<_>>();
    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Project / nets / masked keys / state  [P/Esc close] "))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn render_key_editor(frame: &mut Frame, app: &App) {
    let area = centered_rect(84, 72, frame.area());
    frame.render_widget(Clear, area);
    let editor = app.key_editor.as_ref().expect("key-editor presence checked");
    let mut lines = editor
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let marker = if index == editor.selected { ">" } else { " " };
            Line::from(format!("{marker} {:<42} {}", entry.label, entry.status))
        })
        .collect::<Vec<_>>();
    lines.push(Line::from(""));
    if let Some(input) = &editor.input {
        lines.push(Line::from(format!("Key: {}", "*".repeat(input.chars().count()))));
        lines.push(Line::from("Enter saves atomically; Esc clears this input"));
    } else {
        lines.push(Line::from("Enter edits; K/Esc closes. Existing identities cannot be overwritten."));
    }
    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Project keys (masked) "))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn centered_rect(width_percent: u16, height_percent: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - height_percent) / 2),
        Constraint::Percentage(height_percent),
        Constraint::Percentage((100 - height_percent) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - width_percent) / 2),
        Constraint::Percentage(width_percent),
        Constraint::Percentage((100 - width_percent) / 2),
    ])
    .split(vertical[1])[1]
}

fn render_tabs(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Tabs;

    let tabs = [
        ("Parameters", MainTab::Parameters),
        ("Communication Objects", MainTab::CommObjects),
        ("Memory", MainTab::Memory),
    ];

    let mut spans = Vec::new();
    spans.push(Span::raw(" "));

    for (i, (name, tab)) in tabs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" │ ", Style::default().fg(Color::DarkGray)));
        }

        let is_selected = *tab == app.current_tab;
        let style = if is_selected {
            if focused {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            }
        } else {
            Style::default().fg(Color::DarkGray)
        };

        if is_selected && focused {
            spans.push(Span::styled("[", Style::default().fg(Color::Yellow)));
            spans.push(Span::styled(*name, style));
            spans.push(Span::styled("]", Style::default().fg(Color::Yellow)));
        } else {
            spans.push(Span::styled(format!(" {} ", name), style));
        }
    }

    // Build title with program name and mask version info
    let title = format!(" KNX Viewer - {} │ {} ", app.device.program().name, app.mask_version_display());

    let block =
        Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(Color::DarkGray)).title(title);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let tabs_line = Paragraph::new(Line::from(spans));
    frame.render_widget(tabs_line, inner);
}

fn render_parameters_view(frame: &mut Frame, area: Rect, app: &mut App) {
    let sidebar_width = responsive_left_width(app.pane_layout.parameter_sidebar_width, area.width, 18, 30);
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(sidebar_width), Constraint::Min(1)])
        .split(area);

    render_sidebar(frame, chunks[0], &*app);
    render_param_content(frame, chunks[1], app);
}

fn render_sidebar(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Sidebar;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if focused { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) })
        .title(" Pages ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.tree_nodes.is_empty() {
        let empty = Paragraph::new("No pages").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(empty, inner);
        return;
    }

    let items: Vec<ListItem> = app
        .tree_nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let is_selected = i == app.selected_tree_idx && focused;

            // Build the indentation
            let indent = "  ".repeat(node.depth);

            // Expand/collapse indicator
            let prefix = if node.has_children { if node.expanded { "▼ " } else { "► " } } else { "  " };

            let style = if is_selected {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else if node.is_group() {
                // Main groups are headers, not pages — ETS-style.
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else if node.depth == 0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            };

            // Truncate name if needed
            let max_len = inner.width.saturating_sub(4 + (node.depth * 2) as u16) as usize;
            let name = if node.name.len() > max_len {
                format!("{}...", &node.name[..max_len.saturating_sub(3)])
            } else {
                node.name.clone()
            };

            ListItem::new(Line::from(vec![
                Span::raw(indent),
                Span::styled(prefix, Style::default().fg(Color::Cyan)),
                Span::styled(name, style),
            ]))
        })
        .collect();

    let mut state = ListState::default().with_selected(Some(app.selected_tree_idx));
    frame.render_stateful_widget(List::new(items), inner, &mut state);
}

fn render_param_content(frame: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focus == Focus::Content && app.current_tab == MainTab::Parameters;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if focused { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) })
        .title(format!(" {} ", app.current_node_name()));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.content_items.is_empty() {
        let empty = Paragraph::new("No parameters").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(empty, inner);
        return;
    }
    keep_selection_visible(&mut app.content_scroll_offset, app.selected_content_idx, usize::from(inner.height).max(1));

    // We need to render items manually to support inline images
    // Each item gets 1 row, except Picture items which get multiple rows for the image
    let label_width = (inner.width as usize * 40 / 100).clamp(20, 45);

    // First pass: collect what we need to render to avoid borrow issues.
    // Every item occupies at least one row, so `inner.height` items are
    // enough to fill the viewport — without the bound this builds lines
    // for everything below the scroll offset on every frame, which large
    // pages cannot afford.
    let items_to_render: Vec<_> = app
        .content_items
        .iter()
        .enumerate()
        .skip(app.content_scroll_offset)
        .take(inner.height as usize)
        .map(|(i, item)| {
            let is_selected = i == app.selected_content_idx && focused;
            match item {
                ContentItem::Picture { ref_id, text, alignment } => {
                    (i, is_selected, Some((ref_id.clone(), text.clone(), alignment.clone())), None)
                }
                _ => {
                    let lines = create_content_lines(item, is_selected, app, inner.width as usize);
                    (i, is_selected, None, Some(lines))
                }
            }
        })
        .collect();

    // Second pass: render. Items may span several rows (pictures, wrapped
    // separator paragraphs).
    let mut y_offset = 0u16;
    for (_i, is_selected, picture_ref, lines) in items_to_render {
        if y_offset >= inner.height {
            break;
        }

        if let Some((ref_id, text, alignment)) = picture_ref {
            // Give the picture its natural height in cells (plus the
            // 1-row padding top and bottom) when the image size is
            // known; the legacy 5 rows otherwise.
            #[cfg(feature = "images")]
            let desired_rows = app
                .picture_cell_size(&ref_id, inner.width.saturating_sub(label_width as u16))
                .map(|(_, rows)| rows + 2)
                .unwrap_or(5);
            #[cfg(not(feature = "images"))]
            let desired_rows = 5;

            let item_area = Rect {
                x: inner.x,
                y: inner.y + y_offset,
                width: inner.width,
                height: (inner.height - y_offset).min(desired_rows),
            };

            render_picture_item(
                frame,
                item_area,
                app,
                &ref_id,
                text.as_deref(),
                alignment.as_deref(),
                is_selected,
                label_width,
            );
            y_offset += item_area.height;
        } else if let Some(lines) = lines {
            for line in lines {
                if y_offset >= inner.height {
                    break;
                }
                let item_area = Rect { x: inner.x, y: inner.y + y_offset, width: inner.width, height: 1 };
                frame.render_widget(Paragraph::new(line), item_area);
                y_offset += 1;
            }
        }
    }
}

/// Create the display lines for a content item (used for manual rendering).
/// Most items are a single line; separator paragraphs may wrap to several.
fn create_content_lines<'a>(item: &ContentItem, is_selected: bool, app: &App, width: usize) -> Vec<Line<'a>> {
    let bg = if is_selected { Color::DarkGray } else { Color::Reset };

    match item {
        ContentItem::Parameter { text, suffix, widget, param_id } => {
            // Check if we're editing this parameter
            let editing = match &app.edit_mode {
                EditMode::NumberInput { param_id: edit_id, .. } => edit_id == param_id,
                EditMode::TextInput { param_id: edit_id, .. } => edit_id == param_id,
                EditMode::EnumDropdown { param_id: edit_id, .. } => edit_id == param_id,
                EditMode::GroupAddressInput { .. }
                | EditMode::ObjectFlagsInput { .. }
                | EditMode::NetNameInput { .. }
                | EditMode::LanguageSelect { .. }
                | EditMode::None => false,
            };

            // Use 40% of width for label, leave rest for value
            let label_width = (width * 40 / 100).clamp(20, 45);
            let label = if text.len() > label_width {
                format!("{}…", &text[..label_width - 1])
            } else {
                format!("{:width$}", text, width = label_width)
            };
            let suffix_text = suffix.as_deref().unwrap_or("");

            let value_spans = render_widget(widget, editing, app, suffix_text, width - label_width);

            let mut spans = vec![Span::styled(label, Style::default().fg(Color::White).bg(bg))];
            spans.extend(
                value_spans
                    .into_iter()
                    .map(|s| if bg != Color::Reset { Span::styled(s.content, s.style.bg(bg)) } else { s }),
            );

            vec![Line::from(spans)]
        }
        ContentItem::Separator { text, ui_hint } => separator_lines(text.as_deref(), ui_hint.as_deref(), width, bg),
        ContentItem::CommObject { name, function, dpt } => {
            // Display comm object with distinctive styling
            let label_width = (width * 40 / 100).clamp(20, 45);
            let label = if name.len() > label_width {
                format!("📡{}…", &name[..label_width - 3])
            } else {
                format!("📡{:width$}", name, width = label_width - 2)
            };

            // Show function and DPT in value area
            let info = if dpt.is_empty() { function.clone() } else { format!("{} [{}]", function, dpt) };

            vec![Line::from(vec![
                Span::styled(label, Style::default().fg(Color::Cyan).bg(bg)),
                Span::styled(info, Style::default().fg(Color::DarkGray).bg(bg)),
            ])]
        }
        ContentItem::Picture { .. } => {
            // Pictures are handled separately by render_picture_item
            vec![Line::from(vec![])]
        }
    }
}

/// Render a `ParameterSeparator` the way ETS distinguishes them: an explicit
/// `HorizontalRuler` is a divider, `Information` is a note, and a plain
/// separator is its text alone — heading or paragraph — or vertical
/// spacing when the text is empty. Only a `HorizontalRuler` draws dashes.
fn separator_lines<'a>(text: Option<&str>, ui_hint: Option<&str>, width: usize, bg: Color) -> Vec<Line<'a>> {
    let ruler_style = Style::default().fg(Color::DarkGray).bg(bg);
    // Vendor texts embed CRLF and LF line breaks (`&#xD;&#xA;` / `&#xA;`).
    let text = text.unwrap_or("").replace("\r\n", "\n");
    let trimmed = text.trim();

    match ui_hint {
        Some("HorizontalRuler") => vec![Line::from(Span::styled("─".repeat(width), ruler_style))],
        Some("Information") => {
            // Informational note: distinct color, ℹ marker on the first line.
            let style = Style::default().fg(Color::Cyan).bg(bg);
            wrapped_paragraph(trimmed, width.saturating_sub(2), style, "ℹ ", "  ")
        }
        _ => {
            if trimmed.is_empty() {
                // Plain empty separator: vertical spacing, not a ruler. The
                // full-width blank keeps the selection highlight visible.
                vec![Line::from(Span::styled(" ".repeat(width), ruler_style))]
            } else {
                // Text, kept as the author's line breaks, wrapped to width.
                // Leading whitespace stays: vendors indent separator text
                // with literal spaces ("    Slave 1") and ETS renders
                // them verbatim.
                let style = Style::default().fg(Color::Gray).bg(bg);
                wrapped_paragraph(text.trim_end(), width, style, "", "")
            }
        }
    }
}

/// Word-wrap `text` to `width` columns, preserving its own line breaks.
/// `first_prefix` starts the first line, `cont_prefix` every following one.
fn wrapped_paragraph<'a>(
    text: &str,
    width: usize,
    style: Style,
    first_prefix: &str,
    cont_prefix: &str,
) -> Vec<Line<'a>> {
    let width = width.max(8);
    let mut lines = Vec::new();
    let mut first = true;

    for source_line in text.lines() {
        // An empty source line is a paragraph break the author wrote.
        if source_line.trim().is_empty() {
            lines.push(String::new());
            continue;
        }

        // Each source line keeps its own leading whitespace — on wrapped
        // continuation rows too — since ETS renders it verbatim.
        let indent: String = source_line.chars().take_while(|c| c.is_whitespace()).collect();
        let wrap_width = width.saturating_sub(indent.chars().count()).max(8);

        let mut current = String::new();
        for word in source_line.split_whitespace() {
            let candidate_len = if current.is_empty() {
                word.chars().count()
            } else {
                current.chars().count() + 1 + word.chars().count()
            };
            if candidate_len > wrap_width && !current.is_empty() {
                lines.push(format!("{indent}{}", std::mem::take(&mut current)));
            }
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
        if !current.is_empty() {
            lines.push(format!("{indent}{current}"));
        }
    }

    lines
        .into_iter()
        .map(|l| {
            let prefix = if first { first_prefix } else { cont_prefix };
            first = false;
            Line::from(Span::styled(format!("{prefix}{l}"), style))
        })
        .collect()
}

/// Render a picture item with inline image in the value column.
#[allow(clippy::too_many_arguments)]
fn render_picture_item(
    frame: &mut Frame,
    area: Rect,
    app: &mut App,
    ref_id: &str,
    text: Option<&str>,
    alignment: Option<&str>,
    is_selected: bool,
    label_width: usize,
) {
    let bg = if is_selected { Color::DarkGray } else { Color::Reset };

    // Calculate value column area (skip the label column width)
    // Add 1 row padding top and bottom for breathing room
    let padding = if area.height > 2 { 1 } else { 0 };
    let value_area = Rect {
        x: area.x + (label_width as u16).min(area.width),
        y: area.y + padding,
        width: area.width.saturating_sub(label_width as u16),
        height: area.height.saturating_sub(padding * 2),
    };

    // The picture parameter's Text goes in the label column, the way a
    // parameter label sits left of its value widget in ETS, vertically
    // centered on the image as ETS does ("Anschluss-Schema:" sits at the
    // wiring diagram's mid-height). The text may carry its own line
    // breaks (the Weinzierl logo caption does).
    if let Some(text) = text {
        let label_height = area.height.saturating_sub(padding * 2);
        let label_cols = (label_width as u16).min(area.width);
        let max_len = label_cols as usize;
        let lines: Vec<Line> = text
            .replace("\r\n", "\n")
            .lines()
            .take(label_height as usize)
            .map(|l| {
                let display = if l.chars().count() > max_len {
                    format!("{}…", l.chars().take(max_len.saturating_sub(1)).collect::<String>())
                } else {
                    l.to_string()
                };
                Line::from(Span::styled(display, Style::default().fg(Color::White).bg(bg)))
            })
            .collect();
        let v_offset = label_height.saturating_sub(lines.len() as u16) / 2;
        let label_area = Rect {
            x: area.x,
            y: area.y + padding + v_offset,
            width: label_cols,
            height: label_height.saturating_sub(v_offset),
        };
        frame.render_widget(Paragraph::new(lines), label_area);
    }

    // ETS places the picture inside the value column per the type's
    // HorizontalAlignment (Left is the schema default).
    let text_alignment = match alignment {
        Some("Right") => ratatui::layout::Alignment::Right,
        Some("Middle") => ratatui::layout::Alignment::Center,
        _ => ratatui::layout::Alignment::Left,
    };

    // Render image in the value column
    #[cfg(feature = "images")]
    {
        // Give the image an exactly-sized area at its logical-pixel cell
        // extent, placed per HorizontalAlignment. Resize::Scale below
        // fills it exactly, up- or downscaling as the terminal's device
        // pixel density demands.
        let image_area = match app.picture_cell_size(ref_id, value_area.width) {
            Some((cols, rows)) => {
                let width = cols.min(value_area.width);
                let x = match alignment {
                    Some("Right") => value_area.x + value_area.width - width,
                    Some("Middle") => value_area.x + (value_area.width - width) / 2,
                    _ => value_area.x,
                };
                Rect { x, y: value_area.y, width, height: rows.min(value_area.height) }
            }
            None => value_area,
        };

        if let Some(protocol) = app.load_image(ref_id) {
            let image: StatefulImage<StatefulProtocol> =
                StatefulImage::default().resize(Resize::Scale(Some(FilterType::Lanczos3)));
            frame.render_stateful_widget(image, image_area, protocol);
        } else {
            // Show placeholder if image not found
            let placeholder = Paragraph::new(format!("[{}]", ref_id))
                .alignment(text_alignment)
                .style(Style::default().fg(Color::DarkGray).bg(bg));
            frame.render_widget(placeholder, value_area);
        }
    }
    #[cfg(not(feature = "images"))]
    {
        // Without images feature, just show the ref_id as text
        let _ = app; // suppress unused warning
        let placeholder = Paragraph::new(format!("[Image: {}]", ref_id))
            .alignment(text_alignment)
            .style(Style::default().fg(Color::Yellow).bg(bg));
        frame.render_widget(placeholder, value_area);
    }
}

fn render_widget<'a>(widget: &WidgetType, editing: bool, app: &App, suffix: &str, max_width: usize) -> Vec<Span<'a>> {
    match widget {
        WidgetType::Dropdown { options, current_idx } => {
            let value_text = options.get(*current_idx).map(|(_, text)| text.as_str()).unwrap_or("?");

            // Truncate if needed
            let display = if value_text.len() > max_width.saturating_sub(5) {
                format!("{}…", &value_text[..max_width.saturating_sub(6)])
            } else {
                value_text.to_string()
            };

            if editing {
                vec![
                    Span::styled("[", Style::default().fg(Color::Yellow)),
                    Span::styled(display, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                    Span::styled(" ▼]", Style::default().fg(Color::Yellow)),
                ]
            } else {
                vec![
                    Span::styled("[", Style::default().fg(Color::DarkGray)),
                    Span::styled(display, Style::default().fg(Color::Green)),
                    Span::styled(" ▼]", Style::default().fg(Color::DarkGray)),
                ]
            }
        }
        WidgetType::Number { value, min, max } => {
            let value_str = match &app.edit_mode {
                EditMode::NumberInput { buffer, .. } if editing => {
                    format!("{}▏", buffer)
                }
                _ => value.to_string(),
            };

            let range_hint = match (min, max) {
                (Some(mn), Some(mx)) => format!(" ({}..{})", mn, mx),
                _ => String::new(),
            };

            if editing {
                vec![
                    Span::styled("[", Style::default().fg(Color::Yellow)),
                    Span::styled(value_str, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::styled("]", Style::default().fg(Color::Yellow)),
                    Span::styled(format!(" {}", suffix), Style::default().fg(Color::DarkGray)),
                    Span::styled(range_hint, Style::default().fg(Color::DarkGray)),
                ]
            } else {
                vec![
                    Span::styled("[", Style::default().fg(Color::DarkGray)),
                    Span::styled(value_str, Style::default().fg(Color::Cyan)),
                    Span::styled("]", Style::default().fg(Color::DarkGray)),
                    Span::styled(format!(" {}", suffix), Style::default().fg(Color::DarkGray)),
                ]
            }
        }
        WidgetType::Text { value } => {
            let value_str = match &app.edit_mode {
                EditMode::TextInput { buffer, cursor, .. } if editing => {
                    let mut s = buffer.clone();
                    s.insert(*cursor, '▏');
                    s
                }
                _ => value.clone(),
            };

            // Use available width
            let text_max = max_width.saturating_sub(4);
            let display = if value_str.len() > text_max {
                format!("{}…", &value_str[..text_max.saturating_sub(1)])
            } else {
                value_str
            };

            if editing {
                vec![
                    Span::styled("[", Style::default().fg(Color::Yellow)),
                    Span::styled(display, Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD)),
                    Span::styled("]", Style::default().fg(Color::Yellow)),
                ]
            } else {
                vec![
                    Span::styled("[", Style::default().fg(Color::DarkGray)),
                    Span::styled(display, Style::default().fg(Color::LightMagenta)),
                    Span::styled("]", Style::default().fg(Color::DarkGray)),
                ]
            }
        }
        WidgetType::ReadOnly { value } => {
            vec![
                Span::styled(value.clone(), Style::default().fg(Color::DarkGray)),
                Span::styled(format!(" {}", suffix), Style::default().fg(Color::DarkGray)),
            ]
        }
    }
}

fn render_comm_objects_view(frame: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focus == Focus::Content && app.current_tab == MainTab::CommObjects;
    let visible_rows = usize::from(area.height.saturating_sub(4)).max(1);
    keep_selection_visible(&mut app.comm_obj_scroll_offset, app.selected_obj_idx, visible_rows);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if focused { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) })
        .title(if app.comm_obj_scroll_offset > 0 || app.com_object_rows.len() > 20 {
            format!(
                " Communication Objects ({}) [{}-{}] ",
                app.com_object_rows.len(),
                app.comm_obj_scroll_offset + 1,
                (app.comm_obj_scroll_offset + 20).min(app.com_object_rows.len())
            )
        } else {
            format!(" Communication Objects ({}) ", app.com_object_rows.len())
        });

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.com_object_rows.is_empty() {
        let empty = Paragraph::new("No communication objects").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(empty, inner);
        return;
    }

    // Build table header
    let header = Row::new(vec![
        "No",
        "Name",
        "Function",
        "Group Addr",
        "Size",
        "DPT",
        "Prio",
        "C",
        "R",
        "W",
        "T",
        "U",
        "I",
        "Src",
    ])
    .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
    .bottom_margin(0);

    // Check if we're editing a group address
    let editing_object = match &app.edit_mode {
        EditMode::GroupAddressInput { object_number, buffer } => Some((*object_number, buffer.clone())),
        _ => None,
    };
    let editing_flags = match &app.edit_mode {
        EditMode::ObjectFlagsInput { object_number, buffer } => Some((*object_number, buffer.clone())),
        _ => None,
    };

    // Calculate visible height (area minus header, borders).
    let visible_rows = inner.height.saturating_sub(2) as usize;

    // Build table rows with scroll offset
    let rows: Vec<Row> = app
        .com_object_rows
        .iter()
        .enumerate()
        .skip(app.comm_obj_scroll_offset)
        .take(visible_rows)
        .map(|(i, row)| {
            let is_selected = i == app.selected_obj_idx && focused;
            let is_editing = editing_object.as_ref().is_some_and(|(n, _)| *n == row.number);
            let style =
                if is_selected { Style::default().bg(Color::DarkGray).fg(Color::White) } else { Style::default() };

            let flag = |b: bool| if b { "●" } else { "○" };

            // Show input buffer if editing this row's group address
            let group_addr_display = if is_editing {
                let buffer = &editing_object.as_ref().unwrap().1;
                format!("▸{}█", buffer)
            } else if row.group_address.is_empty() {
                "—".to_string()
            } else {
                row.group_address.clone()
            };

            let name = editing_flags
                .as_ref()
                .filter(|(number, _)| *number == row.number)
                .map_or_else(|| truncate_string(&row.name, 35), |(_, buffer)| format!("FLAGS: {buffer}█"));
            Row::new(vec![
                format!("{:3}", row.number),
                name,
                truncate_string(&row.function, 25),
                group_addr_display,
                row.size.clone(),
                truncate_string(&row.dpt, 14),
                row.priority.clone(),
                flag(row.flag_c).to_string(),
                flag(row.flag_r).to_string(),
                flag(row.flag_w).to_string(),
                flag(row.flag_t).to_string(),
                flag(row.flag_u).to_string(),
                flag(row.flag_i).to_string(),
                row.provenance.clone(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(4),  // No
        Constraint::Length(37), // Name
        Constraint::Length(27), // Function
        Constraint::Length(12), // Group Addr
        Constraint::Length(10), // Size
        Constraint::Length(16), // DPT
        Constraint::Length(5),  // Prio
        Constraint::Length(2),  // C
        Constraint::Length(2),  // R
        Constraint::Length(2),  // W
        Constraint::Length(2),  // T
        Constraint::Length(2),  // U
        Constraint::Length(2),  // I
        Constraint::Length(8),  // source provenance
    ];

    let table = Table::new(rows, widths).header(header).row_highlight_style(Style::default().bg(Color::DarkGray));

    frame.render_widget(table, inner);
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() > max_len { format!("{}…", &s[..max_len - 1]) } else { s.to_string() }
}

fn render_memory_view(frame: &mut Frame, area: Rect, app: &mut App) {
    let sidebar_width = responsive_left_width(app.pane_layout.memory_sidebar_width, area.width, 20, 30);
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(sidebar_width), Constraint::Min(1)])
        .split(area);

    render_segment_selector(frame, chunks[0], app);
    render_hex_view(frame, chunks[1], app);
}

/// Honor a preferred column width while reserving room for the pane on its
/// right. On a narrow terminal the preferred/minimum left width yields first;
/// because the preference itself is untouched, enlarging the window restores
/// the user's split instead of making the temporary compression permanent.
fn responsive_left_width(preferred: u16, total: u16, minimum_left: u16, minimum_right: u16) -> u16 {
    if total == 0 {
        return 0;
    }
    let maximum_left = total.saturating_sub(minimum_right).max(1);
    if maximum_left < minimum_left { maximum_left } else { preferred.clamp(minimum_left, maximum_left) }
}

fn keep_selection_visible(offset: &mut usize, selected: usize, visible_rows: usize) {
    let visible_rows = visible_rows.max(1);
    if selected < *offset {
        *offset = selected;
    } else if selected >= *offset + visible_rows {
        *offset = selected + 1 - visible_rows;
    }
}

fn render_segment_selector(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Sidebar && app.current_tab == MainTab::Memory;

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if focused { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) })
        .title(format!(" Segments ({}) ", app.memory_segments.len()));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.memory_segments.is_empty() {
        let empty = Paragraph::new("No memory segments").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(empty, inner);
        return;
    }

    let items: Vec<ListItem> = app
        .memory_segments
        .iter()
        .enumerate()
        .map(|(i, seg)| {
            let is_selected = i == app.selected_segment_idx && focused;

            // Format segment info
            let type_char = match seg.segment_type {
                SegmentType::Absolute => "A",
                SegmentType::Relative => "R",
            };

            let addr_str = match seg.segment_type {
                SegmentType::Absolute => format!("0x{:04X}", seg.address),
                SegmentType::Relative => format!("+0x{:04X}", seg.address),
            };

            let mem_type = seg.memory_type.as_deref().unwrap_or("");
            let lsm = seg.load_state_machine.map(|l| format!(" LSM:{}", l)).unwrap_or_default();

            let size_str =
                if seg.data.is_empty() { format!("{}B (no data)", seg.size) } else { format!("{}B", seg.data.len()) };

            let text = format!("[{}] {} {} {}{}", type_char, addr_str, size_str, mem_type, lsm);

            let style = if is_selected {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default().fg(Color::White)
            };

            // Truncate if needed
            let max_len = inner.width.saturating_sub(2) as usize;
            let display =
                if text.len() > max_len { format!("{}…", &text[..max_len.saturating_sub(1)]) } else { text };

            ListItem::new(Line::from(Span::styled(display, style)))
        })
        .collect();

    let mut state = ListState::default().with_selected(Some(app.selected_segment_idx));
    frame.render_stateful_widget(List::new(items), inner, &mut state);
}

fn render_hex_view(frame: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focus == Focus::Content && app.current_tab == MainTab::Memory;

    let segment = app.memory_segments.get(app.selected_segment_idx);

    let title = if let Some(seg) = segment {
        let addr_str = match seg.segment_type {
            SegmentType::Absolute => format!("0x{:04X}", seg.address),
            SegmentType::Relative => format!("+0x{:04X}", seg.address),
        };
        format!(" {} @ {} ", seg.id, addr_str)
    } else {
        " No Segment ".to_string()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if focused { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) })
        .title(title);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // The viewport can change independently of keyboard navigation when the
    // terminal or a neighbouring pane is resized.
    let visible_lines = usize::from(inner.height.saturating_sub(2)).max(1);
    keep_selection_visible(&mut app.memory_scroll_offset, app.selected_byte_offset / 16, visible_lines);

    let segment = match segment {
        Some(s) => s,
        None => {
            let empty = Paragraph::new("No segment selected").style(Style::default().fg(Color::DarkGray));
            frame.render_widget(empty, inner);
            return;
        }
    };

    if segment.data.is_empty() {
        let empty = Paragraph::new("(no data in segment)").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(empty, inner);
        return;
    }

    // Calculate visible lines (reserve 2 lines: 1 for header, 1 for info)
    let total_lines = segment.data.len().div_ceil(16);

    // Build hex dump lines
    let mut lines: Vec<Line> = Vec::with_capacity(visible_lines + 2);

    // Header line
    lines.push(Line::from(vec![Span::styled(
        "Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ASCII",
        Style::default().fg(Color::Cyan),
    )]));

    // Data lines
    for line_idx in 0..visible_lines {
        let actual_line = app.memory_scroll_offset + line_idx;
        if actual_line >= total_lines {
            break;
        }

        let offset = actual_line * 16;
        let mut spans = Vec::new();

        // Offset column
        spans.push(Span::styled(format!("{:04X}:     ", offset), Style::default().fg(Color::DarkGray)));

        // Hex bytes
        for i in 0..16 {
            let byte_offset = offset + i;
            if byte_offset >= segment.data.len() {
                spans.push(Span::raw("   "));
            } else {
                let byte = segment.data[byte_offset];
                let is_selected = byte_offset == app.selected_byte_offset && focused;
                let is_annotated = app.get_annotation_at_offset(byte_offset).is_some();

                let style = if is_selected {
                    Style::default().bg(Color::Yellow).fg(Color::Black).add_modifier(Modifier::BOLD)
                } else if is_annotated {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::White)
                };

                spans.push(Span::styled(format!("{:02X}", byte), style));
                spans.push(Span::raw(" "));
            }

            // Add extra space in middle
            if i == 7 {
                spans.push(Span::raw(" "));
            }
        }

        // ASCII representation
        spans.push(Span::raw(" "));
        for i in 0..16 {
            let byte_offset = offset + i;
            if byte_offset >= segment.data.len() {
                spans.push(Span::raw(" "));
            } else {
                let byte = segment.data[byte_offset];
                let ch = if byte.is_ascii_graphic() || byte == b' ' { byte as char } else { '.' };
                let is_selected = byte_offset == app.selected_byte_offset && focused;

                let style = if is_selected {
                    Style::default().bg(Color::Yellow).fg(Color::Black).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                };

                spans.push(Span::styled(ch.to_string(), style));
            }
        }

        lines.push(Line::from(spans));
    }

    // Info line at bottom showing annotation if cursor is on one
    let info_text = if let Some(ann) = app.get_annotation_at_offset(app.selected_byte_offset) {
        format!("Parameter: {} (offset: {}, {} bits)", ann.name, ann.offset, ann.size_bits)
    } else {
        let byte_val = segment.data.get(app.selected_byte_offset).copied();
        if let Some(b) = byte_val {
            format!(
                "Offset: 0x{:04X} | Value: 0x{:02X} ({}) | Line {}/{}",
                app.selected_byte_offset,
                b,
                b,
                app.selected_byte_offset / 16 + 1,
                total_lines
            )
        } else {
            String::new()
        }
    };

    lines.push(Line::from(Span::styled(info_text, Style::default().fg(Color::Cyan))));

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, inner);
}

/// Maximum visible items in dropdown (must match App::DROPDOWN_VISIBLE_ITEMS)
const DROPDOWN_VISIBLE_ITEMS: usize = 12;

fn render_dropdown_popup(
    frame: &mut Frame,
    options: &[(i64, String)],
    selected_idx: usize,
    scroll_offset: usize,
    title: &str,
) {
    let max_width = options.iter().map(|(_, t)| t.len()).max().unwrap_or(10) + 8;
    let visible_count = options.len().min(DROPDOWN_VISIBLE_ITEMS);
    let height = (visible_count + 2) as u16;
    let width = (max_width as u16).min(50);

    let area = frame.area();
    let popup_area =
        Rect { x: area.width.saturating_sub(width) / 2, y: area.height.saturating_sub(height) / 2, width, height };

    // Clear background
    frame.render_widget(Block::default().style(Style::default().bg(Color::Black)), popup_area);

    // Show scroll indicators in title
    let has_more_above = scroll_offset > 0;
    let has_more_below = scroll_offset + visible_count < options.len();
    let title = match (has_more_above, has_more_below) {
        (true, true) => format!(" ▲ {title} ▼ "),
        (true, false) => format!(" ▲ {title} "),
        (false, true) => format!(" {title} ▼ "),
        (false, false) => format!(" {title} "),
    };

    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow)).title(title);

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Only show items within the visible window
    let visible_options = options.iter().enumerate().skip(scroll_offset).take(visible_count);

    let items: Vec<ListItem> = visible_options
        .map(|(i, (_, text))| {
            let is_selected = i == selected_idx;
            let style = if is_selected {
                Style::default().bg(Color::Yellow).fg(Color::Black).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let prefix = if is_selected { "● " } else { "  " };
            ListItem::new(Line::from(vec![Span::styled(prefix, style), Span::styled(text.clone(), style)]))
        })
        .collect();

    let list = List::new(items);
    frame.render_widget(list, inner);
}

fn render_status(frame: &mut Frame, area: Rect, app: &App) {
    // Cached on App: counting means hashing every visible ref id,
    // far too expensive per frame on large products.
    let visible_params = app.visible_param_count;
    let visible_objs = app.visible_obj_count;

    // Feedback (export result, input error) displaces the key hints
    // until the next message replaces it.
    if let Some(message) = &app.status_message {
        let status = Paragraph::new(format!(" {message}")).style(Style::default().fg(Color::Black).bg(Color::Yellow));
        frame.render_widget(status, area);
        return;
    }

    let help = match (&app.edit_mode, app.current_tab, app.focus) {
        (EditMode::EnumDropdown { .. }, _, _) => "↑/↓: Select | Enter: Confirm | Esc: Cancel",
        (EditMode::NumberInput { .. }, _, _) => "Type number | Enter: Confirm | Esc: Cancel",
        (EditMode::TextInput { .. }, _, _) => "Type text | Enter: Confirm | Esc: Cancel",
        (EditMode::NetNameInput { .. }, _, _) => "Type group-address name | Enter: Confirm | Esc: Cancel",
        (EditMode::LanguageSelect { .. }, _, _) => "↑/↓: Select language | Enter: Apply | Esc: Cancel",
        (EditMode::GroupAddressInput { .. }, _, _) => {
            "Type group address(es), comma-separated, first one sends | Enter: Confirm | Esc: Cancel"
        }
        (EditMode::ObjectFlagsInput { .. }, _, _) => {
            "Edit C/R/W/T/U/I as 1, 0, or -; P as system/high/alarm/low/- | Enter: Confirm | Esc: Cancel"
        }
        (EditMode::None, _, Focus::Project) => {
            "↑/↓: Navigate | Enter: Open/details | r: Rename GA | Ctrl+arrows: Resize | Tab: Editor | q: Quit"
        }
        (EditMode::None, _, Focus::Tabs) => {
            "←/→: Tab | a: Address | u: App | p: Both | A: Affected | P: Project | K: Keys | q: Quit"
        }
        (EditMode::None, MainTab::Parameters, Focus::Sidebar) => {
            "↑/↓: Navigate | Enter: Expand | Ctrl+←/→: Width | Tab: Content | q: Quit"
        }
        (EditMode::None, MainTab::Parameters, Focus::Content) => {
            "↑/↓: Navigate | Enter: Edit | Ctrl+←/→: Page width | Tab: Next pane | q: Quit"
        }
        (EditMode::None, MainTab::CommObjects, Focus::Content) => {
            "↑/↓: Navigate | Enter: GA | f: Flags | s: Net security | d: Data Secure | e: Save | P: Project | Tab: Tabs"
        }
        (EditMode::None, MainTab::CommObjects, Focus::Sidebar) => {
            // Shouldn't happen
            "Tab: Switch focus | q: Quit"
        }
        (EditMode::None, MainTab::Memory, Focus::Sidebar) => {
            "↑/↓: Select segment | Ctrl+←/→: Width | Enter: View | Tab: Hex view | q: Quit"
        }
        (EditMode::None, MainTab::Memory, Focus::Content) => {
            "↑/↓/←/→: Navigate bytes | Ctrl+←/→: Segment width | Tab: Next pane | q: Quit"
        }
    };

    // Build device info string from master data
    let secure_state = match (app.device.program().is_secure_enabled.unwrap_or(false), app.data_secure.is_enabled()) {
        (false, false) => "DS unsupported",
        (false, true) => "DS invalid",
        (true, false) => "DS supported/off",
        (true, true) => "DS supported/on",
    };
    let device_info = if let Some(model) = app.management_model() {
        let first_obj = app.first_app_object_idx();
        format!(
            " Params: {} | Objects: {} | {} | ObjIdx: {} | {} ",
            visible_params, visible_objs, model, first_obj, secure_state
        )
    } else {
        format!(" Params: {} | Objects: {} | {} ", visible_params, visible_objs, secure_state)
    };

    let status = Paragraph::new(Line::from(vec![
        Span::styled(device_info, Style::default().fg(Color::DarkGray)),
        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
        Span::styled(help, Style::default().fg(Color::Cyan)),
    ]));

    frame.render_widget(status, area);
}

/// The programming popup: the tasks already done, the one in flight,
/// and a progress gauge over the whole procedure.
fn render_download_popup(frame: &mut Frame, app: &App) {
    let Some(download) = &app.download else { return };

    let popup = programming_popup_area(frame.area());

    // Styling a block changes the cells' colours but deliberately leaves their
    // symbols intact. Clear first so text from the editor cannot bleed through
    // otherwise-empty parts of the modal.
    frame.render_widget(Clear, popup);
    frame.render_widget(Block::default().style(Style::default().bg(Color::Black)), popup);

    let (border, title) = match &download.result {
        None => (Color::Cyan, " ⚡ Programming device ".to_string()),
        Some(Ok(_)) => (Color::Green, " ✔ Programming complete ".to_string()),
        Some(Err(_)) => (Color::Red, " ✘ Programming failed ".to_string()),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border).add_modifier(Modifier::BOLD))
        .title(title);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(4),    // task history + current
            Constraint::Length(1), // spacer
            Constraint::Length(2), // gauge
            Constraint::Length(1), // footer
        ])
        .split(inner);

    // Task list: as many finished tasks as fit above the current one.
    let task_rows = chunks[0].height as usize;
    let mut lines: Vec<Line> = Vec::new();
    let history = task_rows.saturating_sub(1);
    for label in download.past.iter().rev().take(history).rev() {
        lines.push(Line::from(vec![
            Span::styled("  ✔ ", Style::default().fg(Color::Green)),
            Span::styled(label.clone(), Style::default().fg(Color::Gray)),
        ]));
    }
    const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    match (&download.current, &download.result) {
        (Some(label), _) => {
            let frame_glyph = SPINNER[download.spinner % SPINNER.len()];
            let mut spans = vec![
                Span::styled(format!("  {frame_glyph} "), Style::default().fg(Color::Cyan)),
                Span::styled(label.clone(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            ];
            if let Some((done, total)) = download.data {
                spans.push(Span::styled(format!("  {done}/{total} B"), Style::default().fg(Color::Cyan)));
            }
            lines.push(Line::from(spans));
        }
        (None, Some(Ok(summary))) => {
            lines.push(Line::from(Span::styled(
                format!("  {summary}"),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            )));
        }
        (None, Some(Err(error))) => {
            lines.push(Line::from(Span::styled(
                format!("  {error}"),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
        }
        (None, None) => {}
    }
    frame.render_widget(Paragraph::new(lines), chunks[0]);

    // The gauge: overall procedure progress, byte-blended.
    let (index, total) = download.step;
    let label = if download.result.is_some() {
        "done".to_string()
    } else if total == 0 {
        "preparing…".to_string()
    } else {
        format!("step {}/{}", index + 1, total)
    };
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(border).bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .percent(app.download_ratio())
        .label(label);
    frame.render_widget(gauge, chunks[2]);

    let footer = match &download.result {
        None => "programming — hands off the keyboard",
        Some(_) => "Enter / Esc: close",
    };
    frame.render_widget(
        Paragraph::new(footer).alignment(Alignment::Center).style(Style::default().fg(Color::Gray)),
        chunks[3],
    );
}

fn programming_popup_area(area: Rect) -> Rect {
    // Keep a small frame of the underlying project visible while using enough
    // room for meaningful download history. Tiny terminals get the entire
    // available area instead of producing an oversized modal.
    let width = if area.width > 4 { area.width.saturating_sub(4).min(100) } else { area.width };
    let height = if area.height > 2 { area.height.saturating_sub(2).min(24) } else { area.height };

    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn responsive_width_preserves_the_preference_when_space_allows() {
        assert_eq!(responsive_left_width(34, 120, 24, 40), 34);
        assert_eq!(responsive_left_width(90, 120, 24, 40), 80);
        assert_eq!(responsive_left_width(10, 120, 24, 40), 24);
    }

    #[test]
    fn responsive_width_yields_to_the_right_pane_on_small_windows() {
        assert_eq!(responsive_left_width(34, 50, 24, 40), 10);
        assert_eq!(responsive_left_width(34, 0, 24, 40), 0);
    }

    #[test]
    fn scrolling_tracks_selection_after_viewport_changes() {
        let mut offset = 20;
        keep_selection_visible(&mut offset, 30, 5);
        assert_eq!(offset, 26);
        keep_selection_visible(&mut offset, 3, 5);
        assert_eq!(offset, 3);
    }

    #[test]
    fn programming_popup_is_roomy_and_bounded() {
        assert_eq!(programming_popup_area(Rect::new(10, 5, 140, 50)), Rect::new(30, 18, 100, 24));
        assert_eq!(programming_popup_area(Rect::new(3, 7, 40, 12)), Rect::new(5, 8, 36, 10));
        assert_eq!(programming_popup_area(Rect::new(3, 7, 4, 2)), Rect::new(3, 7, 4, 2));
    }
}
