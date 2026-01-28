//! UI rendering for the KNX TUI viewer.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table},
    Frame,
};

use crate::app::{App, ContentItem, EditMode, Focus, MainTab, WidgetType};

/// Render the application UI.
pub fn render(frame: &mut Frame, app: &App) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tab bar
            Constraint::Min(10),   // Main content
            Constraint::Length(2), // Status bar
        ])
        .split(frame.area());

    render_tabs(frame, main_chunks[0], app);

    match app.current_tab {
        MainTab::Parameters => render_parameters_view(frame, main_chunks[1], app),
        MainTab::CommObjects => render_comm_objects_view(frame, main_chunks[1], app),
    }

    render_status(frame, main_chunks[2], app);

    // Render edit popup if in edit mode
    if let EditMode::EnumDropdown {
        options,
        selected_idx,
        scroll_offset,
        ..
    } = &app.edit_mode
    {
        render_dropdown_popup(frame, options, *selected_idx, *scroll_offset);
    }
}

fn render_tabs(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Tabs;

    let tabs = vec![
        ("Parameters", MainTab::Parameters),
        ("Communication Objects", MainTab::CommObjects),
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
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
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

    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(format!(" KNX Viewer - {} ", app.model.program.name));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let tabs_line = Paragraph::new(Line::from(spans));
    frame.render_widget(tabs_line, inner);
}

fn render_parameters_view(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Max(30),        // Sidebar - max 30 chars
            Constraint::Percentage(70), // Content - gets most of the space
        ])
        .split(area);

    render_sidebar(frame, chunks[0], app);
    render_param_content(frame, chunks[1], app);
}

fn render_sidebar(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Sidebar;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        })
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
            let prefix = if node.has_children {
                if node.expanded {
                    "▼ "
                } else {
                    "► "
                }
            } else {
                "  "
            };

            let style = if is_selected {
                Style::default().bg(Color::DarkGray).fg(Color::White)
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

    let list = List::new(items);
    frame.render_widget(list, inner);
}

fn render_param_content(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Content && app.current_tab == MainTab::Parameters;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        })
        .title(format!(" {} ", app.current_node_name()));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.content_items.is_empty() {
        let empty = Paragraph::new("No parameters").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(empty, inner);
        return;
    }

    let items: Vec<ListItem> = app
        .content_items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let is_selected = i == app.selected_content_idx && focused;
            create_content_item(item, is_selected, app, inner.width as usize)
        })
        .collect();

    let list = List::new(items);
    frame.render_widget(list, inner);
}

fn create_content_item<'a>(
    item: &ContentItem,
    is_selected: bool,
    app: &App,
    width: usize,
) -> ListItem<'a> {
    let bg = if is_selected {
        Color::DarkGray
    } else {
        Color::Reset
    };

    match item {
        ContentItem::Parameter {
            text,
            suffix,
            widget,
            param_id,
        } => {
            // Check if we're editing this parameter
            let editing = match &app.edit_mode {
                EditMode::NumberInput {
                    param_id: edit_id, ..
                } => edit_id == param_id,
                EditMode::TextInput {
                    param_id: edit_id, ..
                } => edit_id == param_id,
                EditMode::EnumDropdown {
                    param_id: edit_id, ..
                } => edit_id == param_id,
                EditMode::None => false,
            };

            // Use 40% of width for label, leave rest for value
            let label_width = (width * 40 / 100).max(20).min(45);
            let label = if text.len() > label_width {
                format!("{}…", &text[..label_width - 1])
            } else {
                format!("{:width$}", text, width = label_width)
            };
            let suffix_text = suffix.as_deref().unwrap_or("");

            let value_spans = render_widget(widget, editing, app, suffix_text, width - label_width);

            let mut spans = vec![Span::styled(label, Style::default().fg(Color::White).bg(bg))];
            spans.extend(value_spans.into_iter().map(|s| {
                if bg != Color::Reset {
                    Span::styled(s.content, s.style.bg(bg))
                } else {
                    s
                }
            }));

            ListItem::new(Line::from(spans))
        }
        ContentItem::Separator { text } => {
            let sep_text = text.as_deref().unwrap_or("");
            // Create a separator that spans the full width
            let separator_line = if sep_text.is_empty() || sep_text.trim().is_empty() {
                "─".repeat(width)
            } else {
                // Format: "── text ────────────" spanning full width
                let prefix = format!("── {} ", sep_text.trim());
                let remaining = width.saturating_sub(prefix.chars().count());
                format!("{}{}", prefix, "─".repeat(remaining))
            };
            ListItem::new(Line::from(vec![Span::styled(
                separator_line,
                Style::default().fg(Color::DarkGray).bg(bg),
            )]))
        }
        ContentItem::CommObject {
            name,
            function,
            dpt,
        } => {
            // Display comm object with distinctive styling
            let label_width = (width * 40 / 100).max(20).min(45);
            let label = if name.len() > label_width {
                format!("📡{}…", &name[..label_width - 3])
            } else {
                format!("📡{:width$}", name, width = label_width - 2)
            };

            // Show function and DPT in value area
            let info = if dpt.is_empty() {
                function.clone()
            } else {
                format!("{} [{}]", function, dpt)
            };

            ListItem::new(Line::from(vec![
                Span::styled(label, Style::default().fg(Color::Cyan).bg(bg)),
                Span::styled(info, Style::default().fg(Color::DarkGray).bg(bg)),
            ]))
        }
    }
}

fn render_widget<'a>(
    widget: &WidgetType,
    editing: bool,
    app: &App,
    suffix: &str,
    max_width: usize,
) -> Vec<Span<'a>> {
    match widget {
        WidgetType::Dropdown {
            options,
            current_idx,
        } => {
            let value_text = options
                .get(*current_idx)
                .map(|(_, text)| text.as_str())
                .unwrap_or("?");

            // Truncate if needed
            let display = if value_text.len() > max_width.saturating_sub(5) {
                format!("{}…", &value_text[..max_width.saturating_sub(6)])
            } else {
                value_text.to_string()
            };

            if editing {
                vec![
                    Span::styled("[", Style::default().fg(Color::Yellow)),
                    Span::styled(
                        display,
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
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
                    Span::styled(
                        value_str,
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
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
                    Span::styled(
                        display,
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("]", Style::default().fg(Color::Yellow)),
                ]
            } else {
                vec![
                    Span::styled("[", Style::default().fg(Color::DarkGray)),
                    Span::styled(display, Style::default().fg(Color::Magenta)),
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

fn render_comm_objects_view(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Content && app.current_tab == MainTab::CommObjects;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        })
        .title(format!(
            " Communication Objects ({}) ",
            app.com_object_rows.len()
        ));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.com_object_rows.is_empty() {
        let empty =
            Paragraph::new("No communication objects").style(Style::default().fg(Color::DarkGray));
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
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
    .bottom_margin(0);

    // Build table rows
    let rows: Vec<Row> = app
        .com_object_rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let is_selected = i == app.selected_obj_idx && focused;
            let style = if is_selected {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };

            let flag = |b: bool| if b { "●" } else { "○" };

            Row::new(vec![
                format!("{:3}", row.number),
                truncate_string(&row.name, 35),
                truncate_string(&row.function, 25),
                if row.group_address.is_empty() {
                    "—".to_string()
                } else {
                    row.group_address.clone()
                },
                row.size.clone(),
                truncate_string(&row.dpt, 14),
                row.priority.clone(),
                flag(row.flag_c).to_string(),
                flag(row.flag_r).to_string(),
                flag(row.flag_w).to_string(),
                flag(row.flag_t).to_string(),
                flag(row.flag_u).to_string(),
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
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    frame.render_widget(table, inner);
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}…", &s[..max_len - 1])
    } else {
        s.to_string()
    }
}

/// Maximum visible items in dropdown (must match App::DROPDOWN_VISIBLE_ITEMS)
const DROPDOWN_VISIBLE_ITEMS: usize = 12;

fn render_dropdown_popup(
    frame: &mut Frame,
    options: &[(i64, String)],
    selected_idx: usize,
    scroll_offset: usize,
) {
    let max_width = options.iter().map(|(_, t)| t.len()).max().unwrap_or(10) + 8;
    let visible_count = options.len().min(DROPDOWN_VISIBLE_ITEMS);
    let height = (visible_count + 2) as u16;
    let width = (max_width as u16).min(50);

    let area = frame.area();
    let popup_area = Rect {
        x: area.width.saturating_sub(width) / 2,
        y: area.height.saturating_sub(height) / 2,
        width,
        height,
    };

    // Clear background
    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Black)),
        popup_area,
    );

    // Show scroll indicators in title
    let has_more_above = scroll_offset > 0;
    let has_more_below = scroll_offset + visible_count < options.len();
    let title = match (has_more_above, has_more_below) {
        (true, true) => " ▲ Select Value ▼ ",
        (true, false) => " ▲ Select Value ",
        (false, true) => " Select Value ▼ ",
        (false, false) => " Select Value ",
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(title);

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Only show items within the visible window
    let visible_options = options
        .iter()
        .enumerate()
        .skip(scroll_offset)
        .take(visible_count);

    let items: Vec<ListItem> = visible_options
        .map(|(i, (_, text))| {
            let is_selected = i == selected_idx;
            let style = if is_selected {
                Style::default()
                    .bg(Color::Yellow)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let prefix = if is_selected { "● " } else { "  " };
            ListItem::new(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(text.clone(), style),
            ]))
        })
        .collect();

    let list = List::new(items);
    frame.render_widget(list, inner);
}

fn render_status(frame: &mut Frame, area: Rect, app: &App) {
    let visible_params = app.model.visible_parameter_refs().count();
    let visible_objs = app.model.visible_com_object_refs().count();

    let help = match (&app.edit_mode, app.current_tab, app.focus) {
        (EditMode::EnumDropdown { .. }, _, _) => "↑/↓: Select | Enter: Confirm | Esc: Cancel",
        (EditMode::NumberInput { .. }, _, _) => "Type number | Enter: Confirm | Esc: Cancel",
        (EditMode::TextInput { .. }, _, _) => "Type text | Enter: Confirm | Esc: Cancel",
        (EditMode::None, _, Focus::Tabs) => "←/→: Switch tab | Tab/Enter: Focus content | q: Quit",
        (EditMode::None, MainTab::Parameters, Focus::Sidebar) => {
            "↑/↓: Navigate | Enter: Expand | Tab: Content | q: Quit"
        }
        (EditMode::None, MainTab::Parameters, Focus::Content) => {
            "↑/↓: Navigate | Enter: Edit | Tab: Tabs | q: Quit"
        }
        (EditMode::None, MainTab::CommObjects, Focus::Content) => {
            "↑/↓: Navigate | Tab: Tabs | q: Quit"
        }
        (EditMode::None, MainTab::CommObjects, Focus::Sidebar) => {
            // Shouldn't happen
            "Tab: Switch focus | q: Quit"
        }
    };

    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" Params: {} | Objects: {} ", visible_params, visible_objs),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
        Span::styled(help, Style::default().fg(Color::Cyan)),
    ]));

    frame.render_widget(status, area);
}
