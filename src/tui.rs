#[cfg(feature = "tui")]
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
#[cfg(feature = "tui")]
use ratatui::{prelude::*, widgets::*};
#[cfg(feature = "tui")]
use std::io;

#[cfg(feature = "tui")]
use crate::subnet_generator::{count_subnets, generate_ipv4_subnets, generate_ipv6_subnets};

#[cfg(feature = "tui")]
#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    Calculate,
    Split,
}

#[cfg(feature = "tui")]
#[derive(Debug, Clone, Copy, PartialEq)]
enum InputField {
    Cidr,
    Prefix,
    Count,
}

#[cfg(feature = "tui")]
struct AppState {
    mode: Mode,
    active_field: InputField,
    cidr_input: String,
    prefix_input: String,
    count_input: String,
    use_max: bool,
    count_only: bool,
    scroll_offset: usize,
    error_message: Option<String>,
}

#[cfg(feature = "tui")]
impl AppState {
    fn new() -> Self {
        Self {
            mode: Mode::Calculate,
            active_field: InputField::Cidr,
            cidr_input: String::from("192.168.1.0/24"),
            prefix_input: String::from(""),
            count_input: String::from(""),
            use_max: false,
            count_only: false,
            scroll_offset: 0,
            error_message: None,
        }
    }

    fn toggle_mode(&mut self) {
        self.mode = match self.mode {
            Mode::Calculate => {
                self.active_field = InputField::Cidr;
                Mode::Split
            }
            Mode::Split => {
                self.active_field = InputField::Cidr;
                Mode::Calculate
            }
        };
        self.scroll_offset = 0;
        self.error_message = None;
        self.count_only = false;
    }

    fn next_field(&mut self) {
        if self.mode == Mode::Split {
            self.active_field = match self.active_field {
                InputField::Cidr => InputField::Prefix,
                InputField::Prefix => InputField::Count,
                InputField::Count => InputField::Cidr,
            };
        }
    }

    fn handle_char_input(&mut self, c: char) {
        match self.active_field {
            InputField::Cidr => self.cidr_input.push(c),
            InputField::Prefix => {
                if c.is_ascii_digit() {
                    self.prefix_input.push(c);
                }
            }
            InputField::Count => {
                if c.is_ascii_digit() {
                    self.count_input.push(c);
                    self.use_max = false;
                }
            }
        }
        self.error_message = None;
    }

    fn handle_backspace(&mut self) {
        match self.active_field {
            InputField::Cidr => {
                self.cidr_input.pop();
            }
            InputField::Prefix => {
                self.prefix_input.pop();
            }
            InputField::Count => {
                self.count_input.pop();
            }
        }
        self.error_message = None;
    }

    fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
        }
    }

    fn scroll_down(&mut self, max_items: usize, visible_height: usize) {
        if self.scroll_offset + visible_height < max_items {
            self.scroll_offset += 1;
        }
    }

    fn toggle_max(&mut self) {
        if self.mode == Mode::Split && self.active_field == InputField::Count {
            self.use_max = !self.use_max;
            if self.use_max {
                self.count_input.clear();
                self.count_only = false;
            }
        }
    }

    fn toggle_count_only(&mut self) {
        if self.mode == Mode::Split && self.active_field == InputField::Count {
            self.count_only = !self.count_only;
            if self.count_only {
                self.count_input.clear();
                self.use_max = false;
            }
        }
    }
}

#[cfg(feature = "tui")]
pub fn run_tui() -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // App state
    let mut app = AppState::new();

    loop {
        terminal.draw(|f| ui(f, &app))?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Esc => break,
                KeyCode::Tab => app.toggle_mode(),
                KeyCode::Enter => app.next_field(),
                KeyCode::Char('m') | KeyCode::Char('M')
                    if app.mode == Mode::Split && app.active_field == InputField::Count =>
                {
                    app.toggle_max()
                }
                KeyCode::Char('c') | KeyCode::Char('C')
                    if app.mode == Mode::Split && app.active_field == InputField::Count =>
                {
                    app.toggle_count_only()
                }
                KeyCode::Char(c) => app.handle_char_input(c),
                KeyCode::Backspace => app.handle_backspace(),
                KeyCode::Up => app.scroll_up(),
                KeyCode::Down => {
                    // We'll calculate max_items in the UI, but for now use a placeholder
                    app.scroll_down(1000, 10);
                }
                _ => {}
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

#[cfg(feature = "tui")]
fn ui(f: &mut Frame, app: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Mode indicator
            Constraint::Length(5), // Input fields
            Constraint::Min(10),   // Results
            Constraint::Length(3), // Help
        ])
        .split(f.area());

    // Mode indicator
    let mode_text = match app.mode {
        Mode::Calculate => " MODE: Calculate (press TAB to switch to Split) ",
        Mode::Split => " MODE: Split (press TAB to switch to Calculate) ",
    };
    let mode_widget =
        Paragraph::new(mode_text).style(Style::default().bg(Color::Blue).fg(Color::White).bold());
    f.render_widget(mode_widget, chunks[0]);

    // Input fields
    match app.mode {
        Mode::Calculate => render_calculate_inputs(f, app, chunks[1]),
        Mode::Split => render_split_inputs(f, app, chunks[1]),
    }

    // Results
    match app.mode {
        Mode::Calculate => render_calculate_results(f, app, chunks[2]),
        Mode::Split => render_split_results(f, app, chunks[2]),
    }

    // Help bar
    let help_text = match app.mode {
        Mode::Calculate => " ESC: Quit | TAB: Switch Mode | Type to edit CIDR ",
        Mode::Split => {
            " ESC: Quit | TAB: Switch Mode | ENTER: Next Field | M: Max | C: Count Only | ↑↓: Scroll "
        }
    };
    let help = Paragraph::new(help_text).block(Block::default().borders(Borders::ALL));
    f.render_widget(help, chunks[3]);
}

#[cfg(feature = "tui")]
fn render_calculate_inputs(f: &mut Frame, app: &AppState, area: Rect) {
    let input_style = Style::default().fg(Color::Yellow);
    let input_text = format!(" {} ", app.cidr_input);
    let input_panel = Paragraph::new(input_text).style(input_style).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Enter CIDR (e.g. 192.168.1.0/24) "),
    );
    f.render_widget(input_panel, area);
}

#[cfg(feature = "tui")]
fn render_split_inputs(f: &mut Frame, app: &AppState, area: Rect) {
    let input_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ])
        .split(area);

    // CIDR input
    let cidr_style = if app.active_field == InputField::Cidr {
        Style::default().fg(Color::Yellow).bold()
    } else {
        Style::default()
    };
    let cidr_panel = Paragraph::new(format!(" {} ", app.cidr_input))
        .style(cidr_style)
        .block(Block::default().borders(Borders::ALL).title(" CIDR "));
    f.render_widget(cidr_panel, input_chunks[0]);

    // Prefix input
    let prefix_style = if app.active_field == InputField::Prefix {
        Style::default().fg(Color::Yellow).bold()
    } else {
        Style::default()
    };
    let prefix_panel = Paragraph::new(format!(" {} ", app.prefix_input))
        .style(prefix_style)
        .block(Block::default().borders(Borders::ALL).title(" New Prefix "));
    f.render_widget(prefix_panel, input_chunks[1]);

    // Count input
    let count_style = if app.active_field == InputField::Count {
        Style::default().fg(Color::Yellow).bold()
    } else {
        Style::default()
    };
    let count_text = if app.count_only {
        " COUNT ONLY ".to_string()
    } else if app.use_max {
        " MAX ".to_string()
    } else if app.count_input.is_empty() {
        " ".to_string()
    } else {
        format!(" {} ", app.count_input)
    };
    let count_panel = Paragraph::new(count_text).style(count_style).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Count (M: Max, C: Count Only) "),
    );
    f.render_widget(count_panel, input_chunks[2]);
}

#[cfg(feature = "tui")]
fn render_calculate_results(f: &mut Frame, app: &AppState, area: Rect) {
    let display_text = if let Some(ref err) = app.error_message {
        format!("Error: {}", err)
    } else if let Ok(net) = app.cidr_input.parse::<ipnet::IpNet>() {
        format!(
            "Network:    {}\nNetmask:    {}\nBroadcast:  {}\nFirst Host: {}\nLast Host:  {}\nTotal Hosts: {}",
            net.network(),
            net.netmask(),
            net.broadcast(),
            net.hosts().next().unwrap_or(net.network()),
            net.hosts().last().unwrap_or(net.network()),
            net.hosts().count()
        )
    } else {
        "Enter a valid CIDR notation".to_string()
    };

    let results = Paragraph::new(display_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Calculations "),
        )
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(results, area);
}

#[cfg(feature = "tui")]
fn render_split_results(f: &mut Frame, app: &AppState, area: Rect) {
    if app.cidr_input.is_empty() || app.prefix_input.is_empty() {
        let help_text = "Enter CIDR and new prefix length to generate subnets";
        let results = Paragraph::new(help_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Split Results "),
            )
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(results, area);
        return;
    }

    if app.mode == Mode::Split && !app.use_max && !app.count_only && app.count_input.is_empty() {
        let help_text = "Enter count, press 'M' for max, or 'C' for count only";
        let results = Paragraph::new(help_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Split Results "),
            )
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(results, area);
        return;
    }

    // Parse inputs
    let prefix = match app.prefix_input.parse::<u8>() {
        Ok(p) => p,
        Err(_) => {
            let error_text = "Invalid prefix length";
            let results = Paragraph::new(error_text)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Split Results "),
                )
                .style(Style::default().fg(Color::Red));
            f.render_widget(results, area);
            return;
        }
    };

    // Count-only mode: just show the available subnet count
    if app.count_only {
        let result_text = match count_subnets(&app.cidr_input, prefix) {
            Ok(summary) => {
                format!(
                    "CidrBlock: {}\nNew Prefix: /{}\nAvailable Subnets: {}",
                    summary.cidr_block, summary.new_prefix, summary.available_subnets
                )
            }
            Err(e) => format!("Error: {}", e),
        };
        let results = Paragraph::new(result_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Split Results (Count Only) "),
            )
            .style(Style::default().fg(Color::Green));
        f.render_widget(results, area);
        return;
    }

    let count = if app.use_max {
        None
    } else {
        match app.count_input.parse::<u64>() {
            Ok(c) => Some(c),
            Err(_) => {
                let error_text = "Invalid count";
                let results = Paragraph::new(error_text)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Split Results "),
                    )
                    .style(Style::default().fg(Color::Red));
                f.render_widget(results, area);
                return;
            }
        }
    };

    // Detect IPv4 vs IPv6
    let is_ipv6 = app.cidr_input.contains(':');

    // Generate subnets
    let result_text = if is_ipv6 {
        match generate_ipv6_subnets(&app.cidr_input, prefix, count) {
            Ok(result) => {
                let mut lines = vec![
                    format!("CidrBlock: {}", result.cidr_block.network),
                    format!("New Prefix: /{}", result.new_prefix),
                    format!("Generated: {} subnets", result.requested_count),
                    String::from(""),
                    String::from("Subnets:"),
                ];

                let visible_height = area.height.saturating_sub(7) as usize; // Account for borders and header
                let start = app
                    .scroll_offset
                    .min(result.subnets.len().saturating_sub(1));
                let end = (start + visible_height).min(result.subnets.len());

                for (i, subnet) in result
                    .subnets
                    .iter()
                    .enumerate()
                    .skip(start)
                    .take(end - start)
                {
                    lines.push(format!(
                        "  {}: {}/{}",
                        i + 1,
                        subnet.network,
                        subnet.prefix_length
                    ));
                }

                if result.subnets.len() > visible_height {
                    lines.push(String::from(""));
                    lines.push(format!(
                        "Showing {}-{} of {} (use ↑↓ to scroll)",
                        start + 1,
                        end,
                        result.subnets.len()
                    ));
                }

                lines.join("\n")
            }
            Err(e) => format!("Error: {}", e),
        }
    } else {
        match generate_ipv4_subnets(&app.cidr_input, prefix, count) {
            Ok(result) => {
                let mut lines = vec![
                    format!("CidrBlock: {}", result.cidr_block.network),
                    format!("New Prefix: /{}", result.new_prefix),
                    format!("Generated: {} subnets", result.requested_count),
                    String::from(""),
                    String::from("Subnets:"),
                ];

                let visible_height = area.height.saturating_sub(7) as usize; // Account for borders and header
                let start = app
                    .scroll_offset
                    .min(result.subnets.len().saturating_sub(1));
                let end = (start + visible_height).min(result.subnets.len());

                for (i, subnet) in result
                    .subnets
                    .iter()
                    .enumerate()
                    .skip(start)
                    .take(end - start)
                {
                    lines.push(format!(
                        "  {}: {}/{}",
                        i + 1,
                        subnet.network,
                        subnet.prefix_length
                    ));
                }

                if result.subnets.len() > visible_height {
                    lines.push(String::from(""));
                    lines.push(format!(
                        "Showing {}-{} of {} (use ↑↓ to scroll)",
                        start + 1,
                        end,
                        result.subnets.len()
                    ));
                }

                lines.join("\n")
            }
            Err(e) => format!("Error: {}", e),
        }
    };

    let results = Paragraph::new(result_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Split Results "),
        )
        .style(Style::default().fg(Color::Green))
        .scroll((0, 0));
    f.render_widget(results, area);
}

#[cfg(all(test, feature = "tui"))]
mod tests {
    use super::*;

    // --- AppState::new() defaults ---

    #[test]
    fn new_defaults() {
        let app = AppState::new();
        assert_eq!(app.mode, Mode::Calculate);
        assert_eq!(app.active_field, InputField::Cidr);
        assert_eq!(app.cidr_input, "192.168.1.0/24");
        assert!(app.prefix_input.is_empty());
        assert!(app.count_input.is_empty());
        assert!(!app.use_max);
        assert!(!app.count_only);
        assert_eq!(app.scroll_offset, 0);
        assert!(app.error_message.is_none());
    }

    // --- toggle_mode ---

    #[test]
    fn toggle_mode_calculate_to_split() {
        let mut app = AppState::new();
        app.toggle_mode();
        assert_eq!(app.mode, Mode::Split);
        assert_eq!(app.active_field, InputField::Cidr);
    }

    #[test]
    fn toggle_mode_split_to_calculate() {
        let mut app = AppState::new();
        app.toggle_mode(); // Calculate -> Split
        app.toggle_mode(); // Split -> Calculate
        assert_eq!(app.mode, Mode::Calculate);
        assert_eq!(app.active_field, InputField::Cidr);
    }

    #[test]
    fn toggle_mode_resets_state() {
        let mut app = AppState::new();
        app.toggle_mode(); // Split
        app.active_field = InputField::Count;
        app.scroll_offset = 5;
        app.error_message = Some("err".into());
        app.count_only = true;

        app.toggle_mode(); // Calculate
        assert_eq!(app.active_field, InputField::Cidr);
        assert_eq!(app.scroll_offset, 0);
        assert!(app.error_message.is_none());
        assert!(!app.count_only);
    }

    // --- next_field ---

    #[test]
    fn next_field_cycles_in_split_mode() {
        let mut app = AppState::new();
        app.mode = Mode::Split;

        assert_eq!(app.active_field, InputField::Cidr);
        app.next_field();
        assert_eq!(app.active_field, InputField::Prefix);
        app.next_field();
        assert_eq!(app.active_field, InputField::Count);
        app.next_field();
        assert_eq!(app.active_field, InputField::Cidr);
    }

    #[test]
    fn next_field_noop_in_calculate_mode() {
        let mut app = AppState::new();
        assert_eq!(app.active_field, InputField::Cidr);
        app.next_field();
        assert_eq!(app.active_field, InputField::Cidr);
    }

    // --- handle_char_input ---

    #[test]
    fn char_input_cidr_accepts_any() {
        let mut app = AppState::new();
        app.cidr_input.clear();
        app.handle_char_input('a');
        app.handle_char_input('/');
        app.handle_char_input(':');
        assert_eq!(app.cidr_input, "a/:");
    }

    #[test]
    fn char_input_cidr_accepts_hex_chars() {
        // Regression: 'c'/'C' and 'm'/'M' must not be swallowed by shortcut
        // handlers when the CIDR field is active (needed for IPv6 input).
        let mut app = AppState::new();
        app.cidr_input.clear();
        for ch in [
            'a', 'b', 'c', 'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F', 'm', 'M',
        ] {
            app.handle_char_input(ch);
        }
        assert_eq!(app.cidr_input, "abcdefABCDEFmM");
    }

    #[test]
    fn char_input_prefix_only_digits() {
        let mut app = AppState::new();
        app.active_field = InputField::Prefix;
        app.handle_char_input('2');
        app.handle_char_input('a');
        app.handle_char_input('4');
        assert_eq!(app.prefix_input, "24");
    }

    #[test]
    fn char_input_count_only_digits() {
        let mut app = AppState::new();
        app.active_field = InputField::Count;
        app.handle_char_input('1');
        app.handle_char_input('x');
        app.handle_char_input('0');
        assert_eq!(app.count_input, "10");
    }

    #[test]
    fn char_input_count_clears_use_max() {
        let mut app = AppState::new();
        app.active_field = InputField::Count;
        app.use_max = true;
        app.handle_char_input('5');
        assert!(!app.use_max);
    }

    #[test]
    fn char_input_clears_error() {
        let mut app = AppState::new();
        app.error_message = Some("bad".into());
        app.handle_char_input('x');
        assert!(app.error_message.is_none());
    }

    // --- handle_backspace ---

    #[test]
    fn backspace_removes_last_char() {
        let mut app = AppState::new();
        app.cidr_input = "abc".into();
        app.handle_backspace();
        assert_eq!(app.cidr_input, "ab");
    }

    #[test]
    fn backspace_on_prefix_field() {
        let mut app = AppState::new();
        app.active_field = InputField::Prefix;
        app.prefix_input = "24".into();
        app.handle_backspace();
        assert_eq!(app.prefix_input, "2");
    }

    #[test]
    fn backspace_on_count_field() {
        let mut app = AppState::new();
        app.active_field = InputField::Count;
        app.count_input = "10".into();
        app.handle_backspace();
        assert_eq!(app.count_input, "1");
    }

    #[test]
    fn backspace_on_empty_is_noop() {
        let mut app = AppState::new();
        app.cidr_input.clear();
        app.handle_backspace();
        assert!(app.cidr_input.is_empty());
    }

    #[test]
    fn backspace_clears_error() {
        let mut app = AppState::new();
        app.error_message = Some("err".into());
        app.handle_backspace();
        assert!(app.error_message.is_none());
    }

    // --- scroll_up / scroll_down ---

    #[test]
    fn scroll_up_decrements() {
        let mut app = AppState::new();
        app.scroll_offset = 3;
        app.scroll_up();
        assert_eq!(app.scroll_offset, 2);
    }

    #[test]
    fn scroll_up_floors_at_zero() {
        let mut app = AppState::new();
        app.scroll_offset = 0;
        app.scroll_up();
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn scroll_down_increments() {
        let mut app = AppState::new();
        app.scroll_down(100, 10);
        assert_eq!(app.scroll_offset, 1);
    }

    #[test]
    fn scroll_down_bounded_by_max() {
        let mut app = AppState::new();
        app.scroll_offset = 5;
        // max_items=10, visible=5 -> max scroll_offset = 5
        app.scroll_down(10, 5);
        assert_eq!(app.scroll_offset, 5);
    }

    #[test]
    fn scroll_down_noop_when_content_fits() {
        let mut app = AppState::new();
        // visible_height >= max_items: no scrolling
        app.scroll_down(5, 10);
        assert_eq!(app.scroll_offset, 0);
    }

    // --- toggle_max ---

    #[test]
    fn toggle_max_in_split_count_field() {
        let mut app = AppState::new();
        app.mode = Mode::Split;
        app.active_field = InputField::Count;
        app.count_input = "5".into();
        app.count_only = true;

        app.toggle_max();
        assert!(app.use_max);
        assert!(app.count_input.is_empty());
        assert!(!app.count_only);
    }

    #[test]
    fn toggle_max_off() {
        let mut app = AppState::new();
        app.mode = Mode::Split;
        app.active_field = InputField::Count;
        app.use_max = true;

        app.toggle_max();
        assert!(!app.use_max);
    }

    #[test]
    fn toggle_max_noop_in_calculate_mode() {
        let mut app = AppState::new();
        app.active_field = InputField::Count;
        app.toggle_max();
        assert!(!app.use_max);
    }

    #[test]
    fn toggle_max_noop_on_cidr_field() {
        let mut app = AppState::new();
        app.mode = Mode::Split;
        app.active_field = InputField::Cidr;
        app.toggle_max();
        assert!(!app.use_max);
    }

    // --- toggle_count_only ---

    #[test]
    fn toggle_count_only_in_split_count_field() {
        let mut app = AppState::new();
        app.mode = Mode::Split;
        app.active_field = InputField::Count;
        app.count_input = "5".into();
        app.use_max = true;

        app.toggle_count_only();
        assert!(app.count_only);
        assert!(app.count_input.is_empty());
        assert!(!app.use_max);
    }

    #[test]
    fn toggle_count_only_off() {
        let mut app = AppState::new();
        app.mode = Mode::Split;
        app.active_field = InputField::Count;
        app.count_only = true;

        app.toggle_count_only();
        assert!(!app.count_only);
    }

    #[test]
    fn toggle_count_only_noop_in_calculate_mode() {
        let mut app = AppState::new();
        app.active_field = InputField::Count;
        app.toggle_count_only();
        assert!(!app.count_only);
    }

    #[test]
    fn toggle_count_only_noop_on_prefix_field() {
        let mut app = AppState::new();
        app.mode = Mode::Split;
        app.active_field = InputField::Prefix;
        app.toggle_count_only();
        assert!(!app.count_only);
    }
}
