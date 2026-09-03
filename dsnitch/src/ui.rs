use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, HighlightSpacing, List, ListItem, ListState, Paragraph, Row, Table, TableState},
    Frame,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionStatus {
    Active,
    Closed,
}

#[derive(Clone, Debug)]
pub struct ConnectionItem {
    pub key: String,
    pub skaddr: u64,
    pub time_str: String,
    pub container_name: String,
    pub service: String,
    pub image: String,
    pub proto: String,
    pub destination: String,
    pub dst_ip_str: String,
    pub is_docker: bool,
    pub cgroup_id: u64,
    pub status: ConnectionStatus,
    pub closed_at: Option<Instant>,
    pub last_seen: Instant,
}

#[derive(Clone, Debug)]
pub struct ContainerItem {
    pub cgroup_id: u64,
    pub name: String,
    pub service: String,
    pub image: String,
    pub conn_count: u64,
    pub is_active: bool,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum FocusedPane {
    Containers,
    Connections,
}

pub struct App {
    pub connections: VecDeque<ConnectionItem>,
    pub max_connections: usize,
    pub containers: HashMap<u64, ContainerItem>,
    pub sorted_containers: Vec<ContainerItem>,
    pub container_list_state: ListState,
    pub table_state: TableState,
    pub selected_cgroup_filter: Option<u64>,
    pub search_query: String,
    pub is_searching: bool,
    pub focused_pane: FocusedPane,
    pub show_host: bool,
    pub grace_period: Duration,
    pub total_conns: u64,
    pub running: bool,
}

impl App {
    pub fn new(show_host: bool, grace_period_secs: u64) -> Self {
        let mut app = Self {
            connections: VecDeque::with_capacity(1000),
            max_connections: 1000,
            containers: HashMap::new(),
            sorted_containers: Vec::new(),
            container_list_state: ListState::default(),
            table_state: TableState::default(),
            selected_cgroup_filter: None,
            search_query: String::new(),
            is_searching: false,
            focused_pane: FocusedPane::Connections,
            show_host,
            grace_period: Duration::from_secs(grace_period_secs),
            total_conns: 0,
            running: true,
        };
        app.container_list_state.select(Some(0));
        app
    }

    pub fn add_connection(&mut self, mut item: ConnectionItem) {
        self.total_conns += 1;

        if let Some(c) = self.containers.get_mut(&item.cgroup_id) {
            c.conn_count += 1;
        }

        item.last_seen = Instant::now();
        item.status = ConnectionStatus::Active;
        item.closed_at = None;

        // Check if an existing socket connection exists to update it
        if let Some(existing) = self.connections.iter_mut().find(|c| c.key == item.key) {
            existing.status = ConnectionStatus::Active;
            existing.closed_at = None;
            existing.last_seen = Instant::now();
            existing.time_str = item.time_str;
            existing.destination = item.destination;
            existing.dst_ip_str = item.dst_ip_str;
        } else {
            if self.connections.len() >= self.max_connections {
                self.connections.pop_front();
            }
            self.connections.push_back(item);
        }

        self.rebuild_sorted_containers();
    }

    pub fn close_connection(&mut self, skaddr: u64, dst_ip_str: &str) {
        let now = Instant::now();
        for item in self.connections.iter_mut() {
            let matched = if skaddr != 0 && item.skaddr != 0 {
                item.skaddr == skaddr
            } else {
                item.dst_ip_str == dst_ip_str
            };

            if matched {
                if item.status == ConnectionStatus::Active {
                    item.status = ConnectionStatus::Closed;
                    item.closed_at = Some(now);
                }
            }
        }
    }

    /// Prune connections whose closed grace period has expired
    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        let grace = self.grace_period;

        // Auto-close connectionless (UDP/ICMP) sockets after 3 seconds of inactivity
        for item in self.connections.iter_mut() {
            if item.status == ConnectionStatus::Active && (item.proto == "UDP" || item.proto == "ICMP" || item.proto == "ICMPv6") {
                if item.last_seen.elapsed() > Duration::from_secs(3) {
                    item.status = ConnectionStatus::Closed;
                    item.closed_at = Some(now);
                }
            }
        }

        self.connections.retain(|item| match (item.status, item.closed_at) {
            (ConnectionStatus::Closed, Some(closed_time)) => closed_time.elapsed() <= grace,
            _ => true,
        });
    }

    pub fn update_container(&mut self, cgroup_id: u64, name: String, service: String, image: String) {
        self.containers
            .entry(cgroup_id)
            .and_modify(|c| {
                c.name = name.clone();
                c.service = service.clone();
                c.image = image.clone();
                c.is_active = true;
            })
            .or_insert(ContainerItem {
                cgroup_id,
                name,
                service,
                image,
                conn_count: 0,
                is_active: true,
            });
        self.rebuild_sorted_containers();
    }

    fn rebuild_sorted_containers(&mut self) {
        let mut list: Vec<ContainerItem> = self.containers.values().cloned().collect();
        list.sort_by(|a, b| {
            b.is_active
                .cmp(&a.is_active)
                .then_with(|| b.conn_count.cmp(&a.conn_count))
                .then_with(|| a.name.cmp(&b.name))
        });
        self.sorted_containers = list;
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if self.is_searching {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.is_searching = false;
                }
                KeyCode::Backspace => {
                    self.search_query.pop();
                }
                KeyCode::Char(c) => {
                    self.search_query.push(c);
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') => {
                self.running = false;
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.running = false;
            }
            KeyCode::Char('/') => {
                self.is_searching = true;
            }
            KeyCode::Char('a') => {
                self.show_host = !self.show_host;
            }
            KeyCode::Char('c') => {
                self.connections.clear();
            }
            KeyCode::Tab => {
                self.focused_pane = match self.focused_pane {
                    FocusedPane::Containers => FocusedPane::Connections,
                    FocusedPane::Connections => FocusedPane::Containers,
                };
            }
            KeyCode::Left => {
                self.focused_pane = FocusedPane::Containers;
            }
            KeyCode::Right => {
                self.focused_pane = FocusedPane::Connections;
            }
            KeyCode::Up | KeyCode::Char('k') => match self.focused_pane {
                FocusedPane::Containers => {
                    if !self.sorted_containers.is_empty() {
                        let i = match self.container_list_state.selected() {
                            Some(0) | None => 0,
                            Some(i) => i.saturating_sub(1),
                        };
                        self.container_list_state.select(Some(i));
                    }
                }
                FocusedPane::Connections => {
                    let i = match self.table_state.selected() {
                        Some(0) | None => 0,
                        Some(i) => i.saturating_sub(1),
                    };
                    self.table_state.select(Some(i));
                }
            },
            KeyCode::Down | KeyCode::Char('j') => match self.focused_pane {
                FocusedPane::Containers => {
                    if !self.sorted_containers.is_empty() {
                        let max_idx = self.sorted_containers.len().saturating_sub(1);
                        let i = match self.container_list_state.selected() {
                            Some(i) => (i + 1).min(max_idx),
                            None => 0,
                        };
                        self.container_list_state.select(Some(i));
                    }
                }
                FocusedPane::Connections => {
                    let total = self.filtered_connections().count();
                    if total > 0 {
                        let max_idx = total.saturating_sub(1);
                        let i = match self.table_state.selected() {
                            Some(i) => (i + 1).min(max_idx),
                            None => 0,
                        };
                        self.table_state.select(Some(i));
                    }
                }
            },
            KeyCode::Enter => {
                if self.focused_pane == FocusedPane::Containers {
                    if let Some(selected_idx) = self.container_list_state.selected() {
                        if let Some(target) = self.sorted_containers.get(selected_idx) {
                            if self.selected_cgroup_filter == Some(target.cgroup_id) {
                                self.selected_cgroup_filter = None;
                            } else {
                                self.selected_cgroup_filter = Some(target.cgroup_id);
                            }
                        }
                    }
                }
            }
            KeyCode::Esc => {
                self.selected_cgroup_filter = None;
                self.search_query.clear();
            }
            _ => {}
        }
    }

    pub fn filtered_connections(&self) -> impl Iterator<Item = &ConnectionItem> {
        let q = self.search_query.to_lowercase();
        let selected_cg = self.selected_cgroup_filter;
        let show_host = self.show_host;

        self.connections.iter().rev().filter(move |item| {
            if !show_host && !item.is_docker {
                return false;
            }
            if let Some(cg) = selected_cg {
                if item.cgroup_id != cg {
                    return false;
                }
            }
            if !q.is_empty() {
                let match_name = item.container_name.to_lowercase().contains(&q);
                let match_svc = item.service.to_lowercase().contains(&q);
                let match_dest = item.destination.to_lowercase().contains(&q);
                let match_ip = item.dst_ip_str.to_lowercase().contains(&q);
                let match_proto = item.proto.to_lowercase().contains(&q);
                let match_img = item.image.to_lowercase().contains(&q);
                if !match_name && !match_svc && !match_dest && !match_ip && !match_proto && !match_img {
                    return false;
                }
            }
            true
        })
    }
}

pub fn render_ui(frame: &mut Frame, app: &mut App) {
    app.prune_expired();
    let size = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header banner
            Constraint::Min(8),    // Split Body (Containers + Live Table)
            Constraint::Length(3), // Status & Help bar
        ])
        .split(size);

    render_header(frame, app, chunks[0]);
    render_body(frame, app, chunks[1]);
    render_footer(frame, app, chunks[2]);
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let active_count = app.containers.values().filter(|c| c.is_active).count();
    let total_count = app.containers.len();
    let active_conns = app.connections.iter().filter(|c| c.status == ConnectionStatus::Active).count();

    let title_line = Line::from(vec![
        Span::styled(" 🕵️ dsnitch ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled("Docker Network & DNS Egress Inspector", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(" │ "),
        Span::styled(format!("Active Containers: {}", active_count), Style::default().fg(Color::Green)),
        Span::raw(" (Total: "),
        Span::styled(format!("{}", total_count), Style::default().fg(Color::Yellow)),
        Span::raw(") │ Active Sockets: "),
        Span::styled(format!("{}", active_conns), Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
        Span::raw(" │ Total Events: "),
        Span::styled(format!("{}", app.total_conns), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Reset));

    let paragraph = Paragraph::new(title_line).block(block);
    frame.render_widget(paragraph, area);
}

fn render_body(frame: &mut Frame, app: &mut App, area: Rect) {
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(30), // Left Pane: Containers
            Constraint::Percentage(70), // Right Pane: Live Egress Connections
        ])
        .split(area);

    render_containers_pane(frame, app, body_chunks[0]);
    render_connections_pane(frame, app, body_chunks[1]);
}

fn render_containers_pane(frame: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.focused_pane == FocusedPane::Containers;
    let border_color = if is_focused { Color::Cyan } else { Color::DarkGray };

    let items: Vec<ListItem> = app
        .sorted_containers
        .iter()
        .map(|c| {
            let is_selected_filter = app.selected_cgroup_filter == Some(c.cgroup_id);
            let status_dot = if c.is_active {
                Span::styled("● ", Style::default().fg(Color::Green))
            } else {
                Span::styled("○ ", Style::default().fg(Color::DarkGray))
            };

            let name_style = if is_selected_filter {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else if c.is_active {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            let svc_text = if c.service != "-" && !c.service.is_empty() {
                format!(" ({})", c.service)
            } else {
                String::new()
            };

            let line = Line::from(vec![
                status_dot,
                Span::styled(&c.name, name_style),
                Span::styled(svc_text, Style::default().fg(Color::Cyan)),
                Span::raw(" "),
                Span::styled(format!("[{} conns]", c.conn_count), Style::default().fg(Color::DarkGray)),
            ]);

            ListItem::new(line)
        })
        .collect();

    let filter_notice = if app.selected_cgroup_filter.is_some() {
        " (FILTER ACTIVE - [Enter] clear)"
    } else {
        ""
    };

    let title = format!(" Containers ({}){} ", app.sorted_containers.len(), filter_notice);

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color))
                .title(Span::styled(title, Style::default().add_modifier(Modifier::BOLD))),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(30, 45, 60))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_spacing(HighlightSpacing::Always);

    frame.render_stateful_widget(list, area, &mut app.container_list_state);
}

fn render_connections_pane(frame: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.focused_pane == FocusedPane::Connections;
    let border_color = if is_focused { Color::Cyan } else { Color::DarkGray };

    let header_cells = ["STATUS", "TIME", "CONTAINER", "SERVICE", "IMAGE/PROCESS", "PROTO", "DESTINATION", "DST IP"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows: Vec<Row> = app
        .filtered_connections()
        .take(150)
        .map(|item| {
            let status_cell = match item.status {
                ConnectionStatus::Active => Cell::from("● ACTIVE").style(Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                ConnectionStatus::Closed => Cell::from("○ CLOSED").style(Style::default().fg(Color::DarkGray)),
            };

            let container_cell = if item.is_docker {
                Cell::from(item.container_name.clone()).style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            } else {
                Cell::from("[HOST]").style(Style::default().fg(Color::DarkGray))
            };

            let service_cell = Cell::from(item.service.clone()).style(Style::default().fg(Color::LightCyan));
            let img_cell = Cell::from(item.image.clone()).style(Style::default().fg(Color::White));

            let proto_cell = match item.proto.as_str() {
                "TCP" => Cell::from("TCP").style(Style::default().fg(Color::LightGreen)),
                "UDP" => Cell::from("UDP").style(Style::default().fg(Color::LightBlue)),
                "ICMP" | "ICMPv6" => Cell::from(item.proto.clone()).style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
                _ => Cell::from(item.proto.clone()).style(Style::default().fg(Color::DarkGray)),
            };

            let is_resolved = !item.destination.chars().next().unwrap_or(' ').is_numeric() && !item.destination.starts_with('[');
            let dest_style = if is_resolved {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            let dest_cell = Cell::from(item.destination.clone()).style(dest_style);
            let ip_cell = Cell::from(item.dst_ip_str.clone()).style(Style::default().fg(Color::White));

            let time_cell = Cell::from(item.time_str.clone()).style(Style::default().fg(Color::DarkGray));

            Row::new(vec![status_cell, time_cell, container_cell, service_cell, img_cell, proto_cell, dest_cell, ip_cell])
        })
        .collect();

    let filter_desc = if !app.search_query.is_empty() {
        format!(" (Filtered: \"{}\")", app.search_query)
    } else {
        String::new()
    };

    let title = format!(" Live Egress Feed ({} shown, {}s grace){} ", rows.len(), app.grace_period.as_secs(), filter_desc);

    let table = Table::new(
        rows,
        [
            Constraint::Length(10), // STATUS
            Constraint::Length(11), // TIME
            Constraint::Length(18), // CONTAINER
            Constraint::Length(12), // SERVICE
            Constraint::Length(15), // IMAGE/PROCESS
            Constraint::Length(7),  // PROTO
            Constraint::Length(28), // DESTINATION
            Constraint::Min(20),    // DST IP
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(Span::styled(title, Style::default().add_modifier(Modifier::BOLD))),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::Rgb(30, 45, 60))
            .add_modifier(Modifier::BOLD),
    );

    frame.render_stateful_widget(table, area, &mut app.table_state);
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    if app.is_searching {
        let search_text = format!(" Search Filter: {}█ (Press [Enter] or [Esc] to commit)", app.search_query);
        let paragraph = Paragraph::new(search_text)
            .style(Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(paragraph, area);
        return;
    }

    let host_mode = if app.show_host { "ON" } else { "OFF" };

    let footer_line = Line::from(vec![
        Span::styled(" [q]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Quit  "),
        Span::styled("[/]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Filter  "),
        Span::styled("[Tab/←/→]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Switch Pane  "),
        Span::styled("[↑/↓/j/k]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Navigate  "),
        Span::styled("[Enter]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Filter to Container  "),
        Span::styled("[a]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(format!(" Host View ({})  ", host_mode)),
        Span::styled("[c]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Clear  "),
    ]);

    let block = Block::default().borders(Borders::ALL).style(Style::default().bg(Color::Reset));
    let paragraph = Paragraph::new(footer_line).block(block);
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_connection(key: &str, skaddr: u64, cgroup_id: u64, proto: &str) -> ConnectionItem {
        ConnectionItem {
            key: key.to_string(),
            skaddr,
            time_str: "1.000s".to_string(),
            container_name: "test-container".to_string(),
            service: "web".to_string(),
            image: "alpine".to_string(),
            proto: proto.to_string(),
            destination: "example.com:80".to_string(),
            dst_ip_str: "93.184.216.34:80".to_string(),
            is_docker: true,
            cgroup_id,
            status: ConnectionStatus::Active,
            closed_at: None,
            last_seen: Instant::now(),
        }
    }

    #[test]
    fn test_app_add_and_close_by_skaddr() {
        let mut app = App::new(false, 5);
        let skaddr = 0xffff8801_12345678;

        let conn = make_test_connection("conn-1", skaddr, 100, "TCP");
        app.add_connection(conn);

        assert_eq!(app.connections.len(), 1);
        assert_eq!(app.connections[0].status, ConnectionStatus::Active);
        assert!(app.connections[0].closed_at.is_none());

        // Close using matching skaddr
        app.close_connection(skaddr, "93.184.216.34:80");

        assert_eq!(app.connections[0].status, ConnectionStatus::Closed);
        assert!(app.connections[0].closed_at.is_some());
    }

    #[test]
    fn test_app_udp_inactivity_auto_close() {
        let mut app = App::new(false, 5);
        let mut conn = make_test_connection("conn-udp", 0, 100, "UDP");
        // Simulate 4 seconds of silence
        conn.last_seen = Instant::now() - Duration::from_secs(4);
        app.add_connection(conn);
        // add_connection resets last_seen to now(), manually adjust it for test
        app.connections[0].last_seen = Instant::now() - Duration::from_secs(4);

        assert_eq!(app.connections[0].status, ConnectionStatus::Active);

        // Pruning cycle should auto-close UDP after 3s inactivity
        app.prune_expired();

        assert_eq!(app.connections[0].status, ConnectionStatus::Closed);
        assert!(app.connections[0].closed_at.is_some());
    }

    #[test]
    fn test_app_prune_expired_grace_period() {
        let mut app = App::new(false, 2); // 2 second grace period
        let conn = make_test_connection("conn-closed", 0, 100, "TCP");
        app.add_connection(conn);

        // Mark as closed 5 seconds ago (past the 2s grace period)
        app.connections[0].status = ConnectionStatus::Closed;
        app.connections[0].closed_at = Some(Instant::now() - Duration::from_secs(5));

        app.prune_expired();

        // Connection should be pruned
        assert!(app.connections.is_empty());
    }

    #[test]
    fn test_app_max_connections_deque_limit() {
        let mut app = App::new(false, 5);
        app.max_connections = 5;

        for i in 0..10 {
            let key = format!("conn-{}", i);
            app.add_connection(make_test_connection(&key, i, 100, "TCP"));
        }

        assert_eq!(app.connections.len(), 5);
        // Newest connection should be at the back
        assert_eq!(app.connections.back().unwrap().key, "conn-9");
    }

    #[test]
    fn test_app_container_locking() {
        let mut app = App::new(false, 5);
        app.update_container(101, "auth-service".to_string(), "auth".to_string(), "alpine".to_string());
        app.update_container(102, "web-service".to_string(), "web".to_string(), "nginx".to_string());

        assert_eq!(app.sorted_containers.len(), 2);

        // Lock to first container
        app.selected_cgroup_filter = Some(101);
        assert_eq!(app.selected_cgroup_filter, Some(101));

        // Unlock
        app.selected_cgroup_filter = None;
        assert_eq!(app.selected_cgroup_filter, None);
    }
}
