use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use hostname::get;
use rand::{distributions::Alphanumeric, Rng};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::{self, stdout, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, RwLock},
};

const DISCOVERY_PORT: u16 = 45454;
const CHAT_PORT: u16 = 45455;
const MAGIC: &str = "LAN_TERM_CHAT_V2";

#[derive(Clone, Debug)]
struct Peer {
    id: String,
    name: String,
    addr: SocketAddr,
    last_seen: u64,
}

#[derive(Clone, Debug)]
struct Message {
    from: String,
    text: String,
    incoming: bool,
    time: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum Packet {
    Hello { id: String, name: String, port: u16 },
    Chat { from: String, text: String, timestamp: u64 },
}

#[derive(Debug)]
enum AppEvent {
    Incoming { from: String, text: String },
}

type Peers = Arc<RwLock<HashMap<String, Peer>>>;

#[tokio::main]
async fn main() -> Result<()> {
    let name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| get().ok().and_then(|x| x.into_string().ok()).unwrap_or_else(|| "user".into()));

    let id: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

    let peers: Peers = Arc::new(RwLock::new(HashMap::new()));
    let udp = Arc::new(UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT)).await?);
    udp.set_broadcast(true)?;
    let tcp = TcpListener::bind(("0.0.0.0", CHAT_PORT))
        .await
        .context("TCP port 45455 is unavailable")?;

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<AppEvent>();

    // Discovery receiver.
    {
        let peers = peers.clone();
        let udp = udp.clone();
        let my_id = id.clone();
        let my_name = name.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((n, src)) = udp.recv_from(&mut buf).await else { continue };
                let Ok(s) = std::str::from_utf8(&buf[..n]) else { continue };
                if !s.starts_with(MAGIC) { continue };
                let Ok(Packet::Hello { id, name, port }) =
                    serde_json::from_str(s.trim_start_matches(MAGIC)) else { continue };
                if id == my_id { continue; }

                peers.write().await.insert(id.clone(), Peer {
                    id,
                    name,
                    addr: SocketAddr::new(src.ip(), port),
                    last_seen: now(),
                });

                let reply = Packet::Hello {
                    id: my_id.clone(),
                    name: my_name.clone(),
                    port: CHAT_PORT,
                };
                if let Ok(bytes) = serde_json::to_vec(&reply) {
                    let msg = format!("{MAGIC}{}", String::from_utf8_lossy(&bytes));
                    let _ = udp.send_to(msg.as_bytes(), SocketAddr::new(src.ip(), DISCOVERY_PORT)).await;
                }
            }
        });
    }

    // Discovery broadcast.
    {
        let udp = udp.clone();
        let peers = peers.clone();
        let my_id = id.clone();
        let my_name = name.clone();

        tokio::spawn(async move {
            loop {
                let packet = Packet::Hello {
                    id: my_id.clone(),
                    name: my_name.clone(),
                    port: CHAT_PORT,
                };
                if let Ok(bytes) = serde_json::to_vec(&packet) {
                    let msg = format!("{MAGIC}{}", String::from_utf8_lossy(&bytes));
                    let _ = udp.send_to(
                        msg.as_bytes(),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DISCOVERY_PORT),
                    ).await;
                }

                let cutoff = now().saturating_sub(15);
                peers.write().await.retain(|_, p| p.last_seen >= cutoff);
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    }

    // TCP server.
    {
        let tx = event_tx.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = tcp.accept().await else { continue };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                        if let Ok(Packet::Chat { from, text, .. }) =
                            serde_json::from_str::<Packet>(line.trim())
                        {
                            let _ = tx.send(AppEvent::Incoming { from, text });
                        }
                        line.clear();
                    }
                });
            }
        });
    }

    let mut terminal = setup_terminal()?;
    let result = run_ui(
        &mut terminal,
        &name,
        &id,
        peers,
        &mut event_rx,
    ).await;
    restore_terminal(&mut terminal)?;
    result
}

async fn run_ui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    name: &str,
    my_id: &str,
    peers: Peers,
    event_rx: &mut mpsc::UnboundedReceiver<AppEvent>,
) -> Result<()> {
    let mut selected: usize = 0;
    let mut input = String::new();
    let mut messages: HashMap<String, Vec<Message>> = HashMap::new();
    let mut known_names: HashMap<String, String> = HashMap::new();
    let mut active_tab = 0usize; // 0 users, 1 chat, 2 input
    let mut should_quit = false;

    while !should_quit {
        while let Ok(ev) = event_rx.try_recv() {
            if let AppEvent::Incoming { from, text } = ev {
                let key = from.clone();
                known_names.entry(key.clone()).or_insert(from.clone());
                messages.entry(key.clone()).or_default().push(Message {
                    from,
                    text,
                    incoming: true,
                    time: clock(),
                });
            }
        }

        let peer_list: Vec<Peer> = {
            let mut v: Vec<Peer> = peers.read().await.values().cloned().collect();
            v.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
            v
        };

        if selected >= peer_list.len() && !peer_list.is_empty() {
            selected = peer_list.len() - 1;
        }

        terminal.draw(|f| {
            draw_ui(
                f,
                name,
                my_id,
                &peer_list,
                selected,
                &messages,
                &input,
                active_tab,
            )
        })?;

        if event::poll(Duration::from_millis(60))? {
            if let Event::Key(KeyEvent { code, modifiers, kind, .. }) = event::read()? {
                if kind != KeyEventKind::Press { continue; }

                if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
                    should_quit = true;
                    continue;
                }

                match code {
                    KeyCode::Char('q') if input.is_empty() => should_quit = true,
                    KeyCode::Tab => active_tab = (active_tab + 1) % 3,
                    KeyCode::Up => {
                        if !peer_list.is_empty() {
                            selected = selected.saturating_sub(1);
                            active_tab = 0;
                        }
                    }
                    KeyCode::Down => {
                        if !peer_list.is_empty() {
                            selected = (selected + 1).min(peer_list.len().saturating_sub(1));
                            active_tab = 0;
                        }
                    }
                    KeyCode::Enter => {
                        if !input.trim().is_empty() && !peer_list.is_empty() {
                            let peer = peer_list[selected].clone();
                            let text = input.trim().to_string();
                            if send_chat(&peer.addr, name, &text).await.is_ok() {
                                messages.entry(peer.id.clone()).or_default().push(Message {
                                    from: name.to_string(),
                                    text,
                                    incoming: false,
                                    time: clock(),
                                });
                                input.clear();
                            }
                        }
                    }
                    KeyCode::Backspace => { input.pop(); }
                    KeyCode::Char(c) => {
                        input.push(c);
                        active_tab = 2;
                    }
                    _ => {}
                }
            }
        }

        // Keep own ID referenced so the value is available for future protocol extensions.
        let _ = my_id;
        let _ = &known_names;
    }

    Ok(())
}

fn draw_ui(
    f: &mut Frame,
    name: &str,
    my_id: &str,
    peers: &[Peer],
    selected: usize,
    messages: &HashMap<String, Vec<Message>>,
    input: &str,
    active_tab: usize,
) {
    let size = f.area();

    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(size);

    let header = Paragraph::new(Line::from(vec![
        Span::styled(" LAN CHAT ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(
            format!("{} online", peers.len()),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  "),
        Span::styled(format!("as {}", name), Style::default().fg(Color::Cyan)),
    ]))
    .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(header, root[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(30)])
        .split(root[1]);

    let items: Vec<ListItem> = peers.iter().map(|p| {
        ListItem::new(Line::from(vec![
            Span::styled("● ", Style::default().fg(Color::Green)),
            Span::raw(&p.name),
            Span::styled(format!("  {}", p.id), Style::default().fg(Color::DarkGray)),
        ]))
    }).collect();

    let mut state = ListState::default();
    if !peers.is_empty() {
        state.select(Some(selected));
    }

    let user_style = if active_tab == 0 {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };

    let users = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Users "))
        .highlight_style(user_style.add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(users, body[0], &mut state);

    let selected_id = peers.get(selected).map(|p| p.id.clone());
    let chat_lines = if let Some(id) = selected_id {
        messages.get(&id).cloned().unwrap_or_default()
            .into_iter()
            .map(|m| {
                let prefix = if m.incoming { "←" } else { "→" };
                let style = if m.incoming {
                    Style::default().fg(Color::White)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                Line::from(vec![
                    Span::styled(format!("{prefix} {} ", m.time), Style::default().fg(Color::DarkGray)),
                    Span::styled(format!("{}: ", m.from), style.add_modifier(Modifier::BOLD)),
                    Span::styled(m.text, style),
                ])
            }).collect::<Vec<_>>()
    } else {
        vec![Line::from(Span::styled(
            "Select a user to start chatting.",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    let chat = Paragraph::new(chat_lines)
        .block(Block::default().borders(Borders::ALL).title(" Chat "))
        .wrap(Wrap { trim: false });
    f.render_widget(chat, body[1]);

    let input_title = if active_tab == 2 { " Message * " } else { " Message " };
    let input_box = Paragraph::new(input)
        .block(Block::default().borders(Borders::ALL).title(input_title));
    f.render_widget(input_box, root[2]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled("↑↓", Style::default().fg(Color::Yellow)),
        Span::raw(" Users  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(" Send  "),
        Span::styled("Tab", Style::default().fg(Color::Yellow)),
        Span::raw(" Switch  "),
        Span::styled("Ctrl+C / q", Style::default().fg(Color::Yellow)),
        Span::raw(" Quit"),
        Span::styled(format!("   ID: {my_id}"), Style::default().fg(Color::DarkGray)),
    ]));
    f.render_widget(footer, root[3]);
}

async fn send_chat(addr: &SocketAddr, from: &str, text: &str) -> Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    let packet = Packet::Chat {
        from: from.to_string(),
        text: text.to_string(),
        timestamp: now(),
    };
    let mut data = serde_json::to_vec(&packet)?;
    data.push(b'\n');
    stream.write_all(&data).await?;
    Ok(())
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    Ok(Terminal::new(backend)?)
}

fn restore_terminal(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn clock() -> String {
    let secs = now() % 86_400;
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs / 60) % 60, secs % 60)
}

