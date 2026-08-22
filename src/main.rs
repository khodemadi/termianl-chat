use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use hostname::get;
use rand::{thread_rng, RngCore};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env,
    fs::{self, File, OpenOptions},
    io::{self, stdout, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, RwLock},
};
use unicode_bidi::BidiInfo;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

const DISCOVERY_PORT: u16 = 45454;
const CHAT_PORT: u16 = 45455;
const MAGIC: &str = "LAN_TERM_CHAT_V3";
const DOWNLOAD_DIR: &str = "LAN-Terminal-Chat";
const FILE_CHUNK: usize = 48 * 1024;

#[derive(Clone, Debug)]
struct Peer {
    id: String,
    name: String,
    addr: SocketAddr,
    last_seen: u64,
    pubkey: [u8; 32],
}

#[derive(Clone, Debug)]
struct Message {
    from: String,
    text: String,
    incoming: bool,
    time: String,
    file_path: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum Packet {
    Hello {
        id: String,
        name: String,
        port: u16,
        pubkey: [u8; 32],
    },
    Chat {
        from: String,
        ciphertext: String,
        timestamp: u64,
    },
    File {
        from: String,
        name: String,
        size: u64,
        index: u64,
        total: u64,
        ciphertext: String,
    },
}

#[derive(Debug)]
enum AppEvent {
    IncomingChat { from: String, text: String },
    IncomingFile {
        from: String,
        name: String,
        size: u64,
        index: u64,
        total: u64,
        data: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
struct FileEntry {
    path: PathBuf,
    is_dir: bool,
}

#[derive(Debug)]
struct FilePicker {
    cwd: PathBuf,
    entries: Vec<FileEntry>,
    selected: usize,
}

type Peers = Arc<RwLock<HashMap<String, Peer>>>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn clock() -> String {
    let secs = now() % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    x25519(*secret, X25519_BASEPOINT_BYTES)
}

fn shared_key(secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    let shared = x25519(*secret, *peer_public);
    let digest = Sha256::digest(shared);
    digest.into()
}

fn encrypt_bytes(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let key = Key::from_slice(key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; 24];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .context("encryption failed")?;
    let mut packet = nonce_bytes.to_vec();
    packet.extend_from_slice(&ciphertext);
    Ok(B64.encode(packet))
}

fn decrypt_bytes(key_bytes: &[u8; 32], encoded: &str) -> Result<Vec<u8>> {
    let raw = B64.decode(encoded).context("invalid encrypted payload")?;
    if raw.len() < 24 {
        anyhow::bail!("encrypted payload is too short");
    }
    let (nonce_bytes, ciphertext) = raw.split_at(24);
    let key = Key::from_slice(key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    cipher
        .decrypt(XNonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| anyhow::anyhow!("authentication/decryption failed"))
}

fn rtl_visual(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.is_empty() {
                return String::new();
            }
            let bidi = BidiInfo::new(line, None);
            if bidi.has_rtl() {
                let para = &bidi.paragraphs[0];
                bidi.reorder_line(para, para.range.clone()).into_owned()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn home_dir() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn download_dir() -> PathBuf {
    home_dir().join("Downloads").join(DOWNLOAD_DIR)
}

fn load_entries(cwd: &Path) -> Vec<FileEntry> {
    let mut entries = Vec::new();

    if cwd.parent().is_some() {
        entries.push(FileEntry {
            path: cwd.join(".."),
            is_dir: true,
        });
    }

    if let Ok(read_dir) = fs::read_dir(cwd) {
        for item in read_dir.flatten() {
            let path = item.path();
            if let Ok(meta) = item.metadata() {
                entries.push(FileEntry {
                    path,
                    is_dir: meta.is_dir(),
                });
            }
        }
    }

    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.path.file_name().cmp(&b.path.file_name()))
    });
    entries
}

impl FilePicker {
    fn new() -> Self {
        let cwd = home_dir();
        let entries = load_entries(&cwd);
        Self {
            cwd,
            entries,
            selected: 0,
        }
    }

    fn reload(&mut self) {
        self.entries = load_entries(&self.cwd);
        if self.entries.is_empty() {
            self.selected = 0;
        } else {
            self.selected = self.selected.min(self.entries.len() - 1);
        }
    }

    fn selected(&self) -> Option<&FileEntry> {
        self.entries.get(self.selected)
    }

    fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    fn move_down(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + 1).min(self.entries.len() - 1);
        }
    }
}

fn unique_download_path(name: &str) -> PathBuf {
    let dir = download_dir();
    let _ = fs::create_dir_all(&dir);
    let original = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file.bin");

    let candidate = dir.join(original);
    if !candidate.exists() {
        return candidate;
    }

    let path = Path::new(original);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = path.extension().and_then(|s| s.to_str());
    for i in 1..10_000 {
        let filename = match ext {
            Some(ext) => format!("{stem} ({i}).{ext}"),
            None => format!("{stem} ({i})"),
        };
        let candidate = dir.join(filename);
        if !candidate.exists() {
            return candidate;
        }
    }
    dir.join(format!("{}-{}", now(), original))
}

#[tokio::main]
async fn main() -> Result<()> {
    let name = env::args()
        .nth(1)
        .unwrap_or_else(|| {
            get()
                .ok()
                .and_then(|x| x.into_string().ok())
                .unwrap_or_else(|| "user".into())
        });

    let mut secret = [0u8; 32];
    thread_rng().fill_bytes(&mut secret);
    let my_pubkey = public_key(&secret);

    let id: String = {
        let mut bytes = [0u8; 6];
        thread_rng().fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    };

    let peers: Peers = Arc::new(RwLock::new(HashMap::new()));
    let udp = Arc::new(UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT)).await?);
    udp.set_broadcast(true)?;
    let tcp = TcpListener::bind(("0.0.0.0", CHAT_PORT))
        .await
        .context("TCP port 45455 is unavailable")?;

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<AppEvent>();

    // Discovery receiver. Hello is intentionally small and contains only public key material.
    {
        let peers = peers.clone();
        let udp = udp.clone();
        let my_id = id.clone();
        let my_name = name.clone();
        let my_pubkey = my_pubkey;

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((n, src)) = udp.recv_from(&mut buf).await else { continue };
                let Ok(s) = std::str::from_utf8(&buf[..n]) else { continue };
                if !s.starts_with(MAGIC) {
                    continue;
                }

                let Ok(Packet::Hello {
                    id,
                    name,
                    port,
                    pubkey,
                }) = serde_json::from_str(s.trim_start_matches(MAGIC))
                else {
                    continue;
                };

                if id == my_id {
                    continue;
                }

                peers.write().await.insert(
                    id.clone(),
                    Peer {
                        id,
                        name,
                        addr: SocketAddr::new(src.ip(), port),
                        last_seen: now(),
                        pubkey,
                    },
                );

                let reply = Packet::Hello {
                    id: my_id.clone(),
                    name: my_name.clone(),
                    port: CHAT_PORT,
                    pubkey: my_pubkey,
                };
                if let Ok(bytes) = serde_json::to_vec(&reply) {
                    let msg = format!("{MAGIC}{}", String::from_utf8_lossy(&bytes));
                    let _ = udp
                        .send_to(
                            msg.as_bytes(),
                            SocketAddr::new(src.ip(), DISCOVERY_PORT),
                        )
                        .await;
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
        let my_pubkey = my_pubkey;

        tokio::spawn(async move {
            loop {
                let packet = Packet::Hello {
                    id: my_id.clone(),
                    name: my_name.clone(),
                    port: CHAT_PORT,
                    pubkey: my_pubkey,
                };

                if let Ok(bytes) = serde_json::to_vec(&packet) {
                    let msg = format!("{MAGIC}{}", String::from_utf8_lossy(&bytes));
                    let _ = udp
                        .send_to(
                            msg.as_bytes(),
                            SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::BROADCAST),
                                DISCOVERY_PORT,
                            ),
                        )
                        .await;
                }

                let cutoff = now().saturating_sub(15);
                peers.write().await.retain(|_, p| p.last_seen >= cutoff);
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    }

    // TCP receiver. Chat/file payloads are authenticated-encrypted.
    {
        let tx = event_tx.clone();
        let peers = peers.clone();
        let my_secret = secret;

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = tcp.accept().await else { continue };
                let tx = tx.clone();
                let peers = peers.clone();

                tokio::spawn(async move {
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();

                    while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                        let parsed = serde_json::from_str::<Packet>(line.trim());
                        line.clear();

                        let Ok(packet) = parsed else { continue };

                        match packet {
                            Packet::Chat {
                                from,
                                ciphertext,
                                ..
                            } => {
                                let peer = peers.read().await.get(&from).cloned();
                                let Some(peer) = peer else { continue };
                                let key = shared_key(&my_secret, &peer.pubkey);

                                if let Ok(bytes) = decrypt_bytes(&key, &ciphertext) {
                                    if let Ok(text) = String::from_utf8(bytes) {
                                        let _ =
                                            tx.send(AppEvent::IncomingChat { from, text });
                                    }
                                }
                            }

                            Packet::File {
                                from,
                                name,
                                size,
                                index,
                                total,
                                ciphertext,
                            } => {
                                let peer = peers.read().await.get(&from).cloned();
                                let Some(peer) = peer else { continue };
                                let key = shared_key(&my_secret, &peer.pubkey);

                                if let Ok(data) = decrypt_bytes(&key, &ciphertext) {
                                    let _ = tx.send(AppEvent::IncomingFile {
                                        from,
                                        name,
                                        size,
                                        index,
                                        total,
                                        data,
                                    });
                                }
                            }

                            Packet::Hello { .. } => {}
                        }
                    }
                });
            }
        });
    }

    let mut terminal = setup_terminal()?;
    let result =
        run_ui(&mut terminal, &name, &id, &secret, peers, &mut event_rx).await;
    restore_terminal(&mut terminal)?;
    result
}

async fn run_ui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    name: &str,
    my_id: &str,
    my_secret: &[u8; 32],
    peers: Peers,
    event_rx: &mut mpsc::UnboundedReceiver<AppEvent>,
) -> Result<()> {
    let mut selected = 0usize;
    let mut input = String::new();
    let mut messages: HashMap<String, Vec<Message>> = HashMap::new();
    let mut active_tab = 2usize;
    let mut should_quit = false;
    let mut picker: Option<FilePicker> = None;
    let mut incoming_files: HashMap<String, IncomingFile> = HashMap::new();

    while !should_quit {
        while let Ok(ev) = event_rx.try_recv() {
            match ev {
                AppEvent::IncomingChat { from, text } => {
                    messages.entry(from.clone()).or_default().push(Message {
                        from,
                        text,
                        incoming: true,
                        time: clock(),
                        file_path: None,
                    });
                }

                AppEvent::IncomingFile {
                    from,
                    name,
                    size,
                    index,
                    total,
                    data,
                } => {
                    let key = format!("{from}:{name}");
                    let entry = incoming_files.entry(key.clone()).or_insert_with(|| {
                        let path = unique_download_path(&name);
                        let _ = fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));
                        let _ = File::create(&path);
                        IncomingFile {
                            path,
                            size,
                            total,
                            received: 0,
                        }
                    });

                    let mut file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&entry.path)?;

                    // TCP writes are ordered for a single file stream, but index is retained
                    // in the protocol so future parallel transfer can be added safely.
                    let _ = index;
                    file.write_all(&data)?;
                    entry.received += data.len() as u64;

                    if entry.received >= entry.size || index + 1 >= entry.total {
                        let path = entry.path.clone();
                        let label = path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("file")
                            .to_string();

                        messages.entry(from.clone()).or_default().push(Message {
                            from,
                            text: format!("📎 {label}  {}", path.display()),
                            incoming: true,
                            time: clock(),
                            file_path: Some(path),
                        });
                        incoming_files.remove(&key);
                    }
                }
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
                picker.as_ref(),
            )
        })?;

        if event::poll(Duration::from_millis(60))? {
            if let Event::Key(KeyEvent {
                code,
                modifiers,
                kind,
                ..
            }) = event::read()?
            {
                if kind != KeyEventKind::Press {
                    continue;
                }

                if let Some(file_picker) = picker.as_mut() {
                    match code {
                        KeyCode::Esc => picker = None,
                        KeyCode::Up => file_picker.move_up(),
                        KeyCode::Down => file_picker.move_down(),
                        KeyCode::Enter => {
                            if let Some(entry) = file_picker.selected().cloned() {
                                if entry.path.file_name().and_then(|n| n.to_str())
                                    == Some("..")
                                {
                                    if let Some(parent) = file_picker.cwd.parent() {
                                        file_picker.cwd = parent.to_path_buf();
                                        file_picker.reload();
                                    }
                                } else if entry.is_dir {
                                    file_picker.cwd = entry.path;
                                    file_picker.selected = 0;
                                    file_picker.reload();
                                } else if !peer_list.is_empty() {
                                    let peer = peer_list[selected].clone();
                                    let path = entry.path.clone();
                                    picker = None;

                                    if let Err(err) =
                                        send_file(&peer, my_id, my_secret, &path).await
                                    {
                                        messages
                                            .entry(peer.id.clone())
                                            .or_default()
                                            .push(Message {
                                                from: name.to_string(),
                                                text: format!("File send failed: {err}"),
                                                incoming: false,
                                                time: clock(),
                                                file_path: None,
                                            });
                                    } else {
                                        let filename = path
                                            .file_name()
                                            .and_then(|s| s.to_str())
                                            .unwrap_or("file")
                                            .to_string();
                                        messages
                                            .entry(peer.id.clone())
                                            .or_default()
                                            .push(Message {
                                                from: name.to_string(),
                                                text: format!(
                                                    "📎 {} ({})",
                                                    filename,
                                                    path.display()
                                                ),
                                                incoming: false,
                                                time: clock(),
                                                file_path: Some(path),
                                            });
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    continue;
                }

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
                            selected =
                                (selected + 1).min(peer_list.len().saturating_sub(1));
                            active_tab = 0;
                        }
                    }
                    KeyCode::Enter => {
                        let command = input.trim().to_string();

                        if command == "/files" {
                            if !peer_list.is_empty() {
                                picker = Some(FilePicker::new());
                                input.clear();
                            }
                            continue;
                        }

                        if !command.is_empty() && !peer_list.is_empty() {
                            let peer = peer_list[selected].clone();
                            let text = command;

                            if send_chat(&peer, my_id, my_secret, &text).await.is_ok() {
                                messages.entry(peer.id.clone()).or_default().push(
                                    Message {
                                        from: name.to_string(),
                                        text,
                                        incoming: false,
                                        time: clock(),
                                        file_path: None,
                                    },
                                );
                                input.clear();
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        input.pop();
                    }
                    KeyCode::Char(c) => {
                        input.push(c);
                        active_tab = 2;
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
struct IncomingFile {
    path: PathBuf,
    size: u64,
    total: u64,
    received: u64,
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
    picker: Option<&FilePicker>,
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
        Span::styled(
            " LAN CHAT ",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{} online", peers.len()),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  "),
        Span::styled(format!("as {}", name), Style::default().fg(Color::Cyan)),
        Span::raw("  "),
        Span::styled("E2E", Style::default().fg(Color::Green)),
    ]))
    .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(header, root[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(30)])
        .split(root[1]);

    let items: Vec<ListItem> = peers
        .iter()
        .map(|p| {
            ListItem::new(Line::from(vec![
                Span::styled("● ", Style::default().fg(Color::Green)),
                Span::raw(&p.name),
                Span::styled(
                    format!("  {}", p.id),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    if !peers.is_empty() {
        state.select(Some(selected));
    }

    let user_style = if active_tab == 0 {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };

    let users = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Users "))
        .highlight_style(user_style.add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(users, body[0], &mut state);

    if let Some(file_picker) = picker {
        draw_file_picker(f, body[1], file_picker);
    } else {
        let selected_id = peers.get(selected).map(|p| p.id.clone());
        let chat_lines = if let Some(id) = selected_id {
            messages
                .get(&id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|m| {
                    let prefix = if m.incoming { "←" } else { "→" };
                    let style = if m.incoming {
                        Style::default().fg(Color::White)
                    } else {
                        Style::default().fg(Color::Cyan)
                    };

                    let rendered = if m.file_path.is_none() {
                        rtl_visual(&m.text)
                    } else {
                        m.text.clone()
                    };

                    Line::from(vec![
                        Span::styled(
                            format!("{prefix} {} ", m.time),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(
                            format!("{}: ", m.from),
                            style.add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(rendered, style),
                    ])
                })
                .collect::<Vec<_>>()
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
    }

    let input_title = if active_tab == 2 {
        " Message * "
    } else {
        " Message "
    };
    let input_box = Paragraph::new(input)
        .block(Block::default().borders(Borders::ALL).title(input_title));
    f.render_widget(input_box, root[2]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled("↑↓", Style::default().fg(Color::Yellow)),
        Span::raw(" Users  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(" Send  "),
        Span::styled("/files", Style::default().fg(Color::Yellow)),
        Span::raw(" File picker  "),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::raw(" Close picker  "),
        Span::styled("Ctrl+C / q", Style::default().fg(Color::Yellow)),
        Span::raw(" Quit"),
        Span::styled(
            format!("   ID: {my_id}"),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    f.render_widget(footer, root[3]);
}

fn draw_file_picker(f: &mut Frame, area: ratatui::layout::Rect, picker: &FilePicker) {
    let items = picker
        .entries
        .iter()
        .map(|entry| {
            let name = entry
                .path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("?");

            let prefix = if entry.is_dir { "📁 " } else { "📄 " };
            ListItem::new(format!("{prefix}{name}"))
        })
        .collect::<Vec<_>>();

    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(picker.selected));
    }

    let title = format!(" Files — {} ", picker.cwd.display());
    let widget = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::REVERSED),
        );

    f.render_stateful_widget(widget, area, &mut state);
}

async fn send_chat(
    peer: &Peer,
    my_id: &str,
    my_secret: &[u8; 32],
    text: &str,
) -> Result<()> {
    let mut stream = TcpStream::connect(peer.addr).await?;
    let key = shared_key(my_secret, &peer.pubkey);
    let ciphertext = encrypt_bytes(&key, text.as_bytes())?;

    let packet = Packet::Chat {
        from: my_id.to_string(),
        ciphertext,
        timestamp: now(),
    };

    let mut data = serde_json::to_vec(&packet)?;
    data.push(b'\n');
    stream.write_all(&data).await?;
    Ok(())
}

async fn send_file(
    peer: &Peer,
    my_id: &str,
    my_secret: &[u8; 32],
    path: &Path,
) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        anyhow::bail!("not a regular file");
    }

    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file.bin")
        .to_string();

    let size = metadata.len();
    let total = ((size as usize + FILE_CHUNK - 1) / FILE_CHUNK).max(1) as u64;
    let key = shared_key(my_secret, &peer.pubkey);
    let mut file = File::open(path)?;
    let mut stream = TcpStream::connect(peer.addr).await?;

    let mut buf = vec![0u8; FILE_CHUNK];
    for index in 0..total {
        let n = std::io::Read::read(&mut file, &mut buf)?;
        if n == 0 && size > 0 {
            break;
        }

        let ciphertext = encrypt_bytes(&key, &buf[..n])?;
        let packet = Packet::File {
            from: my_id.to_string(),
            name: name.clone(),
            size,
            index,
            total,
            ciphertext,
        };

        let mut line = serde_json::to_vec(&packet)?;
        line.push(b'\n');
        stream.write_all(&line).await?;

        if n == 0 {
            break;
        }
    }

    Ok(())
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    Ok(Terminal::new(backend)?)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
