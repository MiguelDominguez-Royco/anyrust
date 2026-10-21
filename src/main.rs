#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod remote;

use chrono::Local;
use eframe::egui;
use remote::{
    compress_bytes, decompress_bytes, get_local_ip_and_id, resolve_target_address, NetPacket,
    DEFAULT_PORT,
};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    mpsc::{channel, Receiver, Sender},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::mpsc as tokio_mpsc;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecentPeer {
    pub name: String,
    pub address: String,
    pub pin: String,
    pub last_connected: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum ThemeFlavor {
    MochaDark,
    LatteLight,
}

struct HostSharedConfig {
    pub pin: Mutex<String>,
    pub allow_connections: AtomicBool,
    pub allow_input_control: AtomicBool,
    pub allow_clipboard: AtomicBool,
    pub active_clients: AtomicU32,
}

enum UiEvent {
    Connected {
        host_name: String,
        screen_w: u32,
        screen_h: u32,
    },
    AuthFailed(String),
    Disconnected(String),
    Frame {
        width: u32,
        height: u32,
        rgba: Vec<u8>,
        compressed_kb: usize,
    },
    Chat {
        sender: String,
        text: String,
        time: String,
    },
    RemoteClipboard(String),
    StatusInfo(String),
}

// Protocolo binario rápido:
// [1 byte tipo: 1 = JSON NetPacket, 2 = VideoFrame binario]
// [4 bytes longitud payload Big-Endian]
// [payload]
async fn write_packet(stream: &mut TcpStream, pkt: &NetPacket) -> std::io::Result<()> {
    match pkt {
        NetPacket::VideoFrame {
            width,
            height,
            compressed_rgba,
        } => {
            let payload_len = 8 + compressed_rgba.len();
            let mut header = [0u8; 13];
            header[0] = 2u8;
            header[1..5].copy_from_slice(&(payload_len as u32).to_be_bytes());
            header[5..9].copy_from_slice(&width.to_be_bytes());
            header[9..13].copy_from_slice(&height.to_be_bytes());
            stream.write_all(&header).await?;
            stream.write_all(compressed_rgba).await?;
        }
        other => {
            let json = serde_json::to_vec(other).unwrap_or_default();
            let mut header = [0u8; 5];
            header[0] = 1u8;
            header[1..5].copy_from_slice(&(json.len() as u32).to_be_bytes());
            stream.write_all(&header).await?;
            stream.write_all(&json).await?;
        }
    }
    stream.flush().await
}

async fn read_packet(stream: &mut TcpStream) -> std::io::Result<NetPacket> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let kind = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > 32 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Paquete demasiado grande",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    if kind == 2 {
        if buf.len() < 8 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Frame incompleto",
            ));
        }
        let width = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let height = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let compressed_rgba = buf[8..].to_vec();
        Ok(NetPacket::VideoFrame {
            width,
            height,
            compressed_rgba,
        })
    } else {
        serde_json::from_slice(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// Servidor Anfitrión (Host) que escucha conexiones entrantes en segundo plano (puerto 7890+)
async fn run_host_server(
    host_cfg: Arc<HostSharedConfig>,
    ui_tx: Sender<UiEvent>,
    egui_ctx: egui::Context,
) {
    let mut bound_listener = None;
    let mut actual_port = DEFAULT_PORT;

    for port in DEFAULT_PORT..=(DEFAULT_PORT + 10) {
        let addr = format!("0.0.0.0:{}", port);
        if let Ok(l) = TcpListener::bind(&addr).await {
            actual_port = port;
            bound_listener = Some(l);
            break;
        }
    }

    let Some(listener) = bound_listener else {
        let _ = ui_tx.send(UiEvent::StatusInfo(
            "❌ No se pudo abrir ningún puerto entre 7890 y 7900.".to_string(),
        ));
        egui_ctx.request_repaint();
        return;
    };

    let _ = ui_tx.send(UiEvent::StatusInfo(format!(
        "🟢 Servidor Anfitrión activo escuchando en el puerto TCP {}",
        actual_port
    )));
    egui_ctx.request_repaint();

    loop {
        let Ok((mut stream, peer_addr)) = listener.accept().await else {
            continue;
        };
        let _ = stream.set_nodelay(true);

        if !host_cfg.allow_connections.load(Ordering::Relaxed) {
            let _ = write_packet(
                &mut stream,
                &NetPacket::AuthResponse {
                    accepted: false,
                    message: "El anfitrión tiene desactivadas las conexiones entrantes.".to_string(),
                    screen_width: 0,
                    screen_height: 0,
                    host_name: String::new(),
                },
            )
            .await;
            continue;
        }

        let cfg_clone = host_cfg.clone();
        let tx_clone = ui_tx.clone();
        let ctx_clone = egui_ctx.clone();

        tokio::spawn(async move {
            // 1. Leer petición de autenticación
            let Ok(NetPacket::AuthRequest {
                pin,
                client_name,
                scale_div,
            }) = read_packet(&mut stream).await
            else {
                return;
            };

            let expected_pin = cfg_clone.pin.lock().unwrap().clone();
            if pin.trim() != expected_pin.trim() {
                let _ = write_packet(
                    &mut stream,
                    &NetPacket::AuthResponse {
                        accepted: false,
                        message: "PIN de seguridad incorrecto.".to_string(),
                        screen_width: 0,
                        screen_height: 0,
                        host_name: String::new(),
                    },
                )
                .await;
                return;
            }

            let (sw, sh) = remote::win_io::get_screen_size();
            let host_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "PC-Host".to_string());

            if write_packet(
                &mut stream,
                &NetPacket::AuthResponse {
                    accepted: true,
                    message: "Conectado".to_string(),
                    screen_width: sw,
                    screen_height: sh,
                    host_name,
                },
            )
            .await
            .is_err()
            {
                return;
            }

            cfg_clone.active_clients.fetch_add(1, Ordering::Relaxed);
            let _ = tx_clone.send(UiEvent::StatusInfo(format!(
                "🟢 Cliente '{}' ({}) conectado a tu pantalla",
                client_name, peer_addr
            )));
            ctx_clone.request_repaint();

            let current_scale = Arc::new(AtomicU32::new(scale_div.clamp(1, 4)));
            let mut interval = tokio::time::interval(Duration::from_millis(85));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if !cfg_clone.allow_connections.load(Ordering::Relaxed) {
                            break;
                        }
                        let div = current_scale.load(Ordering::Relaxed);
                        // Capturar y comprimir en hilo bloqueante para no frenar el runtime
                        let frame_opt = tokio::task::spawn_blocking(move || {
                            let (w, h, rgba) = remote::win_io::capture_screen_rgba(div)?;
                            let compressed = compress_bytes(&rgba);
                            Some((w, h, compressed))
                        }).await.ok().flatten();

                        if let Some((w, h, compressed_rgba)) = frame_opt {
                            if write_packet(&mut stream, &NetPacket::VideoFrame {
                                width: w,
                                height: h,
                                compressed_rgba,
                            }).await.is_err() {
                                break;
                            }
                        }
                    }
                    pkt_res = read_packet(&mut stream) => {
                        match pkt_res {
                            Ok(NetPacket::MouseMove { norm_x, norm_y }) => {
                                if cfg_clone.allow_input_control.load(Ordering::Relaxed) {
                                    remote::win_io::inject_mouse_move(norm_x, norm_y);
                                }
                            }
                            Ok(NetPacket::MouseClick { norm_x, norm_y, button, pressed }) => {
                                if cfg_clone.allow_input_control.load(Ordering::Relaxed) {
                                    remote::win_io::inject_mouse_click(norm_x, norm_y, button, pressed);
                                }
                            }
                            Ok(NetPacket::KeyPress { vk }) => {
                                if cfg_clone.allow_input_control.load(Ordering::Relaxed) {
                                    remote::win_io::inject_key_press(vk);
                                }
                            }
                            Ok(NetPacket::SetQuality { scale_div }) => {
                                current_scale.store(scale_div.clamp(1, 4), Ordering::Relaxed);
                            }
                            Ok(NetPacket::ChatMessage { sender, text, time }) => {
                                let _ = tx_clone.send(UiEvent::Chat { sender, text, time });
                                ctx_clone.request_repaint();
                            }
                            Ok(NetPacket::ClipboardSync { text }) => {
                                if cfg_clone.allow_clipboard.load(Ordering::Relaxed) {
                                    let _ = tx_clone.send(UiEvent::RemoteClipboard(text));
                                    ctx_clone.request_repaint();
                                }
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                }
            }

            cfg_clone.active_clients.fetch_sub(1, Ordering::Relaxed);
            let _ = tx_clone.send(UiEvent::StatusInfo(format!(
                "🔌 Cliente '{}' desconectado",
                client_name
            )));
            ctx_clone.request_repaint();
        });
    }
}

pub struct AnyRustApp {
    local_ip: String,
    local_id: String,
    host_cfg: Arc<HostSharedConfig>,
    host_pin_input: String,

    // Estado de conexión saliente (Cliente)
    target_address_input: String,
    target_pin_input: String,
    scale_div: u32,
    is_connecting: bool,
    is_connected: bool,
    remote_host_name: String,
    remote_screen_size: (u32, u32),
    remote_control_enabled: bool, // Desactivado por defecto al probar en localhost para evitar bucle de ratón
    remote_texture: Option<egui::TextureHandle>,
    fps: f32,
    frame_kb: usize,
    last_frame_instant: Instant,
    last_mouse_send: Instant,

    // Historial de equipos recientes y Chat
    recent_peers: Vec<RecentPeer>,
    chat_messages: Vec<(String, String, String)>,
    chat_input: String,
    status_banner: String,
    theme: ThemeFlavor,

    // Canales de comunicación con Tokio
    rt: Runtime,
    ui_rx: Receiver<UiEvent>,
    ui_tx: Sender<UiEvent>,
    client_out_tx: Option<tokio_mpsc::UnboundedSender<NetPacket>>,
}

impl AnyRustApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (local_ip, local_id) = get_local_ip_and_id();
        let default_pin = "1234".to_string();

        let host_cfg = Arc::new(HostSharedConfig {
            pin: Mutex::new(default_pin.clone()),
            allow_connections: AtomicBool::new(true),
            allow_input_control: AtomicBool::new(true),
            allow_clipboard: AtomicBool::new(true),
            active_clients: AtomicU32::new(0),
        });

        let (ui_tx, ui_rx) = channel();
        let rt = Runtime::new().expect("No se pudo iniciar Tokio Runtime");

        // Iniciar servidor Anfitrión en segundo plano
        let cfg_clone = host_cfg.clone();
        let tx_clone = ui_tx.clone();
        let ctx_clone = cc.egui_ctx.clone();
        rt.spawn(async move {
            run_host_server(cfg_clone, tx_clone, ctx_clone).await;
        });

        let theme = ThemeFlavor::MochaDark;
        Self::apply_theme(&cc.egui_ctx, theme);

        let recent_peers = vec![RecentPeer {
            name: "Mi Propia PC (Prueba Local Loopback)".to_string(),
            address: "127.0.0.1".to_string(),
            pin: "1234".to_string(),
            last_connected: "Listo para probar".to_string(),
        }];

        Self {
            local_ip,
            local_id,
            host_cfg,
            host_pin_input: default_pin,
            target_address_input: "127.0.0.1".to_string(),
            target_pin_input: "1234".to_string(),
            scale_div: 2,
            is_connecting: false,
            is_connected: false,
            remote_host_name: String::new(),
            remote_screen_size: (1920, 1080),
            remote_control_enabled: false,
            remote_texture: None,
            fps: 0.0,
            frame_kb: 0,
            last_frame_instant: Instant::now(),
            last_mouse_send: Instant::now(),
            recent_peers,
            chat_messages: Vec::new(),
            chat_input: String::new(),
            status_banner: format!("🟢 Servidor activo escuchando en el puerto TCP {}", DEFAULT_PORT),
            theme,
            rt,
            ui_rx,
            ui_tx,
            client_out_tx: None,
        }
    }

    fn apply_theme(ctx: &egui::Context, flavor: ThemeFlavor) {
        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 7.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);

        let mut visuals = match flavor {
            ThemeFlavor::MochaDark => {
                let mut v = egui::Visuals::dark();
                v.panel_fill = egui::Color32::from_rgb(30, 30, 46);      // #1e1e2e
                v.window_fill = egui::Color32::from_rgb(24, 24, 37);     // #181825
                v.extreme_bg_color = egui::Color32::from_rgb(17, 17, 27);// #11111b
                v.widgets.noninteractive.fg_stroke =
                    egui::Stroke::new(1.2_f32, egui::Color32::from_rgb(238, 242, 255));
                v.widgets.inactive.bg_fill = egui::Color32::from_rgb(49, 50, 68);
                v.widgets.inactive.fg_stroke =
                    egui::Stroke::new(1.2_f32, egui::Color32::from_rgb(238, 242, 255));
                v.widgets.hovered.bg_fill = egui::Color32::from_rgb(69, 71, 90);
                v.widgets.active.bg_fill = egui::Color32::from_rgb(210, 15, 57);
                v
            }
            ThemeFlavor::LatteLight => {
                let mut v = egui::Visuals::light();
                v.panel_fill = egui::Color32::from_rgb(239, 241, 245);
                v.window_fill = egui::Color32::from_rgb(230, 233, 239);
                v.extreme_bg_color = egui::Color32::WHITE;
                v.widgets.noninteractive.fg_stroke =
                    egui::Stroke::new(1.2_f32, egui::Color32::from_rgb(25, 28, 42));
                v.widgets.inactive.bg_fill = egui::Color32::from_rgb(204, 208, 218);
                v.widgets.inactive.fg_stroke =
                    egui::Stroke::new(1.2_f32, egui::Color32::from_rgb(25, 28, 42));
                v
            }
        };

        visuals.window_rounding = egui::Rounding::same(8.0);
        style.visuals = visuals;
        ctx.set_style(style);
    }

    fn connect_to_peer(&mut self, ctx: &egui::Context) {
        if self.is_connecting || self.is_connected {
            return;
        }
        let resolved_addr = resolve_target_address(&self.target_address_input, &self.local_ip);
        let pin = self.target_pin_input.clone();
        let scale_div = self.scale_div;

        // Si el usuario se conecta a sí mismo (127.0.0.1 o su propia IP), desactivar control de mouse inicial para evitar bucle infinito
        let is_self = resolved_addr.starts_with("127.0.0.1")
            || resolved_addr.starts_with(&self.local_ip);
        self.remote_control_enabled = !is_self;

        self.is_connecting = true;
        self.status_banner = format!("⏳ Conectando a {}...", resolved_addr);

        let (out_tx, mut out_rx) = tokio_mpsc::unbounded_channel::<NetPacket>();
        self.client_out_tx = Some(out_tx);

        let ui_tx = self.ui_tx.clone();
        let egui_ctx = ctx.clone();

        self.rt.spawn(async move {
            let mut stream = match tokio::time::timeout(
                Duration::from_secs(5),
                TcpStream::connect(&resolved_addr),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    let _ = ui_tx.send(UiEvent::AuthFailed(format!(
                        "No se pudo conectar a {}: {}",
                        resolved_addr, e
                    )));
                    egui_ctx.request_repaint();
                    return;
                }
                Err(_) => {
                    let _ = ui_tx.send(UiEvent::AuthFailed(format!(
                        "Tiempo de espera agotado al conectar a {}",
                        resolved_addr
                    )));
                    egui_ctx.request_repaint();
                    return;
                }
            };

            let _ = stream.set_nodelay(true);
            let client_name =
                std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Cliente-AnyRust".to_string());

            if write_packet(
                &mut stream,
                &NetPacket::AuthRequest {
                    pin,
                    client_name,
                    scale_div,
                },
            )
            .await
            .is_err()
            {
                let _ = ui_tx.send(UiEvent::AuthFailed(
                    "Error enviando credenciales.".to_string(),
                ));
                egui_ctx.request_repaint();
                return;
            }

            match read_packet(&mut stream).await {
                Ok(NetPacket::AuthResponse {
                    accepted: true,
                    screen_width,
                    screen_height,
                    host_name,
                    ..
                }) => {
                    let _ = ui_tx.send(UiEvent::Connected {
                        host_name,
                        screen_w: screen_width,
                        screen_h: screen_height,
                    });
                    egui_ctx.request_repaint();
                }
                Ok(NetPacket::AuthResponse {
                    accepted: false,
                    message,
                    ..
                }) => {
                    let _ = ui_tx.send(UiEvent::AuthFailed(message));
                    egui_ctx.request_repaint();
                    return;
                }
                _ => {
                    let _ = ui_tx.send(UiEvent::AuthFailed(
                        "Respuesta inválida del servidor remoto.".to_string(),
                    ));
                    egui_ctx.request_repaint();
                    return;
                }
            }

            loop {
                tokio::select! {
                    Some(out_pkt) = out_rx.recv() => {
                        if write_packet(&mut stream, &out_pkt).await.is_err() {
                            break;
                        }
                    }
                    in_res = read_packet(&mut stream) => {
                        match in_res {
                            Ok(NetPacket::VideoFrame { width, height, compressed_rgba }) => {
                                let compressed_kb = compressed_rgba.len() / 1024;
                                if let Some(rgba) = decompress_bytes(&compressed_rgba) {
                                    if rgba.len() == (width as usize) * (height as usize) * 4 {
                                        let _ = ui_tx.send(UiEvent::Frame {
                                            width,
                                            height,
                                            rgba,
                                            compressed_kb,
                                        });
                                        egui_ctx.request_repaint();
                                    }
                                }
                            }
                            Ok(NetPacket::ChatMessage { sender, text, time }) => {
                                let _ = ui_tx.send(UiEvent::Chat { sender, text, time });
                                egui_ctx.request_repaint();
                            }
                            Ok(NetPacket::ClipboardSync { text }) => {
                                let _ = ui_tx.send(UiEvent::RemoteClipboard(text));
                                egui_ctx.request_repaint();
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                }
            }

            let _ = ui_tx.send(UiEvent::Disconnected(
                "La sesión remota ha finalizado.".to_string(),
            ));
            egui_ctx.request_repaint();
        });
    }

    fn disconnect(&mut self) {
        self.client_out_tx = None;
        self.is_connected = false;
        self.is_connecting = false;
        self.remote_texture = None;
        self.status_banner = "🔌 Sesión desconectada.".to_string();
    }
}

impl eframe::App for AnyRustApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let is_light = self.theme == ThemeFlavor::LatteLight;
        let accent_red = if is_light {
            egui::Color32::from_rgb(210, 15, 57)
        } else {
            egui::Color32::from_rgb(243, 139, 168)
        };
        let accent_green = if is_light {
            egui::Color32::from_rgb(64, 160, 43)
        } else {
            egui::Color32::from_rgb(166, 227, 161)
        };
        let accent_blue = if is_light {
            egui::Color32::from_rgb(30, 102, 245)
        } else {
            egui::Color32::from_rgb(137, 180, 250)
        };
        let card_bg = if is_light {
            egui::Color32::from_rgb(230, 233, 239)
        } else {
            egui::Color32::from_rgb(24, 24, 37)
        };

        // Procesar eventos asíncronos
        while let Ok(ev) = self.ui_rx.try_recv() {
            match ev {
                UiEvent::Connected {
                    host_name,
                    screen_w,
                    screen_h,
                } => {
                    self.is_connecting = false;
                    self.is_connected = true;
                    self.remote_host_name = host_name.clone();
                    self.remote_screen_size = (screen_w, screen_h);
                    self.status_banner = format!(
                        "✅ Conectado a '{}' ({}x{})",
                        host_name, screen_w, screen_h
                    );

                    // Guardar en recientes si no existe
                    let addr_clean = self.target_address_input.trim().to_string();
                    if !self.recent_peers.iter().any(|p| p.address == addr_clean) {
                        self.recent_peers.insert(
                            0,
                            RecentPeer {
                                name: host_name,
                                address: addr_clean,
                                pin: self.target_pin_input.clone(),
                                last_connected: Local::now().format("%H:%M:%S").to_string(),
                            },
                        );
                    }
                }
                UiEvent::AuthFailed(msg) => {
                    self.is_connecting = false;
                    self.is_connected = false;
                    self.client_out_tx = None;
                    self.status_banner = format!("❌ {}", msg);
                }
                UiEvent::Disconnected(msg) => {
                    self.is_connecting = false;
                    self.is_connected = false;
                    self.client_out_tx = None;
                    self.remote_texture = None;
                    self.status_banner = format!("🔌 {}", msg);
                }
                UiEvent::Frame {
                    width,
                    height,
                    rgba,
                    compressed_kb,
                } => {
                    let elapsed = self.last_frame_instant.elapsed().as_secs_f32().max(0.001);
                    self.fps = 1.0 / elapsed;
                    self.last_frame_instant = Instant::now();
                    self.frame_kb = compressed_kb;

                    let color_img =
                        egui::ColorImage::from_rgba_unmultiplied([width as usize, height as usize], &rgba);
                    match &mut self.remote_texture {
                        Some(tex) => tex.set(color_img, egui::TextureOptions::LINEAR),
                        None => {
                            self.remote_texture = Some(ctx.load_texture(
                                "remote_screen",
                                color_img,
                                egui::TextureOptions::LINEAR,
                            ));
                        }
                    }
                }
                UiEvent::Chat { sender, text, time } => {
                    self.chat_messages.push((sender, text, time));
                }
                UiEvent::RemoteClipboard(text) => {
                    ctx.output_mut(|o| o.copied_text = text);
                    self.status_banner = "📋 Portapapeles recibido del equipo remoto.".to_string();
                }
                UiEvent::StatusInfo(info) => {
                    self.status_banner = info;
                }
            }
        }

        // Barra Superior
        egui::TopBottomPanel::top("anyrust_top_bar")
            .frame(
                egui::Frame::none()
                    .fill(card_bg)
                    .inner_margin(egui::Margin::symmetric(16.0, 10.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(
                        egui::RichText::new("🔴 AnyRust")
                            .size(21.0)
                            .strong()
                            .color(accent_red),
                    );
                    ui.separator();
                    let active_clients = self.host_cfg.active_clients.load(Ordering::Relaxed);
                    ui.colored_label(
                        accent_green,
                        egui::RichText::new(format!(
                            "● En línea (Clientes conectados a ti: {})",
                            active_clients
                        ))
                        .strong(),
                    );
                    ui.separator();
                    ui.label(&self.status_banner);

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let theme_btn = if is_light {
                            "🌙 Modo Oscuro"
                        } else {
                            "☀ Modo Claro"
                        };
                        if ui.button(theme_btn).clicked() {
                            self.theme = if is_light {
                                ThemeFlavor::MochaDark
                            } else {
                                ThemeFlavor::LatteLight
                            };
                            Self::apply_theme(ctx, self.theme);
                        }
                    });
                });
            });

        // Panel Lateral Izquierdo: "Este Puesto de Trabajo" + Permisos + Chat
        egui::SidePanel::left("anyrust_left_panel")
            .resizable(true)
            .default_width(310.0)
            .frame(
                egui::Frame::none()
                    .fill(card_bg)
                    .inner_margin(egui::Margin::same(14.0)),
            )
            .show(ctx, |ui| {
                ui.label(
                    egui::RichText::new("ESTE PUESTO DE TRABAJO")
                        .size(12.0)
                        .strong()
                        .color(accent_blue),
                );
                ui.add_space(4.0);

                egui::Frame::none()
                    .fill(ui.visuals().extreme_bg_color)
                    .rounding(egui::Rounding::same(8.0))
                    .inner_margin(egui::Margin::same(12.0))
                    .stroke(egui::Stroke::new(1.5_f32, accent_red))
                    .show(ui, |ui| {
                        ui.label("Tu Dirección AnyRust (ID):");
                        ui.horizontal(|ui| {
                            ui.heading(
                                egui::RichText::new(&self.local_id)
                                    .size(24.0)
                                    .strong()
                                    .monospace()
                                    .color(accent_red),
                            );
                            if ui
                                .button("📋 Copiar")
                                .on_hover_text("Copiar tu ID de 9 dígitos")
                                .clicked()
                            {
                                ui.output_mut(|o| o.copied_text = self.local_id.clone());
                            }
                        });
                        ui.small(format!(
                            "IP Red Local: {}:{}",
                            self.local_ip, DEFAULT_PORT
                        ));
                    });

                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new("🔑 PIN de Acceso Desatendido:")
                        .strong(),
                );
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut self.host_pin_input)
                                .desired_width(120.0),
                        )
                        .changed()
                    {
                        *self.host_cfg.pin.lock().unwrap() = self.host_pin_input.clone();
                    }
                    if ui.button("🎲 Nuevo PIN").clicked() {
                        let rand_pin = format!(
                            "{:04}",
                            (Local::now().timestamp_subsec_millis() % 9000) + 1000
                        );
                        self.host_pin_input = rand_pin.clone();
                        *self.host_cfg.pin.lock().unwrap() = rand_pin;
                    }
                });

                ui.add_space(8.0);
                ui.separator();
                ui.label(egui::RichText::new("🛡 Permisos de Anfitrión:").strong());

                let mut allow_conn = self.host_cfg.allow_connections.load(Ordering::Relaxed);
                if ui
                    .checkbox(&mut allow_conn, "Permitir conexiones entrantes")
                    .changed()
                {
                    self.host_cfg
                        .allow_connections
                        .store(allow_conn, Ordering::Relaxed);
                }

                let mut allow_inp = self.host_cfg.allow_input_control.load(Ordering::Relaxed);
                if ui
                    .checkbox(&mut allow_inp, "Permitir control de Mouse y Teclado")
                    .changed()
                {
                    self.host_cfg
                        .allow_input_control
                        .store(allow_inp, Ordering::Relaxed);
                }

                let mut allow_clip = self.host_cfg.allow_clipboard.load(Ordering::Relaxed);
                if ui
                    .checkbox(&mut allow_clip, "Permitir sincronizar Portapapeles")
                    .changed()
                {
                    self.host_cfg
                        .allow_clipboard
                        .store(allow_clip, Ordering::Relaxed);
                }

                ui.add_space(8.0);
                ui.separator();
                ui.label(egui::RichText::new("💬 Chat de Sesión en Vivo:").strong());

                egui::ScrollArea::vertical()
                    .id_salt("chat_scroll")
                    .max_height(150.0)
                    .show(ui, |ui| {
                        if self.chat_messages.is_empty() {
                            ui.small("Sin mensajes aún.");
                        }
                        for (sender, msg, time) in &self.chat_messages {
                            ui.horizontal_wrapped(|ui| {
                                ui.colored_label(accent_blue, format!("[{}] {}:", time, sender));
                                ui.label(msg);
                            });
                        }
                    });

                ui.horizontal(|ui| {
                    let chat_resp = ui.add(
                        egui::TextEdit::singleline(&mut self.chat_input)
                            .hint_text("Escribe un mensaje...")
                            .desired_width(180.0),
                    );
                    let send_clicked = ui.button("Enviar").clicked()
                        || (chat_resp.lost_focus()
                            && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                    if send_clicked && !self.chat_input.trim().is_empty() {
                        let time = Local::now().format("%H:%M").to_string();
                        let text = self.chat_input.trim().to_string();
                        self.chat_messages
                            .push(("Yo".to_string(), text.clone(), time.clone()));
                        if let Some(tx) = &self.client_out_tx {
                            let _ = tx.send(NetPacket::ChatMessage {
                                sender: "Remoto".to_string(),
                                text,
                                time,
                            });
                        }
                        self.chat_input.clear();
                    }
                });
            });

        // Panel Central: Conexión a "Otro Puesto de Trabajo" y Visor en Tiempo Real
        egui::CentralPanel::default().show(ctx, |ui| {
            // Barra de conexión a otro equipo
            egui::Frame::none()
                .fill(card_bg)
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::same(12.0))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            egui::RichText::new("🔗 OTRO PUESTO DE TRABAJO:")
                                .strong()
                                .color(accent_blue),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.target_address_input)
                                .hint_text("ID (ej. 168 160 237) o IP (127.0.0.1)")
                                .desired_width(210.0),
                        );

                        ui.label("PIN:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.target_pin_input)
                                .hint_text("1234")
                                .desired_width(70.0),
                        );

                        ui.label("Calidad:");
                        let prev_scale = self.scale_div;
                        egui::ComboBox::from_id_salt("quality_combo")
                            .selected_text(match self.scale_div {
                                1 => "💎 Alta HD (100%)",
                                2 => "⚖ Equilibrada (50%)",
                                _ => "⚡ Rápida (33%)",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.scale_div, 1, "💎 Alta HD (100%)");
                                ui.selectable_value(
                                    &mut self.scale_div,
                                    2,
                                    "⚖ Equilibrada (50%)",
                                );
                                ui.selectable_value(&mut self.scale_div, 3, "⚡ Rápida (33%)");
                            });
                        if prev_scale != self.scale_div {
                            if let Some(tx) = &self.client_out_tx {
                                let _ = tx.send(NetPacket::SetQuality {
                                    scale_div: self.scale_div,
                                });
                            }
                        }

                        if !self.is_connected {
                            let btn = egui::Button::new(
                                egui::RichText::new(if self.is_connecting {
                                    "⏳ Conectando..."
                                } else {
                                    "⚡ Conectar"
                                })
                                .strong()
                                .color(egui::Color32::WHITE),
                            )
                            .fill(accent_red);

                            if ui.add_enabled(!self.is_connecting, btn).clicked() {
                                self.connect_to_peer(ctx);
                            }
                        } else {
                            let disc_btn = egui::Button::new(
                                egui::RichText::new("🔌 Desconectar")
                                    .strong()
                                    .color(egui::Color32::WHITE),
                            )
                            .fill(accent_red);
                            if ui.add(disc_btn).clicked() {
                                self.disconnect();
                            }
                        }
                    });
                });

            ui.add_space(8.0);

            if self.is_connected {
                // Barra de control del Visor Remoto
                ui.horizontal(|ui| {
                    ui.colored_label(
                        accent_green,
                        egui::RichText::new(format!(
                            "🖥 Viendo: {} ({}x{}) | {:.1} FPS | ~{} KB/frame",
                            self.remote_host_name,
                            self.remote_screen_size.0,
                            self.remote_screen_size.1,
                            self.fps,
                            self.frame_kb
                        ))
                        .strong(),
                    );
                    ui.separator();
                    ui.checkbox(
                        &mut self.remote_control_enabled,
                        "🖱️ Controlar Mouse y Teclado Remoto",
                    )
                    .on_hover_text(
                        "Actívalo cuando te conectes a otra PC (desactívalo si pruebas en 127.0.0.1)",
                    );
                });
                ui.separator();

                // Lienzo de Escritorio Remoto en Tiempo Real
                if let Some(tex) = &self.remote_texture {
                    let avail = ui.available_size();
                    let tex_size = tex.size_vec2();
                    let aspect = (tex_size.x / tex_size.y.max(1.0)).max(0.1);

                    let mut draw_w = avail.x;
                    let mut draw_h = draw_w / aspect;
                    if draw_h > avail.y {
                        draw_h = avail.y;
                        draw_w = draw_h * aspect;
                    }

                    let (rect, response) = ui.allocate_exact_size(
                        egui::vec2(draw_w, draw_h),
                        egui::Sense::click_and_drag(),
                    );

                    ui.painter().image(
                        tex.id(),
                        rect,
                        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                        egui::Color32::WHITE,
                    );

                    // Si el control remoto está activo, enviar eventos de Mouse al equipo remoto
                    if self.remote_control_enabled {
                        if let Some(pos) = response.hover_pos() {
                            let norm_x = ((pos.x - rect.min.x) / rect.width()).clamp(0.0, 1.0);
                            let norm_y = ((pos.y - rect.min.y) / rect.height()).clamp(0.0, 1.0);

                            if self.last_mouse_send.elapsed() > Duration::from_millis(35) {
                                if let Some(tx) = &self.client_out_tx {
                                    let _ = tx.send(NetPacket::MouseMove { norm_x, norm_y });
                                }
                                self.last_mouse_send = Instant::now();
                            }

                            if ui.input(|i| i.pointer.primary_pressed()) {
                                if let Some(tx) = &self.client_out_tx {
                                    let _ = tx.send(NetPacket::MouseClick {
                                        norm_x,
                                        norm_y,
                                        button: 0,
                                        pressed: true,
                                    });
                                }
                            }
                            if ui.input(|i| i.pointer.primary_released()) {
                                if let Some(tx) = &self.client_out_tx {
                                    let _ = tx.send(NetPacket::MouseClick {
                                        norm_x,
                                        norm_y,
                                        button: 0,
                                        pressed: false,
                                    });
                                }
                            }
                            if ui.input(|i| i.pointer.secondary_pressed()) {
                                if let Some(tx) = &self.client_out_tx {
                                    let _ = tx.send(NetPacket::MouseClick {
                                        norm_x,
                                        norm_y,
                                        button: 1,
                                        pressed: true,
                                    });
                                }
                            }
                            if ui.input(|i| i.pointer.secondary_released()) {
                                if let Some(tx) = &self.client_out_tx {
                                    let _ = tx.send(NetPacket::MouseClick {
                                        norm_x,
                                        norm_y,
                                        button: 1,
                                        pressed: false,
                                    });
                                }
                            }
                        }
                    }
                } else {
                    ui.vertical_centered(|ui| {
                        ui.add_space(80.0);
                        ui.spinner();
                        ui.label("Recibiendo primer cuadro de video del equipo remoto...");
                    });
                }
            } else {
                // Dashboard de Sesiones Recientes / Favoritos estilo AnyDesk
                ui.heading("⭐ Equipos Recientes y Prueba Rápida");
                ui.add_space(6.0);

                let mut connect_now: Option<(String, String)> = None;

                egui::Grid::new("recent_peers_grid")
                    .striped(true)
                    .num_columns(4)
                    .spacing([18.0, 10.0])
                    .show(ui, |ui| {
                        ui.strong("Nombre del Equipo");
                        ui.strong("Dirección / ID");
                        ui.strong("Estado");
                        ui.strong("Acción");
                        ui.end_row();

                        for peer in &self.recent_peers {
                            ui.label(&peer.name);
                            ui.monospace(&peer.address);
                            ui.label(&peer.last_connected);
                            if ui.button("⚡ Conectar Ahora").clicked() {
                                connect_now = Some((peer.address.clone(), peer.pin.clone()));
                            }
                            ui.end_row();
                        }
                    });

                if let Some((addr, pin)) = connect_now {
                    self.target_address_input = addr;
                    self.target_pin_input = pin;
                    self.connect_to_peer(ctx);
                }

                ui.add_space(24.0);
                ui.separator();
                ui.label(
                    egui::RichText::new("💡 ¿Cómo funciona AnyRust?")
                        .strong()
                        .color(accent_blue),
                );
                ui.label("1. Para probarlo ahora mismo en tu propia PC, haz clic en '⚡ Conectar Ahora' en la fila '127.0.0.1' (con el PIN 1234).");
                ui.label("2. Para conectarte a otra PC de tu red u oficina, abre AnyRust en ambas computadoras, escribe su ID de 9 dígitos o su IP local y presiona '⚡ Conectar'.");
                ui.label("3. Incluye transmisión de pantalla comprimida con Zlib sobre TCP, control remoto de Mouse/Clicks y Chat bidireccional.");
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 740.0])
            .with_min_inner_size([850.0, 560.0])
            .with_title("AnyRust - Escritorio Remoto en Tiempo Real (Clon de AnyDesk)"),
        ..Default::default()
    };

    eframe::run_native(
        "AnyRust",
        native_options,
        Box::new(|cc| Ok(Box::new(AnyRustApp::new(cc)))),
    )
}
